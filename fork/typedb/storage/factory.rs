/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Central storage backend/profile factory (BT-P3).
//!
//! Every production and shared-test-utility construction of a durability
//! service (WAL) routes through this factory, keyed by a conformance profile.
//! The profile matrix follows the conformance plan:
//!
//! - `U0` — pristine upstream lane (identical runtime backend to `U1`; the
//!   distinction is which source tree runs, not which backend is selected).
//! - `U1` — fork lane: RocksDB keyspaces + file WAL (the oracle). Default.
//! - `U2` — SlateDB LocalFS keyspaces + file WAL (TB-P7, ADR-0001): the
//!   candidate engine over a local object store, with TypeDB's WAL remaining
//!   the durability authority.
//! - `U2S3` — SlateDB keyspaces over an S3-compatible object store (TB-P8):
//!   the same U2 semantics with the data path exercised through the S3 API
//!   (local MinIO stand-in for Cloudflare R2); file WAL unchanged.
//! - `U3` — SlateDB + remote WAL simulation. Not yet available; fail-closed.
//! - `U4` — production remote object-store lane. Not yet available; fail-closed.
//!
//! Upstream tests that construct backends directly (never edited) are
//! enumerated in the direct-constructor inventory evidence document.

use std::{env, error::Error, fmt, path::Path, sync::OnceLock};

use diagnostics::metrics::FsyncMetrics;
use durability::{DurabilityServiceError, wal::WAL};

use crate::keyspace::StorageBackend;

/// Environment variable selecting the storage backend profile for factory
/// construction. Unset means [`StorageBackendProfile::U1ForkRocksFileWal`].
pub const STORAGE_PROFILE_ENV: &str = "TYPEDB_STORAGE_PROFILE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackendProfile {
    /// Pristine-upstream lane; backend-identical to `U1`.
    U0PristineUpstream,
    /// Fork lane: RocksDB + file WAL oracle (default).
    U1ForkRocksFileWal,
    /// SlateDB LocalFS keyspaces + file WAL (TB-P7).
    U2SlateLocalFs,
    /// SlateDB over an S3-compatible object store + file WAL (TB-P8): U2
    /// semantics with the data path speaking the same S3 API Cloudflare R2
    /// serves, against a local stand-in (MinIO) in the L0 lane. The WAL
    /// remains the local file WAL — this profile moves only the keyspace
    /// object store off the local filesystem.
    U2S3SlateS3FileWal,
    /// SlateDB remote-WAL-simulation lane (unavailable).
    U3SlateRemoteSim,
    /// Production remote object-store lane (unavailable).
    U4ProductionRemote,
}

impl StorageBackendProfile {
    pub fn code(&self) -> &'static str {
        match self {
            Self::U0PristineUpstream => "U0",
            Self::U1ForkRocksFileWal => "U1",
            Self::U2SlateLocalFs => "U2",
            Self::U2S3SlateS3FileWal => "U2S3",
            Self::U3SlateRemoteSim => "U3",
            Self::U4ProductionRemote => "U4",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "U0" => Some(Self::U0PristineUpstream),
            "U1" | "" => Some(Self::U1ForkRocksFileWal),
            "U2" => Some(Self::U2SlateLocalFs),
            "U2S3" => Some(Self::U2S3SlateS3FileWal),
            "U3" => Some(Self::U3SlateRemoteSim),
            "U4" => Some(Self::U4ProductionRemote),
            _ => None,
        }
    }

    /// Resolve this profile to its typed keyspace backend (S-P0-06, v17
    /// A17.4). This is the ONE place a profile becomes a
    /// [`StorageBackend`]; the keyspace layer takes the result as an
    /// explicit constructor argument and never consults the profile (or any
    /// process-global) itself. Fail-closed: a profile whose backend is not
    /// yet buildable (U3/U4 — the remote/product lanes) is a typed
    /// `BackendNotYetAvailable` refusal here, BEFORE any engine or
    /// namespace is touched, never a fallback to a default engine.
    pub fn storage_backend(&self) -> Result<StorageBackend, StorageFactoryError> {
        match self {
            Self::U0PristineUpstream | Self::U1ForkRocksFileWal => Ok(StorageBackend::Rocks),
            Self::U2SlateLocalFs => Ok(StorageBackend::SlateLocalFs),
            Self::U2S3SlateS3FileWal => Ok(StorageBackend::SlateS3),
            Self::U3SlateRemoteSim | Self::U4ProductionRemote => {
                Err(StorageFactoryError::BackendNotYetAvailable { profile: self.code() })
            }
        }
    }

    fn file_wal_available(&self) -> bool {
        // U2/U2S3 pair SlateDB keyspaces with the file WAL: the KV engine
        // (and, for U2S3, its object store) swaps, durability authority
        // does not.
        matches!(
            self,
            Self::U0PristineUpstream | Self::U1ForkRocksFileWal | Self::U2SlateLocalFs | Self::U2S3SlateS3FileWal
        )
    }
}

/// The process-wide backend profile, resolved from the environment exactly
/// once. Cached deliberately: two engines writing one storage directory would
/// corrupt it, so a mid-process profile change must be impossible.
pub fn resolved_backend_profile() -> Result<StorageBackendProfile, StorageFactoryError> {
    static PROFILE: OnceLock<Result<StorageBackendProfile, StorageFactoryError>> = OnceLock::new();
    PROFILE.get_or_init(|| StorageFactory::resolve_from_env().map(|factory| factory.profile())).clone()
}

/// The single decision point for which durability/key-value backend a storage
/// instance is built with. Today the only available backend pair is
/// RocksDB + file WAL; unavailable profiles fail closed with a typed error
/// rather than silently degrading to the default.
#[derive(Debug, Clone, Copy)]
pub struct StorageFactory {
    profile: StorageBackendProfile,
}

impl StorageFactory {
    /// Resolve the factory from the environment (bounded configuration:
    /// unknown profile values are a typed error, never a silent default).
    pub fn resolve_from_env() -> Result<Self, StorageFactoryError> {
        match env::var(STORAGE_PROFILE_ENV) {
            Err(env::VarError::NotPresent) => Ok(Self { profile: StorageBackendProfile::U1ForkRocksFileWal }),
            Err(env::VarError::NotUnicode(_)) => {
                Err(StorageFactoryError::InvalidProfile { value: "<non-unicode>".to_owned() })
            }
            Ok(value) => match StorageBackendProfile::parse(&value) {
                Some(profile) => Ok(Self { profile }),
                None => Err(StorageFactoryError::InvalidProfile { value }),
            },
        }
    }

    pub fn with_profile(profile: StorageBackendProfile) -> Self {
        Self { profile }
    }

    pub fn profile(&self) -> StorageBackendProfile {
        self.profile
    }

    pub fn create_wal(&self, directory: &Path, metrics: FsyncMetrics) -> Result<WAL, StorageFactoryError> {
        self.require_file_wal()?;
        WAL::create(directory, metrics).map_err(|source| StorageFactoryError::WalOpen { source })
    }

    pub fn load_wal(&self, directory: &Path, metrics: FsyncMetrics) -> Result<WAL, StorageFactoryError> {
        self.require_file_wal()?;
        WAL::load(directory, metrics).map_err(|source| StorageFactoryError::WalOpen { source })
    }

    fn require_file_wal(&self) -> Result<(), StorageFactoryError> {
        if self.profile.file_wal_available() {
            Ok(())
        } else {
            Err(StorageFactoryError::ProfileUnavailable { profile: self.profile.code() })
        }
    }
}

#[derive(Debug, Clone)]
pub enum StorageFactoryError {
    InvalidProfile {
        value: String,
    },
    ProfileUnavailable {
        profile: &'static str,
    },
    /// The profile's keyspace backend is not yet buildable (S-P0-06): the
    /// remote/product lanes stay a typed refusal until their gate opens.
    BackendNotYetAvailable {
        profile: &'static str,
    },
    WalOpen {
        source: DurabilityServiceError,
    },
}

impl fmt::Display for StorageFactoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProfile { value } => {
                write!(f, "invalid {STORAGE_PROFILE_ENV} value '{value}': expected one of U0..U4")
            }
            Self::ProfileUnavailable { profile } => {
                write!(f, "storage backend profile '{profile}' is not available in this build; refusing to fall back")
            }
            Self::BackendNotYetAvailable { profile } => {
                write!(
                    f,
                    "the keyspace backend for storage profile '{profile}' is not yet available (v17 A17.4); \
                     refusing before any engine or namespace mutation rather than falling back"
                )
            }
            Self::WalOpen { .. } => write!(f, "error opening write-ahead log"),
        }
    }
}

impl Error for StorageFactoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidProfile { .. } | Self::ProfileUnavailable { .. } | Self::BackendNotYetAvailable { .. } => None,
            Self::WalOpen { source } => Some(source),
        }
    }
}

#[cfg(test)]
mod backend_seam_tests {
    //! S-P0-06: the profile -> backend resolution is the seam's single
    //! decision point. Positive cases pin the exact typed mapping; the
    //! negative case proves the not-yet-available lanes are a typed refusal
    //! at resolution — BEFORE any engine or namespace could be touched —
    //! and never a silent fallback to a default engine.

    use super::{StorageBackendProfile, StorageFactoryError};
    use crate::keyspace::StorageBackend;

    #[test]
    fn every_available_profile_resolves_to_its_exact_backend() {
        assert_eq!(StorageBackendProfile::U0PristineUpstream.storage_backend().unwrap(), StorageBackend::Rocks);
        assert_eq!(StorageBackendProfile::U1ForkRocksFileWal.storage_backend().unwrap(), StorageBackend::Rocks);
        assert_eq!(StorageBackendProfile::U2SlateLocalFs.storage_backend().unwrap(), StorageBackend::SlateLocalFs);
        assert_eq!(StorageBackendProfile::U2S3SlateS3FileWal.storage_backend().unwrap(), StorageBackend::SlateS3);
    }

    #[test]
    fn a_not_yet_available_lane_is_a_typed_refusal_never_a_default_engine() {
        for profile in [StorageBackendProfile::U3SlateRemoteSim, StorageBackendProfile::U4ProductionRemote] {
            let refused = profile.storage_backend();
            assert!(
                matches!(refused, Err(StorageFactoryError::BackendNotYetAvailable { profile: code }) if code == profile.code()),
                "profile {} must refuse with the typed BackendNotYetAvailable, got: {refused:?}",
                profile.code(),
            );
        }
    }

    #[test]
    fn an_unknown_profile_value_is_a_typed_error_not_a_silent_default() {
        assert!(matches!(StorageBackendProfile::parse("U9"), None));
        // and the parse-level fail-closed contract feeds the same seam: an
        // unset value defaults to the oracle profile EXPLICITLY (U1), while
        // any present-but-unknown value refuses in resolve_from_env — that
        // path reads the process environment, so it is pinned here only at
        // the parse level to keep this test hermetic.
        assert_eq!(StorageBackendProfile::parse("u2s3"), Some(StorageBackendProfile::U2S3SlateS3FileWal));
    }
}
