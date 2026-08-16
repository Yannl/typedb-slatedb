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
//! - `U2` — SlateDB LocalFS backend. Not yet available; requesting it is a
//!   typed, fail-closed error until the SlateDB adapter patch lands.
//! - `U3` — SlateDB + remote WAL simulation. Not yet available; fail-closed.
//! - `U4` — production remote object-store lane. Not yet available; fail-closed.
//!
//! Upstream tests that construct backends directly (never edited) are
//! enumerated in the direct-constructor inventory evidence document.

use std::{env, error::Error, fmt, path::Path};

use diagnostics::metrics::FsyncMetrics;
use durability::{DurabilityServiceError, wal::WAL};

/// Environment variable selecting the storage backend profile for factory
/// construction. Unset means [`StorageBackendProfile::U1ForkRocksFileWal`].
pub const STORAGE_PROFILE_ENV: &str = "TYPEDB_STORAGE_PROFILE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackendProfile {
    /// Pristine-upstream lane; backend-identical to `U1`.
    U0PristineUpstream,
    /// Fork lane: RocksDB + file WAL oracle (default).
    U1ForkRocksFileWal,
    /// SlateDB LocalFS lane (unavailable until the SlateDB adapter patch).
    U2SlateLocalFs,
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
            Self::U3SlateRemoteSim => "U3",
            Self::U4ProductionRemote => "U4",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "U0" => Some(Self::U0PristineUpstream),
            "U1" | "" => Some(Self::U1ForkRocksFileWal),
            "U2" => Some(Self::U2SlateLocalFs),
            "U3" => Some(Self::U3SlateRemoteSim),
            "U4" => Some(Self::U4ProductionRemote),
            _ => None,
        }
    }

    fn file_wal_available(&self) -> bool {
        matches!(self, Self::U0PristineUpstream | Self::U1ForkRocksFileWal)
    }
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
    InvalidProfile { value: String },
    ProfileUnavailable { profile: &'static str },
    WalOpen { source: DurabilityServiceError },
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
            Self::WalOpen { .. } => write!(f, "error opening write-ahead log"),
        }
    }
}

impl Error for StorageFactoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidProfile { .. } | Self::ProfileUnavailable { .. } => None,
            Self::WalOpen { source } => Some(source),
        }
    }
}
