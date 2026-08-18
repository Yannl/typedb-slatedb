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

use std::{env, error::Error, fmt, fs, io, path::Path, sync::OnceLock};

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

/// The durable, per-database backend identity (S-01, v17). This is the typed
/// choice a database is BOUND to at creation and re-verified at every open —
/// distinct from [`StorageBackendProfile`], which is conformance-runner
/// metadata (`TYPEDB_STORAGE_PROFILE` U0…U4) and MUST NOT be product
/// configuration.
///
/// The discriminant (`classic` vs `slatedb-r2`) is persisted atomically in the
/// database directory and is the anchor that turns a cross-engine open from a
/// silent data-loss hazard (a fresh engine constructed beside the other
/// backend's files) into a typed refusal:
///
/// - opening with a **missing/ambiguous** marker on an existing tree is a typed
///   refusal that requires an explicit migration/import workflow;
/// - opening with a **mismatch** (a `classic` marker while `slatedb-r2` is
///   resolved, or vice versa) is a typed refusal BEFORE any filesystem, WAL, or
///   object-namespace mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendSpec {
    /// RocksDB keyspaces + file WAL (the classic in-process engine).
    Classic,
    /// SlateDB-over-object-store (R2) lane, carrying the controller-provisioned
    /// choices its remote identity and behaviour derive from.
    SlateDbR2(SlateDbR2Spec),
}

/// The SlateDB-R2 backend's controller-provisioned configuration (S-01). Every
/// field is a policy the CONTROLLER owns in the production design; on the local
/// lanes the profile stands in for it. These are recorded so a checkpoint can
/// re-attest the exact backend a database was written with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlateDbR2Spec {
    /// Which object store the data path speaks to (`local-fs`, `s3`).
    pub object_store_profile: &'static str,
    /// How materialisations are minted/retired (here: fresh-per-open, no
    /// in-place replacement — inv. 81–84).
    pub materialisation_policy: &'static str,
    /// Read-cache posture (`none`, or a bounded disk cache).
    pub cache_policy: &'static str,
    /// The remote namespace format version(s) this backend reads/writes.
    pub protocol_versions: &'static str,
}

/// The persisted marker discriminant — exactly the identity comparison a
/// mismatch/missing check needs, independent of the richer [`SlateDbR2Spec`]
/// fields (which may evolve without changing engine identity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendMarker {
    Classic,
    SlateDbR2,
}

/// The file, inside the database directory, that records the durable backend
/// marker (S-01). A sibling of the `storage/` subtree and the WAL, written
/// once at creation.
pub const BACKEND_MARKER_FILE: &str = "backend-spec.marker";
const BACKEND_MARKER_TMP: &str = ".backend-spec.marker.tmp";

impl BackendMarker {
    fn tag(self) -> &'static str {
        match self {
            Self::Classic => "classic",
            Self::SlateDbR2 => "slatedb-r2",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "classic" => Some(Self::Classic),
            "slatedb-r2" => Some(Self::SlateDbR2),
            _ => None,
        }
    }
}

impl BackendSpec {
    /// Resolve the typed backend a profile binds to (S-01). A not-yet-available
    /// lane (U3/U4) is a typed refusal here, BEFORE any touch — never a fresh
    /// default engine. This is the single profile → backend-identity mapping.
    pub fn from_profile(profile: StorageBackendProfile) -> Result<Self, StorageFactoryError> {
        match profile {
            StorageBackendProfile::U0PristineUpstream | StorageBackendProfile::U1ForkRocksFileWal => Ok(Self::Classic),
            StorageBackendProfile::U2SlateLocalFs => Ok(Self::SlateDbR2(SlateDbR2Spec {
                object_store_profile: "local-fs",
                materialisation_policy: "fresh-per-open-no-inplace",
                cache_policy: "none",
                protocol_versions: "fv1",
            })),
            StorageBackendProfile::U2S3SlateS3FileWal => Ok(Self::SlateDbR2(SlateDbR2Spec {
                object_store_profile: "s3",
                materialisation_policy: "fresh-per-open-no-inplace",
                cache_policy: "optional-bounded-disk",
                protocol_versions: "fv1",
            })),
            StorageBackendProfile::U3SlateRemoteSim | StorageBackendProfile::U4ProductionRemote => {
                Err(StorageFactoryError::BackendNotYetAvailable { profile: profile.code() })
            }
        }
    }

    /// Resolve the backend identity from the environment profile, BEFORE any
    /// filesystem/WAL/object touch (S-01). No side effects.
    pub fn resolve_from_env() -> Result<Self, StorageFactoryError> {
        Self::from_profile(StorageFactory::resolve_from_env()?.profile())
    }

    /// The durable marker discriminant for this spec.
    pub fn marker(&self) -> BackendMarker {
        match self {
            Self::Classic => BackendMarker::Classic,
            Self::SlateDbR2(_) => BackendMarker::SlateDbR2,
        }
    }
}

/// Persist the backend marker atomically in the database directory (S-01):
/// write a temp file, then rename it into place (atomic on the same
/// filesystem). Called exactly once, right after the database directory is
/// created, so the identity is durable before any keyspace/WAL data lands.
pub fn write_backend_marker(database_dir: &Path, spec: &BackendSpec) -> io::Result<()> {
    let tmp = database_dir.join(BACKEND_MARKER_TMP);
    let final_path = database_dir.join(BACKEND_MARKER_FILE);
    fs::write(&tmp, spec.marker().tag().as_bytes())?;
    fs::rename(&tmp, &final_path)?;
    Ok(())
}

/// Read the persisted backend marker (S-01). `Ok(None)` means the file is
/// absent (an unmarked/ambiguous database — a migration case); an
/// unrecognised marker value is a typed refusal, never a silent default.
pub fn read_backend_marker(database_dir: &Path) -> Result<Option<BackendMarker>, StorageFactoryError> {
    match fs::read_to_string(database_dir.join(BACKEND_MARKER_FILE)) {
        Ok(contents) => match BackendMarker::parse(&contents) {
            Some(marker) => Ok(Some(marker)),
            None => Err(StorageFactoryError::BackendMarkerUnrecognised { value: contents.trim().to_owned() }),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(StorageFactoryError::BackendMarkerRead { source: error.to_string() }),
    }
}

/// The verdict of checking a resolved backend against an existing database's
/// persisted marker (S-01). PURE: no filesystem effects — the caller reads the
/// marker and passes it in, so the verification is testable and, crucially,
/// happens BEFORE any WAL/storage touch on the open path.
pub fn verify_backend_marker(
    resolved: &BackendSpec,
    persisted: Option<BackendMarker>,
) -> Result<(), StorageFactoryError> {
    match persisted {
        None => Err(StorageFactoryError::BackendMarkerMissing),
        Some(marker) if marker == resolved.marker() => Ok(()),
        Some(marker) => Err(StorageFactoryError::BackendMarkerMismatch {
            persisted: marker.tag(),
            resolved: resolved.marker().tag(),
        }),
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
    /// S-01: the existing database carries no backend marker — it is ambiguous
    /// and must not be opened by silently constructing a fresh engine beside
    /// the other backend's files. Requires an explicit migration/import.
    BackendMarkerMissing,
    /// S-01: the persisted marker names a different backend than the one
    /// resolved for this open. A typed refusal BEFORE any touch — never a
    /// cross-engine open.
    BackendMarkerMismatch {
        persisted: &'static str,
        resolved: &'static str,
    },
    /// S-01: the marker file holds an unrecognised value (corrupt/foreign);
    /// fail closed rather than guess a backend.
    BackendMarkerUnrecognised {
        value: String,
    },
    /// S-01: the marker file could not be read (I/O error other than absence).
    BackendMarkerRead {
        source: String,
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
            Self::BackendMarkerMissing => {
                write!(
                    f,
                    "refusing to open: the database directory carries no backend marker (S-01), so its storage \
                     backend is ambiguous; opening would risk constructing a fresh engine beside another \
                     backend's files. An explicit migration/import is required."
                )
            }
            Self::BackendMarkerMismatch { persisted, resolved } => {
                write!(
                    f,
                    "refusing to open: the database was created with the '{persisted}' backend but the '{resolved}' \
                     backend is configured for this open (S-01). This is a typed refusal BEFORE any filesystem, \
                     WAL, or object-namespace touch — never a silent cross-engine open."
                )
            }
            Self::BackendMarkerUnrecognised { value } => {
                write!(f, "refusing to open: the backend marker holds an unrecognised value '{value}' (S-01)")
            }
            Self::BackendMarkerRead { source } => {
                write!(f, "refusing to open: the backend marker could not be read (S-01): {source}")
            }
            Self::WalOpen { .. } => write!(f, "error opening write-ahead log"),
        }
    }
}

impl Error for StorageFactoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidProfile { .. }
            | Self::ProfileUnavailable { .. }
            | Self::BackendNotYetAvailable { .. }
            | Self::BackendMarkerMissing
            | Self::BackendMarkerMismatch { .. }
            | Self::BackendMarkerUnrecognised { .. }
            | Self::BackendMarkerRead { .. } => None,
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

#[cfg(test)]
mod backend_marker_tests {
    //! S-01: the per-database backend identity is persisted atomically and
    //! re-verified at open. A missing marker is a migration refusal; a
    //! mismatch is a typed cross-engine refusal; the profile → identity
    //! mapping keeps conformance U* out of product config.

    use test_utils::create_tmp_dir;

    use super::{
        BackendMarker, BackendSpec, StorageBackendProfile, StorageFactoryError, read_backend_marker,
        verify_backend_marker, write_backend_marker,
    };

    #[test]
    fn the_profile_maps_to_a_typed_backend_identity_not_the_u_star_conformance_label() {
        // classic lanes -> Classic; slate lanes -> SlateDbR2 with the
        // controller-provisioned config recorded; the not-yet lanes refuse.
        assert_eq!(BackendSpec::from_profile(StorageBackendProfile::U1ForkRocksFileWal).unwrap(), BackendSpec::Classic);
        assert_eq!(BackendSpec::from_profile(StorageBackendProfile::U0PristineUpstream).unwrap(), BackendSpec::Classic);
        let slate = BackendSpec::from_profile(StorageBackendProfile::U2SlateLocalFs).unwrap();
        assert_eq!(slate.marker(), BackendMarker::SlateDbR2);
        assert!(matches!(slate, BackendSpec::SlateDbR2(spec) if spec.object_store_profile == "local-fs"));
        let s3 = BackendSpec::from_profile(StorageBackendProfile::U2S3SlateS3FileWal).unwrap();
        assert!(matches!(s3, BackendSpec::SlateDbR2(spec) if spec.object_store_profile == "s3"));
        assert!(matches!(
            BackendSpec::from_profile(StorageBackendProfile::U4ProductionRemote),
            Err(StorageFactoryError::BackendNotYetAvailable { .. })
        ));
    }

    #[test]
    fn the_marker_round_trips_atomically() {
        let dir = create_tmp_dir("factory-marker-roundtrip");
        // absent before write
        assert_eq!(read_backend_marker(&dir).unwrap(), None);
        write_backend_marker(&dir, &BackendSpec::Classic).unwrap();
        assert_eq!(read_backend_marker(&dir).unwrap(), Some(BackendMarker::Classic));
        // and no stray temp file is left behind by the atomic rename
        assert!(!dir.join(super::BACKEND_MARKER_TMP).exists(), "the atomic rename must leave no temp file");
    }

    #[test]
    fn a_missing_marker_on_an_existing_database_is_a_migration_refusal() {
        // verify against an existing tree that carries no marker.
        let refused = verify_backend_marker(&BackendSpec::Classic, None);
        assert!(
            matches!(refused, Err(StorageFactoryError::BackendMarkerMissing)),
            "a marker-less database must refuse with a migration error, got: {refused:?}",
        );
    }

    #[test]
    fn a_classic_database_cannot_be_opened_as_slatedb_and_vice_versa() {
        let slate = BackendSpec::from_profile(StorageBackendProfile::U2SlateLocalFs).unwrap();
        // classic marker, slatedb resolved -> mismatch
        let refused = verify_backend_marker(&slate, Some(BackendMarker::Classic));
        assert!(
            matches!(
                refused,
                Err(StorageFactoryError::BackendMarkerMismatch { persisted: "classic", resolved: "slatedb-r2" })
            ),
            "opening a classic database as slatedb must be a typed mismatch refusal, got: {refused:?}",
        );
        // slatedb marker, classic resolved -> mismatch (the converse)
        let refused = verify_backend_marker(&BackendSpec::Classic, Some(BackendMarker::SlateDbR2));
        assert!(
            matches!(
                refused,
                Err(StorageFactoryError::BackendMarkerMismatch { persisted: "slatedb-r2", resolved: "classic" })
            ),
            "opening a slatedb database as classic must be a typed mismatch refusal, got: {refused:?}",
        );
        // and the matching case is admitted
        assert!(verify_backend_marker(&slate, Some(BackendMarker::SlateDbR2)).is_ok());
        assert!(verify_backend_marker(&BackendSpec::Classic, Some(BackendMarker::Classic)).is_ok());
    }

    #[test]
    fn an_unrecognised_marker_value_is_a_typed_refusal_not_a_silent_default() {
        let dir = create_tmp_dir("factory-marker-foreign");
        std::fs::write(dir.join(super::BACKEND_MARKER_FILE), b"postgres").unwrap();
        let refused = read_backend_marker(&dir);
        assert!(
            matches!(&refused, Err(StorageFactoryError::BackendMarkerUnrecognised { value }) if value == "postgres"),
            "an unrecognised marker must refuse, got: {refused:?}",
        );
    }
}
