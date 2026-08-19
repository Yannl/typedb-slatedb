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
//!
//! R4-STOR-00: the environment is read at exactly ONE admission point per
//! database open — [`BackendContext::resolve_from_env`] — and the resulting
//! immutable context is passed explicitly through every lower layer
//! (marker/WAL/MVCC/keyspaces/task policy/checkpoint identity). Lower layers
//! never re-read the environment; the process profile cache below turns a
//! mid-process environment change into a typed refusal instead of a silent
//! half-old/half-new split.

use std::{
    env,
    error::Error,
    fmt, fs,
    hash::{BuildHasher, Hasher},
    io,
    io::Write as _,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use diagnostics::metrics::FsyncMetrics;
use durability::{DurabilityServiceError, wal::WAL};

use crate::keyspace::{S3_BUCKET_ENV, S3_ENDPOINT_ENV, S3_PREFIX_ENV, StorageBackend};

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

/// R4-STOR-00: the ONE immutable backend context per database open/create.
///
/// Resolved exactly once at the admission point ([`Self::resolve_from_env`],
/// called at the top of `Database::open` — or at the top of a direct
/// `MVCCStorage::create`/`load` for tests/benches that construct storage
/// without a database), then passed EXPLICITLY through marker resolution,
/// WAL/durability construction, MVCC/keyspace open, background-task policy,
/// and checkpoint identity binding. No lower layer consults the environment
/// or a global cache to re-derive any of these; lower layers only re-check
/// the process profile cache via [`Self::verify_process_consistency`], so a
/// context resolved before a mid-process environment change can never be
/// silently mixed with one resolved after it.
#[derive(Debug, Clone)]
pub struct BackendContext {
    profile: StorageBackendProfile,
    spec: BackendSpec,
    backend: StorageBackend,
    identity: BackendIdentity,
}

/// The process-wide backend profile witness (R4-STOR-00). Seeded by the FIRST
/// successful context resolution and never changed afterwards: two engines
/// writing one storage directory would corrupt it, so a mid-process profile
/// change must be a typed refusal, never a silently honoured switch. This is
/// deliberately the ONLY process-global the backend seam keeps, and it is a
/// consistency CHECK, not a resolution source — every resolution still reads
/// the environment and then proves it agrees with the witness.
static PROCESS_PROFILE_WITNESS: OnceLock<StorageBackendProfile> = OnceLock::new();

impl BackendContext {
    /// Resolve the immutable context from the environment — the single
    /// admission point (R4-STOR-00). Side-effect free on the filesystem; a
    /// not-yet-available lane (U3/U4), an unknown profile value, or a profile
    /// that disagrees with the process witness is a typed refusal HERE,
    /// before any directory, WAL, engine, or namespace is touched.
    pub fn resolve_from_env() -> Result<Self, StorageFactoryError> {
        let profile = StorageFactory::resolve_from_env()?.profile();
        let context = Self::for_profile(profile)?;
        context.verify_process_consistency()?;
        Ok(context)
    }

    /// Build a context for an explicit profile (tests / injected
    /// configuration). Does NOT seed or consult the process witness — that
    /// belongs to the env admission path — but still refuses the
    /// not-yet-available lanes.
    pub fn for_profile(profile: StorageBackendProfile) -> Result<Self, StorageFactoryError> {
        let spec = BackendSpec::from_profile(profile)?;
        let backend = profile.storage_backend()?;
        let identity = BackendIdentity::resolve(&spec);
        Ok(Self { profile, spec, backend, identity })
    }

    /// The single OnceLock consistency check (R4-STOR-00): if the process
    /// witness exists and disagrees with this context's profile, the
    /// environment changed mid-process — a typed mismatch, never silent.
    /// The lower storage layers call this when handed a context, so even a
    /// mutant that re-resolves the environment somewhere below the admission
    /// point cannot mix two profiles against one tree.
    pub fn verify_process_consistency(&self) -> Result<(), StorageFactoryError> {
        let witness = *PROCESS_PROFILE_WITNESS.get_or_init(|| self.profile);
        if witness == self.profile {
            Ok(())
        } else {
            Err(StorageFactoryError::BackendContextChanged { cached: witness.code(), resolved: self.profile.code() })
        }
    }

    pub fn profile(&self) -> StorageBackendProfile {
        self.profile
    }

    pub fn spec(&self) -> &BackendSpec {
        &self.spec
    }

    pub fn backend(&self) -> StorageBackend {
        self.backend
    }

    pub fn identity(&self) -> &BackendIdentity {
        &self.identity
    }

    pub fn factory(&self) -> StorageFactory {
        StorageFactory::with_profile(self.profile)
    }
}

/// The durable, per-database backend identity (S-01, v17). This is the typed
/// choice a database is BOUND to at creation and re-verified at every open —
/// distinct from [`StorageBackendProfile`], which is conformance-runner
/// metadata (`TYPEDB_STORAGE_PROFILE` U0…U4) and MUST NOT be product
/// configuration.
///
/// The full identity derived from this spec ([`BackendIdentity`]) is persisted
/// atomically in the database directory and is the anchor that turns a
/// cross-engine or cross-configuration open from a silent data-loss hazard
/// (a fresh engine constructed beside the other backend's files, or the same
/// engine pointed at a different object namespace) into a typed refusal:
///
/// - opening with a **missing/ambiguous** marker on an existing tree is a typed
///   refusal that requires an explicit migration/import workflow;
/// - opening with a **mismatch** (kind, or ANY identity field — endpoint,
///   bucket, root prefix, materialisation policy, protocol version, …) is a
///   typed refusal BEFORE any filesystem, WAL, or object-namespace mutation.
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

/// The backend KIND discriminant — the coarsest identity component
/// (`classic` vs `slatedb-r2`), used both inside the full
/// [`BackendIdentity`] and to read legacy v1 markers that persisted only
/// this discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendMarker {
    Classic,
    SlateDbR2,
}

/// The file, inside the database directory, that records the durable backend
/// identity (S-01/R4-STOR-01). A sibling of the `storage/` subtree and the
/// WAL, written once at creation and immutable thereafter (the single
/// sanctioned exception is the one-time v1 → v2 in-place upgrade,
/// [`upgrade_backend_marker_to_v2`]).
pub const BACKEND_MARKER_FILE: &str = "backend-spec.marker";
/// Temp-file prefix for the atomic marker write; a random per-attempt suffix
/// is appended so two racing attempts can never open each other's temp file
/// (each opens with `create_new`).
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

    /// The kind discriminant for this spec.
    pub fn marker(&self) -> BackendMarker {
        match self {
            Self::Classic => BackendMarker::Classic,
            Self::SlateDbR2(_) => BackendMarker::SlateDbR2,
        }
    }
}

/// R4-STOR-01: the versioned, canonical backend identity a database directory
/// is durably bound to. Persisted as the v2 marker and re-verified — EVERY
/// field, not just the kind — before the WAL, local engine, or object store is
/// touched on an open. The same identity (its serialisation, digest included)
/// is bound into every checkpoint the database exports, so a cut created under
/// configuration A refuses restore under configuration B.
///
/// INVARIANT: only NON-SECRET identifiers are ever recorded here — endpoint,
/// bucket name, root prefix. Access keys / secrets never enter the identity,
/// its serialisation, or its digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendIdentity {
    /// Backend kind: `classic` (RocksDB) or `slatedb-r2`.
    pub kind: BackendMarker,
    /// Durability backend identifier (currently always the file WAL — the
    /// only lane whose durability authority exists).
    pub durability: String,
    /// SlateDB lanes only: which object store the data path speaks to.
    pub object_store_profile: Option<String>,
    /// SlateDB lanes only: materialisation mint/retire policy.
    pub materialisation_policy: Option<String>,
    /// SlateDB lanes only: read-cache posture (a profile-level policy, not a
    /// tunable byte budget — budgets may change between opens, policy not).
    pub cache_policy: Option<String>,
    /// SlateDB lanes only: remote namespace format version(s).
    pub protocol_versions: Option<String>,
    /// S3 lane only: object-store endpoint (non-secret binding identifier).
    pub endpoint: Option<String>,
    /// S3 lane only: bucket name (non-secret binding identifier).
    pub bucket: Option<String>,
    /// S3 lane only: root prefix inside the bucket.
    pub root_prefix: Option<String>,
}

/// v2 marker header. The version is part of the header line so a future
/// format change is a new header, never a silently reinterpreted file.
const BACKEND_IDENTITY_HEADER: &str = "backend-identity v2";

/// All current lanes pair their keyspace engine with the file WAL.
const DURABILITY_FILE_WAL: &str = "file-wal";

impl BackendIdentity {
    /// The identity fields derivable from the spec alone (no environment
    /// read): kind, durability backend, and the SlateDB policy fields.
    pub fn from_spec(spec: &BackendSpec) -> Self {
        let mut identity = Self {
            kind: spec.marker(),
            durability: DURABILITY_FILE_WAL.to_owned(),
            object_store_profile: None,
            materialisation_policy: None,
            cache_policy: None,
            protocol_versions: None,
            endpoint: None,
            bucket: None,
            root_prefix: None,
        };
        if let BackendSpec::SlateDbR2(slate) = spec {
            identity.object_store_profile = Some(slate.object_store_profile.to_owned());
            identity.materialisation_policy = Some(slate.materialisation_policy.to_owned());
            identity.cache_policy = Some(slate.cache_policy.to_owned());
            identity.protocol_versions = Some(slate.protocol_versions.to_owned());
        }
        identity
    }

    /// The full identity, including the NON-SECRET object-store binding for
    /// the S3 lane (endpoint, bucket, root prefix — read from the same
    /// environment the keyspace layer will bind to, at the ONE admission
    /// point). Secrets (access/secret keys) are deliberately never read here.
    pub fn resolve(spec: &BackendSpec) -> Self {
        let mut identity = Self::from_spec(spec);
        if let BackendSpec::SlateDbR2(slate) = spec {
            if slate.object_store_profile == "s3" {
                identity.endpoint = env::var(S3_ENDPOINT_ENV).ok();
                identity.bucket = env::var(S3_BUCKET_ENV).ok();
                // same default the keyspace layer applies (slate::s3_config)
                identity.root_prefix = Some(env::var(S3_PREFIX_ENV).unwrap_or_else(|_| "typedb".to_owned()));
            }
        }
        identity
    }

    /// The optional identity fields in their fixed canonical order, paired
    /// with their canonical field names. One order for serialisation,
    /// digesting, AND field-by-field verification.
    fn optional_fields(&self) -> [(&'static str, &Option<String>); 7] {
        [
            ("object-store", &self.object_store_profile),
            ("materialisation", &self.materialisation_policy),
            ("cache", &self.cache_policy),
            ("protocol", &self.protocol_versions),
            ("endpoint", &self.endpoint),
            ("bucket", &self.bucket),
            ("root-prefix", &self.root_prefix),
        ]
    }

    /// Canonical serialisation WITHOUT the digest line — the exact bytes the
    /// configuration digest is computed over.
    pub fn canonical_body(&self) -> String {
        let mut out = String::new();
        out.push_str(BACKEND_IDENTITY_HEADER);
        out.push('\n');
        out.push_str(&format!("kind {}\n", self.kind.tag()));
        out.push_str(&format!("durability {}\n", self.durability));
        for (field, value) in self.optional_fields() {
            if let Some(value) = value {
                out.push_str(&format!("{field} {value}\n"));
            }
        }
        out
    }

    /// SHA-256 (hex) over the canonical serialisation — the configuration
    /// digest bound into the marker and into every checkpoint.
    pub fn config_digest(&self) -> String {
        sha256::digest_hex(self.canonical_body().as_bytes())
    }

    /// The full v2 marker content: canonical body sealed by its digest line.
    pub fn serialise_marker(&self) -> String {
        format!("{}digest {}\n", self.canonical_body(), self.config_digest())
    }

    /// Parse persisted marker content. A bare `classic`/`slatedb-r2` line is
    /// the legacy v1 format (kind only); the v2 format requires the digest
    /// line to verify against the bytes it seals. Anything else — unknown
    /// header, unknown field, bad digest — is a typed refusal, never a guess.
    pub fn parse_marker(text: &str) -> Result<PersistedBackendMarker, StorageFactoryError> {
        if !text.starts_with(BACKEND_IDENTITY_HEADER) {
            // legacy v1: exactly one bare kind line.
            return match BackendMarker::parse(text) {
                Some(kind) => Ok(PersistedBackendMarker::V1 { kind }),
                None => Err(StorageFactoryError::BackendMarkerUnrecognised { value: text.trim().to_owned() }),
            };
        }
        // v2: the digest line is last and seals every byte before it.
        let digest_marker = "\ndigest ";
        let Some(index) = text.rfind(digest_marker) else {
            return Err(StorageFactoryError::BackendMarkerUnrecognised { value: "<v2 marker without digest>".to_owned() });
        };
        let body = &text[..index + 1]; // keep the newline that ends the body
        let persisted_digest = text[index + digest_marker.len()..].trim();
        let computed = sha256::digest_hex(body.as_bytes());
        if !computed.eq_ignore_ascii_case(persisted_digest) {
            return Err(StorageFactoryError::BackendMarkerDigestMismatch {
                persisted: persisted_digest.to_owned(),
                computed,
            });
        }
        let mut kind = None;
        let mut durability = None;
        let mut optionals: [Option<String>; 7] = Default::default();
        for line in body.lines().skip(1) {
            if line.is_empty() {
                continue;
            }
            let Some((field, value)) = line.split_once(' ') else {
                return Err(StorageFactoryError::BackendMarkerUnrecognised { value: line.to_owned() });
            };
            match field {
                "kind" => match BackendMarker::parse(value) {
                    Some(parsed) => kind = Some(parsed),
                    None => return Err(StorageFactoryError::BackendMarkerUnrecognised { value: value.to_owned() }),
                },
                "durability" => durability = Some(value.to_owned()),
                "object-store" => optionals[0] = Some(value.to_owned()),
                "materialisation" => optionals[1] = Some(value.to_owned()),
                "cache" => optionals[2] = Some(value.to_owned()),
                "protocol" => optionals[3] = Some(value.to_owned()),
                "endpoint" => optionals[4] = Some(value.to_owned()),
                "bucket" => optionals[5] = Some(value.to_owned()),
                "root-prefix" => optionals[6] = Some(value.to_owned()),
                // fail closed on an unknown field: a richer future format
                // must bump the header version, not smuggle fields past v2.
                unknown => {
                    return Err(StorageFactoryError::BackendMarkerUnrecognised { value: unknown.to_owned() });
                }
            }
        }
        let Some(kind) = kind else {
            return Err(StorageFactoryError::BackendMarkerUnrecognised { value: "<v2 marker without kind>".to_owned() });
        };
        let [object_store_profile, materialisation_policy, cache_policy, protocol_versions, endpoint, bucket, root_prefix] =
            optionals;
        Ok(PersistedBackendMarker::V2(BackendIdentity {
            kind,
            durability: durability.unwrap_or_default(),
            object_store_profile,
            materialisation_policy,
            cache_policy,
            protocol_versions,
            endpoint,
            bucket,
            root_prefix,
        }))
    }
}

/// What the database directory's marker file persists: either the legacy v1
/// kind-only discriminant, or the full v2 identity (R4-STOR-01).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistedBackendMarker {
    /// Legacy v1 marker: a bare `classic`/`slatedb-r2` line. Read-compatible;
    /// upgraded in place to v2 on the first open whose kind matches.
    V1 { kind: BackendMarker },
    /// The versioned full identity (v2).
    V2(BackendIdentity),
}

/// The verdict of a successful marker verification: whether the persisted
/// marker already carries the full v2 identity or is a verified legacy v1
/// that the caller should upgrade in place (the documented ONE-TIME upgrade).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerVerification {
    /// Full v2 identity verified field-by-field.
    V2Verified,
    /// A legacy v1 marker whose kind matches the resolved identity. The
    /// caller upgrades it to v2 via [`upgrade_backend_marker_to_v2`].
    LegacyV1Verified,
}

/// A per-attempt random suffix for the marker temp file, so racing attempts
/// never share a temp path (each then opens with `create_new`). Sourced from
/// the standard-library hasher's randomly-seeded keys — no non-dev `rand`
/// dependency is available to this crate.
fn marker_tmp_nonce() -> u64 {
    std::collections::hash_map::RandomState::new().build_hasher().finish()
}

/// Write the marker temp file (R4-STOR-02): `create_new` (never through an
/// existing file or symlink at the temp name), full write, then `sync_all`
/// so the CONTENT is durable before the caller publishes the NAME. The temp
/// file is removed on any failure — no strays.
fn write_marker_tmp(database_dir: &Path, identity: &BackendIdentity) -> io::Result<PathBuf> {
    let tmp = database_dir.join(format!("{BACKEND_MARKER_TMP}.{:016x}", marker_tmp_nonce()));
    let write = (|| {
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        file.write_all(identity.serialise_marker().as_bytes())?;
        file.sync_all()
    })();
    match write {
        Ok(()) => Ok(tmp),
        Err(error) => {
            let _ = fs::remove_file(&tmp);
            Err(error)
        }
    }
}

/// Persist the backend identity marker durably and atomically (S-01 /
/// R4-STOR-02). Invariants, in order:
///
/// 1. an EXISTING marker (or anything else at the marker path — including a
///    symlink, checked no-follow) is IMMUTABLE: refuse, never overwrite;
/// 2. the temp file is opened `create_new` under a random per-attempt name
///    and `sync_all`ed, so the bytes are durable before the name appears;
/// 3. publication is `hard_link(tmp, final)` — atomic create-new semantics:
///    if a marker appeared between the check in (1) and here, the link fails
///    with `AlreadyExists` (this closes the TOCTOU window a bare `rename`,
///    which silently replaces, would leave open);
/// 4. the parent directory is fsynced, so the marker's NAME survives a crash.
///
/// The temp file is removed on every path; a failed attempt leaves the
/// directory as it found it.
pub fn write_backend_marker(database_dir: &Path, identity: &BackendIdentity) -> io::Result<()> {
    let final_path = database_dir.join(BACKEND_MARKER_FILE);
    match fs::symlink_metadata(&final_path) {
        Ok(existing) => {
            let what = if existing.file_type().is_symlink() { "a symlink" } else { "an existing marker" };
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "refusing to write the backend marker at {final_path:?}: {what} is already present and \
                     markers are immutable (R4-STOR-02); never overwritten, never followed"
                ),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let tmp = write_marker_tmp(database_dir, identity)?;
    let published = fs::hard_link(&tmp, &final_path);
    // the temp name is removed on success AND failure; a failure to unlink it
    // is tolerated (a stray `.tmp.<nonce>` is inert — never read, never
    // published) rather than failing an already-durable publish.
    let _ = fs::remove_file(&tmp);
    published?;
    // durability of the NAME: fsync the directory that now holds the entry.
    crate::fsync_path(database_dir)
}

/// The ONE sanctioned marker replacement (R4-STOR-01): upgrade a VERIFIED
/// legacy v1 marker to the full v2 identity, in place, on first open. The
/// caller must hold a [`MarkerVerification::LegacyV1Verified`] verdict —
/// i.e. the v1 kind was already proven to match `identity.kind`. The replace
/// is atomic (synced temp + rename) and the existing marker is validated
/// no-follow first; every other overwrite of a marker remains forbidden.
pub fn upgrade_backend_marker_to_v2(database_dir: &Path, identity: &BackendIdentity) -> io::Result<()> {
    let final_path = database_dir.join(BACKEND_MARKER_FILE);
    let existing = fs::symlink_metadata(&final_path)?;
    if !existing.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("refusing to upgrade the backend marker at {final_path:?}: not a regular file (no-follow)"),
        ));
    }
    let tmp = write_marker_tmp(database_dir, identity)?;
    match fs::rename(&tmp, &final_path) {
        Ok(()) => crate::fsync_path(database_dir),
        Err(error) => {
            let _ = fs::remove_file(&tmp);
            Err(error)
        }
    }
}

/// Read the persisted backend marker (S-01/R4-STOR-01). `Ok(None)` means the
/// file is absent (an unmarked/ambiguous database — a migration case); an
/// unrecognised or digest-broken marker is a typed refusal, never a silent
/// default. The path is checked no-follow: a symlink at the marker path is
/// refused, not read through (R4-STOR-02).
pub fn read_backend_marker(database_dir: &Path) -> Result<Option<PersistedBackendMarker>, StorageFactoryError> {
    let path = database_dir.join(BACKEND_MARKER_FILE);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(StorageFactoryError::BackendMarkerRead { source: error.to_string() }),
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(StorageFactoryError::BackendMarkerRead {
                source: format!("the marker path {path:?} is a symlink; refusing to follow it (R4-STOR-02)"),
            });
        }
        Ok(meta) if !meta.file_type().is_file() => {
            return Err(StorageFactoryError::BackendMarkerRead {
                source: format!("the marker path {path:?} is not a regular file"),
            });
        }
        Ok(_) => {}
    }
    match fs::read_to_string(&path) {
        Ok(contents) => BackendIdentity::parse_marker(&contents).map(Some),
        Err(error) => Err(StorageFactoryError::BackendMarkerRead { source: error.to_string() }),
    }
}

/// The verdict of checking a resolved backend identity against an existing
/// database's persisted marker (S-01/R4-STOR-01). PURE: no filesystem effects
/// — the caller reads the marker and passes it in, so the verification is
/// testable and, crucially, happens BEFORE any WAL/storage touch on the open
/// path.
///
/// A v2 marker is compared FIELD BY FIELD (kind, durability backend,
/// object-store profile, materialisation policy, cache policy, protocol
/// version, endpoint, bucket, root prefix) and finally by configuration
/// digest; the first differing field is named in the typed refusal. A legacy
/// v1 marker can only prove its kind; a matching kind yields
/// [`MarkerVerification::LegacyV1Verified`] so the caller performs the
/// one-time in-place upgrade to v2.
pub fn verify_backend_marker(
    resolved: &BackendIdentity,
    persisted: Option<&PersistedBackendMarker>,
) -> Result<MarkerVerification, StorageFactoryError> {
    fn rendered(value: &Option<String>) -> String {
        value.clone().unwrap_or_else(|| "<unbound>".to_owned())
    }

    match persisted {
        None => Err(StorageFactoryError::BackendMarkerMissing),
        Some(PersistedBackendMarker::V1 { kind }) => {
            if *kind == resolved.kind {
                Ok(MarkerVerification::LegacyV1Verified)
            } else {
                Err(StorageFactoryError::BackendMarkerMismatch {
                    persisted: kind.tag(),
                    resolved: resolved.kind.tag(),
                })
            }
        }
        Some(PersistedBackendMarker::V2(identity)) => {
            if identity.kind != resolved.kind {
                return Err(StorageFactoryError::BackendMarkerMismatch {
                    persisted: identity.kind.tag(),
                    resolved: resolved.kind.tag(),
                });
            }
            if identity.durability != resolved.durability {
                return Err(StorageFactoryError::BackendIdentityFieldMismatch {
                    field: "durability",
                    persisted: identity.durability.clone(),
                    resolved: resolved.durability.clone(),
                });
            }
            for ((field, persisted_value), (_, resolved_value)) in
                identity.optional_fields().iter().zip(resolved.optional_fields().iter())
            {
                if persisted_value != resolved_value {
                    return Err(StorageFactoryError::BackendIdentityFieldMismatch {
                        field,
                        persisted: rendered(persisted_value),
                        resolved: rendered(resolved_value),
                    });
                }
            }
            // belt-and-braces: with every field equal the digests are equal by
            // construction, but the comparison stays so a future field added
            // to the canonical body cannot silently escape verification.
            if identity.config_digest() != resolved.config_digest() {
                return Err(StorageFactoryError::BackendIdentityFieldMismatch {
                    field: "config-digest",
                    persisted: identity.config_digest(),
                    resolved: resolved.config_digest(),
                });
            }
            Ok(MarkerVerification::V2Verified)
        }
    }
}

/// Minimal, dependency-free SHA-256 (FIPS 180-4), used solely to derive the
/// NON-SECRET backend-identity configuration digest (R4-STOR-01). This crate
/// deliberately carries no cryptographic-hash dependency; the reference
/// implementation below is pinned by the standard test vectors.
mod sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
        0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
        0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    const H0: [u32; 8] =
        [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

    pub(super) fn digest_hex(data: &[u8]) -> String {
        let mut h = H0;
        let bit_length = (data.len() as u64).wrapping_mul(8);
        let mut message = data.to_vec();
        message.push(0x80);
        while message.len() % 64 != 56 {
            message.push(0);
        }
        message.extend_from_slice(&bit_length.to_be_bytes());
        for block in message.chunks_exact(64) {
            let mut w = [0u32; 64];
            for (i, word) in block.chunks_exact(4).enumerate() {
                w[i] = u32::from_be_bytes(word.try_into().expect("4-byte chunk"));
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);
                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }
            h = [
                h[0].wrapping_add(a),
                h[1].wrapping_add(b),
                h[2].wrapping_add(c),
                h[3].wrapping_add(d),
                h[4].wrapping_add(e),
                h[5].wrapping_add(f),
                h[6].wrapping_add(g),
                h[7].wrapping_add(hh),
            ];
        }
        h.iter().map(|word| format!("{word:08x}")).collect()
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
    /// R4-STOR-00: the process already resolved a different backend profile —
    /// the environment changed mid-process. Two engines against one tree is
    /// corruption; the change is a typed refusal, never honoured silently.
    BackendContextChanged {
        cached: &'static str,
        resolved: &'static str,
    },
    /// S-01: the existing database carries no backend marker — it is ambiguous
    /// and must not be opened by silently constructing a fresh engine beside
    /// the other backend's files. Requires an explicit migration/import.
    BackendMarkerMissing,
    /// S-01: the persisted marker names a different backend KIND than the one
    /// resolved for this open. A typed refusal BEFORE any touch — never a
    /// cross-engine open.
    BackendMarkerMismatch {
        persisted: &'static str,
        resolved: &'static str,
    },
    /// R4-STOR-01: the persisted identity and the resolved identity share the
    /// kind but differ in a configuration field (endpoint, bucket, prefix,
    /// policy, protocol, …). Reconfiguring a database requires a typed
    /// migration/export-import, never an environment switch.
    BackendIdentityFieldMismatch {
        field: &'static str,
        persisted: String,
        resolved: String,
    },
    /// R4-STOR-01: the v2 marker's digest line does not seal its own bytes —
    /// the marker is corrupt or hand-edited; fail closed.
    BackendMarkerDigestMismatch {
        persisted: String,
        computed: String,
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
            Self::BackendContextChanged { cached, resolved } => {
                write!(
                    f,
                    "refusing to open: this process first resolved storage backend profile '{cached}', but the \
                     environment now resolves '{resolved}' (R4-STOR-00). A mid-process profile change would let \
                     two engines write one storage tree; the open is refused with the tree untouched."
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
            Self::BackendIdentityFieldMismatch { field, persisted, resolved } => {
                write!(
                    f,
                    "refusing to open: the database's persisted backend identity differs from the resolved \
                     configuration in the '{field}' field (persisted '{persisted}', resolved '{resolved}') \
                     (R4-STOR-01). Changing a database's backend configuration requires an explicit typed \
                     migration/export-import, never an environment switch."
                )
            }
            Self::BackendMarkerDigestMismatch { persisted, computed } => {
                write!(
                    f,
                    "refusing to open: the backend marker's digest line '{persisted}' does not match its own \
                     content (computed '{computed}') (R4-STOR-01); the marker is corrupt"
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
            | Self::BackendContextChanged { .. }
            | Self::BackendMarkerMissing
            | Self::BackendMarkerMismatch { .. }
            | Self::BackendIdentityFieldMismatch { .. }
            | Self::BackendMarkerDigestMismatch { .. }
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

    #[test]
    fn a_context_for_a_not_yet_available_lane_refuses_at_construction() {
        // R4-STOR-00: the immutable context is where admission happens; the
        // U3/U4 lanes refuse while the context is being built, before any
        // caller could thread it anywhere.
        for profile in [StorageBackendProfile::U3SlateRemoteSim, StorageBackendProfile::U4ProductionRemote] {
            assert!(matches!(
                super::BackendContext::for_profile(profile),
                Err(StorageFactoryError::BackendNotYetAvailable { .. })
            ));
        }
    }
}

#[cfg(test)]
mod sha256_tests {
    //! The dependency-free SHA-256 is pinned by the FIPS 180-4 test vectors:
    //! a digest that drifts would silently invalidate every persisted
    //! identity, so the reference vectors are load-bearing.

    use super::sha256::digest_hex;

    #[test]
    fn the_standard_test_vectors_hold() {
        assert_eq!(digest_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(digest_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            digest_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }
}

#[cfg(test)]
mod backend_identity_tests {
    //! R4-STOR-01: the persisted marker is a versioned FULL identity — every
    //! configuration field is verified at open, a legacy v1 marker upgrades
    //! in place exactly once, and any field or digest drift is a typed
    //! refusal naming the differing field.

    use test_utils::create_tmp_dir;

    use super::{
        BackendIdentity, BackendMarker, BackendSpec, MarkerVerification, PersistedBackendMarker,
        StorageBackendProfile, StorageFactoryError, read_backend_marker, upgrade_backend_marker_to_v2,
        verify_backend_marker, write_backend_marker,
    };

    fn slate_s3_identity() -> BackendIdentity {
        let mut identity =
            BackendIdentity::from_spec(&BackendSpec::from_profile(StorageBackendProfile::U2S3SlateS3FileWal).unwrap());
        identity.endpoint = Some("https://minio.local:9000".to_owned());
        identity.bucket = Some("typedb-conformance".to_owned());
        identity.root_prefix = Some("typedb".to_owned());
        identity
    }

    #[test]
    fn a_v2_identity_round_trips_through_the_marker() {
        let dir = create_tmp_dir("identity-roundtrip");
        let identity = slate_s3_identity();
        write_backend_marker(&dir, &identity).unwrap();
        let persisted = read_backend_marker(&dir).unwrap().expect("marker present");
        assert_eq!(persisted, PersistedBackendMarker::V2(identity.clone()));
        assert_eq!(verify_backend_marker(&identity, Some(&persisted)).unwrap(), MarkerVerification::V2Verified);
        // and no temp file survives the atomic publish
        let strays: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp"))
            .collect();
        assert!(strays.is_empty(), "no marker temp file may outlive the publish: {strays:?}");
    }

    #[test]
    fn every_differing_identity_field_is_a_typed_refusal_naming_the_field() {
        let persisted_identity = slate_s3_identity();
        let persisted = PersistedBackendMarker::V2(persisted_identity.clone());
        for (field, mutate) in [
            ("endpoint", Box::new(|id: &mut BackendIdentity| id.endpoint = Some("https://other:9000".into()))
                as Box<dyn Fn(&mut BackendIdentity)>),
            ("bucket", Box::new(|id: &mut BackendIdentity| id.bucket = Some("other-bucket".into()))),
            ("root-prefix", Box::new(|id: &mut BackendIdentity| id.root_prefix = Some("elsewhere".into()))),
            ("materialisation", Box::new(|id: &mut BackendIdentity| id.materialisation_policy = Some("in-place".into()))),
            ("protocol", Box::new(|id: &mut BackendIdentity| id.protocol_versions = Some("fv2".into()))),
            ("object-store", Box::new(|id: &mut BackendIdentity| id.object_store_profile = Some("local-fs".into()))),
            ("durability", Box::new(|id: &mut BackendIdentity| id.durability = "remote-wal".into())),
        ] {
            let mut resolved = persisted_identity.clone();
            mutate(&mut resolved);
            let refused = verify_backend_marker(&resolved, Some(&persisted));
            assert!(
                matches!(&refused, Err(StorageFactoryError::BackendIdentityFieldMismatch { field: named, .. }) if *named == field),
                "a differing '{field}' must be a typed field-mismatch refusal, got: {refused:?}",
            );
        }
    }

    #[test]
    fn a_kind_mismatch_is_the_cross_engine_refusal() {
        let classic = BackendIdentity::from_spec(&BackendSpec::Classic);
        let slate = slate_s3_identity();
        let refused = verify_backend_marker(&classic, Some(&PersistedBackendMarker::V2(slate)));
        assert!(matches!(
            refused,
            Err(StorageFactoryError::BackendMarkerMismatch { persisted: "slatedb-r2", resolved: "classic" })
        ));
    }

    #[test]
    fn a_tampered_marker_digest_is_a_typed_refusal() {
        let dir = create_tmp_dir("identity-tamper");
        let identity = slate_s3_identity();
        // hand-edit a field after the digest sealed the body
        let tampered = identity.serialise_marker().replace("typedb-conformance", "attacker-bucket");
        std::fs::write(dir.join(super::BACKEND_MARKER_FILE), tampered).unwrap();
        let refused = read_backend_marker(&dir);
        assert!(
            matches!(refused, Err(StorageFactoryError::BackendMarkerDigestMismatch { .. })),
            "an edited v2 marker must fail its own digest, got: {refused:?}",
        );
    }

    #[test]
    fn a_legacy_v1_marker_verifies_by_kind_and_upgrades_in_place_once() {
        let dir = create_tmp_dir("identity-v1-upgrade");
        // a database created before R4-STOR-01: bare kind line
        std::fs::write(dir.join(super::BACKEND_MARKER_FILE), b"classic").unwrap();
        let persisted = read_backend_marker(&dir).unwrap().expect("marker present");
        assert_eq!(persisted, PersistedBackendMarker::V1 { kind: BackendMarker::Classic });

        let resolved = BackendIdentity::from_spec(&BackendSpec::Classic);
        // matching kind: verified as legacy, prompting the one-time upgrade
        assert_eq!(
            verify_backend_marker(&resolved, Some(&persisted)).unwrap(),
            MarkerVerification::LegacyV1Verified
        );
        upgrade_backend_marker_to_v2(&dir, &resolved).unwrap();
        // after the upgrade the marker is the full v2 identity
        let upgraded = read_backend_marker(&dir).unwrap().expect("marker present");
        assert_eq!(upgraded, PersistedBackendMarker::V2(resolved.clone()));
        assert_eq!(verify_backend_marker(&resolved, Some(&upgraded)).unwrap(), MarkerVerification::V2Verified);

        // and a v1 marker with the WRONG kind never upgrades — it is the
        // cross-engine refusal
        let slate_resolved = slate_s3_identity();
        let refused = verify_backend_marker(&slate_resolved, Some(&persisted));
        assert!(matches!(refused, Err(StorageFactoryError::BackendMarkerMismatch { .. })));
    }

    #[test]
    fn an_existing_marker_is_never_overwritten() {
        let dir = create_tmp_dir("identity-immutable");
        let original = BackendIdentity::from_spec(&BackendSpec::Classic);
        write_backend_marker(&dir, &original).unwrap();
        let before = std::fs::read(dir.join(super::BACKEND_MARKER_FILE)).unwrap();

        let refused = write_backend_marker(&dir, &slate_s3_identity());
        assert!(refused.is_err(), "R4-STOR-02: an existing marker is immutable");
        assert_eq!(refused.unwrap_err().kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(dir.join(super::BACKEND_MARKER_FILE)).unwrap(),
            before,
            "the existing marker's bytes must be untouched by the refused write",
        );
    }

    #[test]
    fn a_symlink_at_the_marker_path_is_refused_by_write_and_read() {
        let dir = create_tmp_dir("identity-symlink");
        let target = dir.join("elsewhere");
        std::fs::write(&target, b"classic").unwrap();
        std::os::unix::fs::symlink(&target, dir.join(super::BACKEND_MARKER_FILE)).unwrap();

        // write: refuse (no-follow, immutable) — and never write THROUGH the link
        let refused = write_backend_marker(&dir, &BackendIdentity::from_spec(&BackendSpec::Classic));
        assert!(refused.is_err(), "a symlink at the marker path must refuse the write");
        assert_eq!(std::fs::read(&target).unwrap(), b"classic", "the symlink target must be untouched");

        // read: refuse (no-follow), never read through the link
        let refused = read_backend_marker(&dir);
        assert!(
            matches!(refused, Err(StorageFactoryError::BackendMarkerRead { .. })),
            "a symlink at the marker path must refuse the read, got: {refused:?}",
        );
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
        BackendIdentity, BackendMarker, BackendSpec, PersistedBackendMarker, StorageBackendProfile,
        StorageFactoryError, read_backend_marker, verify_backend_marker, write_backend_marker,
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
        let identity = BackendIdentity::from_spec(&BackendSpec::Classic);
        write_backend_marker(&dir, &identity).unwrap();
        assert_eq!(read_backend_marker(&dir).unwrap(), Some(PersistedBackendMarker::V2(identity)));
        // and no stray temp file is left behind by the atomic publish
        let strays: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp"))
            .collect();
        assert!(strays.is_empty(), "the atomic publish must leave no temp file: {strays:?}");
    }

    #[test]
    fn a_missing_marker_on_an_existing_database_is_a_migration_refusal() {
        // verify against an existing tree that carries no marker.
        let refused = verify_backend_marker(&BackendIdentity::from_spec(&BackendSpec::Classic), None);
        assert!(
            matches!(refused, Err(StorageFactoryError::BackendMarkerMissing)),
            "a marker-less database must refuse with a migration error, got: {refused:?}",
        );
    }

    #[test]
    fn a_classic_database_cannot_be_opened_as_slatedb_and_vice_versa() {
        let slate_spec = BackendSpec::from_profile(StorageBackendProfile::U2SlateLocalFs).unwrap();
        let slate = BackendIdentity::from_spec(&slate_spec);
        let classic = BackendIdentity::from_spec(&BackendSpec::Classic);
        // classic marker, slatedb resolved -> mismatch
        let persisted_classic = PersistedBackendMarker::V2(classic.clone());
        let refused = verify_backend_marker(&slate, Some(&persisted_classic));
        assert!(
            matches!(
                refused,
                Err(StorageFactoryError::BackendMarkerMismatch { persisted: "classic", resolved: "slatedb-r2" })
            ),
            "opening a classic database as slatedb must be a typed mismatch refusal, got: {refused:?}",
        );
        // slatedb marker, classic resolved -> mismatch (the converse)
        let persisted_slate = PersistedBackendMarker::V2(slate.clone());
        let refused = verify_backend_marker(&classic, Some(&persisted_slate));
        assert!(
            matches!(
                refused,
                Err(StorageFactoryError::BackendMarkerMismatch { persisted: "slatedb-r2", resolved: "classic" })
            ),
            "opening a slatedb database as classic must be a typed mismatch refusal, got: {refused:?}",
        );
        // and the matching case is admitted
        assert!(verify_backend_marker(&slate, Some(&persisted_slate)).is_ok());
        assert!(verify_backend_marker(&classic, Some(&persisted_classic)).is_ok());
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
