/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! TB-P7: SlateDB-backed keyspace engine for the U2 conformance profile.
//!
//! SlateDB is consumed unmodified from crates.io (ADR-0001); this module is
//! the entire adapter. The engine contract it implements is the one the
//! RocksDB keyspaces already satisfy:
//!
//! - **Non-durable KV**: SlateDB's own WAL is disabled (`wal_enabled: false`,
//!   mirroring the RocksDB `disable_wal(true)` write options). TypeDB's WAL
//!   is the sole durability authority; on reopen without a checkpoint the
//!   storage directory is rebuilt from the TypeDB WAL, and checkpoints flush
//!   the memtable before copying files.
//! - **Committed-memory-visible reads** (V16 inv. 74/75): writes go to the
//!   memtable with `await_durable: false`; every read/scan uses the resolved
//!   `DurabilityLevel::Memory` + `dirty: false` options, so a COMMITTED
//!   write is visible to the very next read exactly as with RocksDB, while a
//!   batch still inside the write pipeline is invisible to every reader.
//! - **No background rewrites**: the in-process compactor and garbage
//!   collector are disabled (ADR-0001's SL-P2/SL-P3 posture), so between
//!   flushes the on-disk object store is quiescent and a post-flush file copy
//!   is a consistent checkpoint.
//!
//! Sync bridge: storage calls are synchronous; SlateDB is async. One
//! process-wide Tokio runtime (brief §12.7) executes every SlateDB future;
//! callers block on a plain std channel, which is safe on any thread —
//! including Tokio worker threads, where `Handle::block_on` would panic.

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use async_trait::async_trait;
use futures::stream::BoxStream;
use slatedb::{
    Db, DbIterator, WriteBatch as SlateWriteBatch,
    bytes::Bytes as SlateBytes,
    config::{ReadOptions, ScanOptions, Settings, WriteOptions},
    object_store::{
        CopyMode, CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
        ObjectStoreExt, PutMultipartOptions, PutOptions, PutPayload, PutResult, RenameOptions, aws::AmazonS3Builder,
        local::LocalFileSystem, path::Path as ObjectPath, prefix::PrefixStore,
    },
};

/// One process-wide storage runtime for every SlateDB keyspace.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("typedb-slate-storage")
            .enable_all()
            .build()
            .expect("failed to start the SlateDB storage runtime")
    })
}

/// Run a SlateDB future to completion from synchronous code.
///
/// The future is spawned onto the storage runtime and the calling thread
/// blocks on a std channel. Unlike `Handle::block_on`, this cannot panic when
/// the caller is itself on a Tokio worker thread (the server's network
/// runtime); it blocks that thread exactly as the equivalent RocksDB syscall
/// would.
fn bridge<T: Send + 'static>(future: impl std::future::Future<Output = T> + Send + 'static) -> T {
    // Q-13/Q-23 containment: the bridge is BOUNDED. It used to block the
    // calling thread forever; combined with unbounded lower-layer retries
    // that made an object-store outage a silent, undiagnosable hang. The
    // wait now reports every 30s and fail-stops at the deadline - a task
    // stuck this long is a wedged storage runtime, and neither returning
    // garbage nor waiting forever is sound. Caller-side cancellation is the
    // OPEN remainder (it needs fallible signatures up the read stack).
    // Deadline: containment default, owner decision OD-006.
    const REPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
    const DEADLINE: std::time::Duration = std::time::Duration::from_secs(600);
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    runtime().spawn(async move {
        // a dropped receiver means the caller thread died; nothing to do
        let _ = sender.send(future.await);
    });
    let started = std::time::Instant::now();
    loop {
        match receiver.recv_timeout(REPORT_INTERVAL) {
            Ok(value) => return value,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let waited = started.elapsed();
                if waited >= DEADLINE {
                    logger::error!(
                        "FATAL: a SlateDB storage task has not completed after {}s. The storage \
                         runtime is wedged (object store unreachable past its bounded retries, or \
                         a task deadlock); blocking further is indistinguishable from a hang and \
                         returning without a result is unsound. Aborting so recovery restarts \
                         from the durability log.",
                        waited.as_secs(),
                    );
                    std::process::abort()
                }
                logger::error!(
                    "a SlateDB storage task is still running after {}s (deadline {}s)",
                    waited.as_secs(),
                    DEADLINE.as_secs(),
                );
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("SlateDB storage task terminated without a result (panicked?)")
            }
        }
    }
}

fn write_options() -> WriteOptions {
    WriteOptions { await_durable: false, ..Default::default() }
}

fn read_options() -> ReadOptions {
    // The committed-memory-visible contract (V16 inv. 74): the defaults are
    // exactly `DurabilityLevel::Memory` + `dirty: false`, i.e. reads see the
    // last COMMITTED sequence — a batch whose `write_with_options` call has
    // returned — and never a batch still inside the write pipeline. `dirty:
    // true` would additionally expose rows with sequence numbers beyond the
    // committed frontier (a concurrent batch mid-commit), breaking the
    // atomicity TypeDB's commit relies on. Read-your-writes (inv. 75) does
    // NOT need dirty reads: SlateDB advances the committed sequence inside
    // the write path before `write_with_options` resolves — proved by the
    // paused-pre-commit negative control below. No caller can override
    // these options; every read/scan in this module resolves them here.
    ReadOptions::default()
}

fn scan_options() -> ScanOptions {
    ScanOptions::default()
}

/// Pre-G13 posture attestation (F5 interim enforcement; donor idea ported
/// after review, audit F11): the settings every open uses MUST attest the
/// disposable-store posture - SlateDB WAL off (TypeDB's durability crate is
/// the sole WAL authority), in-process compactor off (compaction is a
/// reachability mutation and must be externally epoch-fenced - ADR-0012's
/// fork lands that), garbage collector off (pre-G13 GC is report-only).
/// A violation is a typed open refusal listing every failed clause - config
/// drift can never silently re-enable a background rewriter. The other two
/// posture clauses are enforced structurally elsewhere: committed-only
/// reads by the hard-resolved read options (read_contract_tests), no delete
/// authority by [`NoDeleteStore`] (materialization_tests).
fn assert_pre_g13_posture(settings: &Settings) -> Result<(), slatedb::Error> {
    let mut violations = Vec::new();
    if settings.wal_enabled {
        violations.push("SlateDB WAL is enabled; TypeDB's WAL is the sole durability authority");
    }
    if settings.compactor_options.is_some() {
        violations.push("in-process compactor is enabled; compaction must be externally epoch-fenced (ADR-0012)");
    }
    if settings.garbage_collector_options.is_some() {
        violations.push("garbage collector is enabled; pre-G13 GC is report-only (inv. 105)");
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(slatedb::Error::unavailable(format!(
            "pre-G13 posture violation refused at open: {}",
            violations.join("; ")
        )))
    }
}

fn settings() -> Settings {
    let mut settings = Settings::default();
    settings.wal_enabled = false;
    settings.flush_interval = None;
    settings.compactor_options = None;
    settings.garbage_collector_options = None;
    settings.compression_codec = None;
    // With the compactor disabled, L0 only ever grows; the default
    // l0_max_ssts=8 backpressure would permanently stall memtable flush
    // dispatch (and eventually every put) once reached. Trade read
    // amplification for liveness — the same posture SlateDB's own
    // compactor-less tests take (settings.l0_max_ssts = 10_000).
    settings.l0_max_ssts = 1_000_000;
    settings.l0_max_ssts_per_key = 1_000_000;
    // Q-13: SlateDB's wrapper-level object-store retries default to None,
    // which is documented as "retry transient errors indefinitely". An
    // infinite lower-layer retry converts an outage into a silent hang that
    // no caller deadline can see past. Bounded here; the exhausted error
    // surfaces through the fallible seam and get_prev's own bounded retry
    // policy decides what is transient (A10). Containment default, not an
    // SLO (docs/owner-decisions.json OD-006).
    settings.object_store_max_retries = Some(8);
    settings
}

/// The SlateDB store subtree under a keyspace root: LocalFS keyspaces put it
/// under `<keyspace-dir>/keyspace/`, S3 keyspaces under
/// `<materialisation-prefix>/keyspace/` — one name, both lanes.
const DB_SUBDIR: &str = "keyspace";
const MANIFEST_SUBDIR: &str = "manifest";

/// Remote namespace format version (V16 F3): a layout change mints a new
/// segment instead of ever rewriting bytes under an old one.
const FORMAT_VERSION_SEGMENT: &str = "fv1";

/// Local file (inside the keyspace lifecycle-marker dir) recording the
/// materialisation this open is writing to — diagnostics and GC-report
/// input, never uploaded and never authoritative for the remote side.
const MATERIALIZATION_FILE: &str = "materialization";

/// Mint a fresh materialisation id: time-ordered (zero-padded hex
/// nanoseconds first, so listings sort oldest-first), made unique across
/// processes by pid + a per-process random seed + a per-process counter.
/// In the production design this id is minted and activated by the
/// controller (inv. 81); on the single-actor local lanes the opener mints
/// it, and uniqueness — not coordination — is all the lane needs.
fn mint_materialization_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    static SEED: OnceLock<u64> = OnceLock::new();
    let seed = *SEED.get_or_init(|| {
        use std::hash::{BuildHasher, Hasher};
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u32(std::process::id());
        hasher.finish()
    });
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("m{nanos:024x}-{:08x}-{seed:016x}-{count:04x}", std::process::id())
}

/// U2S3 profile configuration (TB-P8): every variable is required except
/// region (default `auto`, the R2 convention) and the root prefix (default
/// `typedb`). Missing values are a typed open error — fail closed, never a
/// silent fallback to another store.
pub const S3_ENDPOINT_ENV: &str = "TYPEDB_S3_ENDPOINT";
pub const S3_BUCKET_ENV: &str = "TYPEDB_S3_BUCKET";
pub const S3_REGION_ENV: &str = "TYPEDB_S3_REGION";
pub const S3_ACCESS_KEY_ENV: &str = "TYPEDB_S3_ACCESS_KEY_ID";
pub const S3_SECRET_KEY_ENV: &str = "TYPEDB_S3_SECRET_ACCESS_KEY";
pub const S3_PREFIX_ENV: &str = "TYPEDB_S3_PREFIX";
/// Optional local disk cache budget (bytes) for remote SST reads. Unset or 0
/// disables the cache. When set, SlateDB's CachedObjectStore keeps part files
/// under `<keyspace-dir>/object-cache/` — INSIDE the lifecycle marker, so the
/// disposable-store contract wipes it with the keyspace dir; a cache that
/// outlived the open-time remote purge would serve stale bytes for reused
/// object paths.
pub const S3_CACHE_BYTES_ENV: &str = "TYPEDB_S3_CACHE_BYTES";

/// Local disk-cache subtree inside the keyspace dir (never uploaded, and
/// wiped at open as defense in depth).
const OBJECT_CACHE_SUBDIR: &str = "object-cache";

struct S3Config {
    endpoint: String,
    bucket: String,
    region: String,
    access_key_id: String,
    secret_access_key: String,
    root_prefix: String,
}

/// Resolved once per process, like the backend profile itself: two opens
/// racing different S3 configurations against one prefix would corrupt it.
fn s3_config() -> Result<&'static S3Config, slatedb::Error> {
    static CONFIG: OnceLock<Result<S3Config, String>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let require = |variable: &str| {
                std::env::var(variable).map_err(|_| format!("{variable} must be set for the U2S3 storage profile"))
            };
            Ok(S3Config {
                endpoint: require(S3_ENDPOINT_ENV)?,
                bucket: require(S3_BUCKET_ENV)?,
                region: std::env::var(S3_REGION_ENV).unwrap_or_else(|_| "auto".to_owned()),
                access_key_id: require(S3_ACCESS_KEY_ENV)?,
                secret_access_key: require(S3_SECRET_KEY_ENV)?,
                root_prefix: std::env::var(S3_PREFIX_ENV).unwrap_or_else(|_| "typedb".to_owned()),
            })
        })
        .as_ref()
        .map_err(|message| slatedb::Error::unavailable(message.clone()))
}

/// Optional disk-cache budget: unset, unparsable or 0 disables the cache
/// (misconfiguration degrades to remote reads, never to a wrong cache).
fn s3_cache_bytes() -> Option<usize> {
    let raw = std::env::var(S3_CACHE_BYTES_ENV).ok()?;
    match raw.trim().parse::<usize>() {
        Ok(0) | Err(_) => None,
        Ok(bytes) => Some(bytes),
    }
}

fn build_s3_store(config: &S3Config) -> Result<Arc<dyn ObjectStore>, slatedb::Error> {
    // Conditional put stays on the 0.14.1 default (`ETagMatch`): both MinIO
    // and Cloudflare R2 implement the standard HTTP preconditions SlateDB's
    // manifest CAS requires.
    AmazonS3Builder::new()
        .with_endpoint(config.endpoint.clone())
        .with_allow_http(config.endpoint.starts_with("http://"))
        .with_bucket_name(config.bucket.clone())
        .with_region(config.region.clone())
        .with_access_key_id(config.access_key_id.clone())
        .with_secret_access_key(config.secret_access_key.clone())
        .build()
        .map(|store| Arc::new(store) as Arc<dyn ObjectStore>)
        .map_err(store_error)
}

/// Map the absolute local keyspace directory to its object-store prefix:
/// `<root>/<encoded absolute path>`. The encoding is injective (`=` is the
/// only escape: `=s` for `/`, `==` for `=`, `=xHH` for anything outside
/// `[A-Za-z0-9._-]`), so two distinct keyspace directories can never share a
/// prefix, and the prefix of a reopened directory is stable.
fn object_prefix(config: &S3Config, keyspace_path: &Path) -> ObjectPath {
    let mut encoded = String::new();
    for ch in keyspace_path.to_string_lossy().chars() {
        match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' => encoded.push(ch),
            '/' => encoded.push_str("=s"),
            '=' => encoded.push_str("=="),
            other => {
                let mut buffer = [0u8; 4];
                for byte in other.encode_utf8(&mut buffer).bytes() {
                    encoded.push_str(&format!("=x{byte:02x}"));
                }
            }
        }
    }
    ObjectPath::from(config.root_prefix.as_str()).join(encoded)
}

fn store_error(error: slatedb::object_store::Error) -> slatedb::Error {
    slatedb::Error::unavailable(format!("keyspace object store: {error}"))
}

/// List every object under `prefix` (iterative multi-level
/// `list_with_delimiter` walk — no stream combinators needed).
async fn list_remote_prefix(store: &dyn ObjectStore, prefix: &ObjectPath) -> Result<Vec<ObjectMeta>, slatedb::Error> {
    let mut pending = vec![prefix.clone()];
    let mut objects = Vec::new();
    while let Some(level) = pending.pop() {
        let listing = store.list_with_delimiter(Some(&level)).await.map_err(store_error)?;
        objects.extend(listing.objects);
        pending.extend(listing.common_prefixes);
    }
    Ok(objects)
}

/// The runtime storage principal, with delete authority structurally removed
/// (V16 inv. 84: before G13 no reachable code path may delete remote
/// objects, and "mere symbol absence is not proof" — this wrapper turns the
/// requirement into a runtime boundary that a probe can exercise). Every
/// remote store the engine touches is wrapped before first use, so a future
/// code path — or SlateDB itself, should a background component ever be
/// misconfigured back on — gets a typed `NotImplemented` error instead of a
/// deletion. `delete_stream` is the trait's ONLY delete primitive in
/// object_store 0.14 (`ObjectStoreExt::delete` and `rename`'s
/// copy-then-delete default both funnel into it), so denying it denies
/// every deletion path transitively.
#[derive(Debug)]
struct NoDeleteStore {
    inner: Arc<dyn ObjectStore>,
}

impl NoDeleteStore {
    fn new(inner: Arc<dyn ObjectStore>) -> Self {
        Self { inner }
    }
}

impl std::fmt::Display for NoDeleteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NoDeleteStore({})", self.inner)
    }
}

#[async_trait]
impl ObjectStore for NoDeleteStore {
    async fn put_opts(
        &self,
        location: &ObjectPath,
        payload: PutPayload,
        opts: PutOptions,
    ) -> slatedb::object_store::Result<PutResult> {
        self.inner.put_opts(location, payload, opts).await
    }

    async fn put_multipart_opts(
        &self,
        location: &ObjectPath,
        opts: PutMultipartOptions,
    ) -> slatedb::object_store::Result<Box<dyn MultipartUpload>> {
        self.inner.put_multipart_opts(location, opts).await
    }

    async fn get_opts(&self, location: &ObjectPath, options: GetOptions) -> slatedb::object_store::Result<GetResult> {
        self.inner.get_opts(location, options).await
    }

    fn list(&self, prefix: Option<&ObjectPath>) -> BoxStream<'static, slatedb::object_store::Result<ObjectMeta>> {
        self.inner.list(prefix)
    }

    async fn list_with_delimiter(&self, prefix: Option<&ObjectPath>) -> slatedb::object_store::Result<ListResult> {
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy_opts(
        &self,
        from: &ObjectPath,
        to: &ObjectPath,
        options: CopyOptions,
    ) -> slatedb::object_store::Result<()> {
        // Q-27 remainder: copies are CREATE-ONLY through the runtime
        // principal. An overwrite-mode copy is a delete of the destination's
        // bytes wearing a copy's name - under the immutable materialisation
        // posture (inv. 81-83) no runtime path may replace existing
        // authoritative bytes, and refusing here means a misrouted copy
        // fails closed instead of clobbering. Create-mode copies (the only
        // kind the checkpoint paths issue) pass through and collide safely
        // on the inner store's precondition.
        if !matches!(options.mode, CopyMode::Create) {
            return Err(slatedb::object_store::Error::NotImplemented {
                operation: format!(
                    "copy {from} -> {to} in overwrite mode (V16 inv. 81-83: the runtime storage \
                     principal must not replace existing authoritative bytes; use create mode)"
                ),
                implementer: "NoDeleteStore".to_owned(),
            });
        }
        self.inner.copy_opts(from, to, options).await
    }

    /// Q-27: refuse the composite BEFORE its copy half runs.
    ///
    /// `ObjectStore`'s default `rename_opts` is `copy_opts(from, to)` then
    /// `delete(from)`. Denying only `delete_stream` therefore denies the
    /// deletion but not the copy: the rename returns an error while a full
    /// duplicate of the object has already landed at the destination, and
    /// the caller believes nothing happened. Under the immutable
    /// materialisation posture that stray object is exactly what must not
    /// exist - a second copy of authoritative bytes under a name nobody
    /// activated. Refusing here means a blocked rename leaves the store
    /// byte-identical.
    async fn rename_opts(
        &self,
        from: &ObjectPath,
        to: &ObjectPath,
        _options: RenameOptions,
    ) -> slatedb::object_store::Result<()> {
        Err(slatedb::object_store::Error::NotImplemented {
            operation: format!(
                "rename {from} -> {to} (V16 inv. 84: rename is copy-then-delete; the runtime \
                 storage principal has no delete authority, and the copy half must not run either)"
            ),
            implementer: "NoDeleteStore".to_owned(),
        })
    }

    fn delete_stream(
        &self,
        locations: BoxStream<'static, slatedb::object_store::Result<ObjectPath>>,
    ) -> BoxStream<'static, slatedb::object_store::Result<ObjectPath>> {
        use futures::StreamExt;
        locations
            .map(|location| {
                location.and_then(|location| {
                    Err(slatedb::object_store::Error::NotImplemented {
                        operation: format!(
                            "delete_stream {location} (V16 inv. 84: the runtime storage principal has no delete authority)"
                        ),
                        implementer: "NoDeleteStore".to_owned(),
                    })
                })
            })
            .boxed()
    }
}

/// Clear the local object cache before a keyspace opens on it.
///
/// Q-14: this is CORRECTNESS-critical, not hygiene. Cache entries are keyed
/// by STORE-RELATIVE paths, and those paths repeat across materialisations -
/// so an entry that survives from a previous materialisation is served for
/// THIS one's object paths. That is wrong bytes under valid metadata, which
/// is strictly worse than failing to open.
///
/// The failure that matters is a PARTIAL wipe: `remove_dir_all` deleting
/// some entries and erroring midway leaves the directory present, so the
/// `create_dir_all` that follows succeeds and the survivors are used. The
/// call site discarded this error (`let _ = fs::remove_dir_all(..)`), which
/// is why the partial case was silent. `NotFound` is the one benign
/// outcome: there was nothing to wipe.
fn wipe_object_cache(cache_dir: &Path) -> io::Result<()> {
    match fs::remove_dir_all(cache_dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Upload a local directory tree (a restored checkpoint) under `prefix`,
/// preserving the relative layout.
async fn upload_dir_to_remote(store: &dyn ObjectStore, prefix: &ObjectPath, root: &Path) -> Result<(), slatedb::Error> {
    fn collect(root: &Path, dir: &Path, out: &mut Vec<(Vec<String>, PathBuf)>) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            // the local disk cache and the materialisation marker are
            // machine-local state, never store state
            if dir == root && (entry.file_name() == OBJECT_CACHE_SUBDIR || entry.file_name() == MATERIALIZATION_FILE) {
                continue;
            }
            if entry.file_type()?.is_dir() {
                collect(root, &path, out)?;
            } else {
                let relative = path
                    .strip_prefix(root)
                    .expect("walked file is under the walk root")
                    .components()
                    .map(|component| component.as_os_str().to_string_lossy().into_owned())
                    .collect();
                out.push((relative, path));
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    collect(root, root, &mut files).map_err(io_error)?;
    for (relative, path) in files {
        let bytes = fs::read(&path).map_err(io_error)?;
        let mut location = prefix.clone();
        for part in relative {
            location = location.join(part);
        }
        store.put(&location, PutPayload::from(bytes)).await.map_err(store_error)?;
    }
    Ok(())
}

/// Download the given objects into `dir`, mapping each location's path
/// relative to `prefix` onto the local relative layout.
async fn download_remote_objects(
    store: &dyn ObjectStore,
    prefix: &ObjectPath,
    locations: &[ObjectPath],
    dir: &Path,
) -> Result<(), slatedb::Error> {
    let prefix_str = format!("{prefix}/");
    for location in locations {
        let relative =
            location.as_ref().strip_prefix(&prefix_str).expect("listed object location is under the listed prefix");
        let mut target = dir.to_owned();
        for part in relative.split('/') {
            target = target.join(part);
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(io_error)?;
        }
        let bytes = store.get(location).await.map_err(store_error)?.bytes().await.map_err(store_error)?;
        fs::write(&target, bytes).map_err(io_error)?;
    }
    Ok(())
}

/// The remote half of an S3-backed keyspace: the no-delete-wrapped
/// bucket-root store plus this open's exclusive materialisation prefix (the
/// `Db` itself sees a `PrefixStore`).
struct RemoteStore {
    store: Arc<dyn ObjectStore>,
    prefix: ObjectPath,
}

/// A SlateDB-backed keyspace over a `LocalFileSystem` object store rooted at
/// the keyspace directory (U2), or over a prefix of an S3-compatible bucket
/// (U2S3) with the local directory retained as the lifecycle marker.
pub(super) struct SlateKeyspace {
    db: Arc<Db>,
    path: PathBuf,
    remote: Option<RemoteStore>,
    /// Bounded-staleness memo for [`Self::estimate_key_count`] on the remote
    /// lane: (computed_at, count). Never locked across a scan — see the
    /// method for why that would be the worse defect.
    key_count_memo: std::sync::Mutex<Option<(std::time::Instant, u64)>>,
}

impl SlateKeyspace {
    pub(super) fn open(path: &Path) -> Result<Self, Arc<slatedb::Error>> {
        fs::create_dir_all(path).map_err(|error| Arc::new(io_error(error)))?;
        let store: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix(path).map_err(|error| {
            Arc::new(slatedb::Error::unavailable(format!("local object store at {path:?}: {error}")))
        })?);
        let settings = settings();
        assert_pre_g13_posture(&settings).map_err(Arc::new)?;
        let db = bridge(async move { Db::builder(DB_SUBDIR, store).with_settings(settings).build().await })
            .map_err(Arc::new)?;
        Ok(Self { db: Arc::new(db), path: path.to_owned(), remote: None, key_count_memo: Default::default() })
    }

    /// Open over the configured S3-compatible store (TB-P8, profile U2S3).
    pub(super) fn open_s3(path: &Path) -> Result<Self, Arc<slatedb::Error>> {
        let config = s3_config().map_err(Arc::new)?;
        let store = build_s3_store(config).map_err(Arc::new)?;
        let base_prefix = object_prefix(config, path);
        Self::open_remote(store, base_prefix, path, s3_cache_bytes())
    }

    /// Open over a remote object store, under a FRESH immutable
    /// materialisation namespace (V16 F3, inv. 81–84):
    /// `<base>/<format-version>/<materialisation-id>/keyspace/…`.
    ///
    /// The local keyspace directory is the lifecycle marker — storage
    /// recovery wipes it to mean "start empty" and checkpoint recovery
    /// repopulates it with the checkpointed store files (those are the only
    /// two states an open can observe; there is no state-preserving reopen
    /// without a checkpoint). Under the previous layout that made the remote
    /// prefix's old contents stale, and open PURGED them — a destructive
    /// posture that is catastrophic on shared storage (a duplicate container
    /// or stale actor purging the active materialisation). Open now NEVER
    /// deletes: it mints a fresh materialisation id, seeds the new namespace
    /// from the restored checkpoint subtree when one is present, and leaves
    /// every earlier materialisation in place as orphan bytes (inv. 83) —
    /// report-only GC candidates (inv. 105) for a separated maintenance
    /// principal (`tools/maintenance/s3_gc.py`), never for the runtime,
    /// whose store handle structurally lacks delete ([`NoDeleteStore`],
    /// inv. 84).
    fn open_remote(
        store: Arc<dyn ObjectStore>,
        base_prefix: ObjectPath,
        path: &Path,
        cache_bytes: Option<usize>,
    ) -> Result<Self, Arc<slatedb::Error>> {
        fs::create_dir_all(path).map_err(|error| Arc::new(io_error(error)))?;
        let store: Arc<dyn ObjectStore> = Arc::new(NoDeleteStore::new(store));
        let materialization = mint_materialization_id();
        let prefix = base_prefix.join(FORMAT_VERSION_SEGMENT).join(materialization.as_str());
        let restored_root = path.join(DB_SUBDIR).is_dir().then(|| path.to_owned());
        if let Some(root) = restored_root {
            let store = store.clone();
            let prefix = prefix.clone();
            bridge(async move { upload_dir_to_remote(store.as_ref(), &prefix, &root).await }).map_err(Arc::new)?;
        }
        // recorded for diagnostics and the GC report; written AFTER the seed
        // upload so it can never itself be uploaded as store state
        fs::write(path.join(MATERIALIZATION_FILE), &materialization).map_err(|error| Arc::new(io_error(error)))?;
        let prefixed: Arc<dyn ObjectStore> = Arc::new(PrefixStore::new(store.clone(), prefix.clone()));
        let mut settings = settings();
        if let Some(cache_bytes) = cache_bytes {
            // hydradb comparative review: SlateDB's local disk cache cuts the
            // per-read object-store round trip; the writer caches its own
            // flushed SSTs (`cache_on_flush`) so reads of recent data never
            // leave the machine. The cache lives inside the keyspace dir (the
            // lifecycle marker) and is wiped here because cache entries are
            // keyed by STORE-RELATIVE paths, which repeat across
            // materialisations — a surviving entry would serve the previous
            // materialisation's bytes for this one's object paths.
            let cache_dir = path.join(OBJECT_CACHE_SUBDIR);
            wipe_object_cache(&cache_dir).map_err(|error| Arc::new(io_error(error)))?;
            fs::create_dir_all(&cache_dir).map_err(|error| Arc::new(io_error(error)))?;
            settings.object_store_cache_options.root_folder = Some(cache_dir);
            settings.object_store_cache_options.max_cache_size_bytes = Some(cache_bytes);
            settings.object_store_cache_options.cache_on_flush = true;
        }
        assert_pre_g13_posture(&settings).map_err(Arc::new)?;
        let db = bridge(async move { Db::builder(DB_SUBDIR, prefixed).with_settings(settings).build().await })
            .map_err(Arc::new)?;
        Ok(Self {
            db: Arc::new(db),
            path: path.to_owned(),
            remote: Some(RemoteStore { store, prefix }),
            key_count_memo: Default::default(),
        })
    }

    pub(super) fn shared_db(&self) -> Arc<Db> {
        self.db.clone()
    }

    pub(super) fn put(&self, key: &[u8], value: &[u8]) -> Result<(), Arc<slatedb::Error>> {
        let db = self.db.clone();
        let key = key.to_vec();
        let value = value.to_vec();
        bridge(async move { db.put_with_options(&key, &value, &Default::default(), &write_options()).await })
            .map(|_write_handle| ())
            .map_err(Arc::new)
    }

    pub(super) fn get<M, V>(&self, key: &[u8], mut mapper: M) -> Result<Option<V>, Arc<slatedb::Error>>
    where
        M: FnMut(&[u8]) -> V,
    {
        let db = self.db.clone();
        let key = key.to_vec();
        bridge(async move { db.get_with_options(&key, &read_options()).await })
            .map(|option| option.map(|value| mapper(value.as_ref())))
            .map_err(Arc::new)
    }

    /// Exact floor lookup (last entry with key <= `key`): a descending scan
    /// over `..=key` — the same contract as RocksDB `seek_for_prev`.
    ///
    /// Error posture (donor A10): SlateDB classifies its errors, and
    /// `ErrorKind::Unavailable` is BY CONTRACT the transient class ("a
    /// storage or network service is unavailable; the user must retry or
    /// drop") — an object-store blip on the remote lane. Aborting the whole
    /// server on the first such blip turns routine S3 weather into an
    /// outage, so Unavailable is retried a bounded number of times with
    /// backoff. Everything else — and Unavailable beyond the budget — still
    /// FAILS CLOSED with a panic: the Option-only signature cannot carry an
    /// error, and the caller (vertex ID allocator seeding) would treat a
    /// silent None as "nothing allocated" and re-issue existing IDs — data
    /// corruption. A crash is recoverable; ID reuse is not.
    pub(super) fn get_prev<M, T>(&self, key: &[u8], mut mapper: M) -> Option<T>
    where
        M: FnMut(&[u8], &[u8]) -> T,
    {
        let mut attempt = 0;
        loop {
            let db = self.db.clone();
            let key = key.to_vec();
            let result = bridge(async move {
                let options = scan_options().with_order(slatedb::IterationOrder::Descending);
                let mut iterator = db.scan_with_options(..=key, &options).await?;
                iterator.next().await
            });
            match result {
                Ok(Some(kv)) => return Some(mapper(kv.key.as_ref(), kv.value.as_ref())),
                Ok(None) => return None,
                Err(error) if retry_transient(&error, attempt) => {
                    attempt += 1;
                    std::thread::sleep(std::time::Duration::from_millis(50 << attempt));
                }
                Err(error) => {
                    panic!(
                        "SlateDB floor scan (get_prev) failed ({} transient retries); \
                         refusing to report absence: {error}",
                        attempt
                    )
                }
            }
        }
    }

    /// Apply one atomic batch of puts (MVCC commits are append-only; deletes
    /// are put tombstone records at the MVCC layer above).
    pub(super) fn write(&self, puts: &[(Vec<u8>, Vec<u8>)]) -> Result<(), Arc<slatedb::Error>> {
        // RocksDB accepts an empty batch as a no-op; SlateDB rejects it with
        // `Invalid`. Empty batches occur legitimately (a commit whose only
        // operation is a Put of an already-stored identical value writes
        // nothing), so parity requires the same no-op here.
        if puts.is_empty() {
            return Ok(());
        }
        let db = self.db.clone();
        let mut batch = SlateWriteBatch::new();
        for (key, value) in puts {
            batch.put(key, value);
        }
        bridge(async move { db.write_with_options(batch, &write_options()).await })
            .map(|_write_handle| ())
            .map_err(Arc::new)
    }

    /// Point-in-time checkpoint under concurrent commits, via manifest
    /// pinning (RocksDB's `Checkpoint` is atomic; a naive directory copy is
    /// not, because a concurrent memtable auto-flush can land a new manifest
    /// whose SSTs the copy misses):
    ///
    /// **Q-16 scope statement — this is the CONFORMANCE-LANE fixture
    /// exporter, not a production checkpoint.** Closure is derived by
    /// listing and copying under the materialisation prefix, which is sound
    /// here only because the conformance runner is single-actor by
    /// construction and GC/compaction are disabled. A production checkpoint
    /// requires a controller-frozen global cut, parsed manifest-root
    /// closure, an independent scratch-restore digest, and controller-only
    /// activation (F6r/16.3) — none of which this function claims. Do not
    /// wire it into any production path.
    ///
    /// 1. flush the memtable (the checkpoint watermark was captured by the
    ///    caller before this, so the flush covers it);
    /// 2. pin the CURRENT latest manifest file — SSTs are immutable and GC
    ///    is disabled, so everything the pinned manifest references keeps
    ///    existing;
    /// 3. copy the whole store EXCEPT the manifest directory (extra SSTs
    ///    from later concurrent flushes are unreferenced and harmless);
    /// 4. copy exactly the pinned manifest file, making it the checkpoint's
    ///    latest — restore opens the pinned state, and WAL replay from the
    ///    watermark covers the rest (idempotent, same as RocksDB).
    pub(super) fn checkpoint(&self, checkpoint_keyspace_dir: &Path) -> Result<(), Arc<slatedb::Error>> {
        let db = self.db.clone();
        bridge(async move { db.flush().await }).map_err(Arc::new)?;
        match &self.remote {
            None => self.checkpoint_local(checkpoint_keyspace_dir),
            Some(remote) => Self::checkpoint_remote(remote, checkpoint_keyspace_dir),
        }
    }

    fn checkpoint_local(&self, checkpoint_keyspace_dir: &Path) -> Result<(), Arc<slatedb::Error>> {
        let manifest_dir = find_manifest_dir(&self.path).map_err(|error| Arc::new(io_error(error)))?;
        // lexicographic max = newest manifest, same pin as checkpoint_remote
        let pinned_manifest = match &manifest_dir {
            Some(dir) => fs::read_dir(dir)
                .map_err(|error| Arc::new(io_error(error)))?
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| path.is_file())
                .max(),
            None => None,
        };

        copy_dir_recursive_excluding(&self.path, checkpoint_keyspace_dir, manifest_dir.as_deref())
            .map_err(|error| Arc::new(io_error(error)))?;

        if let (Some(dir), Some(pinned)) = (&manifest_dir, &pinned_manifest) {
            let relative = dir.strip_prefix(&self.path).expect("manifest dir is under the keyspace path");
            let target_dir = checkpoint_keyspace_dir.join(relative);
            fs::create_dir_all(&target_dir).map_err(|error| Arc::new(io_error(error)))?;
            fs::copy(pinned, target_dir.join(pinned.file_name().expect("manifest file name")))
                .map_err(|error| Arc::new(io_error(error)))?;
        }
        Ok(())
    }

    /// The S3 checkpoint is the same manifest-pinning algorithm as
    /// [`Self::checkpoint_local`], executed through the object-store API and
    /// *downloading* into the local checkpoint directory — the checkpoint on
    /// disk has the identical shape either way, so checkpoint restore (a
    /// local file sync followed by [`Self::open_s3`]'s upload) needs no
    /// engine-specific code.
    fn checkpoint_remote(remote: &RemoteStore, checkpoint_keyspace_dir: &Path) -> Result<(), Arc<slatedb::Error>> {
        let manifest_dir = remote.prefix.clone().join(DB_SUBDIR).join(MANIFEST_SUBDIR);
        let manifest_prefix = format!("{manifest_dir}/");
        let store = remote.store.clone();
        let prefix = remote.prefix.clone();
        let dir = checkpoint_keyspace_dir.to_owned();
        bridge(async move {
            // Pin FIRST, from a listing of the manifest prefix ALONE, and only
            // then list the data prefixes: SSTs are immutable and durable
            // before the manifest that references them, so the strictly-later
            // full listing is a superset of everything the pinned manifest
            // needs (extra SSTs from later flushes are unreferenced and
            // harmless, as in the LocalFS path). A single interleaved walk
            // could list a data prefix BEFORE a concurrent flush and the
            // manifest prefix after it, pinning a manifest whose SSTs the
            // walk never saw — the checkpoint the docstring above promises
            // this algorithm can never produce.
            let manifests = list_remote_prefix(store.as_ref(), &manifest_dir).await?;
            // lexicographically last manifest object — the same ordering the
            // LocalFS path applies to manifest file names
            let pinned = manifests.iter().map(|meta| &meta.location).max().cloned();
            let objects = list_remote_prefix(store.as_ref(), &prefix).await?;
            let is_manifest = |location: &ObjectPath| location.as_ref().starts_with(&manifest_prefix);
            let mut to_copy: Vec<ObjectPath> =
                objects.iter().map(|meta| meta.location.clone()).filter(|location| !is_manifest(location)).collect();
            to_copy.extend(pinned);
            download_remote_objects(store.as_ref(), &prefix, &to_copy, &dir).await
        })
        .map_err(Arc::new)
    }

    /// Retire this keyspace's remote materialisation IN PLACE (V16 F3):
    /// close the engine and leave every remote object exactly where it is.
    /// Keyspace deletion previously purged the remote prefix here; under the
    /// immutable-namespace model the runtime has no delete authority at all
    /// (inv. 84 — structurally enforced by [`NoDeleteStore`]), so a deleted
    /// keyspace's bytes become orphans (inv. 83) that only the separated
    /// maintenance principal (`tools/maintenance/s3_gc.py`, report-only by
    /// default, inv. 105) may ever reclaim. No-op on the LocalFS lane. The
    /// second close attempted later by `Drop` is a swallowed error.
    pub(super) fn retire_remote(&self) {
        if self.remote.is_none() {
            return;
        }
        let db = self.db.clone();
        let _ = bridge(async move { db.close().await });
    }

    pub(super) fn reset(&self) -> Result<(), Arc<slatedb::Error>> {
        // chunked: one batch per CHUNK keys, so memory stays bounded by the
        // chunk rather than the store size
        const CHUNK: usize = 10_000;
        let db = self.db.clone();
        bridge(async move {
            let mut iterator = db.scan_with_options(.., &scan_options()).await?;
            let mut batch = SlateWriteBatch::new();
            let mut in_batch = 0usize;
            while let Some(kv) = iterator.next().await? {
                batch.delete(kv.key);
                in_batch += 1;
                if in_batch == CHUNK {
                    db.write_with_options(std::mem::take(&mut batch), &write_options()).await?;
                    in_batch = 0;
                }
            }
            if in_batch > 0 {
                db.write_with_options(batch, &write_options()).await?;
            }
            Ok(())
        })
        .map_err(Arc::new)
    }

    /// Close the engine, flushing in-memory state to the object store. Used
    /// on drop and before directory deletion; failures on the drop path are
    /// ignored (the store is rebuilt from the TypeDB WAL on reopen).
    pub(super) fn close(&self) -> Result<(), Arc<slatedb::Error>> {
        let db = self.db.clone();
        bridge(async move {
            db.flush().await?;
            db.close().await
        })
        .map_err(Arc::new)
    }

    /// Manifest-based size estimate (donor idea, ADR-0013 portable list;
    /// observational per V16 inv. 72): summed SST size estimates from the
    /// in-memory manifest — no directory walk, no remote LIST. TypeDB's
    /// diagnostics loop polls this every ~15s; the previous implementation
    /// issued one full remote LIST per poll on the S3 lane (billed Class-A
    /// operations on R2) to compute a number that is an estimate either way,
    /// and a local directory walk on the LocalFS lane. Memtable-resident
    /// bytes are excluded on both lanes, exactly as before.
    pub(super) fn estimate_size_in_bytes(&self) -> u64 {
        let manifest = self.db.manifest();
        let l0: u64 = manifest.l0().iter().map(|sst| sst.estimate_size()).sum();
        let compacted: u64 = manifest.compacted().iter().map(|run| run.estimate_size()).sum();
        l0 + compacted
    }

    /// Key count for periodic database metrics. The RocksDB path serves an
    /// O(1) engine estimate; SlateDB has no equivalent property, so LocalFS
    /// serves an exact full scan (cheap, and exactness beats inventing an
    /// estimator). On the REMOTE lane a full scan re-reads the store from
    /// the object store on every ~15s diagnostics poll, so the exact scan is
    /// memoised with bounded staleness (observational metric, V16 inv. 72).
    /// The memo lock is NEVER held across the scan — holding a mutex across
    /// a remote scan is a named excluded defect (audit F12): a slow scan
    /// would block every concurrent metrics caller. The cost of that choice
    /// is that two callers racing an expired memo may both scan; the
    /// diagnostics loop is single-threaded, so that race is theoretical.
    pub(super) fn estimate_key_count(&self) -> Result<u64, Arc<slatedb::Error>> {
        const REMOTE_KEY_COUNT_TTL: std::time::Duration = std::time::Duration::from_secs(60);
        let remote = self.remote.is_some();
        if remote {
            if let Some((computed_at, count)) = *self.key_count_memo.lock().unwrap() {
                if computed_at.elapsed() < REMOTE_KEY_COUNT_TTL {
                    return Ok(count);
                }
            }
        }
        let db = self.db.clone();
        let count = bridge(async move {
            let mut iterator = db.scan_with_options(.., &scan_options()).await?;
            let mut count = 0u64;
            while iterator.next().await?.is_some() {
                count += 1;
            }
            Ok(count)
        })
        .map_err(Arc::new)?;
        // Populate the memo so the TTL actually bounds the remote scan
        // (without this write the memo above was dead code and every ~15s
        // metrics poll re-scanned the whole store — donor A6). The lock is
        // taken only for this O(1) store, never across the scan above.
        if remote {
            *self.key_count_memo.lock().unwrap() = Some((std::time::Instant::now(), count));
        }
        Ok(count)
    }
}

impl Drop for SlateKeyspace {
    fn drop(&mut self) {
        // Failures (and panics from the bridged close task) are swallowed:
        // this drop can run during another panic's unwind, where a second
        // panic would abort the process. The store is rebuilt from the
        // TypeDB WAL on reopen, so an unclean close loses nothing durable.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = self.close();
        }));
    }
}

impl std::fmt::Debug for SlateKeyspace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SlateKeyspace[path={:?}]", self.path)
    }
}

/// Forward cursor over a SlateDB keyspace with RocksDB raw-iterator
/// positioning semantics: `seek` places the cursor on the first entry >= key,
/// `advance` steps forward, `item` reads the current entry without moving.
///
/// A SlateDB scan can only seek forward within itself, so a `seek` to a key
/// at or before the current position starts a fresh scan (fresh scans also
/// give recycled cursors a view at least as fresh as their pool's snapshot,
/// which MVCC filtering above makes sufficient).
pub(super) struct SlateCursor {
    db: Arc<Db>,
    iterator: Option<DbIterator>,
    current: Option<(SlateBytes, SlateBytes)>,
    error: Option<Arc<slatedb::Error>>,
}

impl SlateCursor {
    pub(super) fn new(db: Arc<Db>) -> Self {
        Self { db, iterator: None, current: None, error: None }
    }

    pub(super) fn reads_from(&self, db: &Arc<Db>) -> bool {
        Arc::ptr_eq(&self.db, db)
    }

    pub(super) fn seek(&mut self, key: &[u8]) {
        self.error = None;
        if let Some((current_key, _)) = &self.current {
            if current_key.as_ref() == key {
                return; // already positioned on the first entry >= key
            }
            if current_key.as_ref() < key && self.iterator.is_some() {
                // strictly-forward reposition within the live scan
                let mut iterator = self.iterator.take().expect("iterator present");
                let key_owned = key.to_vec();
                let (iterator, outcome) = bridge(async move {
                    match iterator.seek(&key_owned).await {
                        Ok(()) => {
                            let next = iterator.next().await;
                            (iterator, next)
                        }
                        Err(error) => (iterator, Err(error)),
                    }
                });
                self.iterator = Some(iterator);
                match outcome {
                    Ok(item) => {
                        self.record(Ok(item));
                        return;
                    }
                    Err(_) => {
                        // e.g. seek at/behind the last yielded key on a scan
                        // whose current item was already consumed: fall back
                        // to a fresh scan below
                    }
                }
            }
        }
        self.fresh_scan(key);
    }

    fn fresh_scan(&mut self, key: &[u8]) {
        let db = self.db.clone();
        let key_owned = key.to_vec();
        let outcome = bridge(async move {
            let mut iterator = db.scan_with_options(key_owned.., &scan_options()).await?;
            let first = iterator.next().await?;
            Ok::<_, slatedb::Error>((iterator, first))
        });
        match outcome {
            Ok((iterator, first)) => {
                self.iterator = Some(iterator);
                self.record(Ok(first));
            }
            Err(error) => {
                self.iterator = None;
                self.current = None;
                self.error = Some(Arc::new(error));
            }
        }
    }

    pub(super) fn advance(&mut self) {
        let Some(mut iterator) = self.iterator.take() else {
            // advancing an unpositioned/errored cursor: stays invalid,
            // matching RocksDB raw-iterator semantics
            self.current = None;
            return;
        };
        let (iterator, item) = bridge(async move {
            let item = iterator.next().await;
            (iterator, item)
        });
        self.iterator = Some(iterator);
        self.record(item);
    }

    fn record(&mut self, item: Result<Option<slatedb::KeyValue>, slatedb::Error>) {
        match item {
            Ok(Some(kv)) => {
                self.current = Some((kv.key, kv.value));
                self.error = None;
            }
            Ok(None) => {
                self.current = None;
                self.error = None;
            }
            Err(error) => {
                self.current = None;
                self.error = Some(Arc::new(error));
            }
        }
    }

    pub(super) fn item(&self) -> Option<(&[u8], &[u8])> {
        self.current.as_ref().map(|(key, value)| (key.as_ref(), value.as_ref()))
    }

    pub(super) fn key(&self) -> Option<&[u8]> {
        self.current.as_ref().map(|(key, _)| key.as_ref())
    }

    pub(super) fn status(&self) -> Result<(), Arc<slatedb::Error>> {
        match &self.error {
            None => Ok(()),
            Some(error) => Err(error.clone()),
        }
    }
}

fn io_error(error: io::Error) -> slatedb::Error {
    slatedb::Error::unavailable(format!("keyspace object store I/O: {error}"))
}

/// The single retry decision for read paths whose signature cannot carry an
/// error (donor A10). ONLY SlateDB's contractual transient class
/// (`ErrorKind::Unavailable` — "must retry or drop") is retried, and only
/// within the bounded budget; every other kind (Invalid, Data, Internal,
/// Closed, Transaction) fails closed immediately — retrying those would
/// mask corruption or a bug behind latency.
const TRANSIENT_RETRIES: u32 = 4;

fn retry_transient(error: &slatedb::Error, attempt: u32) -> bool {
    error.kind() == slatedb::ErrorKind::Unavailable && attempt < TRANSIENT_RETRIES
}

fn copy_dir_recursive_excluding(from: &Path, to: &Path, exclude_dir: Option<&Path>) -> io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let path = entry.path();
        if Some(path.as_path()) == exclude_dir {
            continue;
        }
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive_excluding(&path, &target, exclude_dir)?;
        } else {
            fs::copy(&path, &target)?;
        }
    }
    Ok(())
}

/// Locate the SlateDB manifest directory under the keyspace path (the store
/// lives at `<path>/keyspace/`, manifests at `<path>/keyspace/manifest/`).
/// Discovered rather than hardcoded so a layout change fails loudly in
/// tests, not silently: no manifest dir means nothing to pin.
fn find_manifest_dir(keyspace_path: &Path) -> io::Result<Option<PathBuf>> {
    let candidate = keyspace_path.join(DB_SUBDIR).join(MANIFEST_SUBDIR);
    if candidate.is_dir() { Ok(Some(candidate)) } else { Ok(None) }
}

#[cfg(test)]
mod retry_channel_tests {
    //! Donor A10 control: the get_prev retry decision. Reintroducing
    //! panic-on-any (never retrying) fails `unavailable_is_retried…`;
    //! widening the retry to every kind (masking corruption behind latency)
    //! fails `non_transient_kinds_fail_closed…`; removing the bound fails
    //! `the_retry_budget_is_bounded`.

    use super::{TRANSIENT_RETRIES, retry_transient};

    #[test]
    fn unavailable_is_retried_within_the_budget() {
        let transient = slatedb::Error::unavailable("s3 blip".to_string());
        for attempt in 0..TRANSIENT_RETRIES {
            assert!(retry_transient(&transient, attempt), "attempt {attempt} must retry");
        }
    }

    #[test]
    fn the_retry_budget_is_bounded() {
        let transient = slatedb::Error::unavailable("s3 outage".to_string());
        assert!(!retry_transient(&transient, TRANSIENT_RETRIES), "an exhausted budget must fail closed, not spin");
    }

    #[test]
    fn non_transient_kinds_fail_closed_immediately() {
        for error in [
            slatedb::Error::invalid("bad argument".to_string()),
            slatedb::Error::data("corrupt sst".to_string()),
            slatedb::Error::internal("bug".to_string()),
        ] {
            assert!(
                !retry_transient(&error, 0),
                "{:?} must never be retried - retrying would mask corruption or a bug",
                error.kind()
            );
        }
    }
}

#[cfg(test)]
mod read_contract_tests {
    //! V16 inv. 74/75 negative control (brief anchor 25): the committed-
    //! memory-visible read contract, proved against the exact options this
    //! module resolves, with SlateDB's own `write-batch-pre-commit`
    //! failpoint pausing a write between memtable insertion and commit.
    //!
    //! The control detects the defect it guards against: while the write is
    //! paused pre-commit, a `dirty: true` probe DOES see the row (so
    //! reintroducing `with_dirty(true)` into `read_options`/`scan_options`
    //! makes the production-options assertions below fail), while the
    //! production options see nothing. Resuming the write advances the
    //! committed frontier and the same options see the row — same-handle
    //! read-your-writes without dirty reads (inv. 75).

    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use fail_parallel::FailPointRegistry;
    use slatedb::{
        Db,
        config::ReadOptions,
        object_store::{ObjectStore, local::LocalFileSystem},
    };
    use test_utils::create_tmp_dir;

    use super::{bridge, read_options, scan_options, settings, write_options};

    #[test]
    fn paused_precommit_write_is_invisible_to_committed_frontier_reads() {
        let dir = create_tmp_dir("slate-read-contract");
        let registry = Arc::new(FailPointRegistry::new());
        let store: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix(&*dir).unwrap());
        let db = Arc::new(
            bridge({
                let registry = registry.clone();
                async move {
                    Db::builder("read-contract", store)
                        .with_settings(settings())
                        .with_fp_registry(registry)
                        .build()
                        .await
                }
            })
            .unwrap(),
        );

        // inv. 75 baseline: a COMMITTED write is visible to the very next
        // read through the production options, before any flush
        {
            let db = db.clone();
            bridge(
                async move { db.put_with_options(b"k-committed", b"v1", &Default::default(), &write_options()).await },
            )
            .unwrap();
        }
        let committed = {
            let db = db.clone();
            bridge(async move { db.get_with_options(b"k-committed", &read_options()).await }).unwrap()
        };
        assert!(committed.is_some(), "read-your-writes must hold for committed writes (inv. 75)");

        // pause the NEXT write between memtable insertion and commit
        fail_parallel::cfg(registry.clone(), "write-batch-pre-commit", "pause").unwrap();
        let writer = {
            let db = db.clone();
            std::thread::spawn(move || {
                bridge(
                    async move { db.put_with_options(b"k-pending", b"v2", &Default::default(), &write_options()).await },
                )
            })
        };

        // wait until the paused write is observable at all — via a dirty
        // probe, which is exactly the visibility the production options must
        // NOT have. This wait doubles as the mutant detector: it proves the
        // row IS in the memtable while the assertions below run.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let dirty_probe = {
                let db = db.clone();
                bridge(async move { db.get_with_options(b"k-pending", &ReadOptions::default().with_dirty(true)).await })
                    .unwrap()
            };
            if dirty_probe.is_some() {
                break;
            }
            assert!(Instant::now() < deadline, "paused write never reached the memtable");
            std::thread::sleep(Duration::from_millis(10));
        }

        // THE CONTRACT (inv. 74): the resolved production options cannot
        // observe a write whose commit has not happened
        let pending_get = {
            let db = db.clone();
            bridge(async move { db.get_with_options(b"k-pending", &read_options()).await }).unwrap()
        };
        assert!(
            pending_get.is_none(),
            "a pre-commit write leaked through read_options() - the committed-frontier contract is broken",
        );
        let pending_scan: Vec<_> = {
            let db = db.clone();
            bridge(async move {
                let mut iterator =
                    db.scan_with_options(b"k-pending".to_vec()..b"k-pending\xff".to_vec(), &scan_options()).await?;
                let mut rows = Vec::new();
                while let Some(row) = iterator.next().await? {
                    rows.push(row.key);
                }
                Ok::<_, slatedb::Error>(rows)
            })
            .unwrap()
        };
        assert!(
            pending_scan.is_empty(),
            "a pre-commit write leaked through scan_options() - the committed-frontier contract is broken",
        );

        // resume: the commit completes, the frontier advances, and the SAME
        // production options now see the row
        fail_parallel::cfg(registry, "write-batch-pre-commit", "off").unwrap();
        writer.join().unwrap().unwrap();
        let resumed = {
            let db = db.clone();
            bridge(async move { db.get_with_options(b"k-pending", &read_options()).await }).unwrap()
        };
        assert!(resumed.is_some(), "the committed write must be visible after the pipeline resumes");
    }
}

#[cfg(test)]
mod posture_tests {
    //! F5 interim enforcement: the pre-G13 posture is attested fail-closed
    //! at every open. Each clause has a violation control; the wiring is
    //! proved by the mutant run (enable the compactor in `settings()` and
    //! every open-path test refuses with the posture error).

    use slatedb::config::{CompactorOptions, GarbageCollectorOptions, Settings};

    use super::{assert_pre_g13_posture, settings};

    #[test]
    fn compliant_settings_pass() {
        assert!(assert_pre_g13_posture(&settings()).is_ok());
    }

    #[test]
    fn each_violation_is_a_typed_refusal_naming_the_clause() {
        let mut wal_on = settings();
        wal_on.wal_enabled = true;
        let error = assert_pre_g13_posture(&wal_on).unwrap_err().to_string();
        assert!(error.contains("sole durability authority"), "{error}");

        let mut compactor_on = settings();
        compactor_on.compactor_options = Some(CompactorOptions::default());
        let error = assert_pre_g13_posture(&compactor_on).unwrap_err().to_string();
        assert!(error.contains("externally epoch-fenced"), "{error}");

        let mut gc_on = settings();
        gc_on.garbage_collector_options = Some(GarbageCollectorOptions::default());
        let error = assert_pre_g13_posture(&gc_on).unwrap_err().to_string();
        assert!(error.contains("report-only"), "{error}");

        let mut all_on = Settings::default();
        all_on.wal_enabled = true;
        all_on.compactor_options = Some(CompactorOptions::default());
        all_on.garbage_collector_options = Some(GarbageCollectorOptions::default());
        let error = assert_pre_g13_posture(&all_on).unwrap_err().to_string();
        assert!(error.matches(';').count() >= 2, "every violated clause must be named: {error}");
    }
}

#[cfg(test)]
mod materialization_tests {
    //! V16 F3 negative controls (inv. 81–84): open NEVER deletes, a stale
    //! actor cannot alter the active materialisation, and the runtime store
    //! principal structurally lacks delete authority. The "remote" store is
    //! a LocalFileSystem object store injected through the same
    //! [`SlateKeyspace::open_remote`] path the S3 lane uses — the namespace
    //! and no-delete logic under test is byte-identical on both.

    use std::{collections::BTreeMap, sync::Arc};

    use slatedb::object_store::{
        CopyMode, CopyOptions, ObjectStore, ObjectStoreExt, PutPayload, local::LocalFileSystem,
        path::Path as ObjectPath,
    };
    use test_utils::create_tmp_dir;

    use super::{
        FORMAT_VERSION_SEGMENT, MATERIALIZATION_FILE, NoDeleteStore, SlateKeyspace, bridge, list_remote_prefix,
    };

    const BASE: &str = "it-base";

    fn remote_fixture() -> (test_utils::TempDir, Arc<dyn ObjectStore>) {
        let store_dir = create_tmp_dir("slate-f3-store");
        let store: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix(&*store_dir).unwrap());
        (store_dir, store)
    }

    /// Every object under `base`, as location → bytes (content compare, not
    /// just presence: an overwrite would slip past a presence check).
    fn snapshot(store: &Arc<dyn ObjectStore>, base: &ObjectPath) -> BTreeMap<String, Vec<u8>> {
        let store = store.clone();
        let base = base.clone();
        bridge(async move {
            let mut contents = BTreeMap::new();
            for meta in list_remote_prefix(store.as_ref(), &base).await.unwrap() {
                let bytes = store.get(&meta.location).await.unwrap().bytes().await.unwrap();
                contents.insert(meta.location.to_string(), bytes.to_vec());
            }
            contents
        })
    }

    fn open(store: &Arc<dyn ObjectStore>, keyspace_dir: &std::path::Path) -> SlateKeyspace {
        SlateKeyspace::open_remote(store.clone(), ObjectPath::from(BASE), keyspace_dir, None).unwrap()
    }

    fn materialization_of(keyspace_dir: &std::path::Path) -> String {
        std::fs::read_to_string(keyspace_dir.join(MATERIALIZATION_FILE)).unwrap()
    }

    #[test]
    fn reopen_mints_fresh_materialization_and_never_deletes_the_previous_one() {
        let (_store_dir, store) = remote_fixture();
        let keyspace_dir = create_tmp_dir("slate-f3-ks");
        let base = ObjectPath::from(BASE);

        // materialisation A: write, flush to the store, close
        let keyspace_a = open(&store, &keyspace_dir);
        keyspace_a.put(b"k", b"v-a").unwrap();
        keyspace_a.close().unwrap();
        let id_a = materialization_of(&keyspace_dir);
        drop(keyspace_a);
        let after_a = snapshot(&store, &base);
        assert!(
            after_a.keys().any(|location| location.contains(&id_a)),
            "materialisation A must have flushed objects under its own namespace",
        );

        // storage recovery semantics: the lifecycle marker dir is wiped
        std::fs::remove_dir_all(&*keyspace_dir).unwrap();

        // materialisation B: a fresh namespace; A's bytes are untouched
        let keyspace_b = open(&store, &keyspace_dir);
        let id_b = materialization_of(&keyspace_dir);
        assert_ne!(id_a, id_b, "reopen must mint a fresh materialisation id (inv. 81/82)");
        keyspace_b.put(b"k", b"v-b").unwrap();
        keyspace_b.close().unwrap();

        let after_b = snapshot(&store, &base);
        for (location, bytes) in &after_a {
            assert_eq!(
                after_b.get(location),
                Some(bytes),
                "open deleted or altered {location} from the previous materialisation - open must never delete (inv. 83)",
            );
        }
        assert!(
            after_b.keys().any(|location| location.contains(&id_b)),
            "materialisation B must write under its own namespace",
        );
        assert!(
            after_b.keys().all(|location| { !location.contains(&id_b) || !location.contains(&id_a) }),
            "materialisation namespaces must be disjoint",
        );

        // retirement (keyspace delete) leaves every byte in place
        keyspace_b.retire_remote();
        assert_eq!(
            snapshot(&store, &base),
            after_b,
            "retire_remote must not delete anything - orphan bytes await the maintenance principal",
        );
    }

    #[test]
    fn stale_actor_cannot_alter_the_active_materialization() {
        let (_store_dir, store) = remote_fixture();
        let keyspace_dir = create_tmp_dir("slate-f3-stale");
        let base = ObjectPath::from(BASE);

        // the stale actor: opened first, still running
        let stale = open(&store, &keyspace_dir);
        let stale_id = materialization_of(&keyspace_dir);
        stale.put(b"k", b"v-stale-early").unwrap();

        // the active actor: a duplicate open of the same keyspace path
        let active = open(&store, &keyspace_dir);
        let active_id = materialization_of(&keyspace_dir);
        assert_ne!(stale_id, active_id, "duplicate open must allocate a fresh materialisation (inv. 81)");
        active.put(b"k", b"v-active").unwrap();
        {
            let db = active.shared_db();
            bridge(async move { db.flush().await }).unwrap();
        }

        let active_prefix = base.join(FORMAT_VERSION_SEGMENT).join(active_id.as_str());
        let active_before = snapshot(&store, &active_prefix);
        assert!(!active_before.is_empty(), "the active materialisation must have flushed objects");

        // the stale actor keeps writing, flushes, and is retired: nothing it
        // does may reach into the active namespace (inv. 82/83)
        stale.put(b"k2", b"v-stale-late").unwrap();
        stale.close().unwrap();
        stale.retire_remote();
        assert_eq!(
            snapshot(&store, &active_prefix),
            active_before,
            "a stale actor's writes/close/retire altered the ACTIVE materialisation (inv. 82 violated)",
        );

        // and the active handle still reads its own data
        let read = active.get(b"k", |value| value.to_vec()).unwrap();
        assert_eq!(read.as_deref(), Some(b"v-active".as_slice()));
    }

    #[test]
    fn remote_key_count_memo_is_populated_and_bounds_the_scan() {
        // donor A6: the memo must be WRITTEN, not just read - otherwise the
        // TTL is dead code and every metrics poll re-scans. Proof: after the
        // first count, add keys directly; a second call within the TTL must
        // return the MEMOISED (stale) count, not a fresh scan.
        let (_store_dir, store) = remote_fixture();
        let keyspace_dir = create_tmp_dir("slate-f3-memo");
        let keyspace = open(&store, &keyspace_dir);
        keyspace.put(b"k1", b"v1").unwrap();
        keyspace.put(b"k2", b"v2").unwrap();
        let first = keyspace.estimate_key_count().unwrap();
        assert_eq!(first, 2, "first count scans the store");
        // more keys land after the memo is populated
        keyspace.put(b"k3", b"v3").unwrap();
        keyspace.put(b"k4", b"v4").unwrap();
        let second = keyspace.estimate_key_count().unwrap();
        assert_eq!(second, 2, "within the TTL the memoised count is served (proves the memo is written)");
    }

    #[test]
    fn a_failed_object_cache_wipe_is_propagated_not_discarded() {
        // Q-14. The call site used to be `let _ = fs::remove_dir_all(..)`.
        //
        // The failure that matters is a PARTIAL wipe - remove_dir_all
        // deleting some entries and erroring midway - because the
        // create_dir_all that follows then SUCCEEDS (the directory is still
        // there) and the surviving entries are served for this
        // materialisation's object paths. So the assertion has to be on the
        // wipe's own result, not on whether the open happens to fail for
        // some other reason: injecting an obstruction that also breaks
        // create_dir_all would pass whether or not the error is discarded,
        // which is no control at all.
        let dir = create_tmp_dir("slate-cache-wipe");
        let cache = dir.join("object-cache");

        // nothing to wipe is benign
        assert!(super::wipe_object_cache(&cache).is_ok(), "absent cache is not an error");

        // a real cache directory with contents is cleared, and reported cleared
        std::fs::create_dir_all(cache.join("nested")).unwrap();
        std::fs::write(cache.join("nested").join("entry"), b"stale bytes").unwrap();
        assert!(super::wipe_object_cache(&cache).is_ok());
        assert!(!cache.exists(), "the wipe must actually remove the cache");

        // and a wipe that CANNOT succeed is reported, never swallowed
        std::fs::write(&cache, b"not a directory").unwrap();
        let refused = super::wipe_object_cache(&cache);
        assert!(
            refused.is_err(),
            "a cache the process cannot clear must be an error - discarding it opens the \
             keyspace on entries keyed to a previous materialisation's object paths",
        );
    }

    #[test]
    fn copies_through_the_runtime_principal_are_create_only() {
        // Q-27 remainder: an overwrite-mode copy is a delete of the
        // destination's bytes wearing a copy's name. Create-mode copies pass
        // through (colliding safely on the inner store's precondition);
        // overwrite mode is refused before the inner store sees it.
        let (_store_dir, inner) = remote_fixture();
        let store = Arc::new(NoDeleteStore::new(inner));
        let source = ObjectPath::from("copy/source");
        let occupied = ObjectPath::from("copy/occupied");
        bridge({
            let (store, source, occupied) = (store.clone(), source.clone(), occupied.clone());
            async move {
                store.put(&source, PutPayload::from_static(b"source bytes")).await?;
                store.put(&occupied, PutPayload::from_static(b"authoritative bytes")).await
            }
        })
        .unwrap();

        // the plain `copy()` extension defaults to OVERWRITE mode: refused
        let overwrite = bridge({
            let (store, source, occupied) = (store.clone(), source.clone(), occupied.clone());
            async move { store.copy(&source, &occupied).await }
        });
        assert!(
            matches!(overwrite, Err(slatedb::object_store::Error::NotImplemented { .. })),
            "an overwrite-mode copy must be a typed denial, got: {overwrite:?}",
        );
        let survives = bridge({
            let (inner, occupied) = (store.inner.clone(), occupied.clone());
            async move { inner.get(&occupied).await?.bytes().await }
        })
        .unwrap();
        assert_eq!(&survives[..], b"authoritative bytes", "the destination is untouched");

        // create-mode copy to a fresh destination passes through
        let fresh = ObjectPath::from("copy/fresh");
        bridge({
            let (store, source, fresh) = (store.clone(), source.clone(), fresh.clone());
            async move {
                store.copy_opts(&source, &fresh, CopyOptions { mode: CopyMode::Create, ..Default::default() }).await
            }
        })
        .unwrap();
        // and a create-mode copy onto an EXISTING destination fails on the
        // inner store's own precondition, not by silently overwriting
        let collision = bridge({
            let (store, source, occupied) = (store.clone(), source.clone(), occupied.clone());
            async move {
                store.copy_opts(&source, &occupied, CopyOptions { mode: CopyMode::Create, ..Default::default() }).await
            }
        });
        assert!(collision.is_err(), "create-mode collision must not overwrite");
    }

    #[test]
    fn a_blocked_rename_leaves_no_copy_behind() {
        // Q-27: ObjectStore's default `rename_opts` is copy-then-delete.
        // Blocking only `delete_stream` blocked the deletion but not the
        // copy, so a refused rename still left a full duplicate of the
        // object at the destination - a second copy of authoritative bytes
        // under a name nobody activated, while the caller was told the
        // rename failed. The refusal must therefore come BEFORE the copy,
        // and the store must be byte-identical afterwards.
        let (_store_dir, inner) = remote_fixture();
        let store = Arc::new(NoDeleteStore::new(inner));
        let from = ObjectPath::from("rename/source");
        let to = ObjectPath::from("rename/destination");
        bridge({
            let payload = PutPayload::from_static(b"authoritative bytes");
            let (from, store) = (from.clone(), store.clone());
            async move { store.put(&from, payload).await }
        })
        .unwrap();

        let denial = bridge({
            let (from, to, store) = (from.clone(), to.clone(), store.clone());
            async move { store.rename(&from, &to).await }
        });
        assert!(
            matches!(denial, Err(slatedb::object_store::Error::NotImplemented { .. })),
            "rename through the runtime principal must be a typed denial, got: {denial:?}",
        );

        // the source survives...
        let source = bridge({
            let (from, inner) = (from.clone(), store.inner.clone());
            async move { inner.head(&from).await }
        });
        assert!(source.is_ok(), "the source must survive a denied rename");
        // ...and NOTHING was written at the destination
        let destination = bridge({
            let (to, inner) = (to.clone(), store.inner.clone());
            async move { inner.head(&to).await }
        });
        assert!(
            matches!(destination, Err(slatedb::object_store::Error::NotFound { .. })),
            "a denied rename must not leave a copy at the destination, got: {destination:?}",
        );
    }

    #[test]
    fn runtime_store_principal_has_no_delete_authority() {
        // inv. 84's probe: not symbol absence but an exercised runtime
        // boundary — delete on the wrapped principal is a typed denial and
        // the object survives.
        let (_store_dir, inner) = remote_fixture();
        let store = Arc::new(NoDeleteStore::new(inner));
        let location = ObjectPath::from("probe/object");
        bridge({
            let payload = PutPayload::from_static(b"bytes");
            let location = location.clone();
            let store = store.clone();
            async move { store.put(&location, payload).await }
        })
        .unwrap();

        let denial = bridge({
            let location = location.clone();
            let store = store.clone();
            async move { store.delete(&location).await }
        });
        assert!(
            matches!(denial, Err(slatedb::object_store::Error::NotImplemented { .. })),
            "delete through the runtime principal must be a typed denial, got: {denial:?}",
        );
        let survives = bridge({
            let store = store.inner.clone();
            async move { store.head(&location).await }
        });
        assert!(survives.is_ok(), "the probed object must survive the denied delete");

        // the same probe against the store handle an OPENED keyspace holds:
        // proves open_remote actually installs the no-delete principal (a
        // wrapper that exists but is not wired in would pass the probe above
        // and still leave the runtime with delete authority)
        let (_ks_store_dir, ks_store) = remote_fixture();
        let keyspace_dir = create_tmp_dir("slate-f3-probe-ks");
        let keyspace = open(&ks_store, &keyspace_dir);
        keyspace.put(b"k", b"v").unwrap();
        keyspace.close().unwrap();
        let installed = keyspace.remote.as_ref().expect("remote lane").store.clone();
        let target = bridge({
            let installed = installed.clone();
            async move {
                let listing = list_remote_prefix(installed.as_ref(), &ObjectPath::from(BASE)).await.unwrap();
                listing.into_iter().next().expect("flushed keyspace has objects").location
            }
        });
        let runtime_denial = bridge({
            let target = target.clone();
            async move { installed.delete(&target).await }
        });
        assert!(
            matches!(runtime_denial, Err(slatedb::object_store::Error::NotImplemented { .. })),
            "the store handle installed by open_remote must deny delete (inv. 84), got: {runtime_denial:?}",
        );
    }
}
