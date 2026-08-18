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
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
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
        ObjectStoreExt, PutMode, PutMultipartOptions, PutOptions, PutPayload, PutResult, RenameOptions, UploadPart,
        aws::AmazonS3Builder, local::LocalFileSystem, path::Path as ObjectPath, prefix::PrefixStore,
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

/// **EXPERIMENTAL, admission-bounded — no-compactor / giant-L0 posture (S-05).**
///
/// The remote lane deliberately disables compaction and GC (`assert_pre_g13_posture`)
/// and lets L0 grow far past SlateDB's default backpressure ceiling. That is a useful
/// *containment* posture before a fenced, controller-authorized compactor exists — but
/// it is NOT a bounded production design: a long-running write workload would otherwise
/// accumulate SSTs, read amplification, LIST/GET cost, memory pressure and recovery time
/// with no controller-approved ceiling.
///
/// This constant is that ceiling. A no-compactor lane MUST reject NEW writes with a
/// typed error *before* it violates its declared capacity envelope rather than degrade
/// without bound (S-05, directive §10). The envelope here is the observed L0 SST count
/// read from the in-memory manifest (cheap: no directory walk, no remote LIST — the same
/// source [`SlateKeyspace::estimate_size_in_bytes`] reads). At or above this count,
/// [`SlateKeyspace::put`]/[`write`](SlateKeyspace::write) refuse with a typed
/// [`ErrorKind::Invalid`](slatedb::ErrorKind) admission error; below it they
/// succeed.
///
/// The value is a **containment default, not a ratified SLO** — it needs owner
/// ratification (docs/owner-decisions.json OD-007). It is set far above any healthy
/// short-lived workload while still bounding the envelope, and far below
/// [`SlateDB's own l0_max_ssts`](Settings::l0_max_ssts) backpressure ceiling so that
/// THIS typed refusal — not an opaque memtable-flush stall — is what a caller observes
/// first.
const EXPERIMENTAL_NO_COMPACTOR_MAX_L0_SSTS: usize = 50_000;

/// The pure admission decision for the no-compactor lane (S-05): a NEW write is admitted
/// only while the observed L0 SST count is strictly below the declared envelope. Pulled
/// out as a total function so the boundary is unit-testable without driving tens of
/// thousands of real flushes, and so the mutant (drop the `>=` guard) fails a named test.
fn admit_write_under_l0_bound(observed_l0_ssts: usize, max_l0_ssts: usize) -> Result<(), AdmissionRefused> {
    if observed_l0_ssts >= max_l0_ssts { Err(AdmissionRefused { observed_l0_ssts, max_l0_ssts }) } else { Ok(()) }
}

/// Typed refusal produced when the no-compactor lane is at its declared capacity
/// envelope (S-05). Non-transient by construction: it surfaces to the keyspace layer as
/// [`ErrorKind::Invalid`](slatedb::ErrorKind), the class the descending-scan retry
/// policy ([`retry_transient`]) does NOT retry — a full lane must refuse, not spin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AdmissionRefused {
    observed_l0_ssts: usize,
    max_l0_ssts: usize,
}

impl AdmissionRefused {
    /// Render as the typed SlateDB error the write path returns. `Invalid` (not
    /// `Unavailable`) because a saturated no-compactor lane is a persistent, caller-
    /// visible refusal to correct, never a transient blip to retry through.
    fn into_slate_error(self) -> slatedb::Error {
        slatedb::Error::invalid(format!(
            "no-compactor lane admission bound reached: {} L0 SSTs at or above the declared \
             capacity envelope of {} (S-05, EXPERIMENTAL; docs/owner-decisions.json OD-007); \
             refusing the write rather than degrading without bound",
            self.observed_l0_ssts, self.max_l0_ssts
        ))
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
    // compactor-less tests take (settings.l0_max_ssts = 10_000). The TypeDB
    // admission bound (EXPERIMENTAL_NO_COMPACTOR_MAX_L0_SSTS, S-05) sits far
    // below this, so a typed write refusal — not this opaque backpressure
    // stall — is what a saturated lane surfaces first.
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

/// External writer epoch for a SlateDB open (ADR-0012 fencing seam).
///
/// SlateDB's writer role is claimed against a monotone epoch: a build with the
/// `external_epoch_required` feature refuses any open that does not present one
/// (fail-closed — an unset epoch is a `SlateDBError::ExternalEpochRequired` at
/// open, never a silent fallback to internal observe-and-bind allocation), and
/// the manifest fences any open whose epoch is `<=` the stored writer epoch.
///
/// **This is the L1/local seam, and it is deliberately honest about its
/// limits.** The AUTHORITATIVE external-epoch source is the CONTROLLER: it
/// alone can hand two contending incarnations (a duplicate container, a stale
/// actor that lost its lease) epochs that totally order across processes and
/// machines, which is the property real fencing needs. TypeDB does not yet
/// carry that controller-issued number down to this adapter, so on the local
/// lane we mint a *process-anchored* monotone epoch instead: strictly
/// increasing for every open in this process, and seeded from the wall clock
/// so opens after a restart still exceed those before it (modulo a clock that
/// runs backwards). That fences a re-open by THIS server against the epoch its
/// own previous open persisted — it does NOT fence a concurrent foreign
/// incarnation, which only the controller's number can. When the controller
/// seam lands, this function is the single site that changes: it takes the
/// controller-provided writer epoch and this local fallback becomes the
/// no-controller degenerate case.
fn local_writer_epoch() -> u64 {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_micros().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0);
    // max(wall, last+1): wall-clock advance across opens/restarts, with a
    // strict +1 tie-break so rapid same-process opens never repeat an epoch
    // (a repeated epoch would be Fenced by the manifest, refusing a legitimate
    // re-open).
    loop {
        let prev = LAST.load(Ordering::Acquire);
        let next = wall.max(prev.saturating_add(1));
        if LAST.compare_exchange_weak(prev, next, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return next;
        }
    }
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

/// O-01: the remote key-count memo TTL. A metrics scrape re-scanning the whole
/// authoritative store on every ~15s poll is an availability hazard on the
/// remote lane; inside this window the memo answers with zero remote I/O.
const REMOTE_KEY_COUNT_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// O-01: a misconfigured cache budget must be a TYPED startup refusal, not a
/// silent fallback that disables the intended protection. This distinguishes
/// three cases the old `s3_cache_bytes` collapsed into `None`:
/// - unset            -> `Ok(None)` (cache deliberately off);
/// - explicit `0`     -> `Ok(None)` (operator explicitly disabled it);
/// - anything else bad -> `Err`     (was silently `None` — the exact "invalid
///   config silently disables protection" defect).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CacheConfigError {
    Invalid { value: String },
}

pub(super) fn validate_cache_config(raw: Option<&str>) -> Result<Option<usize>, CacheConfigError> {
    match raw {
        None => Ok(None),
        Some(text) => match text.trim().parse::<usize>() {
            Ok(0) => Ok(None),
            Ok(bytes) => Ok(Some(bytes)),
            Err(_) => Err(CacheConfigError::Invalid { value: text.to_owned() }),
        },
    }
}

/// Optional disk-cache budget, validated at startup (O-01). Unset or an explicit
/// `0` disables the cache; a set-but-invalid value is a typed refusal so a
/// fat-fingered budget cannot silently degrade every read to a remote round trip
/// while the operator believes the cache is on.
fn s3_cache_bytes() -> Result<Option<usize>, CacheConfigError> {
    let raw = std::env::var(S3_CACHE_BYTES_ENV).ok();
    validate_cache_config(raw.as_deref())
}

/// Render an invalid cache budget as a typed engine-open failure (O-01).
fn cache_config_error(error: &CacheConfigError) -> slatedb::Error {
    match error {
        CacheConfigError::Invalid { value } => slatedb::Error::unavailable(format!(
            "invalid {S3_CACHE_BYTES_ENV} value {value:?}: expected a byte count (0 or unset disables the cache); \
             refusing rather than silently disabling the read cache"
        )),
    }
}

/// O-01: is a memoised remote key count still fresh? Inside the TTL the cached
/// value is authoritative and NO remote scan runs; outside it (or with no memo)
/// a scan is required. Extracted so "a second call inside the TTL performs zero
/// remote I/O" is a deterministic, mutant-killable test — removing this TTL
/// check (always returning `None`) makes that test rescan and fail.
fn remote_key_count_is_fresh(
    memo: Option<(std::time::Instant, u64)>,
    ttl: std::time::Duration,
    now: std::time::Instant,
) -> Option<u64> {
    match memo {
        Some((at, count)) if now.saturating_duration_since(at) < ttl => Some(count),
        _ => None,
    }
}

/// O-01: drive a key count through the bounded-staleness memo. On the remote
/// lane a fresh memo short-circuits with zero I/O; otherwise the scan runs, and
/// its result is cached ONLY on success (a failed scan never caches a fabricated
/// count). The memo lock is held only for the two O(1) accesses, never across
/// the scan (audit F12). On the local lane the cache is bypassed (a local scan
/// is cheap and exactness beats staleness).
fn key_count_with_memo<E>(
    memo: &std::sync::Mutex<Option<(std::time::Instant, u64)>>,
    ttl: std::time::Duration,
    cache_enabled: bool,
    scan: impl FnOnce() -> Result<u64, E>,
) -> Result<u64, E> {
    if cache_enabled {
        let current = *memo.lock().unwrap();
        if let Some(count) = remote_key_count_is_fresh(current, ttl, std::time::Instant::now()) {
            return Ok(count);
        }
    }
    let count = scan()?;
    if cache_enabled {
        *memo.lock().unwrap() = Some((std::time::Instant::now(), count));
    }
    Ok(count)
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
/// only escape: `=s` for `/`, `==` for `=`, `=xHH` for any byte outside
/// `[A-Za-z0-9._-]`), so two distinct keyspace directories can never share a
/// prefix, and the prefix of a reopened directory is stable. It operates on
/// the path's RAW BYTES (`OsStr::as_encoded_bytes`), never on a lossy
/// UTF-8 rendering: `to_string_lossy` collapses every ill-formed sequence to
/// U+FFFD, so two byte-distinct non-UTF-8 directories would silently share a
/// prefix — the exact aliasing the injectivity claim exists to rule out.
/// Byte-wise `=xHH` escaping of non-ASCII produces the identical encoding to
/// the previous per-UTF-8-char escaping for all valid-UTF-8 paths, so every
/// existing prefix keeps resolving.
fn object_prefix(config: &S3Config, keyspace_path: &Path) -> ObjectPath {
    let mut encoded = String::new();
    for &byte in keyspace_path.as_os_str().as_encoded_bytes() {
        encode_segment_byte(byte, &mut encoded);
    }
    ObjectPath::from(config.root_prefix.as_str()).join(encoded)
}

/// The injective byte escaping both [`object_prefix`] and
/// [`MaterialisationNamespace`] use: `=` is the only escape (`=s` for `/`,
/// `==` for `=`, `=xHH` for any byte outside `[A-Za-z0-9._-]`), so distinct
/// byte strings never share an encoding.
fn encode_segment_byte(byte: u8, out: &mut String) {
    match byte {
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_' => out.push(byte as char),
        b'/' => out.push_str("=s"),
        b'=' => out.push_str("=="),
        other => out.push_str(&format!("=x{other:02x}")),
    }
}

fn encode_segment(value: &str) -> String {
    let mut out = String::new();
    for &byte in value.as_bytes() {
        encode_segment_byte(byte, &mut out);
    }
    out
}

/// A controller-provisioned materialisation namespace (S-01): the STABLE
/// tenant/database identity a remote object namespace derives from, made of
/// opaque identifiers the controller owns — NOT a host-local absolute path.
///
/// **Honest scope note.** The authoritative source of every field below is the
/// CONTROLLER (environment, tenant, `DatabaseId`, generation, materialisation,
/// keyspace). TypeDB does not yet carry those controller-issued identifiers
/// down to this adapter — that wiring is control-plane work not present in this
/// tree. This struct is the TYPED SEAM for it: the moment the controller
/// provides the identifiers, they flow through here and the object namespace
/// derives from THEM. Until then the local lanes fall back to
/// [`object_prefix`]'s host-path derivation (the S-01 defect this seam
/// replaces), whose instability across checkout roots / hosts is exactly why
/// the namespace must eventually derive from these opaque IDs instead.
///
/// The derivation is path-independent by construction: two handles for the same
/// `(environment, tenant, database_id, generation, materialisation, keyspace)`
/// resolve to the SAME object prefix on any machine or checkout, and changing
/// any one identifier changes the prefix (injective encoding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterialisationNamespace {
    pub environment: String,
    pub tenant: String,
    pub database_id: String,
    pub generation: String,
    pub materialisation: String,
    pub keyspace: String,
}

impl MaterialisationNamespace {
    /// Derive the object-store prefix from the controller identifiers ALONE —
    /// never from a host-local path. Each opaque segment is injectively
    /// encoded, so distinct identities can never alias and the same identity is
    /// stable across hosts and checkout roots (S-01 acceptance: "changing the
    /// local path cannot change the remote namespace").
    pub fn to_object_prefix(&self, root: &str) -> ObjectPath {
        ObjectPath::from(root)
            .join(encode_segment(&self.environment))
            .join(encode_segment(&self.tenant))
            .join(encode_segment(&self.database_id))
            .join(encode_segment(&self.generation))
            .join(encode_segment(&self.materialisation))
            .join(encode_segment(&self.keyspace))
    }
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

/// The immutable-data segment SlateDB writes its manifest under
/// (`<materialisation>/keyspace/manifest/…`). The manifest is the SOLE typed
/// conditional-CAS publication path (S-04) and is exempt from the create-only
/// immutability guard below — its own `PutMode` carries the CAS precondition
/// that publishes a new store version. Every other object under the keyspace
/// (SSTs, blobs) is immutable once written.
fn is_manifest_key(location: &ObjectPath) -> bool {
    location.parts().any(|part| part.as_ref() == MANIFEST_SUBDIR)
}

/// Compare an outgoing [`PutPayload`] against bytes already stored at an
/// immutable key: an idempotent replay must match in length AND content
/// (S-04: "exact same-key/same-length/same-digest replay"). Byte-exact
/// comparison is strictly stronger than a digest match — no collision window.
fn payload_matches_existing(payload: &PutPayload, existing: &[u8]) -> bool {
    if payload.content_length() != existing.len() {
        return false;
    }
    let mut offset = 0usize;
    for chunk in payload {
        let end = offset + chunk.len();
        if &existing[offset..end] != chunk.as_ref() {
            return false;
        }
        offset = end;
    }
    true
}

/// A dependency-free content checksum (std SipHash) for the immutability
/// LEDGER — the instrumentation that proves a referenced object's bytes never
/// change over its lifetime (S-04). Not a security digest; the accept/reject
/// decision uses byte-exact comparison, and this is only the recorded witness.
fn content_checksum(bytes: &[u8]) -> u64 {
    use std::hash::Hasher;
    // DefaultHasher::new() uses FIXED keys (unlike RandomState), so the same
    // bytes always produce the same checksum across calls — the property the
    // immutability ledger needs to compare a key's checksum over its lifetime.
    let mut hasher = std::hash::DefaultHasher::new();
    hasher.write(bytes);
    hasher.finish()
}

/// One journaled multipart upload attempt (S-04): completion is gated to the
/// still-active, uncommitted attempt for a location; a stale attempt (one a
/// newer attempt for the same location superseded) can neither complete nor
/// commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptState {
    /// Recorded, parts may still be uploaded, completion still permitted.
    Uncommitted,
    /// Completed exactly once; no further completion may replace it.
    Committed,
    /// Aborted; terminal.
    Aborted,
}

/// The runtime storage principal and immutability boundary (V16 inv. 81–84,
/// S-04). Delete authority is structurally removed AND ordinary conditional
/// puts / multipart completions can no longer replace bytes at an existing
/// immutable key:
///
/// - **create-only or exact same-digest replay** for immutable SST/blob keys:
///   a `put_opts` is forced to `PutMode::Create`; an `AlreadyExists` is
///   accepted only when the incoming bytes are byte-identical to what is
///   stored (idempotent retry), and a DIFFERENT-bytes put at an existing
///   immutable key is a typed [`Error::Precondition`] refusal that also raises
///   the materialisation's quarantine flag;
/// - the **manifest** path is exempt and passes through unchanged — it is the
///   sole typed conditional-CAS publication path;
/// - every **multipart** upload carries a journaled `UploadAttemptId` with
///   gated completion (completion only for the recorded uncommitted attempt;
///   abort only for that attempt; a stale attempt's completion is refused);
/// - `delete_stream` (the trait's only delete primitive: `delete`, and
///   `rename`'s copy-then-delete both funnel through it), overwrite-mode
///   `copy`, and `rename` are all typed refusals.
///
/// "Mere symbol absence is not proof": every clause is a runtime boundary a
/// probe exercises, not a compile-time convention.
#[derive(Debug)]
struct NoDeleteStore {
    inner: Arc<dyn ObjectStore>,
    /// Raised the first time a different-bytes overwrite of an immutable key
    /// is refused: the materialisation is no longer trustworthy and a
    /// supervisor should quarantine it (S-04). Shared so wrappers derived from
    /// this store observe the same flag.
    quarantined: Arc<AtomicBool>,
    /// Per-location multipart attempt journal: the active attempt id and its
    /// state. A completion is gated to the still-active, uncommitted attempt.
    multipart_journal: Arc<Mutex<HashMap<String, (u64, AttemptState)>>>,
    next_attempt_id: Arc<AtomicU64>,
    /// Immutability ledger (S-04 instrumentation): the recorded checksum of
    /// every immutable key this principal has admitted. Re-admitting a key
    /// whose checksum differs is the very overwrite the boundary refuses; the
    /// ledger lets a test prove bytes+checksum never change over a lifetime.
    immutable_ledger: Arc<Mutex<HashMap<String, u64>>>,
}

impl NoDeleteStore {
    fn new(inner: Arc<dyn ObjectStore>) -> Self {
        Self {
            inner,
            quarantined: Arc::new(AtomicBool::new(false)),
            multipart_journal: Arc::new(Mutex::new(HashMap::new())),
            next_attempt_id: Arc::new(AtomicU64::new(1)),
            immutable_ledger: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Whether a different-bytes overwrite of an immutable key was ever
    /// refused on this principal (S-04 quarantine signal).
    fn is_quarantined(&self) -> bool {
        self.quarantined.load(Ordering::SeqCst)
    }

    /// Record (or verify) an immutable key's checksum in the ledger. Returns
    /// `Err` if the key is already recorded with a DIFFERENT checksum — the
    /// witnessed proof that a referenced object's bytes changed.
    fn ledger_admit(&self, location: &ObjectPath, checksum: u64) -> Result<(), ()> {
        let mut ledger = self.immutable_ledger.lock().unwrap();
        match ledger.get(location.as_ref()) {
            Some(previous) if *previous != checksum => Err(()),
            _ => {
                ledger.insert(location.to_string(), checksum);
                Ok(())
            }
        }
    }

    /// The immutable-key branch of [`ObjectStore::put_opts`]: create-only, with
    /// an `AlreadyExists` accepted only for a byte-identical idempotent replay,
    /// and a different-bytes overwrite refused + quarantined.
    async fn put_immutable(
        &self,
        location: &ObjectPath,
        payload: PutPayload,
        opts: PutOptions,
    ) -> slatedb::object_store::Result<PutResult> {
        let checksum = {
            // materialise once for the ledger witness + comparison fallback
            let mut bytes = Vec::with_capacity(payload.content_length());
            for chunk in &payload {
                bytes.extend_from_slice(chunk.as_ref());
            }
            content_checksum(&bytes)
        };
        // Force create semantics regardless of the caller's requested mode: an
        // immutable key may only be written once (SlateDB names SSTs by unique
        // ULID, so a legitimate first write always creates).
        let create = PutOptions { mode: PutMode::Create, ..opts };
        match self.inner.put_opts(location, payload.clone(), create).await {
            Ok(result) => {
                // ledger records the admitted checksum; a create cannot
                // collide with a differing prior (the key was absent).
                let _ = self.ledger_admit(location, checksum);
                Ok(result)
            }
            Err(slatedb::object_store::Error::AlreadyExists { .. }) => {
                // an object is already here: allowed ONLY if byte-identical.
                let existing = self.inner.get(location).await?;
                let meta = existing.meta.clone();
                let existing_bytes = existing.bytes().await?;
                if payload_matches_existing(&payload, &existing_bytes) {
                    // idempotent replay of identical bytes: success, no rewrite
                    let _ = self.ledger_admit(location, checksum);
                    Ok(PutResult { e_tag: meta.e_tag, version: meta.version, extensions: Default::default() })
                } else {
                    self.quarantined.store(true, Ordering::SeqCst);
                    Err(slatedb::object_store::Error::Precondition {
                        path: location.to_string(),
                        source: format!(
                            "immutable key overwrite refused (S-04, V16 inv. 81-83): a put with \
                             different bytes at already-written immutable key {location} would replace \
                             authoritative data; the materialisation is quarantined"
                        )
                        .into(),
                    })
                }
            }
            Err(other) => Err(other),
        }
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
        // Fail-closed once quarantined (S-04): a materialisation that has
        // already refused a different-bytes overwrite is no longer trustworthy,
        // so every subsequent put — the manifest CAS path included — is refused
        // rather than layered on top of a detected immutability violation.
        if self.is_quarantined() {
            return Err(slatedb::object_store::Error::Precondition {
                path: location.to_string(),
                source: "materialisation is quarantined (S-04): a prior immutable-key overwrite was refused; \
                         refusing all further writes"
                    .into(),
            });
        }
        if is_manifest_key(location) {
            // the sole typed conditional-CAS publication path (S-04): its own
            // PutMode carries the CAS precondition; pass through unchanged.
            return self.inner.put_opts(location, payload, opts).await;
        }
        self.put_immutable(location, payload, opts).await
    }

    async fn put_multipart_opts(
        &self,
        location: &ObjectPath,
        opts: PutMultipartOptions,
    ) -> slatedb::object_store::Result<Box<dyn MultipartUpload>> {
        let inner = self.inner.put_multipart_opts(location, opts).await?;
        // Journal a fresh attempt id and record it as the active attempt for
        // this location; any earlier attempt for the same location is thereby
        // superseded and can no longer complete (S-04 stale-completion guard).
        let attempt_id = self.next_attempt_id.fetch_add(1, Ordering::SeqCst);
        self.multipart_journal.lock().unwrap().insert(location.to_string(), (attempt_id, AttemptState::Uncommitted));
        Ok(Box::new(JournaledMultipart {
            inner,
            location: location.clone(),
            attempt_id,
            journal: self.multipart_journal.clone(),
            manifest_key: is_manifest_key(location),
        }))
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

/// A multipart upload gated by the [`NoDeleteStore`] journal (S-04). Parts
/// stream straight through, but completion is admitted only for the still-
/// active, uncommitted attempt recorded for this location: a stale attempt
/// (one superseded by a newer `put_multipart_opts` on the same location) and
/// an already-committed attempt are both typed refusals, so a delayed or
/// duplicate actor can never complete a multipart that would replace bytes a
/// newer attempt already published. Abort is likewise allowed only for the
/// still-active, uncommitted attempt.
#[derive(Debug)]
struct JournaledMultipart {
    inner: Box<dyn MultipartUpload>,
    location: ObjectPath,
    attempt_id: u64,
    journal: Arc<Mutex<HashMap<String, (u64, AttemptState)>>>,
    /// Manifest multipart (should not occur — manifests are small single
    /// puts — but if one ever did, it is the CAS path and is not gated).
    manifest_key: bool,
}

impl JournaledMultipart {
    /// Is this attempt still the active, uncommitted one for its location?
    /// Returns the reason it is not, for a precise typed refusal.
    fn active_uncommitted(&self) -> Result<(), String> {
        if self.manifest_key {
            return Ok(());
        }
        let journal = self.journal.lock().unwrap();
        match journal.get(self.location.as_ref()) {
            Some((active_id, state)) if *active_id == self.attempt_id => match state {
                AttemptState::Uncommitted => Ok(()),
                AttemptState::Committed => Err("this attempt is already committed".to_owned()),
                AttemptState::Aborted => Err("this attempt was aborted".to_owned()),
            },
            Some((active_id, _)) => {
                Err(format!("attempt {} is stale; attempt {active_id} superseded it", self.attempt_id))
            }
            None => Err("no journal entry for this location".to_owned()),
        }
    }

    fn mark(&self, state: AttemptState) {
        if let Some(entry) = self.journal.lock().unwrap().get_mut(self.location.as_ref()) {
            if entry.0 == self.attempt_id {
                entry.1 = state;
            }
        }
    }
}

#[async_trait]
impl MultipartUpload for JournaledMultipart {
    fn put_part(&mut self, data: PutPayload) -> UploadPart {
        self.inner.put_part(data)
    }

    async fn complete(&mut self) -> slatedb::object_store::Result<PutResult> {
        if let Err(reason) = self.active_uncommitted() {
            return Err(slatedb::object_store::Error::Precondition {
                path: self.location.to_string(),
                source: format!(
                    "multipart completion refused for {} (S-04): {reason}; completion is gated to the \
                     recorded uncommitted upload attempt so a stale actor cannot replace published bytes",
                    self.location
                )
                .into(),
            });
        }
        let result = self.inner.complete().await?;
        self.mark(AttemptState::Committed);
        Ok(result)
    }

    async fn abort(&mut self) -> slatedb::object_store::Result<()> {
        if let Err(reason) = self.active_uncommitted() {
            return Err(slatedb::object_store::Error::Precondition {
                path: self.location.to_string(),
                source: format!(
                    "multipart abort refused for {} (S-04): {reason}; abort is allowed only for the \
                     still-uncommitted active attempt",
                    self.location
                )
                .into(),
            });
        }
        let result = self.inner.abort().await;
        self.mark(AttemptState::Aborted);
        result
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
        // R-06: fsync the downloaded file AND its parent directory. A checkpoint
        // the caller goes on to declare COMPLETE must not lose a downloaded SST
        // (or its directory entry) to a crash that empties the page cache; a
        // bare `fs::write` leaves both only in the page cache.
        write_and_fsync(&target, &bytes).map_err(io_error)?;
    }
    Ok(())
}

/// Write `bytes` to `path` and make the file AND its parent directory entry
/// durable (R-06). Extracted so the write-then-fsync sequence is one auditable
/// unit at every remote-download site.
fn write_and_fsync(path: &Path, bytes: &[u8]) -> io::Result<()> {
    {
        let mut file = fs::File::create(path)?;
        io::Write::write_all(&mut file, bytes)?;
        file.sync_all()?;
    }
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
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
    /// No-compactor lane admission envelope (S-05): the maximum observed L0
    /// SST count this keyspace admits NEW writes below. Defaults to
    /// [`EXPERIMENTAL_NO_COMPACTOR_MAX_L0_SSTS`]; tests lower it so the bound
    /// is reachable without driving 50k real flushes.
    admission_max_l0_ssts: usize,
}

impl SlateKeyspace {
    pub(super) fn open(path: &Path) -> Result<Self, Arc<slatedb::Error>> {
        fs::create_dir_all(path).map_err(|error| Arc::new(io_error(error)))?;
        let store: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix(path).map_err(|error| {
            Arc::new(slatedb::Error::unavailable(format!("local object store at {path:?}: {error}")))
        })?);
        let settings = settings();
        assert_pre_g13_posture(&settings).map_err(Arc::new)?;
        let epoch = local_writer_epoch();
        let db = bridge(async move {
            Db::builder(DB_SUBDIR, store).with_settings(settings).with_external_writer_epoch(epoch).build().await
        })
        .map_err(Arc::new)?;
        Ok(Self {
            db: Arc::new(db),
            path: path.to_owned(),
            remote: None,
            key_count_memo: Default::default(),
            admission_max_l0_ssts: EXPERIMENTAL_NO_COMPACTOR_MAX_L0_SSTS,
        })
    }

    /// Open over the configured S3-compatible store (TB-P8, profile U2S3).
    pub(super) fn open_s3(path: &Path) -> Result<Self, Arc<slatedb::Error>> {
        let config = s3_config().map_err(Arc::new)?;
        let store = build_s3_store(config).map_err(Arc::new)?;
        let base_prefix = object_prefix(config, path);
        // O-01: validate the cache budget at startup. An invalid budget is a
        // typed open failure, never a silent fallback that disables the cache.
        let cache_bytes = s3_cache_bytes().map_err(|error| Arc::new(cache_config_error(&error)))?;
        Self::open_remote(store, base_prefix, path, cache_bytes)
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
        let epoch = local_writer_epoch();
        let db = bridge(async move {
            Db::builder(DB_SUBDIR, prefixed).with_settings(settings).with_external_writer_epoch(epoch).build().await
        })
        .map_err(Arc::new)?;
        Ok(Self {
            db: Arc::new(db),
            path: path.to_owned(),
            remote: Some(RemoteStore { store, prefix }),
            key_count_memo: Default::default(),
            admission_max_l0_ssts: EXPERIMENTAL_NO_COMPACTOR_MAX_L0_SSTS,
        })
    }

    pub(super) fn shared_db(&self) -> Arc<Db> {
        self.db.clone()
    }

    /// Observed L0 SST count from the in-memory manifest — the cheap capacity
    /// signal the S-05 admission bound reads (same source, no directory walk
    /// or remote LIST, as [`Self::estimate_size_in_bytes`]).
    fn observed_l0_ssts(&self) -> usize {
        self.db.manifest().l0().iter().count()
    }

    /// S-05 admission gate: refuse a NEW write once the no-compactor lane sits
    /// at or above its declared L0 envelope, with the typed non-transient
    /// error, rather than let L0 grow without bound. Checked BEFORE the write
    /// touches the memtable so a refused write is a true no-op.
    fn check_admission(&self) -> Result<(), Arc<slatedb::Error>> {
        admit_write_under_l0_bound(self.observed_l0_ssts(), self.admission_max_l0_ssts)
            .map_err(|refused| Arc::new(refused.into_slate_error()))
    }

    /// Lower the S-05 admission envelope so an integration test can reach it
    /// without driving tens of thousands of real flushes. Test-only: the
    /// production ceiling is fixed at [`EXPERIMENTAL_NO_COMPACTOR_MAX_L0_SSTS`].
    #[cfg(test)]
    fn set_admission_max_l0_ssts_for_test(&mut self, max: usize) {
        self.admission_max_l0_ssts = max;
    }

    /// Force a memtable flush so the write just made becomes a countable L0
    /// SST (the admission signal). Test-only helper for the S-05 lane bound.
    #[cfg(test)]
    fn flush_for_test(&self) {
        let db = self.db.clone();
        bridge(async move { db.flush().await }).unwrap();
    }

    pub(super) fn put(&self, key: &[u8], value: &[u8]) -> Result<(), Arc<slatedb::Error>> {
        self.check_admission()?;
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
    /// FAILS CLOSED, with logger::error + process abort: the Option-only
    /// signature cannot carry an error, and the caller (vertex ID allocator
    /// seeding) would treat a silent None as "nothing allocated" and
    /// re-issue existing IDs — data corruption. An unwind is not enough
    /// (it can be caught, or kill only one worker thread while the rest of
    /// the server keeps serving on the unseeded allocator); a crash is
    /// recoverable, ID reuse is not.
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
                    // fail-stop, not panic: an unwind can be caught (or kill
                    // only one worker thread) and the server would keep
                    // serving with an allocator that was never seeded —
                    // exactly the silent ID reuse this branch exists to
                    // prevent. Abort so recovery restarts from the WAL.
                    logger::error!(
                        "FATAL: SlateDB floor scan (get_prev) failed ({attempt} transient retries); \
                         refusing to report absence and aborting: {error}"
                    );
                    std::process::abort()
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
        self.check_admission()?;
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
            Some(dir) => pin_newest_manifest(dir).map_err(|error| Arc::new(io_error(error)))?,
            None => None,
        };

        copy_dir_recursive_excluding(&self.path, checkpoint_keyspace_dir, manifest_dir.as_deref())
            .map_err(|error| Arc::new(io_error(error)))?;

        if let (Some(dir), Some(pinned)) = (&manifest_dir, &pinned_manifest) {
            let relative = dir.strip_prefix(&self.path).expect("manifest dir is under the keyspace path");
            let target_dir = checkpoint_keyspace_dir.join(relative);
            fs::create_dir_all(&target_dir).map_err(|error| Arc::new(io_error(error)))?;
            let target = target_dir.join(pinned.file_name().expect("manifest file name"));
            fs::copy(pinned, &target).map_err(|error| Arc::new(io_error(error)))?;
            // the pinned manifest is what restore opens: its bytes and its
            // directory entry must be durable, not just in the page cache
            crate::fsync_path(&target).map_err(|error| Arc::new(io_error(error)))?;
            crate::fsync_path(&target_dir).map_err(|error| Arc::new(io_error(error)))?;
        }
        // completion boundary: the checkpoint tree's root entry itself — a
        // checkpoint the caller goes on to declare finished must not lose
        // files to a crash that empties the page cache
        crate::fsync_path(checkpoint_keyspace_dir).map_err(|error| Arc::new(io_error(error)))?;
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
        // O-01: saturating wide aggregation. A no-compactor lane can accumulate
        // a very large L0; summing raw estimates with `+` risks an overflow that
        // panics in debug and wraps to a tiny fabricated size in release. The
        // metric saturates at u64::MAX instead — a large-but-true ceiling, never
        // a wrapped lie.
        let l0 = manifest.l0().iter().fold(0u64, |acc, sst| acc.saturating_add(sst.estimate_size()));
        let compacted = manifest.compacted().iter().fold(0u64, |acc, run| acc.saturating_add(run.estimate_size()));
        l0.saturating_add(compacted)
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
        let remote = self.remote.is_some();
        let db = self.db.clone();
        // O-01: a second call inside the TTL returns the memo and issues ZERO
        // remote I/O; a FAILED scan is never cached (no fabricated count); the
        // per-key increment saturates rather than overflowing. The decision and
        // driver are extracted (below) so those three properties are hermetic,
        // deterministic tests.
        key_count_with_memo(&self.key_count_memo, REMOTE_KEY_COUNT_TTL, remote, || {
            bridge(async move {
                let mut iterator = db.scan_with_options(.., &scan_options()).await?;
                let mut count = 0u64;
                while iterator.next().await?.is_some() {
                    count = count.saturating_add(1);
                }
                Ok(count)
            })
            .map_err(Arc::new)
        })
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
                if !self.absorb_forward_seek_outcome(outcome) {
                    return; // positioned — or poisoned, surfaced via status()
                }
                // recoverable: fall through to a fresh scan below
            }
        }
        self.fresh_scan(key);
    }

    /// Fold the outcome of an in-scan forward seek into the cursor. Returns
    /// `true` when the error is recoverable by starting a fresh scan.
    ///
    /// Only two error classes may be masked by a silent fresh scan:
    /// `Invalid` — the seek positioning contract (`SeekKeyOutOfRange`,
    /// `SeekKeyLessThanLastReturnedKey`: e.g. a seek at/behind the last
    /// yielded key on a scan whose current item was already consumed), where
    /// a fresh scan re-establishes a valid range — and `Unavailable`,
    /// SlateDB's contractual transient class, where the fresh scan is the
    /// retry (its own failure is recorded, so this cannot loop). Every other
    /// kind (Data, Internal, Closed, Transaction) is real corruption or a
    /// bug — including a sticky invalidation error replayed from an earlier
    /// failed read — and retrying the scan would silently mask it as an
    /// empty/short result; the cursor is poisoned instead and the error
    /// surfaces through [`Self::status`].
    fn absorb_forward_seek_outcome(&mut self, outcome: Result<Option<slatedb::KeyValue>, slatedb::Error>) -> bool {
        match outcome {
            Ok(item) => {
                self.record(Ok(item));
                false
            }
            Err(error) if matches!(error.kind(), slatedb::ErrorKind::Invalid | slatedb::ErrorKind::Unavailable) => true,
            Err(error) => {
                self.iterator = None;
                self.record(Err(error));
                false
            }
        }
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

/// Pin the newest manifest file in `manifest_dir` (lexicographic max = newest,
/// the same ordering `checkpoint_remote` applies to manifest object names).
///
/// Every directory-entry error is PROPAGATED: the erroring entry could be the
/// newest manifest, and dropping it would silently pin an older manifest while
/// the checkpoint metadata claims the current watermark — restore then replays
/// from watermark+1 and silently skips the commits in between. For the same
/// reason a nonempty manifest directory in which no manifest file can be
/// pinned is an error, never a silent no-manifest checkpoint.
fn pin_newest_manifest(manifest_dir: &Path) -> io::Result<Option<PathBuf>> {
    let mut newest: Option<PathBuf> = None;
    let mut nonempty = false;
    for entry in fs::read_dir(manifest_dir)? {
        let entry = entry?;
        nonempty = true;
        let path = entry.path();
        // follows symlinks, so a dangling link or otherwise unreadable entry
        // is an error here rather than a silently skipped candidate
        let metadata = fs::metadata(&path)?;
        if metadata.is_file() && newest.as_ref().is_none_or(|max| &path > max) {
            newest = Some(path);
        }
    }
    if nonempty && newest.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("manifest directory {manifest_dir:?} is nonempty but holds no manifest file to pin"),
        ));
    }
    Ok(newest)
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
            // checkpoint durability boundary: the copy must be on disk, not
            // just in the page cache, before the checkpoint is declared done
            crate::fsync_path(&target)?;
        }
    }
    // and the copied names themselves must be durable in this directory
    crate::fsync_path(to)?;
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
mod checkpoint_pin_tests {
    //! S-P0-04 controls: manifest pinning must never silently drop an
    //! erroring directory entry (the dropped entry could be the newest
    //! manifest — the checkpoint would then claim the current watermark
    //! while pinning an older manifest, and restore would skip commits).
    //! The mutant "swallow entry errors with `.ok()` / `is_file()`" fails
    //! the dangling-symlink tests below.

    use std::fs;

    use test_utils::create_tmp_dir;

    use super::{SlateKeyspace, pin_newest_manifest};

    #[test]
    fn pin_newest_manifest_orders_and_tolerates_the_empty_dir() {
        let dir = create_tmp_dir("slate-pin");
        assert_eq!(pin_newest_manifest(&dir).unwrap(), None, "an empty manifest dir pins nothing");
        fs::write(dir.join("00000000000000000001.manifest"), b"old").unwrap();
        fs::write(dir.join("00000000000000000002.manifest"), b"new").unwrap();
        let pinned = pin_newest_manifest(&dir).unwrap().expect("a manifest file must be pinned");
        assert_eq!(pinned.file_name().unwrap(), "00000000000000000002.manifest", "lexicographic max = newest");
    }

    #[test]
    fn an_erroring_manifest_entry_fails_the_pin_instead_of_pinning_an_older_manifest() {
        let dir = create_tmp_dir("slate-pin-err");
        fs::write(dir.join("00000000000000000001.manifest"), b"old").unwrap();
        // the dangling symlink sorts AFTER the readable manifest: swallowing
        // its metadata error would silently pin the older manifest
        std::os::unix::fs::symlink(dir.join("nonexistent-target"), dir.join("00000000000000000002.manifest")).unwrap();
        let refused = pin_newest_manifest(&dir);
        assert!(refused.is_err(), "an unreadable candidate entry must fail the pin, not be dropped: {refused:?}");
    }

    #[test]
    fn a_nonempty_manifest_dir_with_no_pinnable_manifest_is_an_error_not_a_silent_none() {
        let dir = create_tmp_dir("slate-pin-none");
        fs::create_dir(dir.join("unexpected-subdirectory")).unwrap();
        let refused = pin_newest_manifest(&dir);
        assert!(
            refused.is_err(),
            "a nonempty manifest dir in which nothing can be pinned would checkpoint a store \
             restore cannot open — it must be an error: {refused:?}"
        );
    }

    #[test]
    fn a_broken_manifest_entry_fails_the_whole_checkpoint() {
        // end-to-end: the same control through SlateKeyspace::checkpoint_local
        let keyspace_dir = create_tmp_dir("slate-ckpt-broken");
        let keyspace = SlateKeyspace::open(&keyspace_dir).unwrap();
        keyspace.put(b"k", b"v").unwrap();

        let good_checkpoint = create_tmp_dir("slate-ckpt-out-good");
        keyspace.checkpoint(&good_checkpoint).unwrap();

        let manifest_dir = super::find_manifest_dir(&keyspace_dir).unwrap().expect("open keyspace has a manifest dir");
        std::os::unix::fs::symlink(manifest_dir.join("nonexistent-target"), manifest_dir.join("zzzz-dangling"))
            .unwrap();
        let broken_checkpoint = create_tmp_dir("slate-ckpt-out-broken");
        let refused = keyspace.checkpoint_local(&broken_checkpoint);
        assert!(refused.is_err(), "an erroring manifest entry must fail the checkpoint: {refused:?}");
        fs::remove_file(manifest_dir.join("zzzz-dangling")).unwrap();
    }
}

#[cfg(test)]
mod cursor_seek_error_tests {
    //! S-P1-01 control: a forward-seek failure may be masked by a fresh scan
    //! ONLY for the transient (Unavailable) and seek-positioning (Invalid)
    //! classes; Data/Internal/Closed poison the cursor and surface through
    //! `status()`. The mutant "fresh-scan on every error" (the previous
    //! `Err(_) =>` arm) fails `a_data_error_poisons_the_cursor…`.

    use test_utils::create_tmp_dir;

    use super::{SlateCursor, SlateKeyspace};

    fn positioned_cursor() -> (test_utils::TempDir, SlateKeyspace, SlateCursor) {
        let dir = create_tmp_dir("slate-cursor-poison");
        let keyspace = SlateKeyspace::open(&dir).unwrap();
        keyspace.put(b"a", b"1").unwrap();
        keyspace.put(b"b", b"2").unwrap();
        let mut cursor = SlateCursor::new(keyspace.shared_db());
        cursor.seek(b"a");
        assert_eq!(cursor.key(), Some(b"a".as_slice()), "fixture: cursor is positioned mid-scan");
        (dir, keyspace, cursor)
    }

    #[test]
    fn a_data_error_poisons_the_cursor_and_surfaces_through_status() {
        let (_dir, _keyspace, mut cursor) = positioned_cursor();
        let needs_fresh_scan = cursor.absorb_forward_seek_outcome(Err(slatedb::Error::data("corrupt sst".to_string())));
        assert!(!needs_fresh_scan, "a Data error must never be masked by a silent fresh scan");
        assert!(cursor.status().is_err(), "the corruption must surface through status()");
        assert_eq!(cursor.item(), None, "a poisoned cursor exposes no item");

        let (_dir2, _keyspace2, mut cursor2) = positioned_cursor();
        assert!(
            !cursor2.absorb_forward_seek_outcome(Err(slatedb::Error::internal("bug".to_string()))),
            "Internal errors poison too"
        );
        assert!(cursor2.status().is_err());
    }

    #[test]
    fn positioning_and_transient_errors_are_recovered_by_a_fresh_scan() {
        let (_dir, _keyspace, mut cursor) = positioned_cursor();
        assert!(
            cursor.absorb_forward_seek_outcome(Err(slatedb::Error::invalid(
                "seek key comes before the current iterator position".to_string()
            ))),
            "the seek positioning contract is recovered by a fresh scan"
        );
        assert!(cursor.status().is_ok(), "a recoverable outcome must not poison the cursor");
        assert!(
            cursor.absorb_forward_seek_outcome(Err(slatedb::Error::unavailable("s3 blip".to_string()))),
            "the contractual transient class is retried via the fresh scan"
        );

        // and a real end-to-end forward seek still works
        cursor.seek(b"b");
        assert_eq!(cursor.key(), Some(b"b".as_slice()));
        assert!(cursor.status().is_ok());
    }
}

#[cfg(test)]
mod object_prefix_tests {
    //! S-P1-04 control: the keyspace-path → object-prefix encoding is
    //! injective over raw path BYTES. `to_string_lossy` folded every
    //! ill-formed sequence to U+FFFD, so byte-distinct non-UTF-8 paths
    //! aliased one prefix — two keyspaces sharing a store namespace.

    use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path};

    use super::{S3Config, object_prefix};

    fn config() -> S3Config {
        S3Config {
            endpoint: "http://127.0.0.1:9000".to_owned(),
            bucket: "bucket".to_owned(),
            region: "auto".to_owned(),
            access_key_id: "key".to_owned(),
            secret_access_key: "secret".to_owned(),
            root_prefix: "typedb".to_owned(),
        }
    }

    #[test]
    fn ascii_paths_keep_their_established_encoding() {
        // pure-ASCII paths (every existing deployment) must resolve to the
        // exact prefix the previous encoder produced
        let prefix = object_prefix(&config(), Path::new("/tmp/data-1.db/ks_A"));
        assert_eq!(prefix.as_ref(), "typedb/=stmp=sdata-1.db=sks_A");
        let escaped = object_prefix(&config(), Path::new("/tmp/a=b c"));
        assert_eq!(escaped.as_ref(), "typedb/=stmp=sa==b=x20c");
    }

    #[test]
    fn byte_distinct_non_utf8_paths_never_share_a_prefix() {
        let path_a = Path::new(OsStr::from_bytes(b"/tmp/ks-\xff\xfe"));
        let path_b = Path::new(OsStr::from_bytes(b"/tmp/ks-\xfe\xff"));
        assert_ne!(path_a, path_b, "fixture: the paths are byte-distinct");
        assert_eq!(
            path_a.to_string_lossy(),
            path_b.to_string_lossy(),
            "fixture: a lossy rendering aliases them — exactly what the encoding must not do"
        );
        let prefix_a = object_prefix(&config(), path_a);
        let prefix_b = object_prefix(&config(), path_b);
        assert_ne!(prefix_a, prefix_b, "distinct keyspace directories must never share an object prefix");
        assert_eq!(prefix_a.as_ref(), "typedb/=stmp=sks-=xff=xfe");
        assert_eq!(prefix_b.as_ref(), "typedb/=stmp=sks-=xfe=xff");
    }
}

#[cfg(test)]
mod materialisation_namespace_tests {
    //! S-01: the controller-provisioned namespace seam. The remote object
    //! namespace derives from opaque controller identifiers, NOT a host-local
    //! path — so changing the local path (or moving between checkout roots /
    //! hosts) cannot change the remote namespace, and distinct identities never
    //! alias.

    use super::MaterialisationNamespace;

    fn namespace() -> MaterialisationNamespace {
        MaterialisationNamespace {
            environment: "prod".to_owned(),
            tenant: "acme".to_owned(),
            database_id: "db-0197f".to_owned(),
            generation: "g7".to_owned(),
            materialisation: "m0001".to_owned(),
            keyspace: "data".to_owned(),
        }
    }

    #[test]
    fn the_namespace_derives_from_controller_ids_and_is_independent_of_any_local_path() {
        // the derivation takes NO path argument: the same controller identity
        // yields the same prefix on any machine or checkout root.
        let ns = namespace();
        let prefix_here = ns.to_object_prefix("typedb");
        let prefix_elsewhere = ns.clone().to_object_prefix("typedb");
        assert_eq!(prefix_here, prefix_elsewhere, "the same controller identity must resolve to the same namespace");
        assert_eq!(prefix_here.as_ref(), "typedb/prod/acme/db-0197f/g7/m0001/data");
    }

    #[test]
    fn a_different_controller_identity_changes_the_namespace() {
        // injectivity: changing any one opaque identifier changes the prefix.
        let base = namespace().to_object_prefix("typedb");
        for mutate in [
            |n: &mut MaterialisationNamespace| n.environment = "staging".to_owned(),
            |n: &mut MaterialisationNamespace| n.tenant = "globex".to_owned(),
            |n: &mut MaterialisationNamespace| n.database_id = "db-other".to_owned(),
            |n: &mut MaterialisationNamespace| n.generation = "g8".to_owned(),
            |n: &mut MaterialisationNamespace| n.materialisation = "m0002".to_owned(),
            |n: &mut MaterialisationNamespace| n.keyspace = "schema".to_owned(),
        ] {
            let mut ns = namespace();
            mutate(&mut ns);
            assert_ne!(ns.to_object_prefix("typedb"), base, "a changed controller id must change the namespace");
        }
    }

    #[test]
    fn opaque_identifiers_are_injectively_encoded() {
        // segment boundaries cannot be forged by embedding separators in an id.
        let sneaky = MaterialisationNamespace {
            environment: "a/b".to_owned(),
            tenant: "t".to_owned(),
            database_id: "d".to_owned(),
            generation: "g".to_owned(),
            materialisation: "m".to_owned(),
            keyspace: "k".to_owned(),
        };
        // the '/' is escaped, not treated as a path separator
        assert_eq!(sneaky.to_object_prefix("typedb").as_ref(), "typedb/a=sb/t/d/g/m/k");
    }
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

    use super::{bridge, local_writer_epoch, read_options, scan_options, settings, write_options};

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
                        .with_external_writer_epoch(local_writer_epoch())
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

#[cfg(test)]
mod admission_bound_tests {
    //! S-05: the no-compactor lane is EXPERIMENTAL and admission-bounded. It
    //! must refuse NEW writes with a typed, non-transient error once the
    //! observed L0 SST count reaches the declared capacity envelope, rather
    //! than let L0 grow without bound. The pure decision is pinned directly
    //! (so the mutant — relaxing `>=` to `>` — fails a named test without
    //! driving 50k real flushes), and one integration test drives a lowered
    //! envelope to a real refusal at the write boundary and proves the refused
    //! write is a no-op.

    use test_utils::create_tmp_dir;

    use super::{AdmissionRefused, EXPERIMENTAL_NO_COMPACTOR_MAX_L0_SSTS, SlateKeyspace, admit_write_under_l0_bound};

    #[test]
    fn the_experimental_envelope_is_a_named_bounded_default() {
        // S-05 requires the posture stay EXPLICITLY experimental and bounded:
        // a finite, non-zero ceiling that leaves headroom below SlateDB's own
        // l0_max_ssts backpressure so the typed refusal — not an opaque stall
        // — is what a saturated lane surfaces first.
        assert!(EXPERIMENTAL_NO_COMPACTOR_MAX_L0_SSTS > 0, "the envelope must be a positive bound");
        assert!(
            EXPERIMENTAL_NO_COMPACTOR_MAX_L0_SSTS < super::settings().l0_max_ssts,
            "the admission bound must fire before SlateDB's own l0_max_ssts backpressure stall",
        );
    }

    #[test]
    fn below_the_envelope_a_write_is_admitted() {
        // positive: strictly below the declared L0 count admits.
        assert_eq!(admit_write_under_l0_bound(0, 3), Ok(()));
        assert_eq!(admit_write_under_l0_bound(2, 3), Ok(()));
    }

    #[test]
    fn at_or_above_the_envelope_a_write_is_refused_with_the_typed_error() {
        // negative: AT the bound (==) and ABOVE it (>) both refuse — this is
        // the exact case the mutant (`>=` -> `>`) would wrongly admit at the
        // boundary, so this test is the mutant's named catcher.
        assert_eq!(admit_write_under_l0_bound(3, 3), Err(AdmissionRefused { observed_l0_ssts: 3, max_l0_ssts: 3 }));
        assert_eq!(admit_write_under_l0_bound(9, 3), Err(AdmissionRefused { observed_l0_ssts: 9, max_l0_ssts: 3 }));

        // the rendered SlateDB error is the non-transient Invalid class (not
        // Unavailable, which the descending-scan retry policy would spin on)
        // and names the S-05 envelope.
        let error = AdmissionRefused { observed_l0_ssts: 3, max_l0_ssts: 3 }.into_slate_error();
        assert_eq!(error.kind(), slatedb::ErrorKind::Invalid, "a full lane is a persistent refusal, not transient");
        let message = error.to_string();
        assert!(message.contains("admission bound"), "the error must name the admission bound: {message}");
        assert!(message.contains("OD-007"), "the error must cite the owner decision: {message}");
    }

    #[test]
    fn at_the_real_write_boundary_the_lane_refuses_over_its_envelope_and_the_refusal_is_a_no_op() {
        // integration: a local SlateDB keyspace with the envelope lowered to 2
        // L0 SSTs. Each write+flush mints one L0 SST; the third write, with
        // L0 already at the bound, must refuse with the typed error, and the
        // refused key must be absent (the check runs BEFORE the memtable put).
        let keyspace_dir = create_tmp_dir("slate-s05-admission");
        let mut keyspace = SlateKeyspace::open(&keyspace_dir).expect("open local keyspace");
        keyspace.set_admission_max_l0_ssts_for_test(2);

        // below the bound: two writes succeed, each flushed into its own L0 SST
        keyspace.put(b"k1", b"v1").expect("write below the envelope is admitted");
        keyspace.flush_for_test();
        keyspace.put(b"k2", b"v2").expect("write below the envelope is admitted");
        keyspace.flush_for_test();
        assert_eq!(keyspace.observed_l0_ssts(), 2, "two flushed writes must have produced two L0 SSTs");

        // at the bound: the next write is refused with the typed admission error
        let refused = keyspace.put(b"k3", b"v3");
        let error = refused.expect_err("a write at the declared L0 envelope must be refused");
        assert_eq!(error.kind(), slatedb::ErrorKind::Invalid, "the refusal is the non-transient Invalid class");
        assert!(error.to_string().contains("admission bound"), "typed S-05 refusal: {error}");

        // the refused write is a true no-op: k3 never reached the memtable
        assert!(
            keyspace.get(b"k3", |v| v.to_vec()).expect("read must still work").is_none(),
            "a refused write must not have touched the store",
        );
        // and the batch write path is gated by the same bound
        let batch_refused = keyspace.write(&[(b"k4".to_vec(), b"v4".to_vec())]);
        assert!(
            batch_refused.is_err_and(|e| e.kind() == slatedb::ErrorKind::Invalid),
            "the batch write path must be admission-gated too",
        );
    }
}

#[cfg(test)]
mod immutability_boundary_tests {
    //! S-04: `NoDeleteStore` is a real immutability boundary, not merely a
    //! delete-blocker. Ordinary conditional puts and multipart completions can
    //! no longer replace bytes at an existing immutable key. Every clause is an
    //! exercised runtime boundary; the mutants (make put_opts unconditional,
    //! accept a changed-byte replay, let a stale multipart complete) each fail
    //! a named test.

    use std::sync::Arc;

    use slatedb::object_store::{
        MultipartUpload, ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload, local::LocalFileSystem,
        path::Path as ObjectPath,
    };
    use test_utils::create_tmp_dir;

    use super::{
        AttemptState, MANIFEST_SUBDIR, NoDeleteStore, bridge, content_checksum, is_manifest_key,
        payload_matches_existing,
    };

    fn wrapped_store() -> (test_utils::TempDir, Arc<NoDeleteStore>) {
        let dir = create_tmp_dir("slate-s04-store");
        let inner: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix(&*dir).unwrap());
        (dir, Arc::new(NoDeleteStore::new(inner)))
    }

    #[test]
    fn manifest_keys_are_classified_apart_from_immutable_data_keys() {
        // the manifest is the sole CAS publication path (exempt); everything
        // else under the keyspace is immutable.
        assert!(is_manifest_key(&ObjectPath::from(format!("base/fv1/m1/keyspace/{MANIFEST_SUBDIR}/0001.manifest"))));
        assert!(!is_manifest_key(&ObjectPath::from("base/fv1/m1/keyspace/01ABC.sst")));
        assert!(!is_manifest_key(&ObjectPath::from("base/fv1/m1/keyspace/compacted/01ABC.sst")));
    }

    #[test]
    fn the_payload_match_is_length_and_byte_exact() {
        let payload = PutPayload::from_static(b"authoritative bytes");
        assert!(payload_matches_existing(&payload, b"authoritative bytes"), "identical bytes match");
        assert!(!payload_matches_existing(&payload, b"authoritative byteS"), "one flipped byte must not match");
        assert!(!payload_matches_existing(&payload, b"authoritative"), "a length mismatch must not match");
        // and the ledger checksum is stable and content-addressed
        assert_eq!(content_checksum(b"authoritative bytes"), content_checksum(b"authoritative bytes"));
        assert_ne!(content_checksum(b"authoritative bytes"), content_checksum(b"authoritative byteS"));
    }

    #[test]
    fn a_first_write_to_an_immutable_key_is_admitted_and_an_identical_replay_is_idempotent() {
        // positive: create then an exact-bytes replay both succeed, the store
        // is never quarantined, and the bytes are unchanged.
        let (_dir, store) = wrapped_store();
        let key = ObjectPath::from("base/fv1/m1/keyspace/01ABC.sst");
        bridge({
            let (store, key) = (store.clone(), key.clone());
            async move {
                store.put(&key, PutPayload::from_static(b"sst bytes")).await.expect("first write creates");
                // idempotent replay of identical bytes: admitted, no rewrite
                store.put(&key, PutPayload::from_static(b"sst bytes")).await.expect("identical replay is idempotent");
            }
        });
        assert!(!store.is_quarantined(), "an identical replay must not quarantine the materialisation");
        let bytes = bridge({
            let (store, key) = (store.clone(), key.clone());
            async move { store.get(&key).await.unwrap().bytes().await.unwrap() }
        });
        assert_eq!(&bytes[..], b"sst bytes", "the immutable object's bytes are unchanged");
    }

    #[test]
    fn a_different_bytes_overwrite_of_an_immutable_key_is_refused_and_quarantines() {
        // negative + mutant catcher: an ordinary (default Overwrite) put with
        // DIFFERENT bytes at an already-written immutable key must be a typed
        // Precondition refusal, must NOT change the stored bytes, and must set
        // the quarantine flag. This is exactly what an unconditional
        // `put_opts` (the removed defect) would silently allow.
        let (_dir, store) = wrapped_store();
        let key = ObjectPath::from("base/fv1/m1/keyspace/01ABC.sst");
        bridge({
            let (store, key) = (store.clone(), key.clone());
            async move { store.put(&key, PutPayload::from_static(b"authoritative")).await }
        })
        .expect("first write creates");

        let refused = bridge({
            let (store, key) = (store.clone(), key.clone());
            // default put mode is Overwrite — the ordinary conditional put the
            // wrapper used to forward unconditionally
            async move { store.put(&key, PutPayload::from_static(b"tampered!!!!!")).await }
        });
        assert!(
            matches!(refused, Err(slatedb::object_store::Error::Precondition { .. })),
            "a different-bytes overwrite of an immutable key must be a typed Precondition refusal, got: {refused:?}",
        );
        assert!(store.is_quarantined(), "a refused overwrite must quarantine the materialisation");
        // the authoritative bytes are untouched — the boundary held
        let bytes = bridge({
            let (store, key) = (store.clone(), key.clone());
            async move { store.get(&key).await.unwrap().bytes().await.unwrap() }
        });
        assert_eq!(&bytes[..], b"authoritative", "the referenced object's bytes must never change over its lifetime");
    }

    #[test]
    fn once_quarantined_every_further_write_fails_closed() {
        // S-04: after a different-bytes overwrite quarantines the
        // materialisation, even a write to a fresh, never-written key is
        // refused — the principal is no longer trustworthy.
        let (_dir, store) = wrapped_store();
        let key = ObjectPath::from("base/fv1/m1/keyspace/01ABC.sst");
        let fresh = ObjectPath::from("base/fv1/m1/keyspace/09XYZ.sst");
        let refused_after = bridge({
            let (store, key, fresh) = (store.clone(), key.clone(), fresh.clone());
            async move {
                store.put(&key, PutPayload::from_static(b"authoritative")).await?;
                // trigger quarantine
                let _ = store.put(&key, PutPayload::from_static(b"tampered!!!!!")).await;
                // a brand-new key must now also be refused
                Ok::<_, slatedb::object_store::Error>(store.put(&fresh, PutPayload::from_static(b"new")).await)
            }
        })
        .unwrap();
        assert!(store.is_quarantined());
        assert!(
            matches!(refused_after, Err(slatedb::object_store::Error::Precondition { .. })),
            "a quarantined materialisation must refuse all further writes, got: {refused_after:?}",
        );
    }

    #[test]
    fn an_explicit_create_mode_overwrite_attempt_is_also_refused() {
        // even a caller that asks for Create at an occupied immutable key is
        // refused (AlreadyExists reconciles to a differing-bytes refusal),
        // proving the guard is not merely rewriting the default mode.
        let (_dir, store) = wrapped_store();
        let key = ObjectPath::from("base/fv1/m1/keyspace/01ABC.sst");
        let occupied = bridge({
            let (store, key) = (store.clone(), key.clone());
            async move {
                store.put(&key, PutPayload::from_static(b"authoritative")).await?;
                store
                    .put_opts(
                        &key,
                        PutPayload::from_static(b"different bytes"),
                        PutOptions { mode: PutMode::Create, ..Default::default() },
                    )
                    .await
            }
        });
        assert!(
            matches!(occupied, Err(slatedb::object_store::Error::Precondition { .. })),
            "a create at an occupied immutable key with different bytes must refuse, got: {occupied:?}",
        );
    }

    #[test]
    fn a_manifest_key_is_exempt_and_may_be_republished() {
        // the manifest is the sole CAS publication path: an overwrite-mode put
        // at a manifest key passes through (SlateDB's manifest CAS depends on
        // this), and the wrapper does NOT quarantine on it.
        let (_dir, store) = wrapped_store();
        let manifest = ObjectPath::from(format!("base/fv1/m1/keyspace/{MANIFEST_SUBDIR}/0001.manifest"));
        let republished = bridge({
            let (store, manifest) = (store.clone(), manifest.clone());
            async move {
                store.put(&manifest, PutPayload::from_static(b"manifest v1")).await?;
                // an ordinary overwrite of the manifest key succeeds (CAS path)
                store.put(&manifest, PutPayload::from_static(b"manifest v2 republished")).await
            }
        });
        assert!(republished.is_ok(), "the manifest CAS path must not be blocked, got: {republished:?}");
        assert!(!store.is_quarantined(), "republishing the manifest is not a quarantine event");
    }

    #[test]
    fn a_stale_multipart_completion_is_refused_but_the_active_attempt_completes() {
        // S-04 multipart gating + mutant catcher: two attempts opened on one
        // location. The first is superseded (stale) by the second; completing
        // the stale attempt is a typed refusal, while the active attempt
        // completes. A wrapper that forwarded completion unconditionally (the
        // removed defect) would let the stale actor publish.
        let (_dir, store) = wrapped_store();
        let location = ObjectPath::from("base/fv1/m1/keyspace/02DEF.sst");

        let outcome = bridge({
            let (store, location) = (store.clone(), location.clone());
            async move {
                let mut stale = store.put_multipart(&location).await?;
                let mut active = store.put_multipart(&location).await?;
                stale.put_part(PutPayload::from_static(b"stale part")).await?;
                active.put_part(PutPayload::from_static(b"active part")).await?;
                // completing the stale (superseded) attempt is refused
                let stale_completion = stale.complete().await;
                // the active attempt completes
                let active_completion = active.complete().await;
                Ok::<_, slatedb::object_store::Error>((stale_completion, active_completion))
            }
        })
        .unwrap();

        assert!(
            matches!(outcome.0, Err(slatedb::object_store::Error::Precondition { .. })),
            "a stale multipart completion must be a typed refusal, got: {:?}",
            outcome.0,
        );
        assert!(outcome.1.is_ok(), "the active, uncommitted attempt must complete, got: {:?}", outcome.1);

        // and the published bytes are the active attempt's
        let bytes = bridge({
            let (store, location) = (store.clone(), location.clone());
            async move { store.get(&location).await.unwrap().bytes().await.unwrap() }
        });
        assert_eq!(&bytes[..], b"active part", "the active attempt's bytes must be what is published");
    }

    #[test]
    fn a_committed_multipart_cannot_be_completed_a_second_time() {
        // completion can never replace a committed object: a second complete()
        // on the same attempt is refused.
        let (_dir, store) = wrapped_store();
        let location = ObjectPath::from("base/fv1/m1/keyspace/03GHI.sst");
        let second = bridge({
            let (store, location) = (store.clone(), location.clone());
            async move {
                let mut upload = store.put_multipart(&location).await?;
                upload.put_part(PutPayload::from_static(b"the bytes")).await?;
                upload.complete().await?;
                // a second completion of an already-committed attempt
                Ok::<_, slatedb::object_store::Error>(upload.complete().await)
            }
        })
        .unwrap();
        assert!(
            matches!(second, Err(slatedb::object_store::Error::Precondition { .. })),
            "a committed multipart must not complete again, got: {second:?}",
        );
    }

    #[test]
    fn the_attempt_journal_supersedes_the_earlier_attempt() {
        // white-box: opening a second multipart on a location records it as
        // the active attempt and marks the first stale (the mechanism the
        // stale-completion refusal rests on).
        let (_dir, store) = wrapped_store();
        let location = ObjectPath::from("base/fv1/m1/keyspace/04JKL.sst");
        bridge({
            let (store, location) = (store.clone(), location.clone());
            async move {
                let _first = store.put_multipart(&location).await.unwrap();
                let _second = store.put_multipart(&location).await.unwrap();
            }
        });
        let journal = store.multipart_journal.lock().unwrap();
        let (active_id, state) = journal.get(location.as_ref()).copied().expect("a journal entry exists");
        assert_eq!(active_id, 2, "the second attempt is the active one");
        assert_eq!(state, AttemptState::Uncommitted);
    }
}

#[cfg(test)]
mod metrics_budget_tests {
    //! O-01: metrics are total, typed, and budgeted. The memo decision/driver
    //! and cache-config validation are pure, so these properties are hermetic
    //! deterministic tests with executable mutants.

    use std::{
        cell::Cell,
        sync::Mutex,
        time::{Duration, Instant},
    };

    use super::{CacheConfigError, key_count_with_memo, remote_key_count_is_fresh, validate_cache_config};

    #[test]
    fn a_second_call_inside_the_ttl_performs_zero_remote_io() {
        // O-01 flagship: within the TTL the memo answers and the scan closure is
        // NEVER invoked. Removing the TTL freshness check (the mutant) makes the
        // second call rescan and this assertion fails.
        let memo = Mutex::new(None);
        let ttl = Duration::from_secs(60);
        let scans = Cell::new(0u32);
        let scan = || {
            scans.set(scans.get() + 1);
            Ok::<u64, ()>(7)
        };

        let first = key_count_with_memo(&memo, ttl, true, &scan).unwrap();
        let second = key_count_with_memo(&memo, ttl, true, &scan).unwrap();

        assert_eq!(first, 7);
        assert_eq!(second, 7, "the memoised count is served inside the TTL");
        assert_eq!(scans.get(), 1, "the second call inside the TTL must issue ZERO remote scans");
    }

    #[test]
    fn an_expired_memo_triggers_exactly_one_rescan() {
        // positive control: outside the TTL a rescan runs (the cache is not
        // simply pinned forever).
        let past = Instant::now().checked_sub(Duration::from_secs(120)).unwrap();
        let memo = Mutex::new(Some((past, 3u64)));
        let ttl = Duration::from_secs(60);
        let scans = Cell::new(0u32);
        let scan = || {
            scans.set(scans.get() + 1);
            Ok::<u64, ()>(9)
        };
        let count = key_count_with_memo(&memo, ttl, true, &scan).unwrap();
        assert_eq!(count, 9, "an expired memo rescans");
        assert_eq!(scans.get(), 1);
    }

    #[test]
    fn a_failed_scan_is_never_cached() {
        // O-01: "never cache a fabricated value". A failing scan must leave the
        // memo untouched, and a subsequent successful scan must still run.
        let memo: Mutex<Option<(Instant, u64)>> = Mutex::new(None);
        let ttl = Duration::from_secs(60);
        let failing = key_count_with_memo(&memo, ttl, true, || Err::<u64, ()>(()));
        assert!(failing.is_err(), "the scan failure is propagated");
        assert!(memo.lock().unwrap().is_none(), "a failed scan must not populate the memo with a fabricated count");

        let ok = key_count_with_memo(&memo, ttl, true, || Ok::<u64, ()>(5)).unwrap();
        assert_eq!(ok, 5, "the next scan still runs and succeeds (the failure was not cached as truth)");
    }

    #[test]
    fn the_local_lane_never_caches() {
        // On the local lane (cache_enabled = false) every call scans (a local
        // scan is cheap and exactness beats staleness).
        let memo: Mutex<Option<(Instant, u64)>> = Mutex::new(None);
        let ttl = Duration::from_secs(60);
        let scans = Cell::new(0u32);
        let scan = || {
            scans.set(scans.get() + 1);
            Ok::<u64, ()>(1)
        };
        key_count_with_memo(&memo, ttl, false, &scan).unwrap();
        key_count_with_memo(&memo, ttl, false, &scan).unwrap();
        assert_eq!(scans.get(), 2, "the local lane bypasses the memo");
        assert!(memo.lock().unwrap().is_none(), "the local lane never writes the memo");
    }

    #[test]
    fn remote_key_count_freshness_boundary() {
        let now = Instant::now();
        let ttl = Duration::from_secs(60);
        // fresh: computed 10s ago
        assert_eq!(
            remote_key_count_is_fresh(Some((now.checked_sub(Duration::from_secs(10)).unwrap(), 4)), ttl, now),
            Some(4)
        );
        // stale: computed 120s ago
        assert_eq!(
            remote_key_count_is_fresh(Some((now.checked_sub(Duration::from_secs(120)).unwrap(), 4)), ttl, now),
            None
        );
        // no memo
        assert_eq!(remote_key_count_is_fresh(None, ttl, now), None);
    }

    #[test]
    fn invalid_cache_config_is_a_typed_refusal_not_a_silent_disable() {
        // O-01: unset and explicit-0 disable the cache; a garbage value is a
        // TYPED refusal. The old behaviour silently returned None for garbage,
        // disabling the protection the operator believed was on — the mutant
        // that reverts to None makes this assertion fail.
        assert_eq!(validate_cache_config(None), Ok(None), "unset disables the cache");
        assert_eq!(validate_cache_config(Some("0")), Ok(None), "explicit 0 disables the cache");
        assert_eq!(validate_cache_config(Some("  0 ")), Ok(None), "whitespace-padded 0 disables the cache");
        assert_eq!(validate_cache_config(Some("1048576")), Ok(Some(1048576)), "a valid budget is honoured");
        assert_eq!(
            validate_cache_config(Some("not-a-number")),
            Err(CacheConfigError::Invalid { value: "not-a-number".to_owned() }),
            "an invalid budget is a typed refusal, never a silent None"
        );
    }
}
