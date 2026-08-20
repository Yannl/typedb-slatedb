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
        CopyMode, CopyOptions, GetOptions, GetRange, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
        ObjectStoreExt, PutMode, PutMultipartOptions, PutOptions, PutPayload, PutPayloadMut, PutResult, RenameOptions,
        UploadPart, aws::AmazonS3Builder, local::LocalFileSystem, path::Path as ObjectPath, prefix::PrefixStore,
    },
};

use crate::recovery::sha256::Sha256;

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
/// R5-STOR-03 — WHAT THIS IS, AND WHAT IT IS NOT.
///
/// This is a LOCAL-LANE epoch source: a process-local wall-clock counter
/// that lets the U2/U2S3 conformance lanes satisfy the SHIPPED
/// `external_epoch_required` fence (R5-STOR-04) so a single local writer
/// can open at all. It is NOT production fencing, and the round-5 audit
/// was right to insist the difference be stated rather than implied:
///
///   * it is per PROCESS — two hosts opening the same store can mint
///     overlapping epochs, so it cannot arbitrate a cross-host takeover;
///   * it derives from the local clock — a clock rollback can produce a
///     non-monotone sequence across restarts (the +1 tie-break only
///     protects same-process ordering);
///   * nothing ALLOCATES it authoritatively — no controller records which
///     epoch a writer was granted, so no evidence exists to fence with.
///
/// Real fencing is the controller's reserve → acquire/fence → recover →
/// attest → activate protocol, whose lanes (U3/U4) refuse at admission
/// with `BackendNotYetAvailable` precisely so this local source can never
/// be mistaken for it — asserted by
/// `factory::product_backend_tests` and by the U3/U4 refusal tests. When
/// the controller seam lands, the epoch arrives as a typed allocation in
/// `BackendContext` and this function is deleted, not extended.
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

/// U2S3 profile configuration variable NAMES (TB-P8). These constants are the
/// ADMISSION POINT'S input names only (R5-STOR-01): the values behind them are
/// read exactly once, by `crate::factory`'s `BackendContext` resolution, and
/// travel from there as an immutable [`S3RuntimeConfig`]. Nothing in this
/// module reads the process environment.
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

/// An opaque secret handle (R5-STOR-01): S3 credentials travel inside the
/// admitted [`S3RuntimeConfig`] but are never rendered by `Debug`, never
/// serialised into the persisted backend identity, and never enter any
/// digest or fingerprint. The raw value is exposed only to the store
/// builder, crate-internally.
#[derive(Clone, PartialEq, Eq)]
pub struct S3Secret(String);

impl S3Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for S3Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// R5-STOR-01: the COMPLETE effective (non-secret-rendered) S3 configuration
/// for one database open. Resolved from the environment exactly once, at the
/// `BackendContext` admission point in `crate::factory`, then passed down
/// explicitly — this module holds NO environment reads and NO config cache of
/// its own, so a mid-process environment change can never make the engine
/// open a different backend than the one the marker attests. Secrets ride
/// along as opaque [`S3Secret`] handles resolved at the SAME admission point.
#[derive(Clone, PartialEq, Eq)]
pub struct S3RuntimeConfig {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub root_prefix: String,
    /// Bounded disk-cache budget in bytes; `None` means the cache is off
    /// (unset or an explicit 0 at the admission point).
    pub cache_bytes: Option<usize>,
    pub access_key_id: S3Secret,
    pub secret_access_key: S3Secret,
}

impl S3RuntimeConfig {
    /// The non-secret rendering used in typed refusals and witness
    /// mismatches. Secrets never appear here.
    pub fn fingerprint(&self) -> String {
        format!(
            "endpoint={};bucket={};region={};root-prefix={};cache-bytes={}",
            self.endpoint,
            self.bucket,
            self.region,
            self.root_prefix,
            match self.cache_bytes {
                None => "none".to_owned(),
                Some(bytes) => bytes.to_string(),
            }
        )
    }

    /// Full behavioural equality, credentials included (a changed credential
    /// is behaviour-affecting even though it is never rendered).
    pub fn same_effective_config(&self, other: &Self) -> bool {
        self == other
    }
}

impl std::fmt::Debug for S3RuntimeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "S3RuntimeConfig({}, credentials <redacted>)", self.fingerprint())
    }
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
pub(crate) enum CacheConfigError {
    Invalid { value: String },
}

pub(crate) fn validate_cache_config(raw: Option<&str>) -> Result<Option<usize>, CacheConfigError> {
    match raw {
        None => Ok(None),
        Some(text) => match text.trim().parse::<usize>() {
            Ok(0) => Ok(None),
            Ok(bytes) => Ok(Some(bytes)),
            Err(_) => Err(CacheConfigError::Invalid { value: text.to_owned() }),
        },
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

fn build_s3_store(config: &S3RuntimeConfig) -> Result<Arc<dyn ObjectStore>, slatedb::Error> {
    // Conditional put stays on the 0.14.1 default (`ETagMatch`): both MinIO
    // and Cloudflare R2 implement the standard HTTP preconditions SlateDB's
    // manifest CAS requires.
    AmazonS3Builder::new()
        .with_endpoint(config.endpoint.clone())
        .with_allow_http(config.endpoint.starts_with("http://"))
        .with_bucket_name(config.bucket.clone())
        .with_region(config.region.clone())
        .with_access_key_id(config.access_key_id.expose().to_owned())
        .with_secret_access_key(config.secret_access_key.expose().to_owned())
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
fn object_prefix(config: &S3RuntimeConfig, keyspace_path: &Path) -> ObjectPath {
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

/// The infix every multipart STAGING key carries (R5-STOR-05). Staging keys
/// are transient: a completed attempt is verified there and then atomically
/// PROMOTED to its target name; the staging object is cleaned best-effort
/// afterwards. Listings that feed durable artifacts (the remote checkpoint)
/// exclude them by this infix.
const MULTIPART_ATTEMPT_INFIX: &str = ".mpa-";

/// Is this key a multipart staging key (never authoritative state)?
fn is_multipart_attempt_key(location: &ObjectPath) -> bool {
    location.as_ref().contains(MULTIPART_ATTEMPT_INFIX)
}

/// Mint the globally unique staging key one multipart attempt completes to
/// before its create-only promote (R5-STOR-05). Uniqueness across processes:
/// pid + a per-process random seed + wall nanoseconds + the per-store attempt
/// id — two attempts (same or different processes) can never share a staging
/// key, so the ONLY contended operation left is the atomic promote.
fn mint_attempt_location(location: &ObjectPath, attempt_id: u64) -> ObjectPath {
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
    ObjectPath::from(format!(
        "{location}{MULTIPART_ATTEMPT_INFIX}{:08x}-{seed:016x}-{nanos:024x}-{attempt_id:08x}",
        std::process::id()
    ))
}

/// R6-STOR-03: the domain-separation tag every object-content digest is
/// framed with. A digest that decides whether bytes may be PROMOTED must not
/// be confusable with a digest computed for any other purpose (the checkpoint
/// manifest's per-file digest, the backend-identity digest), so the framing is
/// `SHA-256(domain || content || big-endian content length)`. The trailing
/// length also makes the digest injective over chunk boundaries: no
/// concatenation of a shorter object plus a suffix can forge it.
const OBJECT_DIGEST_DOMAIN: &[u8] = b"typedb.storage.object-content.v1\x00";

/// R6-STOR-03: the content identity of one stored object — its length AND a
/// full cryptographic digest, never a 64-bit checksum. This is the value the
/// immutability ledger stores, the value multipart stage verification
/// compares, and the value an occupied-target settlement is decided by.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ContentWitness {
    len: u64,
    digest: [u8; 32],
}

impl ContentWitness {
    /// Accept only on EXACT length and digest equality. The digest comparison
    /// is constant-time: the decision is a promotion authority, and an
    /// early-exit comparison leaks how much of a forged digest is right.
    fn matches(&self, other: &Self) -> bool {
        let mut difference = ((self.len ^ other.len) != 0) as u8;
        for index in 0..32 {
            difference |= self.digest[index] ^ other.digest[index];
        }
        difference == 0
    }

    fn hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.digest {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

impl std::fmt::Debug for ContentWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ContentWitness[len={}, sha256={}]", self.len, self.hex())
    }
}

/// R6-STOR-02/R6-STOR-03: an INCREMENTAL object-content digest. Parts, staged
/// readbacks and published readbacks all flow through this one type, so no
/// path ever needs the whole object resident to learn its identity.
#[derive(Clone)]
struct ObjectDigest {
    hasher: Sha256,
    len: u64,
}

impl ObjectDigest {
    fn new() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(OBJECT_DIGEST_DOMAIN);
        Self { hasher, len: 0 }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
        self.len = self.len.saturating_add(bytes.len() as u64);
    }

    fn len(&self) -> u64 {
        self.len
    }

    /// The witness so far. Takes `&self` (the state is cloned) so a streaming
    /// producer can be witnessed without being consumed.
    fn witness(&self) -> ContentWitness {
        let mut hasher = self.hasher.clone();
        hasher.update(&self.len.to_be_bytes());
        ContentWitness { len: self.len, digest: hasher.finalize() }
    }
}

/// One-shot witness of an in-memory slice (tests and evidence only: every
/// production path hashes incrementally).
#[cfg(test)]
fn content_witness(bytes: &[u8]) -> ContentWitness {
    let mut digest = ObjectDigest::new();
    digest.update(bytes);
    digest.witness()
}

/// Witness of an outgoing payload, computed over its chunks WITHOUT
/// materialising a contiguous copy (R6-STOR-02: the previous code built a
/// `Vec` of the whole payload purely to checksum it).
fn payload_witness(payload: &PutPayload) -> ContentWitness {
    let mut digest = ObjectDigest::new();
    for chunk in payload {
        digest.update(chunk.as_ref());
    }
    digest.witness()
}

/// One journaled multipart upload attempt (S-04): completion is gated to the
/// still-active, uncommitted attempt for a location; a stale attempt (one a
/// newer attempt for the same location superseded) can neither complete nor
/// commit — but it remains individually addressable, so its own
/// still-uncommitted provider upload can be aborted even after supersession.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptState {
    /// Recorded, parts may still be uploaded, completion still permitted.
    Uncommitted,
    /// Completed exactly once; no further completion may replace it.
    Committed,
    /// Aborted; terminal.
    Aborted,
}

/// R5-STOR-08 admission budgets for the multipart journal. Containment
/// defaults, not ratified SLOs: far above any healthy SlateDB workload (the
/// engine streams one SST at a time per flush/compaction path) while giving
/// the journal a hard ceiling so repeated disconnects/abandons reach a TYPED
/// refusal instead of unbounded memory.
const MULTIPART_MAX_OPEN_ATTEMPTS: usize = 64;
/// Maximum bytes journaled (reserved) across ALL open attempts at once.
const MULTIPART_MAX_JOURNALED_BYTES: u64 = 8 * 1024 * 1024 * 1024; // 8 GiB
/// How many TERMINAL (committed/aborted) attempt receipts are retained for
/// idempotency answers ("this attempt is already committed/was aborted")
/// before the oldest is reaped. Bounded count — the documented retention
/// window N of R5-STOR-08.
const MULTIPART_TERMINAL_RECEIPTS: usize = 128;

/// R6-STOR-02: the PER-OBJECT maximum, deliberately independent of the
/// aggregate journal budget above. The aggregate budget bounds how much the
/// journal may ACCOUNT across all attempts; it says nothing about how large a
/// SINGLE object may be, and a single object is what completion has to verify
/// and (on providers without a conditional copy) re-upload. SlateDB freezes a
/// memtable at `l0_sst_size_bytes` (64 MiB by default), so 512 MiB is eight
/// times the largest object this lane legitimately produces — headroom, with a
/// hard, typed ceiling instead of "whatever the caller streams".
const MULTIPART_MAX_OBJECT_BYTES: u64 = 512 * 1024 * 1024;

/// R6-STOR-02: the window every streaming read uses — staged verification,
/// occupied-target settlement, checkpoint download. Peak buffer residency for
/// those paths is this value per concurrent completion, NOT the object size.
const MULTIPART_VERIFY_CHUNK_BYTES: u64 = 8 * 1024 * 1024;

/// R6-STOR-02: how many completions may hold verification/promotion buffers at
/// once. Peak heap for the bounded paths is therefore
/// `MULTIPART_VERIFY_CHUNK_BYTES * MULTIPART_MAX_CONCURRENT_COMPLETIONS`.
const MULTIPART_MAX_CONCURRENT_COMPLETIONS: usize = 4;

/// R6-STOR-02, HONEST BOUND. The promote is a create-only conditional COPY
/// wherever the provider supports one (`hard_link` on `LocalFileSystem`,
/// copy-if-not-exists where configured); that path never materialises the
/// object. Where the provider reports conditional copy unsupported — which
/// includes the plain S3 builder this lane currently constructs, because
/// enabling `copy_if_not_exists` for R2 is explicitly gated on qualification —
/// the only create-only publication primitive left is a single conditional
/// PUT, and `object_store`'s `PutPayload` is by definition resident. That path
/// is therefore `O(min(object, this constant))` per concurrent completion and
/// is capped here rather than left to the 8 GiB journal budget: an object
/// above the cap is a TYPED refusal (fail closed), never an unbounded
/// allocation. Four times the SlateDB L0 SST threshold.
const MULTIPART_MAX_MATERIALISED_PROMOTE_BYTES: u64 = 256 * 1024 * 1024;

/// R6-STOR-02 instrumentation: bytes of object payload currently held in
/// completion buffers, plus the high-water mark. This accounting IS the
/// evidence that admission is `O(chunk x concurrency)`: the audit is explicit
/// that no test may allocate an 8 GiB object to prove the bound, so the bound
/// is proven by observing that peak residency does not grow with object size.
///
/// Every charge is recorded against the process-wide meter (heap pressure is a
/// process property) and, where one is in scope, against the materialisation's
/// own meter (so a test observes only its own traffic).
#[derive(Debug, Default)]
struct BufferMeter {
    live: AtomicU64,
    peak: AtomicU64,
}

impl BufferMeter {
    fn add(&self, bytes: u64) {
        let live = self.live.fetch_add(bytes, Ordering::SeqCst).saturating_add(bytes);
        self.peak.fetch_max(live, Ordering::SeqCst);
    }

    fn sub(&self, bytes: u64) {
        self.live.fetch_sub(bytes, Ordering::SeqCst);
    }

    #[allow(dead_code)] // read by the R6-STOR-02 instrumentation tests
    fn peak(&self) -> u64 {
        self.peak.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    fn reset_peak(&self) {
        self.peak.store(self.live.load(Ordering::SeqCst), Ordering::SeqCst);
    }
}

/// R6-STOR-02: the effective streaming/size limits of one materialisation.
/// The production values are the named constants; the fields exist so a test
/// can drive every boundary at kilobyte scale instead of allocating the
/// gigabytes the audit explicitly forbids a test from allocating.
#[derive(Debug)]
struct MultipartLimits {
    verify_chunk_bytes: AtomicU64,
    max_object_bytes: AtomicU64,
    max_materialised_promote_bytes: AtomicU64,
}

impl Default for MultipartLimits {
    fn default() -> Self {
        Self {
            verify_chunk_bytes: AtomicU64::new(MULTIPART_VERIFY_CHUNK_BYTES),
            max_object_bytes: AtomicU64::new(MULTIPART_MAX_OBJECT_BYTES),
            max_materialised_promote_bytes: AtomicU64::new(MULTIPART_MAX_MATERIALISED_PROMOTE_BYTES),
        }
    }
}

impl MultipartLimits {
    fn verify_chunk(&self) -> u64 {
        self.verify_chunk_bytes.load(Ordering::SeqCst)
    }

    fn max_object(&self) -> u64 {
        self.max_object_bytes.load(Ordering::SeqCst)
    }

    fn max_materialised_promote(&self) -> u64 {
        self.max_materialised_promote_bytes.load(Ordering::SeqCst)
    }
}

/// Process-wide completion-buffer high-water mark.
fn process_buffer_meter() -> &'static BufferMeter {
    static METER: OnceLock<BufferMeter> = OnceLock::new();
    METER.get_or_init(BufferMeter::default)
}

/// RAII charge against the completion buffer meters: the bytes are accounted
/// while the buffer is live and released when it drops.
struct BufferCharge {
    meter: Option<Arc<BufferMeter>>,
    bytes: u64,
}

fn charge_buffer(meter: Option<&Arc<BufferMeter>>, bytes: u64) -> BufferCharge {
    process_buffer_meter().add(bytes);
    if let Some(meter) = meter {
        meter.add(bytes);
    }
    BufferCharge { meter: meter.cloned(), bytes }
}

impl Drop for BufferCharge {
    fn drop(&mut self) {
        process_buffer_meter().sub(self.bytes);
        if let Some(meter) = &self.meter {
            meter.sub(self.bytes);
        }
    }
}

/// R6-STOR-02: the process-wide completion gate. Heap pressure is a PROCESS
/// property, so the semaphore is process-wide rather than per materialisation.
fn completion_gate() -> &'static tokio::sync::Semaphore {
    static GATE: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    GATE.get_or_init(|| tokio::sync::Semaphore::new(MULTIPART_MAX_CONCURRENT_COMPLETIONS))
}

static COMPLETIONS_IN_FLIGHT: AtomicU64 = AtomicU64::new(0);
static COMPLETIONS_PEAK: AtomicU64 = AtomicU64::new(0);

/// A held completion permit, with the observed concurrency accounted so a test
/// can prove the cap rather than trust it.
struct CompletionPermit(#[allow(dead_code)] tokio::sync::SemaphorePermit<'static>);

impl CompletionPermit {
    async fn acquire() -> Self {
        let permit = completion_gate().acquire().await.expect("the completion gate is never closed");
        let live = COMPLETIONS_IN_FLIGHT.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        COMPLETIONS_PEAK.fetch_max(live, Ordering::SeqCst);
        Self(permit)
    }
}

impl Drop for CompletionPermit {
    fn drop(&mut self) {
        COMPLETIONS_IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
    }
}

/// R6-STOR-04: the durable inventory of staging objects whose reclaim FAILED.
///
/// A swallowed `let _ = store.delete(..)` made orphan state invisible. Every
/// failed reclaim now produces a record: appended to a durable, fsynced file
/// inside the keyspace's lifecycle-marker directory (so it survives the
/// process that produced it) and kept in memory for the same process's
/// observability. A record that cannot be made durable is counted and logged
/// at error level — never dropped silently.
#[derive(Debug, Default)]
struct OrphanInventory {
    sink: Mutex<Option<PathBuf>>,
    records: Mutex<Vec<String>>,
    undurable: AtomicU64,
}

/// File name of the durable orphan inventory inside the keyspace directory.
const MULTIPART_ORPHAN_FILE: &str = "MULTIPART-ORPHANS";

impl OrphanInventory {
    fn bind(&self, path: PathBuf) {
        *self.sink.lock().unwrap() = Some(path);
    }

    fn record(&self, key: &str, reason: &str) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let line = format!("{nanos:039}\t{key}\t{reason}");
        self.records.lock().unwrap().push(line.clone());
        let sink = self.sink.lock().unwrap().clone();
        let durable = match sink {
            Some(path) => Self::append_durably(&path, &line),
            None => Err(io::Error::other("no durable orphan sink is bound to this materialisation")),
        };
        if let Err(error) = durable {
            self.undurable.fetch_add(1, Ordering::SeqCst);
            logger::error!(
                "R6-STOR-04: a multipart staging object could not be reclaimed AND its orphan record \
                 could not be made durable ({error}). Orphan key: {key}; reason: {reason}"
            );
        }
    }

    fn append_durably(path: &Path, line: &str) -> io::Result<()> {
        use std::io::Write;
        let mut file = fs::OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "{line}")?;
        file.sync_all()?;
        if let Some(parent) = path.parent() {
            crate::fsync_path(parent)?;
        }
        Ok(())
    }

    /// The orphan records this process has produced — the observability
    /// surface a supervisor or test reads.
    #[allow(dead_code)]
    fn records(&self) -> Vec<String> {
        self.records.lock().unwrap().clone()
    }

    /// How many orphan records could NOT be made durable.
    #[allow(dead_code)]
    fn undurable(&self) -> u64 {
        self.undurable.load(Ordering::SeqCst)
    }
}

/// Typed budget refusal (R5-STOR-08): exceeding an admission budget refuses,
/// it never grows the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MultipartBudgetRefused {
    Attempts { open: usize, max: usize },
    Bytes { reserved: u64, incoming: u64, max: u64 },
    /// R6-STOR-02: the PER-OBJECT ceiling, independent of the aggregate.
    Object { streamed: u64, incoming: u64, max: u64 },
}

impl MultipartBudgetRefused {
    fn into_store_error(self, location: &ObjectPath) -> slatedb::object_store::Error {
        let detail = match self {
            Self::Attempts { open, max } => format!(
                "{open} multipart attempts already open, at the admission budget of {max} concurrent attempts"
            ),
            Self::Bytes { reserved, incoming, max } => format!(
                "{reserved} bytes already journaled and {incoming} more requested, over the admission \
                 budget of {max} journaled bytes"
            ),
            Self::Object { streamed, incoming, max } => format!(
                "{streamed} bytes already streamed for THIS object and {incoming} more requested, over \
                 the per-object maximum of {max} bytes (R6-STOR-02): one object is what completion must \
                 verify and, where the provider has no conditional copy, re-upload, so its size is \
                 bounded independently of the aggregate journal budget"
            ),
        };
        slatedb::object_store::Error::Precondition {
            path: location.to_string(),
            source: format!(
                "multipart admission refused (R5-STOR-08): {detail}; budget is reserved at initiation/\
                 streaming and released only on proven abort or commit — refusing rather than growing \
                 without bound"
            )
            .into(),
        }
    }
}

/// Pure attempt-count admission (R5-STOR-08): a NEW attempt is admitted only
/// while the open-attempt count is strictly below the budget — at the budget
/// (`==`) the initiation refuses. Total function so the boundary is an exact
/// unit test.
fn admit_multipart_attempt(open: usize, max: usize) -> Result<(), MultipartBudgetRefused> {
    if open >= max { Err(MultipartBudgetRefused::Attempts { open, max }) } else { Ok(()) }
}

/// Pure byte-budget admission (R5-STOR-08): the incoming reservation is
/// admitted only while `reserved + incoming <= max` (exactly AT the budget is
/// still admitted; one byte over refuses; overflow refuses).
fn admit_multipart_bytes(reserved: u64, incoming: u64, max: u64) -> Result<(), MultipartBudgetRefused> {
    match reserved.checked_add(incoming) {
        Some(total) if total <= max => Ok(()),
        _ => Err(MultipartBudgetRefused::Bytes { reserved, incoming, max }),
    }
}

/// R6-STOR-02 per-object admission: ONE object may stream at most `max` bytes,
/// no matter how much aggregate journal budget is free. Exactly at the maximum
/// is still admitted; one byte over refuses; overflow refuses.
fn admit_object_bytes(streamed: u64, incoming: u64, max: u64) -> Result<(), MultipartBudgetRefused> {
    match streamed.checked_add(incoming) {
        Some(total) if total <= max => Ok(()),
        _ => Err(MultipartBudgetRefused::Object { streamed, incoming, max }),
    }
}

/// The multipart attempt journal (S-04, R4-STOR-04, R5-STOR-08): every OPEN
/// (unresolved) attempt carries a row with its reserved byte count, and each
/// location additionally records which attempt is the ACTIVE (most recently
/// initiated) one. Completion requires being the active, uncommitted attempt;
/// abort requires only being uncommitted — a superseded attempt must still be
/// able to reclaim its exact provider upload.
///
/// R5-STOR-08 lifecycle: rows exist only while an attempt is unresolved.
/// Initiation reserves against the attempt budget; part streaming reserves
/// against the byte budget; a proven abort/commit RETIRES the row — releasing
/// its budget and moving its id into a bounded terminal-receipt window
/// (last [`MULTIPART_TERMINAL_RECEIPTS`] receipts) that keeps idempotency
/// answers addressable without unbounded growth. Exceeding either budget is a
/// typed refusal, never growth.
///
/// Honest scope: this journal is process-local — neither controller-durable
/// nor shared across restarts/incarnations. Cross-process and cross-restart
/// safety rests on the completion-time create-only PROMOTE against the STORE
/// (R5-STOR-05), never on this map.
#[derive(Debug)]
struct MultipartJournal {
    /// location → the attempt id most recently initiated for it. The entry is
    /// removed when that attempt retires, so this map is bounded by the open
    /// attempts.
    active: HashMap<String, u64>,
    /// attempt id → bytes reserved by its streamed parts. ONLY unresolved
    /// (uncommitted) attempts have rows here.
    open_attempts: HashMap<u64, u64>,
    /// Total bytes reserved across every open attempt.
    reserved_bytes: u64,
    /// Bounded terminal receipts, oldest at the front.
    terminal: std::collections::VecDeque<(u64, AttemptState)>,
    max_open_attempts: usize,
    max_journaled_bytes: u64,
    max_terminal_receipts: usize,
}

impl Default for MultipartJournal {
    fn default() -> Self {
        Self {
            active: HashMap::new(),
            open_attempts: HashMap::new(),
            reserved_bytes: 0,
            terminal: std::collections::VecDeque::new(),
            max_open_attempts: MULTIPART_MAX_OPEN_ATTEMPTS,
            max_journaled_bytes: MULTIPART_MAX_JOURNALED_BYTES,
            max_terminal_receipts: MULTIPART_TERMINAL_RECEIPTS,
        }
    }
}

impl MultipartJournal {
    /// The state of an attempt: open rows are `Uncommitted`; retired ids
    /// answer from the bounded receipt window; anything older is `None`
    /// (retired beyond retention).
    fn state_of(&self, attempt_id: u64) -> Option<AttemptState> {
        if self.open_attempts.contains_key(&attempt_id) {
            return Some(AttemptState::Uncommitted);
        }
        self.terminal.iter().rev().find(|(id, _)| *id == attempt_id).map(|(_, state)| *state)
    }

    /// Admit and record a fresh attempt (R5-STOR-08): the attempt budget is
    /// checked BEFORE any row is inserted or any provider upload opened.
    fn initiate(&mut self, location: &ObjectPath, attempt_id: u64) -> Result<(), MultipartBudgetRefused> {
        admit_multipart_attempt(self.open_attempts.len(), self.max_open_attempts)?;
        self.open_attempts.insert(attempt_id, 0);
        self.active.insert(location.to_string(), attempt_id);
        Ok(())
    }

    /// Reserve `len` streamed bytes for an open attempt against the byte
    /// budget; a refusal reserves nothing.
    fn reserve_part_bytes(&mut self, attempt_id: u64, len: u64) -> Result<(), MultipartBudgetRefused> {
        admit_multipart_bytes(self.reserved_bytes, len, self.max_journaled_bytes)?;
        let Some(bytes) = self.open_attempts.get_mut(&attempt_id) else {
            // no open row: nothing to reserve against (the caller's state
            // gate reports the precise refusal)
            return Ok(());
        };
        *bytes = bytes.saturating_add(len);
        self.reserved_bytes = self.reserved_bytes.saturating_add(len);
        Ok(())
    }

    /// Retire an attempt on proven abort/commit (R5-STOR-08): release its
    /// byte reservation, drop its open row (and its active-attempt entry when
    /// it holds one), and record a bounded terminal receipt.
    fn retire(&mut self, location: &str, attempt_id: u64, state: AttemptState) {
        if let Some(bytes) = self.open_attempts.remove(&attempt_id) {
            self.reserved_bytes = self.reserved_bytes.saturating_sub(bytes);
        }
        if self.active.get(location) == Some(&attempt_id) {
            self.active.remove(location);
        }
        self.terminal.push_back((attempt_id, state));
        while self.terminal.len() > self.max_terminal_receipts {
            self.terminal.pop_front();
        }
    }
}

/// R6-STOR-04: authority separated by TYPE, not by convention.
///
/// The previous boundary was a wrapper: `NoDeleteStore` denied the public
/// delete/rename verbs while HOLDING an `Arc<dyn ObjectStore>` and handing
/// that raw handle to the multipart machinery, which called `store.delete`
/// directly. Denial by convention is one confused code path away from
/// deleting authoritative bytes.
///
/// This module splits one provider handle into two DISJOINT capability types
/// at construction, after which the raw handle is unreachable:
///
/// - [`AuthoritativeStore`] wraps `Arc<dyn AuthoritativeIo>`. That trait has
///   no delete, no rename, no overwrite-mode copy and no unconditional put in
///   its vtable, so `authoritative.delete(..)` is not a runtime refusal — it
///   is a name that does not exist, and no method returns the underlying
///   store. Deleting an authoritative object through this handle cannot be
///   written, let alone executed.
/// - [`StagingAuthority`] wraps `Arc<dyn StagingIo>`, whose every method takes
///   a [`StagingKey`]. A `StagingKey` is minted only from a target key plus an
///   attempt id, always inside the `.mpa-` staging namespace, and the
///   implementation re-checks the namespace before it acts — so the one handle
///   that CAN delete can only ever address transient staging objects.
///
/// PROVIDER LIMITATION, recorded rather than papered over: SlateDB's builder
/// takes an `Arc<dyn ObjectStore>`, and that trait carries delete in its
/// vtable by definition. The handle SlateDB itself holds is therefore still an
/// `ObjectStore` — `NoDeleteStore` — whose delete/rename/overwrite-copy verbs
/// are TYPED refusals at the boundary rather than absent names. In-process
/// structural separation stops exactly there; the remaining half is a
/// provider-side credential/binding split (separate buckets or a service
/// binding for staging), which is Worker/infrastructure territory and out of
/// scope for this module.
mod authority {
    use super::*;

    /// The ONE place a raw provider handle survives construction. Private to
    /// this module and never returned: neither capability type exposes it.
    #[derive(Debug)]
    struct ProviderIo {
        store: Arc<dyn ObjectStore>,
    }

    /// Non-destructive capability set over AUTHORITATIVE names. Note what is
    /// absent: delete, rename, overwrite copy, unconditional put, multipart
    /// abort of a published name.
    #[async_trait]
    pub(super) trait AuthoritativeIo: std::fmt::Debug + Send + Sync + 'static {
        async fn get_opts(
            &self,
            location: &ObjectPath,
            options: GetOptions,
        ) -> slatedb::object_store::Result<GetResult>;
        async fn head(&self, location: &ObjectPath) -> slatedb::object_store::Result<ObjectMeta>;
        /// Create-only put: the caller's tags/attributes/extensions are
        /// preserved, but the MODE is forced, so no caller can turn this into
        /// an overwrite.
        async fn put_create(
            &self,
            location: &ObjectPath,
            payload: PutPayload,
            options: PutOptions,
        ) -> slatedb::object_store::Result<PutResult>;
        /// The SOLE conditional-CAS publication path (S-04): refuses any
        /// location that is not a manifest key, so the caller's `PutOptions`
        /// can never be aimed at an immutable data key.
        async fn put_manifest(
            &self,
            location: &ObjectPath,
            payload: PutPayload,
            options: PutOptions,
        ) -> slatedb::object_store::Result<PutResult>;
        /// Create-only copy: the caller's other options are preserved, the
        /// MODE is forced.
        async fn copy_create(
            &self,
            from: &ObjectPath,
            to: &ObjectPath,
            options: CopyOptions,
        ) -> slatedb::object_store::Result<()>;
        async fn list_with_delimiter(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> slatedb::object_store::Result<ListResult>;
        fn list(&self, prefix: Option<&ObjectPath>) -> BoxStream<'static, slatedb::object_store::Result<ObjectMeta>>;
    }

    /// Create/read/reclaim inside the STAGING namespace, and nowhere else.
    #[async_trait]
    pub(super) trait StagingIo: std::fmt::Debug + Send + Sync + 'static {
        async fn open_multipart(
            &self,
            key: &StagingKey,
            options: PutMultipartOptions,
        ) -> slatedb::object_store::Result<Box<dyn MultipartUpload>>;
        async fn get_opts(&self, key: &StagingKey, options: GetOptions)
        -> slatedb::object_store::Result<GetResult>;
        async fn head(&self, key: &StagingKey) -> slatedb::object_store::Result<ObjectMeta>;
        async fn reclaim(&self, key: &StagingKey) -> slatedb::object_store::Result<()>;
    }

    /// A key inside the multipart staging namespace. The only public
    /// constructor mints one (always carrying [`MULTIPART_ATTEMPT_INFIX`]), so
    /// no authoritative name can be spelled as a `StagingKey`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct StagingKey(ObjectPath);

    impl StagingKey {
        pub(super) fn mint(target: &ObjectPath, attempt_id: u64) -> Self {
            Self(mint_attempt_location(target, attempt_id))
        }

        pub(super) fn path(&self) -> &ObjectPath {
            &self.0
        }

        /// Test-only forgery, so the namespace re-check in [`StagingIo`] is an
        /// EXERCISED boundary rather than an unreachable assertion.
        #[cfg(test)]
        pub(super) fn forged_for_test(path: ObjectPath) -> Self {
            Self(path)
        }
    }

    impl std::fmt::Display for StagingKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    fn not_staging(key: &StagingKey) -> slatedb::object_store::Error {
        slatedb::object_store::Error::Precondition {
            path: key.0.to_string(),
            source: format!(
                "staging authority refused {} (R6-STOR-04): this principal may only address the \
                 multipart staging namespace (keys carrying '{MULTIPART_ATTEMPT_INFIX}'); it has no \
                 authority over any published name",
                key.0
            )
            .into(),
        }
    }

    #[async_trait]
    impl AuthoritativeIo for ProviderIo {
        async fn get_opts(
            &self,
            location: &ObjectPath,
            options: GetOptions,
        ) -> slatedb::object_store::Result<GetResult> {
            self.store.get_opts(location, options).await
        }

        async fn head(&self, location: &ObjectPath) -> slatedb::object_store::Result<ObjectMeta> {
            self.store.head(location).await
        }

        async fn put_create(
            &self,
            location: &ObjectPath,
            payload: PutPayload,
            options: PutOptions,
        ) -> slatedb::object_store::Result<PutResult> {
            let create = PutOptions { mode: PutMode::Create, ..options };
            self.store.put_opts(location, payload, create).await
        }

        async fn put_manifest(
            &self,
            location: &ObjectPath,
            payload: PutPayload,
            options: PutOptions,
        ) -> slatedb::object_store::Result<PutResult> {
            if !is_manifest_key(location) {
                return Err(slatedb::object_store::Error::Precondition {
                    path: location.to_string(),
                    source: "the conditional-CAS publication path is reserved for manifest keys \
                             (S-04, R6-STOR-04)"
                        .into(),
                });
            }
            self.store.put_opts(location, payload, options).await
        }

        async fn copy_create(
            &self,
            from: &ObjectPath,
            to: &ObjectPath,
            options: CopyOptions,
        ) -> slatedb::object_store::Result<()> {
            let create = CopyOptions { mode: CopyMode::Create, ..options };
            self.store.copy_opts(from, to, create).await
        }

        async fn list_with_delimiter(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> slatedb::object_store::Result<ListResult> {
            self.store.list_with_delimiter(prefix).await
        }

        fn list(&self, prefix: Option<&ObjectPath>) -> BoxStream<'static, slatedb::object_store::Result<ObjectMeta>> {
            self.store.list(prefix)
        }
    }

    #[async_trait]
    impl StagingIo for ProviderIo {
        async fn open_multipart(
            &self,
            key: &StagingKey,
            options: PutMultipartOptions,
        ) -> slatedb::object_store::Result<Box<dyn MultipartUpload>> {
            if !is_multipart_attempt_key(key.path()) {
                return Err(not_staging(key));
            }
            self.store.put_multipart_opts(key.path(), options).await
        }

        async fn get_opts(
            &self,
            key: &StagingKey,
            options: GetOptions,
        ) -> slatedb::object_store::Result<GetResult> {
            if !is_multipart_attempt_key(key.path()) {
                return Err(not_staging(key));
            }
            self.store.get_opts(key.path(), options).await
        }

        async fn head(&self, key: &StagingKey) -> slatedb::object_store::Result<ObjectMeta> {
            if !is_multipart_attempt_key(key.path()) {
                return Err(not_staging(key));
            }
            self.store.head(key.path()).await
        }

        async fn reclaim(&self, key: &StagingKey) -> slatedb::object_store::Result<()> {
            if !is_multipart_attempt_key(key.path()) {
                return Err(not_staging(key));
            }
            self.store.delete(key.path()).await
        }
    }

    /// The authoritative-namespace handle. No delete exists on it, and no raw
    /// store can be recovered from it.
    #[derive(Clone, Debug)]
    pub(super) struct AuthoritativeStore(Arc<dyn AuthoritativeIo>);

    /// The staging-namespace handle: the only one with reclaim authority, and
    /// it can only address staging keys.
    #[derive(Clone, Debug)]
    pub(super) struct StagingAuthority(Arc<dyn StagingIo>);

    /// Split one provider handle into the two disjoint authorities. After this
    /// call the raw `Arc<dyn ObjectStore>` is owned solely by the private
    /// `ProviderIo` and is reachable from neither returned value.
    pub(super) fn split(store: Arc<dyn ObjectStore>) -> (AuthoritativeStore, StagingAuthority) {
        let io = Arc::new(ProviderIo { store });
        (AuthoritativeStore(io.clone()), StagingAuthority(io))
    }

    impl AuthoritativeStore {
        pub(super) async fn get_opts(
            &self,
            location: &ObjectPath,
            options: GetOptions,
        ) -> slatedb::object_store::Result<GetResult> {
            self.0.get_opts(location, options).await
        }

        pub(super) async fn head(&self, location: &ObjectPath) -> slatedb::object_store::Result<ObjectMeta> {
            self.0.head(location).await
        }

        pub(super) async fn put_create(
            &self,
            location: &ObjectPath,
            payload: PutPayload,
            options: PutOptions,
        ) -> slatedb::object_store::Result<PutResult> {
            self.0.put_create(location, payload, options).await
        }

        pub(super) async fn put_manifest(
            &self,
            location: &ObjectPath,
            payload: PutPayload,
            options: PutOptions,
        ) -> slatedb::object_store::Result<PutResult> {
            self.0.put_manifest(location, payload, options).await
        }

        pub(super) async fn copy_create(
            &self,
            from: &ObjectPath,
            to: &ObjectPath,
            options: CopyOptions,
        ) -> slatedb::object_store::Result<()> {
            self.0.copy_create(from, to, options).await
        }

        pub(super) async fn list_with_delimiter(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> slatedb::object_store::Result<ListResult> {
            self.0.list_with_delimiter(prefix).await
        }

        pub(super) fn list(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> BoxStream<'static, slatedb::object_store::Result<ObjectMeta>> {
            self.0.list(prefix)
        }
    }

    impl StagingAuthority {
        pub(super) async fn open_multipart(
            &self,
            key: &StagingKey,
            options: PutMultipartOptions,
        ) -> slatedb::object_store::Result<Box<dyn MultipartUpload>> {
            self.0.open_multipart(key, options).await
        }

        pub(super) async fn get_opts(
            &self,
            key: &StagingKey,
            options: GetOptions,
        ) -> slatedb::object_store::Result<GetResult> {
            self.0.get_opts(key, options).await
        }

        pub(super) async fn head(&self, key: &StagingKey) -> slatedb::object_store::Result<ObjectMeta> {
            self.0.head(key).await
        }

        pub(super) async fn reclaim(&self, key: &StagingKey) -> slatedb::object_store::Result<()> {
            self.0.reclaim(key).await
        }
    }
}

use authority::{AuthoritativeStore, StagingAuthority, StagingKey};

/// R6-STOR-02: what a streaming witness reads from.
enum RangeSource<'a> {
    Authoritative(&'a AuthoritativeStore, &'a ObjectPath),
    Staging(&'a StagingAuthority, &'a StagingKey),
}

impl RangeSource<'_> {
    fn name(&self) -> String {
        match self {
            Self::Authoritative(_, location) => location.to_string(),
            Self::Staging(_, key) => key.to_string(),
        }
    }

    async fn len(&self) -> slatedb::object_store::Result<u64> {
        match self {
            Self::Authoritative(store, location) => Ok(store.head(location).await?.size),
            Self::Staging(staging, key) => Ok(staging.head(key).await?.size),
        }
    }

    async fn range(&self, from: u64, to: u64) -> slatedb::object_store::Result<slatedb::bytes::Bytes> {
        let options = GetOptions { range: Some(GetRange::Bounded(from..to)), ..Default::default() };
        let result = match self {
            Self::Authoritative(store, location) => store.get_opts(location, options).await?,
            Self::Staging(staging, key) => staging.get_opts(key, options).await?,
        };
        result.bytes().await
    }
}

/// R6-STOR-02/R6-STOR-03: the content witness of a stored object, computed by
/// STREAMING fixed-size ranges through the incremental digest.
///
/// This replaces `get(..).bytes().await` — the call that made one admitted
/// object cost its own size in live heap (twice, on the fallback path). Peak
/// residency here is one `chunk`, whatever the object's size, which is what
/// the completion-buffer meter records.
async fn stream_witness(
    source: RangeSource<'_>,
    chunk: u64,
    meter: &Arc<BufferMeter>,
) -> slatedb::object_store::Result<ContentWitness> {
    let chunk = chunk.max(1);
    let len = source.len().await?;
    let mut digest = ObjectDigest::new();
    let mut offset = 0u64;
    while offset < len {
        let end = offset.saturating_add(chunk).min(len);
        let bytes = source.range(offset, end).await?;
        let _charge = charge_buffer(Some(meter), bytes.len() as u64);
        if bytes.is_empty() {
            return Err(slatedb::object_store::Error::Precondition {
                path: source.name(),
                source: format!(
                    "a ranged read of {}..{end} returned no bytes while {len} were expected \
                     (R6-STOR-02): refusing rather than looping or accepting a short object",
                    offset
                )
                .into(),
            });
        }
        digest.update(&bytes);
        offset = offset.saturating_add(bytes.len() as u64);
    }
    Ok(digest.witness())
}

/// R6-STOR-02: byte-exact comparison of an outgoing payload against an object
/// already stored at an immutable key, by STREAMING the stored object through
/// fixed windows instead of pulling it whole into memory. Byte-exact is
/// strictly stronger than a digest match, and it is affordable here because
/// the payload is already the caller's own resident buffer.
async fn payload_matches_object(
    store: &AuthoritativeStore,
    location: &ObjectPath,
    payload: &PutPayload,
    len: u64,
    chunk: u64,
    meter: &Arc<BufferMeter>,
) -> slatedb::object_store::Result<bool> {
    if payload.content_length() as u64 != len {
        return Ok(false);
    }
    let chunk = chunk.max(1);
    let mut chunks = payload.into_iter();
    let mut pending: &[u8] = &[];
    let mut offset = 0u64;
    while offset < len {
        let end = offset.saturating_add(chunk).min(len);
        let options = GetOptions { range: Some(GetRange::Bounded(offset..end)), ..Default::default() };
        let stored = store.get_opts(location, options).await?.bytes().await?;
        let _charge = charge_buffer(Some(meter), stored.len() as u64);
        if stored.is_empty() {
            return Ok(false);
        }
        let mut window = &stored[..];
        while !window.is_empty() {
            if pending.is_empty() {
                match chunks.next() {
                    Some(next) => pending = next.as_ref(),
                    None => return Ok(false),
                }
                continue;
            }
            let take = pending.len().min(window.len());
            if pending[..take] != window[..take] {
                return Ok(false);
            }
            pending = &pending[take..];
            window = &window[take..];
        }
        offset = offset.saturating_add(stored.len() as u64);
    }
    Ok(true)
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
/// - the **manifest** single-put path is exempt and passes through unchanged —
///   it is the sole typed conditional-CAS publication path (its own `PutMode`
///   carries the precondition);
/// - every **multipart** upload — the manifest included — is refused at
///   initiation while quarantined, journaled with a unique attempt id, and
///   revalidated AT COMPLETION: quarantine is re-checked, completion is
///   create-only against the store (onto an existing immutable key it is
///   refused + quarantined; onto an existing manifest key it is refused,
///   because the multipart API cannot carry the manifest's CAS precondition),
///   and only the still-active uncommitted attempt may commit. Abort is
///   allowed for ANY still-uncommitted attempt — superseded included — so
///   every provider upload stays individually reclaimable;
/// - `delete_stream` (the trait's only delete primitive: `delete`, and
///   `rename`'s copy-then-delete both funnel through it), overwrite-mode
///   `copy`, and `rename` are all typed refusals.
///
/// "Mere symbol absence is not proof": every clause is a runtime boundary a
/// probe exercises, not a compile-time convention.
#[derive(Debug)]
struct NoDeleteStore {
    /// R6-STOR-04: the AUTHORITATIVE-namespace handle. It has no delete,
    /// rename, overwrite-copy or unconditional-put method, and no way back to
    /// a raw `ObjectStore` — the wrapper no longer holds one.
    authoritative: AuthoritativeStore,
    /// R6-STOR-04: the disjoint STAGING-namespace handle. The only handle in
    /// the process with reclaim (delete) authority, and it can only address
    /// keys inside the multipart staging namespace.
    staging: StagingAuthority,
    /// Raised the first time a different-bytes overwrite of an immutable key
    /// is refused: the materialisation is no longer trustworthy and a
    /// supervisor should quarantine it (S-04). Shared so wrappers derived from
    /// this store observe the same flag.
    quarantined: Arc<AtomicBool>,
    /// Per-attempt multipart journal (see [`MultipartJournal`]): completion is
    /// gated to the still-active, uncommitted attempt; abort to any
    /// still-uncommitted attempt, superseded included.
    multipart_journal: Arc<Mutex<MultipartJournal>>,
    next_attempt_id: Arc<AtomicU64>,
    /// Immutability ledger (S-04 instrumentation, R6-STOR-03): the recorded
    /// length + FULL SHA-256 digest of every immutable key this principal has
    /// admitted — never a 64-bit checksum. Re-admitting a key whose witness
    /// differs is the very overwrite the boundary refuses.
    immutable_ledger: Arc<Mutex<HashMap<String, ContentWitness>>>,
    /// R6-STOR-04: durable inventory of staging objects whose reclaim failed.
    orphans: Arc<OrphanInventory>,
    /// R6-STOR-02: the streaming window and the object-size ceilings this
    /// materialisation admits under.
    limits: Arc<MultipartLimits>,
    /// R6-STOR-02: this materialisation's completion-buffer high-water mark.
    buffers: Arc<BufferMeter>,
}

impl NoDeleteStore {
    fn new(inner: Arc<dyn ObjectStore>) -> Self {
        // R6-STOR-04: the raw handle is consumed HERE and is unreachable from
        // either capability afterwards.
        let (authoritative, staging) = authority::split(inner);
        Self {
            authoritative,
            staging,
            quarantined: Arc::new(AtomicBool::new(false)),
            multipart_journal: Arc::new(Mutex::new(MultipartJournal::default())),
            next_attempt_id: Arc::new(AtomicU64::new(1)),
            immutable_ledger: Arc::new(Mutex::new(HashMap::new())),
            orphans: Arc::new(OrphanInventory::default()),
            limits: Arc::new(MultipartLimits::default()),
            buffers: Arc::new(BufferMeter::default()),
        }
    }

    /// R6-STOR-04: bind the durable orphan sink to this materialisation's
    /// lifecycle-marker directory, so a failed staging reclaim leaves a record
    /// that outlives the process.
    fn bind_orphan_sink(&self, keyspace_dir: &Path) {
        self.orphans.bind(keyspace_dir.join(MULTIPART_ORPHAN_FILE));
    }

    fn verify_chunk(&self) -> u64 {
        self.limits.verify_chunk()
    }

    /// Lower the R6-STOR-02 streaming window and size ceilings so a test can
    /// reach every boundary without multi-gigabyte objects. Production values
    /// are the named constants ([`MULTIPART_VERIFY_CHUNK_BYTES`],
    /// [`MULTIPART_MAX_OBJECT_BYTES`],
    /// [`MULTIPART_MAX_MATERIALISED_PROMOTE_BYTES`]).
    #[cfg(test)]
    fn set_limits_for_test(&self, verify_chunk: u64, max_object: u64, max_materialised_promote: u64) {
        self.limits.verify_chunk_bytes.store(verify_chunk, Ordering::SeqCst);
        self.limits.max_object_bytes.store(max_object, Ordering::SeqCst);
        self.limits.max_materialised_promote_bytes.store(max_materialised_promote, Ordering::SeqCst);
    }

    /// Whether a different-bytes overwrite of an immutable key was ever
    /// refused on this principal (S-04 quarantine signal).
    fn is_quarantined(&self) -> bool {
        self.quarantined.load(Ordering::SeqCst)
    }

    /// Lower the R5-STOR-08 journal budgets so a test can reach them without
    /// streaming gigabytes. Test-only: production budgets are the named
    /// constants ([`MULTIPART_MAX_OPEN_ATTEMPTS`],
    /// [`MULTIPART_MAX_JOURNALED_BYTES`], [`MULTIPART_TERMINAL_RECEIPTS`]).
    #[cfg(test)]
    fn set_multipart_budgets_for_test(&self, max_open_attempts: usize, max_journaled_bytes: u64, receipts: usize) {
        let mut journal = self.multipart_journal.lock().unwrap();
        journal.max_open_attempts = max_open_attempts;
        journal.max_journaled_bytes = max_journaled_bytes;
        journal.max_terminal_receipts = receipts;
    }

    /// Record (or verify) an immutable key's content witness in the ledger.
    /// Returns `Err` if the key is already recorded with a DIFFERENT witness —
    /// the proof that a referenced object's bytes changed. R6-STOR-03: the
    /// stored witness is the full digest, not a `u64`.
    fn ledger_admit(&self, location: &ObjectPath, witness: ContentWitness) -> Result<(), ()> {
        let mut ledger = self.immutable_ledger.lock().unwrap();
        match ledger.get(location.as_ref()) {
            Some(previous) if !previous.matches(&witness) => Err(()),
            _ => {
                ledger.insert(location.to_string(), witness);
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
        // R6-STOR-02/R6-STOR-03: the witness is computed INCREMENTALLY over
        // the payload's own chunks. The previous code copied every payload
        // into a fresh `Vec` solely to checksum it — a full extra copy of
        // every admitted object, for a 64-bit hash.
        let witness = payload_witness(&payload);
        // Force create semantics regardless of the caller's requested mode: an
        // immutable key may only be written once (SlateDB names SSTs by unique
        // ULID, so a legitimate first write always creates). R6-STOR-04: the
        // create-only mode is now a property of the authoritative handle's
        // API, not a `PutOptions` field this wrapper remembers to set.
        match self.authoritative.put_create(location, payload.clone(), opts).await {
            Ok(result) => {
                // ledger records the admitted witness; a create cannot
                // collide with a differing prior (the key was absent).
                let _ = self.ledger_admit(location, witness);
                Ok(result)
            }
            Err(slatedb::object_store::Error::AlreadyExists { .. }) => {
                // an object is already here: allowed ONLY if byte-identical.
                // R6-STOR-02: the stored object is compared by STREAMING
                // windows, never pulled whole into memory.
                let meta = self.authoritative.head(location).await?;
                let identical = payload_matches_object(
                    &self.authoritative,
                    location,
                    &payload,
                    meta.size,
                    self.verify_chunk(),
                    &self.buffers,
                )
                .await?;
                if identical {
                    // idempotent replay of identical bytes: success, no rewrite
                    let _ = self.ledger_admit(location, witness);
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
        write!(f, "NoDeleteStore(authoritative={:?})", self.authoritative)
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
            // PutMode carries the CAS precondition; passed through the
            // authoritative handle's manifest-only method (R6-STOR-04), which
            // refuses any non-manifest location.
            return self.authoritative.put_manifest(location, payload, opts).await;
        }
        self.put_immutable(location, payload, opts).await
    }

    async fn put_multipart_opts(
        &self,
        location: &ObjectPath,
        opts: PutMultipartOptions,
    ) -> slatedb::object_store::Result<Box<dyn MultipartUpload>> {
        // Fail-closed once quarantined (S-04, R4-STOR-04): initiation is
        // refused for EVERY key class — the manifest included — BEFORE the
        // inner store opens a provider upload; a quarantined materialisation
        // admits no new mutation attempt of any kind.
        if self.is_quarantined() {
            return Err(slatedb::object_store::Error::Precondition {
                path: location.to_string(),
                source: "materialisation is quarantined (S-04): a prior immutable-key overwrite was refused; \
                         refusing multipart initiation"
                    .into(),
            });
        }
        // Initiation at an occupied immutable key is admitted: until the
        // create-only PROMOTE at completion the provider holds only staged
        // bytes under this attempt's own unique key, and the mutation decision
        // is the atomic promote (R5-STOR-05), never an overwrite.
        let attempt_id = self.next_attempt_id.fetch_add(1, Ordering::SeqCst);
        let attempt_location = StagingKey::mint(location, attempt_id);
        // R5-STOR-08: budget admission BEFORE the provider upload is opened —
        // a refused attempt journals nothing and touches no provider state.
        {
            let mut journal = self.multipart_journal.lock().unwrap();
            journal.initiate(location, attempt_id).map_err(|refused| refused.into_store_error(location))?;
        }
        // The provider upload streams to the ATTEMPT key (R5-STOR-05) through
        // the STAGING authority (R6-STOR-04): two racing completers can never
        // collide before the promote, and this handle cannot address a
        // published name at all.
        let inner = match self.staging.open_multipart(&attempt_location, opts).await {
            Ok(upload) => upload,
            Err(error) => {
                // release the reservation: the attempt never opened
                self.multipart_journal.lock().unwrap().retire(location.as_ref(), attempt_id, AttemptState::Aborted);
                return Err(error);
            }
        };
        Ok(Box::new(JournaledMultipart {
            inner,
            authoritative: self.authoritative.clone(),
            staging: self.staging.clone(),
            orphans: self.orphans.clone(),
            quarantined: self.quarantined.clone(),
            location: location.clone(),
            attempt_location,
            attempt_id,
            attempt_object_completed: false,
            streamed: ObjectDigest::new(),
            limits: self.limits.clone(),
            buffers: self.buffers.clone(),
            journal: self.multipart_journal.clone(),
            manifest_key: is_manifest_key(location),
        }))
    }

    async fn get_opts(&self, location: &ObjectPath, options: GetOptions) -> slatedb::object_store::Result<GetResult> {
        self.authoritative.get_opts(location, options).await
    }

    fn list(&self, prefix: Option<&ObjectPath>) -> BoxStream<'static, slatedb::object_store::Result<ObjectMeta>> {
        self.authoritative.list(prefix)
    }

    async fn list_with_delimiter(&self, prefix: Option<&ObjectPath>) -> slatedb::object_store::Result<ListResult> {
        self.authoritative.list_with_delimiter(prefix).await
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
        // R6-STOR-04: forwarded through the authoritative handle, whose copy
        // is create-only by TYPE — an overwrite-mode copy cannot be expressed.
        self.authoritative.copy_create(from, to, options).await
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

/// A multipart upload gated by the [`NoDeleteStore`] journal and published
/// through a provider-atomic create-only PROMOTE (S-04, R4-STOR-04,
/// R5-STOR-05). Parts stream to this attempt's own globally unique STAGING
/// key (never the target), with their length and checksum accounted as they
/// stream; completion then:
///
/// - **quarantine re-check**: a namespace quarantined since initiation refuses
///   the completion and reclaims the staged upload;
/// - **journal gate**: only the still-active, uncommitted attempt recorded for
///   this location may complete — a stale attempt (one superseded by a newer
///   `put_multipart_opts` on the same location) and an already-committed
///   attempt are both typed refusals;
/// - **stage + verify**: the provider upload completes to the unique staging
///   key (no contention possible there), and the staged object is read back
///   and verified against the streamed length + checksum;
/// - **atomic promote (R5-STOR-05)**: the staged object is promoted to the
///   target name with a create-only conditional copy
///   (`CopyMode::Create` — atomic `hard_link` on `LocalFileSystem`,
///   `copy-if-not-exists` where the provider supports it). Where the store
///   reports conditional copy unsupported (plain S3 without a
///   copy-if-not-exists configuration), the promote falls back to a
///   create-only single PUT of the verified staged bytes — byte cost: one
///   full readback (always paid for verification) plus one full re-upload on
///   the fallback path only;
/// - **loser settlement**: the loser of a promote race (or a replay onto an
///   already-published key) compares the published bytes against its staged
///   bytes: IDENTICAL bytes settle idempotently as success (timeout-after-
///   promote replays converge); DIFFERENT bytes are a typed refusal — with
///   quarantine for immutable keys (changed-byte overwrite attempt), without
///   quarantine for the manifest (an existing manifest is normal CAS state,
///   and manifest republication is only admitted through the conditional
///   single-put path). Either way the loser cleans its OWN staging object.
///
/// Abort is allowed for ANY still-uncommitted attempt — superseded and
/// quarantined included — so an authorized cleanup actor can always reclaim
/// an attempt's exact staged upload; only the committed attempt (whose object
/// is published) and an already-aborted one refuse.
///
/// Honest scope: the journal is process-local (see [`MultipartJournal`]); the
/// atomic promote against the STORE — not the journal — is what holds across
/// processes and restarts (R5-STOR-05). Staging cleanup is best-effort and
/// scoped to THIS attempt's own staging key (a named exception to the
/// no-delete posture: a staging object never became authoritative state); a
/// failed cleanup leaves an inert `.mpa-` orphan for the separated
/// maintenance principal, and durable listings (the remote checkpoint)
/// exclude staging keys by infix.
struct JournaledMultipart {
    /// Provider upload streaming to [`Self::attempt_location`].
    inner: Box<dyn MultipartUpload>,
    /// R6-STOR-04: read/create-only authority over the TARGET namespace. No
    /// delete exists on this handle, and no raw store can be recovered from
    /// it — the previous field was the raw `Arc<dyn ObjectStore>`, which is
    /// what let `cleanup_attempt_object` call `store.delete` directly.
    authoritative: AuthoritativeStore,
    /// R6-STOR-04: the disjoint staging authority — the only reclaim path, and
    /// it can only address this attempt's own staging namespace.
    staging: StagingAuthority,
    /// R6-STOR-04: where a FAILED reclaim is recorded durably.
    orphans: Arc<OrphanInventory>,
    /// The materialisation's shared quarantine flag, re-checked at completion.
    quarantined: Arc<AtomicBool>,
    /// The TARGET key this attempt publishes to (via the promote).
    location: ObjectPath,
    /// This attempt's globally unique staging key (R5-STOR-05).
    attempt_location: StagingKey,
    attempt_id: u64,
    /// Whether the provider upload has completed to the staging key (so a
    /// later abort must clean the staged OBJECT, not the provider upload).
    attempt_object_completed: bool,
    /// R6-STOR-03: the domain-separated SHA-256 of the streamed parts, hashed
    /// INCREMENTALLY as they flow, plus their exact length. This is the
    /// authoritative expected identity the staged object is verified against
    /// and the occupied target is settled by.
    streamed: ObjectDigest,
    /// R6-STOR-02: the streaming window and object-size ceilings in force.
    limits: Arc<MultipartLimits>,
    /// R6-STOR-02: the materialisation's completion-buffer meter.
    buffers: Arc<BufferMeter>,
    journal: Arc<Mutex<MultipartJournal>>,
    /// Manifest multipart (should not occur — manifests are small single
    /// puts): gated exactly like data, except an occupied-target refusal does
    /// not quarantine (see the type-level policy above).
    manifest_key: bool,
}

impl std::fmt::Debug for JournaledMultipart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "JournaledMultipart[target={}, attempt={}, staging={}]",
            self.location, self.attempt_id, self.attempt_location
        )
    }
}

/// The two outcomes of the atomic promote (R5-STOR-05).
enum PromoteOutcome {
    /// This attempt's staged object became the target — the one winner.
    Won,
    /// The target already holds an object (a racing winner or a replay):
    /// settle by byte comparison.
    Occupied,
}

impl JournaledMultipart {
    /// Is this attempt still the active, uncommitted one for its location?
    /// Returns the reason it is not, for a precise typed refusal.
    fn active_uncommitted(&self) -> Result<(), String> {
        let journal = self.journal.lock().unwrap();
        Self::own_state_uncommitted(&journal, self.attempt_id)?;
        match journal.active.get(self.location.as_ref()) {
            Some(active_id) if *active_id == self.attempt_id => Ok(()),
            Some(active_id) => {
                Err(format!("attempt {} is stale; attempt {active_id} superseded it", self.attempt_id))
            }
            None => Err("no journal entry for this location".to_owned()),
        }
    }

    /// Is this attempt itself still uncommitted? Supersession is deliberately
    /// NOT checked: a superseded attempt must remain abortable so its staged
    /// upload stays reclaimable (R4-STOR-04).
    fn own_uncommitted(&self) -> Result<(), String> {
        Self::own_state_uncommitted(&self.journal.lock().unwrap(), self.attempt_id)
    }

    fn own_state_uncommitted(journal: &MultipartJournal, attempt_id: u64) -> Result<(), String> {
        match journal.state_of(attempt_id) {
            Some(AttemptState::Uncommitted) => Ok(()),
            Some(AttemptState::Committed) => Err("this attempt is already committed".to_owned()),
            Some(AttemptState::Aborted) => Err("this attempt was aborted".to_owned()),
            None => Err("no journal entry for this attempt (retired beyond the receipt window)".to_owned()),
        }
    }

    /// Retire exactly THIS attempt's journal row (R5-STOR-08): budget
    /// released, bounded terminal receipt recorded — never another attempt's.
    fn retire(&self, state: AttemptState) {
        self.journal.lock().unwrap().retire(self.location.as_ref(), self.attempt_id, state);
    }

    fn refusal(&self, message: String) -> slatedb::object_store::Error {
        slatedb::object_store::Error::Precondition { path: self.location.to_string(), source: message.into() }
    }

    fn verify_chunk(&self) -> u64 {
        self.limits.verify_chunk()
    }

    /// Reclaim THIS attempt's own staging object (R5-STOR-05, R6-STOR-04).
    ///
    /// It goes through the STAGING authority, which structurally cannot
    /// address a published name, and it is scoped to the exact staging key
    /// this instance minted — never a listing, never another attempt's key.
    /// A FAILED reclaim is no longer a swallowed `let _ = ..`: it produces a
    /// durable orphan record naming the key and the reason, so the inert
    /// `.mpa-` object left behind is visible to the separated maintenance
    /// principal instead of being invisible state.
    async fn reclaim_staged(&mut self) {
        if let Err(error) = self.staging.reclaim(&self.attempt_location).await {
            self.orphans.record(
                self.attempt_location.path().as_ref(),
                &format!(
                    "staging reclaim failed for multipart attempt {} targeting {}: {error}",
                    self.attempt_id, self.location
                ),
            );
        }
    }

    /// The published target's metadata as a [`PutResult`].
    async fn published_result(&mut self) -> slatedb::object_store::Result<PutResult> {
        let meta = self.authoritative.head(&self.location).await?;
        Ok(PutResult { e_tag: meta.e_tag, version: meta.version, extensions: Default::default() })
    }

    /// R6-STOR-02 fallback promote: a create-only single PUT, used only where
    /// the provider reports conditional copy unsupported.
    ///
    /// The staged bytes are streamed in through fixed windows and pushed onto
    /// a CHUNKED `PutPayload` — there is no contiguous `Vec` and no second
    /// copy (the previous code did `bytes().await` and then `to_vec()`). The
    /// object is nevertheless resident for the duration of the PUT, because
    /// `object_store` has no create-only streaming publication primitive, so
    /// this path is capped at [`MULTIPART_MAX_MATERIALISED_PROMOTE_BYTES`]:
    /// above it the completion is a typed refusal, never an unbounded
    /// allocation. The bytes are re-hashed on the way through and must still
    /// match the expected witness, so a staged object mutated between
    /// verification and promotion cannot be published.
    async fn promote_by_streaming_put(
        &mut self,
        expected: &ContentWitness,
    ) -> slatedb::object_store::Result<PromoteOutcome> {
        let maximum = self.limits.max_materialised_promote();
        if expected.len > maximum {
            return Err(self.refusal(format!(
                "multipart completion refused for {} (R6-STOR-02): the provider reports conditional \
                 copy unsupported, so the only create-only publication primitive left is a single \
                 conditional PUT, which is resident for its whole payload; this object is {} bytes, \
                 over the {maximum}-byte materialised-promote maximum. Refusing rather than \
                 allocating without bound.",
                self.location, expected.len
            )));
        }
        let chunk = self.verify_chunk();
        let mut payload = PutPayloadMut::new();
        let mut digest = ObjectDigest::new();
        let mut charges = Vec::new();
        let mut offset = 0u64;
        while offset < expected.len {
            let end = offset.saturating_add(chunk).min(expected.len);
            let options = GetOptions { range: Some(GetRange::Bounded(offset..end)), ..Default::default() };
            let bytes = self.staging.get_opts(&self.attempt_location, options).await?.bytes().await?;
            if bytes.is_empty() {
                return Err(self.refusal(format!(
                    "the staged object for {} returned no bytes at offset {offset} (R6-STOR-02)",
                    self.location
                )));
            }
            charges.push(charge_buffer(Some(&self.buffers), bytes.len() as u64));
            digest.update(&bytes);
            offset = offset.saturating_add(bytes.len() as u64);
            payload.push(bytes);
        }
        if !digest.witness().matches(expected) {
            return Err(self.refusal(format!(
                "the staged object for {} changed between verification and promotion (R6-STOR-03): \
                 expected {}, streamed {}",
                self.location,
                expected.hex(),
                digest.witness().hex()
            )));
        }
        match self.authoritative.put_create(&self.location, payload.freeze(), PutOptions::default()).await {
            Ok(_) => Ok(PromoteOutcome::Won),
            Err(slatedb::object_store::Error::AlreadyExists { .. }) => Ok(PromoteOutcome::Occupied),
            Err(other) => Err(other),
        }
    }
}

#[async_trait]
impl MultipartUpload for JournaledMultipart {
    fn put_part(&mut self, data: PutPayload) -> UploadPart {
        let len = data.content_length() as u64;
        // R6-STOR-02: the PER-OBJECT ceiling is checked FIRST and is
        // independent of the aggregate journal budget — a single object that
        // would be too large to verify and promote is refused even when the
        // aggregate budget is entirely free.
        if let Err(refused) = admit_object_bytes(self.streamed.len(), len, self.limits.max_object()) {
            let error = refused.into_store_error(&self.location);
            return Box::pin(async move { Err(error) });
        }
        // R5-STOR-08: streamed bytes are reserved against the journal's byte
        // budget as they arrive; a refusal reserves nothing and streams
        // nothing — typed admission, not growth.
        let admission = self.journal.lock().unwrap().reserve_part_bytes(self.attempt_id, len);
        if let Err(refused) = admission {
            let error = refused.into_store_error(&self.location);
            return Box::pin(async move { Err(error) });
        }
        // R6-STOR-02/R6-STOR-03: hash INCREMENTALLY while the parts flow, into
        // the same domain-separated digest the staged object is verified with.
        // Nothing is retained beyond the digest state.
        for chunk in &data {
            self.streamed.update(chunk.as_ref());
        }
        self.inner.put_part(data)
    }

    async fn complete(&mut self) -> slatedb::object_store::Result<PutResult> {
        // Quarantine, revalidated AT USE TIME (R4-STOR-04): a namespace
        // quarantined since initiation admits no completion. The staged
        // upload is reclaimed — and marked Aborted only when that reclaim
        // succeeds, so a failed reclaim stays retryable.
        if self.quarantined.load(Ordering::SeqCst) {
            if self.attempt_object_completed {
                self.reclaim_staged().await;
                self.retire(AttemptState::Aborted);
            } else if self.inner.abort().await.is_ok() {
                self.retire(AttemptState::Aborted);
            }
            return Err(self.refusal(format!(
                "multipart completion refused for {} (S-04): the materialisation was quarantined after \
                 this attempt was initiated; the upload has been aborted",
                self.location
            )));
        }
        // Journal gate: only the still-active, uncommitted attempt.
        if let Err(reason) = self.active_uncommitted() {
            return Err(self.refusal(format!(
                "multipart completion refused for {} (S-04): {reason}; completion is gated to the \
                 recorded uncommitted upload attempt so a stale actor cannot replace published bytes",
                self.location
            )));
        }
        // Stage (R5-STOR-05): complete the provider upload to this attempt's
        // globally unique staging key — no other attempt can contend there.
        if !self.attempt_object_completed {
            self.inner.complete().await?;
            self.attempt_object_completed = true;
        }
        // R6-STOR-02: from here on the completion holds buffers, so it runs
        // under the process-wide completion gate. Peak heap for the streaming
        // paths is one window per permitted completion, not one object.
        let _permit = CompletionPermit::acquire().await;
        // R6-STOR-03: the authoritative expected identity of this attempt —
        // exact length plus the domain-separated SHA-256 of the parts as they
        // streamed. The previous predicate was length plus a 64-bit
        // `DefaultHasher` value, which is a weaker authority than the
        // content-addressed identity it is guarding.
        let expected = self.streamed.witness();
        // Verify the staged object by STREAMING it back through the same
        // digest (R6-STOR-02: never `get(..).bytes()` of the whole object)
        // before anything can be published under the target name.
        let staged = match stream_witness(
            RangeSource::Staging(&self.staging, &self.attempt_location),
            self.verify_chunk(),
            &self.buffers,
        )
        .await
        {
            Ok(staged) => staged,
            Err(error) => {
                self.reclaim_staged().await;
                self.retire(AttemptState::Aborted);
                return Err(error);
            }
        };
        if !staged.matches(&expected) {
            self.reclaim_staged().await;
            self.retire(AttemptState::Aborted);
            return Err(self.refusal(format!(
                "multipart stage verification failed for {} (R5-STOR-05, R6-STOR-03): the staged \
                 object does not match the streamed parts (expected length {} digest {}, staged \
                 length {} digest {}); the staged upload has been reclaimed (a reclaim that itself \
                 fails is recorded as a durable orphan, R6-STOR-04)",
                self.location,
                expected.len,
                expected.hex(),
                staged.len,
                staged.hex()
            )));
        }
        // Atomic promote (R5-STOR-05): create-only conditional copy where the
        // store supports it; create-only streaming PUT of the verified staged
        // bytes where it does not. Exactly one contender can win the target.
        let outcome = match self
            .authoritative
            .copy_create(self.attempt_location.path(), &self.location, CopyOptions::default())
            .await
        {
            Ok(()) => PromoteOutcome::Won,
            Err(slatedb::object_store::Error::AlreadyExists { .. }) => PromoteOutcome::Occupied,
            Err(
                slatedb::object_store::Error::NotSupported { .. }
                | slatedb::object_store::Error::NotImplemented { .. },
            ) => match self.promote_by_streaming_put(&expected).await {
                Ok(outcome) => outcome,
                Err(error) => {
                    self.reclaim_staged().await;
                    return Err(error);
                }
            },
            Err(other) => {
                self.reclaim_staged().await;
                return Err(other);
            }
        };
        match outcome {
            PromoteOutcome::Won => {
                self.reclaim_staged().await;
                self.retire(AttemptState::Committed);
                self.published_result().await
            }
            PromoteOutcome::Occupied => {
                // Loser settlement: idempotent on identical content, typed
                // refusal (no overwrite, ever) on different content. R6-STOR-02:
                // the published object is compared by length + STREAMING
                // cryptographic digest against this attempt's authoritative
                // expected witness — never by pulling both objects into memory.
                let published = stream_witness(
                    RangeSource::Authoritative(&self.authoritative, &self.location),
                    self.verify_chunk(),
                    &self.buffers,
                )
                .await?;
                self.reclaim_staged().await;
                if published.matches(&expected) {
                    // a replayed/racing publication of the SAME bytes has
                    // already converged — settle as success (R5-STOR-05
                    // timeout-after-promote convergence).
                    self.retire(AttemptState::Committed);
                    self.published_result().await
                } else if self.manifest_key {
                    // manifest republication is legitimate, but ONLY through
                    // the conditional single-put path — the multipart API
                    // carries no CAS precondition, so this is a refusal, not
                    // tamper evidence.
                    Err(self.refusal(format!(
                        "multipart completion refused for manifest key {} (S-04): the multipart API \
                         carries no CAS precondition; manifest republication must use the typed \
                         conditional single-put path",
                        self.location
                    )))
                } else {
                    // the changed-byte overwrite the boundary exists to stop:
                    // this attempt lost the create-only promote and its bytes
                    // differ from the published object — refuse + quarantine.
                    self.quarantined.store(true, Ordering::SeqCst);
                    Err(self.refusal(format!(
                        "immutable key multipart overwrite refused (S-04, V16 inv. 81-83, R5-STOR-05): \
                         the create-only promote for already-written immutable key {} lost to different \
                         published bytes; the materialisation is quarantined",
                        self.location
                    )))
                }
            }
        }
    }

    async fn abort(&mut self) -> slatedb::object_store::Result<()> {
        // Abort is allowed for ANY still-uncommitted attempt — superseded and
        // quarantined included (R4-STOR-04): cleanup must always be able to
        // reclaim an uncommitted staged upload. Only the committed attempt
        // (whose object is published) and an already-aborted one refuse.
        if let Err(reason) = self.own_uncommitted() {
            return Err(self.refusal(format!(
                "multipart abort refused for {} (S-04): {reason}; abort is allowed for any \
                 still-uncommitted attempt",
                self.location
            )));
        }
        if self.attempt_object_completed {
            // the provider upload already became a staged object: reclaim is
            // the staging cleanup, not a provider abort
            self.reclaim_staged().await;
        } else {
            self.inner.abort().await?;
        }
        // retired only on success, so a failed abort stays retryable
        self.retire(AttemptState::Aborted);
        Ok(())
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
        // R6-STOR-02: STREAM the object into the file through fixed windows.
        // `get(..).bytes()` here cost one whole object in live heap per
        // downloaded file — a multi-GiB checkpoint restore was a multi-GiB
        // allocation. Peak residency is now one window.
        // R-06: fsync the downloaded file AND its parent directory. A checkpoint
        // the caller goes on to declare COMPLETE must not lose a downloaded SST
        // (or its directory entry) to a crash that empties the page cache; a
        // bare `fs::write` leaves both only in the page cache.
        stream_object_to_file(store, location, &target, MULTIPART_VERIFY_CHUNK_BYTES).await?;
    }
    Ok(())
}

/// Write `bytes` to `path` and make the file AND its parent directory entry
/// durable (R-06). Extracted so the write-then-fsync sequence is one auditable
/// unit at every remote-download site.
/// R6-STOR-02: copy one remote object into a local file through fixed
/// windows, then fsync the file and its parent directory (R-06). Peak heap is
/// one window, whatever the object's size.
async fn stream_object_to_file(
    store: &dyn ObjectStore,
    location: &ObjectPath,
    target: &Path,
    chunk: u64,
) -> Result<(), slatedb::Error> {
    let chunk = chunk.max(1);
    let size = store.head(location).await.map_err(store_error)?.size;
    {
        let mut file = fs::File::create(target).map_err(io_error)?;
        let mut offset = 0u64;
        while offset < size {
            let end = offset.saturating_add(chunk).min(size);
            let options = GetOptions { range: Some(GetRange::Bounded(offset..end)), ..Default::default() };
            let bytes =
                store.get_opts(location, options).await.map_err(store_error)?.bytes().await.map_err(store_error)?;
            let _charge = charge_buffer(None, bytes.len() as u64);
            if bytes.is_empty() {
                return Err(store_error(slatedb::object_store::Error::Precondition {
                    path: location.to_string(),
                    source: format!("a ranged read at offset {offset} returned no bytes of {size} (R6-STOR-02)")
                        .into(),
                }));
            }
            io::Write::write_all(&mut file, &bytes).map_err(io_error)?;
            offset = offset.saturating_add(bytes.len() as u64);
        }
        file.sync_all().map_err(io_error)?;
    }
    if let Some(parent) = target.parent() {
        fs::File::open(parent).and_then(|dir| dir.sync_all()).map_err(io_error)?;
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
    ///
    /// R5-STOR-01: the configuration consumed here is the process-ADMITTED
    /// one — resolved from the environment exactly once at the
    /// `BackendContext` admission point and witnessed against every later
    /// context (`verify_process_consistency`), so it is provably the same
    /// object the caller's context carries and the marker attests. This
    /// module performs no environment read of its own; an open before any
    /// admission is a typed refusal, never a fresh resolution.
    pub(super) fn open_s3(path: &Path) -> Result<Self, Arc<slatedb::Error>> {
        let config = crate::factory::admitted_s3_runtime().ok_or_else(|| {
            Arc::new(slatedb::Error::unavailable(
                "no admitted S3 runtime configuration for this process (R5-STOR-01): the S3 lane opens \
                 only through BackendContext admission; refusing rather than re-reading the environment \
                 below the admission point"
                    .to_owned(),
            ))
        })?;
        Self::open_s3_with(&config, path)
    }

    /// The explicit-config S3 open (R5-STOR-01): every effective input —
    /// endpoint, region, bucket, root prefix, cache budget, credentials —
    /// comes from the passed [`S3RuntimeConfig`] and nowhere else.
    pub(super) fn open_s3_with(config: &S3RuntimeConfig, path: &Path) -> Result<Self, Arc<slatedb::Error>> {
        let store = build_s3_store(config).map_err(Arc::new)?;
        let base_prefix = object_prefix(config, path);
        Self::open_remote(store, base_prefix, path, config.cache_bytes)
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
        let principal = NoDeleteStore::new(store);
        // R6-STOR-04: bind the durable orphan inventory to the keyspace's
        // lifecycle-marker directory BEFORE anything can be staged, so a
        // failed staging reclaim always has somewhere durable to land.
        principal.bind_orphan_sink(path);
        let store: Arc<dyn ObjectStore> = Arc::new(principal);
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
        // R4-STOR-07: this method runs on a LIVE keyspace handle, and a live
        // store always has a published manifest root (open itself writes the
        // initial manifest before any data lands) — so "no manifest" is never
        // inferred as emptiness: it is missing or corrupt live root state, and
        // the checkpoint is refused BEFORE any file is copied, leaving the
        // checkpoint target (and any predecessor state) untouched.
        let manifest_dir = find_manifest_dir(&self.path).map_err(|error| Arc::new(io_error(error)))?.ok_or_else(
            || Arc::new(missing_manifest_root_error(format!("no manifest directory under {:?}", self.path))),
        )?;
        // lexicographic max = newest manifest, same pin as checkpoint_remote
        let pinned = pin_newest_manifest(&manifest_dir)
            .map_err(|error| Arc::new(io_error(error)))?
            .ok_or_else(|| Arc::new(missing_manifest_root_error(format!("empty manifest directory {manifest_dir:?}"))))?;

        copy_dir_recursive_excluding(&self.path, checkpoint_keyspace_dir, Some(&manifest_dir))
            .map_err(|error| Arc::new(io_error(error)))?;

        let relative = manifest_dir.strip_prefix(&self.path).expect("manifest dir is under the keyspace path");
        let target_dir = checkpoint_keyspace_dir.join(relative);
        fs::create_dir_all(&target_dir).map_err(|error| Arc::new(io_error(error)))?;
        let target = target_dir.join(pinned.file_name().expect("manifest file name"));
        fs::copy(&pinned, &target).map_err(|error| Arc::new(io_error(error)))?;
        // the pinned manifest is what restore opens: its bytes and its
        // directory entry must be durable, not just in the page cache
        crate::fsync_path(&target).map_err(|error| Arc::new(io_error(error)))?;
        crate::fsync_path(&target_dir).map_err(|error| Arc::new(io_error(error)))?;
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
            // LocalFS path applies to manifest file names. R4-STOR-07: a LIVE
            // keyspace always has a published manifest, so an empty manifest
            // listing is missing or corrupt root state, never emptiness — the
            // checkpoint is refused before anything is downloaded.
            // R5-STOR-05: transient multipart STAGING objects (`.mpa-` infix)
            // are never authoritative state — they are excluded both from the
            // pin (a staging name could sort after the newest real manifest)
            // and from the download set (a concurrently cleaned staging object
            // would otherwise fail the checkpoint with NotFound).
            let pinned = manifests
                .iter()
                .map(|meta| &meta.location)
                .filter(|location| !is_multipart_attempt_key(location))
                .max()
                .cloned()
                .ok_or_else(|| {
                    missing_manifest_root_error(format!("empty remote manifest listing under {manifest_dir}"))
                })?;
            let objects = list_remote_prefix(store.as_ref(), &prefix).await?;
            let is_manifest = |location: &ObjectPath| location.as_ref().starts_with(&manifest_prefix);
            let mut to_copy: Vec<ObjectPath> = objects
                .iter()
                .map(|meta| meta.location.clone())
                .filter(|location| !is_manifest(location) && !is_multipart_attempt_key(location))
                .collect();
            to_copy.push(pinned);
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
/// tests, not silently. For a LIVE keyspace `None` is a typed checkpoint
/// refusal (R4-STOR-07), never an empty root.
fn find_manifest_dir(keyspace_path: &Path) -> io::Result<Option<PathBuf>> {
    let candidate = keyspace_path.join(DB_SUBDIR).join(MANIFEST_SUBDIR);
    if candidate.is_dir() { Ok(Some(candidate)) } else { Ok(None) }
}

/// The typed refusal for a LIVE keyspace whose manifest root cannot be found
/// (R4-STOR-07). Checkpointing is only reachable through an open
/// [`SlateKeyspace`], and an open `Db` always has a published manifest root —
/// open itself writes the initial manifest before any data lands — so there
/// is no representable "never-initialized" keyspace state at this layer: a
/// truly empty keyspace is still represented BY a manifest, and absence of
/// the physical manifest is always missing or corrupt live store state, never
/// emptiness. `Data` (not `Unavailable`): the condition is integrity damage
/// to correct, never a transient blip to retry through.
fn missing_manifest_root_error(context: String) -> slatedb::Error {
    slatedb::Error::data(format!(
        "checkpoint refused (R4-STOR-07): no SlateDB manifest root to pin for a live keyspace \
         ({context}); an open keyspace always has a published manifest, so its absence is missing \
         or corrupt store state, never an empty keyspace"
    ))
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
mod checkpoint_root_tests {
    //! R4-STOR-07 controls: "no manifest" is never inferred as emptiness.
    //! Checkpointing runs only through a LIVE keyspace handle, and an open Db
    //! always has a published manifest root, so a missing manifest dir / empty
    //! manifest listing is a typed refusal that copies nothing — never a
    //! silent empty checkpoint. The mutant (treat `None` as an optional root
    //! and keep copying) fails the refusal tests below.

    use std::{fs, sync::Arc};

    use slatedb::object_store::{ObjectStore, ObjectStoreExt, local::LocalFileSystem, path::Path as ObjectPath};
    use test_utils::create_tmp_dir;

    use super::{DB_SUBDIR, MANIFEST_SUBDIR, SlateKeyspace, bridge, find_manifest_dir, list_remote_prefix};

    #[test]
    fn a_fresh_empty_keyspace_checkpoints_through_its_manifest_root_not_through_silence() {
        // an open keyspace with NO data still has a typed root: SlateDB
        // publishes the initial manifest at open, and the checkpoint pins and
        // records it — emptiness is represented BY a manifest, never by the
        // absence of one.
        let keyspace_dir = create_tmp_dir("slate-r7-fresh");
        let keyspace = SlateKeyspace::open(&keyspace_dir).unwrap();
        let checkpoint_dir = create_tmp_dir("slate-r7-fresh-out");
        keyspace.checkpoint(&checkpoint_dir).unwrap();
        let manifest_dir = checkpoint_dir.join(DB_SUBDIR).join(MANIFEST_SUBDIR);
        assert!(manifest_dir.is_dir(), "the checkpoint must carry the manifest root");
        assert!(
            fs::read_dir(&manifest_dir).unwrap().next().is_some(),
            "the pinned manifest must be recorded in the checkpoint",
        );
    }

    #[test]
    fn a_live_keyspace_with_a_removed_manifest_dir_refuses_the_checkpoint_and_copies_nothing() {
        let keyspace_dir = create_tmp_dir("slate-r7-missing");
        let keyspace = SlateKeyspace::open(&keyspace_dir).unwrap();
        keyspace.put(b"k", b"v").unwrap();
        let manifest_dir = find_manifest_dir(&keyspace_dir).unwrap().expect("open keyspace has a manifest dir");
        fs::remove_dir_all(&manifest_dir).unwrap();

        let checkpoint_dir = create_tmp_dir("slate-r7-missing-out");
        let refused = keyspace.checkpoint_local(&checkpoint_dir);
        let error = refused.expect_err("a live keyspace without a manifest root must refuse to checkpoint");
        assert!(error.to_string().contains("manifest root"), "the refusal names the missing root: {error}");
        // the refusal happened BEFORE any copy: the target is untouched
        assert!(
            fs::read_dir(&checkpoint_dir).unwrap().next().is_none(),
            "a refused checkpoint must not have copied anything",
        );
    }

    #[test]
    fn a_live_keyspace_with_an_emptied_manifest_dir_refuses_the_checkpoint() {
        // the dir exists but holds nothing to pin: the same missing-root
        // refusal — pin_newest_manifest's Ok(None) is never a silent
        // no-manifest checkpoint for a live keyspace.
        let keyspace_dir = create_tmp_dir("slate-r7-empty");
        let keyspace = SlateKeyspace::open(&keyspace_dir).unwrap();
        keyspace.put(b"k", b"v").unwrap();
        let manifest_dir = find_manifest_dir(&keyspace_dir).unwrap().expect("open keyspace has a manifest dir");
        for entry in fs::read_dir(&manifest_dir).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }

        let checkpoint_dir = create_tmp_dir("slate-r7-empty-out");
        let refused = keyspace.checkpoint_local(&checkpoint_dir);
        let error = refused.expect_err("an empty manifest dir on a live keyspace must refuse the checkpoint");
        assert!(error.to_string().contains("manifest root"), "the refusal names the missing root: {error}");
        assert!(fs::read_dir(&checkpoint_dir).unwrap().next().is_none(), "nothing was copied");
    }

    #[test]
    fn an_empty_remote_manifest_listing_refuses_the_checkpoint_and_downloads_nothing() {
        // the RAW inner store deletes the manifest objects, simulating a
        // missing/corrupt remote root (the runtime principal itself cannot
        // delete); the remote checkpoint path must then refuse rather than
        // download a rootless tree the outer checkpoint would hash and seal.
        let store_dir = create_tmp_dir("slate-r7-remote-store");
        let inner: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix(&*store_dir).unwrap());
        let keyspace_dir = create_tmp_dir("slate-r7-remote-ks");
        let keyspace =
            SlateKeyspace::open_remote(inner.clone(), ObjectPath::from("r7-base"), &keyspace_dir, None).unwrap();
        keyspace.put(b"k", b"v").unwrap();
        {
            let db = keyspace.shared_db();
            bridge(async move { db.flush().await }).unwrap();
        }

        let remote = keyspace.remote.as_ref().expect("remote lane");
        let manifest_prefix = remote.prefix.clone().join(DB_SUBDIR).join(MANIFEST_SUBDIR);
        bridge({
            let (inner, manifest_prefix) = (inner.clone(), manifest_prefix.clone());
            async move {
                for meta in list_remote_prefix(inner.as_ref(), &manifest_prefix).await.unwrap() {
                    inner.delete(&meta.location).await.unwrap();
                }
            }
        });

        let checkpoint_dir = create_tmp_dir("slate-r7-remote-out");
        let refused = SlateKeyspace::checkpoint_remote(remote, &checkpoint_dir);
        let error = refused.expect_err("an empty manifest listing on a live keyspace must refuse the checkpoint");
        assert!(error.to_string().contains("manifest root"), "the refusal names the missing root: {error}");
        assert!(fs::read_dir(&checkpoint_dir).unwrap().next().is_none(), "nothing was downloaded");
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

    use super::{S3RuntimeConfig, S3Secret, object_prefix};

    fn config() -> S3RuntimeConfig {
        S3RuntimeConfig {
            endpoint: "http://127.0.0.1:9000".to_owned(),
            bucket: "bucket".to_owned(),
            region: "auto".to_owned(),
            root_prefix: "typedb".to_owned(),
            cache_bytes: None,
            access_key_id: S3Secret::new("key".to_owned()),
            secret_access_key: S3Secret::new("secret".to_owned()),
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
        // R6-STOR-04: the test keeps its OWN raw handle to observe the
        // provider directly; the principal no longer exposes one.
        let store = Arc::new(NoDeleteStore::new(inner.clone()));
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
            let (inner, occupied) = (inner.clone(), occupied.clone());
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
        let store = Arc::new(NoDeleteStore::new(inner.clone()));
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
            let (from, inner) = (from.clone(), inner.clone());
            async move { inner.head(&from).await }
        });
        assert!(source.is_ok(), "the source must survive a denied rename");
        // ...and NOTHING was written at the destination
        let destination = bridge({
            let (to, inner) = (to.clone(), inner.clone());
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
        let store = Arc::new(NoDeleteStore::new(inner.clone()));
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
            let store = inner.clone();
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

    use super::{AttemptState, MANIFEST_SUBDIR, NoDeleteStore, bridge, content_witness, is_manifest_key};

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
    fn the_ledger_witness_is_a_stable_content_addressed_digest() {
        // R6-STOR-03: the ledger records length + a full SHA-256, and the
        // witness is stable across calls (the property the immutability
        // ledger needs to compare a key's identity over its lifetime).
        assert!(content_witness(b"authoritative bytes").matches(&content_witness(b"authoritative bytes")));
        assert!(!content_witness(b"authoritative bytes").matches(&content_witness(b"authoritative byteS")));
        assert!(!content_witness(b"authoritative bytes").matches(&content_witness(b"authoritative")));
        assert_eq!(content_witness(b"authoritative bytes").len, 19);
        assert_eq!(content_witness(b"authoritative bytes").hex().len(), 64);
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
        // the active attempt and makes the first stale (the mechanism the
        // stale-completion refusal rests on) — while the first attempt's own
        // journal row survives, keeping it addressable for abort.
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
        let active_id = journal.active.get(location.as_ref()).copied().expect("an active attempt is recorded");
        assert_eq!(active_id, 2, "the second attempt is the active one");
        assert_eq!(journal.state_of(active_id), Some(AttemptState::Uncommitted));
        assert_eq!(
            journal.state_of(1),
            Some(AttemptState::Uncommitted),
            "the superseded attempt keeps its own row — individually addressable for abort",
        );
    }

    #[test]
    fn a_quarantined_namespace_refuses_multipart_initiation() {
        // R4-STOR-04: initiation while quarantined is a typed refusal BEFORE
        // the inner store opens a provider upload — for data keys AND the
        // manifest (the manifest has no initiation exemption).
        let (_dir, store) = wrapped_store();
        let key = ObjectPath::from("base/fv1/m1/keyspace/01ABC.sst");
        bridge({
            let (store, key) = (store.clone(), key.clone());
            async move {
                store.put(&key, PutPayload::from_static(b"authoritative")).await.unwrap();
                let _ = store.put(&key, PutPayload::from_static(b"tampered!!!!!")).await;
            }
        });
        assert!(store.is_quarantined(), "fixture: the namespace is quarantined");

        let data_init = bridge({
            let store = store.clone();
            async move { store.put_multipart(&ObjectPath::from("base/fv1/m1/keyspace/05MNO.sst")).await.map(|_| ()) }
        });
        assert!(
            matches!(data_init, Err(slatedb::object_store::Error::Precondition { .. })),
            "a quarantined namespace must refuse multipart initiation, got: {data_init:?}",
        );
        let manifest_init = bridge({
            let store = store.clone();
            let manifest = ObjectPath::from(format!("base/fv1/m1/keyspace/{MANIFEST_SUBDIR}/0009.manifest"));
            async move { store.put_multipart(&manifest).await.map(|_| ()) }
        });
        assert!(
            matches!(manifest_init, Err(slatedb::object_store::Error::Precondition { .. })),
            "the manifest is not exempt from the initiation quarantine gate, got: {manifest_init:?}",
        );
    }

    #[test]
    fn a_multipart_completion_onto_an_existing_immutable_key_is_refused_and_quarantines() {
        // R4-STOR-04 fail-closed completion policy: multipart parts stream to
        // the provider, so byte-identity with the published object cannot be
        // proved at completion — completion onto an EXISTING immutable key is
        // therefore refused + quarantined (the analogue of put_opts's
        // changed-bytes branch), and the refused attempt's provider upload
        // remains abortable.
        let (_dir, store) = wrapped_store();
        let key = ObjectPath::from("base/fv1/m1/keyspace/01ABC.sst");
        let (completion, abort) = bridge({
            let (store, key) = (store.clone(), key.clone());
            async move {
                store.put(&key, PutPayload::from_static(b"authoritative")).await.unwrap();
                let mut upload = store.put_multipart(&key).await.unwrap();
                upload.put_part(PutPayload::from_static(b"replacement bytes")).await.unwrap();
                let completion = upload.complete().await;
                // the refused attempt can still reclaim its own upload
                let abort = upload.abort().await;
                (completion, abort)
            }
        });
        assert!(
            matches!(completion, Err(slatedb::object_store::Error::Precondition { .. })),
            "completing a multipart onto an existing immutable key must be a typed refusal, got: {completion:?}",
        );
        assert!(store.is_quarantined(), "the refused completion must quarantine the materialisation");
        assert!(abort.is_ok(), "the refused attempt must still be able to abort its own upload, got: {abort:?}");
        let bytes = bridge({
            let (store, key) = (store.clone(), key.clone());
            async move { store.get(&key).await.unwrap().bytes().await.unwrap() }
        });
        assert_eq!(&bytes[..], b"authoritative", "the published object's bytes must never change");
    }

    #[test]
    fn when_the_active_attempt_commits_first_the_superseded_attempt_is_refused_but_can_abort() {
        // R4-STOR-04 two-attempts, order B (order A — stale completes first —
        // is a_stale_multipart_completion_is_refused_but_the_active_attempt_completes):
        // the active attempt commits, the superseded attempt's completion is a
        // typed refusal, and its abort still succeeds so its provider upload
        // is reclaimed rather than stranded.
        let (_dir, store) = wrapped_store();
        let location = ObjectPath::from("base/fv1/m1/keyspace/06PQR.sst");
        let (active_completion, stale_completion, stale_abort) = bridge({
            let (store, location) = (store.clone(), location.clone());
            async move {
                let mut superseded = store.put_multipart(&location).await.unwrap();
                let mut active = store.put_multipart(&location).await.unwrap();
                superseded.put_part(PutPayload::from_static(b"superseded part")).await.unwrap();
                active.put_part(PutPayload::from_static(b"active part")).await.unwrap();
                let active_completion = active.complete().await;
                let stale_completion = superseded.complete().await;
                let stale_abort = superseded.abort().await;
                (active_completion, stale_completion, stale_abort)
            }
        });
        assert!(active_completion.is_ok(), "exactly one attempt commits — the active one: {active_completion:?}");
        assert!(
            matches!(stale_completion, Err(slatedb::object_store::Error::Precondition { .. })),
            "the superseded attempt's completion must be a typed refusal, got: {stale_completion:?}",
        );
        assert!(
            stale_abort.is_ok(),
            "a superseded-but-uncommitted attempt must be able to abort its own upload, got: {stale_abort:?}",
        );
        assert!(!store.is_quarantined(), "a refused stale completion is a gate refusal, not tamper evidence");
        let bytes = bridge({
            let (store, location) = (store.clone(), location.clone());
            async move { store.get(&location).await.unwrap().bytes().await.unwrap() }
        });
        assert_eq!(&bytes[..], b"active part", "the committed attempt's bytes are what is published");
    }

    #[test]
    fn a_completion_after_the_namespace_is_quarantined_is_refused_and_the_upload_is_reclaimed() {
        // R4-STOR-04: quarantine is revalidated at completion time. An attempt
        // initiated BEFORE the quarantine must not complete after it — the
        // completion is refused and the provider upload aborted.
        let (_dir, store) = wrapped_store();
        let location = ObjectPath::from("base/fv1/m1/keyspace/07STU.sst");
        let other = ObjectPath::from("base/fv1/m1/keyspace/01ABC.sst");
        let (completion, second_abort) = bridge({
            let (store, location, other) = (store.clone(), location.clone(), other.clone());
            async move {
                let mut upload = store.put_multipart(&location).await.unwrap();
                upload.put_part(PutPayload::from_static(b"pending part")).await.unwrap();
                // the quarantine lands AFTER this attempt was initiated
                store.put(&other, PutPayload::from_static(b"authoritative")).await.unwrap();
                let _ = store.put(&other, PutPayload::from_static(b"tampered!!!!!")).await;
                let completion = upload.complete().await;
                // the completion already aborted the upload: a second abort is
                // the "was aborted" refusal — proof the reclamation happened
                let second_abort = upload.abort().await;
                (completion, second_abort)
            }
        });
        assert!(store.is_quarantined());
        assert!(
            matches!(completion, Err(slatedb::object_store::Error::Precondition { .. })),
            "completion after quarantine must be a typed refusal, got: {completion:?}",
        );
        assert!(
            matches!(second_abort, Err(slatedb::object_store::Error::Precondition { .. })),
            "the refused completion must already have aborted the upload, got: {second_abort:?}",
        );
        // nothing was published at the pending location
        let head = bridge({
            let (store, location) = (store.clone(), location.clone());
            async move { store.head(&location).await }
        });
        assert!(
            matches!(head, Err(slatedb::object_store::Error::NotFound { .. })),
            "the refused completion must not have published an object, got: {head:?}",
        );
    }

    #[test]
    fn a_restart_between_publication_and_a_replayed_completion_cannot_overwrite() {
        // R4-STOR-04 restart / response-loss: incarnation ONE publishes a key
        // via multipart; incarnation TWO (a fresh wrapper over the same inner
        // store — the process-local journal is gone) replays initiation and
        // completion of the same key. The journal cannot help here; the
        // create-only completion check against the STORE is what refuses.
        let dir = create_tmp_dir("slate-s04-restart");
        let inner: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix(&*dir).unwrap());
        let key = ObjectPath::from("base/fv1/m1/keyspace/08VWX.sst");

        let first = Arc::new(NoDeleteStore::new(inner.clone()));
        bridge({
            let (first, key) = (first.clone(), key.clone());
            async move {
                let mut upload = first.put_multipart(&key).await.unwrap();
                upload.put_part(PutPayload::from_static(b"published bytes")).await.unwrap();
                upload.complete().await.unwrap();
            }
        });

        let second = Arc::new(NoDeleteStore::new(inner)); // the "restarted" incarnation
        let replayed = bridge({
            let (second, key) = (second.clone(), key.clone());
            async move {
                let mut upload = second.put_multipart(&key).await.unwrap();
                upload.put_part(PutPayload::from_static(b"replayed bytes")).await.unwrap();
                upload.complete().await
            }
        });
        assert!(
            matches!(replayed, Err(slatedb::object_store::Error::Precondition { .. })),
            "a replayed completion after restart must be refused by the store-level check, got: {replayed:?}",
        );
        assert!(second.is_quarantined(), "the replayed overwrite attempt quarantines the new incarnation");
        let bytes = bridge({
            let (second, key) = (second.clone(), key.clone());
            async move { second.get(&key).await.unwrap().bytes().await.unwrap() }
        });
        assert_eq!(&bytes[..], b"published bytes", "the originally published bytes survive");
    }

    #[test]
    fn a_manifest_multipart_completion_cannot_silently_overwrite_the_manifest() {
        // R4-STOR-04: manifest republication is legitimate ONLY through the
        // conditional single-put CAS path; the multipart API carries no
        // precondition, so completion onto an existing manifest key is a typed
        // refusal (no silent overwrite) — but NOT a quarantine event, because
        // an existing manifest is the normal published state, not tamper
        // evidence. Completion onto an ABSENT manifest key still succeeds.
        let (_dir, store) = wrapped_store();
        let manifest = ObjectPath::from(format!("base/fv1/m1/keyspace/{MANIFEST_SUBDIR}/0001.manifest"));
        let (overwrite, fresh) = bridge({
            let (store, manifest) = (store.clone(), manifest.clone());
            async move {
                store.put(&manifest, PutPayload::from_static(b"manifest v1")).await.unwrap();
                let mut onto_existing = store.put_multipart(&manifest).await.unwrap();
                onto_existing.put_part(PutPayload::from_static(b"manifest v2 via multipart")).await.unwrap();
                let overwrite = onto_existing.complete().await;
                let fresh_key =
                    ObjectPath::from(format!("base/fv1/m1/keyspace/{MANIFEST_SUBDIR}/0002.manifest"));
                let mut onto_absent = store.put_multipart(&fresh_key).await.unwrap();
                onto_absent.put_part(PutPayload::from_static(b"manifest v2")).await.unwrap();
                let fresh = onto_absent.complete().await;
                (overwrite, fresh)
            }
        });
        assert!(
            matches!(overwrite, Err(slatedb::object_store::Error::Precondition { .. })),
            "a multipart completion onto an existing manifest key must be refused, got: {overwrite:?}",
        );
        assert!(!store.is_quarantined(), "an existing manifest is not tamper evidence — no quarantine");
        assert!(fresh.is_ok(), "a multipart completion onto an absent manifest key creates, got: {fresh:?}");
        let bytes = bridge({
            let (store, manifest) = (store.clone(), manifest.clone());
            async move { store.get(&manifest).await.unwrap().bytes().await.unwrap() }
        });
        assert_eq!(&bytes[..], b"manifest v1", "the published manifest bytes are untouched");
    }
}

#[cfg(test)]
mod multipart_promote_tests {
    //! R5-STOR-05 controls: multipart completion is provider-ATOMIC
    //! create-only. Each attempt stages to its own globally unique key and
    //! publishes through a create-only conditional copy (falling back to a
    //! create-only single PUT of the verified bytes where conditional copy is
    //! unsupported). Two INDEPENDENT completer instances — separate journals,
    //! simulating two processes — synchronized after both have fully staged
    //! ("passed their prechecks"), completing DIFFERENT bytes, produce
    //! exactly one winner and no changed-byte overwrite; a replay of the SAME
    //! bytes after a lost response converges idempotently.

    use std::sync::{Arc, Barrier};

    use async_trait::async_trait;
    use futures::stream::BoxStream;
    use slatedb::object_store::{
        CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore, ObjectStoreExt,
        PutMultipartOptions, PutOptions, PutPayload, PutResult, local::LocalFileSystem, path::Path as ObjectPath,
    };
    use test_utils::create_tmp_dir;

    use super::{NoDeleteStore, bridge, list_remote_prefix};

    fn raw_local_store() -> (test_utils::TempDir, Arc<dyn ObjectStore>) {
        let dir = create_tmp_dir("slate-r5-promote");
        let inner: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix(&*dir).unwrap());
        (dir, inner)
    }

    /// Open a multipart attempt on `store` and stage `bytes` into it — the
    /// full "precheck + upload" phase, everything short of completion.
    fn staged_upload(
        store: &Arc<NoDeleteStore>,
        target: &ObjectPath,
        bytes: &'static [u8],
    ) -> Box<dyn MultipartUpload> {
        bridge({
            let (store, target) = (store.clone(), target.clone());
            async move {
                let mut upload = store.put_multipart(&target).await.unwrap();
                upload.put_part(PutPayload::from_static(bytes)).await.unwrap();
                upload
            }
        })
    }

    fn read_target(inner: &Arc<dyn ObjectStore>, target: &ObjectPath) -> Vec<u8> {
        bridge({
            let (inner, target) = (inner.clone(), target.clone());
            async move { inner.get(&target).await.unwrap().bytes().await.unwrap().to_vec() }
        })
    }

    fn objects_under(inner: &Arc<dyn ObjectStore>, prefix: &str) -> Vec<String> {
        bridge({
            let (inner, prefix) = (inner.clone(), ObjectPath::from(prefix));
            async move {
                list_remote_prefix(inner.as_ref(), &prefix)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|meta| meta.location.to_string())
                    .collect()
            }
        })
    }

    #[test]
    fn two_independent_completers_publish_exactly_one_winner_and_no_changed_bytes() {
        // R5-STOR-05 flagship mutant: two completer instances with SEPARATE
        // journals (two "processes") over one store, both fully staged with
        // DIFFERENT bytes, complete concurrently from a barrier. The old
        // HEAD-then-complete TOCTOU let both pass the absence check and the
        // last writer win; the atomic create-only promote admits exactly ONE
        // winner, types the loser, and never replaces published bytes.
        let (_dir, inner) = raw_local_store();
        let store_a = Arc::new(NoDeleteStore::new(inner.clone()));
        let store_b = Arc::new(NoDeleteStore::new(inner.clone()));
        let target = ObjectPath::from("base/fv1/m1/keyspace/10AAA.sst");

        let upload_a = staged_upload(&store_a, &target, b"completer-a bytes");
        let upload_b = staged_upload(&store_b, &target, b"completer-b bytes");

        // both prechecks (journal admission, staging upload) have passed;
        // synchronize the decisive completions
        let barrier = Arc::new(Barrier::new(2));
        let race = |mut upload: Box<dyn MultipartUpload>, barrier: Arc<Barrier>| {
            std::thread::spawn(move || {
                barrier.wait();
                bridge(async move { upload.complete().await })
            })
        };
        let result_a = race(upload_a, barrier.clone());
        let result_b = race(upload_b, barrier);
        let result_a = result_a.join().unwrap();
        let result_b = result_b.join().unwrap();

        let winners = [result_a.is_ok(), result_b.is_ok()].iter().filter(|ok| **ok).count();
        assert_eq!(winners, 1, "exactly one completer may win: a={result_a:?}, b={result_b:?}");
        let (loser_result, winner_bytes, loser_store) = if result_a.is_ok() {
            (result_b, b"completer-a bytes".as_slice(), &store_b)
        } else {
            (result_a, b"completer-b bytes".as_slice(), &store_a)
        };
        assert!(
            matches!(loser_result, Err(slatedb::object_store::Error::Precondition { .. })),
            "the loser must be a typed refusal, got: {loser_result:?}",
        );
        assert_eq!(read_target(&inner, &target), winner_bytes, "the published bytes are the winner's, never replaced");
        assert!(loser_store.is_quarantined(), "a changed-byte loser quarantines its own materialisation");
        // both staging objects are cleaned: only the published target remains
        let remaining = objects_under(&inner, "base");
        assert_eq!(remaining, vec![target.to_string()], "staging objects must be cleaned: {remaining:?}");
    }

    #[test]
    fn a_timeout_after_promote_replay_converges_idempotently() {
        // R5-STOR-05: incarnation ONE promotes bytes X and the response is
        // lost; incarnation TWO (fresh wrapper, fresh journal — the restart)
        // replays the same upload with the SAME bytes. The replay settles
        // idempotently on the published object: success, no quarantine, no
        // second object, bytes untouched.
        let (_dir, inner) = raw_local_store();
        let target = ObjectPath::from("base/fv1/m1/keyspace/11BBB.sst");

        let first = Arc::new(NoDeleteStore::new(inner.clone()));
        let mut upload = staged_upload(&first, &target, b"published bytes");
        bridge(async move { upload.complete().await }).expect("the first completion publishes");

        let second = Arc::new(NoDeleteStore::new(inner.clone()));
        let mut replay = staged_upload(&second, &target, b"published bytes");
        let converged = bridge(async move { replay.complete().await });
        assert!(converged.is_ok(), "a same-bytes replay after restart must converge, got: {converged:?}");
        assert!(!second.is_quarantined(), "idempotent convergence is not tamper evidence");
        assert_eq!(read_target(&inner, &target), b"published bytes");
        assert_eq!(objects_under(&inner, "base"), vec![target.to_string()], "no staging object survives");
    }

    /// A store shim whose conditional copy is unsupported (the plain-S3
    /// posture without a copy-if-not-exists configuration): forces the
    /// promote onto its documented fallback — a create-only single PUT of the
    /// verified staged bytes.
    #[derive(Debug)]
    struct NoConditionalCopyStore {
        inner: Arc<dyn ObjectStore>,
    }

    impl std::fmt::Display for NoConditionalCopyStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "NoConditionalCopyStore({})", self.inner)
        }
    }

    #[async_trait]
    impl ObjectStore for NoConditionalCopyStore {
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

        async fn get_opts(
            &self,
            location: &ObjectPath,
            options: GetOptions,
        ) -> slatedb::object_store::Result<GetResult> {
            self.inner.get_opts(location, options).await
        }

        fn delete_stream(
            &self,
            locations: BoxStream<'static, slatedb::object_store::Result<ObjectPath>>,
        ) -> BoxStream<'static, slatedb::object_store::Result<ObjectPath>> {
            self.inner.delete_stream(locations)
        }

        fn list(&self, prefix: Option<&ObjectPath>) -> BoxStream<'static, slatedb::object_store::Result<ObjectMeta>> {
            self.inner.list(prefix)
        }

        async fn list_with_delimiter(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> slatedb::object_store::Result<ListResult> {
            self.inner.list_with_delimiter(prefix).await
        }

        async fn copy_opts(
            &self,
            _from: &ObjectPath,
            _to: &ObjectPath,
            _options: CopyOptions,
        ) -> slatedb::object_store::Result<()> {
            Err(slatedb::object_store::Error::NotSupported {
                source: "this store does not support conditional copy".to_string().into(),
            })
        }
    }

    #[test]
    fn promote_falls_back_to_a_create_only_put_when_conditional_copy_is_unsupported() {
        // R5-STOR-05: on a store without conditional copy the promote pays
        // its documented byte cost (one create-only re-upload of the verified
        // staged bytes) but keeps the create-only guarantee: a fresh target
        // publishes; a second, different-bytes completer is a typed refusal
        // with the published bytes untouched.
        let dir = create_tmp_dir("slate-r5-promote-fallback");
        let local: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix(&*dir).unwrap());
        let shim: Arc<dyn ObjectStore> = Arc::new(NoConditionalCopyStore { inner: local.clone() });
        let target = ObjectPath::from("base/fv1/m1/keyspace/12CCC.sst");

        let first = Arc::new(NoDeleteStore::new(shim.clone()));
        let mut upload = staged_upload(&first, &target, b"fallback bytes");
        let published = bridge(async move { upload.complete().await });
        assert!(published.is_ok(), "the fallback promote must publish a fresh target, got: {published:?}");
        assert_eq!(read_target(&local, &target), b"fallback bytes");

        let second = Arc::new(NoDeleteStore::new(shim));
        let mut contender = staged_upload(&second, &target, b"different bytes!");
        let refused = bridge(async move { contender.complete().await });
        assert!(
            matches!(refused, Err(slatedb::object_store::Error::Precondition { .. })),
            "the fallback path must stay create-only, got: {refused:?}",
        );
        assert_eq!(read_target(&local, &target), b"fallback bytes", "the published bytes are untouched");
        assert_eq!(objects_under(&local, "base"), vec![target.to_string()], "staging cleaned on both paths");
    }
}

#[cfg(test)]
mod multipart_journal_budget_tests {
    //! R5-STOR-08 controls: the multipart journal retires terminal rows into
    //! a bounded receipt window and enforces hard admission budgets — max
    //! concurrent attempts (reserved at initiation) and max journaled bytes
    //! (reserved as parts stream) — released only on proven abort/commit.
    //! Exceeding a budget is a typed refusal, never growth; repeated
    //! disconnect/abandon cycles therefore reach typed admission instead of
    //! unbounded memory.

    use std::sync::Arc;

    use slatedb::object_store::{
        MultipartUpload, ObjectStore, ObjectStoreExt, PutPayload, local::LocalFileSystem, path::Path as ObjectPath,
    };
    use test_utils::create_tmp_dir;

    use super::{
        AttemptState, MULTIPART_MAX_JOURNALED_BYTES, MULTIPART_MAX_OPEN_ATTEMPTS, MULTIPART_TERMINAL_RECEIPTS,
        MultipartBudgetRefused, NoDeleteStore, admit_multipart_attempt, admit_multipart_bytes, bridge,
    };

    fn wrapped_store() -> (test_utils::TempDir, Arc<NoDeleteStore>) {
        let dir = create_tmp_dir("slate-r5-journal");
        let inner: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix(&*dir).unwrap());
        (dir, Arc::new(NoDeleteStore::new(inner)))
    }

    #[test]
    fn multipart_budget_arithmetic_is_exact_at_the_boundary() {
        // attempts: strictly-below admits, AT the budget refuses
        assert_eq!(admit_multipart_attempt(0, 3), Ok(()));
        assert_eq!(admit_multipart_attempt(2, 3), Ok(()));
        assert_eq!(admit_multipart_attempt(3, 3), Err(MultipartBudgetRefused::Attempts { open: 3, max: 3 }));
        assert_eq!(admit_multipart_attempt(4, 3), Err(MultipartBudgetRefused::Attempts { open: 4, max: 3 }));
        // bytes: exactly AT the budget admits, one byte over refuses,
        // overflow refuses (never wraps into admission)
        assert_eq!(admit_multipart_bytes(0, 10, 10), Ok(()));
        assert_eq!(admit_multipart_bytes(6, 4, 10), Ok(()));
        assert_eq!(
            admit_multipart_bytes(7, 4, 10),
            Err(MultipartBudgetRefused::Bytes { reserved: 7, incoming: 4, max: 10 })
        );
        assert_eq!(
            admit_multipart_bytes(u64::MAX, 1, u64::MAX),
            Err(MultipartBudgetRefused::Bytes { reserved: u64::MAX, incoming: 1, max: u64::MAX })
        );
        // and the production budgets are real, positive bounds
        assert!(MULTIPART_MAX_OPEN_ATTEMPTS > 0);
        assert!(MULTIPART_MAX_JOURNALED_BYTES > 0);
        assert!(MULTIPART_TERMINAL_RECEIPTS > 0);
    }

    #[test]
    fn abandoned_attempts_reach_a_typed_admission_refusal_not_unbounded_growth() {
        // R5-STOR-08 mutant: attempts that disconnect without abort/commit
        // hold their reservation; once the budget is full, the NEXT
        // initiation is a typed refusal BEFORE any journal row or provider
        // upload is created — the journal cannot grow past its budget.
        let (_dir, store) = wrapped_store();
        store.set_multipart_budgets_for_test(3, 1_000_000, 8);
        let mut abandoned = Vec::new();
        for index in 0..3 {
            let upload = bridge({
                let store = store.clone();
                let location = ObjectPath::from(format!("base/fv1/m1/keyspace/2{index}ABC.sst"));
                async move { store.put_multipart(&location).await }
            })
            .expect("attempts below the budget are admitted");
            abandoned.push(upload); // never completed, never aborted
        }
        let refused = bridge({
            let store = store.clone();
            async move { store.put_multipart(&ObjectPath::from("base/fv1/m1/keyspace/29XYZ.sst")).await.map(|_| ()) }
        });
        let error = refused.expect_err("the attempt over the budget must be refused");
        assert!(
            matches!(&error, slatedb::object_store::Error::Precondition { .. }),
            "budget exhaustion is a typed refusal, got: {error:?}",
        );
        assert!(error.to_string().contains("admission refused"), "the refusal names the budget: {error}");
        {
            let journal = store.multipart_journal.lock().unwrap();
            assert_eq!(journal.open_attempts.len(), 3, "the refused attempt must not have grown the journal");
        }
        // an abandoned attempt that finally aborts releases its slot
        bridge(async move { abandoned.pop().unwrap().abort().await }).unwrap();
        let admitted = bridge({
            let store = store.clone();
            async move { store.put_multipart(&ObjectPath::from("base/fv1/m1/keyspace/29XYZ.sst")).await.map(|_| ()) }
        });
        assert!(admitted.is_ok(), "a proven abort must release the reservation, got: {admitted:?}");
    }

    #[test]
    fn terminal_attempts_are_retired_to_a_bounded_receipt_window_and_budgets_release() {
        // R5-STOR-08: repeated disconnect/abort cycles never accumulate rows.
        // Terminal rows retire into a bounded receipt window (last N), byte
        // and attempt reservations release on proven abort/commit, and the
        // active-location map empties with them.
        let (_dir, store) = wrapped_store();
        store.set_multipart_budgets_for_test(4, 1_000_000, 2);
        for cycle in 0..5u32 {
            let location = ObjectPath::from(format!("base/fv1/m1/keyspace/3{cycle}DEF.sst"));
            bridge({
                let (store, location) = (store.clone(), location.clone());
                async move {
                    let mut upload = store.put_multipart(&location).await.unwrap();
                    upload.put_part(PutPayload::from_static(b"cycle bytes")).await.unwrap();
                    upload.abort().await.unwrap();
                }
            });
        }
        // one full commit cycle retires the same way
        bridge({
            let store = store.clone();
            async move {
                let location = ObjectPath::from("base/fv1/m1/keyspace/39GHI.sst");
                let mut upload = store.put_multipart(&location).await.unwrap();
                upload.put_part(PutPayload::from_static(b"committed bytes")).await.unwrap();
                upload.complete().await.unwrap();
            }
        });
        let journal = store.multipart_journal.lock().unwrap();
        assert!(journal.open_attempts.is_empty(), "terminal attempts must be retired: {:?}", journal.open_attempts);
        assert_eq!(journal.reserved_bytes, 0, "every reservation must be released on proven abort/commit");
        assert!(journal.active.is_empty(), "retired attempts must release their active-location rows");
        assert!(
            journal.terminal.len() <= 2,
            "terminal receipts must be bounded to the retention window: {:?}",
            journal.terminal
        );
        // the newest receipt is the committed attempt — still addressable for
        // idempotency inside the window
        let (_, newest_state) = journal.terminal.back().expect("the newest receipt is retained");
        assert_eq!(*newest_state, AttemptState::Committed);
    }

    #[test]
    fn the_byte_budget_is_reserved_while_streaming_and_released_on_abort() {
        // R5-STOR-08: journaled bytes are reserved as parts stream — a part
        // that would exceed the budget is a typed refusal that reserves and
        // streams nothing — and a proven abort releases the reservation
        // exactly.
        let (_dir, store) = wrapped_store();
        store.set_multipart_budgets_for_test(4, 10, 8);
        let location = ObjectPath::from("base/fv1/m1/keyspace/40JKL.sst");
        let mut upload = bridge({
            let (store, location) = (store.clone(), location.clone());
            async move { store.put_multipart(&location).await }
        })
        .unwrap();
        bridge(async move {
            upload.put_part(PutPayload::from_static(b"12345678")).await.expect("8 bytes fit the 10-byte budget");
            let refused = upload.put_part(PutPayload::from_static(b"wxyz")).await;
            assert!(
                matches!(&refused, Err(slatedb::object_store::Error::Precondition { .. })),
                "the part over the byte budget must be a typed refusal, got: {refused:?}",
            );
            upload.abort().await.expect("abort releases the reservation");
        });
        {
            let journal = store.multipart_journal.lock().unwrap();
            assert_eq!(journal.reserved_bytes, 0, "abort must release the exact reservation");
        }
        // released budget admits the next attempt's parts again
        let location2 = ObjectPath::from("base/fv1/m1/keyspace/41MNO.sst");
        let mut upload2 = bridge({
            let (store, location2) = (store.clone(), location2.clone());
            async move { store.put_multipart(&location2).await }
        })
        .unwrap();
        bridge(async move {
            upload2.put_part(PutPayload::from_static(b"12345678")).await.expect("the released budget re-admits");
            upload2.abort().await.unwrap();
        });
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

#[cfg(test)]
mod r6_multipart_integrity_tests {
    //! R6-STOR-02, R6-STOR-03 and R6-STOR-04.
    //!
    //! - **R6-STOR-02**: admission is `O(chunk x concurrency)`, not
    //!   `O(object size)`. Proven by instrumentation — an observing store that
    //!   records every ranged read plus a per-materialisation buffer meter —
    //!   rather than by allocating a giant object.
    //! - **R6-STOR-03**: the promotion predicate is a domain-separated
    //!   SHA-256, not a 64-bit checksum. A test-only weak checksum admits a
    //!   constructed collision; the production digest kills it, and every
    //!   staged-byte mutation (equal-length flip, reorder, duplicate, drop,
    //!   post-completion alteration) is refused before anything is published.
    //! - **R6-STOR-04**: authority is separated by TYPE. The authoritative
    //!   handle has no delete/rename/overwrite verb to call, the staging
    //!   handle can only address the staging namespace, and a failed staging
    //!   reclaim produces a durable orphan record instead of a swallowed
    //!   error.

    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::Duration,
    };

    use futures::stream::BoxStream;
    use slatedb::{
        bytes::Bytes,
        object_store::{
            CopyMode, CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
            ObjectStoreExt, PutMode, PutMultipartOptions, PutOptions, PutPayload, PutResult, UploadPart,
            local::LocalFileSystem, path::Path as ObjectPath,
        },
    };
    use test_utils::create_tmp_dir;

    use super::{
        CompletionPermit, MULTIPART_ATTEMPT_INFIX, MULTIPART_MAX_CONCURRENT_COMPLETIONS,
        MULTIPART_MAX_MATERIALISED_PROMOTE_BYTES, MULTIPART_MAX_OBJECT_BYTES, MULTIPART_ORPHAN_FILE,
        MultipartBudgetRefused, NoDeleteStore, StagingKey, admit_object_bytes, authority, bridge, content_witness,
    };

    // ------------------------------------------------------------------
    // an observing / fault-injecting provider
    // ------------------------------------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Tamper {
        None,
        /// same length, one byte different
        FlipByte,
        /// same length, same byte multiset, different order
        SwapParts,
        /// a part repeated
        DuplicatePart,
        /// a part missing
        DropPart,
    }

    /// A provider that records exactly what the layer above asks it for, and
    /// can inject the faults the audit's mutants name.
    #[derive(Debug)]
    struct ProbeStore {
        inner: Arc<dyn ObjectStore>,
        tamper: Mutex<Tamper>,
        deny_reclaim: AtomicBool,
        deny_conditional_copy: AtomicBool,
        /// The largest single range this store was ever asked for. The
        /// R6-STOR-02 bound is that this does not grow with object size.
        max_range_bytes: AtomicU64,
        /// How many WHOLE-object reads were requested. The bound requires
        /// zero of these on the completion paths.
        unbounded_gets: AtomicU64,
    }

    impl ProbeStore {
        fn new(inner: Arc<dyn ObjectStore>) -> Arc<Self> {
            Arc::new(Self {
                inner,
                tamper: Mutex::new(Tamper::None),
                deny_reclaim: AtomicBool::new(false),
                deny_conditional_copy: AtomicBool::new(false),
                max_range_bytes: AtomicU64::new(0),
                unbounded_gets: AtomicU64::new(0),
            })
        }

        fn set_tamper(&self, tamper: Tamper) {
            *self.tamper.lock().unwrap() = tamper;
        }

        fn reset_observations(&self) {
            self.max_range_bytes.store(0, Ordering::SeqCst);
            self.unbounded_gets.store(0, Ordering::SeqCst);
        }
    }

    impl std::fmt::Display for ProbeStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "ProbeStore")
        }
    }

    #[async_trait::async_trait]
    impl ObjectStore for ProbeStore {
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
            let inner = self.inner.put_multipart_opts(location, opts).await?;
            Ok(Box::new(TamperUpload {
                inner,
                store: self.inner.clone(),
                location: location.clone(),
                parts: Vec::new(),
                tamper: *self.tamper.lock().unwrap(),
            }))
        }

        async fn get_opts(
            &self,
            location: &ObjectPath,
            options: GetOptions,
        ) -> slatedb::object_store::Result<GetResult> {
            match &options.range {
                Some(slatedb::object_store::GetRange::Bounded(range)) => {
                    self.max_range_bytes.fetch_max(range.end - range.start, Ordering::SeqCst);
                }
                Some(_) => {
                    self.unbounded_gets.fetch_add(1, Ordering::SeqCst);
                }
                None if !options.head => {
                    self.unbounded_gets.fetch_add(1, Ordering::SeqCst);
                }
                None => {}
            }
            self.inner.get_opts(location, options).await
        }

        fn list(&self, prefix: Option<&ObjectPath>) -> BoxStream<'static, slatedb::object_store::Result<ObjectMeta>> {
            self.inner.list(prefix)
        }

        async fn list_with_delimiter(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> slatedb::object_store::Result<ListResult> {
            self.inner.list_with_delimiter(prefix).await
        }

        async fn copy_opts(
            &self,
            from: &ObjectPath,
            to: &ObjectPath,
            options: CopyOptions,
        ) -> slatedb::object_store::Result<()> {
            if self.deny_conditional_copy.load(Ordering::SeqCst) && matches!(options.mode, CopyMode::Create) {
                return Err(slatedb::object_store::Error::NotSupported {
                    source: "this provider has no copy-if-not-exists (the plain-S3 posture)".into(),
                });
            }
            self.inner.copy_opts(from, to, options).await
        }

        fn delete_stream(
            &self,
            locations: BoxStream<'static, slatedb::object_store::Result<ObjectPath>>,
        ) -> BoxStream<'static, slatedb::object_store::Result<ObjectPath>> {
            use futures::StreamExt;
            if self.deny_reclaim.load(Ordering::SeqCst) {
                return locations
                    .map(|location| {
                        location.and_then(|location| {
                            Err(slatedb::object_store::Error::Generic {
                                store: "ProbeStore",
                                source: format!("injected reclaim failure for {location}").into(),
                            })
                        })
                    })
                    .boxed();
            }
            self.inner.delete_stream(locations)
        }
    }

    /// Alters the staged object AFTER the provider upload completes and BEFORE
    /// the promote — the exact window the audit's "alter bytes after provider
    /// completion but before promotion" mutant names.
    #[derive(Debug)]
    struct TamperUpload {
        inner: Box<dyn MultipartUpload>,
        store: Arc<dyn ObjectStore>,
        location: ObjectPath,
        parts: Vec<Bytes>,
        tamper: Tamper,
    }

    #[async_trait::async_trait]
    impl MultipartUpload for TamperUpload {
        fn put_part(&mut self, data: PutPayload) -> UploadPart {
            for chunk in &data {
                self.parts.push(chunk.clone());
            }
            self.inner.put_part(data)
        }

        async fn complete(&mut self) -> slatedb::object_store::Result<PutResult> {
            let result = self.inner.complete().await?;
            if self.tamper == Tamper::None {
                return Ok(result);
            }
            let mut parts = self.parts.clone();
            match self.tamper {
                Tamper::None => unreachable!(),
                Tamper::FlipByte => {
                    let mut bytes = parts[0].to_vec();
                    bytes[0] ^= 0xff;
                    parts[0] = Bytes::from(bytes);
                }
                Tamper::SwapParts => parts.swap(0, 1),
                Tamper::DuplicatePart => {
                    let first = parts[0].clone();
                    parts.push(first);
                }
                Tamper::DropPart => {
                    parts.pop();
                }
            }
            let payload: PutPayload = parts.into_iter().collect();
            self.store.put_opts(&self.location, payload, PutOptions::default()).await?;
            Ok(result)
        }

        async fn abort(&mut self) -> slatedb::object_store::Result<()> {
            self.inner.abort().await
        }
    }

    fn fixture() -> (test_utils::TempDir, Arc<ProbeStore>, Arc<NoDeleteStore>) {
        let dir = create_tmp_dir("slate-r6-probe");
        let raw: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix(&*dir).unwrap());
        let probe = ProbeStore::new(raw);
        let principal = NoDeleteStore::new(probe.clone() as Arc<dyn ObjectStore>);
        principal.bind_orphan_sink(&dir);
        (dir, probe, Arc::new(principal))
    }

    /// Stream `parts` through a multipart upload on `location`.
    fn upload(store: &Arc<NoDeleteStore>, location: &ObjectPath, parts: Vec<Vec<u8>>) -> slatedb::object_store::Result<PutResult> {
        let store = store.clone();
        let location = location.clone();
        bridge(async move {
            let mut upload = store.put_multipart(&location).await?;
            for part in parts {
                upload.put_part(PutPayload::from(part)).await?;
            }
            upload.complete().await
        })
    }

    fn read(store: &Arc<NoDeleteStore>, location: &ObjectPath) -> Option<Vec<u8>> {
        let store = store.clone();
        let location = location.clone();
        bridge(async move {
            match store.get(&location).await {
                Ok(result) => Some(result.bytes().await.unwrap().to_vec()),
                Err(_) => None,
            }
        })
    }

    // ------------------------------------------------------------------
    // R6-STOR-03 — the digest is a cryptographic authority
    // ------------------------------------------------------------------

    /// The MUTANT of the removed production predicate: a cheap,
    /// order-insensitive 64-bit checksum, exactly the class of hash the audit
    /// rules out as a promotion authority.
    fn weak_checksum_for_test(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0u64, |accumulator, byte| accumulator.wrapping_add(*byte as u64))
    }

    #[test]
    fn a_weak_checksum_admits_a_collision_the_production_digest_kills() {
        // R6-STOR-03 mutant: a test-only weak-hash path accepts two DIFFERENT
        // byte strings of EQUAL length. Length + weak checksum — the shape of
        // the removed `length && DefaultHasher` predicate — cannot tell them
        // apart; the domain-separated SHA-256 does, which is what makes it
        // safe to decide a promotion with.
        let left = b"AB".as_slice();
        let right = b"BA".as_slice();
        assert_eq!(left.len(), right.len(), "the collision is equal-length");
        assert_ne!(left, right, "the collision is over DIFFERENT bytes");
        assert_eq!(
            weak_checksum_for_test(left),
            weak_checksum_for_test(right),
            "the weak-hash mutant must ADMIT this constructed collision",
        );
        assert!(
            !content_witness(left).matches(&content_witness(right)),
            "the production digest must KILL the collision the weak hash admits",
        );

        // and the framing is domain-separated: the same bytes under a bare
        // SHA-256 are not the witness digest, so a digest computed for some
        // other purpose can never be replayed as a content witness.
        assert_ne!(
            content_witness(left).digest,
            crate::recovery::sha256::digest(left),
            "the content witness must be domain-separated from a bare digest",
        );
        // the length is bound INTO the digest, so no shorter prefix can forge
        // a longer object's witness
        assert_ne!(content_witness(b"AB").digest, content_witness(b"AB\x00").digest);
    }

    #[test]
    fn the_witness_comparison_is_exact_on_length_and_digest() {
        let witness = content_witness(b"authoritative");
        assert!(witness.matches(&witness));
        assert!(!witness.matches(&content_witness(b"authoritativd")));
        assert!(!witness.matches(&content_witness(b"authoritative ")));
        assert_eq!(witness.len, 13);
    }

    fn tampered_staging_is_refused(tamper: Tamper, label: &str) {
        let (_dir, probe, store) = fixture();
        let location = ObjectPath::from("base/fv1/m1/keyspace/01TAMPER.sst");
        probe.set_tamper(tamper);
        let outcome = upload(&store, &location, vec![b"first-part-".to_vec(), b"second-part".to_vec()]);
        let error = outcome.expect_err(&format!("{label} must be refused"));
        assert!(
            matches!(error, slatedb::object_store::Error::Precondition { .. }),
            "{label} must be a typed refusal, got {error:?}",
        );
        assert!(error.to_string().contains("R6-STOR-03"), "{label} must cite the digest predicate: {error}");
        assert!(read(&store, &location).is_none(), "{label} must publish NOTHING at the target");
    }

    #[test]
    fn staged_bytes_mutated_without_changing_length_are_refused() {
        // MUTANT: alter the staged object after provider completion, before
        // promotion, keeping the length identical.
        tampered_staging_is_refused(Tamper::FlipByte, "an equal-length byte flip");
    }

    #[test]
    fn reordered_staged_chunks_are_refused() {
        // MUTANT: same length AND same byte multiset — a commutative or
        // additive checksum would accept this; SHA-256 does not.
        tampered_staging_is_refused(Tamper::SwapParts, "a chunk reorder");
    }

    #[test]
    fn duplicated_staged_chunks_are_refused() {
        tampered_staging_is_refused(Tamper::DuplicatePart, "a duplicated chunk");
    }

    #[test]
    fn dropped_staged_chunks_are_refused() {
        tampered_staging_is_refused(Tamper::DropPart, "a dropped chunk");
    }

    #[test]
    fn an_untampered_upload_still_publishes() {
        // positive control: the refusals above are not "refuse everything".
        let (_dir, _probe, store) = fixture();
        let location = ObjectPath::from("base/fv1/m1/keyspace/01CLEAN.sst");
        upload(&store, &location, vec![b"first-part-".to_vec(), b"second-part".to_vec()])
            .expect("a clean upload publishes");
        assert_eq!(read(&store, &location).unwrap(), b"first-part-second-part");
    }

    #[test]
    fn the_ledger_witness_stores_full_digest_bytes() {
        // R6-STOR-03: the immutability ledger's witness is length + 32 digest
        // bytes, never a u64.
        let (_dir, _probe, store) = fixture();
        let location = ObjectPath::from("base/fv1/m1/keyspace/01LEDGER.sst");
        bridge({
            let (store, location) = (store.clone(), location.clone());
            async move { store.put(&location, PutPayload::from_static(b"ledger bytes")).await }
        })
        .expect("first write creates");
        let ledger = store.immutable_ledger.lock().unwrap();
        let recorded = ledger.get(location.as_ref()).expect("the admitted key is in the ledger");
        assert_eq!(recorded.digest.len(), 32, "the ledger witness is full digest bytes");
        assert!(recorded.matches(&content_witness(b"ledger bytes")));
    }

    // ------------------------------------------------------------------
    // R6-STOR-02 — bounded, streaming admission
    // ------------------------------------------------------------------

    #[test]
    fn completion_reads_are_bounded_by_the_window_and_never_whole_object() {
        // R6-STOR-02 acceptance, proven by INSTRUMENTATION rather than by
        // allocating a giant object: with a 4 KiB streaming window, growing
        // the object 8x must not grow either the largest single read or the
        // materialisation's peak completion-buffer residency, and no
        // whole-object read may be issued at all.
        const WINDOW: u64 = 4 * 1024;
        let mut observed = Vec::new();
        for (index, size) in [64 * 1024usize, 512 * 1024usize].into_iter().enumerate() {
            let (_dir, probe, store) = fixture();
            store.set_limits_for_test(WINDOW, MULTIPART_MAX_OBJECT_BYTES, MULTIPART_MAX_MATERIALISED_PROMOTE_BYTES);
            let location = ObjectPath::from(format!("base/fv1/m1/keyspace/0{index}SIZE.sst"));
            probe.reset_observations();
            store.buffers.reset_peak();
            // stream the object as 16 KiB parts — four windows each
            let parts: Vec<Vec<u8>> = (0..size / (16 * 1024)).map(|part| vec![part as u8; 16 * 1024]).collect();
            upload(&store, &location, parts).expect("a large streamed object publishes");
            observed.push((
                size as u64,
                probe.max_range_bytes.load(Ordering::SeqCst),
                probe.unbounded_gets.load(Ordering::SeqCst),
                store.buffers.peak(),
            ));
        }
        for (size, max_range, unbounded, peak) in &observed {
            assert_eq!(*unbounded, 0, "no whole-object read may be issued for a {size}-byte object");
            assert_eq!(*max_range, WINDOW, "every read must be exactly one window for a {size}-byte object");
            assert!(
                *peak <= WINDOW * MULTIPART_MAX_CONCURRENT_COMPLETIONS as u64,
                "peak buffer residency {peak} for a {size}-byte object must stay within window x concurrency",
            );
        }
        let (small, large) = (&observed[0], &observed[1]);
        assert_eq!(large.0, small.0 * 8, "the second object really is eight times the first");
        assert_eq!(large.1, small.1, "the largest single read must NOT grow with object size");
        assert_eq!(large.3, small.3, "peak buffer residency must NOT grow with object size");
    }

    #[test]
    fn the_occupied_target_settlement_also_streams() {
        // The loser of a promote race settles by comparing the PUBLISHED
        // object against its own authoritative expected witness. That
        // comparison used to pull both objects into memory.
        const WINDOW: u64 = 4 * 1024;
        let (_dir, probe, store) = fixture();
        store.set_limits_for_test(WINDOW, MULTIPART_MAX_OBJECT_BYTES, MULTIPART_MAX_MATERIALISED_PROMOTE_BYTES);
        let location = ObjectPath::from("base/fv1/m1/keyspace/01RACE.sst");
        let parts: Vec<Vec<u8>> = (0..8).map(|part| vec![part as u8; 16 * 1024]).collect();
        upload(&store, &location, parts.clone()).expect("the winner publishes");
        probe.reset_observations();
        store.buffers.reset_peak();
        // an identical replay settles idempotently against the published bytes
        upload(&store, &location, parts).expect("an identical replay settles as success");
        assert_eq!(probe.unbounded_gets.load(Ordering::SeqCst), 0, "settlement must not read a whole object");
        assert_eq!(probe.max_range_bytes.load(Ordering::SeqCst), WINDOW, "settlement reads one window at a time");
        assert!(store.buffers.peak() <= WINDOW * MULTIPART_MAX_CONCURRENT_COMPLETIONS as u64);
    }

    #[test]
    fn an_occupied_target_holding_different_bytes_is_still_refused_and_quarantines() {
        // the streaming settlement must not have weakened the refusal
        let (_dir, _probe, store) = fixture();
        let location = ObjectPath::from("base/fv1/m1/keyspace/01DIFF.sst");
        upload(&store, &location, vec![b"published bytes".to_vec()]).expect("the winner publishes");
        let refused = upload(&store, &location, vec![b"different bytes".to_vec()]);
        assert!(
            matches!(refused, Err(slatedb::object_store::Error::Precondition { .. })),
            "a losing attempt with different bytes must refuse, got {refused:?}",
        );
        assert!(store.is_quarantined(), "the refused overwrite must quarantine the materialisation");
        assert_eq!(read(&store, &location).unwrap(), b"published bytes", "the published bytes are untouched");
    }

    #[test]
    fn the_streaming_fallback_publishes_without_a_contiguous_copy() {
        // Providers without copy-if-not-exists (the plain-S3 posture this lane
        // currently builds) take the create-only PUT fallback. It must still
        // publish, must still verify, and must read the staged object one
        // window at a time.
        const WINDOW: u64 = 4 * 1024;
        let (_dir, probe, store) = fixture();
        probe.deny_conditional_copy.store(true, Ordering::SeqCst);
        store.set_limits_for_test(WINDOW, MULTIPART_MAX_OBJECT_BYTES, MULTIPART_MAX_MATERIALISED_PROMOTE_BYTES);
        let location = ObjectPath::from("base/fv1/m1/keyspace/01FALLBACK.sst");
        let parts: Vec<Vec<u8>> = (0..4).map(|part| vec![part as u8 + 1; 16 * 1024]).collect();
        upload(&store, &location, parts).expect("the fallback promote publishes");
        // observations are captured BEFORE the test's own verification read
        // (which is deliberately a whole-object read)
        let (unbounded, max_range) =
            (probe.unbounded_gets.load(Ordering::SeqCst), probe.max_range_bytes.load(Ordering::SeqCst));
        assert_eq!(read(&store, &location).unwrap().len(), 64 * 1024);
        assert_eq!(unbounded, 0, "the fallback must not read the object whole");
        assert_eq!(max_range, WINDOW);
    }

    #[test]
    fn the_size_ceilings_are_named_independent_and_ordered() {
        // R6-STOR-02: the per-object maximum is INDEPENDENT of the aggregate
        // journal budget and strictly tighter than it, and the fallback's
        // materialised cap is tighter still.
        assert!(
            MULTIPART_MAX_MATERIALISED_PROMOTE_BYTES < MULTIPART_MAX_OBJECT_BYTES,
            "the materialised-promote cap must be strictly tighter than the per-object maximum",
        );
        assert!(
            MULTIPART_MAX_OBJECT_BYTES < super::MULTIPART_MAX_JOURNALED_BYTES,
            "the per-object maximum must be independent of, and tighter than, the aggregate budget",
        );
        // the pure decision function, at its exact boundary (the mutant
        // `<=` -> `<` fails the first assertion, `>` -> `>=` the second)
        assert_eq!(admit_object_bytes(0, MULTIPART_MAX_OBJECT_BYTES, MULTIPART_MAX_OBJECT_BYTES), Ok(()));
        assert_eq!(
            admit_object_bytes(1, MULTIPART_MAX_OBJECT_BYTES, MULTIPART_MAX_OBJECT_BYTES),
            Err(MultipartBudgetRefused::Object {
                streamed: 1,
                incoming: MULTIPART_MAX_OBJECT_BYTES,
                max: MULTIPART_MAX_OBJECT_BYTES
            }),
        );
        assert!(admit_object_bytes(u64::MAX, 1, MULTIPART_MAX_OBJECT_BYTES).is_err(), "overflow refuses");
    }

    #[test]
    fn a_single_object_over_the_per_object_maximum_is_refused_while_the_aggregate_budget_is_free() {
        // MUTANT: rely on the aggregate journal budget alone. The aggregate
        // budget is left wide open here (8 GiB, untouched); the per-object
        // ceiling must still fire, and the refusal must name it.
        let (_dir, _probe, store) = fixture();
        store.set_limits_for_test(4 * 1024, 16, MULTIPART_MAX_MATERIALISED_PROMOTE_BYTES);
        let location = ObjectPath::from("base/fv1/m1/keyspace/01HUGE.sst");
        let refused = upload(&store, &location, vec![vec![b'x'; 8], vec![b'y'; 9]])
            .expect_err("an object over the per-object maximum must be refused");
        assert!(
            refused.to_string().contains("per-object maximum"),
            "the refusal must name the per-object maximum: {refused}",
        );
        assert!(read(&store, &location).is_none(), "nothing may be published for a refused object");
        // and an object AT the ceiling is still admitted
        let admitted = ObjectPath::from("base/fv1/m1/keyspace/01FITS.sst");
        upload(&store, &admitted, vec![vec![b'x'; 8], vec![b'y'; 8]]).expect("an object at the ceiling is admitted");
        assert_eq!(read(&store, &admitted).unwrap().len(), 16);
    }

    #[test]
    fn the_fallback_refuses_an_object_over_the_materialised_promote_maximum() {
        // The create-only PUT fallback is the one path that must hold the
        // object. Above its named cap the completion is a typed refusal (fail
        // closed) rather than an unbounded allocation, nothing is published,
        // and the staging object is reclaimed.
        let (_dir, probe, store) = fixture();
        probe.deny_conditional_copy.store(true, Ordering::SeqCst);
        store.set_limits_for_test(4 * 1024, MULTIPART_MAX_OBJECT_BYTES, 8);
        let location = ObjectPath::from("base/fv1/m1/keyspace/01BIGFALL.sst");
        let refused = upload(&store, &location, vec![vec![b'z'; 32]])
            .expect_err("an object over the materialised-promote cap must be refused");
        assert!(refused.to_string().contains("R6-STOR-02"), "the refusal cites the bound: {refused}");
        assert!(
            refused.to_string().contains("materialised-promote maximum"),
            "the refusal names the cap: {refused}",
        );
        assert!(read(&store, &location).is_none(), "nothing may be published");

        // an object AT the cap still publishes through the same fallback
        store.set_limits_for_test(4 * 1024, MULTIPART_MAX_OBJECT_BYTES, 32);
        let fits = ObjectPath::from("base/fv1/m1/keyspace/01FITFALL.sst");
        upload(&store, &fits, vec![vec![b'z'; 32]]).expect("an object at the cap publishes");
        assert_eq!(read(&store, &fits).unwrap().len(), 32);
    }

    #[test]
    fn the_completion_gate_admits_exactly_its_budget_at_once() {
        // R6-STOR-02: concurrent completions are bounded by a semaphore, so
        // peak heap is `window x budget` rather than `window x callers`.
        bridge(async move {
            let mut held = Vec::new();
            for _ in 0..MULTIPART_MAX_CONCURRENT_COMPLETIONS {
                held.push(CompletionPermit::acquire().await);
            }
            let blocked = tokio::time::timeout(Duration::from_millis(250), CompletionPermit::acquire()).await;
            assert!(blocked.is_err(), "a completion beyond the budget must WAIT, not proceed");
            held.pop();
            let admitted = tokio::time::timeout(Duration::from_secs(10), CompletionPermit::acquire()).await;
            assert!(admitted.is_ok(), "releasing a permit must admit the waiter");
        });
        assert!(MULTIPART_MAX_CONCURRENT_COMPLETIONS > 0, "the budget is positive");
    }

    // ------------------------------------------------------------------
    // R6-STOR-04 — authority separated by type
    // ------------------------------------------------------------------

    #[test]
    fn the_staging_authority_cannot_address_an_authoritative_name() {
        // R6-STOR-04: the ONE handle with reclaim authority is scoped to the
        // staging namespace. A forged key outside it is a typed refusal at the
        // boundary and the authoritative object survives.
        let dir = create_tmp_dir("slate-r6-staging-scope");
        let raw: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix(&*dir).unwrap());
        let published = ObjectPath::from("base/fv1/m1/keyspace/01LIVE.sst");
        bridge({
            let (raw, published) = (raw.clone(), published.clone());
            async move { raw.put(&published, PutPayload::from_static(b"authoritative")).await }
        })
        .unwrap();

        let (_authoritative, staging) = authority::split(raw.clone());
        let forged = StagingKey::forged_for_test(published.clone());
        let refused = bridge({
            let (staging, forged) = (staging.clone(), forged.clone());
            async move { staging.reclaim(&forged).await }
        });
        assert!(
            matches!(refused, Err(slatedb::object_store::Error::Precondition { .. })),
            "the staging authority must refuse an authoritative name, got {refused:?}",
        );
        assert!(refused.unwrap_err().to_string().contains("R6-STOR-04"));
        let survives = bridge({
            let (raw, published) = (raw.clone(), published.clone());
            async move { raw.head(&published).await }
        });
        assert!(survives.is_ok(), "the authoritative object must survive a refused staging reclaim");

        // and a legitimately minted staging key IS reclaimable through it
        let target = ObjectPath::from("base/fv1/m1/keyspace/01STAGE.sst");
        let minted = StagingKey::mint(&target, 7);
        assert!(minted.path().as_ref().contains(MULTIPART_ATTEMPT_INFIX), "a minted key is in the staging namespace");
        bridge({
            let (raw, minted) = (raw.clone(), minted.clone());
            async move { raw.put(minted.path(), PutPayload::from_static(b"staged")).await }
        })
        .unwrap();
        let reclaimed = bridge({
            let (staging, minted) = (staging.clone(), minted.clone());
            async move { staging.reclaim(&minted).await }
        });
        assert!(reclaimed.is_ok(), "a staging key must be reclaimable, got {reclaimed:?}");
    }

    #[test]
    fn a_failed_staging_reclaim_records_a_durable_orphan() {
        // R6-STOR-04: a swallowed `let _ = store.delete(..)` made orphan state
        // invisible. A reclaim that fails must leave a DURABLE record.
        let (dir, probe, store) = fixture();
        let location = ObjectPath::from("base/fv1/m1/keyspace/01ORPHAN.sst");
        probe.deny_reclaim.store(true, Ordering::SeqCst);
        upload(&store, &location, vec![b"published anyway".to_vec()]).expect("publication still succeeds");

        let records = store.orphans.records();
        assert_eq!(records.len(), 1, "a failed reclaim must record exactly one orphan, got {records:?}");
        assert!(records[0].contains(MULTIPART_ATTEMPT_INFIX), "the record names the staging key: {}", records[0]);
        assert!(records[0].contains("staging reclaim failed"), "the record names the reason: {}", records[0]);
        assert_eq!(store.orphans.undurable(), 0, "the record must have been made durable");

        let inventory = std::fs::read_to_string(dir.join(MULTIPART_ORPHAN_FILE)).expect("the durable inventory exists");
        assert!(inventory.contains(MULTIPART_ATTEMPT_INFIX), "the durable inventory carries the orphan key");
        assert_eq!(inventory.lines().count(), 1);

        // the published object is unaffected: cleanup is best effort, the
        // publication is the mutation decision
        assert_eq!(read(&store, &location).unwrap(), b"published anyway");
    }

    #[test]
    fn an_orphan_that_cannot_be_made_durable_is_counted_not_swallowed() {
        // No sink bound (a materialisation constructed outside `open_remote`):
        // the record still exists in memory AND the un-durable count rises, so
        // the failure is observable rather than silent.
        let dir = create_tmp_dir("slate-r6-no-sink");
        let raw: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix(&*dir).unwrap());
        let probe = ProbeStore::new(raw);
        probe.deny_reclaim.store(true, Ordering::SeqCst);
        let store = Arc::new(NoDeleteStore::new(probe.clone() as Arc<dyn ObjectStore>));
        let location = ObjectPath::from("base/fv1/m1/keyspace/01NOSINK.sst");
        upload(&store, &location, vec![b"bytes".to_vec()]).expect("publication succeeds");
        assert_eq!(store.orphans.records().len(), 1, "the orphan is recorded in memory");
        assert_eq!(store.orphans.undurable(), 1, "a record that cannot be made durable is COUNTED");
    }

    #[test]
    fn a_committed_attempt_cannot_abort_its_published_object_away() {
        // R6-STOR-04 mutant: multipart abort aimed at an authoritative name.
        // Abort only ever addresses the attempt's own staging key, and a
        // COMMITTED attempt refuses abort outright — so no abort path can
        // remove published bytes.
        let (_dir, _probe, store) = fixture();
        let location = ObjectPath::from("base/fv1/m1/keyspace/01ABORT.sst");
        let refused = bridge({
            let (store, location) = (store.clone(), location.clone());
            async move {
                let mut upload = store.put_multipart(&location).await?;
                upload.put_part(PutPayload::from_static(b"published")).await?;
                upload.complete().await?;
                Ok::<_, slatedb::object_store::Error>(upload.abort().await)
            }
        })
        .unwrap();
        assert!(
            matches!(refused, Err(slatedb::object_store::Error::Precondition { .. })),
            "aborting a committed attempt must be a typed refusal, got {refused:?}",
        );
        assert_eq!(read(&store, &location).unwrap(), b"published", "the published object survives");
    }

    #[test]
    fn the_authoritative_handle_cannot_overwrite_or_copy_over_a_published_name() {
        // R6-STOR-04: the authoritative handle exposes only create-only verbs.
        // There is no `delete`, no `rename` and no overwrite-mode copy to call
        // on it — those names do not exist on the trait, which is why this
        // test can only exercise the create-only ones. What it proves is that
        // the create-only verbs cannot be turned into replacements.
        let dir = create_tmp_dir("slate-r6-authoritative");
        let raw: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix(&*dir).unwrap());
        let (authoritative, _staging) = authority::split(raw.clone());
        let occupied = ObjectPath::from("base/fv1/m1/keyspace/01OCC.sst");
        let source = ObjectPath::from("base/fv1/m1/keyspace/01SRC.sst");
        bridge({
            let (authoritative, occupied, source) = (authoritative.clone(), occupied.clone(), source.clone());
            async move {
                authoritative
                    .put_create(&occupied, PutPayload::from_static(b"authoritative"), PutOptions::default())
                    .await
                    .unwrap();
                authoritative
                    .put_create(&source, PutPayload::from_static(b"other"), PutOptions::default())
                    .await
                    .unwrap();
            }
        });
        let overwritten = bridge({
            let (authoritative, occupied) = (authoritative.clone(), occupied.clone());
            async move {
                authoritative
                    .put_create(&occupied, PutPayload::from_static(b"replacement"), PutOptions::default())
                    .await
            }
        });
        assert!(overwritten.is_err(), "put through the authoritative handle is create-only");
        let copied = bridge({
            let (authoritative, occupied, source) = (authoritative.clone(), occupied.clone(), source.clone());
            async move { authoritative.copy_create(&source, &occupied, CopyOptions::default()).await }
        });
        assert!(copied.is_err(), "copy through the authoritative handle is create-only");
        let survives = bridge({
            let (raw, occupied) = (raw.clone(), occupied.clone());
            async move { raw.get(&occupied).await.unwrap().bytes().await.unwrap() }
        });
        assert_eq!(&survives[..], b"authoritative", "the authoritative bytes never changed");

        // the manifest CAS path is reserved for manifest keys: aiming it at a
        // data key is a typed refusal, not a conditional overwrite.
        let misaimed = bridge({
            let (authoritative, occupied) = (authoritative.clone(), occupied.clone());
            async move {
                authoritative
                    .put_manifest(
                        &occupied,
                        PutPayload::from_static(b"cas"),
                        PutOptions { mode: PutMode::Overwrite, ..Default::default() },
                    )
                    .await
            }
        });
        assert!(
            matches!(misaimed, Err(slatedb::object_store::Error::Precondition { .. })),
            "the CAS path must refuse a non-manifest location, got {misaimed:?}",
        );
    }
}
