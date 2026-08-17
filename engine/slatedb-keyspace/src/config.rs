/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Where the store lives, and how hard it is allowed to hit the object store.
//!
//! # Why this module exists
//!
//! SlateDB's defaults are tuned for S3-class storage where the dominant concern is latency.
//! On Cloudflare R2 the dominant concern is *operation count*, because R2 prices operations
//! and gives egress away:
//!
//! | | R2 | note |
//! |---|---|---|
//! | Class A (`PUT`, `LIST`, `COPY`, multipart) | $4.50 / million | every write costs one |
//! | Class B (`GET`, `HEAD`) | $0.36 / million | 12.5x cheaper than a write |
//! | `DELETE` | free | deleting garbage is never the expensive part |
//! | egress | free | so *bytes* are nearly free; *requests* are not |
//! | storage | $0.015 / GB-month | keeping garbage is cheap |
//!
//! Two consequences drive every value below. First, a write-shaped operation costs 12.5x a
//! read-shaped one, so the flush path deserves more attention than the read path. Second,
//! because deletes are free and storage is cheap but `LIST` is Class A, it is cheaper to let
//! garbage accumulate a while than to hunt for it often — which inverts the usual instinct to
//! GC aggressively.
//!
//! # The default that matters most
//!
//! SlateDB's `flush_interval` defaults to **100ms**, and its own documentation notes this
//! "should result in $130/month in PUT costs on S3 standard". That is the single largest line
//! item, it accrues whenever the database is being written to, and it is invisible until the
//! bill arrives. [`Tuning::object_storage`] moves it to 5s.
//!
//! An idle database costs nothing regardless: `WalBuffer::freeze_current_wal` returns early
//! when the buffer is empty, so the timer firing does not by itself issue a `PUT`. The cost is
//! driven by *how often writes happen*, capped at one `PUT` per interval — which is exactly
//! why lengthening the interval is a cap on spend rather than a tax on idling.
//!
//! # Workload assumption
//!
//! These values are shaped for a knowledge base serving LLM agents: write-once/read-many,
//! bursty ingestion, read-heavy steady state, and strong temporal locality (an agent reads
//! back what was just written, then re-reads the same neighbourhood repeatedly). That shape
//! is what justifies spending local disk on a read cache and accepting a longer flush
//! interval. A write-heavy OLTP workload would want different numbers, which is why every
//! field here is public and documented rather than baked in.

use std::{path::PathBuf, sync::Arc, time::Duration};

use slatedb::config::{
    GarbageCollectorDirectoryOptions, GarbageCollectorOptions, ObjectStoreCacheOptions, Settings,
};

use crate::error::KeyspaceError;

/// SlateDB's enforced floor for `max_wal_flushes_before_l0_flush`.
///
/// Mirrored here so a [`Tuning`] can be checked before it reaches SlateDB, where violating it
/// surfaces as a generic open failure rather than a pointer at the field responsible.
pub const MIN_WAL_FLUSHES_BEFORE_L0_FLUSH: u64 = 4096;

/// Cloudflare R2 credentials and location.
///
/// R2 speaks the S3 API, so this becomes an `AmazonS3` object store. The two settings that are
/// not obvious: the region must be the literal `auto` (R2 has no regions but the S3 signing
/// algorithm requires one), and the endpoint is account-scoped rather than bucket-scoped, so
/// requests are path-style rather than virtual-hosted.
#[derive(Clone)]
pub struct R2Credentials {
    pub account_id: String,
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Overrides the derived `https://<account_id>.r2.cloudflarestorage.com`.
    ///
    /// Exists for R2's jurisdiction-specific endpoints (`.eu`, `.fedramp`) and for pointing
    /// tests at a local S3 implementation.
    pub endpoint: Option<String>,
}

impl std::fmt::Debug for R2Credentials {
    /// Hand-written so a config dump cannot leak the secret into a log.
    ///
    /// `#[derive(Debug)]` here would print `secret_access_key` in full, and config structs end
    /// up in error messages and tracing spans by exactly this route.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("R2Credentials")
            .field("account_id", &self.account_id)
            .field("bucket", &self.bucket)
            .field("access_key_id", &Redacted)
            .field("secret_access_key", &Redacted)
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

struct Redacted;

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Environment variable names, exported so operators and tests agree on them.
pub mod env {
    pub const ACCOUNT_ID: &str = "TYPEDB_R2_ACCOUNT_ID";
    pub const BUCKET: &str = "TYPEDB_R2_BUCKET";
    pub const ACCESS_KEY_ID: &str = "TYPEDB_R2_ACCESS_KEY_ID";
    pub const SECRET_ACCESS_KEY: &str = "TYPEDB_R2_SECRET_ACCESS_KEY";
    pub const ENDPOINT: &str = "TYPEDB_R2_ENDPOINT";
    pub const CACHE_DIR: &str = "TYPEDB_R2_CACHE_DIR";
}

impl R2Credentials {
    /// Read credentials from the environment, or `None` if R2 is not configured.
    ///
    /// Returning `Ok(None)` when *nothing* is set — rather than an error — is what lets a
    /// single call site serve both lanes: no R2 environment means local storage.
    ///
    /// A *partially* configured environment is an error rather than a silent fallback. Falling
    /// back would mean a deployment that meant to use R2, fat-fingered one variable name, and
    /// silently came up on local disk: it would pass every health check, serve reads and
    /// writes correctly, and lose the entire database when the container was replaced.
    pub fn from_env() -> Result<Option<Self>, KeyspaceError> {
        let account_id = std::env::var(env::ACCOUNT_ID).ok();
        let bucket = std::env::var(env::BUCKET).ok();
        let access_key_id = std::env::var(env::ACCESS_KEY_ID).ok();
        let secret_access_key = std::env::var(env::SECRET_ACCESS_KEY).ok();

        let present: Vec<&str> = [
            (env::ACCOUNT_ID, account_id.is_some()),
            (env::BUCKET, bucket.is_some()),
            (env::ACCESS_KEY_ID, access_key_id.is_some()),
            (env::SECRET_ACCESS_KEY, secret_access_key.is_some()),
        ]
        .iter()
        .filter_map(|(name, set)| set.then_some(*name))
        .collect();

        if present.is_empty() {
            return Ok(None);
        }

        let (Some(account_id), Some(bucket), Some(access_key_id), Some(secret_access_key)) =
            (account_id, bucket, access_key_id, secret_access_key)
        else {
            let missing: Vec<&str> = [env::ACCOUNT_ID, env::BUCKET, env::ACCESS_KEY_ID, env::SECRET_ACCESS_KEY]
                .into_iter()
                .filter(|name| !present.contains(name))
                .collect();
            return Err(KeyspaceError::Config(format!(
                "R2 is partially configured: {} set, {} missing. \
                 Set all four or none — falling back to local storage here would silently \
                 discard the database when the process is replaced.",
                present.join(", "),
                missing.join(", "),
            )));
        };

        Ok(Some(Self {
            account_id,
            bucket,
            access_key_id,
            secret_access_key,
            endpoint: std::env::var(env::ENDPOINT).ok(),
        }))
    }

    fn endpoint(&self) -> String {
        self.endpoint
            .clone()
            .unwrap_or_else(|| format!("https://{}.r2.cloudflarestorage.com", self.account_id))
    }

    /// Build the `object_store` handle R2 is reached through.
    pub fn build(&self) -> Result<Arc<dyn object_store::ObjectStore>, KeyspaceError> {
        let store = object_store::aws::AmazonS3Builder::new()
            .with_bucket_name(&self.bucket)
            .with_access_key_id(&self.access_key_id)
            .with_secret_access_key(&self.secret_access_key)
            .with_endpoint(self.endpoint())
            // R2 has no regions, but SigV4 requires one in the signature. `auto` is the value
            // Cloudflare specifies; anything else produces a signature mismatch, not a
            // redirect, so this is not a value to guess at.
            .with_region("auto")
            // The endpoint is account-scoped (`<account>.r2.cloudflarestorage.com/<bucket>`),
            // so the bucket is part of the path. Virtual-hosted style would resolve to
            // `<bucket>.<account>.r2.cloudflarestorage.com`, which does not exist.
            .with_virtual_hosted_style_request(false)
            // SlateDB commits its manifest with a compare-and-swap, which `object_store`
            // implements over `If-Match`/`If-None-Match`. R2 supports those headers; this is
            // the crate's default, set explicitly because a silent change to `Disabled` would
            // not fail loudly — it would let two writers both believe they hold the lease.
            .with_conditional_put(object_store::aws::S3ConditionalPut::ETagMatch)
            .build()
            .map_err(|error| KeyspaceError::Open(format!("could not reach R2: {error}")))?;
        Ok(Arc::new(store))
    }
}

/// How hard the store is allowed to hit object storage.
///
/// Every field trades one of durability lag, read latency, or money against the others. The
/// defaults differ by backend because the right trade differs: on a local filesystem an
/// operation is free and the only cost is `fsync` latency, while on R2 an operation is money.
#[derive(Clone, Debug)]
pub struct Tuning {
    /// How often buffered writes are flushed to the WAL. `None` disables timed flushing.
    pub flush_interval: Option<Duration>,

    /// Whether SlateDB keeps a write-ahead log at all.
    ///
    /// TypeDB keeps its own WAL in the `durability` crate and disables RocksDB's for exactly
    /// that reason (`keyspace.rs` sets `disable_wal(true)`), so SlateDB's WAL is the *second*
    /// redundant log in the stack. Turning it off removes the entire WAL `PUT` stream — the
    /// largest single cost item — and matches upstream's configuration precisely.
    ///
    /// It is nonetheless left **on** by default. With the WAL off, an acknowledged write
    /// reaches object storage only when the memtable flushes, so the volume TypeDB must replay
    /// after a crash is bounded by `l0_sst_size_bytes` rather than by time. Whether that is
    /// acceptable depends on the deployment's checkpoint cadence, which this crate cannot see.
    /// The saving is real and the option is here; it should be taken deliberately, by an
    /// operator who knows their checkpoint interval, rather than inherited from a default.
    pub wal_enabled: bool,

    /// How often to re-read the manifest to notice compactions and fencing by another writer.
    ///
    /// Costs one Class B `GET` per interval per open handle in the steady state: the store
    /// probes for the next manifest id and treats a 404 as "still current", falling back to a
    /// `LIST` only after repeated misses.
    pub manifest_poll_interval: Duration,

    /// Freeze the memtable after this many WAL flushes even if it has not reached
    /// `l0_sst_size_bytes`.
    ///
    /// This bounds how much WAL a restart has to replay on a database too quiet to fill a
    /// memtable. It is expressed in flushes rather than seconds, so it must be read together
    /// with `flush_interval`: the product of the two is the real window, and lengthening the
    /// interval silently lengthens that window by the same factor.
    ///
    /// SlateDB rejects anything below [`MIN_WAL_FLUSHES_BEFORE_L0_FLUSH`], so the window
    /// cannot be shortened here to compensate for a longer flush interval — with a 5s
    /// interval it is about 5.7 hours. That is a bound on replay *time*, not on durability:
    /// the WAL entries are already in object storage, so nothing is at risk of loss, and at
    /// the write rate that fails to fill a 64 MB memtable in 5.7 hours the volume to replay
    /// is small in absolute terms.
    pub max_wal_flushes_before_l0_flush: u64,

    /// Build a bloom filter for any SST with at least this many keys.
    ///
    /// The filter is what stops a point lookup from fetching an SST that cannot contain the
    /// key. On local disk that saves a page-cache hit and the default of 1000 is reasonable.
    /// Against R2 it saves a network round trip costing money and 50-200ms, so the trade moves
    /// decisively toward filtering everything.
    pub min_filter_keys: u32,

    /// The minimum memtable size before it is flushed to an L0 SST.
    pub l0_sst_size_bytes: usize,

    /// Compress SST blocks.
    ///
    /// Egress is free on R2, so this does not save transfer *cost* — it saves storage cost,
    /// transfer *time*, and cache footprint. A knowledge base is mostly text, which is exactly
    /// the input compression is good at.
    pub compression: bool,

    /// Local directory backing the read-through cache of object-store blocks.
    ///
    /// The highest-leverage setting here for a read-heavy workload. Without it every block
    /// read is a Class B operation and a network round trip; with it, repeat reads of the same
    /// neighbourhood are local. Agent workloads re-read aggressively, so the hit rate is high.
    pub cache_dir: Option<PathBuf>,

    /// Cache size cap.
    pub cache_max_bytes: usize,

    /// Bytes a range scan fetches ahead of the cursor.
    ///
    /// SlateDB defaults this to 1 byte — one block — and [`Self::scan_fetch_tasks`] to 1, so a
    /// scan pulls one block at a time, serially. On local disk that is a page-cache hit and the
    /// default is fine. Against R2 every block is a network round trip: at a 4 KB block and
    /// ~50ms of latency, scanning 1 MB costs 256 sequential round trips, on the order of ten
    /// seconds, for data that could have arrived in two or three requests.
    ///
    /// Reading ahead is cheaper in operations as well as faster, which is the unusual part.
    /// Egress is free on R2 and requests are not, so one large fetch beats many small ones on
    /// both axes — the usual worry about wasted bandwidth simply does not apply.
    ///
    /// It is not free everywhere, which is why it is a scan setting rather than a global one:
    /// a cursor that reads two keys and stops has paid for a megabyte it never used. Point
    /// lookups and [`crate::Keyspace::get_prev`] deliberately do not use this.
    pub scan_read_ahead_bytes: usize,

    /// Concurrent block fetches within a single scan.
    ///
    /// Turns the read-ahead window above into parallel requests rather than a longer serial
    /// chain. Bounded modestly: each task is an in-flight request against the same store, and
    /// past a handful the gain is throughput SlateDB's compaction and flush paths also want.
    pub scan_fetch_tasks: usize,

    /// Give up on an object-store operation after this many retries.
    ///
    /// SlateDB's default is `None`, meaning *retry transient errors indefinitely*. Under a
    /// synchronous facade that is a liveness hazard rather than a resilience feature: a TypeDB
    /// query thread is parked inside `block_on` for the duration, so an outage or a revoked
    /// credential does not surface as a failed query, it surfaces as a server that stops
    /// answering and never explains why. A bounded count converts that into an error the layer
    /// above can report, retry, or fail on.
    pub object_store_max_retries: Option<u32>,

    /// How often the garbage collector sweeps.
    ///
    /// Sweeping means `LIST`, which is Class A — the expensive class — while `DELETE` is free
    /// and storage is $0.015/GB-month. The economics therefore favour sweeping *less* often
    /// than instinct suggests: retaining garbage an extra hour costs a fraction of a cent,
    /// while listing every ten minutes across five directories costs six times as many Class A
    /// operations as listing hourly.
    pub gc_interval: Option<Duration>,

    /// How long an object must be unreferenced before collection.
    pub gc_min_age: Duration,
}

impl Tuning {
    /// Defaults for a local filesystem: operations are free, so favour freshness.
    ///
    /// These deliberately stay close to SlateDB's own defaults. The local lane exists to be a
    /// faithful rehearsal of the cloud lane, and a local profile tuned differently would hide
    /// exactly the behaviour the cloud profile changes.
    pub fn local() -> Self {
        Self {
            flush_interval: Some(Duration::from_millis(100)),
            wal_enabled: true,
            manifest_poll_interval: Duration::from_secs(1),
            max_wal_flushes_before_l0_flush: 4096,
            min_filter_keys: 1000,
            l0_sst_size_bytes: 64 * 1024 * 1024,
            compression: false,
            cache_dir: None,
            cache_max_bytes: 0,
            // SlateDB's own defaults: one block at a time. Correct where a block is a
            // page-cache hit rather than a round trip.
            scan_read_ahead_bytes: 1,
            scan_fetch_tasks: 1,
            // Unbounded, as SlateDB has it. A local filesystem does not produce the transient
            // failures the bound exists to escape.
            object_store_max_retries: None,
            gc_interval: Some(Duration::from_secs(600)),
            gc_min_age: Duration::from_secs(300),
        }
    }

    /// Defaults for R2 and other pay-per-operation object stores.
    ///
    /// The reasoning for each departure from SlateDB's defaults is on the field it changes.
    /// In aggregate: cap the write-side operation rate, spend local disk to avoid read-side
    /// operations, and stop sweeping for garbage so eagerly.
    pub fn object_storage() -> Self {
        Self {
            // 100ms -> 5s. Caps WAL PUTs at 0.2/s instead of 10/s: a 50x reduction in the
            // dominant cost, bought with up to 5s of additional lag before a write reaches
            // object storage. TypeDB's own WAL already covers that window, so the guarantee
            // being relaxed is one the caller above does not rely on.
            flush_interval: Some(Duration::from_secs(5)),
            wal_enabled: true,
            // 1s -> 30s. Polling detects compactions and fencing by another writer. In the
            // single-writer deployment this backend targets, the only real consumer is noticing
            // compaction output; 30s of staleness there is invisible, and the poll is pure
            // background spend the rest of the time.
            manifest_poll_interval: Duration::from_secs(30),
            // Held at SlateDB's enforced minimum. Lengthening the flush interval 50x also
            // lengthens this window 50x, and the natural compensation — lowering the flush
            // count to match — is not available: SlateDB validates a floor of 4096. The
            // window is therefore ~5.7 hours of unpromoted WAL on a quiet database, which
            // costs replay time on restart and nothing else.
            max_wal_flushes_before_l0_flush: MIN_WAL_FLUSHES_BEFORE_L0_FLUSH,
            // Filter everything. A filter that avoids one R2 `GET` has already paid for itself
            // many times over in both latency and money.
            min_filter_keys: 0,
            l0_sst_size_bytes: 64 * 1024 * 1024,
            compression: true,
            cache_dir: None,
            cache_max_bytes: 8 * 1024 * 1024 * 1024,
            // 1 byte -> 1 MiB, 1 task -> 4. The single largest scan-latency lever: a graph
            // traversal reading a range no longer pays one network round trip per 4 KB block.
            scan_read_ahead_bytes: 1024 * 1024,
            scan_fetch_tasks: 4,
            // Bounded rather than SlateDB's unlimited. See the field's documentation: under a
            // synchronous API, "retry forever" is a hang, not resilience.
            object_store_max_retries: Some(10),
            // 600s -> 3600s. Six times fewer Class A `LIST` sweeps, paid for with a little
            // retained garbage at $0.015/GB-month.
            gc_interval: Some(Duration::from_secs(3600)),
            gc_min_age: Duration::from_secs(3600),
        }
    }

    /// Turn off SlateDB's WAL, leaving TypeDB's `durability` WAL as the only log.
    ///
    /// See [`Self::wal_enabled`] for what this costs. Requires the `wal_disable` feature.
    #[cfg(feature = "wal_disable")]
    pub fn without_wal(mut self) -> Self {
        self.wal_enabled = false;
        self
    }

    /// Point the read-through block cache at a local directory.
    pub fn with_cache_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cache_dir = Some(dir.into());
        self
    }

    /// Check the constraints SlateDB enforces, naming the field at fault.
    ///
    /// SlateDB validates the same rules and rejects a bad `Settings` at open, but it reports
    /// them as an opaque open failure. Catching them here means an operator who mis-tunes a
    /// deployment is told which knob is wrong rather than that the database would not start.
    pub fn validate(&self) -> Result<(), KeyspaceError> {
        if self.max_wal_flushes_before_l0_flush < MIN_WAL_FLUSHES_BEFORE_L0_FLUSH {
            return Err(KeyspaceError::Config(format!(
                "max_wal_flushes_before_l0_flush is {} but SlateDB requires at least {}",
                self.max_wal_flushes_before_l0_flush, MIN_WAL_FLUSHES_BEFORE_L0_FLUSH,
            )));
        }
        if self.cache_dir.is_some() && self.cache_max_bytes == 0 {
            return Err(KeyspaceError::Config(
                "a block cache directory is set but cache_max_bytes is 0, so nothing would ever \
                 be cached; either raise the limit or clear cache_dir"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Scan options for a full range walk, where reading ahead pays for itself.
    ///
    /// Deliberately not used by point lookups or `get_prev`, which read one entry: prefetching
    /// a megabyte to answer them would trade a latency win on scans for a latency loss
    /// everywhere else.
    pub fn scan_options(&self) -> slatedb::config::ScanOptions {
        slatedb::config::ScanOptions {
            read_ahead_bytes: self.scan_read_ahead_bytes,
            max_fetch_tasks: self.scan_fetch_tasks,
            ..slatedb::config::ScanOptions::default()
        }
    }

    /// Translate to SlateDB's own settings type.
    pub fn to_settings(&self) -> Settings {
        let gc_directory = GarbageCollectorDirectoryOptions {
            interval: self.gc_interval,
            min_age: self.gc_min_age,
            dry_run: false,
        };

        Settings {
            flush_interval: self.flush_interval,
            #[cfg(feature = "wal_disable")]
            wal_enabled: self.wal_enabled,
            manifest_poll_interval: self.manifest_poll_interval,
            max_wal_flushes_before_l0_flush: self.max_wal_flushes_before_l0_flush,
            min_filter_keys: self.min_filter_keys,
            l0_sst_size_bytes: self.l0_sst_size_bytes,
            object_store_max_retries: self.object_store_max_retries,
            compression_codec: self.compression_codec(),
            object_store_cache_options: ObjectStoreCacheOptions {
                root_folder: self.cache_dir.clone(),
                max_cache_size_bytes: Some(self.cache_max_bytes),
                // Cache what we just wrote. An agent that ingests a document and immediately
                // queries it is the common case, and without this that read leaves the machine
                // to fetch bytes this process produced moments ago.
                cache_on_flush: self.cache_dir.is_some(),
                cache_on_compaction: self.cache_dir.is_some(),
                ..ObjectStoreCacheOptions::default()
            },
            garbage_collector_options: Some(GarbageCollectorOptions {
                manifest_options: Some(gc_directory),
                wal_options: Some(gc_directory),
                compacted_options: Some(gc_directory),
                compactions_options: Some(gc_directory),
                ..GarbageCollectorOptions::default()
            }),
            ..Settings::default()
        }
    }

    /// Resolve [`Self::compression`] against what was actually compiled in.
    ///
    /// The `cfg` names *this* crate's `compression` feature, not SlateDB's `zstd`. Testing for
    /// `feature = "zstd"` here reads correctly and is always false, because a dependency's
    /// features are not this crate's — which would leave `compression: true` silently doing
    /// nothing, the failure mode being a config that claims a saving it never delivers.
    fn compression_codec(&self) -> Option<slatedb::config::CompressionCodec> {
        #[cfg(feature = "compression")]
        if self.compression {
            return Some(slatedb::config::CompressionCodec::Zstd);
        }
        None
    }
}

/// Where a keyspace set's data lives.
pub enum Backend {
    /// A directory on the local filesystem.
    Local { path: PathBuf },
    /// Any `object_store` implementation, under `path` within it.
    ObjectStore { path: String, store: Arc<dyn object_store::ObjectStore> },
}

/// A complete description of how to open a [`crate::KeyspaceSet`].
pub struct StoreConfig {
    pub backend: Backend,
    pub tuning: Tuning,
}

impl StoreConfig {
    /// A local store under `path`, with local-appropriate tuning.
    pub fn local(path: impl Into<PathBuf>) -> Self {
        Self { backend: Backend::Local { path: path.into() }, tuning: Tuning::local() }
    }

    /// An R2-backed store, with object-storage tuning.
    ///
    /// `path` is the prefix within the bucket, which is what allows several databases to share
    /// one bucket without a `LIST` from one seeing another's objects.
    pub fn r2(path: impl Into<String>, credentials: &R2Credentials) -> Result<Self, KeyspaceError> {
        Ok(Self {
            backend: Backend::ObjectStore { path: path.into(), store: credentials.build()? },
            tuning: Tuning::object_storage(),
        })
    }

    /// R2 if the environment configures it, local otherwise.
    ///
    /// The one call site both lanes go through. `local_path` is used for the local fallback and,
    /// when R2 is configured, as the parent of the block cache directory — the cache is local
    /// disk either way, and putting it beside the data directory keeps a deployment's on-disk
    /// footprint in one place.
    pub fn from_env(local_path: impl Into<PathBuf>, prefix: &str) -> Result<Self, KeyspaceError> {
        let local_path = local_path.into();
        match R2Credentials::from_env()? {
            None => Ok(Self::local(local_path)),
            Some(credentials) => {
                let mut config = Self::r2(prefix.to_string(), &credentials)?;
                let cache_dir = std::env::var(env::CACHE_DIR)
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| local_path.join("r2-cache"));
                config.tuning = config.tuning.with_cache_dir(cache_dir);
                Ok(config)
            }
        }
    }

    pub fn with_tuning(mut self, tuning: Tuning) -> Self {
        self.tuning = tuning;
        self
    }
}
