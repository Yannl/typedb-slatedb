//! A synchronous, keyspace-partitioned facade over SlateDB.
//!
//! Shaped to the operations `storage::keyspace::Keyspace` performs against RocksDB at
//! TB `2256711a`, so it can stand behind the same interface:
//!
//! | TypeDB / RocksDB | here |
//! |---|---|
//! | `put_opt(k, v)` | [`Keyspace::put`] |
//! | `get_pinned_opt(k)` | [`Keyspace::get`] |
//! | `raw_iterator.seek_for_prev(k)` | [`Keyspace::get_prev`] |
//! | `raw_iterator.seek(k)` + `next()` | [`Keyspace::iterate_from`] |
//! | `write_opt(WriteBatch)` | [`KeyspaceSet::write`] |
//! | `property_int_value(estimate-num-keys)` | [`Keyspace::estimated_stats`] |
//! | `property_int_value(estimate-live-data-size)` | [`KeyspaceSet::size_bytes`] |
//!
//! ## The two problems this crate exists to solve
//!
//! **Async under a sync API.** TypeDB's storage calls are synchronous; every SlateDB entry
//! point is `async`. Calls are bridged onto a runtime owned by [`KeyspaceSet`]. Where the
//! caller is already inside a Tokio worker, `block_in_place` moves the wait off the async
//! worker so the reactor is not starved — a plain `block_on` there deadlocks.
//!
//! **Keyspace partitioning.** RocksDB gives TypeDB N independent column-family-like stores;
//! SlateDB is one keyspace. Keys are therefore prefixed with a one-byte keyspace id, which
//! preserves ordering *within* a keyspace (the property every iterator depends on) and keeps
//! ranges disjoint *between* them. One byte matches `KeyspaceId(pub u8)` upstream, and
//! `KEYSPACE_MAXIMUM_COUNT` bounds it.
//!
//! ## Cost is a correctness concern here
//!
//! Against a local filesystem an operation is free and only latency matters. Against
//! Cloudflare R2 every operation is billed, writes 12.5x more than reads, so an API that is
//! merely *slow* on local disk can be *unaffordable* in production. Two consequences shape
//! this module, and both are departures from the obvious implementation:
//!
//! - **Size and key-count are not scans.** They are polled by TypeDB's diagnostics loop every
//!   15 seconds. See [`KeyspaceSet::size_bytes`] and [`Keyspace::estimated_stats`].
//! - **Batches are coalesced, not looped.** One logical commit is one object-store write. See
//!   [`KeyspaceSet::write`].
//!
//! See [`config`] for the settings that govern flush, cache and GC spend.

use std::{
    ops::Bound,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bytes::Bytes;
use slatedb::{
    config::{CheckpointOptions, CheckpointScope, ScanOptions, WriteOptions},
    Db, WriteBatch,
};

pub mod config;
pub mod error;

pub use config::{Backend, R2Credentials, StoreConfig, Tuning};
pub use error::KeyspaceError;

/// Re-exported so callers can build keys and values for [`Batch::put_prefixed`] without
/// depending on `bytes` themselves. TypeDB ships its own crate named `bytes`, so a caller
/// naming the dependency directly resolves to the wrong one.
pub use bytes::{Bytes as ValueBytes, BytesMut as KeyBytes};

/// Matches upstream's `KeyspaceId(pub u8)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyspaceId(pub u8);

/// Upstream's `KEYSPACE_MAXIMUM_COUNT`.
pub const KEYSPACE_MAXIMUM_COUNT: usize = 10;

/// How long a computed key-count estimate is served before being recomputed.
///
/// TypeDB polls its metrics every 15 seconds (`DATABASE_METRICS_UPDATE_INTERVAL`). Because the
/// estimate costs a scan, serving it uncached would mean a full pass over the store four times
/// a minute forever. Ten minutes is chosen to be far longer than that poll interval while
/// staying short enough that the reported figure tracks a bulk ingest within one report.
pub const DEFAULT_ESTIMATE_TTL: Duration = Duration::from_secs(600);

/// How long a checkpoint's pin survives before expiring on its own.
///
/// A checkpoint holds every SST it references alive, so garbage collection cannot reclaim any
/// of them while it exists. `CheckpointOptions::lifetime` defaults to `None`, meaning *never
/// expires*, and that default is a slow leak here rather than a conservative choice: TypeDB
/// checkpoints every 60 seconds (`CHECKPOINT_INTERVAL`), so a database left running accrues
/// 1,440 permanent pins a day, none of whose objects GC may ever delete. Storage grows without
/// bound, and the manifest grows with it, since every checkpoint is an entry in it.
///
/// An expiry is the right shape because of what the pin is *for*: it exists to keep files from
/// being deleted underneath the directory copy that immediately follows, and that copy finishes
/// in seconds. An hour is far longer than the job needs and far shorter than forever.
///
/// This also makes [`KeyspaceSet::release_checkpoint`] honestly a no-op. Releasing explicitly
/// would need an `Admin` handle this type does not hold, so without an expiry the pin would
/// depend on a cleanup path that does not exist.
pub const CHECKPOINT_LIFETIME: Duration = Duration::from_secs(3600);

/// Keys deleted per batch by [`Keyspace::clear`].
///
/// Bounds both the memory held while clearing and the size of any single object-store write.
const CLEAR_CHUNK_KEYS: usize = 10_000;

/// Bytes of keys accumulated per batch by [`Keyspace::clear`], whichever limit is reached first.
const CLEAR_CHUNK_BYTES: usize = 8 * 1024 * 1024;

/// Prefix a user key with its keyspace id.
///
/// Ordering within a keyspace is preserved because the prefix is constant across it, which is
/// what every range iterator and `seek_for_prev` depends on.
fn physical_key(keyspace: KeyspaceId, key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() + 1);
    out.push(keyspace.0);
    out.extend_from_slice(key);
    out
}

/// Strip the keyspace prefix from a physical key.
fn logical_key(physical: &[u8]) -> &[u8] {
    &physical[1..]
}

/// The exclusive upper bound covering exactly one keyspace.
fn keyspace_end(keyspace: KeyspaceId) -> Bound<Vec<u8>> {
    match keyspace.0.checked_add(1) {
        Some(next) => Bound::Excluded(vec![next]),
        // The last representable keyspace runs to the end of the key space.
        None => Bound::Unbounded,
    }
}

/// Bridge one async call onto `runtime`.
///
/// `block_in_place` is required when the caller is already on a Tokio worker: a bare
/// `Handle::block_on` from inside the runtime panics, and blocking the worker directly starves
/// the reactor SlateDB needs to make progress on its own I/O.
///
/// Free function rather than a method so that types holding only an `Arc<Runtime>` — notably
/// [`KeyspaceIterator`] — can bridge without borrowing the whole [`KeyspaceSet`].
fn block_on<F>(runtime: &tokio::runtime::Runtime, fut: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        // No runtime on this thread: the simple case, and the one TypeDB's synchronous storage
        // calls normally take.
        return runtime.block_on(fut);
    };

    match handle.runtime_flavor() {
        // The caller is on a multi-threaded worker. `block_in_place` hands its work to a
        // sibling worker before blocking, so the caller's reactor keeps running.
        tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| runtime.block_on(fut))
        }
        // The caller is on a single-threaded runtime, where `block_in_place` has no sibling to
        // hand off to and panics outright. TypeDB's server builds a multi-threaded runtime so
        // production never lands here, but `#[tokio::test]` is single-threaded by default —
        // meaning any async test that touched storage would panic inside the storage layer,
        // which is a confusing place to discover the rule.
        //
        // Blocking a scoped thread instead is sound because the two runtimes are independent:
        // this future runs to completion on *our* runtime, which needs nothing from the
        // caller's, so parking the caller's only worker cannot deadlock it. `scope` rather than
        // `spawn` because the future borrows the `Db`, and requiring `'static` here would push
        // an `Arc` clone into every call site to satisfy a path that is rarely taken.
        _ => std::thread::scope(|scope| {
            scope.spawn(|| runtime.block_on(fut)).join().unwrap_or_else(|payload| {
                std::panic::resume_unwind(payload);
            })
        }),
    }
}

/// A key count and byte total, with the instant it was computed.
struct CachedEstimate {
    keys: u64,
    bytes: u64,
    computed_at: Instant,
}

/// Owns the SlateDB handle and the runtime every call is bridged onto.
pub struct KeyspaceSet {
    db: Arc<Db>,
    runtime: Arc<tokio::runtime::Runtime>,
    /// Prefetch settings for full range walks. Held rather than recomputed so `iterate_from`
    /// stays allocation-free on a hot path.
    scan_options: ScanOptions,
    /// Set only when the store is a local directory, and used to refuse operations that are
    /// meaningful only against one — see [`Self::local_directory`].
    local_directory: Option<std::path::PathBuf>,
    /// Per-keyspace memo for [`Keyspace::estimated_stats`], indexed by keyspace id.
    estimates: Vec<Mutex<Option<CachedEstimate>>>,
    estimate_ttl: Duration,
}

impl KeyspaceSet {
    /// Open against a local directory.
    ///
    /// Exists so callers can run the SlateDB lane without taking an `object_store` dependency
    /// of their own, and without credentials. It is the same code path as [`Self::open_with`]
    /// — a local filesystem is just another `ObjectStore` — so a bug here is a bug in the cloud
    /// path too, which is exactly the property that makes local testing worth anything.
    pub fn open_local(path: &std::path::Path) -> Result<Self, KeyspaceError> {
        Self::open_with(StoreConfig::local(path))
    }

    /// Open R2 if the environment configures it, local under `path` otherwise.
    ///
    /// The single call site both lanes go through; see [`StoreConfig::from_env`] for the
    /// variables read and for why a half-configured environment is an error rather than a
    /// silent fallback to local disk.
    pub fn open_from_env(path: &std::path::Path, prefix: &str) -> Result<Self, KeyspaceError> {
        Self::open_with(StoreConfig::from_env(path, prefix)?)
    }

    /// Open against any `object_store` implementation with default local tuning.
    ///
    /// Prefer [`Self::open_with`], which carries the tuning that makes the difference between
    /// a viable and an unaffordable R2 deployment.
    pub fn open(
        path: &str,
        object_store: Arc<dyn object_store::ObjectStore>,
    ) -> Result<Self, KeyspaceError> {
        Self::open_with(StoreConfig {
            backend: Backend::ObjectStore { path: path.to_string(), store: object_store },
            tuning: Tuning::object_storage(),
        })
    }

    /// Open exactly as `config` describes.
    pub fn open_with(config: StoreConfig) -> Result<Self, KeyspaceError> {
        let StoreConfig { backend, tuning } = config;
        tuning.validate()?;

        let local_directory = match &backend {
            Backend::Local { path } => Some(path.clone()),
            Backend::ObjectStore { .. } => None,
        };

        let (path, store) = match backend {
            Backend::Local { path } => {
                std::fs::create_dir_all(&path).map_err(|error| {
                    KeyspaceError::Open(format!("could not create {}: {error}", path.display()))
                })?;
                let store = object_store::local::LocalFileSystem::new_with_prefix(&path)
                    .map_err(|error| KeyspaceError::Open(error.to_string()))?;
                ("typedb".to_string(), Arc::new(store) as Arc<dyn object_store::ObjectStore>)
            }
            Backend::ObjectStore { path, store } => (path, store),
        };

        // The block cache is local disk, so its directory has to exist before SlateDB opens.
        // Failing to create it is a hard error rather than a downgrade to an uncached store:
        // running without the cache is not a mild degradation on R2, it multiplies the read
        // operation count for the life of the process, and doing that silently is how a
        // storage bill becomes a surprise.
        if let Some(cache_dir) = &tuning.cache_dir {
            std::fs::create_dir_all(cache_dir).map_err(|error| {
                KeyspaceError::Open(format!(
                    "could not create block cache directory {}: {error}",
                    cache_dir.display()
                ))
            })?;
        }

        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| KeyspaceError::Open(e.to_string()))?,
        );
        let db = runtime
            .block_on(Db::builder(path, store).with_settings(tuning.to_settings()).build())
            .map_err(|e| KeyspaceError::Open(e.to_string()))?;

        Ok(Self {
            db: Arc::new(db),
            runtime,
            scan_options: tuning.scan_options(),
            local_directory,
            estimates: (0..KEYSPACE_MAXIMUM_COUNT).map(|_| Mutex::new(None)).collect(),
            estimate_ttl: DEFAULT_ESTIMATE_TTL,
        })
    }

    /// The directory holding this store's files, or `None` when it lives in an object store.
    ///
    /// Exists for one reason: TypeDB's checkpoint mechanism copies a store's *files* into a
    /// checkpoint directory and later copies them back. That is meaningful for a local store
    /// and meaningless for a remote one, where the local directory holds at most a block cache.
    /// Callers must be able to tell the difference, because the failure is otherwise silent —
    /// the copy succeeds, produces a directory of the wrong bytes, and yields a checkpoint that
    /// is present, plausible and unrestorable.
    pub fn local_directory(&self) -> Option<&std::path::Path> {
        self.local_directory.as_deref()
    }

    /// Override how long a key-count estimate is cached. Chiefly for tests.
    pub fn with_estimate_ttl(mut self, ttl: Duration) -> Self {
        self.estimate_ttl = ttl;
        self
    }

    fn block<F>(&self, fut: F) -> F::Output
    where
        F: std::future::Future + Send,
        F::Output: Send,
    {
        block_on(&self.runtime, fut)
    }

    pub fn keyspace(&self, id: KeyspaceId) -> Keyspace<'_> {
        Keyspace { set: self, id }
    }

    /// Total on-disk size of the store, from the manifest. No I/O, no scan.
    ///
    /// This is the equivalent of RocksDB's `rocksdb.estimate-live-data-size`, and it is an
    /// estimate in the same sense: it sums each SST's recorded extent rather than counting
    /// live bytes, so it includes data that compaction has superseded but not yet dropped.
    ///
    /// The implementation matters more than the number. TypeDB's diagnostics loop calls this
    /// every 15 seconds per database, and the obvious implementation — scan the store, add up
    /// the entries — is O(n) in *stored bytes*. On RocksDB that mistake is invisible, because
    /// the property lookup it replaces is O(1) against local files. On R2 it means dragging
    /// the entire database across the network four times a minute, forever, at Class B rates:
    /// a 10 GB knowledge base would sustain roughly 2.3 TB/hour of reads while completely
    /// idle. Reading the manifest instead is O(number of SSTs) against memory the handle
    /// already holds.
    pub fn size_bytes(&self) -> u64 {
        let manifest = self.db.manifest();
        let l0: u64 = manifest.l0().iter().map(|sst| sst.estimate_size()).sum();
        let compacted: u64 = manifest.compacted().iter().map(|run| run.estimate_size()).sum();
        l0 + compacted
    }

    /// Apply a batch spanning any number of keyspaces. Returns once the write is *visible*,
    /// not once it is durable.
    ///
    /// ## Why a batch, and not a call per keyspace
    ///
    /// SlateDB's `WriteBatch` is atomic across the whole database, so a batch touching several
    /// keyspaces costs exactly one write no matter how many it spans. Issuing one call per
    /// keyspace instead — the shape RocksDB forces, because there each keyspace is a separate
    /// database — would multiply the object-store write rate by the number of keyspaces a
    /// commit happens to touch. TypeDB defines eight, and its commit path writes to several of
    /// them at once, so the difference on the hottest path in the system is close to an order
    /// of magnitude in Class A operations.
    ///
    /// The atomicity that comes with it is a side effect, not the goal, and it is a safe one:
    /// a commit that lands wholly rather than partially leaves strictly less for TypeDB's WAL
    /// replay to repair. No caller can observe the absence of a partial state it would have
    /// had to recover from anyway.
    ///
    /// ## Where the durability point sits
    ///
    /// This is the question the whole backend turns on, so it is answered here rather than at
    /// a call site.
    ///
    /// Upstream sets `write_options.disable_wal(true)` on RocksDB (`keyspace.rs`), so a
    /// committed write lands in the memtable and nowhere else — it is *not* durable when the
    /// call returns. TypeDB is fine with that because it keeps its own WAL in the `durability`
    /// crate: the WAL is the durability point, and each keyspace is a materialization that
    /// replay can rebuild.
    ///
    /// This matches that contract exactly. `write_with_options` returns a `WriteHandle` whose
    /// `await_durable` waits for SlateDB's WAL flush; dropping the handle without awaiting is
    /// what makes the write asynchronous-durable rather than synchronous-durable.
    ///
    /// Dropping the handle is safe, and that is a property worth stating rather than assuming:
    /// `WriteHandle` has no `Drop` impl and holds only a sequence number and a waiter closure,
    /// so discarding it cannot cancel or roll back a write that has already been applied. Had
    /// it been a cancellation guard — as such handles often are — this line would silently
    /// discard every commit, and every read-your-writes test would still pass, because the
    /// memtable would answer correctly right up until the process restarted.
    ///
    /// Awaiting durability here instead would put an object-store round trip in TypeDB's
    /// commit path for a guarantee TypeDB does not use and does not want. [`Self::flush`] and
    /// [`Self::checkpoint`] are the explicit barriers for callers that do.
    pub fn write(&self, batch: Batch) -> Result<(), KeyspaceError> {
        // SlateDB rejects an empty batch. Upstream's RocksDB treats one as a successful no-op,
        // and `WriteBatches::from_operations` really does produce empty batches — a batch whose
        // writes are all `Write::Put` with `reinsert == false` emits no puts at all. Matching
        // RocksDB here is what keeps that a no-op instead of a failed commit.
        if batch.is_empty() {
            return Ok(());
        }
        self.block(self.db.write_with_options(batch.inner, &WriteOptions::default()))
            .map(|_| ())
            .map_err(|e| KeyspaceError::Write(e.to_string()))
    }

    pub fn flush(&self) -> Result<(), KeyspaceError> {
        self.block(self.db.flush()).map_err(|e| KeyspaceError::Write(e.to_string()))
    }

    pub fn close(&self) -> Result<(), KeyspaceError> {
        self.block(self.db.close()).map_err(|e| KeyspaceError::Write(e.to_string()))
    }

    /// Make every acknowledged write durable and pin the resulting state.
    ///
    /// `CheckpointScope::All` flushes the batch writer before recording the checkpoint, so the
    /// returned state includes everything written so far — not merely everything already
    /// durable. That distinction is the whole point: a checkpoint that silently excluded
    /// in-flight writes would restore to a past the caller never asked for.
    ///
    /// The pin matters for a second reason. The caller copies the store's files immediately
    /// after this returns, and compaction or GC deleting an SST mid-copy would produce a
    /// checkpoint that looks complete and is not. Holding a checkpoint keeps every referenced
    /// object alive for the duration.
    /// The pin is given an expiry rather than being held forever; see [`CHECKPOINT_LIFETIME`].
    pub fn checkpoint(&self) -> Result<uuid::Uuid, KeyspaceError> {
        let options =
            CheckpointOptions { lifetime: Some(CHECKPOINT_LIFETIME), ..CheckpointOptions::default() };
        let result = self
            .block(self.db.create_checkpoint(CheckpointScope::All, &options))
            .map_err(|e| KeyspaceError::Write(e.to_string()))?;
        Ok(result.id)
    }

    /// Checkpoints currently recorded in the manifest.
    ///
    /// Exposed so a caller — or a test — can confirm that pins carry an expiry, which is the
    /// difference between a checkpoint that releases itself and one that suppresses garbage
    /// collection for the life of the database.
    ///
    /// Refreshes the manifest first, and therefore costs a read. `Db::manifest` returns the
    /// handle's cached copy, which does not include a checkpoint this process just created —
    /// checkpoint creation commits a new manifest version rather than mutating the cached one.
    /// Reading the cache would report an empty list immediately after a successful checkpoint.
    ///
    /// Unlike [`Self::size_bytes`], which is deliberately cache-only because it is polled every
    /// 15 seconds, this is called rarely and correctness is worth the round trip.
    pub fn checkpoints(&self) -> Result<Vec<slatedb::Checkpoint>, KeyspaceError> {
        self.block(self.db.refresh_manifest()).map_err(|e| KeyspaceError::Get(e.to_string()))?;
        Ok(self.db.manifest().checkpoints().to_vec())
    }

    /// Release a checkpoint taken by [`Self::checkpoint`].
    ///
    /// A no-op, and safe to be one: the checkpoint carries an expiry, so the pin releases
    /// itself. Deleting one explicitly needs an `Admin` handle against the same object store,
    /// which this type does not hold.
    pub fn release_checkpoint(&self, _id: uuid::Uuid) -> Result<(), KeyspaceError> {
        Ok(())
    }
}

/// A batch of writes, keyspace-prefixed as they are added.
///
/// Spans keyspaces deliberately — see [`KeyspaceSet::write`] for why one commit must not
/// become one object-store write per keyspace it touches.
#[derive(Default)]
pub struct Batch {
    inner: WriteBatch,
    len: usize,
}

impl Batch {
    pub fn new() -> Self {
        Self { inner: WriteBatch::new(), len: 0 }
    }

    pub fn put(&mut self, keyspace: KeyspaceId, key: &[u8], value: &[u8]) {
        self.inner.put(physical_key(keyspace, key), value);
        self.len += 1;
    }

    /// Add an entry whose key already reserves its keyspace prefix at byte 0.
    ///
    /// Exists to remove copies from the ingest path, which is the one place they add up. A
    /// caller that buffers writes before knowing which keyspace they belong to — as TypeDB's
    /// `WriteBatches` does, since the keyspace is only fixed when the commit is applied —
    /// otherwise has to build the key once for its own buffer and again with the prefix here,
    /// and hand the value through `AsRef<[u8]>`, which SlateDB copies a third time on the way
    /// into its own batch.
    ///
    /// Reserving byte 0 up front collapses that to one copy of the key and one of the value.
    /// The prefix is stamped rather than prepended, so no reallocation happens here at all.
    ///
    /// # Panics
    ///
    /// If `key` is empty. An empty key has no byte 0 to stamp, so silently accepting it would
    /// write an entry into whichever keyspace sorts first rather than the one requested.
    pub fn put_prefixed(&mut self, keyspace: KeyspaceId, mut key: KeyBytes, value: ValueBytes) {
        assert!(!key.is_empty(), "a prefixed key must reserve a byte for its keyspace id");
        key[0] = keyspace.0;
        self.inner.put_bytes(key.freeze(), value);
        self.len += 1;
    }

    /// A key buffer with byte 0 reserved for the keyspace prefix, ready for [`Self::put_prefixed`].
    pub fn prefixed_key(key: &[u8]) -> KeyBytes {
        let mut buffer = KeyBytes::with_capacity(key.len() + 1);
        buffer.extend_from_slice(&[0]);
        buffer.extend_from_slice(key);
        buffer
    }

    pub fn delete(&mut self, keyspace: KeyspaceId, key: &[u8]) {
        self.inner.delete(physical_key(keyspace, key));
        self.len += 1;
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

/// One logical keyspace.
pub struct Keyspace<'a> {
    set: &'a KeyspaceSet,
    id: KeyspaceId,
}

impl Keyspace<'_> {
    pub fn id(&self) -> KeyspaceId {
        self.id
    }

    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KeyspaceError> {
        self.set
            .block(self.set.db.put(physical_key(self.id, key), value))
            .map(|_| ())
            .map_err(|e| KeyspaceError::Put(e.to_string()))
    }

    pub fn delete(&self, key: &[u8]) -> Result<(), KeyspaceError> {
        self.set
            .block(self.set.db.delete(physical_key(self.id, key)))
            .map(|_| ())
            .map_err(|e| KeyspaceError::Put(e.to_string()))
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Bytes>, KeyspaceError> {
        self.set
            .block(self.set.db.get(physical_key(self.id, key)))
            .map_err(|e| KeyspaceError::Get(e.to_string()))
    }

    /// The greatest key `<= key`, matching RocksDB's `seek_for_prev`.
    ///
    /// SlateDB has no reverse cursor, but it does support a descending scan
    /// (`IterationOrder::Descending`), so the equivalent is a descending scan over
    /// `[keyspace_start, key]` taking the first entry. Without that ordering option this
    /// operation would need a full forward scan of the keyspace, which is why its
    /// availability decided the feasibility of the whole substitution.
    pub fn get_prev(&self, key: &[u8]) -> Result<Option<(Vec<u8>, Bytes)>, KeyspaceError> {
        let start = Bound::Included(vec![self.id.0]);
        let end = Bound::Included(physical_key(self.id, key));
        let options = ScanOptions::default().with_order(slatedb::IterationOrder::Descending);
        let mut iter = self
            .set
            .block(self.set.db.scan_with_options((start, end), &options))
            .map_err(|e| KeyspaceError::Iterate(e.to_string()))?;
        let first =
            self.set.block(iter.next()).map_err(|e| KeyspaceError::Iterate(e.to_string()))?;
        Ok(first.map(|kv| (logical_key(&kv.key).to_vec(), kv.value)))
    }

    /// Delete every key in this keyspace, leaving other keyspaces untouched.
    ///
    /// Scan-and-delete rather than a native range delete, which this SlateDB version does not
    /// expose. That is not a compromise here: upstream's `Keyspace::reset` walks the store with
    /// an iterator and deletes key by key too (`keyspace.rs`), so the cost profile matches what
    /// TypeDB already expects.
    ///
    /// Deletes are applied in bounded chunks rather than one batch, and never through a live
    /// cursor. Both constraints matter and for different reasons. Deleting through the cursor
    /// would mutate the range being scanned — the one ordering mistake here that produces a
    /// *partial* clear rather than an error, and a keyspace that is only mostly empty is worse
    /// than one that failed to clear at all. Accumulating every delete into a single batch
    /// instead is correct but unbounded: clearing a large keyspace would hold every key in
    /// memory at once and then hand SlateDB one enormous write. Chunking bounds both, at the
    /// cost of losing all-or-nothing semantics — which `reset` does not have upstream either,
    /// since it deletes key by key.
    pub fn clear(&self) -> Result<usize, KeyspaceError> {
        let mut total = 0usize;
        // Where the next chunk resumes. Deleted keys are tombstoned rather than removed, so
        // restarting each scan from the beginning would re-walk every tombstone already
        // written and turn this into a quadratic operation on a large keyspace.
        let mut resume: Vec<u8> = Vec::new();

        loop {
            let mut batch = Batch::new();
            let mut chunk_bytes = 0usize;
            let mut last_key: Option<Vec<u8>> = None;

            let mut iterator = self.iterate_from(&resume)?;
            while let Some((key, _)) = iterator.advance()? {
                batch.delete(self.id, key);
                chunk_bytes += key.len();
                last_key = Some(key.to_vec());
                if batch.len() >= CLEAR_CHUNK_KEYS || chunk_bytes >= CLEAR_CHUNK_BYTES {
                    break;
                }
            }
            drop(iterator);

            let chunk = batch.len();
            if chunk == 0 {
                return Ok(total);
            }
            self.set.write(batch)?;
            total += chunk;

            match last_key {
                // Resume strictly after the last key deleted. Appending a zero byte yields the
                // smallest key greater than it, which is exact for a byte-ordered keyspace and
                // needs no carry handling the way incrementing the final byte would.
                Some(key) => {
                    resume = key;
                    resume.push(0);
                }
                None => return Ok(total),
            }
        }
    }

    /// Exact `(key_count, total_bytes)` for this keyspace, by scanning.
    ///
    /// O(n) in the keyspace's contents and, against object storage, O(n) in network reads. It
    /// is exact, and there is no cheaper exact answer: SlateDB records per-SST row counts in
    /// each SST's stats block but does not expose them through a public API, so the only way
    /// to count live keys from outside the crate is to look at them.
    ///
    /// Prefer [`Self::estimated_stats`] for anything polled. This exists for callers that
    /// genuinely need an exact figure and know what they are asking for.
    pub fn stats(&self) -> Result<(u64, u64), KeyspaceError> {
        let mut keys = 0u64;
        let mut bytes = 0u64;
        let mut iterator = self.iterate_from(&[])?;
        while let Some((key, value)) = iterator.advance()? {
            keys += 1;
            bytes += (key.len() + value.len()) as u64;
        }
        Ok((keys, bytes))
    }

    /// `(key_count, total_bytes)` for this keyspace, memoized for [`DEFAULT_ESTIMATE_TTL`].
    ///
    /// Matches the contract of the RocksDB properties it replaces, which upstream calls
    /// *estimates* and reads in constant time. The figure here is exact when computed and goes
    /// stale between recomputations, which is the trade that makes a polled metric affordable:
    /// TypeDB's diagnostics loop asks every 15 seconds, and answering each of those with a
    /// scan would mean a continuous full pass over the store — on object storage, a permanent
    /// background transfer of the entire database, billed per request.
    ///
    /// Only the count justifies a scan at all. Total size has a free answer from the manifest;
    /// see [`KeyspaceSet::size_bytes`].
    pub fn estimated_stats(&self) -> Result<(u64, u64), KeyspaceError> {
        let slot = self
            .set
            .estimates
            .get(self.id.0 as usize)
            .ok_or_else(|| KeyspaceError::Config(format!("keyspace id {} out of range", self.id.0)))?;

        // The lock is held across the scan on purpose. Two threads finding the entry stale at
        // once should produce one scan, not two: with the scan outside the lock, the 15-second
        // diagnostics poll and any concurrent caller would each start their own pass over the
        // store, which is precisely the cost this memo exists to avoid.
        let mut guard = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some(cached) = guard.as_ref() {
            if cached.computed_at.elapsed() < self.set.estimate_ttl {
                return Ok((cached.keys, cached.bytes));
            }
        }

        let (keys, bytes) = self.stats()?;
        *guard = Some(CachedEstimate { keys, bytes, computed_at: Instant::now() });
        Ok((keys, bytes))
    }

    /// A forward iterator positioned at the first key `>= from`, bounded to this keyspace.
    ///
    /// The returned cursor owns everything it needs and borrows nothing, so it outlives both
    /// this `Keyspace` handle and the `&KeyspaceSet` it came from. That is not a convenience:
    /// `slatedb::DbIterator` itself borrows nothing from `Db`, so a cursor tied to a borrow
    /// would be imposing a lifetime the underlying type does not have — and a caller who needs
    /// to store the cursor would have no way to satisfy it except `unsafe`.
    pub fn iterate_from(&self, from: &[u8]) -> Result<KeyspaceIterator, KeyspaceError> {
        let start = Bound::Included(physical_key(self.id, from));
        let end = keyspace_end(self.id);
        let iter = self
            .set
            .block(self.set.db.scan_with_options((start, end), &self.set.scan_options))
            .map_err(|e| KeyspaceError::Iterate(e.to_string()))?;
        Ok(KeyspaceIterator {
            runtime: Arc::clone(&self.set.runtime),
            inner: iter,
            current: None,
        })
    }
}

/// Forward cursor over one keyspace.
///
/// Holds the current entry so `peek` can hand out borrows, mirroring upstream's
/// `LendingIterator` contract where the item borrows from the iterator rather than being
/// owned by the caller.
///
/// Owns an `Arc` to the runtime rather than borrowing the [`KeyspaceSet`]. `slatedb::DbIterator`
/// carries no lifetime parameter — it borrows nothing from the `Db` that produced it — so the
/// only thing a cursor needs to keep alive is the runtime it blocks on. Making that ownership
/// explicit costs one refcount and removes the need for any caller to reach `'static` by
/// transmuting a borrow.
pub struct KeyspaceIterator {
    runtime: Arc<tokio::runtime::Runtime>,
    inner: slatedb::DbIterator,
    current: Option<(Vec<u8>, Bytes)>,
}

impl KeyspaceIterator {
    /// Advance and return the new position.
    pub fn advance(&mut self) -> Result<Option<(&[u8], &[u8])>, KeyspaceError> {
        let next = block_on(&self.runtime, self.inner.next())
            .map_err(|e| KeyspaceError::Iterate(e.to_string()))?;
        self.current = next.map(|kv| (logical_key(&kv.key).to_vec(), kv.value));
        Ok(self.peek())
    }

    /// The current entry without advancing.
    pub fn peek(&self) -> Option<(&[u8], &[u8])> {
        self.current.as_ref().map(|(k, v)| (k.as_slice(), v.as_ref()))
    }

    /// Move to the first key `>= key`. Forward-only, like RocksDB's `seek` on a forward cursor.
    pub fn seek(&mut self, keyspace: KeyspaceId, key: &[u8]) -> Result<(), KeyspaceError> {
        block_on(&self.runtime, self.inner.seek(physical_key(keyspace, key)))
            .map_err(|e| KeyspaceError::Iterate(e.to_string()))?;
        self.current = None;
        Ok(())
    }
}
