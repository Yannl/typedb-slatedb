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
//! - **Read-your-writes**: writes go to the memtable with
//!   `await_durable: false` and every read/scan opts into
//!   `dirty: true` + `DurabilityLevel::Memory`, so a write is visible to the
//!   very next read exactly as with RocksDB.
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
    sync::{Arc, OnceLock},
};

use slatedb::{
    Db, DbIterator, WriteBatch as SlateWriteBatch,
    bytes::Bytes as SlateBytes,
    config::{ReadOptions, ScanOptions, Settings, WriteOptions},
    object_store::{
        ObjectMeta, ObjectStore, ObjectStoreExt, PutPayload,
        aws::AmazonS3Builder,
        local::LocalFileSystem,
        path::Path as ObjectPath,
        prefix::PrefixStore,
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
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    runtime().spawn(async move {
        // a dropped receiver means the caller thread died; nothing to do
        let _ = sender.send(future.await);
    });
    receiver.recv().expect("SlateDB storage task terminated without a result (panicked?)")
}

fn write_options() -> WriteOptions {
    WriteOptions { await_durable: false, ..Default::default() }
}

fn read_options() -> ReadOptions {
    // DurabilityLevel::Memory is the default; dirty=true additionally exposes
    // writes whose sequence numbers are not yet committed-durable — required
    // for read-your-writes with `await_durable: false`.
    ReadOptions::default().with_dirty(true)
}

fn scan_options() -> ScanOptions {
    ScanOptions::default().with_dirty(true)
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
    settings
}

/// The SlateDB store subtree under a keyspace root: LocalFS keyspaces put it
/// under `<keyspace-dir>/keyspace/`, S3 keyspaces under
/// `<object-prefix>/keyspace/` — one name, both lanes.
const DB_SUBDIR: &str = "keyspace";
const MANIFEST_SUBDIR: &str = "manifest";

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
async fn list_remote_prefix(
    store: &dyn ObjectStore,
    prefix: &ObjectPath,
) -> Result<Vec<ObjectMeta>, slatedb::Error> {
    let mut pending = vec![prefix.clone()];
    let mut objects = Vec::new();
    while let Some(level) = pending.pop() {
        let listing = store.list_with_delimiter(Some(&level)).await.map_err(store_error)?;
        objects.extend(listing.objects);
        pending.extend(listing.common_prefixes);
    }
    Ok(objects)
}

async fn purge_remote_prefix(store: &dyn ObjectStore, prefix: &ObjectPath) -> Result<(), slatedb::Error> {
    for meta in list_remote_prefix(store, prefix).await? {
        store.delete(&meta.location).await.map_err(store_error)?;
    }
    Ok(())
}

/// Upload a local directory tree (a restored checkpoint) under `prefix`,
/// preserving the relative layout.
async fn upload_dir_to_remote(
    store: &dyn ObjectStore,
    prefix: &ObjectPath,
    root: &Path,
) -> Result<(), slatedb::Error> {
    fn collect(root: &Path, dir: &Path, out: &mut Vec<(Vec<String>, PathBuf)>) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
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
        let relative = location
            .as_ref()
            .strip_prefix(&prefix_str)
            .expect("listed object location is under the listed prefix");
        let mut target = dir.to_owned();
        for part in relative.split('/') {
            target = target.join(part);
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(io_error)?;
        }
        let bytes =
            store.get(location).await.map_err(store_error)?.bytes().await.map_err(store_error)?;
        fs::write(&target, bytes).map_err(io_error)?;
    }
    Ok(())
}

/// The remote half of an S3-backed keyspace: the bucket-root store plus this
/// keyspace's exclusive prefix (the `Db` itself sees a `PrefixStore`).
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
}

impl SlateKeyspace {
    pub(super) fn open(path: &Path) -> Result<Self, Arc<slatedb::Error>> {
        fs::create_dir_all(path).map_err(|error| Arc::new(io_error(error)))?;
        let store: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix(path).map_err(|error| {
            Arc::new(slatedb::Error::unavailable(format!("local object store at {path:?}: {error}")))
        })?);
        let db = bridge(async move { Db::builder(DB_SUBDIR, store).with_settings(settings()).build().await })
            .map_err(Arc::new)?;
        Ok(Self { db: Arc::new(db), path: path.to_owned(), remote: None })
    }

    /// Open over the configured S3-compatible store (TB-P8, profile U2S3).
    ///
    /// The local keyspace directory is the lifecycle marker — storage
    /// recovery wipes it to mean "start empty" and checkpoint recovery
    /// repopulates it with the checkpointed store files (those are the only
    /// two states an open can observe; there is no state-preserving reopen
    /// without a checkpoint). Either way the remote prefix's previous
    /// contents are stale: purge them, and when a restored subtree is
    /// present, upload it as the new store state.
    pub(super) fn open_s3(path: &Path) -> Result<Self, Arc<slatedb::Error>> {
        fs::create_dir_all(path).map_err(|error| Arc::new(io_error(error)))?;
        let config = s3_config().map_err(Arc::new)?;
        let store = build_s3_store(config).map_err(Arc::new)?;
        let prefix = object_prefix(config, path);
        let restored_root = path.join(DB_SUBDIR).is_dir().then(|| path.to_owned());
        {
            let store = store.clone();
            let prefix = prefix.clone();
            bridge(async move {
                purge_remote_prefix(store.as_ref(), &prefix).await?;
                if let Some(root) = restored_root {
                    upload_dir_to_remote(store.as_ref(), &prefix, &root).await?;
                }
                Ok(())
            })
            .map_err(Arc::new)?;
        }
        let prefixed: Arc<dyn ObjectStore> = Arc::new(PrefixStore::new(store.clone(), prefix.clone()));
        let db = bridge(async move { Db::builder(DB_SUBDIR, prefixed).with_settings(settings()).build().await })
            .map_err(Arc::new)?;
        Ok(Self { db: Arc::new(db), path: path.to_owned(), remote: Some(RemoteStore { store, prefix }) })
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
    pub(super) fn get_prev<M, T>(&self, key: &[u8], mut mapper: M) -> Option<T>
    where
        M: FnMut(&[u8], &[u8]) -> T,
    {
        let db = self.db.clone();
        let key = key.to_vec();
        let result = bridge(async move {
            let options = scan_options().with_order(slatedb::IterationOrder::Descending);
            let mut iterator = db.scan_with_options(..=key, &options).await?;
            iterator.next().await
        });
        match result {
            Ok(Some(kv)) => Some(mapper(kv.key.as_ref(), kv.value.as_ref())),
            Ok(None) => None,
            // FAIL CLOSED: the Option-only signature cannot carry an error,
            // and the caller (vertex ID allocator seeding) would treat a
            // silent None as "nothing allocated" and re-issue existing IDs —
            // data corruption. A storage-engine failure here must stop the
            // process, exactly like an unreadable RocksDB would.
            Err(error) => {
                panic!("SlateDB floor scan (get_prev) failed; refusing to report absence: {error}")
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
        let pinned_manifest = match &manifest_dir {
            Some(dir) => {
                let mut entries: Vec<PathBuf> = fs::read_dir(dir)
                    .map_err(|error| Arc::new(io_error(error)))?
                    .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                    .filter(|path| path.is_file())
                    .collect();
                entries.sort();
                entries.into_iter().next_back()
            }
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
        let manifest_prefix = format!("{}/", remote.prefix.clone().join(DB_SUBDIR).join(MANIFEST_SUBDIR));
        let store = remote.store.clone();
        let prefix = remote.prefix.clone();
        let dir = checkpoint_keyspace_dir.to_owned();
        bridge(async move {
            let objects = list_remote_prefix(store.as_ref(), &prefix).await?;
            let is_manifest = |location: &ObjectPath| location.as_ref().starts_with(&manifest_prefix);
            // pin the lexicographically last manifest object — the same
            // ordering the LocalFS path applies to manifest file names
            let pinned =
                objects.iter().map(|meta| &meta.location).filter(|location| is_manifest(location)).max().cloned();
            let mut to_copy: Vec<ObjectPath> = objects
                .iter()
                .map(|meta| meta.location.clone())
                .filter(|location| !is_manifest(location))
                .collect();
            to_copy.extend(pinned);
            download_remote_objects(store.as_ref(), &prefix, &to_copy, &dir).await
        })
        .map_err(Arc::new)
    }

    /// Delete every object under this keyspace's remote prefix (no-op on the
    /// LocalFS lane, where deleting the local directory is already complete).
    /// The engine is closed first so no background flush races the purge; the
    /// second close attempted later by `Drop` is a swallowed error.
    pub(super) fn purge_remote(&self) -> Result<(), Arc<slatedb::Error>> {
        let Some(remote) = &self.remote else {
            return Ok(());
        };
        let db = self.db.clone();
        let _ = bridge(async move { db.close().await });
        let store = remote.store.clone();
        let prefix = remote.prefix.clone();
        bridge(async move { purge_remote_prefix(store.as_ref(), &prefix).await }).map_err(Arc::new)
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

    pub(super) fn estimate_size_in_bytes(&self) -> u64 {
        match &self.remote {
            None => dir_size(&self.path).unwrap_or(0),
            Some(remote) => {
                let store = remote.store.clone();
                let prefix = remote.prefix.clone();
                bridge(async move { list_remote_prefix(store.as_ref(), &prefix).await })
                    .map(|objects| objects.iter().map(|meta| meta.size).sum())
                    .unwrap_or(0)
            }
        }
    }

    /// Exact key count by full scan. The RocksDB path serves an O(1) engine
    /// estimate; SlateDB has no equivalent property, and the only caller is
    /// periodic database metrics, so a scan (exact, bounded by store size)
    /// is preferred over inventing an estimator.
    pub(super) fn estimate_key_count(&self) -> Result<u64, Arc<slatedb::Error>> {
        let db = self.db.clone();
        bridge(async move {
            let mut iterator = db.scan_with_options(.., &scan_options()).await?;
            let mut count = 0u64;
            while iterator.next().await?.is_some() {
                count += 1;
            }
            Ok(count)
        })
        .map_err(Arc::new)
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

fn dir_size(path: &Path) -> io::Result<u64> {
    let mut total = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            total += dir_size(&entry.path())?;
        } else {
            total += entry.metadata()?.len();
        }
    }
    Ok(total)
}
