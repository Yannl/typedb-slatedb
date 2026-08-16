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
    object_store::{ObjectStore, local::LocalFileSystem},
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
    settings
}

/// A SlateDB-backed keyspace over a `LocalFileSystem` object store rooted at
/// the keyspace directory.
pub(super) struct SlateKeyspace {
    db: Arc<Db>,
    path: PathBuf,
}

impl SlateKeyspace {
    pub(super) fn open(path: &Path) -> Result<Self, Arc<slatedb::Error>> {
        fs::create_dir_all(path).map_err(|error| Arc::new(io_error(error)))?;
        let store: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix(path).map_err(|error| {
            Arc::new(slatedb::Error::unavailable(format!("local object store at {path:?}: {error}")))
        })?);
        let db = bridge(async move { Db::builder("keyspace", store).with_settings(settings()).build().await })
            .map_err(Arc::new)?;
        Ok(Self { db: Arc::new(db), path: path.to_owned() })
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
            // a floor-read failure surfaces as absence, matching the RocksDB
            // path's Option-only signature; callers treat it as "no allocation"
            Ok(None) | Err(_) => None,
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

    /// Flush the memtable, then copy the quiescent object-store directory:
    /// with compactor/GC disabled nothing rewrites files between flushes, so
    /// the copy is a consistent point-in-time checkpoint (same contract as
    /// the RocksDB `Checkpoint` hardlink tree, which also flushes first).
    pub(super) fn checkpoint(&self, checkpoint_keyspace_dir: &Path) -> Result<(), Arc<slatedb::Error>> {
        let db = self.db.clone();
        bridge(async move { db.flush().await }).map_err(Arc::new)?;
        copy_dir_recursive(&self.path, checkpoint_keyspace_dir).map_err(|error| Arc::new(io_error(error)))?;
        Ok(())
    }

    pub(super) fn reset(&self) -> Result<(), Arc<slatedb::Error>> {
        let db = self.db.clone();
        bridge(async move {
            let mut iterator = db.scan_with_options(.., &scan_options()).await?;
            let mut batch = SlateWriteBatch::new();
            let mut any = false;
            while let Some(kv) = iterator.next().await? {
                batch.delete(kv.key);
                any = true;
            }
            if !any {
                return Ok(()); // resetting an empty store is a no-op
            }
            db.write_with_options(batch, &write_options()).await.map(|_write_handle| ())
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
        dir_size(&self.path).unwrap_or(0)
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
        // Arc'd db may still be co-owned by pooled cursors; close only when
        // this is the last keyspace-side owner. Cursor-held Arcs never call
        // close, so closing here is single-shot in practice; failures are
        // ignored — reopen rebuilds from the TypeDB WAL.
        let _ = self.close();
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

fn copy_dir_recursive(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
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
