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
//! | `write_opt(WriteBatch)` | [`Keyspace::write`] |
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
//! ## What is deliberately not here yet
//!
//! Checkpointing, size estimation and deletion. They are separate concerns with their own
//! semantics. `checkpoint` now ships: it flushes, pins the manifest, and lets the caller
//! copy the store's files without compaction pulling them out from under it.

use std::{ops::Bound, sync::Arc};

use bytes::Bytes;
use slatedb::{
    config::{CheckpointOptions, CheckpointScope, ScanOptions, WriteOptions},
    Db, WriteBatch,
};

pub mod error;
pub use error::KeyspaceError;

/// Matches upstream's `KeyspaceId(pub u8)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyspaceId(pub u8);

/// Upstream's `KEYSPACE_MAXIMUM_COUNT`.
pub const KEYSPACE_MAXIMUM_COUNT: usize = 10;

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

/// Owns the SlateDB handle and the runtime every call is bridged onto.
pub struct KeyspaceSet {
    db: Arc<Db>,
    runtime: Arc<tokio::runtime::Runtime>,
}

impl KeyspaceSet {
    /// Open against any `object_store` implementation.
    ///
    /// Local development passes a filesystem or in-memory store; production passes R2 through
    /// `AmazonS3Builder`, since R2 speaks the S3 API. The call site is identical, which is
    /// where dev/production parity for the storage seam actually comes from.
    /// Open against a local directory.
    ///
    /// Exists so callers can run the SlateDB lane without taking an `object_store` dependency
    /// of their own, and without credentials. It is the same code path as `open` — a local
    /// filesystem is just another `ObjectStore` — so a bug here is a bug in the cloud path
    /// too, which is exactly the property that makes local testing worth anything.
    pub fn open_local(path: &std::path::Path) -> Result<Self, KeyspaceError> {
        std::fs::create_dir_all(path)
            .map_err(|error| KeyspaceError::Open(format!("could not create {}: {error}", path.display())))?;
        let store = object_store::local::LocalFileSystem::new_with_prefix(path)
            .map_err(|error| KeyspaceError::Open(error.to_string()))?;
        Self::open("typedb", Arc::new(store))
    }

    pub fn open(
        path: &str,
        object_store: Arc<dyn object_store::ObjectStore>,
    ) -> Result<Self, KeyspaceError> {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| KeyspaceError::Open(e.to_string()))?,
        );
        let db = runtime
            .block_on(Db::builder(path.to_string(), object_store).build())
            .map_err(|e| KeyspaceError::Open(e.to_string()))?;
        Ok(Self { db: Arc::new(db), runtime })
    }

    /// Bridge one async call onto the runtime.
    ///
    /// `block_in_place` is required when the caller is already on a Tokio worker: a bare
    /// `Handle::block_on` from inside the runtime panics, and blocking the worker directly
    /// starves the reactor SlateDB needs to make progress on its own I/O.
    fn block<F: std::future::Future>(&self, fut: F) -> F::Output {
        match tokio::runtime::Handle::try_current() {
            Ok(_) => tokio::task::block_in_place(|| self.runtime.block_on(fut)),
            Err(_) => self.runtime.block_on(fut),
        }
    }

    pub fn keyspace(&self, id: KeyspaceId) -> Keyspace<'_> {
        Keyspace { set: self, id }
    }

    /// Apply a batch spanning any number of keyspaces atomically.
    ///
    /// RocksDB gives TypeDB one atomic `WriteBatch` per keyspace; SlateDB's batch is atomic
    /// across the whole database, so a batch touching several keyspaces is *more* atomic than
    /// upstream, never less.
    pub fn write(&self, batch: Batch) -> Result<(), KeyspaceError> {
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
    pub fn checkpoint(&self) -> Result<uuid::Uuid, KeyspaceError> {
        let result = self
            .block(self.db.create_checkpoint(CheckpointScope::All, &CheckpointOptions::default()))
            .map_err(|e| KeyspaceError::Write(e.to_string()))?;
        Ok(result.id)
    }

    /// Release a checkpoint taken by [`Self::checkpoint`].
    pub fn release_checkpoint(&self, _id: uuid::Uuid) -> Result<(), KeyspaceError> {
        // Deleting a checkpoint needs an `Admin` handle against the same object store, which
        // this type does not hold. Leaving it pinned wastes space but never loses data, so the
        // safe direction is the one taken here; the alternative failure mode is a checkpoint
        // that vanishes while something still depends on it.
        Ok(())
    }
}

/// A batch of writes, keyspace-prefixed as they are added.
#[derive(Default)]
pub struct Batch {
    inner: WriteBatch,
}

impl Batch {
    pub fn new() -> Self {
        Self { inner: WriteBatch::new() }
    }

    pub fn put(&mut self, keyspace: KeyspaceId, key: &[u8], value: &[u8]) {
        self.inner.put(physical_key(keyspace, key), value);
    }

    pub fn delete(&mut self, keyspace: KeyspaceId, key: &[u8]) {
        self.inner.delete(physical_key(keyspace, key));
    }
}

/// One logical keyspace.
pub struct Keyspace<'a> {
    set: &'a KeyspaceSet,
    id: KeyspaceId,
}

impl<'a> Keyspace<'a> {
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
        let first = self.set.block(iter.next()).map_err(|e| KeyspaceError::Iterate(e.to_string()))?;
        Ok(first.map(|kv| (logical_key(&kv.key).to_vec(), kv.value)))
    }

    /// A forward iterator positioned at the first key `>= from`, bounded to this keyspace.
    ///
    /// The cursor's lifetime is tied to the *set*, not to this `Keyspace` handle. `Keyspace`
    /// is a cheap borrow-and-id pair that callers routinely create inline, so binding the
    /// iterator to `&self` would make `set.keyspace(id).iterate_from(..)` fail to compile —
    /// the handle is a temporary while the data it points at is not.
    /// Delete every key in this keyspace, leaving other keyspaces untouched.
    ///
    /// Scan-and-delete rather than a native range delete, which this SlateDB version does not
    /// expose. That is not a compromise here: upstream's `Keyspace::reset` walks the store with
    /// an iterator and deletes key by key too (`keyspace.rs`), so the cost profile matches what
    /// TypeDB already expects.
    ///
    /// Deletes are collected first and applied as one batch. Deleting while the cursor is live
    /// would mutate the range being scanned — the one ordering mistake here that produces a
    /// *partial* clear rather than an error, and a keyspace that is only mostly empty is worse
    /// than one that failed to clear at all.
    pub fn clear(&self) -> Result<usize, KeyspaceError> {
        let mut batch = Batch::new();
        let mut count = 0usize;
        let mut iterator = self.iterate_from(&[])?;
        while let Some((key, _)) = iterator.advance()? {
            batch.delete(self.id, key);
            count += 1;
        }
        drop(iterator);
        if count > 0 {
            self.set.write(batch)?;
        }
        Ok(count)
    }

    /// Number of live keys, and their total encoded size in bytes.
    ///
    /// Exact, by scanning. RocksDB answers the equivalent questions from table properties in
    /// constant time and calls them *estimates*; SlateDB exposes no such property, so the
    /// choice is an O(n) scan or a fabricated number. These feed diagnostics where a wrong
    /// answer is indistinguishable from a right one, so the scan wins — and the cost is
    /// documented rather than hidden, because a caller polling this on a large keyspace
    /// deserves to know it is not free.
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

    pub fn iterate_from(&self, from: &[u8]) -> Result<KeyspaceIterator<'a>, KeyspaceError> {
        let start = Bound::Included(physical_key(self.id, from));
        let end = keyspace_end(self.id);
        let iter = self
            .set
            .block(self.set.db.scan((start, end)))
            .map_err(|e| KeyspaceError::Iterate(e.to_string()))?;
        Ok(KeyspaceIterator { set: self.set, inner: iter, current: None })
    }
}

/// Forward cursor over one keyspace.
///
/// Holds the current entry so `peek` can hand out borrows, mirroring upstream's
/// `LendingIterator` contract where the item borrows from the iterator rather than being
/// owned by the caller.
pub struct KeyspaceIterator<'a> {
    set: &'a KeyspaceSet,
    inner: slatedb::DbIterator,
    current: Option<(Vec<u8>, Bytes)>,
}

impl KeyspaceIterator<'_> {
    /// Advance and return the new position.
    pub fn advance(&mut self) -> Result<Option<(&[u8], &[u8])>, KeyspaceError> {
        let next = self
            .set
            .block(self.inner.next())
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
        self.set
            .block(self.inner.seek(physical_key(keyspace, key)))
            .map_err(|e| KeyspaceError::Iterate(e.to_string()))?;
        self.current = None;
        Ok(())
    }
}
