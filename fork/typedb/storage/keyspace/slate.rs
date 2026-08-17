/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The SlateDB-backed keyspace: TypeDB's storage layer over object storage.
//!
//! Mirrors [`super::keyspace::Keyspace`]'s operations so the two are interchangeable behind
//! the `slatedb-backend` feature. Selection is central — no upstream test file changes for
//! either lane, which is what brief §22.5 requires and what keeps the U0/U1 comparison
//! measuring the backend rather than the harness.
//!
//! ## What differs from RocksDB, and why it is safe
//!
//! **One store, not N.** RocksDB gives each keyspace its own database directory. SlateDB is a
//! single ordered store, so keys carry a one-byte keyspace prefix. Ordering *within* a
//! keyspace is preserved (the prefix is constant), and ranges between keyspaces are disjoint.
//! The prefix width matches upstream's `KeyspaceId(pub u8)`.
//!
//! **Writes are durable by acknowledgement, not by `fsync`.** Upstream sets
//! `write_options.disable_wal(true)` (`keyspace.rs` L230) because TypeDB keeps its own WAL in
//! the `durability` crate and does not want RocksDB writing a second one. SlateDB also keeps
//! its own WAL, so the same reasoning applies one layer down — and *where the durability
//! point sits* is the open question this backend has to answer before it can claim SF-2. It
//! is not answered here; this layer exposes `flush` so the caller can force it explicitly.
//!
//! **Everything is async underneath.** The bridge lives in `slatedb-keyspace`, not here, so
//! this module stays a plain synchronous shim like the RocksDB one it replaces.

use std::{path::PathBuf, sync::Arc};

use slatedb_keyspace::{Batch as SlateBatch, KeyspaceId as SlateKeyspaceId, KeyspaceSet};

use super::keyspace::{KeyspaceId, KeyspaceSet as KeyspaceSetTrait};

/// Shared handle to the single SlateDB instance backing every keyspace.
///
/// Held by `Keyspaces` and cloned into each `SlateKeyspace`; opening one database per keyspace
/// would multiply object-store round trips and lose cross-keyspace batch atomicity.
pub(crate) type SharedStore = Arc<KeyspaceSet>;

/// One logical keyspace over the shared SlateDB store.
pub(crate) struct SlateKeyspace {
    store: SharedStore,
    name: &'static str,
    id: KeyspaceId,
    prefix_length: Option<usize>,
    path: PathBuf,
}

impl SlateKeyspace {
    pub(crate) fn new(
        store: SharedStore,
        keyspace: impl KeyspaceSetTrait,
        path: PathBuf,
    ) -> Self {
        Self {
            store,
            name: keyspace.name(),
            id: keyspace.id(),
            prefix_length: keyspace.prefix_length(),
            path,
        }
    }

    /// A view onto an already-attached `Keyspace`.
    ///
    /// `Keyspace` holds the store directly rather than a `SlateKeyspace`, so that its field
    /// layout and its `Debug` output stay lane-symmetric. This rebuilds the richer handle for
    /// the duration of one call; the only cost is an `Arc` refcount bump.
    pub(crate) fn from_parts(keyspace: &super::keyspace::Keyspace) -> Self {
        Self {
            store: Arc::clone(&keyspace.store),
            name: keyspace.name(),
            id: keyspace.id(),
            prefix_length: keyspace.prefix_length(),
            path: keyspace.path.clone(),
        }
    }

    fn slate_id(&self) -> SlateKeyspaceId {
        SlateKeyspaceId(self.id.0)
    }

    pub(crate) fn id(&self) -> KeyspaceId {
        self.id
    }

    pub(crate) fn name(&self) -> &'static str {
        self.name
    }

    pub(crate) fn prefix_length(&self) -> Option<usize> {
        self.prefix_length
    }

    pub(crate) fn path(&self) -> &PathBuf {
        &self.path
    }

    pub(crate) fn put(&self, key: &[u8], value: &[u8]) -> Result<(), SlateKeyspaceError> {
        self.store
            .keyspace(self.slate_id())
            .put(key, value)
            .map_err(|source| SlateKeyspaceError { name: self.name, source })
    }

    pub(crate) fn delete(&self, key: &[u8]) -> Result<(), SlateKeyspaceError> {
        self.store
            .keyspace(self.slate_id())
            .delete(key)
            .map_err(|source| SlateKeyspaceError { name: self.name, source })
    }

    /// Mirrors upstream's `get<M, V>(key, mapper)`: the mapper runs on the borrowed value so
    /// callers can avoid a copy when they only need part of it.
    pub(crate) fn get<M, V>(&self, key: &[u8], mut mapper: M) -> Result<Option<V>, SlateKeyspaceError>
    where
        M: FnMut(&[u8]) -> V,
    {
        self.store
            .keyspace(self.slate_id())
            .get(key)
            .map(|opt| opt.map(|value| mapper(value.as_ref())))
            .map_err(|source| SlateKeyspaceError { name: self.name, source })
    }

    /// Mirrors upstream's `get_prev`, i.e. RocksDB `seek_for_prev`: the greatest key `<= key`.
    ///
    /// # Why this panics instead of returning `None`
    ///
    /// Upstream's signature is `Option<T>` with no error channel, and its RocksDB
    /// implementation discards iteration errors into `None`. That is defensible there and
    /// dangerous here, because moving the store to R2 changes an I/O error from
    /// near-impossible to routine while leaving the caller's interpretation of `None`
    /// unchanged.
    ///
    /// The interpretation is the problem. The only caller is the object-id generator
    /// (`vertex_generator.rs`), which seeks back from the maximum id of each type to find the
    /// highest one in use and resumes allocating after it. `None` there means *no vertex of
    /// this type exists*, so it starts from zero. A transient network error that becomes
    /// `None` therefore does not fail the read — it silently reissues object ids that are
    /// already in use, overwriting live data, with no error anywhere and no way to detect it
    /// afterwards.
    ///
    /// A panic on the startup path is a bad outcome; silently corrupting a knowledge base is a
    /// worse one, and unlike the panic it is unrecoverable and undetectable. So the error is
    /// made loud here rather than converted.
    ///
    /// The proper fix is upstream: `Storage::get_prev_raw` should return `Result<Option<T>>`.
    /// Both of its call sites already sit inside functions returning `Result`, so the change
    /// is small — it is simply not this layer's to make unilaterally, since it alters a
    /// signature the RocksDB lane shares.
    pub(crate) fn get_prev<M, T>(&self, key: &[u8], mut mapper: M) -> Option<T>
    where
        M: FnMut(&[u8], &[u8]) -> T,
    {
        match self.store.keyspace(self.slate_id()).get_prev(key) {
            Ok(found) => found.map(|(k, v)| mapper(&k, v.as_ref())),
            Err(error) => panic!(
                "keyspace '{}': seeking backwards failed: {error}. Treating this as \"no such \
                 key\" would let the object-id generator restart from zero and overwrite live \
                 data, so it is raised here instead.",
                self.name
            ),
        }
    }

    /// Apply a batch to this keyspace atomically.
    ///
    /// An empty batch is a successful no-op, because that is what RocksDB does. SlateDB
    /// instead rejects it ("empty write batch not allowed"), and the difference is not
    /// hypothetical: `WriteBatches::from_operations` creates a batch for any keyspace that has
    /// writes, but a batch whose writes are all `Write::Put` with `reinsert == false` emits no
    /// puts at all (`write_batches.rs` L38-42). Under RocksDB that commits as a no-op; without
    /// this guard it fails the commit outright, which is how it surfaced — three concurrency
    /// tests failing with a storage error rather than the conflict they were testing for.
    pub(crate) fn write(&self, batch: SlateWriteBatch) -> Result<(), SlateKeyspaceError> {
        if batch.is_empty() {
            return Ok(());
        }
        let mut inner = SlateBatch::new();
        for (key, value) in &batch.puts {
            inner.put(self.slate_id(), key, value);
        }
        self.store.write(inner).map_err(|source| SlateKeyspaceError { name: self.name, source })
    }

    /// Delete every key in this keyspace, leaving siblings untouched.
    pub(crate) fn clear(&self) -> Result<usize, SlateKeyspaceError> {
        self.store
            .keyspace(self.slate_id())
            .clear()
            .map_err(|source| SlateKeyspaceError { name: self.name, source })
    }

    /// Exact `(key_count, total_bytes)` for this keyspace. O(n) — see the engine's `stats`.
    ///
    /// Use [`Self::estimated_stats`] for anything polled on a timer.
    pub(crate) fn stats(&self) -> Result<(u64, u64), SlateKeyspaceError> {
        self.store
            .keyspace(self.slate_id())
            .stats()
            .map_err(|source| SlateKeyspaceError { name: self.name, source })
    }

    /// `(key_count, total_bytes)` for this keyspace, memoized by the engine.
    pub(crate) fn estimated_stats(&self) -> Result<(u64, u64), SlateKeyspaceError> {
        self.store
            .keyspace(self.slate_id())
            .estimated_stats()
            .map_err(|source| SlateKeyspaceError { name: self.name, source })
    }

    /// Flush every acknowledged write and pin the resulting state so the store's files can be
    /// copied without compaction removing one midway. See the engine's `checkpoint`.
    pub(crate) fn checkpoint(&self) -> Result<(), SlateKeyspaceError> {
        self.store
            .checkpoint()
            .map(|_| ())
            .map_err(|source| SlateKeyspaceError { name: self.name, source })
    }

    /// Force everything acknowledged so far to durable storage.
    pub(crate) fn flush(&self) -> Result<(), SlateKeyspaceError> {
        self.store.flush().map_err(|source| SlateKeyspaceError { name: self.name, source })
    }

    /// Forward cursor positioned at the first key `>= from`, bounded to this keyspace.
    pub(crate) fn iterate_from(&self, from: &[u8]) -> Result<SlateRangeIterator, SlateKeyspaceError> {
        let store = Arc::clone(&self.store);
        let id = self.slate_id();
        // The iterator borrows the store, so the guard keeps it alive for the cursor's life.
        SlateRangeIterator::new(store, id, from, self.name)
    }
}

/// Apply the batches for every keyspace a commit touches as a *single* store write.
///
/// This is the difference between one Class A operation per commit and one per keyspace the
/// commit happens to touch, and it is the highest-frequency path in the system.
///
/// Upstream loops: `Keyspaces::write` calls `Keyspace::write` once per keyspace, because on
/// RocksDB each keyspace is a separate database and there is no other option. Reproducing that
/// loop against SlateDB would keep the shape while discarding the reason for it — every
/// keyspace here lives in one store, so N calls are N writes to the same place. TypeDB defines
/// eight keyspaces and a schema-touching commit writes several at once, so the loop costs
/// close to an order of magnitude in write operations on the hottest path, and buys nothing.
///
/// The resulting cross-keyspace atomicity is a consequence rather than a goal. It is safe in
/// the direction that matters: a commit landing whole rather than in pieces leaves strictly
/// less for TypeDB's WAL replay to reconcile, and no correct caller can depend on observing a
/// partial commit it would have had to repair anyway.
pub(crate) fn write_coalesced(
    store: &SharedStore,
    batches: impl IntoIterator<Item = (SlateKeyspaceId, SlateWriteBatch)>,
) -> Result<(), SlateKeyspaceError> {
    let mut combined = SlateBatch::new();
    for (id, batch) in batches {
        for (key, value) in &batch.puts {
            combined.put(id, key, value);
        }
    }
    // An all-empty commit is a successful no-op, as it is on RocksDB. `WriteBatches` really
    // does produce them: a batch whose writes are all `Write::Put` with `reinsert == false`
    // emits no puts at all (`write_batches.rs` L38-42). The engine's `write` absorbs this, but
    // relying on that silently would leave the guarantee undocumented at the site that needs
    // it — without it, three concurrency tests fail with a storage error rather than the
    // conflict they were written to detect.
    //
    // The write spans keyspaces, so no single one is at fault when it fails; naming the store
    // is more honest than attributing the failure to whichever keyspace happened to be first.
    store.write(combined).map_err(|source| SlateKeyspaceError { name: "<store>", source })
}

/// A batch of writes destined for a single keyspace.
///
/// Shaped to match the subset of `rocksdb::WriteBatch` that `write_batches.rs` actually uses —
/// `default()` and `put()` — so that file needs only its import switched.
///
/// Deliberately *not* cross-keyspace, even though SlateDB could do that. Upstream's
/// `Keyspaces::write` loops over keyspaces and writes each batch separately
/// (`keyspace.rs` L119-125), so RocksDB gives no cross-keyspace atomicity either; TypeDB
/// gets that from its own WAL in the `durability` crate. Making the SlateDB lane atomic
/// where the RocksDB lane is not would be an upgrade, and an upgrade is still a behaviour
/// difference — the comparison would stop measuring the backend and start measuring my
/// improvement. Matching upstream is the whole job.
///
/// Note also that deletes never appear here: MVCC encodes a delete as a put of a tombstone
/// key with an empty value (`write_batches.rs` L45), so `put` is the only operation needed.
#[derive(Default)]
pub(crate) struct SlateWriteBatch {
    puts: Vec<(Vec<u8>, Vec<u8>)>,
}

impl SlateWriteBatch {
    pub(crate) fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
        self.puts.push((key.as_ref().to_vec(), value.as_ref().to_vec()));
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.puts.is_empty()
    }
}

/// Owning cursor over one keyspace.
///
/// Upstream's `DBIterator` pools `DBRawIterator<'static>` and reaches `'static` through an
/// `unsafe transmute` of a borrow into the pool (`keyspace/mod.rs` L36-45). Nothing equivalent
/// is needed here, and the reason is worth stating because the obvious reading of the engine's
/// API suggests otherwise: `slatedb::DbIterator` carries no lifetime parameter at all — it
/// borrows nothing from the `Db` that produced it — so the engine's cursor owns an `Arc` to
/// the runtime and is already `'static`. There is no borrow to launder.
///
/// An earlier version of this file did transmute a `&KeyspaceSet` to `&'static` to satisfy a
/// lifetime the engine no longer asks for. It was sound, by an argument about field drop
/// order that had to be re-derived by every future reader. Deleting the borrow was cheaper
/// than maintaining the argument.
pub(crate) struct SlateRangeIterator {
    iterator: slatedb_keyspace::KeyspaceIterator,
    /// Keeps the store open for the cursor's life. The cursor no longer borrows from it, but
    /// dropping the last handle would still close the database out from under an open scan.
    _store: SharedStore,
    keyspace_name: &'static str,
    finished: bool,
}

impl SlateRangeIterator {
    fn new(
        store: SharedStore,
        id: SlateKeyspaceId,
        from: &[u8],
        keyspace_name: &'static str,
    ) -> Result<Self, SlateKeyspaceError> {
        let iterator = store
            .keyspace(id)
            .iterate_from(from)
            .map_err(|source| SlateKeyspaceError { name: keyspace_name, source })?;
        Ok(Self { iterator, _store: store, keyspace_name, finished: false })
    }

    /// Advance, returning the new position or `None` at the end.
    pub(crate) fn advance(&mut self) -> Result<Option<(&[u8], &[u8])>, SlateKeyspaceError> {
        if self.finished {
            return Ok(None);
        }
        let name = self.keyspace_name;
        let item = self
            .iterator
            .advance()
            .map_err(|source| SlateKeyspaceError { name, source })?;
        if item.is_none() {
            self.finished = true;
        }
        Ok(self.iterator.peek())
    }

    pub(crate) fn peek(&self) -> Option<(&[u8], &[u8])> {
        self.iterator.peek()
    }
}

/// `Clone` is required because `IteratorItemState` clones the error to preserve it across
/// `take_value_else_retain` — a state machine that must not lose an error by yielding it once.
#[derive(Debug, Clone)]
pub struct SlateKeyspaceError {
    pub name: &'static str,
    pub source: slatedb_keyspace::KeyspaceError,
}

impl std::fmt::Display for SlateKeyspaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "keyspace '{}': {}", self.name, self.source)
    }
}

impl std::error::Error for SlateKeyspaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
