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
    /// Upstream returns `Option<T>` and swallows iteration errors. That is preserved rather
    /// than improved: changing an error into a `None` — or a `None` into an error — would
    /// alter behaviour the conformance corpus is measuring, and this layer's job is to be
    /// invisible.
    pub(crate) fn get_prev<M, T>(&self, key: &[u8], mut mapper: M) -> Option<T>
    where
        M: FnMut(&[u8], &[u8]) -> T,
    {
        self.store
            .keyspace(self.slate_id())
            .get_prev(key)
            .ok()
            .flatten()
            .map(|(k, v)| mapper(&k, v.as_ref()))
    }

    /// Apply a batch to this keyspace atomically.
    pub(crate) fn write(&self, batch: SlateWriteBatch) -> Result<(), SlateKeyspaceError> {
        let mut inner = SlateBatch::new();
        for (key, value) in &batch.puts {
            inner.put(self.slate_id(), key, value);
        }
        self.store.write(inner).map_err(|source| SlateKeyspaceError { name: self.name, source })
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
/// `unsafe transmute` of a borrow into the pool (`keyspace/mod.rs` L36-45). That trick is not
/// reproduced: it is sound there only because the pool outlives every iterator it hands out,
/// and re-deriving that argument for a different store is exactly the kind of reasoning that
/// silently stops holding. This cursor owns an `Arc` to the store instead, which costs one
/// refcount per iterator and needs no unsafe at all.
pub(crate) struct SlateRangeIterator {
    // Field order matters: `iterator` borrows from `store`, so it must drop first.
    iterator: slatedb_keyspace::KeyspaceIterator<'static>,
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
        // SAFETY: `iterator` borrows from the `KeyspaceSet` inside `store`, and `store` is an
        // owned `Arc` field of this struct that is dropped *after* `iterator` (declaration
        // order above). The referent therefore outlives the borrow. The `Arc` is never handed
        // out or mutated, so the address is stable for the struct's lifetime.
        let borrowed: &'static KeyspaceSet = unsafe { std::mem::transmute(store.as_ref()) };
        let iterator = borrowed
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
