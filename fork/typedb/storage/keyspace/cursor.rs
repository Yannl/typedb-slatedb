/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::sync::Arc;

use rocksdb::{DB, DBRawIterator, ReadOptions};

use crate::snapshot::pool::Poolable;

/// An owned RocksDB cursor.
///
/// The cursor co-owns the database it reads from: the `Arc<DB>` handle is held
/// for as long as the raw iterator exists, so the iterator can never observe a
/// closed database regardless of what happens to the `Keyspace` that created
/// it. This replaces the previous design, which forged a `&'static DB` borrow
/// and relied on every pooled iterator being dropped before its keyspace.
///
/// SAFETY invariant (enforced by this type, relied upon by the one `unsafe`
/// block in [`RawCursor::new`]):
/// - `iterator` is created from the `DB` owned by `db` and must never outlive
///   it. The `DB` heap allocation is stable behind `Arc`, `iterator` is
///   declared before `db` so it is dropped first, and neither field can be
///   moved out of this type.
/// - The erased `'static` lifetime never escapes this type's API: every read
///   returns borrows tied to `&self`.
pub(super) struct RawCursor {
    iterator: DBRawIterator<'static>,
    db: Arc<DB>,
}

impl Poolable for RawCursor {}

impl RawCursor {
    pub(super) fn new(db: Arc<DB>, read_options: ReadOptions) -> Self {
        let iterator = db.raw_iterator_opt(read_options);
        // SAFETY: see the type invariant above — the iterator borrows the
        // heap-stable `DB` owned by `db`, which is moved into `self` alongside
        // it and strictly outlives it.
        let iterator =
            unsafe { std::mem::transmute::<DBRawIterator<'_>, DBRawIterator<'static>>(iterator) };
        Self { iterator, db }
    }

    /// True if this cursor reads from the same database instance.
    pub(super) fn reads_from(&self, db: &Arc<DB>) -> bool {
        Arc::ptr_eq(&self.db, db)
    }

    pub(super) fn seek(&mut self, key: &[u8]) {
        self.iterator.seek(key)
    }

    pub(super) fn advance(&mut self) {
        self.iterator.next()
    }

    pub(super) fn item(&self) -> Option<(&[u8], &[u8])> {
        self.iterator.item()
    }

    pub(super) fn key(&self) -> Option<&[u8]> {
        self.iterator.key()
    }

    pub(super) fn status(&self) -> Result<(), rocksdb::Error> {
        self.iterator.status()
    }
}
