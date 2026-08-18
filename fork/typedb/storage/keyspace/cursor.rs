/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::sync::Arc;

use rocksdb::{DB, DBRawIterator, ReadOptions};

use crate::{
    keyspace::slate::{SlateCursor, SlateKeyspace},
    snapshot::pool::Poolable,
};

/// Engine-neutral cursor error: RocksDB errors are cheap values; SlateDB
/// errors are shared behind `Arc` (they are not `Clone`).
#[derive(Debug, Clone)]
pub enum CursorError {
    Rocks(rocksdb::Error),
    Slate(Arc<slatedb::Error>),
}

impl std::fmt::Display for CursorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rocks(error) => write!(f, "{error}"),
            Self::Slate(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for CursorError {}

/// An owned RocksDB cursor.
///
/// The cursor co-owns the database it reads from: the `Arc<DB>` handle is held
/// for as long as the raw iterator exists, so the iterator can never observe a
/// closed database regardless of what happens to the `Keyspace` that created
/// it. This replaces the original design, which forged a `&'static DB` borrow
/// and relied on every pooled iterator being dropped before its keyspace.
///
/// Q-22 hardening: the audited fragility was that the drop ORDER — iterator
/// strictly before `db` — hung on field declaration order, which nothing
/// enforced and any refactor could silently break. The order is now
/// STRUCTURAL: the iterator lives in [`ManuallyDrop`] and the explicit
/// [`Drop`] impl below is the only place it dies, always before `db`.
/// Reordering the fields no longer changes anything.
///
/// SAFETY invariant (enforced by this type, relied upon by the one `unsafe`
/// block in [`RocksCursor::new`] and the one in [`Drop`]):
/// - `iterator` is created from the `DB` owned by `db` and never outlives it:
///   the `DB` heap allocation is stable behind `Arc`, the explicit `Drop`
///   drops the iterator first, and neither field can be moved out (no field
///   is public and the type has a `Drop` impl, which forbids destructuring).
/// - The erased `'static` lifetime never escapes this type's API: every read
///   returns borrows tied to `&self`.
pub(super) struct RocksCursor {
    iterator: std::mem::ManuallyDrop<DBRawIterator<'static>>,
    db: Arc<DB>,
}

impl RocksCursor {
    fn new(db: Arc<DB>, read_options: ReadOptions) -> Self {
        let iterator = db.raw_iterator_opt(read_options);
        // SAFETY: see the type invariant above — the iterator borrows the
        // heap-stable `DB` owned by `db`, which is moved into `self` alongside
        // it and strictly outlives it (explicit Drop order below).
        let iterator = unsafe { std::mem::transmute::<DBRawIterator<'_>, DBRawIterator<'static>>(iterator) };
        Self { iterator: std::mem::ManuallyDrop::new(iterator), db }
    }
}

impl Drop for RocksCursor {
    fn drop(&mut self) {
        // SAFETY: dropped exactly once, here, and nowhere else — and always
        // before `db` (dropped by the compiler after this body), which is
        // the whole point: the borrow the transmute erased ends while the
        // DB it borrows from is still alive, regardless of field order.
        unsafe { std::mem::ManuallyDrop::drop(&mut self.iterator) };
    }
}

/// The pooled cursor handed to range iterators: one variant per keyspace
/// engine, same positioning semantics (seek to first entry >= key, forward
/// advance, read-in-place item).
pub(super) enum RawCursor {
    Rocks(RocksCursor),
    Slate(SlateCursor),
}

impl Poolable for RawCursor {}

impl RawCursor {
    pub(super) fn new_rocks(db: Arc<DB>, read_options: ReadOptions) -> Self {
        Self::Rocks(RocksCursor::new(db, read_options))
    }

    pub(super) fn new_slate(keyspace: &SlateKeyspace) -> Self {
        Self::Slate(SlateCursor::new(keyspace.shared_db()))
    }

    /// True if this cursor reads from the same engine instance as `keyspace`.
    pub(super) fn reads_from(&self, keyspace: &super::keyspace::Keyspace) -> bool {
        match (self, keyspace.engine()) {
            (Self::Rocks(cursor), super::keyspace::KeyspaceEngine::Rocks { db, .. }) => Arc::ptr_eq(&cursor.db, db),
            (Self::Slate(cursor), super::keyspace::KeyspaceEngine::Slate(slate)) => {
                cursor.reads_from(&slate.shared_db())
            }
            _ => false,
        }
    }

    pub(super) fn seek(&mut self, key: &[u8]) {
        match self {
            Self::Rocks(cursor) => cursor.iterator.seek(key),
            Self::Slate(cursor) => cursor.seek(key),
        }
    }

    pub(super) fn advance(&mut self) {
        match self {
            Self::Rocks(cursor) => cursor.iterator.next(),
            Self::Slate(cursor) => cursor.advance(),
        }
    }

    pub(super) fn item(&self) -> Option<(&[u8], &[u8])> {
        match self {
            Self::Rocks(cursor) => cursor.iterator.item(),
            Self::Slate(cursor) => cursor.item(),
        }
    }

    pub(super) fn key(&self) -> Option<&[u8]> {
        match self {
            Self::Rocks(cursor) => cursor.iterator.key(),
            Self::Slate(cursor) => cursor.key(),
        }
    }

    pub(super) fn status(&self) -> Result<(), CursorError> {
        match self {
            Self::Rocks(cursor) => cursor.iterator.status().map_err(CursorError::Rocks),
            Self::Slate(cursor) => cursor.status().map_err(CursorError::Slate),
        }
    }
}

#[cfg(test)]
mod rocks_cursor_tests {
    use std::sync::Arc;

    use rocksdb::{DB, Options, ReadOptions};

    use super::RocksCursor;

    /// Q-22 control: the cursor CO-OWNS the database. Dropping every other
    /// handle while the cursor is live must leave it fully readable — the
    /// use-after-free the original `&'static` forgery permitted is exactly
    /// what this exercises.
    #[test]
    fn a_cursor_keeps_its_database_alive_after_every_other_handle_is_gone() {
        let dir = test_utils::create_tmp_dir("rocks-cursor-ownership");
        let mut options = Options::default();
        options.create_if_missing(true);
        let db = Arc::new(DB::open(&options, &*dir).unwrap());
        db.put(b"k1", b"v1").unwrap();
        db.put(b"k2", b"v2").unwrap();

        let mut cursor = RocksCursor::new(db.clone(), ReadOptions::default());
        drop(db); // the cursor's Arc is now the ONLY owner

        cursor.iterator.seek(b"k1");
        assert_eq!(cursor.iterator.item(), Some((&b"k1"[..], &b"v1"[..])));
        cursor.iterator.next();
        assert_eq!(cursor.iterator.item(), Some((&b"k2"[..], &b"v2"[..])));
        cursor.iterator.status().unwrap();
        // and the drop path runs iterator-then-db in that order, structurally
        drop(cursor);
    }
}
