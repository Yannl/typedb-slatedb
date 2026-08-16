/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::{cmp::Ordering, mem, mem::transmute};

use lending_iterator::{LendingIterator, Seekable};
use resource::profile::StorageCounters;
#[cfg(not(feature = "slatedb-backend"))]
use rocksdb::DBRawIterator;

#[cfg(not(feature = "slatedb-backend"))]
use crate::snapshot::pool::PoolRecycleGuard;

type KeyValue<'a> = (&'a [u8], &'a [u8]);

enum IteratorItemState {
    None,
    Some(KeyValue<'static>),
    Finished,
    Err(rocksdb::Error),
}

impl IteratorItemState {
    const fn is_none(&self) -> bool {
        matches!(self, IteratorItemState::None)
    }

    #[inline]
    pub fn take_value_else_retain(&mut self) -> Self {
        // this method protects us from losing the Finished or Error state
        match self {
            IteratorItemState::None => {
                // unchanged
                Self::None
            }
            IteratorItemState::Some(_) => mem::replace(self, IteratorItemState::None),
            IteratorItemState::Finished => {
                // unchanged, keep finished
                Self::Finished
            }
            IteratorItemState::Err(err) => Self::Err(err.clone()),
        }
    }
}

/// SAFETY NOTE: `'static` here represents that the `DBIterator` owns the data.
/// The item's lifetime is in fact invalidated when `iterator` is advanced.
#[cfg(not(feature = "slatedb-backend"))]
pub(super) struct DBIterator {
    iterator: PoolRecycleGuard<DBRawIterator<'static>>,
    storage_counters: StorageCounters,
    // NOTE: when item is empty, that means that the kv pair the Rocks iterator _is currently pointing to_
    //       has been yielded to the user, and the underlying iterator needs to be advanced before  reading
    state: IteratorItemState,
}

#[cfg(not(feature = "slatedb-backend"))]
impl DBIterator {
    pub(super) fn new_from(
        mut iterator: PoolRecycleGuard<DBRawIterator<'static>>,
        start: &[u8],
        storage_counters: StorageCounters,
    ) -> Self {
        iterator.seek(start);
        storage_counters.increment_raw_seek();
        let mut this = Self { iterator, state: IteratorItemState::None, storage_counters };
        this.record_iterator_state(); // initialise with the first state read from the seek'ed value
        this
    }

    pub(super) fn peek(&mut self) -> Option<<Self as LendingIterator>::Item<'_>> {
        let state = self.next_internal();
        self.state = state;
        match &self.state {
            IteratorItemState::None => unreachable!("State after internal check should be error, Some, or Finished"),
            IteratorItemState::Some(kv) => Some(Ok(*kv)),
            IteratorItemState::Finished => None,
            IteratorItemState::Err(err) => Some(Err(err.clone())),
        }
    }

    fn next_internal(&mut self) -> IteratorItemState {
        if !self.state.is_none() {
            self.state.take_value_else_retain()
        } else {
            self.storage_counters.increment_raw_advance();
            self.iterator.next();
            self.record_iterator_state();
            self.state.take_value_else_retain()
        }
    }

    fn record_iterator_state(&mut self) {
        self.state = match self.iterator.item() {
            None => match self.iterator.status() {
                Ok(_) => IteratorItemState::Finished,
                Err(err) => IteratorItemState::Err(err),
            },
            Some(item) => {
                let kv = unsafe { transmute::<KeyValue<'_>, KeyValue<'static>>(item) };
                IteratorItemState::Some(kv)
            }
        }
    }
}

#[cfg(not(feature = "slatedb-backend"))]
impl LendingIterator for DBIterator {
    type Item<'a>
        = Result<(&'a [u8], &'a [u8]), rocksdb::Error>
    where
        Self: 'a;

    fn next(&mut self) -> Option<Self::Item<'_>> {
        let next_state = self.next_internal();
        match next_state {
            IteratorItemState::None => unreachable!("State after internal check should be error, Some, or Finished"),
            IteratorItemState::Some(kv) => Some(Ok(kv)),
            IteratorItemState::Finished => None,
            IteratorItemState::Err(err) => Some(Err(err)),
        }
    }
}

#[cfg(not(feature = "slatedb-backend"))]
impl Seekable<[u8]> for DBIterator {
    fn seek(&mut self, key: &[u8]) {
        if matches!(&self.state, IteratorItemState::Finished) {
            return;
        } else if let IteratorItemState::Some((item_key, _)) = &self.state {
            match (*item_key).cmp(key) {
                Ordering::Less => {
                    // fall through
                }
                Ordering::Equal => {
                    return;
                }
                Ordering::Greater => {
                    unreachable!("Cannot seek DBIterator to a value ordered behind the current item")
                }
            }
        }
        self.state.take_value_else_retain();
        self.iterator.seek(key);
        self.storage_counters.increment_raw_seek();
        self.record_iterator_state()
    }

    fn compare_key(&self, item: &Self::Item<'_>, key: &[u8]) -> Ordering {
        compare_key(item, key)
    }
}

pub(super) fn compare_key<E>(item: &Result<(&[u8], &[u8]), E>, key: &[u8]) -> Ordering {
    if let Ok(item) = item {
        let (peek, _) = item;
        peek.cmp(&key)
    } else {
        Ordering::Equal
    }
}

// ---------------------------------------------------------------------------------------
// SlateDB lane
// ---------------------------------------------------------------------------------------
//
// Same name, same methods, same `LendingIterator`/`Seekable` contract as the RocksDB
// `DBIterator` above, so `KeyspaceRangeIterator` is unchanged between lanes. Keeping the two
// as separate `#[cfg]` types rather than one runtime enum means the default build carries no
// dispatch and no SlateDB code at all — U0 stays exactly upstream's binary.

/// The SlateDB lane's item state.
///
/// A separate enum rather than a reuse of `IteratorItemState`: that one holds
/// `rocksdb::Error`, and widening it to a shared type would have changed U0's error type.
/// U0 is the reference the whole comparison is measured against, so it stays untouched even
/// at the cost of a near-duplicate here.
#[cfg(feature = "slatedb-backend")]
enum SlateItemState {
    None,
    Some(KeyValue<'static>),
    Finished,
    Err(super::slate::SlateKeyspaceError),
}

#[cfg(feature = "slatedb-backend")]
impl SlateItemState {
    const fn is_none(&self) -> bool {
        matches!(self, SlateItemState::None)
    }

    /// Yield a value once, but never lose a `Finished` or `Err` — the same contract as the
    /// RocksDB lane's `take_value_else_retain`, and the same reason: dropping a terminal
    /// state turns a failed iteration into a silently short one.
    fn take_value_else_retain(&mut self) -> Self {
        match self {
            SlateItemState::None => Self::None,
            SlateItemState::Some(_) => mem::replace(self, SlateItemState::None),
            SlateItemState::Finished => Self::Finished,
            SlateItemState::Err(err) => Self::Err(err.clone()),
        }
    }
}

/// Cursor over a SlateDB-backed keyspace.
///
/// The state machine mirrors the RocksDB one deliberately, including the subtle part: an
/// empty `state` means the pair the cursor currently points at has already been yielded and
/// the underlying iterator must advance before the next read. Getting that wrong yields every
/// row twice, which no type would have caught.
#[cfg(feature = "slatedb-backend")]
pub(super) struct DBIterator {
    iterator: super::slate::SlateRangeIterator,
    storage_counters: StorageCounters,
    state: SlateItemState,
}

#[cfg(feature = "slatedb-backend")]
impl DBIterator {
    pub(super) fn new_from(
        mut iterator: super::slate::SlateRangeIterator,
        storage_counters: StorageCounters,
    ) -> Self {
        // The cursor is already positioned at the seek key by `iterate_from`, so the initial
        // read is an `advance` into the first item rather than a seek.
        storage_counters.increment_raw_seek();
        let state = Self::read_state(&mut iterator);
        Self { iterator, storage_counters, state }
    }

    fn read_state(iterator: &mut super::slate::SlateRangeIterator) -> SlateItemState {
        match iterator.advance() {
            Err(err) => SlateItemState::Err(err),
            Ok(None) => SlateItemState::Finished,
            Ok(Some(item)) => {
                // SAFETY: the borrow is into the cursor's own current-entry buffer, which
                // lives until the next `advance`. This mirrors upstream's contract exactly —
                // "`'static` here represents that the `DBIterator` owns the data. The item's
                // lifetime is in fact invalidated when `iterator` is advanced." The state is
                // always consumed before the next advance, by `take_value_else_retain`.
                let kv = unsafe { transmute::<KeyValue<'_>, KeyValue<'static>>(item) };
                SlateItemState::Some(kv)
            }
        }
    }

    pub(super) fn peek(&mut self) -> Option<<Self as LendingIterator>::Item<'_>> {
        let state = self.next_internal();
        self.state = state;
        match &self.state {
            SlateItemState::None => unreachable!("State after internal check should be error, Some, or Finished"),
            SlateItemState::Some(kv) => Some(Ok(*kv)),
            SlateItemState::Finished => None,
            SlateItemState::Err(err) => Some(Err(err.clone())),
        }
    }

    fn next_internal(&mut self) -> SlateItemState {
        if !self.state.is_none() {
            self.state.take_value_else_retain()
        } else {
            self.storage_counters.increment_raw_advance();
            self.state = Self::read_state(&mut self.iterator);
            self.state.take_value_else_retain()
        }
    }
}

#[cfg(feature = "slatedb-backend")]
impl LendingIterator for DBIterator {
    type Item<'a>
        = Result<(&'a [u8], &'a [u8]), super::slate::SlateKeyspaceError>
    where
        Self: 'a;

    fn next(&mut self) -> Option<Self::Item<'_>> {
        match self.next_internal() {
            SlateItemState::None => unreachable!("State after internal advance should never be None"),
            SlateItemState::Some(kv) => Some(Ok(kv)),
            SlateItemState::Finished => None,
            SlateItemState::Err(err) => Some(Err(err)),
        }
    }
}

#[cfg(feature = "slatedb-backend")]
impl Seekable<[u8]> for DBIterator {
    fn seek(&mut self, key: &[u8]) {
        // Forward-only, matching the RocksDB lane's precondition. Seeking backwards is a bug
        // in the caller, and upstream makes that `unreachable!` rather than silently
        // repositioning — preserved here so a caller error surfaces identically on both lanes.
        if let SlateItemState::Some((item_key, _)) = &self.state {
            match (*item_key).cmp(key) {
                Ordering::Less => {}
                Ordering::Equal => return,
                Ordering::Greater => {
                    unreachable!("Cannot seek DBIterator to a value ordered behind the current item")
                }
            }
        }
        // Advance until at or past the key. SlateDB's cursor has its own `seek`, but reusing
        // it here would bypass the state machine above and lose the already-read item.
        loop {
            match self.next_internal() {
                SlateItemState::Some((k, v)) => {
                    if k >= key {
                        self.state = SlateItemState::Some((k, v));
                        return;
                    }
                }
                other => {
                    self.state = other;
                    return;
                }
            }
        }
    }

    fn compare_key(&self, item: &Self::Item<'_>, key: &[u8]) -> Ordering {
        match item {
            Ok((k, _)) => (*k).cmp(key),
            Err(_) => Ordering::Equal,
        }
    }
}
