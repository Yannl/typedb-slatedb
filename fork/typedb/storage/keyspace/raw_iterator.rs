/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::cmp::Ordering;

use lending_iterator::{LendingIterator, Seekable};
use resource::profile::StorageCounters;

use crate::{
    keyspace::cursor::{CursorError, RawCursor},
    snapshot::pool::PoolRecycleGuard,
};

/// Position of the underlying cursor relative to what has been yielded.
///
/// Unlike the previous design, no key/value borrow is ever cached here: items
/// are always re-read from the cursor at yield time, so their lifetimes are
/// enforced by the borrow checker instead of a forged `'static` transmute.
enum CursorState {
    /// The item the cursor is positioned on has been yielded to the consumer;
    /// the cursor must be advanced before the next read.
    Consumed,
    /// The cursor is positioned on an item that has not yet been yielded.
    Ready,
    Finished,
    Err(CursorError),
}

pub(super) struct DBIterator {
    cursor: PoolRecycleGuard<RawCursor>,
    storage_counters: StorageCounters,
    state: CursorState,
}

impl DBIterator {
    pub(super) fn new_from(
        mut cursor: PoolRecycleGuard<RawCursor>,
        start: &[u8],
        storage_counters: StorageCounters,
    ) -> Self {
        cursor.seek(start);
        storage_counters.increment_raw_seek();
        let mut this = Self { cursor, state: CursorState::Consumed, storage_counters };
        this.record_cursor_state(); // initialise with the first state read from the seek'ed value
        this
    }

    pub(super) fn peek(&mut self) -> Option<<Self as LendingIterator>::Item<'_>> {
        if matches!(self.state, CursorState::Consumed) {
            self.advance_and_record();
        }
        match &self.state {
            CursorState::Consumed => unreachable!("State after advancing should be error, Ready, or Finished"),
            CursorState::Ready => Some(Ok(self.cursor.item().expect("Ready state implies a current item"))),
            CursorState::Finished => None,
            CursorState::Err(err) => Some(Err(err.clone())),
        }
    }

    fn advance_and_record(&mut self) {
        self.storage_counters.increment_raw_advance();
        self.cursor.advance();
        self.record_cursor_state();
    }

    fn record_cursor_state(&mut self) {
        self.state = if self.cursor.item().is_some() {
            CursorState::Ready
        } else {
            match self.cursor.status() {
                Ok(_) => CursorState::Finished,
                Err(err) => CursorState::Err(err),
            }
        };
    }
}

impl LendingIterator for DBIterator {
    type Item<'a>
        = Result<(&'a [u8], &'a [u8]), CursorError>
    where
        Self: 'a;

    fn next(&mut self) -> Option<Self::Item<'_>> {
        if matches!(self.state, CursorState::Consumed) {
            self.advance_and_record();
        }
        match &self.state {
            CursorState::Consumed => unreachable!("State after advancing should be error, Ready, or Finished"),
            CursorState::Ready => {
                self.state = CursorState::Consumed;
                Some(Ok(self.cursor.item().expect("current item must exist when yielding")))
            }
            CursorState::Finished => None,
            CursorState::Err(err) => Some(Err(err.clone())),
        }
    }
}

impl Seekable<[u8]> for DBIterator {
    fn seek(&mut self, key: &[u8]) {
        match &self.state {
            CursorState::Finished => return,
            CursorState::Ready => {
                let item_key = self.cursor.key().expect("Ready state implies a current item");
                match item_key.cmp(key) {
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
            CursorState::Consumed | CursorState::Err(_) => {
                // fall through
            }
        }
        self.cursor.seek(key);
        self.storage_counters.increment_raw_seek();
        self.record_cursor_state()
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
