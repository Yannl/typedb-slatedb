/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

pub use cursor::CursorError;
pub use engine::KeyspaceTuningProfile;
pub(crate) use keyspace::{KEYSPACE_MAXIMUM_COUNT, Keyspace, KeyspaceCheckpointError, KeyspaceError, Keyspaces};
pub use keyspace::{
    KeyspaceDeleteError, KeyspaceId, KeyspaceOpenError, KeyspaceSet, KeyspaceValidationError, StorageBackend,
};

use crate::{
    keyspace::cursor::RawCursor,
    snapshot::pool::{PoolRecycleGuard, SinglePool},
};

mod constants;
mod cursor;
mod engine;
pub mod iterator;
mod keyspace;
mod raw_iterator;
pub mod rocks_resources;
mod slate;

#[derive(Default)]
pub struct IteratorPool {
    unprefixed_iterators_per_keyspace: [SinglePool<RawCursor>; KEYSPACE_MAXIMUM_COUNT],
    prefixed_iterators_per_keyspace: [SinglePool<RawCursor>; KEYSPACE_MAXIMUM_COUNT],
}

impl IteratorPool {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_iterator_unprefixed(&self, keyspace: &Keyspace) -> PoolRecycleGuard<RawCursor> {
        let cursor = self.unprefixed_iterators_per_keyspace[keyspace.id().0 as usize]
            .get_or_create(|| keyspace.new_raw_cursor(false));
        debug_assert!(cursor.reads_from(keyspace), "pooled cursor recycled across database instances");
        cursor
    }

    fn get_iterator_prefixed(&self, keyspace: &Keyspace) -> PoolRecycleGuard<RawCursor> {
        let cursor = self.prefixed_iterators_per_keyspace[keyspace.id().0 as usize]
            .get_or_create(|| keyspace.new_raw_cursor(true));
        debug_assert!(cursor.reads_from(keyspace), "pooled cursor recycled across database instances");
        cursor
    }
}
