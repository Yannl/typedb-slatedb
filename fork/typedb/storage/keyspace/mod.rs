/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

pub use engine::KeyspaceTuningProfile;
pub(crate) use keyspace::{KEYSPACE_MAXIMUM_COUNT, Keyspace, KeyspaceCheckpointError, KeyspaceError, Keyspaces};
pub use keyspace::{KeyspaceDeleteError, KeyspaceId, KeyspaceOpenError, KeyspaceSet, KeyspaceValidationError};

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
            .get_or_create(|| RawCursor::new(keyspace.shared_db(), keyspace.new_read_options()));
        debug_assert!(cursor.reads_from(&keyspace.kv_storage), "pooled cursor recycled across database instances");
        cursor
    }

    fn get_iterator_prefixed(&self, keyspace: &Keyspace) -> PoolRecycleGuard<RawCursor> {
        let cursor = self.prefixed_iterators_per_keyspace[keyspace.id().0 as usize].get_or_create(|| {
            let mut read_options = keyspace.new_read_options();
            read_options.set_prefix_same_as_start(true);
            read_options.set_total_order_seek(false);
            RawCursor::new(keyspace.shared_db(), read_options)
        });
        debug_assert!(cursor.reads_from(&keyspace.kv_storage), "pooled cursor recycled across database instances");
        cursor
    }
}
