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
/// S-01: the controller-provisioned remote-namespace seam (see
/// [`slate::MaterialisationNamespace`]). Exposed as a public seam so the
/// control-plane wiring, when it lands, and a checkpoint recording the backend
/// identity can both derive the object namespace from opaque controller
/// identifiers rather than a host-local path.
pub use slate::MaterialisationNamespace;
// R4-STOR-01: the factory's backend-identity resolution records the NON-SECRET
// S3 binding (endpoint/bucket/prefix) from the same variables the keyspace
// layer binds to — one set of names, re-exported crate-internally.
pub(crate) use slate::{S3_BUCKET_ENV, S3_ENDPOINT_ENV, S3_PREFIX_ENV};

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
