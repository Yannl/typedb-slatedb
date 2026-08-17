/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

pub(crate) use keyspace::{KEYSPACE_MAXIMUM_COUNT, Keyspace, KeyspaceCheckpointError, KeyspaceError, Keyspaces};
pub use keyspace::{KeyspaceDeleteError, KeyspaceId, KeyspaceOpenError, KeyspaceSet, KeyspaceValidationError};
use rocksdb::{DB, DBRawIterator};

use crate::snapshot::pool::{PoolRecycleGuard, Poolable, SinglePool};

mod constants;
pub mod iterator;
mod keyspace;
mod raw_iterator;
pub mod rocks_resources;

/// The SlateDB lane. Compiled only when the `slatedb-backend` feature selects it, so the
/// default build is byte-for-byte the upstream RocksDB path.
#[cfg(feature = "slatedb-backend")]
pub(crate) mod slate;
#[cfg(feature = "slatedb-backend")]
pub(crate) use keyspace::{SLATEDB_CHECKPOINT_DIR, copy_dir_recursive};

/// The error type a backend's iterator yields.
///
/// On the default lane this *is* `rocksdb::Error`, so the U0 build is unchanged down to the
/// type — the alias exists so the SlateDB lane can carry its own error without every caller
/// naming a backend. Introducing a shared wrapper enum instead would have changed U0's
/// error type too, and U0 is the reference the whole comparison is measured against.
/// The batch type callers build writes into.
///
/// Aliased rather than abstracted behind a trait: the only surface `write_batches.rs` uses is
/// `default()` and `put()`, and a trait for two methods would add a vtable and a generic
/// parameter to every caller for no gain.
#[cfg(not(feature = "slatedb-backend"))]
pub(crate) use rocksdb::WriteBatch;
#[cfg(feature = "slatedb-backend")]
pub(crate) use slate::SlateWriteBatch as WriteBatch;

#[cfg(not(feature = "slatedb-backend"))]
pub(crate) type BackendError = rocksdb::Error;
#[cfg(feature = "slatedb-backend")]
pub(crate) type BackendError = slate::SlateKeyspaceError;

#[cfg(not(feature = "slatedb-backend"))]
impl Poolable for DBRawIterator<'static> {}

/// Reuses RocksDB iterators, which are expensive to construct.
///
/// On the SlateDB lane this is deliberately an empty struct rather than a removed parameter:
/// a SlateDB cursor is an `Arc` clone plus a scan, so there is nothing to amortise, but every
/// caller still threads an `&IteratorPool` through. Keeping the type means those callers —
/// and the upstream test files that construct one — are identical on both lanes.
#[cfg(not(feature = "slatedb-backend"))]
#[derive(Default)]
pub struct IteratorPool {
    unprefixed_iterators_per_keyspace: [SinglePool<DBRawIterator<'static>>; KEYSPACE_MAXIMUM_COUNT],
    prefixed_iterators_per_keyspace: [SinglePool<DBRawIterator<'static>>; KEYSPACE_MAXIMUM_COUNT],
}

#[cfg(feature = "slatedb-backend")]
#[derive(Default)]
pub struct IteratorPool;

#[cfg(feature = "slatedb-backend")]
impl IteratorPool {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(feature = "slatedb-backend"))]
impl IteratorPool {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_iterator_unprefixed(&self, keyspace: &Keyspace) -> PoolRecycleGuard<DBRawIterator<'static>> {
        self.unprefixed_iterators_per_keyspace[keyspace.id().0 as usize].get_or_create(|| {
            let kv_storage: &'static DB = unsafe { std::mem::transmute(&keyspace.kv_storage) };
            kv_storage.raw_iterator_opt(keyspace.new_read_options())
        })
    }

    fn get_iterator_prefixed(&self, keyspace: &Keyspace) -> PoolRecycleGuard<DBRawIterator<'static>> {
        self.prefixed_iterators_per_keyspace[keyspace.id().0 as usize].get_or_create(|| {
            let kv_storage: &'static DB = unsafe { std::mem::transmute(&keyspace.kv_storage) };
            let mut read_options = keyspace.new_read_options();
            read_options.set_prefix_same_as_start(true);
            read_options.set_total_order_seek(false);
            kv_storage.raw_iterator_opt(read_options)
        })
    }
}
