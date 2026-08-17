/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::{
    iter,
    ops::{Deref, DerefMut},
    sync::atomic::Ordering,
};

use super::{MVCCKey, StorageOperation};
use crate::{
    keyspace::KEYSPACE_MAXIMUM_COUNT,
    sequence_number::SequenceNumber,
    snapshot::{buffer::OperationsBuffer, write::Write},
};

/// One engine-neutral atomic batch for a single keyspace (TB-P7).
///
/// MVCC commits are append-only at the keyspace layer: logical deletes are
/// tombstone-record puts, so a batch is exactly an ordered list of puts. The
/// keyspace converts it into the engine's native batch (RocksDB `WriteBatch`
/// or SlateDB `WriteBatch`) at apply time, preserving order and atomicity.
#[derive(Default)]
pub(crate) struct KeyspaceWriteBatch {
    puts: Vec<(Vec<u8>, Vec<u8>)>,
}

impl KeyspaceWriteBatch {
    pub(crate) fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
        self.puts.push((key.as_ref().to_vec(), value.as_ref().to_vec()));
    }

    pub(crate) fn puts(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.puts
    }
}

pub(crate) struct WriteBatches {
    pub(crate) batches: [Option<KeyspaceWriteBatch>; KEYSPACE_MAXIMUM_COUNT],
}

impl WriteBatches {
    pub(crate) fn from_operations(seq: SequenceNumber, operations: &OperationsBuffer) -> Self {
        let mut write_batches = Self::default();

        for (index, buffer) in operations.write_buffers().enumerate() {
            let writes = buffer.writes();
            if !writes.is_empty() {
                let write_batch = write_batches[index].insert(KeyspaceWriteBatch::default());
                for (key, write) in writes {
                    match write {
                        Write::Insert { value } => {
                            write_batch.put(MVCCKey::build(key, seq, StorageOperation::Insert).bytes(), value)
                        }
                        Write::Put { value, reinsert, .. } => {
                            if reinsert.load(Ordering::SeqCst) {
                                write_batch.put(MVCCKey::build(key, seq, StorageOperation::Insert).bytes(), value)
                            }
                        }
                        Write::Delete => {
                            write_batch.put(MVCCKey::build(key, seq, StorageOperation::Delete).bytes(), [])
                        }
                    }
                }
            }
        }
        write_batches
    }
}

impl IntoIterator for WriteBatches {
    type Item = (usize, KeyspaceWriteBatch);
    type IntoIter = iter::FilterMap<
        iter::Enumerate<<[Option<KeyspaceWriteBatch>; KEYSPACE_MAXIMUM_COUNT] as IntoIterator>::IntoIter>,
        fn((usize, Option<KeyspaceWriteBatch>)) -> Option<(usize, KeyspaceWriteBatch)>,
    >;
    fn into_iter(self) -> Self::IntoIter {
        self.batches.into_iter().enumerate().filter_map(|(index, batch)| Some((index, batch?)))
    }
}

impl Deref for WriteBatches {
    type Target = [Option<KeyspaceWriteBatch>];
    fn deref(&self) -> &Self::Target {
        &self.batches
    }
}

impl DerefMut for WriteBatches {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.batches
    }
}

impl Default for WriteBatches {
    fn default() -> Self {
        Self { batches: std::array::from_fn(|_| None) }
    }
}
