/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::{
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
    sync::Arc,
};

use bytes::Bytes;
use fail_point::{KEYSPACE_CHECKPOINT_FAIL, KEYSPACE_DELETE_FAIL, KEYSPACE_OPEN_FAIL, fail_point};
use itertools::Itertools;
use resource::profile::StorageCounters;
#[cfg(not(feature = "slatedb-backend"))]
use rocksdb::{DB, IteratorMode, Options, ReadOptions, WriteOptions, checkpoint::Checkpoint};
use serde::{Deserialize, Serialize};

use super::{IteratorPool, WriteBatch, constants, iterator};
use crate::{key_range::KeyRange, keyspace::rocks_resources::RocksResources, write_batches::WriteBatches};

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyspaceId(pub u8);

impl fmt::Debug for KeyspaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for KeyspaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// WARNING: adjusting these constants affects many things, including serialised WAL records and in-memory data structures.  //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
pub(crate) const KEYSPACE_MAXIMUM_COUNT: usize = 10;
pub(crate) const KEYSPACE_ID_MAX: KeyspaceId = KeyspaceId(KEYSPACE_MAXIMUM_COUNT as u8 - 1);
pub(crate) const KEYSPACE_ID_RESERVED_UNSET: KeyspaceId = KeyspaceId(KEYSPACE_ID_MAX.0 + 1);

pub trait KeyspaceSet: Copy {
    fn iter() -> impl Iterator<Item = Self>;
    fn id(&self) -> KeyspaceId;
    fn name(&self) -> &'static str;
    fn rocks_configuration(&self, _resources: &RocksResources) -> rocksdb::Options {
        let mut options = rocksdb::Options::default();
        options.create_if_missing(true);
        options
    }
    fn prefix_length(&self) -> Option<usize>;
}

#[derive(Debug)]
pub struct Keyspaces {
    keyspaces: Vec<Keyspace>,
    index: [Option<KeyspaceId>; KEYSPACE_MAXIMUM_COUNT],
}

impl Keyspaces {
    pub(crate) fn new() -> Self {
        Self { keyspaces: Vec::new(), index: std::array::from_fn(|_| None) }
    }

    pub(crate) fn open<KS: KeyspaceSet>(
        storage_dir: impl AsRef<Path>,
        resources: &RocksResources,
    ) -> Result<Self, KeyspaceOpenError> {
        let path = storage_dir.as_ref();

        // One store for every keyspace, opened once. RocksDB opens N databases because each
        // keyspace is its own directory; SlateDB keyspaces are prefixes in one ordered space,
        // and opening N stores would multiply object-store round trips and manifest traffic
        // for no benefit.
        //
        // A local filesystem object store is used here so the lane is runnable without cloud
        // credentials. Pointing this at R2 is a one-line change at exactly this call site —
        // which is the point of routing everything through `object_store`.
        #[cfg(feature = "slatedb-backend")]
        let store: super::slate::SharedStore = std::sync::Arc::new(
            slatedb_keyspace::KeyspaceSet::open_local(path)
                .map_err(|error| KeyspaceOpenError::SlateDB { source: error.to_string() })?,
        );

        let mut keyspaces = Keyspaces::new();
        for keyspace in KS::iter() {
            keyspaces
                .validate_new_keyspace(keyspace)
                .map_err(|error| KeyspaceOpenError::Validation { source: error })?;
            fail_point!(KEYSPACE_OPEN_FAIL);
            #[cfg(not(feature = "slatedb-backend"))]
            keyspaces.keyspaces.push(Keyspace::open(path, keyspace, &keyspace.rocks_configuration(resources))?);
            #[cfg(feature = "slatedb-backend")]
            keyspaces.keyspaces.push(Keyspace::attach(path, keyspace, store.clone()));
            keyspaces.index[keyspace.id().0 as usize] = Some(KeyspaceId(keyspaces.keyspaces.len() as u8 - 1));
        }
        Ok(keyspaces)
    }

    fn validate_new_keyspace(&self, keyspace_id: impl KeyspaceSet) -> Result<(), KeyspaceValidationError> {
        use KeyspaceValidationError::{IdExists, IdReserved, IdTooLarge, NameExists};

        let name = keyspace_id.name();

        if keyspace_id.id() == KEYSPACE_ID_RESERVED_UNSET {
            return Err(IdReserved { name, id: keyspace_id.id().0 });
        }

        if keyspace_id.id() > KEYSPACE_ID_MAX {
            return Err(IdTooLarge { name, id: keyspace_id.id().0, max_id: KEYSPACE_ID_MAX.0 });
        }

        for (existing_id, existing_keyspace_index) in self.index.iter().enumerate() {
            if let Some(existing_index) = existing_keyspace_index {
                let keyspace = &self.keyspaces[existing_index.0 as usize];
                if keyspace.name() == name {
                    return Err(NameExists { name });
                }
                if existing_id == keyspace_id.id().0 as usize {
                    return Err(IdExists { new_name: name, id: keyspace_id.id().0, existing_name: keyspace.name() });
                }
            }
        }
        Ok(())
    }

    pub(crate) fn get(&self, keyspace_id: KeyspaceId) -> &Keyspace {
        let keyspace_index = self.index[keyspace_id.0 as usize].unwrap();
        &self.keyspaces[keyspace_index.0 as usize]
    }

    pub(crate) fn write(&self, write_batches: WriteBatches) -> Result<(), KeyspaceError> {
        for (index, write_batch) in write_batches.into_iter() {
            debug_assert!(index < KEYSPACE_MAXIMUM_COUNT);
            self.get(KeyspaceId(index as u8)).write(write_batch)?;
        }
        Ok(())
    }

    pub(crate) fn checkpoint(&self, current_checkpoint_dir: &Path) -> Result<(), KeyspaceCheckpointError> {
        for keyspace in &self.keyspaces {
            fail_point!(KEYSPACE_CHECKPOINT_FAIL);
            keyspace.checkpoint(current_checkpoint_dir)?;
        }
        Ok(())
    }

    pub(crate) fn delete(self) -> Result<(), Vec<KeyspaceDeleteError>> {
        let errors = self
            .keyspaces
            .into_iter()
            .filter_map(|keyspace| {
                fail_point!(KEYSPACE_DELETE_FAIL);
                keyspace.delete().err()
            })
            .collect_vec();
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(())
    }

    /// Clear every keyspace. RocksDB lane only — see `Keyspace::reset`.
    #[cfg(not(feature = "slatedb-backend"))]
    pub(crate) fn reset(&mut self) -> Result<(), KeyspaceError> {
        for keyspace in self.keyspaces.iter_mut() {
            keyspace.reset()?
        }
        Ok(())
    }

    pub fn estimate_size_in_bytes(&self) -> Result<u64, KeyspaceError> {
        self.keyspaces.iter().try_fold(0, |total, keyspace| {
            let size = keyspace.estimate_size_in_bytes()?;
            Ok(total + size)
        })
    }

    pub fn estimate_key_count(&self) -> Result<u64, KeyspaceError> {
        self.keyspaces.iter().try_fold(0, |total, keyspace| {
            let count = keyspace.estimate_key_count()?;
            Ok(total + count)
        })
    }
}

#[derive(Debug, Clone)]
pub enum KeyspaceValidationError {
    IdReserved { name: &'static str, id: u8 },
    IdTooLarge { name: &'static str, id: u8, max_id: u8 },
    NameExists { name: &'static str },
    IdExists { new_name: &'static str, id: u8, existing_name: &'static str },
}

impl fmt::Display for KeyspaceValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameExists { name, .. } => write!(f, "keyspace '{name}' is defined multiple times."),
            Self::IdReserved { name, id, .. } => {
                write!(f, "reserved keyspace id '{id}' cannot be used for new keyspace '{name}'.")
            }
            Self::IdTooLarge { name, id, max_id, .. } => write!(
                f,
                "keyspace id '{id}' cannot be used for new keyspace '{name}' since it is larger than maximum keyspace id '{max_id}'.",
            ),
            Self::IdExists { new_name, id, existing_name, .. } => write!(
                f,
                "keyspace id '{}' cannot be used for new keyspace '{}' since it is already used by keyspace '{}'.",
                id, new_name, existing_name
            ),
        }
    }
}

impl Error for KeyspaceValidationError {}

/// A non-durable key-value store that supports put, get, delete, iterate and checkpointing.
pub(crate) struct Keyspace {
    pub(super) path: PathBuf,
    name: &'static str,
    id: KeyspaceId,
    #[cfg(not(feature = "slatedb-backend"))]
    pub(super) kv_storage: DB,
    #[cfg(not(feature = "slatedb-backend"))]
    read_options: ReadOptions,
    #[cfg(not(feature = "slatedb-backend"))]
    write_options: WriteOptions,
    /// The shared SlateDB store. One store backs every keyspace — see `slate.rs` for why
    /// keyspaces are prefixes of one ordered space rather than separate databases.
    #[cfg(feature = "slatedb-backend")]
    pub(super) store: super::slate::SharedStore,
    prefix_length: Option<usize>,
}

impl Keyspace {
    #[cfg(not(feature = "slatedb-backend"))]
    pub(crate) fn open(
        storage_path: &Path,
        keyspace: impl KeyspaceSet,
        options: &Options,
    ) -> Result<Keyspace, KeyspaceOpenError> {
        use KeyspaceOpenError::RocksDB;
        let name = keyspace.name();
        let path = storage_path.join(name);
        let kv_storage = DB::open(options, &path).map_err(|error| RocksDB { name, source: error })?;
        Ok(Self::new(path, keyspace, kv_storage))
    }

    #[cfg(not(feature = "slatedb-backend"))]
    fn new(path: PathBuf, keyspace: impl KeyspaceSet, kv_storage: DB) -> Self {
        // initial read options, should be customised to this storage's properties
        let read_options = ReadOptions::default();
        let mut write_options = WriteOptions::default();
        write_options.disable_wal(true);
        let prefix_length = keyspace.prefix_length();
        Self { path, name: keyspace.name(), id: keyspace.id(), kv_storage, read_options, write_options, prefix_length }
    }

    /// Attach a keyspace to an already-open shared store.
    ///
    /// Unlike the RocksDB lane there is nothing to open here: the store is opened once by
    /// `Keyspaces::open` and every keyspace is a prefix within it. `path` is kept only so the
    /// `Debug`/`path()` surface matches across lanes; nothing on this lane reads it as a
    /// filesystem location, because on object storage it is not one.
    #[cfg(feature = "slatedb-backend")]
    pub(crate) fn attach(
        storage_path: &Path,
        keyspace: impl KeyspaceSet,
        store: super::slate::SharedStore,
    ) -> Keyspace {
        let name = keyspace.name();
        Self {
            path: storage_path.join(name),
            name,
            id: keyspace.id(),
            store,
            prefix_length: keyspace.prefix_length(),
        }
    }

    #[cfg(not(feature = "slatedb-backend"))]
    pub(super) fn new_read_options(&self) -> ReadOptions {
        let mut options = ReadOptions::default();
        options.set_total_order_seek(true); // Set this to 'false' to use bloom-filters
        options
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

    #[cfg(not(feature = "slatedb-backend"))]
    pub(crate) fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KeyspaceError> {
        self.kv_storage
            .put_opt(key, value, &self.write_options)
            .map_err(|error| KeyspaceError::Put { name: self.name, source: error })
    }

    #[cfg(feature = "slatedb-backend")]
    pub(crate) fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KeyspaceError> {
        super::slate::SlateKeyspace::from_parts(self)
            .put(key, value)
            .map_err(|source| KeyspaceError::Put { name: self.name, source })
    }

    #[cfg(not(feature = "slatedb-backend"))]
    pub(crate) fn get<M, V>(&self, key: &[u8], mut mapper: M) -> Result<Option<V>, KeyspaceError>
    where
        M: FnMut(&[u8]) -> V,
    {
        self.kv_storage
            .get_pinned_opt(key, &self.read_options)
            .map(|option| option.map(|value| mapper(value.as_ref())))
            .map_err(|error| KeyspaceError::Get { name: self.name, source: error })
    }

    #[cfg(feature = "slatedb-backend")]
    pub(crate) fn get<M, V>(&self, key: &[u8], mapper: M) -> Result<Option<V>, KeyspaceError>
    where
        M: FnMut(&[u8]) -> V,
    {
        super::slate::SlateKeyspace::from_parts(self)
            .get(key, mapper)
            .map_err(|source| KeyspaceError::Get { name: self.name, source })
    }

    #[cfg(not(feature = "slatedb-backend"))]
    pub(crate) fn get_prev<M, T>(&self, key: &[u8], mut mapper: M) -> Option<T>
    where
        M: FnMut(&[u8], &[u8]) -> T,
    {
        let mut iterator = self.kv_storage.raw_iterator_opt(self.new_read_options());
        iterator.seek_for_prev(key);
        iterator.item().map(|(k, v)| mapper(k, v))
    }

    #[cfg(feature = "slatedb-backend")]
    pub(crate) fn get_prev<M, T>(&self, key: &[u8], mapper: M) -> Option<T>
    where
        M: FnMut(&[u8], &[u8]) -> T,
    {
        super::slate::SlateKeyspace::from_parts(self).get_prev(key, mapper)
    }

    pub(crate) fn iterate_range<const PREFIX_INLINE_SIZE: usize>(
        &self,
        iterpool: &IteratorPool,
        range: &KeyRange<Bytes<'_, PREFIX_INLINE_SIZE>>,
        storage_counters: StorageCounters,
    ) -> iterator::KeyspaceRangeIterator {
        iterator::KeyspaceRangeIterator::new(self, iterpool, range, storage_counters)
    }

    #[cfg(not(feature = "slatedb-backend"))]
    pub(crate) fn write(&self, write_batch: WriteBatch) -> Result<(), KeyspaceError> {
        self.kv_storage
            .write_opt(write_batch, &self.write_options)
            .map_err(|error| KeyspaceError::BatchWrite { name: self.name, source: error })
    }

    #[cfg(feature = "slatedb-backend")]
    pub(crate) fn write(&self, write_batch: WriteBatch) -> Result<(), KeyspaceError> {
        super::slate::SlateKeyspace::from_parts(self)
            .write(write_batch)
            .map_err(|source| KeyspaceError::BatchWrite { name: self.name, source })
    }

    pub(crate) fn checkpoint(&self, checkpoint_dir: &Path) -> Result<(), KeyspaceCheckpointError> {
        use KeyspaceCheckpointError::{CheckpointExists, CreateRocksDBCheckpoint};

        let checkpoint_dir = checkpoint_dir.join(self.name);
        if checkpoint_dir.exists() {
            return Err(CheckpointExists { name: self.name, dir: checkpoint_dir });
        }

        #[cfg(not(feature = "slatedb-backend"))]
        Checkpoint::new(&self.kv_storage)
            .and_then(|checkpoint| checkpoint.create_checkpoint(&checkpoint_dir))
            .map_err(|error| CreateRocksDBCheckpoint { name: self.name, source: error })?;

        // SlateDB has first-class checkpoints (a named, retained manifest version), but they
        // are a different object from RocksDB's: RocksDB hard-links SSTs into a directory the
        // caller then owns, whereas SlateDB's live inside the store and are referred to by id.
        // Mapping one onto the other decides how TypeDB's recovery path finds a checkpoint,
        // and that is a design question, not a translation. Left explicit rather than guessed.
        #[cfg(feature = "slatedb-backend")]
        {
            let _ = &checkpoint_dir;
            unimplemented!("SlateDB checkpoints are manifest ids, not directories; see slate.rs")
        }

        #[cfg(not(feature = "slatedb-backend"))]
        Ok(())
    }

    pub(crate) fn delete(self) -> Result<(), KeyspaceDeleteError> {
        // On the RocksDB lane the keyspace *is* a directory, so closing the handle and
        // removing it is the whole operation. On SlateDB the keyspace is a key prefix inside a
        // shared store and `self.path` names nothing on disk — removing it would delete an
        // unrelated directory, or silently succeed having deleted nothing. Neither is
        // acceptable, so the SlateDB lane needs a prefix range delete instead.
        #[cfg(feature = "slatedb-backend")]
        {
            drop(self.store);
            unimplemented!("SlateDB keyspace delete needs a prefix range delete; see slate.rs")
        }
        #[cfg(not(feature = "slatedb-backend"))]
        drop(self.kv_storage);
        #[cfg(not(feature = "slatedb-backend"))]
        fs::remove_dir_all(self.path.clone())
            .map_err(|error| KeyspaceDeleteError::DirectoryRemove { name: self.name, source: Arc::new(error) })?;
        Ok(())
    }

    /// Delete every entry in this keyspace.
    ///
    /// RocksDB-only for now: it walks the store with a native iterator. The SlateDB lane needs
    /// a range delete over the keyspace prefix, which is a different operation with different
    /// cost, so it is not faked here — `Keyspace` still owns a `rocksdb::DB` on both lanes and
    /// this method is unreachable on the SlateDB one.
    #[cfg(not(feature = "slatedb-backend"))]
    pub(crate) fn reset(&mut self) -> Result<(), KeyspaceError> {
        let iterator = self.kv_storage.iterator(IteratorMode::Start);
        for entry in iterator {
            let (key, _) = entry.map_err(|err| KeyspaceError::Iterate { name: self.name, source: err })?;
            self.kv_storage.delete(key).map_err(|err| KeyspaceError::Iterate { name: self.name, source: err })?;
        }
        Ok(())
    }

    #[cfg(not(feature = "slatedb-backend"))]
    pub fn estimate_size_in_bytes(&self) -> Result<u64, KeyspaceError> {
        let property_name = constants::rocksdb::PROPERTY_ESTIMATE_LIVE_DATA_SIZE;
        self.kv_storage
            .property_int_value(property_name)
            .map_err(|source| KeyspaceError::Property { name: property_name, source })
            .map(|result_opt| result_opt.unwrap_or(0))
    }

    #[cfg(not(feature = "slatedb-backend"))]
    pub fn estimate_key_count(&self) -> Result<u64, KeyspaceError> {
        let property_name = constants::rocksdb::PROPERTY_ESTIMATE_NUM_KEYS;
        self.kv_storage
            .property_int_value(property_name)
            .map_err(|source| KeyspaceError::Property { name: property_name, source })
            .map(|result_opt| result_opt.unwrap_or(0))
    }

    /// Both estimates read RocksDB table properties, which SlateDB does not expose.
    ///
    /// These feed diagnostics, not correctness, so returning 0 is tempting — and wrong for the
    /// same reason a no-op `reset` is wrong: a plausible-looking zero is indistinguishable from
    /// an empty database, so the diagnostic silently lies rather than visibly failing. Whether
    /// SlateDB can answer these at all is an open question worth answering deliberately.
    #[cfg(feature = "slatedb-backend")]
    pub fn estimate_size_in_bytes(&self) -> Result<u64, KeyspaceError> {
        unimplemented!("SlateDB exposes no live-data-size property; see slate.rs")
    }

    #[cfg(feature = "slatedb-backend")]
    pub fn estimate_key_count(&self) -> Result<u64, KeyspaceError> {
        unimplemented!("SlateDB exposes no key-count property; see slate.rs")
    }
}

impl fmt::Debug for Keyspace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keyspace[name={}, path={:?}, id={}]", self.name, self.path, self.id)
    }
}

#[derive(Debug, Clone)]
pub enum KeyspaceOpenError {
    RocksDB { name: &'static str, source: rocksdb::Error },
    /// Opening the shared SlateDB store failed. Carries a rendered string rather than the
    /// source error because two unrelated error types reach here (`object_store` and
    /// `slatedb`), and neither is worth leaking into this enum's public shape.
    #[cfg(feature = "slatedb-backend")]
    SlateDB { source: String },
    Validation { source: KeyspaceValidationError },
}

impl fmt::Display for KeyspaceOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        error::todo_display_for_error!(f, self)
    }
}

impl Error for KeyspaceOpenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RocksDB { source, .. } => Some(source),
            Self::Validation { source, .. } => Some(source),
            // The rendered string is the whole error; there is no inner source to chain to.
            #[cfg(feature = "slatedb-backend")]
            Self::SlateDB { .. } => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum KeyspaceCheckpointError {
    CheckpointExists { name: &'static str, dir: PathBuf },
    CreateRocksDBCheckpoint { name: &'static str, source: rocksdb::Error },
}

impl fmt::Display for KeyspaceCheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        error::todo_display_for_error!(f, self)
    }
}

impl Error for KeyspaceCheckpointError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CheckpointExists { .. } => None,
            Self::CreateRocksDBCheckpoint { source, .. } => Some(source),
        }
    }
}

#[derive(Debug, Clone)]
pub enum KeyspaceDeleteError {
    DirectoryRemove { name: &'static str, source: Arc<io::Error> },
}

impl fmt::Display for KeyspaceDeleteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        error::todo_display_for_error!(f, self)
    }
}

impl Error for KeyspaceDeleteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self {
            Self::DirectoryRemove { source, .. } => Some(source),
        }
    }
}

#[derive(Clone, Debug)]
pub enum KeyspaceError {
    Get { name: &'static str, source: super::BackendError },
    Put { name: &'static str, source: super::BackendError },
    BatchWrite { name: &'static str, source: super::BackendError },
    // The only KeyspaceError variant whose source crosses the backend boundary: it carries
    // whatever the iterator produced. On the default lane the alias *is* `rocksdb::Error`,
    // so U0's error type is unchanged.
    Iterate { name: &'static str, source: super::BackendError },
    DeleteRange { name: &'static str, source: super::BackendError },
    Property { name: &'static str, source: super::BackendError },
}

impl fmt::Display for KeyspaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        error::todo_display_for_error!(f, self)
    }
}

impl Error for KeyspaceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self {
            Self::Get { source, .. } => Some(source),
            Self::Put { source, .. } => Some(source),
            Self::BatchWrite { source, .. } => Some(source),
            Self::Iterate { source, .. } => Some(source),
            Self::DeleteRange { source, .. } => Some(source),
            Self::Property { source, .. } => Some(source),
        }
    }
}
