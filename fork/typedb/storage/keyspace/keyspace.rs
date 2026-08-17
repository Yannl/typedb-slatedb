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
use rocksdb::{DB, IteratorMode, Options, ReadOptions, WriteBatch, WriteOptions, checkpoint::Checkpoint};
use serde::{Deserialize, Serialize};

use super::{IteratorPool, constants, iterator};
use crate::{
    factory::{StorageBackendProfile, StorageFactoryError, resolved_backend_profile},
    key_range::KeyRange,
    keyspace::{
        cursor::RawCursor,
        engine::{KeyspaceTuningProfile, build_rocks_options},
        rocks_resources::RocksResources,
        slate::SlateKeyspace,
    },
    write_batches::{KeyspaceWriteBatch, WriteBatches},
};

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
    fn tuning_profile(&self) -> KeyspaceTuningProfile {
        KeyspaceTuningProfile::Default
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

        let mut keyspaces = Keyspaces::new();
        for keyspace in KS::iter() {
            keyspaces
                .validate_new_keyspace(keyspace)
                .map_err(|error| KeyspaceOpenError::Validation { source: error })?;
            fail_point!(KEYSPACE_OPEN_FAIL);
            // engine options are only built for the engine actually selected:
            // under U2 the RocksDB tuning (block cache wiring, bloom setup)
            // would be constructed and discarded per keyspace
            let profile = resolved_backend_profile()
                .map_err(|source| KeyspaceOpenError::Factory { name: keyspace.name(), source })?;
            let options = match profile {
                StorageBackendProfile::U0PristineUpstream | StorageBackendProfile::U1ForkRocksFileWal => {
                    build_rocks_options(keyspace.tuning_profile(), keyspace.prefix_length(), resources)
                }
                _ => Options::default(),
            };
            keyspaces.keyspaces.push(Keyspace::open(path, keyspace, &options)?);
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

/// The key-value engine behind one keyspace: RocksDB for the U0/U1 oracle
/// profiles, SlateDB (TB-P7, ADR-0001) for U2. Both are NON-durable stores —
/// engine WALs are off and TypeDB's WAL is the durability authority.
pub(crate) enum KeyspaceEngine {
    Rocks {
        // shared with `RawCursor`s handed out via the `IteratorPool`, which
        // co-own the database so that no cursor can ever observe a closed `DB`
        db: Arc<DB>,
        read_options: ReadOptions,
        write_options: WriteOptions,
    },
    Slate(SlateKeyspace),
}

/// A non-durable key-value store that supports put, get, delete, iterate and checkpointing.
pub(crate) struct Keyspace {
    path: PathBuf,
    name: &'static str,
    id: KeyspaceId,
    engine: KeyspaceEngine,
    prefix_length: Option<usize>,
}

impl Keyspace {
    pub(crate) fn open(
        storage_path: &Path,
        keyspace: impl KeyspaceSet,
        options: &Options,
    ) -> Result<Keyspace, KeyspaceOpenError> {
        use KeyspaceOpenError::{Factory, ProfileUnavailable, RocksDB, SlateDB};
        let name = keyspace.name();
        let path = storage_path.join(name);
        let profile = resolved_backend_profile().map_err(|source| Factory { name, source })?;
        let engine = match profile {
            StorageBackendProfile::U0PristineUpstream | StorageBackendProfile::U1ForkRocksFileWal => {
                let db = DB::open(options, &path).map_err(|error| RocksDB { name, source: error })?;
                // initial read options, should be customised to this storage's properties
                let read_options = ReadOptions::default();
                let mut write_options = WriteOptions::default();
                write_options.disable_wal(true);
                KeyspaceEngine::Rocks { db: Arc::new(db), read_options, write_options }
            }
            StorageBackendProfile::U2SlateLocalFs => {
                KeyspaceEngine::Slate(SlateKeyspace::open(&path).map_err(|source| SlateDB { name, source })?)
            }
            StorageBackendProfile::U2S3SlateS3FileWal => {
                KeyspaceEngine::Slate(SlateKeyspace::open_s3(&path).map_err(|source| SlateDB { name, source })?)
            }
            StorageBackendProfile::U3SlateRemoteSim | StorageBackendProfile::U4ProductionRemote => {
                return Err(ProfileUnavailable { name, profile: profile.code() });
            }
        };
        Ok(Self { path, name, id: keyspace.id(), engine, prefix_length: keyspace.prefix_length() })
    }

    pub(super) fn engine(&self) -> &KeyspaceEngine {
        &self.engine
    }

    /// Construct an engine cursor for the pool. `prefixed` requests the
    /// bloom-prefix read path on RocksDB; SlateDB scans are always
    /// total-order, which is a strict superset of the prefixed contract
    /// (every prefixed use seeks within one prefix and stops at its end,
    /// enforced above the cursor by `KeyspaceRangeIterator`).
    pub(super) fn new_raw_cursor(&self, prefixed: bool) -> RawCursor {
        match &self.engine {
            KeyspaceEngine::Rocks { db, .. } => {
                let mut read_options = self.new_read_options();
                if prefixed {
                    read_options.set_prefix_same_as_start(true);
                    read_options.set_total_order_seek(false);
                }
                RawCursor::new_rocks(db.clone(), read_options)
            }
            KeyspaceEngine::Slate(slate) => RawCursor::new_slate(slate),
        }
    }

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

    pub(crate) fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KeyspaceError> {
        match &self.engine {
            KeyspaceEngine::Rocks { db, write_options, .. } => db
                .put_opt(key, value, write_options)
                .map_err(|error| KeyspaceError::Put { name: self.name, source: error }),
            KeyspaceEngine::Slate(slate) => {
                slate.put(key, value).map_err(|source| KeyspaceError::Slate { name: self.name, op: "put", source })
            }
        }
    }

    pub(crate) fn get<M, V>(&self, key: &[u8], mapper: M) -> Result<Option<V>, KeyspaceError>
    where
        M: FnMut(&[u8]) -> V,
    {
        match &self.engine {
            KeyspaceEngine::Rocks { db, read_options, .. } => {
                let mut mapper = mapper;
                db.get_pinned_opt(key, read_options)
                    .map(|option| option.map(|value| mapper(value.as_ref())))
                    .map_err(|error| KeyspaceError::Get { name: self.name, source: error })
            }
            KeyspaceEngine::Slate(slate) => {
                slate.get(key, mapper).map_err(|source| KeyspaceError::Slate { name: self.name, op: "get", source })
            }
        }
    }

    pub(crate) fn get_prev<M, T>(&self, key: &[u8], mut mapper: M) -> Option<T>
    where
        M: FnMut(&[u8], &[u8]) -> T,
    {
        match &self.engine {
            KeyspaceEngine::Rocks { db, .. } => {
                let mut iterator = db.raw_iterator_opt(self.new_read_options());
                iterator.seek_for_prev(key);
                iterator.item().map(|(k, v)| mapper(k, v))
            }
            KeyspaceEngine::Slate(slate) => slate.get_prev(key, mapper),
        }
    }

    pub(crate) fn iterate_range<const PREFIX_INLINE_SIZE: usize>(
        &self,
        iterpool: &IteratorPool,
        range: &KeyRange<Bytes<'_, PREFIX_INLINE_SIZE>>,
        storage_counters: StorageCounters,
    ) -> iterator::KeyspaceRangeIterator {
        iterator::KeyspaceRangeIterator::new(self, iterpool, range, storage_counters)
    }

    /// Apply one atomic per-keyspace batch. MVCC commit batches contain only
    /// puts (MVCC deletes are tombstone-record puts), so the engine-neutral
    /// batch is a put list applied atomically by both engines.
    pub(crate) fn write(&self, write_batch: KeyspaceWriteBatch) -> Result<(), KeyspaceError> {
        match &self.engine {
            KeyspaceEngine::Rocks { db, write_options, .. } => {
                let mut rocks_batch = WriteBatch::default();
                for (key, value) in write_batch.puts() {
                    rocks_batch.put(key, value);
                }
                db.write_opt(rocks_batch, write_options)
                    .map_err(|error| KeyspaceError::BatchWrite { name: self.name, source: error })
            }
            KeyspaceEngine::Slate(slate) => slate.write(write_batch.puts()).map_err(|source| KeyspaceError::Slate {
                name: self.name,
                op: "batch write",
                source,
            }),
        }
    }

    pub(crate) fn checkpoint(&self, checkpoint_dir: &Path) -> Result<(), KeyspaceCheckpointError> {
        use KeyspaceCheckpointError::{CheckpointExists, CreateRocksDBCheckpoint, CreateSlateDBCheckpoint};

        let checkpoint_dir = checkpoint_dir.join(self.name);
        if checkpoint_dir.exists() {
            return Err(CheckpointExists { name: self.name, dir: checkpoint_dir });
        }

        match &self.engine {
            KeyspaceEngine::Rocks { db, .. } => {
                Checkpoint::new(db)
                    .and_then(|checkpoint| checkpoint.create_checkpoint(&checkpoint_dir))
                    .map_err(|error| CreateRocksDBCheckpoint { name: self.name, source: error })?;
            }
            KeyspaceEngine::Slate(slate) => {
                slate
                    .checkpoint(&checkpoint_dir)
                    .map_err(|source| CreateSlateDBCheckpoint { name: self.name, source })?;
            }
        }

        Ok(())
    }

    pub(crate) fn delete(self) -> Result<(), KeyspaceDeleteError> {
        // Dropping releases this keyspace's handle; any cursor still pooled in a
        // live snapshot keeps the engine open (and safe) until it is dropped. On
        // POSIX the directory removal below succeeds regardless (unlink-while-
        // open); on Windows an outstanding cursor can make removal fail with a
        // sharing violation, surfaced as the typed DirectoryRemove error rather
        // than upstream's undefined behavior on the same race.
        //
        // U2S3 caveat: that guarantee is local-lane only. purge_remote() below
        // closes the shared engine and deletes the remote objects, so a cursor
        // still pooled in a live snapshot fails its next read (typed engine/
        // object error, never silent corruption). Callers reach delete() only
        // through database deletion, which requires exclusive ownership of the
        // database, so no such cursor exists on that path; new callers on the
        // remote lane must uphold the same exclusivity.
        let path = self.path.clone();
        let name = self.name;
        // S3-backed keyspaces (U2S3) also own remote objects; deleting only
        // the local directory would leak them AND leave state a later open of
        // the same path would purge as stale — delete both sides.
        if let KeyspaceEngine::Slate(slate) = &self.engine {
            slate.purge_remote().map_err(|source| KeyspaceDeleteError::RemotePurge { name, source })?;
        }
        drop(self.engine); // SlateKeyspace::drop closes the engine, flushing state
        fs::remove_dir_all(path)
            .map_err(|error| KeyspaceDeleteError::DirectoryRemove { name, source: Arc::new(error) })?;
        Ok(())
    }

    pub(crate) fn reset(&mut self) -> Result<(), KeyspaceError> {
        match &self.engine {
            KeyspaceEngine::Rocks { db, .. } => {
                let iterator = db.iterator(IteratorMode::Start);
                for entry in iterator {
                    let (key, _) = entry.map_err(|err| KeyspaceError::Iterate { name: self.name, source: err })?;
                    db.delete(key).map_err(|err| KeyspaceError::Iterate { name: self.name, source: err })?;
                }
                Ok(())
            }
            KeyspaceEngine::Slate(slate) => {
                slate.reset().map_err(|source| KeyspaceError::Slate { name: self.name, op: "reset", source })
            }
        }
    }

    pub fn estimate_size_in_bytes(&self) -> Result<u64, KeyspaceError> {
        match &self.engine {
            KeyspaceEngine::Rocks { db, .. } => {
                let property_name = constants::rocksdb::PROPERTY_ESTIMATE_LIVE_DATA_SIZE;
                db.property_int_value(property_name)
                    .map_err(|source| KeyspaceError::Property { name: property_name, source })
                    .map(|result_opt| result_opt.unwrap_or(0))
            }
            KeyspaceEngine::Slate(slate) => Ok(slate.estimate_size_in_bytes()),
        }
    }

    pub fn estimate_key_count(&self) -> Result<u64, KeyspaceError> {
        match &self.engine {
            KeyspaceEngine::Rocks { db, .. } => {
                let property_name = constants::rocksdb::PROPERTY_ESTIMATE_NUM_KEYS;
                db.property_int_value(property_name)
                    .map_err(|source| KeyspaceError::Property { name: property_name, source })
                    .map(|result_opt| result_opt.unwrap_or(0))
            }
            KeyspaceEngine::Slate(slate) => slate.estimate_key_count().map_err(|source| KeyspaceError::Slate {
                name: self.name,
                op: "estimate key count",
                source,
            }),
        }
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
    SlateDB { name: &'static str, source: Arc<slatedb::Error> },
    Factory { name: &'static str, source: StorageFactoryError },
    ProfileUnavailable { name: &'static str, profile: &'static str },
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
            Self::SlateDB { source, .. } => Some(source.as_ref()),
            Self::Factory { source, .. } => Some(source),
            Self::ProfileUnavailable { .. } => None,
            Self::Validation { source, .. } => Some(source),
        }
    }
}

#[derive(Debug, Clone)]
pub enum KeyspaceCheckpointError {
    CheckpointExists { name: &'static str, dir: PathBuf },
    CreateRocksDBCheckpoint { name: &'static str, source: rocksdb::Error },
    CreateSlateDBCheckpoint { name: &'static str, source: Arc<slatedb::Error> },
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
            Self::CreateSlateDBCheckpoint { source, .. } => Some(source.as_ref()),
        }
    }
}

#[derive(Debug, Clone)]
pub enum KeyspaceDeleteError {
    DirectoryRemove { name: &'static str, source: Arc<io::Error> },
    RemotePurge { name: &'static str, source: Arc<slatedb::Error> },
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
            Self::RemotePurge { source, .. } => Some(source.as_ref()),
        }
    }
}

#[derive(Clone, Debug)]
pub enum KeyspaceError {
    Get { name: &'static str, source: rocksdb::Error },
    Put { name: &'static str, source: rocksdb::Error },
    BatchWrite { name: &'static str, source: rocksdb::Error },
    Iterate { name: &'static str, source: rocksdb::Error },
    DeleteRange { name: &'static str, source: rocksdb::Error },
    Property { name: &'static str, source: rocksdb::Error },
    Slate { name: &'static str, op: &'static str, source: Arc<slatedb::Error> },
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
            Self::Slate { source, .. } => Some(source.as_ref()),
        }
    }
}
