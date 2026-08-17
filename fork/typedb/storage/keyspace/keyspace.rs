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

use super::{IteratorPool, WriteBatch, iterator};
// Only the RocksDB lane reads store properties by name; the SlateDB lane answers the same two
// questions from its manifest and its memo.
#[cfg(not(feature = "slatedb-backend"))]
use super::constants;
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
    /// Root directory of the shared SlateDB store. Held explicitly rather than derived from a
    /// keyspace's `path`, because a keyspace path on this lane is a label, not a location.
    #[cfg(feature = "slatedb-backend")]
    store_dir: PathBuf,
}

impl Keyspaces {
    pub(crate) fn new() -> Self {
        Self {
            keyspaces: Vec::new(),
            index: std::array::from_fn(|_| None),
            #[cfg(feature = "slatedb-backend")]
            store_dir: PathBuf::new(),
        }
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
        // R2 when the environment configures it, a local filesystem object store otherwise, so
        // the lane stays runnable without cloud credentials and the two differ only in which
        // `ObjectStore` is constructed. `storage_dir` names the prefix within the bucket as
        // well as the local directory, which is what lets several databases share one bucket
        // without either seeing the other's objects.
        //
        // A half-configured environment fails here rather than falling back — see
        // `StoreConfig::from_env`. A deployment that meant to use R2 and mistyped one variable
        // would otherwise come up on the container's local disk, pass every health check, and
        // lose the database when the container was replaced.
        #[cfg(feature = "slatedb-backend")]
        let store: super::slate::SharedStore = std::sync::Arc::new(
            slatedb_keyspace::KeyspaceSet::open_from_env(path, &Self::store_prefix(path))
                .map_err(|error| KeyspaceOpenError::SlateDB { source: error.to_string() })?,
        );

        let mut keyspaces = Keyspaces::new();
        #[cfg(feature = "slatedb-backend")]
        {
            keyspaces.store_dir = path.to_path_buf();
        }
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

    /// The prefix a database's objects live under inside the bucket.
    ///
    /// Derived from the storage directory's final component — the database name — so that the
    /// bucket layout mirrors the on-disk layout and two databases in one bucket cannot collide.
    /// A directory with no final component (a bare root) falls back to a fixed name rather than
    /// an empty prefix, because an empty prefix would place one database's objects at the
    /// bucket root where every other database's `LIST` would see them.
    #[cfg(feature = "slatedb-backend")]
    fn store_prefix(path: &Path) -> String {
        // A restore leaves a pointer naming the prefix it cloned into; honour it before falling
        // back to the derived name, or the database would reopen onto the pre-restore data.
        if let Ok(active) = fs::read_to_string(path.join(SLATEDB_ACTIVE_PREFIX)) {
            let active = active.trim();
            if !active.is_empty() {
                return active.to_string();
            }
        }
        path.file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or("typedb")
            .to_string()
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

    #[cfg(not(feature = "slatedb-backend"))]
    pub(crate) fn write(&self, write_batches: WriteBatches) -> Result<(), KeyspaceError> {
        for (index, write_batch) in write_batches.into_iter() {
            debug_assert!(index < KEYSPACE_MAXIMUM_COUNT);
            self.get(KeyspaceId(index as u8)).write(write_batch)?;
        }
        Ok(())
    }

    /// One commit, one store write — see `slate::write_coalesced` for why the loop above is
    /// not reproduced here.
    #[cfg(feature = "slatedb-backend")]
    pub(crate) fn write(&self, write_batches: WriteBatches) -> Result<(), KeyspaceError> {
        let Some(first) = self.keyspaces.first() else { return Ok(()) };
        let batches = write_batches.into_iter().map(|(index, write_batch)| {
            debug_assert!(index < KEYSPACE_MAXIMUM_COUNT);
            (slatedb_keyspace::KeyspaceId(index as u8), write_batch)
        });
        super::slate::write_coalesced(&first.store, batches)
            .map_err(|source| KeyspaceError::BatchWrite { name: source.name, source })
    }

    #[cfg(not(feature = "slatedb-backend"))]
    pub(crate) fn checkpoint(&self, current_checkpoint_dir: &Path) -> Result<(), KeyspaceCheckpointError> {
        for keyspace in &self.keyspaces {
            fail_point!(KEYSPACE_CHECKPOINT_FAIL);
            keyspace.checkpoint(current_checkpoint_dir)?;
        }
        Ok(())
    }

    /// Checkpoint the whole store once, not once per keyspace.
    ///
    /// RocksDB checkpoints per keyspace because each keyspace is a separate database. Every
    /// SlateDB keyspace lives in one store, so N per-keyspace copies would be N copies of the
    /// same bytes — and, worse, N copies taken at N different instants, which is not a
    /// checkpoint of anything. One copy at one pinned instant is both cheaper and the only
    /// version that is actually consistent.
    #[cfg(feature = "slatedb-backend")]
    pub(crate) fn checkpoint(&self, current_checkpoint_dir: &Path) -> Result<(), KeyspaceCheckpointError> {
        use KeyspaceCheckpointError::{CheckpointExists, SlateDBCheckpoint};

        fail_point!(KEYSPACE_CHECKPOINT_FAIL);
        let Some(keyspace) = self.keyspaces.first() else { return Ok(()) };

        let target = current_checkpoint_dir.join(SLATEDB_CHECKPOINT_DIR);
        if target.exists() {
            return Err(CheckpointExists { name: SLATEDB_CHECKPOINT_DIR, dir: target });
        }

        // A file-copy checkpoint is only meaningful for a store made of local files. When the
        // backend is an object store, `store_dir` holds a block cache and nothing else, so the
        // copy below would succeed, produce a directory of the wrong bytes, and leave a
        // checkpoint that is present, plausible and unrestorable — discovered at restore time,
        // which is the worst moment to discover it. Refusing is the only safe answer available
        // here: mapping this onto SlateDB's own checkpoints means reopening the store at a
        // manifest id or cloning it to a new prefix, which is a recovery-path design decision
        // rather than a translation, and is not one to make silently.
        // Flush and pin first, on both paths. The pin is what stops compaction or GC removing
        // an SST between the checkpoint being recorded and anything being done with it.
        let checkpoint_id = keyspace
            .store
            .checkpoint()
            .map_err(|error| SlateDBCheckpoint { message: error.to_string() })?;

        let Some(store_dir) = keyspace.store.local_directory().map(Path::to_path_buf) else {
            // Object-store backed. There are no local files to copy — the local directory holds
            // at most a block cache — so the checkpoint is recorded by reference instead. That
            // is not a lesser checkpoint: SlateDB's clone materializes it later by writing a
            // manifest that points at the pinned SSTs, so a restore moves no data at all and
            // costs a handful of writes whatever the database weighs. Copying would have been
            // the expensive option even if it were possible.
            fs::create_dir_all(&target)
                .map_err(|error| SlateDBCheckpoint { message: error.to_string() })?;
            let pointer = target.join(SLATEDB_CHECKPOINT_POINTER);
            fs::write(
                &pointer,
                format!("{}\n{}\n", keyspace.store.prefix(), checkpoint_id),
            )
            .map_err(|error| SlateDBCheckpoint { message: error.to_string() })?;
            return Ok(());
        };

        copy_dir_recursive(&store_dir, &target)
            .map_err(|error| SlateDBCheckpoint { message: error.to_string() })?;
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

    /// Clear every keyspace.
    pub(crate) fn reset(&mut self) -> Result<(), KeyspaceError> {
        for keyspace in self.keyspaces.iter_mut() {
            keyspace.reset()?
        }
        Ok(())
    }

    #[cfg(not(feature = "slatedb-backend"))]
    pub fn estimate_size_in_bytes(&self) -> Result<u64, KeyspaceError> {
        self.keyspaces.iter().try_fold(0, |total, keyspace| {
            let size = keyspace.estimate_size_in_bytes()?;
            Ok(total + size)
        })
    }

    /// The store's size, read once from the manifest rather than summed over keyspaces.
    ///
    /// Summing per-keyspace figures is the right shape on RocksDB, where each keyspace is its
    /// own database with its own properties. Here they share one store and one manifest, so
    /// asking it once is both cheaper and the only version that cannot double-count.
    #[cfg(feature = "slatedb-backend")]
    pub fn estimate_size_in_bytes(&self) -> Result<u64, KeyspaceError> {
        let Some(first) = self.keyspaces.first() else { return Ok(0) };
        Ok(first.store.size_bytes())
    }

    #[cfg(not(feature = "slatedb-backend"))]
    pub fn estimate_key_count(&self) -> Result<u64, KeyspaceError> {
        self.keyspaces.iter().try_fold(0, |total, keyspace| {
            let count = keyspace.estimate_key_count()?;
            Ok(total + count)
        })
    }

    /// Rows across the store, summed from SST metadata rather than by scanning.
    ///
    /// Asked of the store once rather than summed per keyspace, for the same reason as
    /// `estimate_size_in_bytes`: the keyspaces share one manifest, so asking each of them would
    /// return the same store-wide figure N times over.
    ///
    /// This is what RocksDB's `estimate-num-keys` does — sum the per-SST row counts recorded in
    /// table metadata — and it is an estimate in the same sense: overwritten keys are counted in
    /// every SST that still holds a version, and rows still in the memtable are not counted at
    /// all. What it is not is a scan, which is what this used to be, four times a minute,
    /// forever.
    #[cfg(feature = "slatedb-backend")]
    pub fn estimate_key_count(&self) -> Result<u64, KeyspaceError> {
        let Some(first) = self.keyspaces.first() else { return Ok(0) };
        first
            .store
            .estimated_key_count()
            .map_err(|source| KeyspaceError::Get { name: first.name(), source })
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

/// Name of the single directory a SlateDB checkpoint is written into.
///
/// Deliberately not a keyspace name: the store is shared, so the copy belongs to all keyspaces
/// at once and naming it after one of them would invite a per-keyspace restore that silently
/// restored everything.
#[cfg(feature = "slatedb-backend")]
pub(crate) const SLATEDB_CHECKPOINT_DIR: &str = "slatedb-store";

/// Names an object-store checkpoint by reference: source prefix on the first line, checkpoint id
/// on the second.
///
/// Its presence is what tells the restore path which of the two mechanisms produced this
/// checkpoint — a directory of copied files, or a pinned manifest version to clone from.
pub(crate) const SLATEDB_CHECKPOINT_POINTER: &str = "checkpoint.ref";

/// Records which prefix inside the bucket the live database occupies.
///
/// Restoring on the object-store path clones the checkpoint to a *new* prefix rather than
/// overwriting the old one, because a clone references the source's SSTs and writing it over its
/// own source would leave a manifest describing objects it was in the middle of replacing. The
/// database therefore has to be told where to open, and this file is that instruction.
pub(crate) const SLATEDB_ACTIVE_PREFIX: &str = "active-prefix";

/// Copy a directory tree.
///
/// `restore_storage_from_checkpoint` syncs a flat file list, which is enough for RocksDB — its
/// checkpoint directory has no subdirectories. A SlateDB store nests (manifest, WAL, compacted
/// SSTs), so a flat copy would silently produce a checkpoint missing its manifest: present,
/// plausible, and unopenable.
#[cfg(feature = "slatedb-backend")]
pub(crate) fn copy_dir_recursive(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

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
    /// The greatest key `<= key`, i.e. RocksDB's `seek_for_prev`.
    ///
    /// Returns `Result` rather than the bare `Option` this used to be. The distinction between
    /// "no such key" and "the store could not be read" is not decorative here: the only caller
    /// is the object-id generator, which treats `None` as *this type has no vertices yet* and
    /// resumes allocating from zero. Collapsing an I/O error into that answer reissues object
    /// ids that are already in use.
    ///
    /// On local RocksDB such an error is near-impossible, which is why the original signature
    /// was safe. It stops being safe the moment the store is remote.
    pub(crate) fn get_prev<M, T>(&self, key: &[u8], mut mapper: M) -> Result<Option<T>, KeyspaceError>
    where
        M: FnMut(&[u8], &[u8]) -> T,
    {
        let mut iterator = self.kv_storage.raw_iterator_opt(self.new_read_options());
        iterator.seek_for_prev(key);
        if let Err(error) = iterator.status() {
            return Err(KeyspaceError::Iterate { name: self.name, source: error });
        }
        Ok(iterator.item().map(|(k, v)| mapper(k, v)))
    }

    /// See the RocksDB-lane sibling for why this returns `Result`.
    #[cfg(feature = "slatedb-backend")]
    pub(crate) fn get_prev<M, T>(&self, key: &[u8], mapper: M) -> Result<Option<T>, KeyspaceError>
    where
        M: FnMut(&[u8], &[u8]) -> T,
    {
        super::slate::SlateKeyspace::from_parts(self)
            .get_prev(key, mapper)
            .map_err(|source| KeyspaceError::Iterate { name: source.name, source })
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
            super::slate::SlateKeyspace::from_parts(&self).clear().map_err(|error| {
                KeyspaceDeleteError::DirectoryRemove {
                    name: self.name,
                    source: Arc::new(std::io::Error::other(error.to_string())),
                }
            })?;
            return Ok(());
        }
        #[cfg(not(feature = "slatedb-backend"))]
        drop(self.kv_storage);
        #[cfg(not(feature = "slatedb-backend"))]
        fs::remove_dir_all(self.path.clone())
            .map_err(|error| KeyspaceDeleteError::DirectoryRemove { name: self.name, source: Arc::new(error) })?;
        Ok(())
    }

    /// Delete every entry in this keyspace.
    #[cfg(not(feature = "slatedb-backend"))]
    pub(crate) fn reset(&mut self) -> Result<(), KeyspaceError> {
        let iterator = self.kv_storage.iterator(IteratorMode::Start);
        for entry in iterator {
            let (key, _) = entry.map_err(|err| KeyspaceError::Iterate { name: self.name, source: err })?;
            self.kv_storage.delete(key).map_err(|err| KeyspaceError::Iterate { name: self.name, source: err })?;
        }
        Ok(())
    }

    /// Delete every entry in this keyspace, leaving sibling keyspaces untouched.
    ///
    /// The engine collects the deletes and applies them as one batch rather than deleting
    /// through a live cursor; see `slatedb-keyspace`'s `clear`.
    #[cfg(feature = "slatedb-backend")]
    pub(crate) fn reset(&mut self) -> Result<(), KeyspaceError> {
        super::slate::SlateKeyspace::from_parts(self)
            .clear()
            .map(|_| ())
            .map_err(|source| KeyspaceError::BatchWrite { name: self.name, source })
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

    /// This keyspace's share of the store, by scanning it.
    ///
    /// Prefer `Keyspaces::estimate_size_in_bytes`, which answers for the whole store from the
    /// manifest without touching the data at all. This per-keyspace form has no such shortcut
    /// — the manifest records each SST's size but does not expose its key range, so there is
    /// nothing to attribute a share from — and it is kept only for symmetry with the RocksDB
    /// lane. Nothing in TypeDB calls it on this lane.
    #[cfg(feature = "slatedb-backend")]
    pub fn estimate_size_in_bytes(&self) -> Result<u64, KeyspaceError> {
        super::slate::SlateKeyspace::from_parts(self)
            .estimated_stats()
            .map(|(_, bytes)| bytes)
            .map_err(|source| KeyspaceError::Get { name: self.name, source })
    }

    /// Live keys in this keyspace, memoized.
    ///
    /// RocksDB answers this from table properties in constant time and calls it an estimate.
    /// SlateDB records per-SST row counts in each SST's stats block but does not expose them
    /// publicly, so from outside the crate the only way to count live keys is to scan.
    ///
    /// That makes *when* it is asked the design question rather than how it is computed.
    /// TypeDB's diagnostics loop polls it every 15 seconds (`DATABASE_METRICS_UPDATE_INTERVAL`),
    /// and a scan on that schedule is a permanent full-speed pass over the database — free
    /// enough against RocksDB's local files to go unnoticed, and against object storage a
    /// continuous transfer of the whole store, billed per request. The engine therefore
    /// memoizes the result; see `slatedb-keyspace`'s `estimated_stats`.
    #[cfg(feature = "slatedb-backend")]
    pub fn estimate_key_count(&self) -> Result<u64, KeyspaceError> {
        super::slate::SlateKeyspace::from_parts(self)
            .estimated_stats()
            .map(|(keys, _)| keys)
            .map_err(|source| KeyspaceError::Get { name: self.name, source })
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
    #[cfg(feature = "slatedb-backend")]
    SlateDBCheckpoint { message: String },
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
            // The rendered message is the whole error; nothing to chain to.
            #[cfg(feature = "slatedb-backend")]
            Self::SlateDBCheckpoint { .. } => None,
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
