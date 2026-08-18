/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::{
    error::Error,
    fmt,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use chrono::{DateTime, Utc};
use error::typedb_error;
use fail_point::{
    CHECKPOINT_CLEANUP_FAIL, CHECKPOINT_CLEANUP_PARTIAL_FAIL, CHECKPOINT_DIR_CREATE_FAIL, CHECKPOINT_FILE_EMPTY,
    CHECKPOINT_FILE_SYNC_FAIL, CHECKPOINT_METADATA_WRITE_FAIL, fail_point,
};
use itertools::Itertools;
use same_file::is_same_file;
use tracing::{debug, trace};

use crate::{
    durability_client::DurabilityClient,
    keyspace::{
        KeyspaceCheckpointError, KeyspaceOpenError, KeyspaceSet, Keyspaces, StorageBackend,
        rocks_resources::RocksResources,
    },
    recovery::commit_recovery::{StorageRecoveryError, apply_recovered, load_commit_data_from},
    sequence_number::SequenceNumber,
};

const CHECKPOINT_DIR_NAME: &str = "checkpoint";
const STORAGE_METADATA_FILE_NAME: &str = "STORAGE_METADATA";
const TEMP_FILE_EXTENSION: &str = "tmp";

/// A checkpoint is a directory, which contains at least the storage checkpointing data: keyspaces + the watermark.
/// The watermark represents a sequence number that is guaranteed to be in all the keyspaces, and after which we may
/// have to reapply commits to the keyspaces from the WAL.
pub struct CheckpointReader {
    pub directory: PathBuf,
}

impl CheckpointReader {
    pub fn open_latest<KS: KeyspaceSet>(storage_path: &Path) -> Result<Option<Self>, CheckpointLoadError> {
        use CheckpointLoadError::CheckpointRead;

        let checkpoint_dir = storage_path.join(CHECKPOINT_DIR_NAME);
        if !checkpoint_dir.exists() {
            return Ok(None);
        }

        fs::read_dir(&checkpoint_dir)
            .and_then(latest_complete_checkpoint::<KS>)
            .map_err(|error| CheckpointRead { dir: checkpoint_dir, source: Arc::new(error) })
    }

    pub fn get_additional_data<T: CheckpointAdditionalData>(&self) -> Result<T, CheckpointLoadError> {
        use CheckpointLoadError::{AdditionalDataDeserialise, AdditionalDataIO, AdditionalDataNotFound};

        let file_name = T::NAME;
        let path = self.directory.join(file_name);
        if !path.exists() {
            return Err(AdditionalDataNotFound { name: T::NAME.to_string() });
        }

        let mut file =
            File::open(path).map_err(|err| AdditionalDataIO { name: T::NAME.to_string(), source: Arc::new(err) })?;

        let deserialised = T::deserialise_from(&mut file)
            .map_err(|err| AdditionalDataDeserialise { name: T::NAME.to_string(), source: Arc::new(err) })?;
        Ok(deserialised)
    }

    pub(crate) fn recover_storage<KS: KeyspaceSet, Durability: DurabilityClient>(
        &self,
        database_name: &str,
        keyspaces_dir: &Path,
        durability_client: &Durability,
        rocks_resources: &RocksResources,
        backend: StorageBackend,
    ) -> Result<(Keyspaces, SequenceNumber), CheckpointLoadError> {
        use CheckpointLoadError::{CheckpointRestore, CommitRecoveryFailed, KeyspaceOpen};

        for keyspace in KS::iter() {
            let keyspace_dir = keyspaces_dir.join(keyspace.name());
            let keyspace_checkpoint_dir = self.directory.join(keyspace.name());
            trace!("Recovering keyspace from checkpoint");
            restore_storage_from_checkpoint(keyspace_dir, keyspace_checkpoint_dir)
                .map_err(|error| CheckpointRestore { dir: self.directory.clone(), source: Arc::new(error) })?;
        }

        let keyspaces = Keyspaces::open::<KS>(&keyspaces_dir, rocks_resources, backend)
            .map_err(|error| KeyspaceOpen { source: error })?;

        trace!("Finished recovering keyspaces, recovering missing commits");

        let checkpoint_sequence_number = self.read_sequence_number()?;
        if checkpoint_sequence_number > durability_client.previous() {
            panic!(
                "The checkpoint is ahead of the durability service! The durability logs may have been corrupted. Aborting."
            );
        }

        // S-P0-09: both `+ 1`s below sit on recovery input (the checkpoint
        // watermark and WAL commit keys). At u64::MAX the unchecked form
        // wrapped in release, making replay restart from sequence number
        // zero; a sequence number that has no successor is typed corruption,
        // never an arithmetic accident.
        let recovery_start = replay_successor(&self.directory, checkpoint_sequence_number)?;
        let recovered_commits = load_commit_data_from(recovery_start, durability_client)
            .map_err(|err| CommitRecoveryFailed { typedb_source: err })?;
        let next_sequence_number = replay_successor(
            &self.directory,
            recovered_commits.keys().max().copied().unwrap_or(checkpoint_sequence_number),
        )?;
        trace!("Applying missing commits");
        apply_recovered(database_name, recovered_commits, durability_client, &keyspaces)
            .map_err(|err| CommitRecoveryFailed { typedb_source: err })?;
        Ok((keyspaces, next_sequence_number))
    }

    pub fn read_sequence_number(&self) -> Result<SequenceNumber, CheckpointLoadError> {
        use CheckpointLoadError::{MetadataCorrupt, MetadataRead};

        let metadata_file_path = self.directory.join(STORAGE_METADATA_FILE_NAME);
        let metadata = fs::read_to_string(metadata_file_path)
            .map_err(|error| MetadataRead { dir: self.directory.clone(), source: Arc::new(error) })?;
        // an unparseable watermark is a typed error, never a panic: the
        // caller can fall back to an older checkpoint or full WAL replay,
        // while a panic here takes down recovery with no recourse
        let number =
            metadata.parse().map_err(|_| MetadataCorrupt { dir: self.directory.clone(), content: metadata.clone() })?;
        Ok(SequenceNumber::new(number))
    }

    fn is_complete<KS: KeyspaceSet>(&self) -> io::Result<bool> {
        if !self.directory.is_dir() {
            return Ok(false);
        }
        if !self.directory.join(STORAGE_METADATA_FILE_NAME).exists() {
            return Ok(false);
        }
        for keyspace in KS::iter() {
            let keyspace_checkpoint_dir = self.directory.join(keyspace.name());
            if !fs::exists(keyspace_checkpoint_dir)? {
                return Ok(false);
            }
        }
        let metadata_file_path = self.directory.join(STORAGE_METADATA_FILE_NAME);
        fs::exists(metadata_file_path)
    }
}

/// Successor of a recovery-input sequence number (S-P0-09): replay both
/// starts at `watermark + 1` and resumes allocation at `highest + 1`, and
/// neither may wrap. A sequence number with no successor means the space is
/// exhausted or the recovery inputs are corrupt — a typed refusal either
/// way, so the caller can fall back to an older checkpoint instead of
/// replaying from sequence number zero.
fn replay_successor(directory: &Path, sequence_number: SequenceNumber) -> Result<SequenceNumber, CheckpointLoadError> {
    sequence_number
        .checked_next()
        .ok_or_else(|| CheckpointLoadError::SequenceExhausted { dir: directory.to_owned(), watermark: sequence_number })
}

fn latest_complete_checkpoint<KS: KeyspaceSet>(mut entries: fs::ReadDir) -> io::Result<Option<CheckpointReader>> {
    let latest: io::Result<_> = entries.try_fold(None, |cur, entry| {
        let path = entry?.path();
        if path.extension() == Some(TEMP_FILE_EXTENSION.as_ref()) {
            // skip unfinished checkpoint
            return Ok(cur);
        }

        let Some(timestamp) = parse_directory_name_timestamp(&path) else {
            // skip unparseable checkpoint
            return Ok(cur);
        };

        if cur.as_ref().is_some_and(|(cur_timestamp, _)| cur_timestamp > &timestamp) {
            return Ok(cur);
        }

        let checkpoint = CheckpointReader { directory: path };
        if checkpoint.is_complete::<KS>()? { Ok(Some((timestamp, checkpoint))) } else { Ok(cur) }
    });

    match latest? {
        Some((_, checkpoint_reader)) => Ok(Some(checkpoint_reader)),
        None => Ok(None),
    }
}

fn parse_directory_name_timestamp(path: &PathBuf) -> Option<DateTime<Utc>> {
    let Some(dir_name) = path.file_name() else {
        debug!("Encountered path with no directory name during checkpoint recovery: {path:?}, skipping");
        return None;
    };

    let Some(dir_name) = dir_name.to_str() else {
        debug!("Encountered directory with non-UTF8 name during checkpoint recovery: {path:?}, skipping");
        return None;
    };

    let Ok(micros) = dir_name.parse() else {
        debug!("Encountered directory with non-timestamp name during checkpoint recovery: {path:?}, skipping");
        return None;
    };

    let Some(timestamp) = DateTime::from_timestamp_micros(micros) else {
        debug!("Encountered directory with timestamp name outside the range of UTC datetimes: {path:?}, skipping");
        return None;
    };

    Some(timestamp)
}

/// Mirror the checkpoint tree over the live keyspace directory. Recursive
/// (TB-P7): RocksDB checkpoints are flat file sets, for which this reduces
/// exactly to the previous per-file logic; SlateDB object stores are nested
/// (`manifest/`, `compacted/`, ...), so entries must be synced per directory
/// level, removing anything the checkpoint does not contain.
fn restore_storage_from_checkpoint(keyspace_dir: PathBuf, keyspace_checkpoint_dir: PathBuf) -> io::Result<()> {
    fs::create_dir_all(&keyspace_dir)?;

    for entry in fs::read_dir(&keyspace_dir)? {
        let entry = entry?;
        let storage_file = entry.path();
        let checkpoint_file = keyspace_checkpoint_dir.join(storage_file.file_name().unwrap());
        if !checkpoint_file.exists() {
            if entry.file_type()?.is_dir() {
                fs::remove_dir_all(storage_file)?;
            } else {
                fs::remove_file(storage_file)?;
            }
        } else if entry.file_type()?.is_dir() != checkpoint_file.is_dir() {
            // a file replaced by a directory (or vice versa) between
            // checkpoint and live state: remove, the copy pass recreates it
            if entry.file_type()?.is_dir() {
                fs::remove_dir_all(storage_file)?;
            } else {
                fs::remove_file(storage_file)?;
            }
        }
    }

    for entry in fs::read_dir(&keyspace_checkpoint_dir)? {
        let checkpoint_file = entry?.path();
        let storage_file = keyspace_dir.join(checkpoint_file.file_name().unwrap());
        if checkpoint_file.is_dir() {
            restore_storage_from_checkpoint(storage_file, checkpoint_file)?;
        } else if !storage_file.exists() || !is_same_file(&storage_file, &checkpoint_file)? {
            copy_file(&checkpoint_file, &storage_file)?;
        }
    }

    Ok(())
}

/// A checkpoint is a directory, which contains at least the storage checkpointing data: keyspaces + the watermark.
/// The watermark represents a sequence number that is guaranteed to be in all the keyspaces, and after which we may
/// have to reapply commits to the keyspaces from the WAL.
pub struct CheckpointWriter {
    pub checkpoint_directory: PathBuf,
    pub temporary_directory: PathBuf,
}

impl CheckpointWriter {
    pub fn new(storage_path: &Path) -> Result<Self, CheckpointCreateError> {
        use CheckpointCreateError::CheckpointDirCreate;

        let checkpoint_dir = storage_path.join(CHECKPOINT_DIR_NAME);
        if !checkpoint_dir.exists() {
            fs::create_dir_all(&checkpoint_dir)
                .map_err(|error| CheckpointDirCreate { dir: checkpoint_dir.clone(), source: Arc::new(error) })?
        }

        let checkpoint_directory = checkpoint_dir.join(format!("{}", Utc::now().timestamp_micros()));
        let temporary_directory = checkpoint_directory.with_extension(TEMP_FILE_EXTENSION);
        fs::create_dir_all(&temporary_directory)
            .map_err(|error| CheckpointDirCreate { dir: checkpoint_dir.clone(), source: Arc::new(error) })?;

        Ok(Self { checkpoint_directory, temporary_directory })
    }

    pub fn add_storage(&self, keyspaces: &Keyspaces, watermark: SequenceNumber) -> Result<(), CheckpointCreateError> {
        use CheckpointCreateError::{KeyspaceCheckpoint, MetadataWrite};

        keyspaces
            .checkpoint(&self.temporary_directory)
            .map_err(|error| KeyspaceCheckpoint { dir: self.temporary_directory.clone(), source: error })?;

        fail_point!(CHECKPOINT_METADATA_WRITE_FAIL);

        let metadata_file_path = self.temporary_directory.join(STORAGE_METADATA_FILE_NAME);
        write_file(&metadata_file_path, watermark.number().to_string().as_bytes())
            .map_err(|e| MetadataWrite { file_path: metadata_file_path, source: Arc::new(e) })?;

        Ok(())
    }

    pub fn add_extension<T: CheckpointAdditionalData>(&self, data: &T) -> Result<(), CheckpointCreateError> {
        use CheckpointCreateError::{ExtensionDuplicate, ExtensionIO, ExtensionSerialise};
        let file_name = T::NAME;
        let path = self.temporary_directory.join(file_name);
        if path.exists() {
            return Err(ExtensionDuplicate { name: T::NAME.to_string() });
        }

        let tmp = path.with_extension(TEMP_FILE_EXTENSION);
        {
            let mut file =
                File::create(&tmp).map_err(|err| ExtensionIO { name: T::NAME.to_string(), source: Arc::new(err) })?;
            data.serialise_into(&mut file)
                .map_err(|err| ExtensionSerialise { name: T::NAME.to_string(), source: Arc::new(err) })?;
        }
        fs::rename(&tmp, &path).map_err(|err| ExtensionIO { name: T::NAME.to_string(), source: Arc::new(err) })?;

        Ok(())
    }

    pub fn finish(self) -> Result<CheckpointReader, CheckpointCreateError> {
        use CheckpointCreateError::{CheckpointDirCreate, CheckpointDirRead, MissingStorageData, OldCheckpointRemove};

        if !self.temporary_directory.join(STORAGE_METADATA_FILE_NAME).exists() {
            return Err(MissingStorageData { dir: self.temporary_directory.clone() });
        }

        fail_point!(CHECKPOINT_DIR_CREATE_FAIL);

        fs::rename(&self.temporary_directory, &self.checkpoint_directory)
            .map_err(|error| CheckpointDirCreate { dir: self.checkpoint_directory.clone(), source: Arc::new(error) })?;

        fail_point!(CHECKPOINT_CLEANUP_FAIL);

        let previous_checkpoints: Vec<_> = fs::read_dir(self.checkpoint_directory.parent().unwrap())
            .and_then(|entries| {
                entries
                    .map_ok(|entry| entry.path())
                    .filter(|path| path.is_ok() && path.as_ref().unwrap() != &self.checkpoint_directory)
                    .try_collect()
            })
            .map_err(|error| CheckpointDirRead { dir: self.checkpoint_directory.clone(), source: Arc::new(error) })?;

        for previous_checkpoint in previous_checkpoints {
            fail_point!(CHECKPOINT_CLEANUP_PARTIAL_FAIL);
            fs::remove_dir_all(&previous_checkpoint)
                .map_err(|error| OldCheckpointRemove { dir: previous_checkpoint, source: Arc::new(error) })?
        }

        Ok(CheckpointReader { directory: self.checkpoint_directory })
    }
}

fn write_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = File::create(path)?;
    fail_point!(CHECKPOINT_FILE_EMPTY);
    file.write_all(bytes)?;
    fail_point!(CHECKPOINT_FILE_SYNC_FAIL);
    file.sync_all()?;
    Ok(())
}

fn copy_file(source: &Path, destination: &Path) -> io::Result<()> {
    let mut source_file = File::open(source)?;
    let mut destination_file = File::create(destination)?;
    fail_point!(CHECKPOINT_FILE_EMPTY);
    io::copy(&mut source_file, &mut destination_file)?;
    fail_point!(CHECKPOINT_FILE_SYNC_FAIL);
    destination_file.sync_all()?;
    Ok(())
}

pub trait CheckpointAdditionalData: Sized {
    const NAME: &'static str;
    fn serialise_into(&self, writer: &mut impl Write) -> bincode::Result<()>;
    fn deserialise_from(reader: &mut impl Read) -> bincode::Result<Self>;
}

#[derive(Debug, Clone)]
pub enum CheckpointCreateError {
    CheckpointDirCreate { dir: PathBuf, source: Arc<io::Error> },
    CheckpointDirRead { dir: PathBuf, source: Arc<io::Error> },

    MissingStorageData { dir: PathBuf },

    KeyspaceCheckpoint { dir: PathBuf, source: KeyspaceCheckpointError },

    MetadataFileCreate { file_path: PathBuf, source: Arc<io::Error> },
    MetadataWrite { file_path: PathBuf, source: Arc<io::Error> },

    ExtensionDuplicate { name: String },
    ExtensionIO { name: String, source: Arc<io::Error> },
    ExtensionSerialise { name: String, source: Arc<bincode::Error> },

    OldCheckpointRemove { dir: PathBuf, source: Arc<io::Error> },
}

impl fmt::Display for CheckpointCreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        error::todo_display_for_error!(f, self)
    }
}

impl Error for CheckpointCreateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CheckpointDirCreate { source, .. } => Some(source),
            Self::CheckpointDirRead { source, .. } => Some(source),
            Self::MissingStorageData { .. } => None,
            Self::KeyspaceCheckpoint { source, .. } => Some(source),
            Self::MetadataFileCreate { source, .. } => Some(source),
            Self::MetadataWrite { source, .. } => Some(source),
            Self::ExtensionDuplicate { .. } => None,
            Self::ExtensionIO { source, .. } => Some(source),
            Self::ExtensionSerialise { source, .. } => Some(source),
            Self::OldCheckpointRemove { source, .. } => Some(source),
        }
    }
}

typedb_error! {
    pub CheckpointLoadError(component = "Checkpoint load.", prefix = "CLO") {
        CheckpointRead(1, "Error to reading checkpoint directory '{dir:?}'.", dir: PathBuf, source: Arc<io::Error>),
        MetadataRead(2, "Error reading checkpoint metadata file in directory '{dir:?}.", dir: PathBuf, source: Arc<io::Error>),
        CheckpointNotFound(3, "No checkpoints found in directory '{dir:?}.", dir: PathBuf),
        CommitRecoveryFailed(4, "Failed to recover commits that are in the WAL but not in the storage layer.", typedb_source: StorageRecoveryError),
        CheckpointRestore(5, "Error restoring checkpoint in directory '{dir:?}'.)", dir: PathBuf, source: Arc<io::Error>),
        KeyspaceOpen(7, "Error while opening storage keyspaces.", source: KeyspaceOpenError),

        AdditionalDataNotFound(8, "Checkpoint additional data with identifier '{name}' not found.", name: String),
        AdditionalDataIO(9, "Error accessing checkpoint additional data with identifier '{name}'.", name: String, source: Arc<io::Error>),
        AdditionalDataDeserialise(10, "Error deserialising checkpoint additional data with identifier '{name}'.", name: String, source: Arc<bincode::Error>),
        MetadataCorrupt(11, "Checkpoint metadata file in directory '{dir:?}' does not hold a parseable watermark (found '{content}'). The checkpoint is corrupt; an older checkpoint or a full WAL replay may still recover the database.", dir: PathBuf, content: String),
        SequenceExhausted(12, "Recovery from the checkpoint in directory '{dir:?}' requires a sequence number beyond the u64 space (watermark {watermark}). The sequence space is exhausted or the recovery inputs are corrupt; refusing rather than wrapping to zero.", dir: PathBuf, watermark: SequenceNumber),
    }
}

#[cfg(test)]
mod metadata_tests {
    //! S-P0-04 control (metadata half): a checkpoint whose STORAGE_METADATA
    //! file cannot be parsed is a typed load error — never an `expect` panic
    //! that kills recovery with no recourse to an older checkpoint.

    use test_utils::create_tmp_dir;

    use super::{CheckpointLoadError, CheckpointReader, STORAGE_METADATA_FILE_NAME};

    #[test]
    fn a_parseable_watermark_round_trips() {
        let dir = create_tmp_dir("checkpoint-metadata");
        std::fs::write(dir.join(STORAGE_METADATA_FILE_NAME), b"42").unwrap();
        let reader = CheckpointReader { directory: dir.to_path_buf() };
        assert_eq!(reader.read_sequence_number().unwrap().number(), 42);
    }

    #[test]
    fn an_unparseable_watermark_is_a_typed_error_not_a_panic() {
        let dir = create_tmp_dir("checkpoint-metadata-corrupt");
        std::fs::write(dir.join(STORAGE_METADATA_FILE_NAME), b"not-a-number").unwrap();
        let reader = CheckpointReader { directory: dir.to_path_buf() };
        let error = reader.read_sequence_number().expect_err("corrupt metadata must be a typed error");
        assert!(
            matches!(error, CheckpointLoadError::MetadataCorrupt { .. }),
            "expected MetadataCorrupt, got: {error:?}"
        );
    }

    #[test]
    fn replay_bounds_are_exact_up_to_the_last_representable_sequence_number() {
        // S-P0-09 positive boundary: MAX-1 still has a successor and replay
        // computes it exactly.
        let dir = create_tmp_dir("checkpoint-replay-boundary");
        let successor = super::replay_successor(&dir, super::SequenceNumber::new(u64::MAX - 1)).unwrap();
        assert_eq!(successor.number(), u64::MAX);
    }

    #[test]
    fn a_watermark_with_no_successor_is_typed_exhaustion_not_a_wrap() {
        // S-P0-09 negative boundary: at u64::MAX the old unchecked `+ 1`
        // panicked in debug and restarted replay at sequence number ZERO in
        // release; it must instead be a typed terminal error.
        let dir = create_tmp_dir("checkpoint-replay-exhausted");
        let error = super::replay_successor(&dir, super::SequenceNumber::MAX)
            .expect_err("u64::MAX has no successor; replay must refuse");
        assert!(
            matches!(error, CheckpointLoadError::SequenceExhausted { .. }),
            "expected SequenceExhausted, got: {error:?}"
        );
    }
}
