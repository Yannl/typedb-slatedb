/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    fs::{self, File},
    hash::{BuildHasher, Hasher},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use chrono::Utc;
use error::typedb_error;
use fail_point::{
    CHECKPOINT_CLEANUP_FAIL, CHECKPOINT_CLEANUP_PARTIAL_FAIL, CHECKPOINT_DIR_CREATE_FAIL, CHECKPOINT_FILE_EMPTY,
    CHECKPOINT_FILE_SYNC_FAIL, CHECKPOINT_METADATA_WRITE_FAIL, fail_point,
};
use itertools::Itertools;
use same_file::is_same_file;
use tracing::trace;

use crate::{
    durability_client::DurabilityClient,
    keyspace::{
        KeyspaceCheckpointError, KeyspaceOpenError, KeyspaceSet, Keyspaces, StorageBackend,
        rocks_resources::RocksResources,
    },
    recovery::commit_recovery::{RecoveryCommitStatus, StorageRecoveryError, apply_recovered, load_commit_data_from},
    sequence_number::SequenceNumber,
};

const CHECKPOINT_DIR_NAME: &str = "checkpoint";
const STORAGE_METADATA_FILE_NAME: &str = "STORAGE_METADATA";
const TEMP_FILE_EXTENSION: &str = "tmp";

/// R-06: the digest-bound completion marker, written LAST inside a checkpoint
/// attempt (after every data file and directory is fsynced) and made durable
/// itself before the attempt is atomically renamed into place. Its presence AND
/// a matching content digest are jointly required for a checkpoint to be
/// selectable — a directory that carries data but no verified COMPLETE is an
/// in-flight or torn attempt, never a checkpoint. Reverting the reader to trust
/// COMPLETE's mere presence (or writing it before the digest is bound) lets an
/// incomplete/truncated checkpoint be accepted — the exact R-06 mutant a named
/// test kills.
const CHECKPOINT_COMPLETE_FILE_NAME: &str = "COMPLETE";

/// R-04: a process-wide monotonic component of the checkpoint attempt id. Two
/// attempts scheduled in the same wall-clock instant (the microsecond-timestamp
/// directory names collided under rapid scheduling — the R-04 dir-sharing
/// hazard) still receive strictly different ids because this counter never
/// repeats within a process.
static ATTEMPT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A checkpoint is a directory, which contains at least the storage checkpointing data: keyspaces + the watermark.
/// The watermark represents a sequence number that is guaranteed to be in all the keyspaces, and after which we may
/// have to reapply commits to the keyspaces from the WAL.
pub struct CheckpointReader {
    pub directory: PathBuf,
}

impl CheckpointReader {
    pub fn open_latest<KS: KeyspaceSet>(storage_path: &Path) -> Result<Option<Self>, CheckpointLoadError> {
        Ok(Self::enumerate_verified::<KS>(storage_path)?.into_iter().next())
    }

    /// R4-STOR-10: EVERY digest-verified checkpoint candidate, ordered newest
    /// to oldest. The recovery policy iterates this list: a newer candidate
    /// that later fails pre-mutation validation (corrupt/ahead watermark, WAL
    /// coverage missing) falls back to the next older one, and only if none
    /// validates does recovery consider full WAL replay. A directory whose
    /// COMPLETE marker is absent, unreadable, or fails digest verification is
    /// not a candidate at all — it is a torn or in-flight attempt (R-06) and
    /// never shadows an older verified cut.
    pub fn enumerate_verified<KS: KeyspaceSet>(storage_path: &Path) -> Result<Vec<Self>, CheckpointLoadError> {
        use CheckpointLoadError::CheckpointRead;

        let checkpoint_dir = storage_path.join(CHECKPOINT_DIR_NAME);
        if !checkpoint_dir.exists() {
            return Ok(Vec::new());
        }

        fs::read_dir(&checkpoint_dir)
            .and_then(verified_checkpoints_newest_first::<KS>)
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

    /// R4-STOR-10 phase 1 — VALIDATE this candidate, mutating NOTHING.
    ///
    /// Everything recovery must prove about a checkpoint before it may touch
    /// the live tree happens here: the watermark is read and parsed, checked
    /// against the durability head (R-05: an ahead checkpoint means truncated
    /// durability logs or a stale cut), its replay successor is proven to
    /// exist (S-P0-09), and the WAL commits replay will need are strictly,
    /// contiguously loaded (R-01 — this also proves the retained WAL actually
    /// covers `watermark+1..head` for THIS candidate). Every failure is a
    /// typed pre-mutation refusal: the caller can fall back to an older
    /// candidate or full WAL replay with the live keyspace directories
    /// byte-identical.
    pub(crate) fn validate_for_recovery<Durability: DurabilityClient>(
        &self,
        durability_client: &Durability,
    ) -> Result<ValidatedCheckpointRecovery, CheckpointLoadError> {
        use CheckpointLoadError::CommitRecoveryFailed;

        let watermark = validate_watermark(&self.directory, durability_client.previous())?;

        // S-P0-09: both `+ 1`s here sit on recovery input (the checkpoint
        // watermark and WAL commit keys). At u64::MAX the unchecked form
        // wrapped in release, making replay restart from sequence number
        // zero; a sequence number that has no successor is typed corruption,
        // never an arithmetic accident.
        let recovery_start = replay_successor(&self.directory, watermark)?;
        let recovered_commits = load_commit_data_from(recovery_start, durability_client)
            .map_err(|err| CommitRecoveryFailed { typedb_source: err })?;
        let next_sequence_number =
            replay_successor(&self.directory, recovered_commits.keys().max().copied().unwrap_or(watermark))?;
        Ok(ValidatedCheckpointRecovery { watermark, recovered_commits, next_sequence_number })
    }

    /// R4-STOR-10 phase 2 — RESTORE a candidate [`Self::validate_for_recovery`]
    /// has already accepted. Destructive from the first statement on: the
    /// checkpoint tree is mirrored over the live keyspace directories, the
    /// keyspaces are opened, and the pre-loaded WAL commits are applied. A
    /// failure here is NOT candidate-fallback material — live state has been
    /// touched — so the caller must propagate it, never retry an older cut
    /// over a half-mirrored tree.
    pub(crate) fn restore_validated<KS: KeyspaceSet, Durability: DurabilityClient>(
        &self,
        database_name: &str,
        keyspaces_dir: &Path,
        validated: ValidatedCheckpointRecovery,
        durability_client: &Durability,
        rocks_resources: &RocksResources,
        backend: StorageBackend,
    ) -> Result<(Keyspaces, SequenceNumber), CheckpointLoadError> {
        use CheckpointLoadError::{CommitRecoveryFailed, KeyspaceOpen};

        let ValidatedCheckpointRecovery { watermark: _, recovered_commits, next_sequence_number } = validated;

        // validated — now, and only now, mirror the checkpoint over live state
        // (R-05 ordering: the validation above ran first, so a rejected
        // candidate never reaches this destructive block).
        restore_checkpoint_tree::<KS>(&self.directory, keyspaces_dir)?;

        let keyspaces = Keyspaces::open::<KS>(&keyspaces_dir, rocks_resources, backend)
            .map_err(|error| KeyspaceOpen { source: error })?;

        trace!("Finished recovering keyspaces, applying missing commits");
        apply_recovered(database_name, recovered_commits, durability_client, &keyspaces)
            .map_err(|err| CommitRecoveryFailed { typedb_source: err })?;
        Ok((keyspaces, next_sequence_number))
    }

    pub fn read_sequence_number(&self) -> Result<SequenceNumber, CheckpointLoadError> {
        read_watermark_at(&self.directory)
    }

    fn is_complete<KS: KeyspaceSet>(&self) -> io::Result<bool> {
        if !self.directory.is_dir() {
            return Ok(false);
        }
        if !self.directory.join(STORAGE_METADATA_FILE_NAME).exists() {
            return Ok(false);
        }
        // R-05: a non-empty expected root set. Every keyspace the set declares
        // must be present — a checkpoint missing a keyspace root is not a
        // checkpoint, no matter what else it carries.
        for keyspace in KS::iter() {
            let keyspace_checkpoint_dir = self.directory.join(keyspace.name());
            if !fs::exists(keyspace_checkpoint_dir)? {
                return Ok(false);
            }
        }
        // R-06: the digest-bound COMPLETE marker must be present AND verify
        // against the bytes on disk. A directory carrying data and metadata but
        // no verified COMPLETE is a torn or in-flight attempt, never selectable.
        // Trusting COMPLETE's mere presence (skipping the digest recomputation)
        // accepts a truncated/tampered checkpoint — the R-06 mutant a named test
        // kills.
        let complete_path = self.directory.join(CHECKPOINT_COMPLETE_FILE_NAME);
        let Ok(serialised) = fs::read_to_string(&complete_path) else {
            return Ok(false);
        };
        CheckpointManifest::verify(&self.directory, &serialised)
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
        .try_next()
        .ok_or_else(|| CheckpointLoadError::SequenceExhausted { dir: directory.to_owned(), watermark: sequence_number })
}

/// Read and parse the checkpoint watermark. An unparseable watermark is a typed
/// error, never a panic: the caller can fall back to an older checkpoint or full
/// WAL replay, while a panic here takes down recovery with no recourse.
fn read_watermark_at(directory: &Path) -> Result<SequenceNumber, CheckpointLoadError> {
    use CheckpointLoadError::{MetadataCorrupt, MetadataRead};
    let metadata_file_path = directory.join(STORAGE_METADATA_FILE_NAME);
    let metadata = fs::read_to_string(metadata_file_path)
        .map_err(|error| MetadataRead { dir: directory.to_owned(), source: Arc::new(error) })?;
    let number =
        metadata.parse().map_err(|_| MetadataCorrupt { dir: directory.to_owned(), content: metadata.clone() })?;
    Ok(SequenceNumber::new(number))
}

/// R4-STOR-10: the result of a checkpoint candidate's PRE-MUTATION validation
/// — the parsed watermark, the strictly-loaded WAL commits replay needs, and
/// the proven post-replay successor. Holding this value is the proof that
/// [`CheckpointReader::restore_validated`] may run; nothing about the live
/// tree has been touched to produce it.
pub(crate) struct ValidatedCheckpointRecovery {
    pub(crate) watermark: SequenceNumber,
    recovered_commits: BTreeMap<SequenceNumber, RecoveryCommitStatus>,
    next_sequence_number: SequenceNumber,
}

/// R-05 validation half: read the sealed watermark ONCE and validate it against
/// the durability head BEFORE any destructive touch. A corrupt or ahead
/// watermark is a typed refusal (was a `panic!`), so recovery can fall back to
/// an older checkpoint or full WAL replay with live state byte-identical.
fn validate_watermark(
    checkpoint_dir: &Path,
    durability_previous: SequenceNumber,
) -> Result<SequenceNumber, CheckpointLoadError> {
    use CheckpointLoadError::CheckpointAheadOfDurability;

    let checkpoint_sequence_number = read_watermark_at(checkpoint_dir)?;
    if checkpoint_sequence_number > durability_previous {
        // an ahead checkpoint (durability logs truncated or a stale
        // checkpoint) is a typed refusal so recovery can fall back, not a
        // process abort with no recourse.
        return Err(CheckpointAheadOfDurability {
            dir: checkpoint_dir.to_owned(),
            watermark: checkpoint_sequence_number,
            durability_head: durability_previous,
        });
    }
    Ok(checkpoint_sequence_number)
}

/// R-05 destructive half: mirror the checkpoint tree over the live keyspace
/// directories. Callers MUST have run validation first — the R-05 mutant
/// (mirror first, validate after) destroys live state on a bad checkpoint
/// with no recourse, and the named restore-safety tests catch it.
fn restore_checkpoint_tree<KS: KeyspaceSet>(
    checkpoint_dir: &Path,
    keyspaces_dir: &Path,
) -> Result<(), CheckpointLoadError> {
    use CheckpointLoadError::CheckpointRestore;

    for keyspace in KS::iter() {
        let keyspace_dir = keyspaces_dir.join(keyspace.name());
        let keyspace_checkpoint_dir = checkpoint_dir.join(keyspace.name());
        trace!("Recovering keyspace from checkpoint");
        restore_storage_from_checkpoint(keyspace_dir, keyspace_checkpoint_dir)
            .map_err(|error| CheckpointRestore { dir: checkpoint_dir.to_owned(), source: Arc::new(error) })?;
    }
    Ok(())
}

/// R4-STOR-08/R4-STOR-10: every verified, selectable checkpoint, ordered
/// newest to oldest.
///
/// Recency is the FULL attempt directory name, compared lexicographically:
/// the id format `<20-digit-nanos>-<counter>-<nonce>` (see [`new_attempt_id`])
/// makes lexicographic order equal numeric recency by construction — the
/// nanos prefix is fixed width, and two attempts whose nanos prefixes are
/// EXACTLY equal (rapid scheduling, coarse clocks) are still totally ordered
/// by the fixed-width counter and nonce components. This is the SAME total
/// order retention ([`siblings_safe_to_delete`]) uses, so the reader's
/// selection and the writer's cleanup can never disagree about which cut is
/// newer.
///
/// R-05/R-06: only a digest-verified COMPLETE checkpoint is a candidate. A
/// newer directory that cannot be read or fails verification does NOT shadow
/// an older one that verifies — it is simply not in the list, which is the
/// seed of the newest->older fallback the recovery policy runs (R4-STOR-10).
fn verified_checkpoints_newest_first<KS: KeyspaceSet>(entries: fs::ReadDir) -> io::Result<Vec<CheckpointReader>> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension() == Some(TEMP_FILE_EXTENSION.as_ref()) {
            // skip an unfinished (in-flight or torn) attempt
            continue;
        }
        if parse_attempt_nanos(&path).is_none() {
            // a directory whose name is not an attempt id — skip it
            continue;
        }
        candidates.push(path);
    }
    // newest first: full-name lexicographic == recency (docstring above)
    candidates.sort_by(|a, b| b.file_name().cmp(&a.file_name()));

    let mut verified = Vec::new();
    for path in candidates {
        let checkpoint = CheckpointReader { directory: path };
        // a candidate whose verification ERRORS (unreadable tree) is treated
        // exactly like one that fails verification: unselectable, and unable
        // to mask an older verified candidate (R4-STOR-10: "newest unreadable
        // with older valid" must select the older).
        if checkpoint.is_complete::<KS>().unwrap_or(false) {
            verified.push(checkpoint);
        }
    }
    Ok(verified)
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
        let is_dir = entry.file_type()?.is_dir();
        let checkpoint_file = keyspace_checkpoint_dir.join(storage_file.file_name().unwrap());
        // remove any live entry the checkpoint no longer contains, or whose
        // kind (file <-> dir) changed between checkpoint and live state — the
        // copy pass below recreates the latter.
        if !checkpoint_file.exists() || is_dir != checkpoint_file.is_dir() {
            if is_dir {
                fs::remove_dir_all(storage_file)?;
            } else {
                fs::remove_file(storage_file)?;
            }
        }
    }

    for entry in fs::read_dir(&keyspace_checkpoint_dir)? {
        let checkpoint_file = entry?.path();
        // R-05: NO-FOLLOW. Establish the no-symlink/no-special-file invariant on
        // every checkpoint entry BEFORE copying or recursing. A crafted
        // checkpoint tree containing a symlink (or a device/fifo) could
        // otherwise make the recursive copy write THROUGH it and escape or
        // clobber a target outside the intended keyspace root. Only regular
        // files and real directories are ever restored.
        let file_type = assert_safe_checkpoint_entry(&checkpoint_file)?;
        let storage_file = keyspace_dir.join(checkpoint_file.file_name().unwrap());
        if file_type.is_dir() {
            restore_storage_from_checkpoint(storage_file, checkpoint_file)?;
        } else if !storage_file.exists() || !is_same_file(&storage_file, &checkpoint_file)? {
            copy_file(&checkpoint_file, &storage_file)?;
        }
    }

    Ok(())
}

/// R-05: reject any checkpoint entry that is not a regular file or a real
/// directory. Uses `symlink_metadata` (NO-FOLLOW), so a symlink is caught as a
/// symlink rather than resolved to whatever it points at, and devices/fifos are
/// refused outright. The returned file type is the no-follow type, used by the
/// caller to decide copy-vs-recurse without a second, follow-through stat.
fn assert_safe_checkpoint_entry(path: &Path) -> io::Result<fs::FileType> {
    let file_type = fs::symlink_metadata(path)?.file_type();
    if file_type.is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("refusing to restore a checkpoint entry that is a symlink: {path:?}"),
        ));
    }
    if !(file_type.is_file() || file_type.is_dir()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("refusing to restore a checkpoint entry that is not a regular file or directory: {path:?}"),
        ));
    }
    Ok(file_type)
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

        // R-04: a cryptographically-unique attempt id, NOT a bare microsecond
        // timestamp. The id is `<20-digit-nanos>-<counter>-<nonce>`: the nanos
        // prefix keeps directories recency-ordered (fixed width => lexicographic
        // == numeric), the process-wide counter guarantees uniqueness within a
        // process even for same-instant attempts, and the random nonce extends
        // that across processes. Two concurrent attempts therefore can never
        // land in the same directory — the collision the old timestamp names
        // permitted.
        let attempt_id = new_attempt_id();
        let temporary_directory = checkpoint_dir.join(format!("{attempt_id}.{TEMP_FILE_EXTENSION}"));
        let checkpoint_directory = checkpoint_dir.join(attempt_id);
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
        use CheckpointCreateError::{
            CheckpointDirCreate, CheckpointDirRead, CompleteMarkerWrite, MissingStorageData, OldCheckpointRemove,
        };

        if !self.temporary_directory.join(STORAGE_METADATA_FILE_NAME).exists() {
            return Err(MissingStorageData { dir: self.temporary_directory.clone() });
        }

        // R-06: bind a machine manifest of every data file (relative path,
        // length, content digest) plus a root digest over them, fsync the whole
        // attempt tree bottom-up, and only THEN write the COMPLETE marker — the
        // very last file — and fsync it. The digest is computed over the sealed
        // bytes, so the marker can never certify content it did not measure.
        let manifest = CheckpointManifest::compute(&self.temporary_directory)
            .map_err(|error| CompleteMarkerWrite { dir: self.temporary_directory.clone(), source: Arc::new(error) })?;
        fsync_tree_bottom_up(&self.temporary_directory)
            .map_err(|error| CompleteMarkerWrite { dir: self.temporary_directory.clone(), source: Arc::new(error) })?;
        let complete_path = self.temporary_directory.join(CHECKPOINT_COMPLETE_FILE_NAME);
        write_file(&complete_path, manifest.serialise().as_bytes())
            .map_err(|error| CompleteMarkerWrite { dir: self.temporary_directory.clone(), source: Arc::new(error) })?;
        crate::fsync_path(&self.temporary_directory)
            .map_err(|error| CompleteMarkerWrite { dir: self.temporary_directory.clone(), source: Arc::new(error) })?;

        fail_point!(CHECKPOINT_DIR_CREATE_FAIL);

        // the atomic publish: the whole verified, COMPLETE-bearing tree appears
        // under its final name in one rename.
        fs::rename(&self.temporary_directory, &self.checkpoint_directory)
            .map_err(|error| CheckpointDirCreate { dir: self.checkpoint_directory.clone(), source: Arc::new(error) })?;
        // R-06: the rename itself must be durable, or a crash can leave the
        // parent directory pointing at the pre-rename tmp name.
        if let Some(parent) = self.checkpoint_directory.parent() {
            crate::fsync_path(parent)
                .map_err(|error| CheckpointDirCreate { dir: parent.to_owned(), source: Arc::new(error) })?;
        }

        fail_point!(CHECKPOINT_CLEANUP_FAIL);

        // R-04/R4-STOR-08: reclaim ONLY sibling checkpoints that are provably
        // both inactive AND OLDER than the cut just published. A `.tmp`
        // sibling is an in-flight attempt and is NEVER deleted; a finalized
        // sibling with a NEWER attempt id is a better cut published by an
        // attempt that finished first (this attempt captured earlier and
        // resumed later) and is NEVER deleted either — deleting it would
        // regress the selectable cut to this older one (the R4-STOR-08
        // defect). Cleanup runs strictly AFTER the durable publish above, so
        // a cleanup failure is a typed error that leaves the just-published
        // cut fully durable and selectable — retention failures never affect
        // the published cut.
        let siblings: Vec<PathBuf> = fs::read_dir(self.checkpoint_directory.parent().unwrap())
            .and_then(|entries| entries.map_ok(|entry| entry.path()).try_collect())
            .map_err(|error| CheckpointDirRead { dir: self.checkpoint_directory.clone(), source: Arc::new(error) })?;

        for previous_checkpoint in siblings_safe_to_delete(&self.checkpoint_directory, &siblings) {
            fail_point!(CHECKPOINT_CLEANUP_PARTIAL_FAIL);
            fs::remove_dir_all(&previous_checkpoint)
                .map_err(|error| OldCheckpointRemove { dir: previous_checkpoint, source: Arc::new(error) })?
        }

        Ok(CheckpointReader { directory: self.checkpoint_directory })
    }
}

/// R-04/R4-STOR-08: the subset of `entries` that `finish` may safely delete
/// after publishing `final_dir`. Retention is RECENCY-AWARE: only a finalized
/// sibling whose attempt id is LEXICOGRAPHICALLY OLDER than the just-published
/// attempt's own id is reclaimable.
///
/// Excluded, in order of the invariant each protects:
/// (a) every `.tmp` entry — an in-flight attempt another checkpoint may be
///     actively writing into (deleting one is the original R-04 collision);
/// (b) any entry that does not parse as an attempt id — a writer never
///     decides reachability of a foreign directory from a listing alone;
/// (c) every sibling whose id is NOT strictly older than `final_dir`'s —
///     which covers both the just-published directory itself (equal) and any
///     NEWER finalized sibling. A newer sibling is the better cut, published
///     by an attempt that captured later but finished first; the R4-STOR-08
///     defect was exactly an older attempt A finishing last and deleting the
///     newer published cut B, regressing selection to the older cut.
///
/// The attempt id format `<20-digit-nanos>-<counter>-<nonce>` makes
/// lexicographic comparison equal numeric recency (fixed-width nanos prefix);
/// two ids sharing an EXACTLY equal nanos prefix are still totally ordered by
/// the fixed-width counter and nonce components. This is the same total order
/// the reader's selection uses ([`verified_checkpoints_newest_first`]), so
/// cleanup can never delete the cut selection would pick.
fn siblings_safe_to_delete(final_dir: &Path, entries: &[PathBuf]) -> Vec<PathBuf> {
    let Some(final_name) = final_dir.file_name() else {
        return Vec::new();
    };
    entries
        .iter()
        .filter(|path| path.extension() != Some(TEMP_FILE_EXTENSION.as_ref()))
        .filter(|path| parse_attempt_nanos(path).is_some())
        .filter(|path| path.file_name().is_some_and(|name| name < final_name))
        .cloned()
        .collect()
}

/// R-04: a unique checkpoint-attempt id. `<20-digit-nanos>-<counter>-<nonce>`:
/// the fixed-width nanosecond prefix preserves recency ordering
/// (lexicographic == numeric), the process-wide [`ATTEMPT_COUNTER`] guarantees
/// two attempts in the same instant differ, and the random nonce extends
/// uniqueness across processes. Bare microsecond timestamps (the old scheme)
/// collided under rapid scheduling; a collision let one attempt land in
/// another's directory.
fn new_attempt_id() -> String {
    let nanos = Utc::now().timestamp_nanos_opt().unwrap_or(0).max(0) as u64;
    let counter = ATTEMPT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nonce = attempt_nonce();
    format!("{nanos:020}-{counter:016x}-{nonce:016x}")
}

/// A per-call random 64-bit nonce sourced from the standard-library hasher's
/// randomly-seeded keys (no non-dev `rand` dependency is available to this
/// crate). Distinct across calls and across processes.
fn attempt_nonce() -> u64 {
    std::collections::hash_map::RandomState::new().build_hasher().finish()
}

/// Parse the recency-ordering nanosecond prefix of an attempt directory name.
/// Returns `None` for a name that does not begin with the fixed-width nanos
/// component (an unrelated/foreign directory), which the selector skips.
fn parse_attempt_nanos(path: &Path) -> Option<u64> {
    let name = path.file_name()?.to_str()?;
    let prefix = name.split('-').next()?;
    prefix.parse::<u64>().ok()
}

/// fsync every regular file and then every directory under `root`, deepest
/// first, so a checkpoint the caller goes on to declare COMPLETE cannot lose a
/// file (or a directory entry) to a crash that empties the page cache (R-06).
fn fsync_tree_bottom_up(root: &Path) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        // no-follow: never traverse or fsync through a symlink/special file the
        // checkpoint tree should not contain — the one shared R-05 enforcement
        // point, which also yields the file-or-dir type to branch on.
        let file_type = assert_safe_checkpoint_entry(&path)?;
        if file_type.is_dir() {
            fsync_tree_bottom_up(&path)?;
        } else {
            crate::fsync_path(&path)?;
        }
    }
    crate::fsync_path(root)
}

/// R-06: the machine manifest a COMPLETE marker carries. It binds, for every
/// data file under the checkpoint root (the COMPLETE marker itself excluded),
/// the file's relative path, byte length, and a content digest, plus a root
/// digest over the whole sorted set. The reader recomputes this from the bytes
/// on disk and refuses any checkpoint where a file is missing, extra, changed,
/// or truncated — so a torn or tampered attempt can never be selected.
///
/// The digest is the standard-library content hasher (SipHash): sufficient to
/// catch truncation and accidental/adversarial content change for integrity,
/// but NOT a cryptographic commitment — this crate has no cryptographic-hash
/// dependency, and the backend *identity* is separately bound by the S-01
/// durable marker verified before any open.
struct CheckpointManifest {
    /// relative path (`/`-joined) -> (length, content digest)
    entries: BTreeMap<String, (u64, u64)>,
    root_digest: u64,
    /// Informational only (human-readable marker content). NOT a bound
    /// integrity input: `verify` compares `entries` + `root_digest`, and the
    /// STORAGE_METADATA file this is read from is itself a regular file under
    /// the root, so its bytes are already hashed into `entries`.
    watermark: Option<u64>,
}

const CHECKPOINT_MANIFEST_HEADER: &str = "CHECKPOINT-COMPLETE v1";

impl CheckpointManifest {
    /// Walk `root` (no-follow), hashing every regular file except the COMPLETE
    /// marker, and derive the bound manifest. Rejects symlinks/special files —
    /// the same no-follow invariant restore enforces (R-05).
    fn compute(root: &Path) -> io::Result<Self> {
        let mut entries = BTreeMap::new();
        Self::walk(root, root, &mut entries)?;
        let watermark =
            fs::read_to_string(root.join(STORAGE_METADATA_FILE_NAME)).ok().and_then(|s| s.trim().parse().ok());
        let root_digest = Self::root_digest(&entries);
        Ok(Self { entries, root_digest, watermark })
    }

    fn walk(root: &Path, dir: &Path, entries: &mut BTreeMap<String, (u64, u64)>) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            // same no-follow R-05 enforcement point as restore/fsync
            let file_type = assert_safe_checkpoint_entry(&path)?;
            if file_type.is_dir() {
                Self::walk(root, &path, entries)?;
            } else {
                let relative = path.strip_prefix(root).expect("walked path is under root");
                let key = relative.to_string_lossy().replace('\\', "/");
                if key == CHECKPOINT_COMPLETE_FILE_NAME {
                    continue; // the marker never certifies itself
                }
                let (len, digest) = hash_file(&path)?;
                entries.insert(key, (len, digest));
            }
        }
        Ok(())
    }

    fn root_digest(entries: &BTreeMap<String, (u64, u64)>) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for (key, (len, digest)) in entries {
            hasher.write(key.as_bytes());
            hasher.write_u8(0);
            hasher.write_u64(*len);
            hasher.write_u64(*digest);
        }
        hasher.finish()
    }

    fn serialise(&self) -> String {
        let mut out = String::new();
        out.push_str(CHECKPOINT_MANIFEST_HEADER);
        out.push('\n');
        out.push_str(&format!("root {:016x}\n", self.root_digest));
        if let Some(watermark) = self.watermark {
            out.push_str(&format!("watermark {watermark}\n"));
        }
        for (key, (len, digest)) in &self.entries {
            // hex-encode the relative path so any byte in a file name round
            // trips without colliding with the field separators.
            out.push_str(&format!("{len:016x} {digest:016x} {}\n", hex_encode(key.as_bytes())));
        }
        out
    }

    /// Verify the on-disk checkpoint tree against a serialised COMPLETE marker:
    /// recompute the manifest from the bytes and require exact equality of the
    /// entry set (paths, lengths, digests) and the root digest. Any missing,
    /// extra, changed, or truncated file makes this `false`.
    fn verify(root: &Path, serialised: &str) -> io::Result<bool> {
        let Some(parsed) = Self::parse(serialised) else {
            return Ok(false);
        };
        let recomputed = Self::compute(root)?;
        Ok(recomputed.entries == parsed.entries && recomputed.root_digest == parsed.root_digest)
    }

    fn parse(serialised: &str) -> Option<Self> {
        let mut lines = serialised.lines();
        if lines.next()? != CHECKPOINT_MANIFEST_HEADER {
            return None;
        }
        let mut entries = BTreeMap::new();
        let mut root_digest = None;
        let mut watermark = None;
        for line in lines {
            if let Some(rest) = line.strip_prefix("root ") {
                root_digest = u64::from_str_radix(rest.trim(), 16).ok();
            } else if let Some(rest) = line.strip_prefix("watermark ") {
                watermark = rest.trim().parse().ok();
            } else {
                let mut parts = line.split(' ');
                let len = u64::from_str_radix(parts.next()?, 16).ok()?;
                let digest = u64::from_str_radix(parts.next()?, 16).ok()?;
                let key_bytes = hex_decode(parts.next()?)?;
                let key = String::from_utf8(key_bytes).ok()?;
                entries.insert(key, (len, digest));
            }
        }
        Some(Self { entries, root_digest: root_digest?, watermark })
    }
}

/// Stream a file through the standard content hasher, returning (length, digest).
fn hash_file(path: &Path) -> io::Result<(u64, u64)> {
    let mut file = File::open(path)?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut len = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.write(&buffer[..read]);
        len = len.saturating_add(read as u64);
    }
    Ok((len, hasher.finish()))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok()).collect()
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
    CheckpointDirCreate {
        dir: PathBuf,
        source: Arc<io::Error>,
    },
    CheckpointDirRead {
        dir: PathBuf,
        source: Arc<io::Error>,
    },

    MissingStorageData {
        dir: PathBuf,
    },

    KeyspaceCheckpoint {
        dir: PathBuf,
        source: KeyspaceCheckpointError,
    },

    MetadataFileCreate {
        file_path: PathBuf,
        source: Arc<io::Error>,
    },
    MetadataWrite {
        file_path: PathBuf,
        source: Arc<io::Error>,
    },

    ExtensionDuplicate {
        name: String,
    },
    ExtensionIO {
        name: String,
        source: Arc<io::Error>,
    },
    ExtensionSerialise {
        name: String,
        source: Arc<bincode::Error>,
    },

    OldCheckpointRemove {
        dir: PathBuf,
        source: Arc<io::Error>,
    },

    /// R-06: failed to bind, fsync, or write the digest-bound COMPLETE marker.
    CompleteMarkerWrite {
        dir: PathBuf,
        source: Arc<io::Error>,
    },
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
            Self::CompleteMarkerWrite { source, .. } => Some(source),
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
        CheckpointAheadOfDurability(13, "The checkpoint in directory '{dir:?}' has watermark {watermark}, ahead of the durability head {durability_head}. The durability logs may have been truncated or the checkpoint is stale; refusing (was a process abort) so recovery can fall back to an older checkpoint or full WAL replay WITHOUT touching live state.", dir: PathBuf, watermark: SequenceNumber, durability_head: SequenceNumber),
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

#[cfg(test)]
mod concurrent_checkpoint_tests {
    //! R-04: concurrent checkpoints must not collide (share a directory) or
    //! delete each other's active attempt.

    use std::{collections::HashSet, path::PathBuf};

    use test_utils::create_tmp_dir;

    use super::{TEMP_FILE_EXTENSION, new_attempt_id, siblings_safe_to_delete};

    #[test]
    fn attempt_ids_are_unique_even_under_rapid_scheduling() {
        // Barrier for the "cannot share A's directory" half of R-04: a tight
        // loop schedules attempts far faster than a microsecond clock ticks.
        // Cryptographically-unique ids are all distinct; the old bare
        // microsecond-timestamp scheme (the mutant) collides here and the set
        // is smaller than the sample.
        const SAMPLES: usize = 20_000;
        let ids: HashSet<String> = (0..SAMPLES).map(|_| new_attempt_id()).collect();
        assert_eq!(ids.len(), SAMPLES, "attempt ids collided: bare timestamps are not unique under rapid scheduling");
    }

    #[test]
    fn an_active_tmp_attempt_is_never_a_deletion_target() {
        // Barrier for the "cannot delete A's active attempt" half of R-04:
        // while checkpoint A is mid-write into its `.tmp`, checkpoint B finishes
        // and runs cleanup. B may reclaim an older completed checkpoint but must
        // NEVER delete A's active `.tmp` nor its own just-published final dir.
        let base = create_tmp_dir("checkpoint-cleanup");
        let b_final: PathBuf = base.join("00000000000000000200-0000000000000002-aaaa");
        let older_complete: PathBuf = base.join("00000000000000000100-0000000000000000-bbbb");
        let a_active_tmp: PathBuf =
            base.join(format!("00000000000000000150-0000000000000001-cccc.{TEMP_FILE_EXTENSION}"));

        let entries = vec![b_final.clone(), older_complete.clone(), a_active_tmp.clone()];
        let to_delete = siblings_safe_to_delete(&b_final, &entries);

        assert!(to_delete.contains(&older_complete), "an older completed sibling should be reclaimable");
        assert!(!to_delete.contains(&b_final), "the just-published final directory must never be deleted");
        assert!(
            !to_delete.contains(&a_active_tmp),
            "an active .tmp attempt (checkpoint A mid-write) must never be deleted — the R-04 collision"
        );
    }

    #[test]
    fn a_newer_finalized_sibling_is_never_a_deletion_target() {
        // R4-STOR-08 core: older attempt A finishes AFTER newer attempt B has
        // already published. A's cleanup may reclaim cuts older than A, but
        // NEVER B — B is the better cut and must stay selectable.
        let base = create_tmp_dir("checkpoint-cleanup-recency");
        let a_final: PathBuf = base.join("00000000000000000100-0000000000000001-aaaa");
        let newer_b: PathBuf = base.join("00000000000000000200-0000000000000002-bbbb");
        let ancient: PathBuf = base.join("00000000000000000050-0000000000000000-cccc");

        let entries = vec![a_final.clone(), newer_b.clone(), ancient.clone()];
        let to_delete = siblings_safe_to_delete(&a_final, &entries);

        assert!(to_delete.contains(&ancient), "a strictly older completed sibling is reclaimable");
        assert!(
            !to_delete.contains(&newer_b),
            "R4-STOR-08: a NEWER finalized sibling is the better cut and must never be deleted"
        );
        assert!(!to_delete.contains(&a_final), "the just-published final directory must never be deleted");
    }

    #[test]
    fn equal_nanos_prefix_ids_are_ordered_by_the_counter_component() {
        // The exact-equal clock prefix case: two attempts in the same instant
        // share the 20-digit nanos prefix; the fixed-width counter (and nonce)
        // still totally order them, so recency-aware cleanup stays exact.
        let base = create_tmp_dir("checkpoint-cleanup-equal-nanos");
        let older: PathBuf = base.join("00000000000000000100-0000000000000001-aaaa");
        let newer: PathBuf = base.join("00000000000000000100-0000000000000002-bbbb");

        let entries = vec![older.clone(), newer.clone()];
        assert!(
            siblings_safe_to_delete(&newer, &entries).contains(&older),
            "with equal nanos, the smaller counter is the older attempt and is reclaimable"
        );
        assert!(
            !siblings_safe_to_delete(&older, &entries).contains(&newer),
            "with equal nanos, the larger counter is the newer attempt and must survive"
        );
    }

    #[test]
    fn a_foreign_directory_is_never_a_deletion_target() {
        // A writer never decides reachability of a directory it cannot prove
        // is a checkpoint attempt from a listing alone: an entry that does not
        // parse as an attempt id is left untouched.
        let base = create_tmp_dir("checkpoint-cleanup-foreign");
        let b_final: PathBuf = base.join("00000000000000000200-0000000000000002-aaaa");
        let foreign: PathBuf = base.join("operator-scratch");

        let to_delete = siblings_safe_to_delete(&b_final, &[b_final.clone(), foreign.clone()]);
        assert!(!to_delete.contains(&foreign), "a non-attempt (foreign) directory must never be deleted");
    }
}

#[cfg(test)]
mod finish_barrier_tests {
    //! R4-STOR-08: the audit's deterministic barrier, run through the REAL
    //! `CheckpointWriter::finish` — capture order and completion order are
    //! decoupled, and the newer published cut always survives and stays
    //! selected, whichever attempt finishes last.

    use std::{fs, path::Path};

    use test_utils::create_tmp_dir;

    use super::{
        CheckpointCreateError, CheckpointWriter, STORAGE_METADATA_FILE_NAME, TEMP_FILE_EXTENSION,
        verified_checkpoints_newest_first,
    };

    #[derive(Clone, Copy)]
    enum TestKs {
        Main,
    }
    impl crate::keyspace::KeyspaceSet for TestKs {
        fn iter() -> impl Iterator<Item = Self> {
            [Self::Main].into_iter()
        }
        fn id(&self) -> crate::keyspace::KeyspaceId {
            crate::keyspace::KeyspaceId(0)
        }
        fn name(&self) -> &'static str {
            "keyspace"
        }
        fn prefix_length(&self) -> Option<usize> {
            None
        }
    }

    /// An in-flight attempt with a fabricated id: a `.tmp` tree carrying the
    /// keyspace data and watermark metadata `finish` requires — the state an
    /// attempt is in right after `add_storage` (captured, not yet sealed).
    fn captured_attempt(checkpoint_parent: &Path, attempt_id: &str, watermark: &str) -> CheckpointWriter {
        let temporary_directory = checkpoint_parent.join(format!("{attempt_id}.{TEMP_FILE_EXTENSION}"));
        fs::create_dir_all(temporary_directory.join("keyspace")).unwrap();
        fs::write(temporary_directory.join("keyspace").join("data.sst"), format!("bytes-of-{attempt_id}")).unwrap();
        fs::write(temporary_directory.join(STORAGE_METADATA_FILE_NAME), watermark).unwrap();
        CheckpointWriter { checkpoint_directory: checkpoint_parent.join(attempt_id), temporary_directory }
    }

    fn selected_name(checkpoint_parent: &Path) -> Option<String> {
        verified_checkpoints_newest_first::<TestKs>(fs::read_dir(checkpoint_parent).unwrap())
            .unwrap()
            .first()
            .map(|c| c.directory.file_name().unwrap().to_str().unwrap().to_owned())
    }

    const A_OLDER: &str = "00000000000000000100-0000000000000001-aaaa";
    const B_NEWER: &str = "00000000000000000200-0000000000000002-bbbb";

    #[test]
    fn reverse_completion_preserves_the_newer_published_cut() {
        // The audit barrier: A captures first (older id), B captures newer
        // and publishes, A resumes and finishes LAST. B must remain published
        // and selected — A cannot remove it.
        let base = create_tmp_dir("finish-reverse");
        let a = captured_attempt(&base, A_OLDER, "10");
        let b = captured_attempt(&base, B_NEWER, "20");

        b.finish().expect("B publishes first");
        a.finish().expect("A finishes last and must not fail");

        assert!(base.join(B_NEWER).exists(), "R4-STOR-08: A's cleanup must not delete the newer published cut B");
        assert_eq!(
            selected_name(&base).as_deref(),
            Some(B_NEWER),
            "the newer cut B must remain the selected candidate after A finishes"
        );
    }

    #[test]
    fn forward_completion_reclaims_the_older_cut() {
        // reverse-order control: A publishes first, B finishes last and — as
        // the strictly newer cut — reclaims A. Selection is monotonic either
        // way: the newest published cut wins.
        let base = create_tmp_dir("finish-forward");
        let a = captured_attempt(&base, A_OLDER, "10");
        let b = captured_attempt(&base, B_NEWER, "20");

        a.finish().expect("A publishes first");
        b.finish().expect("B finishes last");

        assert!(!base.join(A_OLDER).exists(), "the strictly older cut A is reclaimed by B's cleanup");
        assert_eq!(selected_name(&base).as_deref(), Some(B_NEWER), "the newer cut B is selected");
    }

    #[test]
    fn equal_clock_prefix_reverse_completion_preserves_the_newer_cut() {
        // equal-nanos mutant: the two attempt ids share the exact 20-digit
        // nanos prefix and differ only in the counter component; recency is
        // still total and the newer cut survives reverse completion.
        const A_EQ: &str = "00000000000000000300-0000000000000003-cccc";
        const B_EQ: &str = "00000000000000000300-0000000000000004-dddd";
        let base = create_tmp_dir("finish-equal-nanos");
        let a = captured_attempt(&base, A_EQ, "10");
        let b = captured_attempt(&base, B_EQ, "20");

        b.finish().expect("B (same nanos, larger counter) publishes first");
        a.finish().expect("A finishes last");

        assert!(base.join(B_EQ).exists(), "the same-instant newer cut must survive the older finisher's cleanup");
        assert_eq!(selected_name(&base).as_deref(), Some(B_EQ), "selection orders equal-nanos ids by counter");
    }

    #[test]
    fn a_cleanup_failure_does_not_affect_the_published_cut() {
        // Retention runs strictly after the durable publish: force cleanup to
        // fail deterministically (an older sibling that is a regular FILE with
        // an attempt-id name — `remove_dir_all` on it errors on every
        // platform) and prove the just-published cut is untouched, verified,
        // and selected despite the typed cleanup error.
        const UNDELETABLE_OLDER: &str = "00000000000000000050-0000000000000000-eeee";
        let base = create_tmp_dir("finish-cleanup-failure");
        fs::write(base.join(UNDELETABLE_OLDER), b"not-a-directory").unwrap();
        let b = captured_attempt(&base, B_NEWER, "20");

        let error = b.finish().err().expect("cleanup failure must surface as a typed error");
        assert!(
            matches!(error, CheckpointCreateError::OldCheckpointRemove { .. }),
            "cleanup failure is the typed OldCheckpointRemove error, got: {error:?}"
        );
        assert!(base.join(B_NEWER).exists(), "the published cut survives a cleanup failure");
        assert_eq!(
            selected_name(&base).as_deref(),
            Some(B_NEWER),
            "the published cut remains digest-verified and selected despite the cleanup failure"
        );
    }
}

#[cfg(test)]
mod restore_safety_tests {
    //! R-05: restore is validated before it touches live state, opens entries
    //! no-follow, and refuses symlinks/special files.

    use std::{fs, path::Path};

    use test_utils::create_tmp_dir;

    use super::{
        CheckpointLoadError, SequenceNumber, restore_checkpoint_tree, restore_storage_from_checkpoint,
        validate_watermark,
    };

    /// The exact validate-then-restore composition the recovery loop in
    /// `MVCCStorage::load_with_recovery_fallback` runs per candidate
    /// (validation phase first, destructive mirror only on success), inlined
    /// here so the R-05 ordering mutant — mirror first, validate after — is a
    /// hermetic, deterministic test.
    fn validate_then_restore<KS: crate::keyspace::KeyspaceSet>(
        checkpoint_dir: &std::path::Path,
        keyspaces_dir: &std::path::Path,
        durability_previous: SequenceNumber,
    ) -> Result<SequenceNumber, CheckpointLoadError> {
        let watermark = validate_watermark(checkpoint_dir, durability_previous)?;
        restore_checkpoint_tree::<KS>(checkpoint_dir, keyspaces_dir)?;
        Ok(watermark)
    }

    #[derive(Clone, Copy)]
    enum TestKs {
        Main,
    }
    impl crate::keyspace::KeyspaceSet for TestKs {
        fn iter() -> impl Iterator<Item = Self> {
            [Self::Main].into_iter()
        }
        fn id(&self) -> crate::keyspace::KeyspaceId {
            crate::keyspace::KeyspaceId(0)
        }
        fn name(&self) -> &'static str {
            "keyspace"
        }
        fn prefix_length(&self) -> Option<usize> {
            None
        }
    }

    /// A live keyspace tree with a sentinel file whose bytes prove whether
    /// restore touched live state.
    fn live_tree_with_sentinel(root: &Path) -> std::path::PathBuf {
        let keyspace = root.join("keyspace");
        fs::create_dir_all(&keyspace).unwrap();
        let sentinel = keyspace.join("SENTINEL");
        fs::write(&sentinel, b"original-live-bytes").unwrap();
        sentinel
    }

    #[test]
    fn a_corrupt_watermark_leaves_live_state_untouched() {
        let checkpoint = create_tmp_dir("ckpt-corrupt");
        fs::create_dir_all(checkpoint.join("keyspace")).unwrap();
        fs::write(checkpoint.join("keyspace").join("data.sst"), b"checkpoint-bytes").unwrap();
        fs::write(checkpoint.join(super::STORAGE_METADATA_FILE_NAME), b"not-a-number").unwrap();

        let live = create_tmp_dir("live-corrupt");
        let sentinel = live_tree_with_sentinel(&live);

        let result = validate_then_restore::<TestKs>(&checkpoint, &live, SequenceNumber::new(1000));
        assert!(
            matches!(result, Err(CheckpointLoadError::MetadataCorrupt { .. })),
            "corrupt watermark must be a typed refusal, got {result:?}"
        );
        assert_eq!(
            fs::read(&sentinel).unwrap(),
            b"original-live-bytes",
            "R-05: live state must be byte-identical after a rejected (corrupt) checkpoint"
        );
    }

    #[test]
    fn an_ahead_watermark_is_a_typed_refusal_not_a_panic_and_leaves_live_untouched() {
        let checkpoint = create_tmp_dir("ckpt-ahead");
        fs::create_dir_all(checkpoint.join("keyspace")).unwrap();
        fs::write(checkpoint.join("keyspace").join("data.sst"), b"checkpoint-bytes").unwrap();
        // watermark 500 is ahead of a durability head of 50
        fs::write(checkpoint.join(super::STORAGE_METADATA_FILE_NAME), b"500").unwrap();

        let live = create_tmp_dir("live-ahead");
        let sentinel = live_tree_with_sentinel(&live);

        let result = validate_then_restore::<TestKs>(&checkpoint, &live, SequenceNumber::new(50));
        assert!(
            matches!(result, Err(CheckpointLoadError::CheckpointAheadOfDurability { .. })),
            "an ahead checkpoint must be typed (was a panic), got {result:?}"
        );
        assert_eq!(
            fs::read(&sentinel).unwrap(),
            b"original-live-bytes",
            "R-05: live state must be byte-identical after a rejected (ahead) checkpoint"
        );
    }

    #[test]
    fn a_valid_checkpoint_restores_and_replaces_live_bytes() {
        // positive control: a well-formed checkpoint DOES restore (proving the
        // validation gate is not simply refusing everything).
        let checkpoint = create_tmp_dir("ckpt-valid");
        fs::create_dir_all(checkpoint.join("keyspace")).unwrap();
        fs::write(checkpoint.join("keyspace").join("SENTINEL"), b"checkpoint-bytes").unwrap();
        fs::write(checkpoint.join(super::STORAGE_METADATA_FILE_NAME), b"10").unwrap();

        let live = create_tmp_dir("live-valid");
        let sentinel = live_tree_with_sentinel(&live);

        let watermark = validate_then_restore::<TestKs>(&checkpoint, &live, SequenceNumber::new(1000)).unwrap();
        assert_eq!(watermark, SequenceNumber::new(10));
        assert_eq!(fs::read(&sentinel).unwrap(), b"checkpoint-bytes", "a valid checkpoint should overwrite live bytes");
    }

    #[test]
    fn a_symlink_checkpoint_entry_is_refused_without_following_it() {
        let checkpoint = create_tmp_dir("ckpt-symlink");
        let ckpt_keyspace = checkpoint.join("keyspace");
        fs::create_dir_all(&ckpt_keyspace).unwrap();
        // a crafted checkpoint entry that is a symlink to a secret outside the
        // intended root
        let secret = create_tmp_dir("symlink-secret-target");
        let secret_file = secret.join("secret");
        fs::write(&secret_file, b"escaped").unwrap();
        std::os::unix::fs::symlink(&secret_file, ckpt_keyspace.join("evil")).unwrap();

        let live = create_tmp_dir("live-symlink");
        let live_keyspace = live.join("keyspace");
        fs::create_dir_all(&live_keyspace).unwrap();

        let result = restore_storage_from_checkpoint(live_keyspace.clone(), ckpt_keyspace);
        assert!(result.is_err(), "R-05: a symlink checkpoint entry must be refused, not followed");
        assert!(
            !live_keyspace.join("evil").exists(),
            "restore must not have created anything through the symlink into live state"
        );
    }
}

#[cfg(test)]
mod complete_marker_tests {
    //! R-06: a checkpoint is selectable only with a digest-bound COMPLETE marker
    //! that verifies against the bytes on disk.

    use std::fs;

    use test_utils::create_tmp_dir;

    use super::{
        CHECKPOINT_COMPLETE_FILE_NAME, CheckpointManifest, CheckpointReader, STORAGE_METADATA_FILE_NAME,
        TEMP_FILE_EXTENSION, verified_checkpoints_newest_first,
    };

    #[derive(Clone, Copy)]
    enum TestKs {
        Main,
    }
    impl crate::keyspace::KeyspaceSet for TestKs {
        fn iter() -> impl Iterator<Item = Self> {
            [Self::Main].into_iter()
        }
        fn id(&self) -> crate::keyspace::KeyspaceId {
            crate::keyspace::KeyspaceId(0)
        }
        fn name(&self) -> &'static str {
            "keyspace"
        }
        fn prefix_length(&self) -> Option<usize> {
            None
        }
    }

    /// Build a checkpoint directory the way `finish` does: data + metadata, then
    /// a COMPLETE marker bound to the sealed bytes, written last.
    fn build_complete_checkpoint(dir: &std::path::Path) {
        fs::create_dir_all(dir.join("keyspace")).unwrap();
        fs::write(dir.join("keyspace").join("data.sst"), b"the-sst-bytes").unwrap();
        fs::write(dir.join(STORAGE_METADATA_FILE_NAME), b"7").unwrap();
        let manifest = CheckpointManifest::compute(dir).unwrap();
        fs::write(dir.join(CHECKPOINT_COMPLETE_FILE_NAME), manifest.serialise().as_bytes()).unwrap();
    }

    #[test]
    fn a_verified_complete_checkpoint_is_selectable() {
        let dir = create_tmp_dir("ckpt-complete");
        build_complete_checkpoint(&dir);
        let reader = CheckpointReader { directory: dir.to_path_buf() };
        assert!(reader.is_complete::<TestKs>().unwrap(), "a digest-verified COMPLETE checkpoint must be selectable");
    }

    #[test]
    fn a_missing_complete_marker_is_not_selectable() {
        let dir = create_tmp_dir("ckpt-no-complete");
        fs::create_dir_all(dir.join("keyspace")).unwrap();
        fs::write(dir.join("keyspace").join("data.sst"), b"the-sst-bytes").unwrap();
        fs::write(dir.join(STORAGE_METADATA_FILE_NAME), b"7").unwrap();
        // no COMPLETE marker
        let reader = CheckpointReader { directory: dir.to_path_buf() };
        assert!(
            !reader.is_complete::<TestKs>().unwrap(),
            "a checkpoint carrying data + metadata but no COMPLETE marker is a torn attempt, not selectable"
        );
    }

    #[test]
    fn a_truncated_file_after_complete_is_rejected() {
        // R-06 mutant kill: COMPLETE binds the digest. If the reader trusted
        // COMPLETE's mere presence (the mutant), this truncated checkpoint would
        // be accepted; the digest recomputation catches it.
        let dir = create_tmp_dir("ckpt-truncated");
        build_complete_checkpoint(&dir);
        // corrupt/truncate a data file AFTER the marker was written
        fs::write(dir.join("keyspace").join("data.sst"), b"trunc").unwrap();
        let reader = CheckpointReader { directory: dir.to_path_buf() };
        assert!(
            !reader.is_complete::<TestKs>().unwrap(),
            "a checkpoint whose bytes no longer match the bound digest must be rejected"
        );
    }

    #[test]
    fn an_added_file_after_complete_is_rejected() {
        let dir = create_tmp_dir("ckpt-extra");
        build_complete_checkpoint(&dir);
        fs::write(dir.join("keyspace").join("unexpected.sst"), b"extra").unwrap();
        let reader = CheckpointReader { directory: dir.to_path_buf() };
        assert!(!reader.is_complete::<TestKs>().unwrap(), "an extra file not bound by the manifest must be rejected");
    }

    #[test]
    fn selection_prefers_a_verified_older_over_an_unverified_newer() {
        // R-05 newest->older fallback seed: a newer directory that fails
        // verification must not shadow an older one that verifies.
        let base = create_tmp_dir("ckpt-select");
        let older = base.join("00000000000000000100-0000000000000000-aaaa");
        let newer = base.join("00000000000000000200-0000000000000001-bbbb");
        build_complete_checkpoint(&older);
        // newer has data + metadata but a corrupted COMPLETE (unverifiable)
        build_complete_checkpoint(&newer);
        fs::write(newer.join("keyspace").join("data.sst"), b"corrupted-after-complete").unwrap();

        let verified = verified_checkpoints_newest_first::<TestKs>(fs::read_dir(&base).unwrap()).unwrap();
        let selected = verified.first().expect("the older verified checkpoint must be selected");
        assert_eq!(
            selected.directory.file_name().unwrap(),
            older.file_name().unwrap(),
            "the older verified checkpoint must win over the newer unverifiable one"
        );
        assert_eq!(verified.len(), 1, "the unverifiable newer directory must not be a candidate at all");
    }

    #[test]
    fn an_in_flight_tmp_attempt_is_never_selected() {
        let base = create_tmp_dir("ckpt-tmp-skip");
        let tmp = base.join(format!("00000000000000000300-0000000000000002-cccc.{TEMP_FILE_EXTENSION}"));
        build_complete_checkpoint(&tmp); // even a fully-built .tmp must be skipped
        let verified = verified_checkpoints_newest_first::<TestKs>(fs::read_dir(&base).unwrap()).unwrap();
        assert!(verified.is_empty(), "a .tmp attempt is in-flight and must never be selected");
    }

    #[test]
    fn candidates_are_enumerated_newest_to_oldest_by_full_attempt_id() {
        // R4-STOR-10: the fallback loop consumes candidates newest-first, in
        // the SAME total order retention uses — full-attempt-id lexicographic.
        // The two same-nanos entries are ordered by their counter component.
        let base = create_tmp_dir("ckpt-enumerate-order");
        let oldest = base.join("00000000000000000100-0000000000000001-aaaa");
        let middle = base.join("00000000000000000200-0000000000000002-bbbb");
        let newest = base.join("00000000000000000200-0000000000000003-cccc"); // equal nanos, larger counter
        for dir in [&oldest, &middle, &newest] {
            build_complete_checkpoint(dir);
        }
        let verified = verified_checkpoints_newest_first::<TestKs>(fs::read_dir(&base).unwrap()).unwrap();
        let names: Vec<_> =
            verified.iter().map(|c| c.directory.file_name().unwrap().to_str().unwrap().to_owned()).collect();
        assert_eq!(
            names,
            vec![
                newest.file_name().unwrap().to_str().unwrap(),
                middle.file_name().unwrap().to_str().unwrap(),
                oldest.file_name().unwrap().to_str().unwrap(),
            ],
            "candidates must be newest-first by full attempt id (equal nanos disambiguated by counter)"
        );
    }
}
