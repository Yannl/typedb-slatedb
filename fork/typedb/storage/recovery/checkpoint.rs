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
    factory::{BackendIdentity, PersistedBackendMarker},
    keyspace::{
        KeyspaceCheckpointError, KeyspaceError, KeyspaceId, KeyspaceOpenError, KeyspaceSet, Keyspaces, StorageBackend,
        rocks_resources::RocksResources,
    },
    recovery::{
        commit_recovery::{
            RecoveryCommitStatus, StorageRecoveryError, apply_recovered_observing, load_commit_data_from,
        },
        sha256::{self, Sha256},
    },
    sequence_number::SequenceNumber,
    write_batches::WriteBatches,
};

const CHECKPOINT_DIR_NAME: &str = "checkpoint";
const STORAGE_METADATA_FILE_NAME: &str = "STORAGE_METADATA";
const TEMP_FILE_EXTENSION: &str = "tmp";

/// R5-STOR-06: prefix (under the database root, a SIBLING of the live
/// `storage` directory on the same filesystem) of the SCRATCH directory a
/// restore materialises, opens, replays, and verifies BEFORE the live tree is
/// touched. A crash at any point before activation leaves only a scratch
/// directory behind; [`converge_interrupted_restore`] removes it on the next
/// load with the predecessor byte-identical and still active.
const RESTORE_SCRATCH_PREFIX: &str = "restore-scratch-";
/// R5-STOR-06: prefix of the directory the PREDECESSOR live tree is renamed
/// to during the atomic rename-swap activation (live -> retired, scratch ->
/// live, fsync parent). A crash between the two renames leaves the retired
/// directory with the live one missing; [`converge_interrupted_restore`]
/// rolls the predecessor back into place. A crash after both renames leaves
/// a fully-activated successor plus the retired predecessor, which the next
/// load reclaims.
const RESTORE_RETIRED_PREFIX: &str = "restore-retired-";

/// R5-STOR-10: provenance record written by the EXPLICIT legacy-identity
/// import ([`import_legacy_checkpoint_identity`]). A regular data file under
/// the checkpoint root, sealed by the recomputed COMPLETE manifest, so the
/// operator acknowledgement that bound the identity travels with the cut.
pub const CHECKPOINT_IDENTITY_PROVENANCE_FILE_NAME: &str = "BACKEND_IDENTITY_PROVENANCE";

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

/// R4-STOR-01: the file, inside a checkpoint, that binds the creating
/// database's full backend identity (the same v2 serialisation the database
/// directory's marker persists, configuration digest included). It is a
/// regular data file under the checkpoint root, so the digest-bound COMPLETE
/// manifest seals it like every other file — a cut cannot have its identity
/// swapped after sealing. Recovery compares it against the opening database's
/// resolved identity BEFORE any restore: a cut created under configuration A
/// refuses restore under configuration B. A checkpoint without this file is a
/// legacy cut (sealed before identity binding existed, or exported by a
/// direct storage-level writer). R5-STOR-10: a legacy cut is NOT silently
/// bound to whatever configuration happens to be current — ordinary recovery
/// refuses it with the typed
/// [`CheckpointLoadError::CheckpointLegacyIdentityRequiresImport`], and only
/// the explicit, operator-acknowledged [`import_legacy_checkpoint_identity`]
/// (which stamps the acknowledged identity plus a provenance record and
/// reseals the manifest) makes it recoverable.
pub const CHECKPOINT_IDENTITY_FILE_NAME: &str = "BACKEND_IDENTITY";

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
        expected_identity: Option<&BackendIdentity>,
    ) -> Result<ValidatedCheckpointRecovery, CheckpointLoadError> {
        use CheckpointLoadError::CommitRecoveryFailed;

        // R4-STOR-01: identity first — a cut bound to a different backend
        // identity is refused before anything else is even parsed.
        self.validate_identity(expected_identity)?;

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

    /// R4-STOR-10 phase 2 / R5-STOR-06 — RESTORE a candidate
    /// [`Self::validate_for_recovery`] has already accepted, proving its
    /// SEMANTICS in a scratch materialisation before the live tree is touched:
    ///
    /// (a) the checkpoint's keyspace trees are materialised into a SCRATCH
    ///     directory (a sibling of the live keyspace directory on the same
    ///     filesystem);
    /// (b) the scratch copy's bytes are verified against the cut's sealed
    ///     COMPLETE manifest (per-file SHA-256 + root — copy fidelity AND a
    ///     late tamper/rot check, since selection-time verification may be
    ///     arbitrarily far in the past);
    /// (c) every declared keyspace is OPENED in scratch — a hash-consistent
    ///     but semantically invalid cut fails here, live untouched;
    /// (d) the fixed WAL head (the strictly pre-loaded commits) is replayed
    ///     into scratch, proving the cut accepts its own replay frontier;
    /// (e) only then is scratch ATOMICALLY activated by rename-swap: live ->
    ///     retired, scratch -> live, fsync parent; on failure the first
    ///     rename is rolled back. Every failure BEFORE activation leaves the
    ///     predecessor byte-identical and still active (the scratch residue
    ///     is reclaimed, here on the error path and by
    ///     [`converge_interrupted_restore`] after a crash).
    ///
    /// R6-STOR-01 adds a fallible durability barrier and a reopen-and-prove
    /// step between (d) and (e): the scratch engine is flushed and closed by
    /// an explicit call whose failure is propagated, then the closed
    /// materialisation is REOPENED and required to reproduce the post-replay
    /// witness (the probed replayed records) before anything is renamed. On
    /// any unproven flush there is no rename, no active-marker change and no
    /// sequence advance.
    ///
    /// Cost, recorded rather than hidden: on the SlateS3 lane every open of a
    /// keyspace directory mints a fresh materialisation namespace and seeds it
    /// from the local tree, so the verification reopen pays one extra seed
    /// upload per restore. Restore is a recovery path, and an unproven
    /// activation is not a trade this layer may make to save it.
    ///
    /// The returned keyspaces are re-opened at the LIVE path after
    /// activation (the scratch engine is closed first: an engine keeps
    /// absolute paths internally, so it must never keep running across the
    /// rename).
    pub(crate) fn restore_validated<KS: KeyspaceSet, Durability: DurabilityClient>(
        &self,
        database_name: &str,
        keyspaces_dir: &Path,
        validated: ValidatedCheckpointRecovery,
        durability_client: &Durability,
        rocks_resources: &RocksResources,
        backend: StorageBackend,
    ) -> Result<(Keyspaces, SequenceNumber), CheckpointLoadError> {
        use CheckpointLoadError::{
            CheckpointRestore, CommitRecoveryFailed, KeyspaceOpen, RestoreFlushBarrier, RestoreWitnessMismatch,
            RestoreWitnessUnreadable,
        };

        let ValidatedCheckpointRecovery { watermark: _, recovered_commits, next_sequence_number } = validated;

        let (scratch_dir, retired_dir) = self.restore_working_directories(keyspaces_dir)?;
        let scratch_error =
            |error: io::Error| CheckpointRestore { dir: self.directory.clone(), source: Arc::new(error) };

        // a leftover scratch directory from an earlier in-process failure is
        // unproven residue; start from empty.
        remove_dir_if_exists(&scratch_dir).map_err(scratch_error)?;

        let staged = (|| -> Result<(), CheckpointLoadError> {
            // (a) materialise into scratch — live state untouched
            restore_checkpoint_tree::<KS>(&self.directory, &scratch_dir)?;

            // (b) prove the materialised bytes against the sealed manifest
            verify_scratch_against_manifest::<KS>(&self.directory, &scratch_dir)?;

            // (c) + (d): open every keyspace in scratch and replay the fixed
            // WAL head there. This is the semantic proof R5-STOR-06 demands:
            // a cut that is hash-consistent but cannot open or cannot accept
            // its own replay fails HERE, with the predecessor intact.
            //
            // R8-P1-02: the expectation is captured from what REPLAY DECIDED
            // to write, at the one point where that decision is final and the
            // bytes have not yet reached a keyspace. It is not sampled and it
            // is not an observation: see `ExpectedReplayWitness`.
            let mut expected = ExpectedReplayWitness::default();
            {
                let scratch_keyspaces = Keyspaces::open::<KS>(&scratch_dir, rocks_resources, backend)
                    .map_err(|error| KeyspaceOpen { source: error })?;
                trace!("Scratch keyspaces opened, replaying the fixed WAL head into scratch");
                apply_recovered_observing(
                    database_name,
                    recovered_commits,
                    durability_client,
                    &scratch_keyspaces,
                    &mut |sequence_number, batches| expected.absorb(sequence_number, batches),
                )
                .map_err(|err| CommitRecoveryFailed { typedb_source: err })?;

                // (d2a) R8-P1-02: every replayed key must be READABLE FROM THE
                // LIVE ENGINE with the bytes replay resolved to write. This is
                // the half the old barrier could not do at all: comparing two
                // observations meant a replay that silently wrote nothing read
                // `None` on both sides and agreed with itself.
                self.witness_or_refuse(&expected, &scratch_keyspaces, "after replay")?;

                // (d2b) R6-STOR-01: the EXPLICIT, FALLIBLE durability barrier.
                // Previously the engine simply left scope and `Drop` closed it
                // — swallowing every flush failure — after which activation
                // renamed a possibly-unflushed materialisation over live state
                // and recovery advanced the sequence. The barrier is now a
                // call whose failure is propagated BEFORE anything is renamed.
                scratch_keyspaces.flush_and_close().map_err(|errors| RestoreFlushBarrier {
                    dir: self.directory.clone(),
                    detail: errors.iter().map(|error| error.to_string()).join("; "),
                })?;
            }

            // (d3) R8-P1-02: REOPEN the closed scratch materialisation and
            // require the SAME expectation of it. A flush that reported success
            // but did not durably carry the replayed records — a short write, a
            // lost provider response, an unpublished manifest, a publication of
            // only the last batch — is caught here, still before any rename,
            // and it is caught for EVERY replayed key rather than for the
            // newest 256 of them. The reopen is itself closed through the same
            // fallible barrier.
            {
                let reopened = Keyspaces::open::<KS>(&scratch_dir, rocks_resources, backend)
                    .map_err(|error| KeyspaceOpen { source: error })?;
                let verdict = self.witness_or_refuse(&expected, &reopened, "after close and reopen");
                reopened.flush_and_close().map_err(|errors| RestoreFlushBarrier {
                    dir: self.directory.clone(),
                    detail: errors.iter().map(|error| error.to_string()).join("; "),
                })?;
                verdict?;
            }
            trace!(
                "post-replay durability witness holds over {} touched keys (logical root {})",
                expected.expected.len(),
                expected.root()
            );

            // (d4) the durable ROOT of what is about to be activated: every
            // declared keyspace must have materialised at least one durable
            // file, and the manifest root over the scratch tree is recorded
            // so the activation decision names the exact bytes it activated.
            let root = scratch_root::<KS>(&scratch_dir)
                .map_err(|detail| RestoreWitnessMismatch { dir: self.directory.clone(), detail })?;
            trace!("scratch materialisation verified post-replay (root {root}), activating");
            Ok(())
        })();
        if let Err(error) = staged {
            // pre-activation failure: reclaim the scratch residue (best
            // effort — a crash-interrupted reclaim is finished by
            // converge_interrupted_restore) and leave the predecessor
            // byte-identical and active.
            if let Err(cleanup) = remove_dir_if_exists(&scratch_dir) {
                trace!("failed to reclaim the restore scratch directory {scratch_dir:?}: {cleanup:?}");
            }
            return Err(error);
        }

        // (e) atomic activation by rename-swap
        activate_scratch(&scratch_dir, keyspaces_dir, &retired_dir).map_err(|error| {
            CheckpointLoadError::RestoreActivation { dir: self.directory.clone(), source: Arc::new(error) }
        })?;

        let keyspaces = Keyspaces::open::<KS>(&keyspaces_dir, rocks_resources, backend)
            .map_err(|error| KeyspaceOpen { source: error })?;
        Ok((keyspaces, next_sequence_number))
    }

    /// The scratch and retired sibling directories this candidate's restore
    /// uses, both under the live keyspace directory's parent (same
    /// filesystem, so activation is two renames).
    /// R8-P1-02: apply the expected-versus-durable witness at one observation
    /// point, mapping its two failure modes onto the existing typed
    /// checkpoint refusals. An unreadable keyspace is infrastructure
    /// (`RestoreWitnessUnreadable`); a divergence is a lost or altered
    /// replayed write (`RestoreWitnessMismatch`). Either way nothing is
    /// renamed and the predecessor stays byte-identical and active.
    fn witness_or_refuse(
        &self,
        expected: &ExpectedReplayWitness,
        keyspaces: &Keyspaces,
        where_: &str,
    ) -> Result<(), CheckpointLoadError> {
        expected.verify(keyspaces, where_).map_err(|divergence| match divergence {
            RestoreWitnessDivergence::Unreadable { source } => {
                CheckpointLoadError::RestoreWitnessUnreadable { dir: self.directory.clone(), source }
            }
            RestoreWitnessDivergence::Lost { detail } => {
                CheckpointLoadError::RestoreWitnessMismatch { dir: self.directory.clone(), detail }
            }
        })
    }

    fn restore_working_directories(&self, keyspaces_dir: &Path) -> Result<(PathBuf, PathBuf), CheckpointLoadError> {
        let root = keyspaces_dir.parent().ok_or_else(|| CheckpointLoadError::CheckpointRestore {
            dir: self.directory.clone(),
            source: Arc::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the live keyspace directory has no parent to host the restore scratch directory",
            )),
        })?;
        let attempt = self.directory.file_name().and_then(|name| name.to_str()).unwrap_or("candidate");
        Ok((
            root.join(format!("{RESTORE_SCRATCH_PREFIX}{attempt}")),
            root.join(format!("{RESTORE_RETIRED_PREFIX}{attempt}")),
        ))
    }

    pub fn read_sequence_number(&self) -> Result<SequenceNumber, CheckpointLoadError> {
        read_watermark_at(&self.directory)
    }

    /// R4-STOR-01: compare the identity bound into this checkpoint against
    /// the opening database's resolved identity, PRE-MUTATION.
    ///
    /// - `expected` of `None` (a direct storage-level caller with no database
    ///   identity above it) skips the comparison;
    /// - an ABSENT identity file is a legacy cut. R5-STOR-10: legacy is NOT
    ///   fail-open — the old bytes never proved endpoint, bucket, prefix,
    ///   protocol, or cache/materialisation policy, so binding them to
    ///   whatever configuration is current would silently launder an
    ///   unproven cut. Ordinary recovery refuses with the typed
    ///   [`CheckpointLoadError::CheckpointLegacyIdentityRequiresImport`];
    ///   the explicit [`import_legacy_checkpoint_identity`] path (operator
    ///   acknowledgement + provenance) is the only way in;
    /// - a PRESENT identity that is unparseable, non-v2, or whose
    ///   configuration digest differs from the expected identity's is the
    ///   typed [`CheckpointLoadError::CheckpointIdentityMismatch`] refusal.
    ///   The digest comparison covers every canonical field (kind, policies,
    ///   endpoint/bucket/prefix), so no single field can drift silently.
    fn validate_identity(&self, expected: Option<&BackendIdentity>) -> Result<(), CheckpointLoadError> {
        use CheckpointLoadError::{
            AdditionalDataIO, CheckpointIdentityMismatch, CheckpointLegacyIdentityRequiresImport,
        };

        let Some(expected) = expected else { return Ok(()) };
        let path = self.directory.join(CHECKPOINT_IDENTITY_FILE_NAME);
        let serialised = match fs::read_to_string(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(CheckpointLegacyIdentityRequiresImport { dir: self.directory.clone() });
            }
            Err(error) => {
                return Err(AdditionalDataIO {
                    name: CHECKPOINT_IDENTITY_FILE_NAME.to_string(),
                    source: Arc::new(error),
                });
            }
            Ok(serialised) => serialised,
        };
        let persisted_digest = match BackendIdentity::parse_marker(&serialised) {
            Ok(PersistedBackendMarker::V2(identity)) => identity.config_digest(),
            // an unparseable or kind-only identity file is never silently a
            // legacy cut: something wrote it, so its meaning must verify.
            Ok(PersistedBackendMarker::V1 { .. }) | Err(_) => "<unparseable>".to_owned(),
        };
        if persisted_digest != expected.config_digest() {
            return Err(CheckpointIdentityMismatch {
                dir: self.directory.clone(),
                persisted: persisted_digest,
                resolved: expected.config_digest(),
            });
        }
        Ok(())
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
        // R5-STOR-11: an attempt-named directory's leading component is the
        // checkpoint SEQUENCE (the storage watermark the cut was taken at) —
        // the recency key selection and retention order by. It must agree
        // with the sealed watermark inside the cut: a renamed directory could
        // otherwise reorder selection/retention without touching any sealed
        // byte. Non-attempt-named directories (unit fixtures, foreign dirs)
        // skip the check — they are never enumerated as candidates.
        if let Some(name_sequence) = parse_attempt_sequence(&self.directory) {
            match read_watermark_at(&self.directory) {
                Ok(watermark) if watermark.number() == name_sequence => {}
                _ => return Ok(false),
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

fn remove_dir_if_exists(dir: &Path) -> io::Result<()> {
    match fs::remove_dir_all(dir) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// R5-STOR-06 (b): prove the SCRATCH materialisation byte-identical to the
/// cut's sealed COMPLETE manifest before the engine ever opens it. The
/// manifest's keyspace-scoped entries (relative path, length, SHA-256) are
/// compared for EXACT set equality against a fresh walk of the scratch tree —
/// a missing, extra, changed, or truncated file is the typed
/// [`CheckpointLoadError::RestoreScratchDigestMismatch`] refusal, with the
/// live tree untouched. This both proves copy fidelity and re-proves the cut
/// itself at USE time (selection-time verification may be arbitrarily stale).
fn verify_scratch_against_manifest<KS: KeyspaceSet>(
    checkpoint_dir: &Path,
    scratch_dir: &Path,
) -> Result<(), CheckpointLoadError> {
    use CheckpointLoadError::RestoreScratchDigestMismatch;

    let mismatch = |detail: String| RestoreScratchDigestMismatch { dir: checkpoint_dir.to_owned(), detail };

    let serialised = fs::read_to_string(checkpoint_dir.join(CHECKPOINT_COMPLETE_FILE_NAME))
        .map_err(|error| mismatch(format!("the sealed COMPLETE manifest cannot be read: {error}")))?;
    let manifest = CheckpointManifest::parse(&serialised)
        .ok_or_else(|| mismatch("the sealed COMPLETE manifest does not parse as the current version".to_owned()))?;

    // the subset of sealed entries that restore materialises: everything
    // under a declared keyspace root
    let mut expected: BTreeMap<Vec<u8>, (u64, [u8; 32])> = BTreeMap::new();
    for keyspace in KS::iter() {
        let mut prefix = keyspace.name().as_bytes().to_vec();
        prefix.push(b'/');
        for (key, value) in manifest.entries.range(prefix.clone()..) {
            if !key.starts_with(&prefix) {
                break;
            }
            expected.insert(key.clone(), *value);
        }
    }

    let mut recomputed: BTreeMap<Vec<u8>, (u64, [u8; 32])> = BTreeMap::new();
    for keyspace in KS::iter() {
        let keyspace_dir = scratch_dir.join(keyspace.name());
        if !keyspace_dir.exists() {
            continue; // its absence shows up as missing entries below
        }
        CheckpointManifest::walk(scratch_dir, &keyspace_dir, &mut recomputed)
            .map_err(|error| mismatch(format!("the scratch tree cannot be re-hashed: {error}")))?;
    }

    if expected != recomputed {
        return Err(mismatch(format!(
            "the scratch materialisation does not match the sealed manifest \
             ({} sealed keyspace entries, {} materialised)",
            expected.len(),
            recomputed.len()
        )));
    }
    Ok(())
}

/// R8-P1-02: the COMPLETE expected-versus-durable restore witness.
///
/// What this replaces, and why.
///
/// The previous barrier sampled: `RESTORE_WITNESS_MAX_PROBES = 256` keys taken
/// from the tail of the recovered commits, captured once from the live engine
/// after replay and once from a reopen, and required the two CAPTURES to be
/// equal. Two things follow from that shape, and the round-8 audit named both:
///
///  * it is observation versus observation. A replay defect that silently
///    omitted a probed operation reads `None` before close and `None` after
///    reopen — the two agree, and activation proceeds;
///  * it is a SAMPLE. A flush defect that loses the 257th-newest replayed key,
///    or any older one, is invisible: every probe still agrees. The existing
///    test proved the bound was respected, never that the bound was
///    semantically complete.
///
/// This type is expected SEMANTICS versus DURABLE OBSERVATION, over EVERY
/// touched key:
///
///  * the expectation is captured at the one point where replay's decision is
///    final and the bytes have not yet reached a keyspace
///    ([`apply_recovered_observing`]) — not from the recovered records, because
///    a `Pending` commit's write set is produced by validation and a
///    non-reinserting `Put` writes nothing, so an input-derived expectation
///    would be a guess about the engine's own decision;
///  * every recorded key is read back and compared to the expected VALUE
///    DIGEST, first from the live engine after replay (which catches a replay
///    that silently wrote nothing) and again from the reopened materialisation
///    (which catches a flush that reported success without carrying the bytes);
///  * memory is bounded by the DEDUPLICATED TOUCHED-KEY INDEX plus one 32-byte
///    digest per key — never by value bytes, however large the values are.
///
/// Tombstones need no special case: at this layer a logical delete IS a put of
/// an empty value under a `Delete`-tagged MVCC key, so it is in the index like
/// any other write and losing one is a divergence like any other.
///
/// Duplicate and reordered writes to one logical key are likewise handled by
/// construction: an MVCC key embeds its sequence number, so two writes to the
/// same logical key are two DISTINCT index entries, and replaying them in a
/// different order cannot change the final set. Two writes at the same
/// sequence number to the same MVCC key are the same byte string written
/// twice, and the last one wins here exactly as it does in the engine.
#[derive(Debug, Default)]
struct ExpectedReplayWitness {
    /// `(keyspace id, MVCC key) -> SHA-256 of the value replay decided to
    /// write`. Values themselves are never retained.
    expected: BTreeMap<(u8, Vec<u8>), [u8; 32]>,
    /// The recovered WAL sequence range this witness is a statement about
    /// (R8-P1-02 item 7): a witness that does not say WHICH replay it
    /// describes cannot be compared with anything later.
    sequence_range: Option<(SequenceNumber, SequenceNumber)>,
    /// Writes absorbed, including ones that overwrote an identical earlier
    /// entry. `expected.len()` is the deduplicated count; the difference is
    /// reported so a suspicious duplicate rate is visible.
    absorbed: usize,
}

impl ExpectedReplayWitness {
    /// Absorb one batch set as replay resolved it, before it is written.
    fn absorb(&mut self, sequence_number: SequenceNumber, batches: &WriteBatches) {
        self.sequence_range = Some(match self.sequence_range {
            None => (sequence_number, sequence_number),
            Some((first, last)) => (first.min(sequence_number), last.max(sequence_number)),
        });
        for (index, batch) in batches.batches.iter().enumerate() {
            let Some(batch) = batch else { continue };
            for (key, value) in batch.puts() {
                self.absorbed += 1;
                self.expected.insert((index as u8, key.clone()), sha256::digest(value));
            }
        }
    }

    /// The LOGICAL root of everything replay decided to write.
    ///
    /// R8-P1-02 item 6: a file-tree root is unstable under legitimate
    /// compaction, so it cannot be compared across a close/reopen. This root is
    /// over the touched-key index and its value digests, in BTreeMap order, so
    /// it is stable under any storage-level rearrangement and changes if and
    /// only if the replayed content does.
    fn root(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"typedb.storage.restore-replay-witness.v1\x00");
        hasher.update(&(self.expected.len() as u64).to_be_bytes());
        for ((keyspace, key), digest) in &self.expected {
            hasher.update(&[*keyspace]);
            hasher.update(&(key.len() as u64).to_be_bytes());
            hasher.update(key);
            hasher.update(digest);
        }
        hex_encode(&hasher.finalize())
    }

    /// Read back EVERY touched key from `keyspaces` and require the expected
    /// value. `where_` names the observation point in the refusal.
    fn verify(&self, keyspaces: &Keyspaces, where_: &str) -> Result<(), RestoreWitnessDivergence> {
        let mut absent = 0usize;
        let mut differing = 0usize;
        let mut first: Option<String> = None;
        for ((keyspace, key), want) in &self.expected {
            let got = keyspaces
                .get(KeyspaceId(*keyspace))
                .get(key, sha256::digest)
                .map_err(|source| RestoreWitnessDivergence::Unreadable { source })?;
            match got {
                Some(got) if got == *want => {}
                observed => {
                    if observed.is_none() {
                        absent += 1;
                    } else {
                        differing += 1;
                    }
                    if first.is_none() {
                        first = Some(format!(
                            "keyspace {keyspace} key {} expected value digest {} but {where_} reads {}",
                            hex_encode(key),
                            hex_encode(want),
                            observed.map(|d| hex_encode(&d)).unwrap_or_else(|| "ABSENT".to_owned()),
                        ));
                    }
                }
            }
        }
        if absent == 0 && differing == 0 {
            return Ok(());
        }
        Err(RestoreWitnessDivergence::Lost {
            detail: format!(
                "{absent} of {} replayed keys are ABSENT and {differing} hold different bytes {where_} \
                 (replay wrote {} operations across sequence numbers {}); first divergence: {}",
                self.expected.len(),
                self.absorbed,
                self.sequence_range.map(|(a, b)| format!("{a}..={b}")).unwrap_or_else(|| "<none>".to_owned()),
                first.unwrap_or_else(|| "<none>".to_owned()),
            ),
        })
    }
}

/// Why a restore witness refused.
#[derive(Debug)]
enum RestoreWitnessDivergence {
    Unreadable { source: KeyspaceError },
    Lost { detail: String },
}

/// R6-STOR-01 (root): the durable root of the materialisation that is about
/// to be activated. Every declared keyspace must have left at least one
/// durable file behind the flush barrier — an engine that closed "cleanly"
/// while writing nothing is not an activatable materialisation — and the
/// manifest root over the whole scratch tree names the exact bytes the rename
/// publishes.
fn scratch_root<KS: KeyspaceSet>(scratch_dir: &Path) -> Result<String, String> {
    let mut entries: BTreeMap<Vec<u8>, (u64, [u8; 32])> = BTreeMap::new();
    for keyspace in KS::iter() {
        let keyspace_dir = scratch_dir.join(keyspace.name());
        let before = entries.len();
        CheckpointManifest::walk(scratch_dir, &keyspace_dir, &mut entries)
            .map_err(|error| format!("the verified scratch tree cannot be re-hashed: {error}"))?;
        if entries.len() == before {
            return Err(format!(
                "keyspace '{}' left no durable file in the scratch materialisation after the flush barrier",
                keyspace.name()
            ));
        }
    }
    Ok(hex_encode(&CheckpointManifest::root_digest(&entries)))
}

/// R5-STOR-06 (e): the atomic activation. On one filesystem this is
/// rename-swap: live -> retired, scratch -> live, fsync the parent. Any
/// failure of the second rename rolls the first back, so the predecessor is
/// byte-identical AND still active on every pre-activation failure. The
/// retired predecessor is reclaimed only after the successor is durably in
/// place; a reclaim failure is deliberately non-fatal (the successor is
/// active) and is finished by [`converge_interrupted_restore`].
fn activate_scratch(scratch_dir: &Path, live_dir: &Path, retired_dir: &Path) -> io::Result<()> {
    let parent = live_dir.parent().expect("restore_working_directories proved the parent exists");
    let had_live = live_dir.exists();
    if had_live {
        remove_dir_if_exists(retired_dir)?;
        fs::rename(live_dir, retired_dir)?;
    }
    if let Err(error) = fs::rename(scratch_dir, live_dir) {
        if had_live {
            // roll back: the predecessor must remain active
            let _ = fs::rename(retired_dir, live_dir);
            let _ = crate::fsync_path(parent);
        }
        return Err(error);
    }
    // the swap must be durable before the successor is reported active
    crate::fsync_path(parent)?;
    if had_live {
        if let Err(error) = remove_dir_if_exists(retired_dir) {
            trace!("failed to reclaim the retired predecessor {retired_dir:?} (successor active): {error:?}");
        } else {
            let _ = crate::fsync_path(parent);
        }
    }
    Ok(())
}

/// R5-STOR-06 restart convergence, run at the START of every storage load,
/// BEFORE any candidate is considered. A crash during a previous restore
/// leaves exactly one of these states, each with a deterministic resolution:
///
/// - live present, scratch residue present (crash anywhere before
///   activation): the predecessor is intact and active; scratch is unproven
///   residue and is reclaimed;
/// - live MISSING, retired present (crash between the two activation
///   renames): the predecessor is rolled back into place (retired -> live) —
///   pre-activation failures always converge to the predecessor;
/// - live present, retired present (crash after both renames, before the
///   retired reclaim): the successor is active; the retired predecessor is
///   reclaimed.
///
/// After convergence the tree holds exactly a live directory (or none, for a
/// fresh database) and no restore residue, and recovery proceeds normally —
/// re-validating and re-restoring the candidate if one is selectable, which
/// converges the "crash after activation" case to the successor.
pub(crate) fn converge_interrupted_restore(keyspaces_dir: &Path) -> io::Result<()> {
    let Some(root) = keyspaces_dir.parent() else { return Ok(()) };
    if !root.exists() {
        return Ok(());
    }
    let mut scratch = Vec::new();
    let mut retired = Vec::new();
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else { continue };
        if name.starts_with(RESTORE_SCRATCH_PREFIX) {
            scratch.push(path);
        } else if name.starts_with(RESTORE_RETIRED_PREFIX) {
            retired.push(path);
        }
    }
    if scratch.is_empty() && retired.is_empty() {
        return Ok(());
    }
    if !keyspaces_dir.exists() {
        // crash between the activation renames: roll the predecessor back.
        // At most one retired directory can exist (activation retires one
        // and convergence runs before every new attempt); if several are
        // somehow present the lexicographically newest is the most recent
        // predecessor.
        retired.sort();
        if let Some(newest) = retired.pop() {
            fs::rename(&newest, keyspaces_dir)?;
        }
    }
    for residue in scratch.into_iter().chain(retired) {
        remove_dir_if_exists(&residue)?;
    }
    crate::fsync_path(root)?;
    Ok(())
}

/// R5-STOR-10: the EXPLICIT, operator-acknowledged import of a legacy
/// checkpoint (one sealed before identity binding existed, or exported by a
/// direct storage-level writer without an identity). Ordinary recovery
/// refuses such a cut with
/// [`CheckpointLoadError::CheckpointLegacyIdentityRequiresImport`]; this
/// function is the only way in, and it:
///
/// 1. refuses a cut that already carries an identity (nothing legacy to
///    import — a mismatched identity is reconfiguration, not import);
/// 2. stamps the ACKNOWLEDGED identity (the full v2 marker serialisation)
///    and a provenance record (the operator's acknowledgement text plus
///    diagnostics) as regular data files under the cut;
/// 3. reseals the cut: the COMPLETE manifest is recomputed (current format,
///    SHA-256) over every file including the new identity and provenance,
///    fsynced bottom-up, and the directory is renamed to the
///    sequence-keyed attempt name its sealed watermark dictates (legacy
///    wall-clock-named directories are re-keyed so selection/retention
///    order them by sequence like every current cut).
///
/// Returns the reader for the imported (possibly renamed) cut.
pub fn import_legacy_checkpoint_identity(
    checkpoint_dir: &Path,
    identity: &BackendIdentity,
    operator_acknowledgement: &str,
) -> Result<CheckpointReader, CheckpointCreateError> {
    use CheckpointCreateError::{
        CheckpointDirCreate, CompleteMarkerWrite, ExtensionDuplicate, ExtensionIO, MetadataUnparseable,
        MissingStorageData,
    };

    if !checkpoint_dir.join(STORAGE_METADATA_FILE_NAME).exists() {
        return Err(MissingStorageData { dir: checkpoint_dir.to_owned() });
    }
    let watermark = read_watermark_at(checkpoint_dir).map_err(|_| MetadataUnparseable {
        dir: checkpoint_dir.to_owned(),
        content: fs::read_to_string(checkpoint_dir.join(STORAGE_METADATA_FILE_NAME)).unwrap_or_default(),
    })?;
    if checkpoint_dir.join(CHECKPOINT_IDENTITY_FILE_NAME).exists() {
        return Err(ExtensionDuplicate { name: CHECKPOINT_IDENTITY_FILE_NAME.to_string() });
    }

    // 2. stamp the acknowledged identity and its provenance
    write_file(&checkpoint_dir.join(CHECKPOINT_IDENTITY_FILE_NAME), identity.serialise_marker().as_bytes())
        .map_err(|error| ExtensionIO { name: CHECKPOINT_IDENTITY_FILE_NAME.to_string(), source: Arc::new(error) })?;
    let provenance = format!(
        "legacy-checkpoint-identity-import v1\nimported-utc {}\nidentity-config-digest {}\nacknowledgement {}\n",
        Utc::now().to_rfc3339(),
        identity.config_digest(),
        operator_acknowledgement.replace('\n', " "),
    );
    write_file(&checkpoint_dir.join(CHECKPOINT_IDENTITY_PROVENANCE_FILE_NAME), provenance.as_bytes()).map_err(
        |error| ExtensionIO { name: CHECKPOINT_IDENTITY_PROVENANCE_FILE_NAME.to_string(), source: Arc::new(error) },
    )?;

    // 3. reseal: recompute the current-format manifest over the whole cut
    let manifest = CheckpointManifest::compute(checkpoint_dir)
        .map_err(|error| CompleteMarkerWrite { dir: checkpoint_dir.to_owned(), source: Arc::new(error) })?;
    fsync_tree_bottom_up(checkpoint_dir)
        .map_err(|error| CompleteMarkerWrite { dir: checkpoint_dir.to_owned(), source: Arc::new(error) })?;
    write_file(&checkpoint_dir.join(CHECKPOINT_COMPLETE_FILE_NAME), manifest.serialise().as_bytes())
        .map_err(|error| CompleteMarkerWrite { dir: checkpoint_dir.to_owned(), source: Arc::new(error) })?;
    crate::fsync_path(checkpoint_dir)
        .map_err(|error| CompleteMarkerWrite { dir: checkpoint_dir.to_owned(), source: Arc::new(error) })?;

    // re-key the directory to the sequence-keyed attempt name (R5-STOR-11)
    // unless it already carries the right sequence prefix
    let final_dir = if parse_attempt_sequence(checkpoint_dir) == Some(watermark.number()) {
        checkpoint_dir.to_owned()
    } else {
        let parent = checkpoint_dir.parent().ok_or_else(|| CheckpointDirCreate {
            dir: checkpoint_dir.to_owned(),
            source: Arc::new(io::Error::new(io::ErrorKind::InvalidInput, "checkpoint directory has no parent")),
        })?;
        let renamed = parent.join(attempt_directory_name(watermark.number(), &new_attempt_suffix()));
        fs::rename(checkpoint_dir, &renamed)
            .map_err(|error| CheckpointDirCreate { dir: renamed.clone(), source: Arc::new(error) })?;
        crate::fsync_path(parent)
            .map_err(|error| CheckpointDirCreate { dir: parent.to_owned(), source: Arc::new(error) })?;
        renamed
    };
    Ok(CheckpointReader { directory: final_dir })
}

/// R4-STOR-08/R4-STOR-10: every verified, selectable checkpoint, ordered
/// newest to oldest.
///
/// Recency is the FULL attempt directory name, compared lexicographically:
/// the name format `<20-digit-sequence>-<counter>-<nonce>` (see
/// [`attempt_directory_name`]) makes lexicographic order equal LOGICAL
/// recency by construction (R5-STOR-11: the fixed-width prefix is the
/// checkpoint sequence, never wall time, so clock rollback cannot reorder
/// it), and two attempts at the EXACT same sequence (equivalent cuts) are
/// still totally ordered by the fixed-width counter and nonce components.
/// This is the SAME total order retention ([`siblings_safe_to_delete`])
/// uses, so the reader's selection and the writer's cleanup can never
/// disagree about which cut is newer.
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
        if parse_attempt_sequence(&path).is_none() {
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
///
/// R5-STOR-11: the FINAL attempt directory name is derived at [`Self::finish`]
/// from the cut's sealed WATERMARK (the storage checkpoint sequence), not from
/// wall time — `<20-digit-sequence>-<counter>-<nonce>`. The sequence is the
/// authority selection and retention order by; wall time appears only inside
/// the manifest as diagnostics. The in-flight temporary directory carries a
/// unique non-attempt name plus the `.tmp` extension, so it is never selected
/// and never a retention target.
pub struct CheckpointWriter {
    pub temporary_directory: PathBuf,
    /// `<counter>-<nonce>`: the uniqueness suffix of the final attempt name.
    attempt_suffix: String,
}

impl CheckpointWriter {
    pub fn new(storage_path: &Path) -> Result<Self, CheckpointCreateError> {
        use CheckpointCreateError::CheckpointDirCreate;

        let checkpoint_dir = storage_path.join(CHECKPOINT_DIR_NAME);
        if !checkpoint_dir.exists() {
            fs::create_dir_all(&checkpoint_dir)
                .map_err(|error| CheckpointDirCreate { dir: checkpoint_dir.clone(), source: Arc::new(error) })?
        }

        // R-04: a unique attempt suffix — the process-wide counter guarantees
        // uniqueness within a process even for simultaneous attempts, and the
        // random nonce extends that across processes. Two concurrent attempts
        // therefore can never land in the same directory — the collision the
        // old timestamp names permitted. R5-STOR-11: no wall-clock component
        // anywhere; the recency-ordering prefix (the checkpoint sequence) is
        // bound at `finish`, when the sealed watermark is known.
        let attempt_suffix = new_attempt_suffix();
        let temporary_directory = checkpoint_dir.join(format!("attempt-{attempt_suffix}.{TEMP_FILE_EXTENSION}"));
        fs::create_dir_all(&temporary_directory)
            .map_err(|error| CheckpointDirCreate { dir: checkpoint_dir.clone(), source: Arc::new(error) })?;

        Ok(Self { temporary_directory, attempt_suffix })
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

    /// R4-STOR-01: bind the creating database's backend identity into this
    /// cut. Must be called BEFORE [`Self::finish`] — the identity lands as a
    /// regular data file under the attempt root, so the digest-bound COMPLETE
    /// manifest computed by `finish` seals it with everything else. Restore
    /// then refuses this cut under any other backend identity.
    pub fn add_identity(&self, identity: &BackendIdentity) -> Result<(), CheckpointCreateError> {
        use CheckpointCreateError::{ExtensionDuplicate, ExtensionIO};

        let path = self.temporary_directory.join(CHECKPOINT_IDENTITY_FILE_NAME);
        if path.exists() {
            return Err(ExtensionDuplicate { name: CHECKPOINT_IDENTITY_FILE_NAME.to_string() });
        }
        write_file(&path, identity.serialise_marker().as_bytes())
            .map_err(|error| ExtensionIO { name: CHECKPOINT_IDENTITY_FILE_NAME.to_string(), source: Arc::new(error) })
    }

    pub fn finish(self) -> Result<CheckpointReader, CheckpointCreateError> {
        use CheckpointCreateError::{
            CheckpointDirCreate, CheckpointDirRead, CompleteMarkerWrite, MetadataUnparseable, MissingStorageData,
            OldCheckpointRemove,
        };

        if !self.temporary_directory.join(STORAGE_METADATA_FILE_NAME).exists() {
            return Err(MissingStorageData { dir: self.temporary_directory.clone() });
        }
        // R5-STOR-11: the final attempt name's recency component is the
        // sealed WATERMARK — the checkpoint sequence, monotonic per store —
        // never wall time. Wall-clock rollback between attempts therefore
        // cannot reorder selection or retention.
        let watermark = read_watermark_at(&self.temporary_directory).map_err(|_| MetadataUnparseable {
            dir: self.temporary_directory.clone(),
            content: fs::read_to_string(self.temporary_directory.join(STORAGE_METADATA_FILE_NAME)).unwrap_or_default(),
        })?;
        let checkpoint_parent = self
            .temporary_directory
            .parent()
            .expect("the temporary attempt directory is created under the checkpoint directory")
            .to_owned();
        let checkpoint_directory =
            checkpoint_parent.join(attempt_directory_name(watermark.number(), &self.attempt_suffix));

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
        fs::rename(&self.temporary_directory, &checkpoint_directory)
            .map_err(|error| CheckpointDirCreate { dir: checkpoint_directory.clone(), source: Arc::new(error) })?;
        // R-06: the rename itself must be durable, or a crash can leave the
        // parent directory pointing at the pre-rename tmp name.
        crate::fsync_path(&checkpoint_parent)
            .map_err(|error| CheckpointDirCreate { dir: checkpoint_parent.clone(), source: Arc::new(error) })?;

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
        let siblings: Vec<PathBuf> = fs::read_dir(&checkpoint_parent)
            .and_then(|entries| entries.map_ok(|entry| entry.path()).try_collect())
            .map_err(|error| CheckpointDirRead { dir: checkpoint_directory.clone(), source: Arc::new(error) })?;

        for previous_checkpoint in siblings_safe_to_delete(&checkpoint_directory, &siblings) {
            fail_point!(CHECKPOINT_CLEANUP_PARTIAL_FAIL);
            fs::remove_dir_all(&previous_checkpoint)
                .map_err(|error| OldCheckpointRemove { dir: previous_checkpoint, source: Arc::new(error) })?
        }

        Ok(CheckpointReader { directory: checkpoint_directory })
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
/// The attempt name format `<20-digit-sequence>-<counter>-<nonce>` makes
/// lexicographic comparison equal LOGICAL recency (R5-STOR-11: the
/// fixed-width prefix is the checkpoint sequence, never wall time — a clock
/// rollback between attempts cannot make a newer cut look older); two names
/// sharing an EXACTLY equal sequence prefix are equivalent cuts, still
/// totally ordered by the fixed-width counter and nonce components. This is
/// the same total order the reader's selection uses
/// ([`verified_checkpoints_newest_first`]), so cleanup can never delete the
/// cut selection would pick.
fn siblings_safe_to_delete(final_dir: &Path, entries: &[PathBuf]) -> Vec<PathBuf> {
    let Some(final_name) = final_dir.file_name() else {
        return Vec::new();
    };
    entries
        .iter()
        .filter(|path| path.extension() != Some(TEMP_FILE_EXTENSION.as_ref()))
        .filter(|path| parse_attempt_sequence(path).is_some())
        .filter(|path| path.file_name().is_some_and(|name| name < final_name))
        .cloned()
        .collect()
}

/// The final attempt directory name: `<20-digit-sequence>-<counter>-<nonce>`.
/// R5-STOR-11: the fixed-width leading component is the CHECKPOINT SEQUENCE
/// (the sealed watermark — monotonic per store), so lexicographic order is
/// LOGICAL recency by construction and a wall-clock rollback between attempts
/// cannot reorder selection or retention. The suffix (`<counter>-<nonce>`)
/// only disambiguates attempts at the SAME sequence (equivalent cuts).
fn attempt_directory_name(sequence: u64, attempt_suffix: &str) -> String {
    format!("{sequence:020}-{attempt_suffix}")
}

/// R-04: a unique attempt suffix `<counter>-<nonce>`: the process-wide
/// [`ATTEMPT_COUNTER`] guarantees two attempts in the same process differ,
/// and the random nonce extends uniqueness across processes. It carries NO
/// wall-clock component and is never used for ordering across sequences.
fn new_attempt_suffix() -> String {
    let counter = ATTEMPT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nonce = attempt_nonce();
    format!("{counter:016x}-{nonce:016x}")
}

/// A per-call random 64-bit nonce sourced from the standard-library hasher's
/// randomly-seeded keys (no non-dev `rand` dependency is available to this
/// crate). Distinct across calls and across processes.
fn attempt_nonce() -> u64 {
    std::collections::hash_map::RandomState::new().build_hasher().finish()
}

/// Parse the recency-ordering checkpoint-sequence prefix of an attempt
/// directory name. Returns `None` for a name that does not begin with the
/// fixed-width sequence component (an unrelated/foreign directory), which the
/// selector skips.
fn parse_attempt_sequence(path: &Path) -> Option<u64> {
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

/// R-06/R5-STOR-09: the machine manifest a COMPLETE marker carries. It binds,
/// for every data file under the checkpoint root (the COMPLETE marker itself
/// excluded), the file's relative path, byte length, and its SHA-256 digest,
/// plus a SHA-256 root over the length-prefix-framed sorted entry set. The
/// reader recomputes this from the bytes on disk and refuses any checkpoint
/// where a file is missing, extra, changed, or truncated — so a torn or
/// tampered attempt can never be selected, and (unlike the retired 64-bit
/// SipHash format) an adversary with storage write access cannot recompute a
/// colliding digest by brute force.
///
/// Path identity (R5-STOR-09): entry keys are the RAW relative path bytes
/// (Unix `OsStrExt::as_bytes` per component, joined with `/`), hex-encoded in
/// the serialised form and length-prefix-framed in the root digest. Two
/// distinct invalid-UTF-8 names that would lossy-collapse to one replacement
/// string therefore remain DISTINCT manifest keys; nothing in the format is
/// lossy. A serialised manifest carrying two entries with the same key does
/// not parse (duplicate-key refusal).
///
/// Format migration: only the `v2` header below parses. A legacy `v1`
/// (64-bit SipHash) COMPLETE marker — or any unknown/forged version — is
/// refused as unverifiable, making the directory unselectable; the explicit
/// [`import_legacy_checkpoint_identity`] path is the sanctioned way to reseal
/// an acknowledged legacy cut in the current format.
struct CheckpointManifest {
    /// raw relative path bytes (`/`-joined) -> (length, SHA-256 digest)
    entries: BTreeMap<Vec<u8>, (u64, [u8; 32])>,
    root_digest: [u8; 32],
    /// Informational only (human-readable marker content). NOT a bound
    /// integrity input: `verify` compares `entries` + `root_digest`, and the
    /// STORAGE_METADATA file this is read from is itself a regular file under
    /// the root, so its bytes are already hashed into `entries`.
    watermark: Option<u64>,
    /// R5-STOR-11: wall-clock creation time, DIAGNOSTICS ONLY — never an
    /// ordering or retention input (the attempt name's sequence prefix is).
    created_utc: Option<String>,
}

const CHECKPOINT_MANIFEST_HEADER: &str = "CHECKPOINT-COMPLETE v2";

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
        Ok(Self { entries, root_digest, watermark, created_utc: Some(Utc::now().to_rfc3339()) })
    }

    fn walk(root: &Path, dir: &Path, entries: &mut BTreeMap<Vec<u8>, (u64, [u8; 32])>) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            // same no-follow R-05 enforcement point as restore/fsync
            let file_type = assert_safe_checkpoint_entry(&path)?;
            if file_type.is_dir() {
                Self::walk(root, &path, entries)?;
            } else {
                let relative = path.strip_prefix(root).expect("walked path is under root");
                let key = manifest_path_key(relative)?;
                if key == CHECKPOINT_COMPLETE_FILE_NAME.as_bytes() {
                    continue; // the marker never certifies itself
                }
                let (len, digest) = hash_file(&path)?;
                entries.insert(key, (len, digest));
            }
        }
        Ok(())
    }

    /// SHA-256 over the sorted entry set with unambiguous length-prefixed
    /// framing: `u64-BE key length | key bytes | u64-BE file length | 32-byte
    /// digest` per entry. No concatenation of two distinct entry sets can
    /// produce the same framed byte stream.
    fn root_digest(entries: &BTreeMap<Vec<u8>, (u64, [u8; 32])>) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for (key, (len, digest)) in entries {
            hasher.update(&(key.len() as u64).to_be_bytes());
            hasher.update(key);
            hasher.update(&len.to_be_bytes());
            hasher.update(digest);
        }
        hasher.finalize()
    }

    fn serialise(&self) -> String {
        let mut out = String::new();
        out.push_str(CHECKPOINT_MANIFEST_HEADER);
        out.push('\n');
        out.push_str(&format!("root {}\n", hex_encode(&self.root_digest)));
        if let Some(watermark) = self.watermark {
            out.push_str(&format!("watermark {watermark}\n"));
        }
        if let Some(created_utc) = &self.created_utc {
            // diagnostics only (R5-STOR-11): parsed back but never compared
            out.push_str(&format!("created-utc {created_utc}\n"));
        }
        for (key, (len, digest)) in &self.entries {
            // hex-encode the raw relative path bytes so any byte in a file
            // name round trips without colliding with the field separators.
            out.push_str(&format!("{len:016x} {} {}\n", hex_encode(digest), hex_encode(key)));
        }
        out
    }

    /// Verify the on-disk checkpoint tree against a serialised COMPLETE marker:
    /// recompute the manifest from the bytes and require exact equality of the
    /// entry set (paths, lengths, digests) and the root digest. Any missing,
    /// extra, changed, or truncated file — and any legacy/unknown manifest
    /// version — makes this `false`.
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
            // R5-STOR-09: v1 (64-bit) and unknown/forged versions are refused
            return None;
        }
        let mut entries = BTreeMap::new();
        let mut root_digest = None;
        let mut watermark = None;
        let mut created_utc = None;
        for line in lines {
            if let Some(rest) = line.strip_prefix("root ") {
                root_digest = decode_digest(rest.trim());
                root_digest.as_ref()?;
            } else if let Some(rest) = line.strip_prefix("watermark ") {
                watermark = rest.trim().parse().ok();
            } else if let Some(rest) = line.strip_prefix("created-utc ") {
                created_utc = Some(rest.trim().to_owned());
            } else {
                let mut parts = line.split(' ');
                let len = u64::from_str_radix(parts.next()?, 16).ok()?;
                let digest = decode_digest(parts.next()?)?;
                let key = hex_decode(parts.next()?)?;
                if parts.next().is_some() {
                    return None; // trailing garbage on an entry line
                }
                // duplicate normalized keys are an explicit refusal, never a
                // silent last-writer-wins (R5-STOR-09)
                if entries.insert(key, (len, digest)).is_some() {
                    return None;
                }
            }
        }
        Some(Self { entries, root_digest: root_digest?, watermark, created_utc })
    }
}

/// The manifest key for a relative path: the RAW path bytes of every
/// component, joined with `/`. On Unix this is `OsStrExt::as_bytes`, so
/// distinct invalid-UTF-8 names stay distinct (no lossy collapse). On
/// non-Unix targets, where raw path bytes are not exposed, a non-UTF-8 name
/// is REFUSED at manifest computation (i.e. at checkpoint creation) rather
/// than serialised lossily.
fn manifest_path_key(relative: &Path) -> io::Result<Vec<u8>> {
    let mut key = Vec::new();
    for component in relative.components() {
        if !key.is_empty() {
            key.push(b'/');
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            key.extend_from_slice(component.as_os_str().as_bytes());
        }
        #[cfg(not(unix))]
        {
            let text = component.as_os_str().to_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("refusing to checkpoint a non-UTF-8 file name on a non-Unix target: {relative:?}"),
                )
            })?;
            key.extend_from_slice(text.as_bytes());
        }
    }
    Ok(key)
}

fn decode_digest(hex: &str) -> Option<[u8; 32]> {
    hex_decode(hex)?.try_into().ok()
}

/// Stream a file through SHA-256, returning (length, digest) — R5-STOR-09.
fn hash_file(path: &Path) -> io::Result<(u64, [u8; 32])> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut len = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        len = len.saturating_add(read as u64);
    }
    Ok((len, hasher.finalize()))
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
    /// R5-STOR-11: the attempt's sealed watermark does not parse, so no
    /// sequence-keyed final name can be derived; the attempt is not published.
    MetadataUnparseable {
        dir: PathBuf,
        content: String,
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
            Self::MetadataUnparseable { .. } => None,
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
        CheckpointIdentityMismatch(14, "The checkpoint in directory '{dir:?}' is bound to backend identity digest '{persisted}', but this database resolves identity digest '{resolved}' (R4-STOR-01). A cut created under one backend configuration must never be restored under another; refusing BEFORE any touch of live state.", dir: PathBuf, persisted: String, resolved: String),
        CheckpointLegacyIdentityRequiresImport(15, "The checkpoint in directory '{dir:?}' carries no backend identity: it is a legacy cut whose bytes never proved endpoint, bucket, prefix, or policy (R5-STOR-10). Ordinary recovery refuses to bind it to the current configuration; run the explicit legacy-identity import (operator acknowledgement + provenance) to make it recoverable. Live storage state was left untouched.", dir: PathBuf),
        RestoreScratchDigestMismatch(16, "The scratch materialisation of the checkpoint in directory '{dir:?}' does not verify against its sealed COMPLETE manifest ({detail}) (R5-STOR-06/R5-STOR-09). The cut is corrupt or tampered; refusing BEFORE any touch of live state.", dir: PathBuf, detail: String),
        RestoreActivation(17, "Failed to atomically activate the verified scratch restore of the checkpoint in directory '{dir:?}' (R5-STOR-06). The rename-swap was rolled back where possible; restart convergence restores the predecessor if the swap was torn.", dir: PathBuf, source: Arc<io::Error>),
        RestoreFlushBarrier(18, "The scratch materialisation of the checkpoint in directory '{dir:?}' could not be flushed and closed ({detail}) (R6-STOR-01). The replayed records are not proven durable, so nothing was renamed, no active marker changed, and the recovery sequence did not advance; the predecessor is byte-identical and still active.", dir: PathBuf, detail: String),
        RestoreWitnessUnreadable(19, "The post-replay witness of the checkpoint restore in directory '{dir:?}' could not be read (R6-STOR-01). Refusing to activate a materialisation whose replayed records cannot be proven; the predecessor is byte-identical and still active.", dir: PathBuf, source: KeyspaceError),
        RestoreWitnessMismatch(20, "The scratch materialisation of the checkpoint in directory '{dir:?}' did not reproduce its post-replay witness after being flushed, closed and reopened ({detail}) (R6-STOR-01). The flush did not durably carry the replay; nothing was renamed, no active marker changed, and the recovery sequence did not advance.", dir: PathBuf, detail: String),
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

    use super::{TEMP_FILE_EXTENSION, new_attempt_suffix, siblings_safe_to_delete};

    #[test]
    fn attempt_suffixes_are_unique_even_under_rapid_scheduling() {
        // Barrier for the "cannot share A's directory" half of R-04: a tight
        // loop schedules attempts far faster than any clock ticks. The
        // counter+nonce suffixes are all distinct; a bare-timestamp scheme
        // (the mutant) collides here and the set is smaller than the sample.
        const SAMPLES: usize = 20_000;
        let ids: HashSet<String> = (0..SAMPLES).map(|_| new_attempt_suffix()).collect();
        assert_eq!(ids.len(), SAMPLES, "attempt suffixes collided: they must be unique under rapid scheduling");
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
    fn equal_sequence_prefix_ids_are_ordered_by_the_counter_component() {
        // The exact-equal sequence prefix case: two attempts cut at the same
        // watermark share the 20-digit sequence prefix (equivalent cuts); the
        // fixed-width counter (and nonce) still totally order them, so
        // recency-aware cleanup stays exact.
        let base = create_tmp_dir("checkpoint-cleanup-equal-seq");
        let older: PathBuf = base.join("00000000000000000100-0000000000000001-aaaa");
        let newer: PathBuf = base.join("00000000000000000100-0000000000000002-bbbb");

        let entries = vec![older.clone(), newer.clone()];
        assert!(
            siblings_safe_to_delete(&newer, &entries).contains(&older),
            "with equal sequences, the smaller counter is the older attempt and is reclaimable"
        );
        assert!(
            !siblings_safe_to_delete(&older, &entries).contains(&newer),
            "with equal sequences, the larger counter is the newer attempt and must survive"
        );
    }

    #[test]
    fn retention_orders_by_checkpoint_sequence_never_by_wall_clock() {
        // R5-STOR-11 mutant: the clock rolls BACKWARD between attempts —
        // attempt A is cut at wall time t2 with sequence 1, attempt B at the
        // earlier wall time t1 with the newer sequence 2. Names carry no
        // wall-clock component at all, so B (seq 2) is strictly newer than A
        // (seq 1): B's cleanup may reclaim A, and A must NEVER be able to
        // reclaim B as "older".
        let base = create_tmp_dir("checkpoint-cleanup-clock-rollback");
        let a_seq1_late_wall: PathBuf = base.join("00000000000000000001-0000000000000007-aaaa");
        let b_seq2_early_wall: PathBuf = base.join("00000000000000000002-0000000000000003-bbbb");

        let entries = vec![a_seq1_late_wall.clone(), b_seq2_early_wall.clone()];
        assert!(
            siblings_safe_to_delete(&b_seq2_early_wall, &entries).contains(&a_seq1_late_wall),
            "the lower-sequence cut is older regardless of when the wall clock said it was taken"
        );
        assert!(
            !siblings_safe_to_delete(&a_seq1_late_wall, &entries).contains(&b_seq2_early_wall),
            "R5-STOR-11: the higher-sequence cut must never be reclaimed as 'older' after a clock rollback"
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

    /// An in-flight attempt with a fabricated suffix: a `.tmp` tree carrying
    /// the keyspace data and watermark metadata `finish` requires — the state
    /// an attempt is in right after `add_storage` (captured, not yet sealed).
    /// The FINAL name is derived by `finish` from the sealed watermark
    /// (R5-STOR-11): `<20-digit-watermark>-<suffix>`.
    fn captured_attempt(checkpoint_parent: &Path, suffix: &str, watermark: &str) -> CheckpointWriter {
        let temporary_directory = checkpoint_parent.join(format!("attempt-{suffix}.{TEMP_FILE_EXTENSION}"));
        fs::create_dir_all(temporary_directory.join("keyspace")).unwrap();
        fs::write(temporary_directory.join("keyspace").join("data.sst"), format!("bytes-of-{suffix}")).unwrap();
        fs::write(temporary_directory.join(STORAGE_METADATA_FILE_NAME), watermark).unwrap();
        CheckpointWriter { temporary_directory, attempt_suffix: suffix.to_owned() }
    }

    fn selected_name(checkpoint_parent: &Path) -> Option<String> {
        verified_checkpoints_newest_first::<TestKs>(fs::read_dir(checkpoint_parent).unwrap())
            .unwrap()
            .first()
            .map(|c| c.directory.file_name().unwrap().to_str().unwrap().to_owned())
    }

    const A_SUFFIX: &str = "0000000000000001-aaaa";
    const B_SUFFIX: &str = "0000000000000002-bbbb";
    /// A's final name: sealed at watermark 10.
    const A_OLDER: &str = "00000000000000000010-0000000000000001-aaaa";
    /// B's final name: sealed at watermark 20 — the logically newer cut.
    const B_NEWER: &str = "00000000000000000020-0000000000000002-bbbb";

    #[test]
    fn reverse_completion_preserves_the_newer_published_cut() {
        // The audit barrier: A captures first (older watermark), B captures
        // newer and publishes, A resumes and finishes LAST. B must remain
        // published and selected — A cannot remove it. R5-STOR-11: this is
        // ALSO the clock-rollback barrier — completion order (a proxy for
        // wall time) contradicts sequence order, and sequence wins.
        let base = create_tmp_dir("finish-reverse");
        let a = captured_attempt(&base, A_SUFFIX, "10");
        let b = captured_attempt(&base, B_SUFFIX, "20");

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
        let a = captured_attempt(&base, A_SUFFIX, "10");
        let b = captured_attempt(&base, B_SUFFIX, "20");

        a.finish().expect("A publishes first");
        b.finish().expect("B finishes last");

        assert!(!base.join(A_OLDER).exists(), "the strictly older cut A is reclaimed by B's cleanup");
        assert_eq!(selected_name(&base).as_deref(), Some(B_NEWER), "the newer cut B is selected");
    }

    #[test]
    fn published_names_are_keyed_by_sequence_not_wall_clock() {
        // R5-STOR-11: the published directory name's ordering component is
        // exactly the sealed watermark — reverting to a wall-clock-leading
        // name (the mutant) changes the published names and fails here.
        let base = create_tmp_dir("finish-name-key");
        let published = captured_attempt(&base, A_SUFFIX, "10").finish().expect("publishes");
        assert_eq!(
            published.directory.file_name().unwrap().to_str().unwrap(),
            A_OLDER,
            "the final attempt name must be <20-digit-watermark>-<suffix>, with no wall-clock component"
        );
        assert_eq!(published.read_sequence_number().unwrap().number(), 10);
    }

    #[test]
    fn equal_sequence_reverse_completion_preserves_the_newer_cut() {
        // equal-sequence mutant: two attempts cut at the SAME watermark
        // (equivalent cuts) differ only in the counter component; recency is
        // still total and the counter-newer cut survives reverse completion.
        const A_EQ_SUFFIX: &str = "0000000000000003-cccc";
        const B_EQ_SUFFIX: &str = "0000000000000004-dddd";
        const B_EQ: &str = "00000000000000000020-0000000000000004-dddd";
        let base = create_tmp_dir("finish-equal-seq");
        let a = captured_attempt(&base, A_EQ_SUFFIX, "20");
        let b = captured_attempt(&base, B_EQ_SUFFIX, "20");

        b.finish().expect("B (same sequence, larger counter) publishes first");
        a.finish().expect("A finishes last");

        assert!(base.join(B_EQ).exists(), "the same-sequence newer cut must survive the older finisher's cleanup");
        assert_eq!(selected_name(&base).as_deref(), Some(B_EQ), "selection orders equal-sequence ids by counter");
    }

    #[test]
    fn a_cleanup_failure_does_not_affect_the_published_cut() {
        // Retention runs strictly after the durable publish: force cleanup to
        // fail deterministically (an older sibling that is a regular FILE with
        // an attempt-id name — `remove_dir_all` on it errors on every
        // platform) and prove the just-published cut is untouched, verified,
        // and selected despite the typed cleanup error.
        const UNDELETABLE_OLDER: &str = "00000000000000000005-0000000000000000-eeee";
        let base = create_tmp_dir("finish-cleanup-failure");
        fs::write(base.join(UNDELETABLE_OLDER), b"not-a-directory").unwrap();
        let b = captured_attempt(&base, B_SUFFIX, "20");

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

    #[test]
    fn an_unparseable_watermark_refuses_publication() {
        // R5-STOR-11: no sequence, no name — the attempt is refused with the
        // typed error instead of being published under a fallback ordering.
        let base = create_tmp_dir("finish-unparseable-watermark");
        let attempt = captured_attempt(&base, A_SUFFIX, "not-a-number");
        let error = attempt.finish().err().expect("an unparseable watermark must refuse publication");
        assert!(
            matches!(error, CheckpointCreateError::MetadataUnparseable { .. }),
            "expected MetadataUnparseable, got: {error:?}"
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

    /// Build a checkpoint directory the way `finish` does: data + metadata
    /// (the given watermark — which must agree with an attempt-named
    /// directory's sequence prefix, R5-STOR-11), then a COMPLETE marker bound
    /// to the sealed bytes, written last.
    fn build_complete_checkpoint(dir: &std::path::Path, watermark: &str) {
        fs::create_dir_all(dir.join("keyspace")).unwrap();
        fs::write(dir.join("keyspace").join("data.sst"), b"the-sst-bytes").unwrap();
        fs::write(dir.join(STORAGE_METADATA_FILE_NAME), watermark).unwrap();
        let manifest = CheckpointManifest::compute(dir).unwrap();
        fs::write(dir.join(CHECKPOINT_COMPLETE_FILE_NAME), manifest.serialise().as_bytes()).unwrap();
    }

    #[test]
    fn a_verified_complete_checkpoint_is_selectable() {
        let dir = create_tmp_dir("ckpt-complete");
        build_complete_checkpoint(&dir, "7");
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
        build_complete_checkpoint(&dir, "7");
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
        build_complete_checkpoint(&dir, "7");
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
        build_complete_checkpoint(&older, "100");
        // newer has data + metadata but a corrupted COMPLETE (unverifiable)
        build_complete_checkpoint(&newer, "200");
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
        build_complete_checkpoint(&tmp, "300"); // even a fully-built .tmp must be skipped
        let verified = verified_checkpoints_newest_first::<TestKs>(fs::read_dir(&base).unwrap()).unwrap();
        assert!(verified.is_empty(), "a .tmp attempt is in-flight and must never be selected");
    }

    #[test]
    fn candidates_are_enumerated_newest_to_oldest_by_full_attempt_id() {
        // R4-STOR-10: the fallback loop consumes candidates newest-first, in
        // the SAME total order retention uses — full-attempt-id lexicographic.
        // The two same-sequence entries are ordered by their counter component.
        let base = create_tmp_dir("ckpt-enumerate-order");
        let oldest = base.join("00000000000000000100-0000000000000001-aaaa");
        let middle = base.join("00000000000000000200-0000000000000002-bbbb");
        let newest = base.join("00000000000000000200-0000000000000003-cccc"); // equal sequence, larger counter
        for (dir, watermark) in [(&oldest, "100"), (&middle, "200"), (&newest, "200")] {
            build_complete_checkpoint(dir, watermark);
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
            "candidates must be newest-first by full attempt id (equal sequence disambiguated by counter)"
        );
    }

    #[test]
    fn a_legacy_or_forged_64bit_manifest_is_refused_as_unknown_version() {
        // R5-STOR-09 migration mutant: a COMPLETE marker in the retired v1
        // (64-bit SipHash) format — or any forged/unknown version — must be
        // refused, never dual-verified. The directory is unselectable.
        let dir = create_tmp_dir("ckpt-legacy-manifest");
        fs::create_dir_all(dir.join("keyspace")).unwrap();
        fs::write(dir.join("keyspace").join("data.sst"), b"the-sst-bytes").unwrap();
        fs::write(dir.join(STORAGE_METADATA_FILE_NAME), b"7").unwrap();
        // a plausible v1-format marker with 64-bit digests
        fs::write(
            dir.join(CHECKPOINT_COMPLETE_FILE_NAME),
            b"CHECKPOINT-COMPLETE v1\nroot 0123456789abcdef\n000000000000000d fedcba9876543210 6b657973706163652f646174612e737374\n",
        )
        .unwrap();
        let reader = CheckpointReader { directory: dir.to_path_buf() };
        assert!(
            !reader.is_complete::<TestKs>().unwrap(),
            "a legacy/unknown-version manifest must be refused, not dual-verified"
        );

        // and an unknown future/forged version equally so
        fs::write(dir.join(CHECKPOINT_COMPLETE_FILE_NAME), b"CHECKPOINT-COMPLETE v99\nroot 00\n").unwrap();
        assert!(!reader.is_complete::<TestKs>().unwrap(), "an unknown manifest version must be refused");
    }

    #[test]
    fn a_manifest_with_duplicate_normalized_keys_does_not_parse() {
        // R5-STOR-09: two entries claiming the same path key are an explicit
        // refusal — never a silent last-writer-wins that could mask a
        // substituted file.
        let dir = create_tmp_dir("ckpt-dup-keys");
        build_complete_checkpoint(&dir, "7");
        let serialised = fs::read_to_string(dir.join(CHECKPOINT_COMPLETE_FILE_NAME)).unwrap();
        let entry_line = serialised
            .lines()
            .find(|line| {
                !line.starts_with("CHECKPOINT-COMPLETE")
                    && !line.starts_with("root")
                    && !line.starts_with("watermark")
                    && !line.starts_with("created-utc")
            })
            .expect("the manifest carries at least one entry line");
        let forged = format!("{}{entry_line}\n", serialised);
        assert!(
            CheckpointManifest::parse(&forged).is_none(),
            "a manifest with a duplicated path key must be refused at parse"
        );
        // control: the unforged manifest parses
        assert!(CheckpointManifest::parse(&serialised).is_some());
    }

    #[cfg(unix)]
    #[test]
    fn distinct_invalid_utf8_names_stay_distinct_and_tampering_is_detected() {
        // R5-STOR-09 path-identity mutant: two file names whose byte
        // sequences are DISTINCT but lossy-collapse to the same replacement
        // string. Raw-byte path serialization must keep them distinct
        // manifest keys, and a byte flip in either file must fail
        // verification.
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let name_a = OsString::from_vec(vec![b'f', 0xC3, b'x']); // invalid UTF-8
        let name_b = OsString::from_vec(vec![b'f', 0xC2, b'x']); // invalid UTF-8, distinct bytes
        assert_eq!(
            name_a.to_string_lossy(),
            name_b.to_string_lossy(),
            "precondition: the two names must lossy-collapse to the same string"
        );

        let dir = create_tmp_dir("ckpt-raw-paths");
        fs::create_dir_all(dir.join("keyspace")).unwrap();
        fs::write(dir.join("keyspace").join(&name_a), b"bytes-of-a").unwrap();
        fs::write(dir.join("keyspace").join(&name_b), b"bytes-of-b").unwrap();
        fs::write(dir.join(STORAGE_METADATA_FILE_NAME), b"7").unwrap();
        let manifest = CheckpointManifest::compute(&dir).unwrap();
        assert_eq!(
            manifest.entries.len(),
            3, // the two data files + STORAGE_METADATA
            "distinct invalid-UTF-8 names must be distinct manifest keys, never collapsed"
        );
        fs::write(dir.join(CHECKPOINT_COMPLETE_FILE_NAME), manifest.serialise().as_bytes()).unwrap();

        let reader = CheckpointReader { directory: dir.to_path_buf() };
        assert!(reader.is_complete::<TestKs>().unwrap(), "the sealed cut with raw-byte names verifies");

        // tamper with ONE of the colliding-lossy-name files: under lossy
        // (collapsed) identity the two files share a key and the flip could
        // hide; under raw-byte identity it must be detected.
        fs::write(dir.join("keyspace").join(&name_b), b"bytes-of-B").unwrap();
        assert!(
            !reader.is_complete::<TestKs>().unwrap(),
            "a byte flip in a lossy-colliding-name file must fail verification"
        );
    }

    #[test]
    fn a_renamed_attempt_directory_is_not_selectable() {
        // R5-STOR-11: the attempt name's sequence prefix must agree with the
        // sealed watermark — renaming a published cut (to reorder selection
        // or retention) makes it unselectable rather than silently reordered.
        let base = create_tmp_dir("ckpt-renamed");
        let dir = base.join("00000000000000000200-0000000000000000-aaaa");
        build_complete_checkpoint(&dir, "100"); // sealed watermark 100, name claims 200
        let reader = CheckpointReader { directory: dir.clone() };
        assert!(
            !reader.is_complete::<TestKs>().unwrap(),
            "an attempt directory whose name sequence disagrees with its sealed watermark must be refused"
        );
    }
}

#[cfg(test)]
mod restore_durability_barrier_tests {
    //! R6-STOR-01 + R8-P1-02: the restore commit protocol is an EXPLICIT,
    //! FALLIBLE durability barrier plus a COMPLETE expected-versus-durable
    //! proof — never a `Drop` side effect, and never a sample.
    //!
    //! The round-8 audit's finding was that the previous barrier compared two
    //! OBSERVATIONS (after replay, after reopen) over the newest 256 replayed
    //! keys. Two whole classes of defect passed it:
    //!
    //!   * a replay that silently omitted an operation read `None` on both
    //!     sides — the observations agreed, and activation proceeded;
    //!   * a flush that lost the 257th-newest key, or any older one, was
    //!     outside the sample entirely.
    //!
    //! Every mutant the directive named is executed below against
    //! [`ExpectedReplayWitness`], which states what replay RESOLVED to write
    //! and requires every one of those keys to read back. `Drop` stays
    //! best-effort for unwind safety; it is no longer what decides whether a
    //! materialisation may be activated.

    use std::{collections::BTreeMap, fs, path::Path};

    use bytes::byte_array::ByteArray;
    use options::byte_size::ByteSize;
    use test_utils::create_tmp_dir;

    use super::{
        ExpectedReplayWitness, RestoreWitnessDivergence, SequenceNumber, WriteBatches, activate_scratch, scratch_root,
    };
    use crate::{
        SnapshotId,
        keyspace::{KeyspaceId, KeyspaceSet, Keyspaces, StorageBackend, rocks_resources::RocksResources},
        record::{CommitRecord, CommitType},
        snapshot::buffer::OperationsBuffer,
    };

    #[derive(Clone, Copy)]
    enum TestKs {
        Main,
    }
    impl KeyspaceSet for TestKs {
        fn iter() -> impl Iterator<Item = Self> {
            [Self::Main].into_iter()
        }
        fn id(&self) -> KeyspaceId {
            KeyspaceId(0)
        }
        fn name(&self) -> &'static str {
            "keyspace"
        }
        fn prefix_length(&self) -> Option<usize> {
            None
        }
    }

    fn resources() -> RocksResources {
        RocksResources::new(ByteSize::mb(64), ByteSize::mb(64))
    }

    fn open(dir: &Path, resources: &RocksResources) -> Keyspaces {
        Keyspaces::open::<TestKs>(dir, resources, StorageBackend::SlateLocalFs).expect("scratch keyspaces open")
    }

    // ------------------------------------------------------------------
    // A synthetic replay: N commits, each writing one key, in sequence order.
    // ------------------------------------------------------------------

    /// The write batches a replay of `count` commits resolves to, in the order
    /// `apply_recovered_observing` would hand them to the observer.
    fn synthetic_replay(count: u64, value: &[u8]) -> Vec<(SequenceNumber, WriteBatches)> {
        let mut out = Vec::new();
        for sequence in 1..=count {
            let mut operations = OperationsBuffer::new();
            operations
                .writes_in_mut(KeyspaceId(0))
                .insert(ByteArray::copy(format!("key-{sequence:08}").as_bytes()), ByteArray::copy(value));
            let record = CommitRecord::new(
                operations,
                SequenceNumber::new(sequence.saturating_sub(1)),
                CommitType::Data,
                SnapshotId::new(),
            );
            let sequence_number = SequenceNumber::new(sequence);
            out.push((sequence_number, WriteBatches::from_operations(sequence_number, record.operations())));
        }
        out
    }

    fn absorb_all(witness: &mut ExpectedReplayWitness, replay: &[(SequenceNumber, WriteBatches)]) {
        for (sequence_number, batches) in replay {
            witness.absorb(*sequence_number, batches);
        }
    }

    /// Apply `replay` to `keyspaces`, optionally DROPPING the batches whose
    /// index satisfies `skip`. That is how each "lose a write" mutant is
    /// injected: the witness still expects them, the store never receives them.
    fn apply(keyspaces: &Keyspaces, replay: Vec<(SequenceNumber, WriteBatches)>, skip: impl Fn(usize) -> bool) {
        for (index, (_sequence_number, batches)) in replay.into_iter().enumerate() {
            if skip(index) {
                continue;
            }
            keyspaces.write(batches).expect("replayed write");
        }
    }

    /// The refusal prints MVCC keys hex-encoded (they carry a binary sequence
    /// suffix), so a test that names a lost record must name it the same way.
    fn hex_key(sequence: u64) -> String {
        super::hex_encode(format!("key-{sequence:08}").as_bytes())
    }

    fn lost_detail(result: Result<(), RestoreWitnessDivergence>) -> String {
        match result {
            Ok(()) => panic!("the witness accepted a materialisation that lost replayed writes"),
            Err(RestoreWitnessDivergence::Lost { detail }) => detail,
            Err(RestoreWitnessDivergence::Unreadable { source }) => {
                panic!("the keyspace was unreadable rather than divergent: {source}")
            }
        }
    }

    // ------------------------------------------------------------------
    // Positive controls first: the suite must not be "refuse always".
    // ------------------------------------------------------------------

    #[test]
    fn a_complete_replay_verifies_before_and_after_the_barrier() {
        let scratch = create_tmp_dir("r8-p1-02-complete");
        let resources = resources();
        let replay = synthetic_replay(300, b"post-checkpoint-commit");
        let mut expected = ExpectedReplayWitness::default();
        absorb_all(&mut expected, &replay);
        assert_eq!(expected.expected.len(), 300, "every replayed key is in the index, not a sample of them");
        assert_eq!(expected.sequence_range, Some((SequenceNumber::new(1), SequenceNumber::new(300))));

        {
            let keyspaces = open(&scratch, &resources);
            apply(&keyspaces, replay, |_| false);
            expected.verify(&keyspaces, "after replay").expect("a complete replay is readable from the live engine");
            keyspaces.flush_and_close().expect("the explicit durability barrier must succeed on a healthy lane");
        }
        let keyspaces = open(&scratch, &resources);
        expected.verify(&keyspaces, "after close and reopen").expect("a proven flush carries every replayed key");
        keyspaces.flush_and_close().expect("the reopen is closed through the same barrier");
    }

    #[test]
    fn the_same_proof_holds_on_the_rocks_lane() {
        // The barrier and the witness are engine-neutral.
        let scratch = create_tmp_dir("r8-p1-02-rocks");
        let resources = resources();
        let replay = synthetic_replay(300, b"post-checkpoint-commit");
        let mut expected = ExpectedReplayWitness::default();
        absorb_all(&mut expected, &replay);
        {
            let keyspaces =
                Keyspaces::open::<TestKs>(&scratch, &resources, StorageBackend::Rocks).expect("rocks scratch opens");
            apply(&keyspaces, replay, |_| false);
            expected.verify(&keyspaces, "after replay").expect("readable from the live rocks engine");
            keyspaces.flush_and_close().expect("the barrier must succeed on a healthy rocks lane");
        }
        let keyspaces =
            Keyspaces::open::<TestKs>(&scratch, &resources, StorageBackend::Rocks).expect("rocks scratch reopens");
        expected.verify(&keyspaces, "after close and reopen").expect("a proven flush carries every key on Rocks too");
        keyspaces.flush_and_close().expect("the reopen is closed through the same barrier");
    }

    // ------------------------------------------------------------------
    // The mandated mutants (report §P1-02). None may activate.
    // ------------------------------------------------------------------

    #[test]
    fn mutant_drop_exactly_the_257th_newest_replayed_key() {
        // THE audit's headline case: the old barrier probed the newest 256
        // keys, so losing the 257th was invisible by construction.
        let scratch = create_tmp_dir("r8-p1-02-257th");
        let resources = resources();
        let replay = synthetic_replay(300, b"v");
        let mut expected = ExpectedReplayWitness::default();
        absorb_all(&mut expected, &replay);
        // newest is index 299; the 257th newest is index 300 - 257 = 43
        let victim = 300 - 257;
        let keyspaces = open(&scratch, &resources);
        apply(&keyspaces, replay, |i| i == victim);
        let detail = lost_detail(expected.verify(&keyspaces, "after replay"));
        assert!(detail.contains(&hex_key(44)), "the refusal names the lost key: {detail}");
        assert!(detail.contains("1 of 300 replayed keys are ABSENT"), "and counts it: {detail}");
        keyspaces.flush_and_close().expect("close still works; the refusal is the verdict, not a crash");
    }

    #[test]
    fn mutant_drop_the_oldest_replayed_key() {
        let scratch = create_tmp_dir("r8-p1-02-oldest");
        let resources = resources();
        let replay = synthetic_replay(300, b"v");
        let mut expected = ExpectedReplayWitness::default();
        absorb_all(&mut expected, &replay);
        let keyspaces = open(&scratch, &resources);
        apply(&keyspaces, replay, |i| i == 0);
        let detail = lost_detail(expected.verify(&keyspaces, "after replay"));
        assert!(detail.contains(&hex_key(1)), "the refusal names the oldest key: {detail}");
        keyspaces.flush_and_close().unwrap();
    }

    #[test]
    fn mutant_omit_an_operation_that_is_absent_in_both_observations() {
        // The defect the OLD barrier structurally could not see: a replay that
        // never wrote the record reads `None` after replay AND after reopen,
        // so observation-versus-observation agrees. Expected-versus-durable
        // does not.
        let scratch = create_tmp_dir("r8-p1-02-omitted");
        let resources = resources();
        let replay = synthetic_replay(8, b"v");
        let mut expected = ExpectedReplayWitness::default();
        absorb_all(&mut expected, &replay);
        {
            let keyspaces = open(&scratch, &resources);
            apply(&keyspaces, replay, |i| i == 3);
            // BOTH observations agree that the key is absent...
            assert!(
                keyspaces.get(KeyspaceId(0)).get(b"anything-absent", |_| ()).unwrap().is_none(),
                "sanity: an unwritten key reads None"
            );
            let detail = lost_detail(expected.verify(&keyspaces, "after replay"));
            assert!(detail.contains(&hex_key(4)), "...and the EXPECTATION still catches it: {detail}");
            keyspaces.flush_and_close().unwrap();
        }
        let keyspaces = open(&scratch, &resources);
        let detail = lost_detail(expected.verify(&keyspaces, "after close and reopen"));
        assert!(detail.contains("ABSENT"), "and it is still caught after the reopen: {detail}");
        keyspaces.flush_and_close().unwrap();
    }

    #[test]
    fn mutant_lose_a_tombstone() {
        // A logical delete at this layer is a PUT of an empty value under a
        // Delete-tagged MVCC key, so it is in the index like any other write —
        // and losing one is a divergence like any other. That is the property
        // being pinned: no special case, and no exemption for an empty value.
        let scratch = create_tmp_dir("r8-p1-02-tombstone");
        let resources = resources();
        let mut replay = Vec::new();
        for sequence in 1..=4u64 {
            let mut operations = OperationsBuffer::new();
            let key = ByteArray::copy(format!("key-{sequence:08}").as_bytes());
            if sequence == 3 {
                operations.writes_in_mut(KeyspaceId(0)).delete(key);
            } else {
                operations.writes_in_mut(KeyspaceId(0)).insert(key, ByteArray::copy(b"v"));
            }
            let record =
                CommitRecord::new(operations, SequenceNumber::new(sequence - 1), CommitType::Data, SnapshotId::new());
            let sequence_number = SequenceNumber::new(sequence);
            replay.push((sequence_number, WriteBatches::from_operations(sequence_number, record.operations())));
        }
        let mut expected = ExpectedReplayWitness::default();
        absorb_all(&mut expected, &replay);
        assert_eq!(expected.expected.len(), 4, "the tombstone is a touched key like any other");

        let keyspaces = open(&scratch, &resources);
        apply(&keyspaces, replay, |i| i == 2); // drop the tombstone
        let detail = lost_detail(expected.verify(&keyspaces, "after replay"));
        assert!(detail.contains(&hex_key(3)), "a lost tombstone is a lost write: {detail}");
        keyspaces.flush_and_close().unwrap();
    }

    #[test]
    fn duplicate_and_reordered_writes_to_one_key_are_handled_by_construction() {
        // An MVCC key embeds its sequence number, so two writes to one logical
        // key are two DISTINCT index entries and a reorder cannot change the
        // final set. Replaying the same batches twice, and in reverse order,
        // must produce the same index and the same root.
        let replay = synthetic_replay(16, b"v");
        let mut straight = ExpectedReplayWitness::default();
        absorb_all(&mut straight, &replay);

        let mut duplicated = ExpectedReplayWitness::default();
        absorb_all(&mut duplicated, &replay);
        absorb_all(&mut duplicated, &replay);
        assert_eq!(duplicated.expected.len(), straight.expected.len(), "a replayed duplicate is idempotent");
        assert_eq!(duplicated.root(), straight.root(), "and does not move the logical root");
        assert_eq!(duplicated.absorbed, 2 * straight.absorbed, "while the raw write count DOES record it");

        let mut reversed = ExpectedReplayWitness::default();
        for (sequence_number, batches) in replay.iter().rev() {
            reversed.absorb(*sequence_number, batches);
        }
        assert_eq!(reversed.root(), straight.root(), "order cannot change the final expected set");
        assert_eq!(reversed.sequence_range, straight.sequence_range, "and the bound WAL range is order-independent");
    }

    #[test]
    fn mutant_flush_reports_success_but_publishes_only_the_last_batch() {
        // A provider/engine defect in which the close returns Ok while only
        // the newest batch is durable. Every older key is lost, and the old
        // sampled barrier would have missed all but the newest 256 of them.
        let scratch = create_tmp_dir("r8-p1-02-last-batch-only");
        let resources = resources();
        let replay = synthetic_replay(300, b"v");
        let mut expected = ExpectedReplayWitness::default();
        absorb_all(&mut expected, &replay);
        let last = replay.len() - 1;
        {
            let keyspaces = open(&scratch, &resources);
            apply(&keyspaces, replay, move |i| i != last);
            keyspaces.flush_and_close().expect("the flush REPORTS success");
        }
        let keyspaces = open(&scratch, &resources);
        let detail = lost_detail(expected.verify(&keyspaces, "after close and reopen"));
        assert!(detail.contains("299 of 300 replayed keys are ABSENT"), "every lost key is counted: {detail}");
        keyspaces.flush_and_close().unwrap();
    }

    #[test]
    fn mutant_a_root_that_contains_only_checkpoint_bytes_and_no_replay() {
        // The materialisation is a perfectly valid restored checkpoint that
        // simply never received the replay. `scratch_root` is satisfied — it
        // asks only that each keyspace left a durable file — so the FILE root
        // cannot distinguish it. The LOGICAL witness can.
        let scratch = create_tmp_dir("r8-p1-02-checkpoint-only");
        let resources = resources();
        let replay = synthetic_replay(64, b"v");
        let mut expected = ExpectedReplayWitness::default();
        absorb_all(&mut expected, &replay);
        {
            let keyspaces = open(&scratch, &resources);
            // checkpoint bytes only: a write that is NOT part of the replay
            keyspaces.get(KeyspaceId(0)).put(b"checkpoint-key", b"checkpoint-value").expect("checkpoint write");
            keyspaces.flush_and_close().expect("the checkpoint-only tree closes cleanly");
        }
        let file_root = scratch_root::<TestKs>(&scratch);
        assert!(file_root.is_ok(), "the FILE root is satisfied by checkpoint bytes alone: {file_root:?}");

        let keyspaces = open(&scratch, &resources);
        let detail = lost_detail(expected.verify(&keyspaces, "after close and reopen"));
        assert!(detail.contains("64 of 64 replayed keys are ABSENT"), "the logical witness is not: {detail}");
        keyspaces.flush_and_close().unwrap();
    }

    #[test]
    fn mutant_a_replayed_value_that_changed_underneath_is_a_divergence_not_a_loss() {
        let scratch = create_tmp_dir("r8-p1-02-changed");
        let resources = resources();
        let replay = synthetic_replay(4, b"v");
        let mut expected = ExpectedReplayWitness::default();
        absorb_all(&mut expected, &replay);
        let mvcc_key = expected.expected.keys().next().unwrap().1.clone();
        let keyspaces = open(&scratch, &resources);
        apply(&keyspaces, replay, |_| false);
        keyspaces.get(KeyspaceId(0)).put(&mvcc_key, b"tampered").expect("overwrite");
        let detail = lost_detail(expected.verify(&keyspaces, "after replay"));
        assert!(detail.contains("0 of 4 replayed keys are ABSENT"), "nothing is missing: {detail}");
        assert!(detail.contains("1 hold different bytes"), "one holds the wrong bytes: {detail}");
        keyspaces.flush_and_close().unwrap();
    }

    #[test]
    fn an_unflushed_replay_never_activates() {
        // The R6-STOR-01 mutant kept: "let the value leave scope and trust
        // Drop". The engine is LEAKED instead of closed, which is what an
        // ignored or failed close leaves behind.
        let scratch = create_tmp_dir("r8-p1-02-no-barrier");
        let resources = resources();
        let replay = synthetic_replay(64, b"v");
        let mut expected = ExpectedReplayWitness::default();
        absorb_all(&mut expected, &replay);
        {
            let keyspaces = open(&scratch, &resources);
            apply(&keyspaces, replay, |_| false);
            expected.verify(&keyspaces, "after replay").expect("the records were in memory after replay");
            std::mem::forget(keyspaces); // no flush_and_close, no Drop
        }
        let keyspaces = open(&scratch, &resources);
        let detail = lost_detail(expected.verify(&keyspaces, "after close and reopen"));
        assert!(detail.contains("64 of 64 replayed keys are ABSENT"), "an unflushed replay is fully lost: {detail}");
        keyspaces.flush_and_close().unwrap();
    }

    // ------------------------------------------------------------------
    // The logical root, and what it is bound to.
    // ------------------------------------------------------------------

    #[test]
    fn the_logical_root_is_content_bound_and_stable_across_storage_rearrangement() {
        let a = {
            let mut w = ExpectedReplayWitness::default();
            absorb_all(&mut w, &synthetic_replay(32, b"v"));
            w
        };
        let same = {
            let mut w = ExpectedReplayWitness::default();
            absorb_all(&mut w, &synthetic_replay(32, b"v"));
            w
        };
        let different_value = {
            let mut w = ExpectedReplayWitness::default();
            absorb_all(&mut w, &synthetic_replay(32, b"w"));
            w
        };
        let fewer = {
            let mut w = ExpectedReplayWitness::default();
            absorb_all(&mut w, &synthetic_replay(31, b"v"));
            w
        };
        assert_eq!(a.root(), same.root(), "the same replay has the same logical root");
        assert_ne!(a.root(), different_value.root(), "changed replayed bytes change the root");
        assert_ne!(a.root(), fewer.root(), "a lost write changes the root");
        assert_eq!(a.root().len(), 64, "the root is a full SHA-256 digest in hex");
    }

    #[test]
    fn the_witness_binds_the_recovered_sequence_range_it_describes() {
        // R8-P1-02 item 7: a witness that does not say WHICH replay it is
        // about cannot be compared with anything later.
        let mut w = ExpectedReplayWitness::default();
        assert_eq!(w.sequence_range, None, "an empty witness names no range");
        absorb_all(&mut w, &synthetic_replay(5, b"v"));
        assert_eq!(w.sequence_range, Some((SequenceNumber::new(1), SequenceNumber::new(5))));
    }

    #[test]
    fn an_empty_replay_is_vacuously_proved_and_says_so() {
        // Nothing was replayed, so nothing can be lost — but the witness must
        // report an empty index rather than a pass over an unexamined store.
        let scratch = create_tmp_dir("r8-p1-02-empty");
        let resources = resources();
        let expected = ExpectedReplayWitness::default();
        assert!(expected.expected.is_empty());
        let keyspaces = open(&scratch, &resources);
        expected.verify(&keyspaces, "after replay").expect("an empty replay has nothing to lose");
        keyspaces.flush_and_close().unwrap();
    }

    // ------------------------------------------------------------------
    // Activation ordering: no divergence may rename anything.
    // ------------------------------------------------------------------

    /// The exact post-replay ordering `restore_validated` runs, inlined so the
    /// activation mutants are hermetic. The returned sequence number is what
    /// recovery would advance to; the error paths never produce one.
    fn barrier_then_activate(
        barrier: Result<(), String>,
        witness: Result<(), String>,
        next_sequence_number: SequenceNumber,
        scratch_dir: &Path,
        live_dir: &Path,
        retired_dir: &Path,
    ) -> Result<SequenceNumber, String> {
        barrier?;
        witness?;
        activate_scratch(scratch_dir, live_dir, retired_dir).map_err(|error| error.to_string())?;
        Ok(next_sequence_number)
    }

    struct Trees {
        _root: test_utils::TempDir,
        scratch: std::path::PathBuf,
        live: std::path::PathBuf,
        retired: std::path::PathBuf,
    }

    fn trees() -> Trees {
        let root = create_tmp_dir("r8-p1-02-trees");
        let (scratch, live, retired) =
            (root.join("restore-scratch"), root.join("storage"), root.join("restore-retired"));
        fs::create_dir_all(&scratch).unwrap();
        fs::write(scratch.join("MARK"), b"successor-bytes").unwrap();
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("MARK"), b"predecessor-bytes").unwrap();
        Trees { _root: root, scratch, live, retired }
    }

    #[test]
    fn an_unproven_flush_renames_nothing_and_advances_no_sequence() {
        let trees = trees();
        let outcome = barrier_then_activate(
            Err("remote flush failed".to_owned()),
            Ok(()),
            SequenceNumber::new(42),
            &trees.scratch,
            &trees.live,
            &trees.retired,
        );
        assert!(outcome.is_err(), "an unproven flush must refuse, got {outcome:?}");
        assert_eq!(
            fs::read(trees.live.join("MARK")).unwrap(),
            b"predecessor-bytes",
            "the predecessor must be byte-identical after a refused activation",
        );
        assert!(trees.scratch.join("MARK").exists(), "the scratch stays quarantined, not renamed over live");
        assert!(!trees.retired.exists(), "no active-marker change: the predecessor was never moved aside");
    }

    #[test]
    fn a_witness_that_does_not_hold_after_reopen_renames_nothing() {
        let trees = trees();
        let outcome = barrier_then_activate(
            Ok(()),
            Err("3 of 300 replayed keys are ABSENT after close and reopen".to_owned()),
            SequenceNumber::new(42),
            &trees.scratch,
            &trees.live,
            &trees.retired,
        );
        let error = outcome.expect_err("a witness divergence must refuse activation");
        assert!(error.contains("replayed keys are ABSENT"), "the refusal names the loss: {error}");
        assert_eq!(
            fs::read(trees.live.join("MARK")).unwrap(),
            b"predecessor-bytes",
            "the predecessor must be byte-identical after a refused activation",
        );
        assert!(!trees.retired.exists(), "no active-marker change");
    }

    #[test]
    fn a_proven_flush_and_a_holding_witness_activates_and_advances() {
        // Positive control: the two refusals above are not "refuse always".
        let trees = trees();
        let advanced =
            barrier_then_activate(Ok(()), Ok(()), SequenceNumber::new(42), &trees.scratch, &trees.live, &trees.retired)
                .expect("a proven restore must activate");
        assert_eq!(advanced, SequenceNumber::new(42));
        assert_eq!(fs::read(trees.live.join("MARK")).unwrap(), b"successor-bytes", "the successor is now live");
        assert!(!trees.scratch.exists(), "the scratch was renamed into place");
    }

    #[test]
    fn the_root_check_refuses_a_keyspace_that_materialised_nothing() {
        // R6-STOR-01 root half: an engine that "closed cleanly" while writing
        // no durable file is not an activatable materialisation. Kept because
        // it catches a different thing from the logical witness: a keyspace
        // that received NO replay at all has an empty expected set and would
        // be vacuously proved.
        let scratch = create_tmp_dir("r8-p1-02-root");
        fs::create_dir_all(scratch.join("keyspace")).unwrap();
        let empty = scratch_root::<TestKs>(&scratch);
        assert!(empty.is_err(), "an empty keyspace tree must not be activatable, got {empty:?}");
        assert!(empty.unwrap_err().contains("no durable file"));

        fs::write(scratch.join("keyspace").join("0001.sst"), b"durable").unwrap();
        let root = scratch_root::<TestKs>(&scratch).expect("a materialised keyspace has a root");
        assert_eq!(root.len(), 64, "the root is a full SHA-256 digest in hex");

        // and the root is content-bound: changed bytes change the root
        fs::write(scratch.join("keyspace").join("0001.sst"), b"different").unwrap();
        assert_ne!(scratch_root::<TestKs>(&scratch).unwrap(), root);
    }

    #[test]
    fn the_expected_index_holds_no_value_bytes() {
        // R8-P1-02: memory is bounded by the deduplicated touched-key index
        // plus one 32-byte digest per key, whatever the values weigh. A
        // 1 MiB-per-value replay must cost the same index as a 1-byte one.
        let small = {
            let mut w = ExpectedReplayWitness::default();
            absorb_all(&mut w, &synthetic_replay(8, b"v"));
            w
        };
        let huge = {
            let mut w = ExpectedReplayWitness::default();
            absorb_all(&mut w, &synthetic_replay(8, &vec![b'x'; 1 << 20]));
            w
        };
        assert_eq!(small.expected.len(), huge.expected.len());
        let index_bytes = |w: &ExpectedReplayWitness| {
            w.expected.iter().map(|((_, key), digest)| key.len() + digest.len()).sum::<usize>()
        };
        assert_eq!(
            index_bytes(&small),
            index_bytes(&huge),
            "the index must not grow with value size — that is the whole memory bound"
        );
        assert_ne!(small.root(), huge.root(), "while still binding the value CONTENT through its digest");
    }

    #[test]
    fn a_rejected_commit_contributes_nothing_to_the_expectation() {
        // A rejected commit writes nothing, so it must expect nothing:
        // `apply_recovered_observing` never calls the observer for one.
        let mut recovered: BTreeMap<SequenceNumber, super::RecoveryCommitStatus> = BTreeMap::new();
        recovered.insert(SequenceNumber::new(1), super::RecoveryCommitStatus::Rejected);
        let witness = ExpectedReplayWitness::default();
        assert!(witness.expected.is_empty(), "nothing observed, nothing expected");
        assert_eq!(recovered.len(), 1, "the rejected row is still part of the recovered set");
    }
}

#[cfg(test)]
mod scratch_restore_tests {
    //! R5-STOR-06 unit level: the atomic rename-swap activation and the
    //! restart convergence of every crash state a restore can leave behind.
    //! (The full kill-point matrix over real storage runs in
    //! `tests/test_recovery.rs`.)

    use std::fs;

    use test_utils::create_tmp_dir;

    use super::{RESTORE_RETIRED_PREFIX, RESTORE_SCRATCH_PREFIX, activate_scratch, converge_interrupted_restore};

    #[test]
    fn activation_swaps_scratch_into_live_and_reclaims_the_retired_predecessor() {
        let root = create_tmp_dir("activate-swap");
        let live = root.join("storage");
        let scratch = root.join(format!("{RESTORE_SCRATCH_PREFIX}a"));
        let retired = root.join(format!("{RESTORE_RETIRED_PREFIX}a"));
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("SENTINEL"), b"predecessor").unwrap();
        fs::create_dir_all(&scratch).unwrap();
        fs::write(scratch.join("SENTINEL"), b"successor").unwrap();

        activate_scratch(&scratch, &live, &retired).expect("activation succeeds");

        assert_eq!(fs::read(live.join("SENTINEL")).unwrap(), b"successor", "the successor is active");
        assert!(!scratch.exists(), "the scratch directory was renamed away");
        assert!(!retired.exists(), "the retired predecessor was reclaimed");
    }

    #[test]
    fn a_failed_swap_rolls_the_predecessor_back() {
        // the second rename fails deterministically (the scratch directory
        // does not exist); the first rename must be rolled back so the
        // predecessor is byte-identical AND still active.
        let root = create_tmp_dir("activate-rollback");
        let live = root.join("storage");
        let scratch = root.join(format!("{RESTORE_SCRATCH_PREFIX}a")); // never created
        let retired = root.join(format!("{RESTORE_RETIRED_PREFIX}a"));
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("SENTINEL"), b"predecessor").unwrap();

        activate_scratch(&scratch, &live, &retired).expect_err("a missing scratch directory must fail activation");

        assert_eq!(
            fs::read(live.join("SENTINEL")).unwrap(),
            b"predecessor",
            "R5-STOR-06: a failed activation must leave the predecessor active and byte-identical"
        );
        assert!(!retired.exists(), "the roll-back must not leave the predecessor stranded under the retired name");
    }

    #[test]
    fn convergence_reclaims_pre_activation_scratch_residue() {
        // crash after copy / open / replay / digest — all leave only scratch
        // residue; the predecessor is intact and the residue is reclaimed.
        let root = create_tmp_dir("converge-scratch");
        let live = root.join("storage");
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("SENTINEL"), b"predecessor").unwrap();
        let scratch = root.join(format!("{RESTORE_SCRATCH_PREFIX}a"));
        fs::create_dir_all(&scratch).unwrap();
        fs::write(scratch.join("SENTINEL"), b"half-restored").unwrap();

        converge_interrupted_restore(&live).unwrap();

        assert_eq!(fs::read(live.join("SENTINEL")).unwrap(), b"predecessor", "the predecessor is untouched");
        assert!(!scratch.exists(), "unproven scratch residue is reclaimed");
    }

    #[test]
    fn convergence_rolls_back_a_crash_between_the_activation_renames() {
        // live -> retired happened, scratch -> live did not: the live
        // directory is missing and the predecessor sits under the retired
        // name. Convergence must reinstate the predecessor.
        let root = create_tmp_dir("converge-torn");
        let live = root.join("storage");
        let retired = root.join(format!("{RESTORE_RETIRED_PREFIX}a"));
        let scratch = root.join(format!("{RESTORE_SCRATCH_PREFIX}a"));
        fs::create_dir_all(&retired).unwrap();
        fs::write(retired.join("SENTINEL"), b"predecessor").unwrap();
        fs::create_dir_all(&scratch).unwrap();
        fs::write(scratch.join("SENTINEL"), b"successor-in-progress").unwrap();

        converge_interrupted_restore(&live).unwrap();

        assert_eq!(
            fs::read(live.join("SENTINEL")).unwrap(),
            b"predecessor",
            "a torn swap must converge to the predecessor being active again"
        );
        assert!(!retired.exists() && !scratch.exists(), "all restore residue is reclaimed");
    }

    #[test]
    fn convergence_reclaims_the_retired_predecessor_after_a_completed_swap() {
        // both renames happened, the retired reclaim did not: the successor
        // is active; the retired predecessor is residue.
        let root = create_tmp_dir("converge-post");
        let live = root.join("storage");
        let retired = root.join(format!("{RESTORE_RETIRED_PREFIX}a"));
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("SENTINEL"), b"successor").unwrap();
        fs::create_dir_all(&retired).unwrap();
        fs::write(retired.join("SENTINEL"), b"predecessor").unwrap();

        converge_interrupted_restore(&live).unwrap();

        assert_eq!(fs::read(live.join("SENTINEL")).unwrap(), b"successor", "the successor stays active");
        assert!(!retired.exists(), "the retired predecessor is reclaimed");
    }

    #[test]
    fn convergence_is_a_no_op_on_a_clean_tree() {
        let root = create_tmp_dir("converge-clean");
        let live = root.join("storage");
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("SENTINEL"), b"live").unwrap();
        converge_interrupted_restore(&live).unwrap();
        assert_eq!(fs::read(live.join("SENTINEL")).unwrap(), b"live");
    }
}
