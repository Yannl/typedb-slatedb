/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::{collections::BTreeMap, error::Error, sync::Arc};

use durability::RawRecord;
use error::typedb_error;
use fail_point::{RECOVERY_PARTIAL_WRITE, fail_point};
use tracing::{Level, event, trace};

use crate::{
    MVCCStorage,
    durability_client::{DurabilityClient, DurabilityClientError, DurabilityRecord},
    isolation_manager::{IsolationManager, ValidatedCommit},
    keyspace::{KeyspaceError, Keyspaces},
    record::{CommitRecord, LegacyCommitRecordV1, StatusRecord},
    sequence_number::SequenceNumber,
    write_batches::WriteBatches,
};

/// Load commit data from the start onwards. Ignores any statuses that are not paired with commit data.
pub fn load_commit_data_from(
    start: SequenceNumber,
    durability_client: &impl DurabilityClient,
) -> Result<BTreeMap<SequenceNumber, RecoveryCommitStatus>, StorageRecoveryError> {
    load_commit_data_from_with_context(start, 0, durability_client, 0)
}

pub fn load_commit_data_from_with_context(
    start: SequenceNumber,
    context_size: u64,
    durability_client: &impl DurabilityClient,
    context_memory_limit: usize,
) -> Result<BTreeMap<SequenceNumber, RecoveryCommitStatus>, StorageRecoveryError> {
    use StorageRecoveryError::{DurabilityClientRead, DurabilityRecordDeserialize, DurabilityRecordsMissing};

    let load_start = start.saturating_sub(context_size);
    let records =
        durability_client.iter_from(load_start).map_err(|error| DurabilityClientRead { typedb_source: error })?;

    let mut recovered_commits = BTreeMap::new();
    let mut recovered_commit_sizes = BTreeMap::new();

    let mut bytes_read = 0;

    let mut first_record = true;
    for record in records {
        let RawRecord { sequence_number, record_type, bytes } =
            record.map_err(|error| DurabilityClientRead { typedb_source: error })?;
        if first_record {
            if sequence_number != load_start {
                return Err(DurabilityRecordsMissing {
                    expected_sequence_number: start,
                    first_record_sequence_number: sequence_number,
                });
            }
            first_record = false;
        }

        match record_type {
            LegacyCommitRecordV1::RECORD_TYPE => {
                let legacy = LegacyCommitRecordV1::deserialise_from(&mut &*bytes)
                    .map_err(|error| DurabilityRecordDeserialize { source: Arc::new(error) })?;
                let commit_record = CommitRecord::from(legacy);
                recovered_commits.insert(sequence_number, RecoveryCommitStatus::Pending(commit_record));
                recovered_commit_sizes.insert(sequence_number, bytes.len());
                bytes_read += bytes.len();
                trace!(
                    "Read legacy commit V1 @ {} with size {}; {} total",
                    sequence_number,
                    format_size(bytes.len()),
                    format_size(bytes_read),
                );
            }
            CommitRecord::RECORD_TYPE => {
                let commit_record = CommitRecord::deserialise_from(&mut &*bytes)
                    .map_err(|error| DurabilityRecordDeserialize { source: Arc::new(error) })?;
                recovered_commits.insert(sequence_number, RecoveryCommitStatus::Pending(commit_record));
                recovered_commit_sizes.insert(sequence_number, bytes.len());
                bytes_read += bytes.len();
                trace!(
                    "Read commit @ {} with size {}; {} total",
                    sequence_number,
                    format_size(bytes.len()),
                    format_size(bytes_read),
                );
            }
            StatusRecord::RECORD_TYPE => {
                let StatusRecord { commit_record_sequence_number, was_committed } =
                    StatusRecord::deserialise_from(&mut &*bytes)
                        .map_err(|error| DurabilityRecordDeserialize { source: Arc::new(error) })?;
                apply_status_record(
                    &mut recovered_commits,
                    &mut recovered_commit_sizes,
                    &mut bytes_read,
                    commit_record_sequence_number,
                    was_committed,
                )?;
            }
            _not_storage_record => (), // skip, not storage record
        }

        while bytes_read > context_memory_limit
            && recovered_commits.first_key_value().is_some_and(|(&seq, _)| seq < start)
        {
            recovered_commits.pop_first();
            let (seq, size) = recovered_commit_sizes.pop_first().expect("can't be over memory limit with zero commits");
            bytes_read -= size;
            trace!("Discarded commit @ {} with size {}; {} total", seq, format_size(size), format_size(bytes_read));
        }
    }
    Ok(recovered_commits)
}

/// Fold one status record into the recovery state.
///
/// The WAL can legitimately carry more than one status record for one commit
/// sequence number: recovery itself re-persists a status for every commit it
/// re-validates (see [`apply_recovered`]), so a crash mid-recovery replays
/// those statuses on the next attempt. The invariant is therefore
/// IDEMPOTENCE, not uniqueness — a repeated IDENTICAL status converges to
/// the same single outcome with no double accounting. OPPOSITE statuses for
/// one commit can never both have been decided, so that pairing is WAL
/// corruption: it quarantines the recovery with a typed error, identically
/// in either order. It must never panic, silently let the last record win,
/// or subtract a commit's size from the running total twice.
fn apply_status_record(
    recovered_commits: &mut BTreeMap<SequenceNumber, RecoveryCommitStatus>,
    recovered_commit_sizes: &mut BTreeMap<SequenceNumber, usize>,
    bytes_read: &mut usize,
    commit_record_sequence_number: SequenceNumber,
    was_committed: bool,
) -> Result<(), StorageRecoveryError> {
    match (recovered_commits.get(&commit_record_sequence_number), was_committed) {
        // a status whose commit data is outside the loaded window: skip, as documented on the loader
        (None, _) => (),
        (Some(RecoveryCommitStatus::Pending(_)), true) => {
            let Some(RecoveryCommitStatus::Pending(record)) = recovered_commits.remove(&commit_record_sequence_number)
            else {
                unreachable!("status entry disappeared between lookup and removal")
            };
            recovered_commits.insert(commit_record_sequence_number, RecoveryCommitStatus::Validated(record));
            trace!("Marked as committed commit @ {}", commit_record_sequence_number);
        }
        (Some(RecoveryCommitStatus::Pending(_)), false) => {
            recovered_commits.insert(commit_record_sequence_number, RecoveryCommitStatus::Rejected);
            // the rejected commit's bytes leave the accounted total exactly once; the size slot is
            // zeroed (not removed — the eviction loop pops commits and sizes in lockstep) so neither
            // a replayed rejection nor a later eviction of this commit can subtract it again
            let commit_record_size = match recovered_commit_sizes.get_mut(&commit_record_sequence_number) {
                Some(size) => std::mem::take(size),
                None => 0,
            };
            *bytes_read -= commit_record_size;
            trace!(
                "Discarded commit @ {} with size {}; {} total",
                commit_record_sequence_number,
                format_size(commit_record_size),
                format_size(*bytes_read),
            );
        }
        // an identical replayed status: recovery already converged on this outcome
        (Some(RecoveryCommitStatus::Validated(_)), true) | (Some(RecoveryCommitStatus::Rejected), false) => (),
        // opposite statuses for one commit: corruption, quarantined order-independently
        (Some(RecoveryCommitStatus::Validated(_)), false) | (Some(RecoveryCommitStatus::Rejected), true) => {
            return Err(StorageRecoveryError::ConflictingRecoveryStatus {
                sequence_number: commit_record_sequence_number,
            });
        }
    }
    Ok(())
}

fn format_size(bytes: usize) -> String {
    const K: usize = 1024;
    const M: usize = 1024 * K;
    const G: usize = 1024 * M;
    match bytes {
        0..K => format!("{} bytes", bytes),
        K..M => format!("{:.2} KiB", bytes as f64 / K as f64),
        M..G => format!("{:.2} MiB", bytes as f64 / M as f64),
        G.. => format!("{:.2} GiB", bytes as f64 / G as f64),
    }
}

pub(crate) fn apply_recovered(
    database_name: &str,
    recovered_commits: BTreeMap<SequenceNumber, RecoveryCommitStatus>,
    durability_client: &impl DurabilityClient,
    keyspaces: &Keyspaces,
) -> Result<(), StorageRecoveryError> {
    event!(Level::TRACE, "Applying recovered commits");
    use StorageRecoveryError::{DurabilityClientRead, DurabilityClientWrite, Internal, KeyspaceWrite};

    if recovered_commits.is_empty() {
        return Ok(());
    }

    let isolation_manager = IsolationManager::new(*recovered_commits.first_key_value().unwrap().0);

    for (commit_sequence_number, commit) in recovered_commits {
        match commit {
            RecoveryCommitStatus::Validated(commit_record) => {
                let write_batches = WriteBatches::from_operations(commit_sequence_number, commit_record.operations());
                isolation_manager.load_validated(commit_sequence_number, commit_record);
                keyspaces.write(write_batches).map_err(|error| KeyspaceWrite { source: error })?;
                fail_point!(RECOVERY_PARTIAL_WRITE);
                isolation_manager
                    .applied(commit_sequence_number)
                    .map_err(|error| Internal { name: Arc::<str>::from(database_name), source: Arc::new(error) })?;
            }
            RecoveryCommitStatus::Rejected => isolation_manager.load_aborted(commit_sequence_number),
            RecoveryCommitStatus::Pending(commit_record) => {
                let read_guard = isolation_manager.opened_for_read(commit_record.open_sequence_number());
                let validated_commit = isolation_manager
                    .validate_commit(commit_sequence_number, commit_record, durability_client)
                    .map_err(|error| DurabilityClientRead { typedb_source: error })?;
                drop(read_guard);
                match validated_commit {
                    ValidatedCommit::Write(write_batches) => {
                        MVCCStorage::persist_commit_status(true, commit_sequence_number, durability_client)
                            .map_err(|error| DurabilityClientWrite { typedb_source: error })?;
                        keyspaces.write(write_batches).map_err(|error| KeyspaceWrite { source: error })?;
                        fail_point!(RECOVERY_PARTIAL_WRITE);
                        isolation_manager.applied(commit_sequence_number).map_err(|error| Internal {
                            name: Arc::<str>::from(database_name),
                            source: Arc::new(error),
                        })?;
                    }
                    ValidatedCommit::Conflict(_) => {
                        MVCCStorage::persist_commit_status(false, commit_sequence_number, durability_client)
                            .map_err(|error| DurabilityClientWrite { typedb_source: error })?;
                    }
                }
            }
        }
    }

    Ok(())
}

pub enum RecoveryCommitStatus {
    Pending(CommitRecord),
    Validated(CommitRecord),
    Rejected,
}

#[cfg(test)]
mod status_replay_tests {
    //! S-P0-03 controls: duplicate status records for one commit are
    //! idempotent, opposite ones are a typed quarantine (order-independent),
    //! and a crash-and-rerun over the same records converges — the four-cell
    //! duplicate matrix plus the replay property. The mutant "last status
    //! record wins for the opposite-status case" fails the quarantine tests;
    //! "subtract the size on every rejection" fails the accounting test.

    use std::collections::BTreeMap;

    use super::{RecoveryCommitStatus, StorageRecoveryError, apply_status_record};
    use crate::{
        record::{CommitRecord, CommitType},
        sequence_number::SequenceNumber,
        snapshot::{buffer::OperationsBuffer, snapshot_id::SnapshotId},
    };

    const COMMIT_SIZE: usize = 100;

    fn commit_record() -> CommitRecord {
        CommitRecord::new(OperationsBuffer::new(), SequenceNumber::MIN, CommitType::Data, SnapshotId::new())
    }

    struct State {
        commits: BTreeMap<SequenceNumber, RecoveryCommitStatus>,
        sizes: BTreeMap<SequenceNumber, usize>,
        bytes_read: usize,
    }

    fn state_with_pending(sequence_numbers: &[u64]) -> State {
        let mut commits = BTreeMap::new();
        let mut sizes = BTreeMap::new();
        for &number in sequence_numbers {
            commits.insert(SequenceNumber::new(number), RecoveryCommitStatus::Pending(commit_record()));
            sizes.insert(SequenceNumber::new(number), COMMIT_SIZE);
        }
        let bytes_read = COMMIT_SIZE * sequence_numbers.len();
        State { commits, sizes, bytes_read }
    }

    fn apply(state: &mut State, sequence_number: u64, was_committed: bool) -> Result<(), StorageRecoveryError> {
        apply_status_record(
            &mut state.commits,
            &mut state.sizes,
            &mut state.bytes_read,
            SequenceNumber::new(sequence_number),
            was_committed,
        )
    }

    fn shape(state: &State) -> Vec<(u64, &'static str)> {
        state
            .commits
            .iter()
            .map(|(seq, status)| {
                let tag = match status {
                    RecoveryCommitStatus::Pending(_) => "pending",
                    RecoveryCommitStatus::Validated(_) => "validated",
                    RecoveryCommitStatus::Rejected => "rejected",
                };
                (seq.number(), tag)
            })
            .collect()
    }

    #[test]
    fn repeated_committed_status_is_idempotent() {
        let mut state = state_with_pending(&[1]);
        apply(&mut state, 1, true).unwrap();
        apply(&mut state, 1, true).unwrap();
        assert_eq!(shape(&state), &[(1, "validated")]);
        assert_eq!(state.bytes_read, COMMIT_SIZE, "a validated commit's bytes stay accounted exactly once");
    }

    #[test]
    fn repeated_rejected_status_subtracts_the_size_exactly_once() {
        let mut state = state_with_pending(&[1, 2]);
        apply(&mut state, 1, false).unwrap();
        assert_eq!(state.bytes_read, COMMIT_SIZE, "the rejected commit's bytes leave the total once");
        apply(&mut state, 1, false).unwrap();
        assert_eq!(shape(&state), &[(1, "rejected"), (2, "pending")]);
        assert_eq!(
            state.bytes_read, COMMIT_SIZE,
            "a replayed rejection must not subtract again (debug underflow / release wrap)"
        );
    }

    #[test]
    fn committed_then_rejected_is_a_typed_quarantine_not_last_write_wins() {
        let mut state = state_with_pending(&[1]);
        apply(&mut state, 1, true).unwrap();
        let error = apply(&mut state, 1, false).expect_err("opposite statuses must quarantine");
        assert!(
            matches!(error, StorageRecoveryError::ConflictingRecoveryStatus { sequence_number } if sequence_number == SequenceNumber::new(1)),
            "expected ConflictingRecoveryStatus, got: {error:?}"
        );
        assert_eq!(shape(&state), &[(1, "validated")], "the recorded outcome must not silently flip");
        assert_eq!(state.bytes_read, COMMIT_SIZE, "quarantine must not alter accounting");
    }

    #[test]
    fn rejected_then_committed_is_the_identical_quarantine() {
        let mut state = state_with_pending(&[1]);
        apply(&mut state, 1, false).unwrap();
        let error = apply(&mut state, 1, true).expect_err("opposite statuses must quarantine in either order");

        // order-independence: the same corruption yields the same typed error either way round
        let mut opposite_order = state_with_pending(&[1]);
        apply(&mut opposite_order, 1, true).unwrap();
        let opposite_error = apply(&mut opposite_order, 1, false).unwrap_err();
        assert_eq!(format!("{error:?}"), format!("{opposite_error:?}"), "both orders must produce one quarantine");
    }

    #[test]
    fn status_without_loaded_commit_data_is_skipped() {
        let mut state = state_with_pending(&[]);
        apply(&mut state, 42, true).unwrap();
        apply(&mut state, 42, false).unwrap();
        assert!(state.commits.is_empty());
        assert_eq!(state.bytes_read, 0);
    }

    #[test]
    fn rerunning_the_handler_over_the_same_records_converges() {
        // a crash mid-recovery replays the WAL from the start, including the
        // statuses the previous attempt persisted: two full runs over the
        // same records must land in the identical state
        let records: &[(u64, bool)] = &[(1, true), (2, false), (1, true), (2, false), (3, true)];
        let mut runs = Vec::new();
        for _ in 0..2 {
            let mut state = state_with_pending(&[1, 2, 3]);
            for &(sequence_number, was_committed) in records {
                apply(&mut state, sequence_number, was_committed).unwrap();
            }
            runs.push((
                shape(&state).into_iter().map(|(seq, tag)| (seq, tag.to_owned())).collect::<Vec<_>>(),
                state.bytes_read,
            ));
        }
        assert_eq!(runs[0], runs[1], "repeated crash recovery must converge to one outcome");
        assert_eq!(runs[0].1, 2 * COMMIT_SIZE, "only the rejected commit leaves the accounted total");
    }
}

typedb_error! {
    pub StorageRecoveryError(component = "Storage recovery", prefix = "REC") {
        DurabilityRecordDeserialize(1, "Failed to deserialise WAL record.", source: Arc<bincode::Error>),
        DurabilityClientRead(2, "Durability client read error.", typedb_source: DurabilityClientError),
        DurabilityClientWrite(3, "Durability client write error.", typedb_source: DurabilityClientError),
        DurabilityRecordsMissing(
            4,
            "Missing initial WAL records - expected first record number '{expected_sequence_number}', but found '{first_record_sequence_number}'.",
            expected_sequence_number: SequenceNumber, first_record_sequence_number: SequenceNumber
        ),
        KeyspaceWrite(5, "Error writing recovered commits to keyspace.", source: KeyspaceError),
        Internal(6, "Storage recovery for database '{name}' failed with internal error.", name: Arc<str>, source: Arc<dyn Error + Send + Sync + 'static>),
        ConflictingRecoveryStatus(
            7,
            "Quarantined WAL: commit '{sequence_number}' carries both a committed and a rejected status record. The durability log is corrupt; refusing to pick either outcome.",
            sequence_number: SequenceNumber
        ),
    }
}
