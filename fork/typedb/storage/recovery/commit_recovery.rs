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
    recovery::status_resolver::{StatusConflict, fold_status},
    sequence_number::SequenceNumber,
    write_batches::WriteBatches,
};

/// Load commit data from the start onwards, proving a strict fixed-head
/// contiguous WAL prefix (R-01).
///
/// Grammar the raw record stream must satisfy, against ONE durability head
/// captured from the WAL's own recovered end BEFORE folding:
/// - exactly one valid sequenced commit record (legacy V1 or current) for
///   every sequence number in `load_start..=head`, in order;
/// - unsequenced records (status records, and non-storage record types such
///   as statistics) are permitted only where the WAL's append discipline
///   puts them: carrying the sequence number of the commit record folded
///   immediately before them;
/// - a status record's payload may only reference an already-folded commit
///   (or one below the window, which is skipped as documented);
/// - EMPTY iteration is legal only when `load_start > head`.
///
/// Gap, regression/duplicate, unknown type claiming a fresh sequence,
/// malformed record, conflicting duplicate status, record beyond the head
/// and early end-of-stream are all typed refusals with nothing mutated.
/// Callers must derive the recovery frontier from the durability head, never
/// from `max()` over the returned map.
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
    use StorageRecoveryError::{
        CommitRecordGap, CommitRecordRegression, DurabilityClientRead, DurabilityRecordDeserialize,
        DurabilityRecordsMissing, IncompleteCommitStream, RecordBeyondDurabilityHead, StatusForUnwrittenCommit,
        UnsequencedRecordWithoutCommit,
    };

    // R-01: ONE fixed durability head, captured from the WAL's own recovered
    // end BEFORE any folding. Every proof below is against this value.
    let head = durability_client.previous();

    let load_start = start.saturating_sub(context_size);
    let records =
        durability_client.iter_from(load_start).map_err(|error| DurabilityClientRead { typedb_source: error })?;

    let mut recovered_commits = BTreeMap::new();
    let mut recovered_commit_sizes = BTreeMap::new();

    let mut bytes_read = 0;

    // the next sequence number a commit record must carry, and the last one
    // a commit record did carry (unsequenced records repeat the latter)
    let mut expected_next = load_start;
    let mut last_commit_sequence_number: Option<SequenceNumber> = None;

    for record in records {
        let RawRecord { sequence_number, record_type, bytes } =
            record.map_err(|error| DurabilityClientRead { typedb_source: error })?;

        if sequence_number > head {
            // no record above the recovered head can exist in a well-formed log
            return Err(RecordBeyondDurabilityHead { sequence_number, head });
        }

        match record_type {
            LegacyCommitRecordV1::RECORD_TYPE | CommitRecord::RECORD_TYPE => {
                if sequence_number != expected_next {
                    if last_commit_sequence_number.is_none() {
                        return Err(DurabilityRecordsMissing {
                            expected_sequence_number: expected_next,
                            first_record_sequence_number: sequence_number,
                        });
                    } else if sequence_number > expected_next {
                        return Err(CommitRecordGap { expected: expected_next, found: sequence_number });
                    } else {
                        // duplicate or regressed commit record: "exactly one
                        // valid commit per sequence" refuses both, whether
                        // the duplicate's payload is identical or not
                        return Err(CommitRecordRegression { expected: expected_next, found: sequence_number });
                    }
                }
                let commit_record = if record_type == LegacyCommitRecordV1::RECORD_TYPE {
                    let legacy = LegacyCommitRecordV1::deserialise_from(&mut &*bytes)
                        .map_err(|error| DurabilityRecordDeserialize { source: Arc::new(error) })?;
                    CommitRecord::from(legacy)
                } else {
                    CommitRecord::deserialise_from(&mut &*bytes)
                        .map_err(|error| DurabilityRecordDeserialize { source: Arc::new(error) })?
                };
                recovered_commits.insert(sequence_number, RecoveryCommitStatus::Pending(commit_record));
                recovered_commit_sizes.insert(sequence_number, bytes.len());
                bytes_read += bytes.len();
                last_commit_sequence_number = Some(sequence_number);
                expected_next =
                    sequence_number.try_next().ok_or(RecordBeyondDurabilityHead { sequence_number, head })?;
                trace!(
                    "Read commit @ {} with size {}; {} total",
                    sequence_number,
                    format_size(bytes.len()),
                    format_size(bytes_read),
                );
            }
            StatusRecord::RECORD_TYPE => {
                if last_commit_sequence_number != Some(sequence_number) {
                    // an unsequenced record always repeats the sequence
                    // number of the commit it was appended after
                    return Err(UnsequencedRecordWithoutCommit { sequence_number, record_type });
                }
                let StatusRecord { commit_record_sequence_number, was_committed } =
                    StatusRecord::deserialise_from(&mut &*bytes)
                        .map_err(|error| DurabilityRecordDeserialize { source: Arc::new(error) })?;
                if commit_record_sequence_number > sequence_number {
                    // a status can only certify a commit the WAL already holds
                    return Err(StatusForUnwrittenCommit {
                        status_sequence_number: commit_record_sequence_number,
                        last_commit_sequence_number: sequence_number,
                    });
                }
                apply_status_record(
                    &mut recovered_commits,
                    &mut recovered_commit_sizes,
                    &mut bytes_read,
                    commit_record_sequence_number,
                    was_committed,
                )?;
            }
            _not_storage_record => {
                // non-storage record types (e.g. statistics) are permitted
                // ONLY as unsequenced records under the same grammar; an
                // unknown type claiming a fresh sequence number would leave
                // that sequence unproved and is refused
                if last_commit_sequence_number != Some(sequence_number) {
                    return Err(UnsequencedRecordWithoutCommit { sequence_number, record_type });
                }
            }
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

    // R-01: the stream must have proven every sequence in load_start..=head;
    // empty is legal only when load_start > head
    if load_start <= head && last_commit_sequence_number != Some(head) {
        return Err(IncompleteCommitStream {
            head,
            last_recovered: last_commit_sequence_number.map_or_else(|| "none".to_owned(), |seq| seq.to_string()),
        });
    }

    Ok(recovered_commits)
}

/// Fold one status record into the recovery state.
///
/// The verdict semantics — identical duplicate converges, opposite verdicts
/// are an order-independent typed quarantine — live in the shared
/// [`status_resolver`](crate::recovery::status_resolver) (R-02), the SAME
/// resolver the live disk-validation path uses, so one raw history can
/// never produce two different outcomes. This function only applies the
/// resolved verdict to the recovery map and its size accounting: a
/// rejection subtracts a commit's bytes exactly once, and nothing panics.
pub(crate) fn apply_status_record(
    recovered_commits: &mut BTreeMap<SequenceNumber, RecoveryCommitStatus>,
    recovered_commit_sizes: &mut BTreeMap<SequenceNumber, usize>,
    bytes_read: &mut usize,
    commit_record_sequence_number: SequenceNumber,
    was_committed: bool,
) -> Result<(), StorageRecoveryError> {
    let existing_verdict = match recovered_commits.get(&commit_record_sequence_number) {
        // a status whose commit data is outside the loaded window: skip, as documented on the loader
        None => return Ok(()),
        Some(RecoveryCommitStatus::Pending(_)) => None,
        Some(RecoveryCommitStatus::Validated(_)) => Some(true),
        Some(RecoveryCommitStatus::Rejected) => Some(false),
    };
    let verdict = fold_status(existing_verdict, was_committed, commit_record_sequence_number).map_err(
        |StatusConflict { sequence_number }| StorageRecoveryError::ConflictingRecoveryStatus { sequence_number },
    )?;
    if existing_verdict == Some(verdict) {
        // an identical replayed status: recovery already converged on this outcome
        return Ok(());
    }
    if verdict {
        let Some(RecoveryCommitStatus::Pending(record)) = recovered_commits.remove(&commit_record_sequence_number)
        else {
            // the match above proved this slot holds Pending when existing_verdict is None
            return Err(StorageRecoveryError::Internal {
                name: Arc::<str>::from("recovery"),
                source: Arc::new(std::io::Error::other("status entry disappeared between lookup and removal")),
            });
        };
        recovered_commits.insert(commit_record_sequence_number, RecoveryCommitStatus::Validated(record));
        trace!("Marked as committed commit @ {}", commit_record_sequence_number);
    } else {
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
    apply_recovered_observing(database_name, recovered_commits, durability_client, keyspaces, &mut |_, _| {})
}

/// R8-P1-02: replay, with an OBSERVER over every batch that is about to be
/// written.
///
/// The restore durability barrier needs to know exactly what replay decided to
/// write, and it cannot derive that from the recovered records alone: a
/// `Pending` commit's write set is produced by `validate_commit`, which may
/// reject it outright, and a `Write::Put` whose `reinsert` flag is false emits
/// nothing at all. A witness computed from the input would therefore be a
/// guess about the engine's commit decision rather than a statement of it.
///
/// So the observer runs at the ONE point where the decision is final and the
/// bytes have not yet been handed to a keyspace. Everything downstream —
/// flush, close, reopen — is then checked against what replay actually
/// resolved to write, which is the "expected semantics versus durable
/// observation" comparison the round-8 audit required in place of the previous
/// observation-versus-observation one.
pub(crate) fn apply_recovered_observing(
    database_name: &str,
    recovered_commits: BTreeMap<SequenceNumber, RecoveryCommitStatus>,
    durability_client: &impl DurabilityClient,
    keyspaces: &Keyspaces,
    observe: &mut dyn FnMut(SequenceNumber, &WriteBatches),
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
                observe(commit_sequence_number, &write_batches);
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
                        observe(commit_sequence_number, &write_batches);
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

#[derive(Debug)]
pub enum RecoveryCommitStatus {
    Pending(CommitRecord),
    Validated(CommitRecord),
    Rejected,
}

#[cfg(test)]
mod strict_parser_tests {
    //! R-01 controls for the fixed-head contiguous parser: one durability
    //! head captured before folding; exactly one valid commit per sequence
    //! in `start..=head`; typed refusals for gap, regression/duplicate,
    //! record-beyond-head, malformed record, unknown type claiming a fresh
    //! sequence, status-before-intent, and early end of stream; empty legal
    //! only when `start > head`. The mutant "drop the final completeness
    //! check" fails the trailing-gap/empty tests; "drop the per-record
    //! contiguity check" fails the gap/regression tests.

    use std::{borrow::Cow, collections::BTreeMap, sync::mpsc};

    use durability::{DurabilityServiceError, RawRecord};

    use super::{RecoveryCommitStatus, StorageRecoveryError, load_commit_data_from};
    use crate::{
        durability_client::{
            DurabilityClient, DurabilityClientError, DurabilityRecord, SequencedDurabilityRecord,
            UnsequencedDurabilityRecord,
        },
        record::{CommitRecord, CommitType, StatusRecord},
        sequence_number::SequenceNumber,
        snapshot::{buffer::OperationsBuffer, snapshot_id::SnapshotId},
    };

    /// A deterministic in-memory durability client: `head` plays the WAL's
    /// recovered end (`previous()`), `records` the raw stream.
    struct MockDurability {
        records: Vec<(u64, u8, Vec<u8>)>,
        head: u64,
    }

    impl MockDurability {
        fn new(head: u64, records: Vec<(u64, u8, Vec<u8>)>) -> Self {
            Self { records, head }
        }
    }

    impl DurabilityClient for MockDurability {
        fn register_record_type<Record: DurabilityRecord>(&mut self) {}

        fn current(&self) -> SequenceNumber {
            SequenceNumber::new(self.head + 1)
        }

        fn previous(&self) -> SequenceNumber {
            SequenceNumber::new(self.head)
        }

        fn sequenced_write<Record: SequencedDurabilityRecord>(
            &self,
            _record: &Record,
        ) -> Result<SequenceNumber, DurabilityClientError> {
            unimplemented!("not needed by the parser under test")
        }

        fn unsequenced_write<Record: UnsequencedDurabilityRecord>(
            &self,
            _record: &Record,
        ) -> Result<(), DurabilityClientError> {
            unimplemented!("not needed by the parser under test")
        }

        fn request_sync(&self) -> mpsc::Receiver<Result<(), DurabilityServiceError>> {
            unimplemented!("not needed by the parser under test")
        }

        fn iter_from(
            &self,
            sequence_number: SequenceNumber,
        ) -> Result<impl Iterator<Item = Result<RawRecord<'static>, DurabilityClientError>>, DurabilityClientError>
        {
            let start = sequence_number.number();
            Ok(self
                .records
                .iter()
                .filter(move |(seq, _, _)| *seq >= start)
                .cloned()
                .map(|(seq, record_type, bytes)| {
                    Ok(RawRecord { sequence_number: SequenceNumber::new(seq), record_type, bytes: Cow::Owned(bytes) })
                })
                .collect::<Vec<_>>()
                .into_iter())
        }

        fn iter_type_from<Record: DurabilityRecord>(
            &self,
            sequence_number: SequenceNumber,
        ) -> Result<impl Iterator<Item = Result<(SequenceNumber, Record), DurabilityClientError>>, DurabilityClientError>
        {
            let start = sequence_number.number();
            Ok(self
                .records
                .iter()
                .filter(move |(seq, record_type, _)| *seq >= start && *record_type == Record::RECORD_TYPE)
                .map(|(seq, _, bytes)| {
                    Record::deserialise_from(&mut &**bytes)
                        .map(|record| (SequenceNumber::new(*seq), record))
                        .map_err(DurabilityClientError::from)
                })
                .collect::<Vec<_>>()
                .into_iter())
        }

        fn find_last_unsequenced_type<Record: UnsequencedDurabilityRecord>(
            &self,
        ) -> Result<Option<Record>, DurabilityClientError> {
            unimplemented!("not needed by the parser under test")
        }

        fn truncate_from(&self, _sequence_number: SequenceNumber) -> Result<(), DurabilityClientError> {
            unimplemented!("not needed by the parser under test")
        }

        fn delete_durability(self) -> Result<(), DurabilityClientError> {
            unimplemented!("not needed by the parser under test")
        }

        fn reset(&mut self) -> Result<(), DurabilityClientError> {
            unimplemented!("not needed by the parser under test")
        }
    }

    fn commit_bytes() -> Vec<u8> {
        let record =
            CommitRecord::new(OperationsBuffer::new(), SequenceNumber::MIN, CommitType::Data, SnapshotId::new());
        let mut bytes = Vec::new();
        record.serialise_into(&mut bytes).unwrap();
        bytes
    }

    fn commit(seq: u64) -> (u64, u8, Vec<u8>) {
        (seq, CommitRecord::RECORD_TYPE, commit_bytes())
    }

    fn status(own_seq: u64, certifies: u64, was_committed: bool) -> (u64, u8, Vec<u8>) {
        let record = StatusRecord::new(SequenceNumber::new(certifies), was_committed);
        let mut bytes = Vec::new();
        record.serialise_into(&mut bytes).unwrap();
        (own_seq, StatusRecord::RECORD_TYPE, bytes)
    }

    fn load(client: &MockDurability) -> Result<BTreeMap<SequenceNumber, RecoveryCommitStatus>, StorageRecoveryError> {
        load_commit_data_from(SequenceNumber::new(1), client)
    }

    fn shape(map: &BTreeMap<SequenceNumber, RecoveryCommitStatus>) -> Vec<(u64, &'static str)> {
        map.iter()
            .map(|(seq, state)| {
                let tag = match state {
                    RecoveryCommitStatus::Pending(_) => "pending",
                    RecoveryCommitStatus::Validated(_) => "validated",
                    RecoveryCommitStatus::Rejected => "rejected",
                };
                (seq.number(), tag)
            })
            .collect()
    }

    #[test]
    fn a_contiguous_prefix_with_statuses_parses_completely() {
        let client = MockDurability::new(
            3,
            vec![commit(1), status(1, 1, true), commit(2), commit(3), status(3, 2, false), status(3, 3, true)],
        );
        let map = load(&client).expect("a contiguous proven prefix must parse");
        assert_eq!(shape(&map), &[(1, "validated"), (2, "rejected"), (3, "validated")]);
    }

    #[test]
    fn empty_is_legal_exactly_when_start_exceeds_the_head() {
        // fresh WAL: head 0 < start 1 -> empty is the proven answer
        let empty = MockDurability::new(0, vec![]);
        assert!(load(&empty).expect("empty stream with start > head is legal").is_empty());

        // head 2 promises records but the stream is empty -> typed refusal
        let hollow = MockDurability::new(2, vec![]);
        let error = load(&hollow).expect_err("empty stream while records are expected must refuse");
        assert!(
            matches!(error, StorageRecoveryError::IncompleteCommitStream { .. }),
            "expected IncompleteCommitStream, got {error:?}"
        );
    }

    #[test]
    fn an_internal_gap_is_a_typed_refusal() {
        let client = MockDurability::new(3, vec![commit(1), commit(3)]);
        let error = load(&client).expect_err("an internal gap must refuse");
        assert!(
            matches!(
                error,
                StorageRecoveryError::CommitRecordGap { expected, found }
                    if expected == SequenceNumber::new(2) && found == SequenceNumber::new(3)
            ),
            "expected CommitRecordGap, got {error:?}"
        );
    }

    #[test]
    fn a_trailing_gap_is_a_typed_refusal() {
        let client = MockDurability::new(4, vec![commit(1), commit(2)]);
        let error = load(&client).expect_err("a stream ending before the head must refuse");
        assert!(
            matches!(error, StorageRecoveryError::IncompleteCommitStream { head, .. } if head == SequenceNumber::new(4)),
            "expected IncompleteCommitStream, got {error:?}"
        );
    }

    #[test]
    fn a_missing_first_record_is_a_typed_refusal() {
        let client = MockDurability::new(2, vec![commit(2)]);
        let error = load(&client).expect_err("a stream starting past the load start must refuse");
        assert!(
            matches!(error, StorageRecoveryError::DurabilityRecordsMissing { .. }),
            "expected DurabilityRecordsMissing, got {error:?}"
        );
    }

    #[test]
    fn a_duplicate_commit_record_is_a_typed_refusal_not_a_silent_overwrite() {
        // identical or conflicting payload makes no difference: exactly one
        // commit record may establish a sequence number
        let client = MockDurability::new(2, vec![commit(1), commit(2), commit(2)]);
        let error = load(&client).expect_err("a duplicate commit record must refuse");
        assert!(
            matches!(error, StorageRecoveryError::CommitRecordRegression { .. }),
            "expected CommitRecordRegression, got {error:?}"
        );
    }

    #[test]
    fn a_record_beyond_the_captured_head_is_a_typed_refusal() {
        let client = MockDurability::new(2, vec![commit(1), commit(2), commit(3)]);
        let error = load(&client).expect_err("a record beyond the fixed head must refuse");
        assert!(
            matches!(
                error,
                StorageRecoveryError::RecordBeyondDurabilityHead { sequence_number, head }
                    if sequence_number == SequenceNumber::new(3) && head == SequenceNumber::new(2)
            ),
            "expected RecordBeyondDurabilityHead, got {error:?}"
        );
    }

    #[test]
    fn a_malformed_commit_record_is_a_typed_refusal() {
        let client = MockDurability::new(1, vec![(1, CommitRecord::RECORD_TYPE, vec![0xFF, 0x00, 0xFF])]);
        let error = load(&client).expect_err("a malformed commit record must refuse");
        assert!(
            matches!(error, StorageRecoveryError::DurabilityRecordDeserialize { .. }),
            "expected DurabilityRecordDeserialize, got {error:?}"
        );
    }

    #[test]
    fn an_unknown_type_claiming_a_fresh_sequence_is_refused_but_a_proper_unsequenced_one_passes() {
        const STATISTICS_LIKE: u8 = 10;
        // permitted: the unknown record repeats the last commit's sequence
        let ok = MockDurability::new(2, vec![commit(1), (1, STATISTICS_LIKE, vec![1, 2, 3]), commit(2)]);
        assert_eq!(shape(&load(&ok).expect("a proper unsequenced non-storage record is permitted")).len(), 2);

        // refused: the unknown record claims the NEXT (unproved) sequence
        let bad = MockDurability::new(2, vec![commit(1), (2, STATISTICS_LIKE, vec![1, 2, 3])]);
        let error = load(&bad).expect_err("an unknown type claiming a fresh sequence must refuse");
        assert!(
            matches!(
                error,
                StorageRecoveryError::UnsequencedRecordWithoutCommit { sequence_number, record_type }
                    if sequence_number == SequenceNumber::new(2) && record_type == STATISTICS_LIKE
            ),
            "expected UnsequencedRecordWithoutCommit, got {error:?}"
        );
    }

    #[test]
    fn a_status_certifying_an_unwritten_commit_is_a_typed_refusal() {
        let client = MockDurability::new(1, vec![commit(1), status(1, 2, true)]);
        let error = load(&client).expect_err("a verdict cannot precede its commit");
        assert!(
            matches!(error, StorageRecoveryError::StatusForUnwrittenCommit { .. }),
            "expected StatusForUnwrittenCommit, got {error:?}"
        );
    }

    #[test]
    fn conflicting_duplicate_statuses_quarantine_through_the_shared_resolver() {
        let client = MockDurability::new(1, vec![commit(1), status(1, 1, true), status(1, 1, false)]);
        let error = load(&client).expect_err("opposite verdicts must quarantine");
        assert!(
            matches!(error, StorageRecoveryError::ConflictingRecoveryStatus { sequence_number } if sequence_number == SequenceNumber::new(1)),
            "expected ConflictingRecoveryStatus, got {error:?}"
        );
    }
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
        CommitRecordGap(
            8,
            "Quarantined WAL: expected a commit record for sequence number '{expected}' but found '{found}'. The durability log has an internal gap; refusing to recover an unproved prefix.",
            expected: SequenceNumber, found: SequenceNumber
        ),
        CommitRecordRegression(
            9,
            "Quarantined WAL: expected a commit record for sequence number '{expected}' but found a duplicate or regressed record at '{found}'. Exactly one commit record may exist per sequence number; refusing.",
            expected: SequenceNumber, found: SequenceNumber
        ),
        IncompleteCommitStream(
            10,
            "Quarantined WAL: the durability head is '{head}' but the record stream ended at '{last_recovered}'. Records the WAL proved durable are missing; refusing to recover a truncated prefix.",
            head: SequenceNumber, last_recovered: String
        ),
        UnsequencedRecordWithoutCommit(
            11,
            "Quarantined WAL: a record of type '{record_type}' claims sequence number '{sequence_number}' which no commit record has established. Refusing to skip an unproved sequence.",
            sequence_number: SequenceNumber, record_type: u8
        ),
        StatusForUnwrittenCommit(
            12,
            "Quarantined WAL: a status record certifies commit '{status_sequence_number}' but the log has only reached '{last_commit_sequence_number}'. A verdict cannot precede its commit; refusing.",
            status_sequence_number: SequenceNumber, last_commit_sequence_number: SequenceNumber
        ),
        RecordBeyondDurabilityHead(
            13,
            "Quarantined WAL: a record carries sequence number '{sequence_number}' beyond the recovered durability head '{head}'. The log and its recovered end disagree; refusing.",
            sequence_number: SequenceNumber, head: SequenceNumber
        ),
    }
}
