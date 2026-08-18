/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! R-02: ONE pure resolver for commit-status history semantics.
//!
//! The same raw status history reaches storage through two doors — live
//! disk validation ([`crate::isolation_manager::IsolationManager::iterate_commit_status_from_disk`])
//! and startup recovery ([`crate::recovery::commit_recovery`]) — and both
//! MUST produce identical verdicts. Before this module, live validation did
//! last-write-wins `HashMap::insert` while recovery quarantined opposite
//! duplicates: one corrupt WAL produced two different databases depending on
//! which path read it first.
//!
//! The rules, in one place:
//! - an IDENTICAL duplicate status converges (recovery re-persists statuses,
//!   so replays after a crash are legitimate);
//! - OPPOSITE verdicts for one commit can never both have been decided, so
//!   the pairing is corruption: a typed [`StatusConflict`], identical in
//!   either order — never last-write-wins, never a panic;
//! - a commit with NO status record is not resolved here: the caller must
//!   either recompute the verdict deterministically (recovery re-validates
//!   pending commits against the proven prefix) or refuse with a typed
//!   error where recomputation is impossible (live validation of an evicted
//!   predecessor).

use std::collections::HashMap;

use crate::sequence_number::SequenceNumber;

/// One commit carries both a committed and a rejected status record.
/// Order-independent by construction: the fold refuses on the second
/// (opposite) verdict regardless of which arrived first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusConflict {
    pub sequence_number: SequenceNumber,
}

/// Fold one status record into a commit's existing verdict slot.
/// `None` existing verdict adopts the incoming one; an identical duplicate
/// converges; opposite verdicts are a typed conflict.
pub fn fold_status(
    existing: Option<bool>,
    incoming_was_committed: bool,
    sequence_number: SequenceNumber,
) -> Result<bool, StatusConflict> {
    match existing {
        None => Ok(incoming_was_committed),
        Some(previous) if previous == incoming_was_committed => Ok(previous),
        Some(_) => Err(StatusConflict { sequence_number }),
    }
}

/// Resolve a raw status-record history into per-commit verdicts
/// (`true` = committed, `false` = rejected). Duplicate-identical converges;
/// duplicate-opposite is the same typed conflict in either order.
pub fn resolve_status_history(
    statuses: impl IntoIterator<Item = (SequenceNumber, bool)>,
) -> Result<HashMap<SequenceNumber, bool>, StatusConflict> {
    let mut verdicts = HashMap::new();
    for (sequence_number, was_committed) in statuses {
        let verdict = fold_status(verdicts.get(&sequence_number).copied(), was_committed, sequence_number)?;
        verdicts.insert(sequence_number, verdict);
    }
    Ok(verdicts)
}

#[cfg(test)]
mod tests {
    //! R-02 controls: the resolver itself, plus the cross-path equivalence
    //! proof — one synthetic history pushed through BOTH the live-validation
    //! fold ([`resolve_status_history`]) and the recovery fold
    //! ([`crate::recovery::commit_recovery`]'s status handler) must produce
    //! byte-identical per-commit verdicts, including reversed-order
    //! duplicates, and the identical typed quarantine for conflicts.

    use std::collections::BTreeMap;

    use super::{StatusConflict, fold_status, resolve_status_history};
    use crate::{
        record::{CommitRecord, CommitType},
        recovery::commit_recovery::{RecoveryCommitStatus, StorageRecoveryError, apply_status_record},
        sequence_number::SequenceNumber,
        snapshot::{buffer::OperationsBuffer, snapshot_id::SnapshotId},
    };

    fn seq(number: u64) -> SequenceNumber {
        SequenceNumber::new(number)
    }

    #[test]
    fn fold_adopts_converges_and_conflicts() {
        assert_eq!(fold_status(None, true, seq(1)), Ok(true));
        assert_eq!(fold_status(None, false, seq(1)), Ok(false));
        assert_eq!(fold_status(Some(true), true, seq(1)), Ok(true));
        assert_eq!(fold_status(Some(false), false, seq(1)), Ok(false));
        let conflict = StatusConflict { sequence_number: seq(1) };
        assert_eq!(fold_status(Some(true), false, seq(1)), Err(conflict.clone()));
        assert_eq!(fold_status(Some(false), true, seq(1)), Err(conflict), "order-independent conflict");
    }

    /// Run one status history through the RECOVERY fold and return per-seq
    /// verdicts (or the conflict's sequence number).
    fn through_recovery(commit_seqs: &[u64], history: &[(u64, bool)]) -> Result<BTreeMap<u64, bool>, u64> {
        let mut commits = BTreeMap::new();
        let mut sizes = BTreeMap::new();
        for &number in commit_seqs {
            let record =
                CommitRecord::new(OperationsBuffer::new(), SequenceNumber::MIN, CommitType::Data, SnapshotId::new());
            commits.insert(seq(number), RecoveryCommitStatus::Pending(record));
            sizes.insert(seq(number), 10usize);
        }
        let mut bytes_read = 10 * commit_seqs.len();
        for &(number, was_committed) in history {
            apply_status_record(&mut commits, &mut sizes, &mut bytes_read, seq(number), was_committed).map_err(
                |error| match error {
                    StorageRecoveryError::ConflictingRecoveryStatus { sequence_number, .. } => sequence_number.number(),
                    other => panic!("unexpected recovery error: {other:?}"),
                },
            )?;
        }
        Ok(commits
            .iter()
            .filter_map(|(sequence_number, status)| match status {
                RecoveryCommitStatus::Validated(_) => Some((sequence_number.number(), true)),
                RecoveryCommitStatus::Rejected => Some((sequence_number.number(), false)),
                RecoveryCommitStatus::Pending(_) => None,
            })
            .collect())
    }

    /// Run the same history through the LIVE-validation fold.
    fn through_live(commit_seqs: &[u64], history: &[(u64, bool)]) -> Result<BTreeMap<u64, bool>, u64> {
        let resolved = resolve_status_history(history.iter().map(|&(number, verdict)| (seq(number), verdict)))
            .map_err(|conflict| conflict.sequence_number.number())?;
        // live validation only consults statuses for commits it loaded
        Ok(commit_seqs
            .iter()
            .filter_map(|&number| resolved.get(&seq(number)).map(|&verdict| (number, verdict)))
            .collect())
    }

    #[test]
    fn both_paths_produce_byte_identical_verdicts_for_one_history() {
        let commits = &[1u64, 2, 3, 4];
        let histories: &[&[(u64, bool)]] = &[
            &[(1, true), (2, false), (3, true)],
            // identical duplicates, interleaved
            &[(1, true), (2, false), (1, true), (3, true), (2, false)],
            // duplicates in reversed order relative to the line above
            &[(2, false), (3, true), (1, true), (2, false), (1, true)],
            // status for a commit outside the loaded window is ignored by
            // both paths' verdict view over the loaded commits
            &[(42, true), (1, false)],
            &[],
        ];
        for history in histories {
            let recovery = through_recovery(commits, history);
            let live = through_live(commits, history);
            assert_eq!(
                format!("{recovery:?}"),
                format!("{live:?}"),
                "recovery and live validation diverged on history {history:?}"
            );
        }
    }

    #[test]
    fn both_paths_produce_the_identical_typed_conflict_in_either_order() {
        let commits = &[1u64, 2];
        for history in [&[(1u64, true), (2, true), (1, false)][..], &[(1, false), (2, true), (1, true)][..]] {
            let recovery = through_recovery(commits, history).expect_err("opposite verdicts must conflict");
            let live = through_live(commits, history).expect_err("opposite verdicts must conflict");
            assert_eq!(recovery, 1, "the conflict names the corrupt commit");
            assert_eq!(recovery, live, "both paths must quarantine the same commit, in either order");
        }
    }
}
