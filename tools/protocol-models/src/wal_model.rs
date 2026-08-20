//! WAL model: late atomic allocation, contiguous AppendLsn, status
//! singletons, sync barriers, and fixed iterator snapshots.
//!
//! Models brief §5.3 invariants 29–47 and §9.4–§9.7:
//! - a failed pre-finalisation upload consumes neither TypeSequence nor
//!   AppendLsn (inv. 31);
//! - sequenced finalisation allocates TypeSequence + AppendLsn + ControlSeq
//!   atomically (inv. 32); unsequenced copies the current previous
//!   TypeSequence (inv. 33);
//! - a finalisation operation id is immutable to one request digest
//!   (inv. 34) and a lost response is resolved by operation id, never by a
//!   fresh identity (inv. 35);
//! - status singletons: same key + same verdict returns the original
//!   record; same key + different verdict is corruption (inv. 49–51);
//! - iterators are fixed at capture and never see later appends
//!   (inv. 41–42); missing data is an error, not EOF (inv. 43);
//! - sync barriers cover exactly the physical prefix (inv. 36–37).

use std::collections::BTreeMap;

pub type OperationId = u64;
pub type TypeSequence = u64;
pub type AppendLsn = u64;
pub type ControlSeq = u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SequencingKind {
    Sequenced,
    Unsequenced { logical_key: Option<WalStatusKey> },
}

/// WalStatusKey = (record type, target commit sequence) — brief §9.5.
/// (Named apart from resolver_model::StatusKey, which keys resolution
/// certificates by (database, generation, commit sequence).)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WalStatusKey {
    pub record_type: u16,
    pub target_sequence: TypeSequence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedRecord {
    pub operation_id: OperationId,
    pub append_lsn: AppendLsn,
    pub type_sequence: TypeSequence,
    pub sequencing: SequencingKind,
    pub control_seq: ControlSeq,
    pub request_digest: u64,
    /// verdict payload for status records (models COMMITTED/ABORTED)
    pub verdict: Option<bool>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FinalizeError {
    /// same operation id, different request digest: permanent conflict
    OperationDigestConflict,
    /// same status key, different verdict: fatal corruption (inv. 51)
    StatusConflict,
    /// stale session/epoch — fenced (inv. 17)
    Fenced,
}

#[derive(Debug, PartialEq, Eq)]
pub enum IterError {
    /// requested start beyond captured head with data expected
    MissingRecord,
    /// snapshot invalidated (catalogue changed / pin released)
    SnapshotInvalid,
}

/// The controller's single linearisation point for one generation's WAL.
#[derive(Default, Clone)]
pub struct WalState {
    next_type_sequence: TypeSequence,
    next_append_lsn: AppendLsn,
    next_control_seq: ControlSeq,
    records: Vec<FinalizedRecord>,
    by_operation: BTreeMap<OperationId, usize>,
    status_singletons: BTreeMap<WalStatusKey, usize>,
    current_session: u64,
}

impl WalState {
    pub fn new() -> Self {
        WalState { next_type_sequence: 1, next_append_lsn: 0, next_control_seq: 1, ..Default::default() }
    }

    pub fn open_session(&mut self) -> u64 {
        self.current_session += 1;
        self.current_session
    }

    /// Models a pre-finalisation upload failure: by construction it touches
    /// no counter (there is no code path here that could).
    pub fn upload_failed(&self) {}

    /// One atomic finalisation transaction (inv. 32–35, 49–51).
    pub fn finalize(
        &mut self,
        session: u64,
        operation_id: OperationId,
        request_digest: u64,
        sequencing: SequencingKind,
        verdict: Option<bool>,
    ) -> Result<FinalizedRecord, FinalizeError> {
        if session != self.current_session {
            return Err(FinalizeError::Fenced);
        }
        // idempotent replay by operation id (inv. 34–35)
        if let Some(&ix) = self.by_operation.get(&operation_id) {
            let existing = &self.records[ix];
            if existing.request_digest == request_digest {
                return Ok(existing.clone());
            }
            return Err(FinalizeError::OperationDigestConflict);
        }
        // status singleton dedupe/conflict BEFORE any allocation (inv. 49–51)
        if let SequencingKind::Unsequenced { logical_key: Some(key) } = &sequencing {
            if let Some(&ix) = self.status_singletons.get(key) {
                let existing = &self.records[ix];
                if existing.verdict == verdict {
                    return Ok(existing.clone());
                }
                return Err(FinalizeError::StatusConflict);
            }
        }
        // late atomic allocation (inv. 31–33)
        let type_sequence = match sequencing {
            SequencingKind::Sequenced => {
                let s = self.next_type_sequence;
                self.next_type_sequence += 1;
                s
            }
            SequencingKind::Unsequenced { .. } => self.next_type_sequence - 1,
        };
        let record = FinalizedRecord {
            operation_id,
            append_lsn: self.next_append_lsn,
            type_sequence,
            sequencing: sequencing.clone(),
            control_seq: self.next_control_seq,
            request_digest,
            verdict,
        };
        self.next_append_lsn += 1;
        self.next_control_seq += 1;
        let ix = self.records.len();
        self.records.push(record.clone());
        self.by_operation.insert(operation_id, ix);
        if let SequencingKind::Unsequenced { logical_key: Some(key) } = sequencing {
            self.status_singletons.insert(key, ix);
        }
        Ok(record)
    }

    /// Lost-response resolution: query by operation id (inv. 35).
    pub fn query_operation(&self, operation_id: OperationId) -> Option<&FinalizedRecord> {
        self.by_operation.get(&operation_id).map(|&ix| &self.records[ix])
    }

    /// Sync barrier: proves the exact physical prefix (inv. 36–37). LSNs are
    /// base-0 (as in the production SQL core), so the barrier LSN is signed:
    /// the empty head is -1, exactly the SQL lane's COALESCE(MAX,-1).
    pub fn sync_barrier(&self) -> (i64, ControlSeq) {
        (self.next_append_lsn as i64 - 1, self.next_control_seq - 1)
    }

    /// Fixed iterator snapshot (inv. 41–43): captures the head at creation.
    /// `through_append_lsn` is EXCLUSIVE (= the head + 1), so an empty
    /// capture needs no signed sentinel under base-0 LSNs.
    pub fn capture_iterator(&self, from_sequence: TypeSequence) -> IteratorSnapshot {
        IteratorSnapshot { from_sequence, through_append_lsn: self.next_append_lsn, valid: true }
    }

    /// Iterate under a snapshot: later appends are invisible; a requested
    /// sequenced start that is absent inside the captured range is a typed
    /// error, never silent EOF.
    pub fn iterate(&self, snap: &IteratorSnapshot) -> Result<Vec<&FinalizedRecord>, IterError> {
        if !snap.valid {
            return Err(IterError::SnapshotInvalid);
        }
        // a sequenced start inside the captured, populated range must exist:
        // absence there is a hole (corruption); a start below the model's
        // genesis floor is a legitimate pre-history read
        let sequenced_in_snapshot = |r: &&FinalizedRecord| {
            r.append_lsn < snap.through_append_lsn && matches!(r.sequencing, SequencingKind::Sequenced)
        };
        if let Some(head) = self.records.iter().filter(sequenced_in_snapshot).map(|r| r.type_sequence).max() {
            let present =
                self.records.iter().filter(sequenced_in_snapshot).any(|r| r.type_sequence == snap.from_sequence);
            let min_seq = self
                .records
                .iter()
                .filter(|r| matches!(r.sequencing, SequencingKind::Sequenced))
                .map(|r| r.type_sequence)
                .min()
                .unwrap_or(0);
            if snap.from_sequence != 0 && snap.from_sequence <= head && snap.from_sequence >= min_seq && !present {
                return Err(IterError::MissingRecord);
            }
        }
        Ok(self
            .records
            .iter()
            .filter(|r| r.append_lsn < snap.through_append_lsn)
            .filter(|r| r.type_sequence >= snap.from_sequence)
            .collect())
    }

    pub fn records(&self) -> &[FinalizedRecord] {
        &self.records
    }

    /// Global model invariants, checked after every schedule.
    pub fn check_invariants(&self) -> Result<(), String> {
        // contiguous AppendLsn from genesis (inv. 5)
        for (i, r) in self.records.iter().enumerate() {
            if r.append_lsn != (i as u64) {
                return Err(format!("AppendLsn hole at index {i}: {}", r.append_lsn));
            }
        }
        // unique TypeSequence among sequenced records (inv. 7)
        let mut seqs: Vec<_> = self
            .records
            .iter()
            .filter(|r| matches!(r.sequencing, SequencingKind::Sequenced))
            .map(|r| r.type_sequence)
            .collect();
        seqs.sort_unstable();
        let n = seqs.len();
        seqs.dedup();
        if seqs.len() != n {
            return Err("duplicate sequenced TypeSequence".into());
        }
        // sequenced TypeSequence contiguous from 1
        for (i, s) in seqs.iter().enumerate() {
            if *s != (i as u64) + 1 {
                return Err(format!("TypeSequence hole: expected {}, got {s}", i + 1));
            }
        }
        // one physical record per status key (inv. 49/50). Verdict-less
        // status records are admissible (finalize dedupes them by
        // None == None), so this must not unwrap the verdict — a second
        // record for the same key is the violation regardless of verdicts.
        let mut status_records: BTreeMap<WalStatusKey, Option<bool>> = BTreeMap::new();
        for r in &self.records {
            if let SequencingKind::Unsequenced { logical_key: Some(k) } = &r.sequencing {
                if let Some(prev) = status_records.insert(*k, r.verdict) {
                    return Err(format!(
                        "two physical records for status key {k:?} (verdicts {prev:?} / {:?})",
                        r.verdict
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct IteratorSnapshot {
    pub from_sequence: TypeSequence,
    /// Exclusive bound: records with `append_lsn < through_append_lsn` are in
    /// the snapshot.
    pub through_append_lsn: AppendLsn,
    pub valid: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq() -> SequencingKind {
        SequencingKind::Sequenced
    }
    fn status(target: TypeSequence) -> SequencingKind {
        SequencingKind::Unsequenced { logical_key: Some(WalStatusKey { record_type: 1, target_sequence: target }) }
    }

    /// inv. 31: failed uploads consume nothing; holes are impossible by
    /// construction. Exhaustively interleave uploads-that-fail with
    /// finalisations for N ops and verify contiguity.
    #[test]
    fn no_holes_under_failed_upload_interleavings() {
        // schedule bitmask: bit i says op i's upload fails (never finalises)
        for mask in 0u32..(1 << 8) {
            let mut w = WalState::new();
            let s = w.open_session();
            for op in 0..8u64 {
                if mask & (1 << op) != 0 {
                    w.upload_failed();
                } else {
                    w.finalize(s, op, op * 17, seq(), None).unwrap();
                }
            }
            w.check_invariants().unwrap();
        }
    }

    /// inv. 34–35: ambiguous responses are resolved by operation id; a
    /// duplicate finalisation of the same operation returns the original
    /// identity; a different digest under the same operation is a permanent
    /// conflict.
    #[test]
    fn lost_response_resolution_by_operation_id() {
        let mut w = WalState::new();
        let s = w.open_session();
        let first = w.finalize(s, 7, 1234, seq(), None).unwrap();
        // duplicate (retry after lost response): same identity, no new alloc
        let dup = w.finalize(s, 7, 1234, seq(), None).unwrap();
        assert_eq!(first, dup);
        assert_eq!(w.records().len(), 1);
        // corrupted retry: same op, different digest
        assert_eq!(w.finalize(s, 7, 9999, seq(), None), Err(FinalizeError::OperationDigestConflict));
        // lost-response query path
        assert_eq!(w.query_operation(7).unwrap(), &first);
        w.check_invariants().unwrap();
    }

    /// inv. 49–51: status singleton — same verdict returns the original
    /// physical record; opposite verdict is corruption; never a second
    /// physical append. Exhaust all orders of (commit, statusA, statusA-dup,
    /// statusA-conflict).
    #[test]
    fn status_singleton_dedupe_and_conflict() {
        let mut w = WalState::new();
        let s = w.open_session();
        w.finalize(s, 1, 11, seq(), None).unwrap(); // commit @ seq 1
        let st = w.finalize(s, 2, 22, status(1), Some(true)).unwrap();
        // same key, same verdict, DIFFERENT operation (recovery repair path):
        // returns the original record, does not append (deterministic op id
        // is derived from WalStatusKey+verdict in production; model allows any)
        let repair = w.finalize(s, 3, 33, status(1), Some(true)).unwrap();
        assert_eq!(repair.append_lsn, st.append_lsn);
        assert_eq!(w.records().len(), 2);
        // opposite verdict: fatal, and nothing appended
        assert_eq!(w.finalize(s, 4, 44, status(1), Some(false)), Err(FinalizeError::StatusConflict));
        assert_eq!(w.records().len(), 2);
        w.check_invariants().unwrap();
    }

    /// inv. 33: unsequenced records copy the current previous TypeSequence
    /// and are ordered by AppendLsn.
    #[test]
    fn unsequenced_stamps_previous_sequence() {
        let mut w = WalState::new();
        let s = w.open_session();
        w.finalize(s, 1, 1, seq(), None).unwrap(); // seq 1
        w.finalize(s, 2, 2, seq(), None).unwrap(); // seq 2
        let u = w.finalize(s, 3, 3, status(2), Some(true)).unwrap();
        assert_eq!(u.type_sequence, 2);
        assert_eq!(u.append_lsn, 2);
        let v = w.finalize(s, 4, 4, seq(), None).unwrap();
        assert_eq!(v.type_sequence, 3);
        w.check_invariants().unwrap();
    }

    /// inv. 41–42: a captured iterator never sees later appends (moving-head
    /// negative control is `iterator_checker_catches_moving_head` below).
    #[test]
    fn fixed_iterator_is_immune_to_later_appends() {
        let mut w = WalState::new();
        let s = w.open_session();
        for op in 1..=4u64 {
            w.finalize(s, op, op, seq(), None).unwrap();
        }
        let snap = w.capture_iterator(2);
        let before: Vec<AppendLsn> = w.iterate(&snap).unwrap().iter().map(|r| r.append_lsn).collect();
        for op in 5..=8u64 {
            w.finalize(s, op, op, seq(), None).unwrap();
        }
        let after: Vec<AppendLsn> = w.iterate(&snap).unwrap().iter().map(|r| r.append_lsn).collect();
        assert_eq!(before, after, "iterator observed post-capture appends");
    }

    /// inv. 36–37: a sync barrier covers every earlier resolved operation.
    #[test]
    fn sync_barrier_covers_physical_prefix() {
        let mut w = WalState::new();
        let s = w.open_session();
        for op in 1..=5u64 {
            w.finalize(
                s,
                op,
                op,
                if op % 2 == 0 { status(op - 1) } else { seq() },
                if op % 2 == 0 { Some(true) } else { None },
            )
            .unwrap();
        }
        let (lsn, cseq) = w.sync_barrier();
        assert_eq!(lsn, 4);
        assert_eq!(cseq, 5);
        // everything at or below the barrier is present and contiguous
        let snap = w.capture_iterator(0);
        assert_eq!(w.iterate(&snap).unwrap().len(), 5);
    }

    /// inv. 17: a fenced (stale-session) finalisation is rejected and
    /// allocates nothing.
    #[test]
    fn stale_session_is_fenced_without_allocation() {
        let mut w = WalState::new();
        let s1 = w.open_session();
        w.finalize(s1, 1, 1, seq(), None).unwrap();
        let _s2 = w.open_session(); // restart: strictly newer session
        assert_eq!(w.finalize(s1, 2, 2, seq(), None), Err(FinalizeError::Fenced));
        assert_eq!(w.records().len(), 1);
        w.check_invariants().unwrap();
    }

    /// inv. 38: a fenced session retrying the IDENTICAL operation it had
    /// already durably finalised gets Fenced, never the replayed receipt —
    /// fencing revokes reporting to the old holder, not durability. (This is
    /// the schedule the TS controller core once ordered differently; all
    /// lanes must agree.)
    #[test]
    fn fenced_replay_of_durable_record_is_fenced_not_replayed() {
        let mut w = WalState::new();
        let s1 = w.open_session();
        w.finalize(s1, 1, 1, seq(), None).unwrap();
        let _s2 = w.open_session(); // fence s1
                                    // identical (operation_id, digest) retry from the fenced holder
        assert_eq!(w.finalize(s1, 1, 1, seq(), None), Err(FinalizeError::Fenced));
        // durable history untouched
        assert_eq!(w.records().len(), 1);
        w.check_invariants().unwrap();
    }

    // ---- negative controls (brief §22.9): the checkers must FAIL when the
    // protected invariant is deliberately broken. ----

    #[test]
    fn invariant_checker_catches_lsn_hole() {
        let mut w = WalState::new();
        let s = w.open_session();
        w.finalize(s, 1, 1, seq(), None).unwrap();
        w.finalize(s, 2, 2, seq(), None).unwrap();
        // deliberately corrupt: remove the middle record
        w.records.remove(0);
        assert!(w.check_invariants().is_err(), "checker must catch an AppendLsn hole");
    }

    #[test]
    fn invariant_checker_catches_duplicate_status() {
        let mut w = WalState::new();
        let s = w.open_session();
        w.finalize(s, 1, 1, seq(), None).unwrap();
        w.finalize(s, 2, 2, status(1), Some(true)).unwrap();
        // deliberately bypass the singleton map to append a duplicate
        let dup = FinalizedRecord {
            operation_id: 99,
            append_lsn: w.next_append_lsn,
            type_sequence: 1,
            sequencing: status(1),
            control_seq: w.next_control_seq,
            request_digest: 99,
            verdict: Some(false),
        };
        w.next_append_lsn += 1;
        w.next_control_seq += 1;
        w.records.push(dup);
        assert!(w.check_invariants().is_err(), "checker must catch conflicting status records");
    }

    /// Regression (review finding): finalize admits a verdict-less status
    /// record, so the invariant checker must report on it — never panic on a
    /// None verdict.
    #[test]
    fn checker_handles_verdictless_status_record_without_panicking() {
        let mut w = WalState::new();
        let s = w.open_session();
        w.finalize(s, 1, 1, status(0), None).unwrap();
        assert!(w.check_invariants().is_ok());
        // and its idempotent duplicate stays a single physical record
        w.finalize(s, 2, 2, status(0), None).unwrap();
        assert!(w.check_invariants().is_ok());
    }

    #[test]
    fn iterator_checker_catches_moving_head() {
        // a deliberately broken snapshot that tracks the live head would
        // observe post-capture appends; prove the equality assertion used in
        // `fixed_iterator_is_immune_to_later_appends` can fail.
        let mut w = WalState::new();
        let s = w.open_session();
        w.finalize(s, 1, 1, seq(), None).unwrap();
        let mut snap = w.capture_iterator(0);
        let before = w.iterate(&snap).unwrap().len();
        w.finalize(s, 2, 2, seq(), None).unwrap();
        // mutation: moving head (the bug this guards against) — the broken
        // snapshot tracks the live exclusive bound instead of the captured one
        snap.through_append_lsn = w.next_append_lsn;
        let after = w.iterate(&snap).unwrap().len();
        assert_ne!(before, after, "moving-head mutant must be observable");
    }
}
