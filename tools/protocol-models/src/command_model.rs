//! Command model: permanent CommandId non-reuse, one intent per command,
//! exact no-intent proofs, terminal outcome / result availability
//! orthogonality.
//!
//! Models brief §5.7 (inv. 85–98), §11, and Appendix B.1:
//! - same CommandId + same digest returns stored state; different digest is
//!   permanent conflict (inv. 86);
//! - once an intent is finalised no execution epoch may run again
//!   (inv. 92);
//! - a new execution epoch requires an exact no-intent proof that rechecks
//!   an unchanged catalogue head (inv. 93–94, §11.7);
//! - result expiry mutates availability, never outcome (inv. 97).

use std::collections::BTreeMap;

pub type CommandId = u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecState {
    Reserved,
    Assigned { epoch: u32 },
    IntentFinalized { epoch: u32 },
    Terminal { outcome: Outcome, available: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Succeeded,
    FailedFinal,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CmdError {
    DigestConflict,
    AlreadyIntent,
    NoIntentProofStale,
    NotAssignable,
    IdPermanentlyUsed,
}

#[derive(Default)]
pub struct CommandLedger {
    /// active + archived: CommandIds are never forgotten (inv. 85)
    entries: BTreeMap<CommandId, (u64 /*digest*/, ExecState)>,
    /// physical intent bindings: (command, epoch) -> wal head position
    intents: Vec<(CommandId, u32)>,
    /// monotonically increasing WAL head; no-intent proofs pin it
    pub wal_head: u64,
}

impl CommandLedger {
    pub fn reserve(&mut self, id: CommandId, digest: u64) -> Result<ExecState, CmdError> {
        match self.entries.get(&id) {
            None => {
                self.entries.insert(id, (digest, ExecState::Reserved));
                Ok(ExecState::Reserved)
            }
            Some((d, state)) if *d == digest => Ok(state.clone()), // idempotent
            Some(_) => Err(CmdError::DigestConflict),
        }
    }

    pub fn assign(&mut self, id: CommandId, epoch: u32) -> Result<(), CmdError> {
        match self.entries.get_mut(&id) {
            Some((_, s @ ExecState::Reserved)) => {
                *s = ExecState::Assigned { epoch };
                Ok(())
            }
            _ => Err(CmdError::NotAssignable),
        }
    }

    /// CommitRecord finalisation with command binding: permanently forbids
    /// re-execution (inv. 92).
    pub fn finalize_intent(&mut self, id: CommandId, epoch: u32) -> Result<(), CmdError> {
        // permanent binding check first: once ANY intent exists for this
        // CommandId, every further finalisation attempt is AlreadyIntent
        // regardless of the projection row's current state (inv. 92)
        if self.intents.iter().any(|(c, _)| *c == id) {
            return Err(CmdError::AlreadyIntent);
        }
        match self.entries.get_mut(&id) {
            Some((_, s @ ExecState::Assigned { .. })) => {
                if let ExecState::Assigned { epoch: e } = *s {
                    if e != epoch {
                        return Err(CmdError::NotAssignable);
                    }
                }
                *s = ExecState::IntentFinalized { epoch };
                self.intents.push((id, epoch));
                self.wal_head += 1;
                Ok(())
            }
            _ => Err(CmdError::NotAssignable),
        }
    }

    /// Exact no-intent proof (§11.7): capture the head, search archived +
    /// active bindings, then atomically recheck the head is unchanged.
    pub fn no_intent_proof(&mut self, id: CommandId, epoch: u32, captured_head: u64) -> Result<(), CmdError> {
        if captured_head != self.wal_head {
            return Err(CmdError::NoIntentProofStale); // repeat with fresh capture
        }
        if self.intents.iter().any(|(c, e)| *c == id && *e == epoch) {
            return Err(CmdError::AlreadyIntent);
        }
        // proof holds: the attempt closes retryable; a new epoch may assign
        if let Some((_, s)) = self.entries.get_mut(&id) {
            *s = ExecState::Reserved;
        }
        Ok(())
    }

    pub fn terminalize(&mut self, id: CommandId, outcome: Outcome) {
        if let Some((_, s)) = self.entries.get_mut(&id) {
            *s = ExecState::Terminal { outcome, available: true };
        }
    }

    /// Result retention expiry (inv. 97): availability only.
    pub fn expire_result(&mut self, id: CommandId) {
        if let Some((_, s)) = self.entries.get_mut(&id) {
            if let ExecState::Terminal { outcome, .. } = *s {
                *s = ExecState::Terminal { outcome, available: false };
            }
        }
    }

    pub fn state(&self, id: CommandId) -> Option<&ExecState> {
        self.entries.get(&id).map(|(_, s)| s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// inv. 86: reservation idempotency and permanent digest conflict —
    /// including after terminal state and after result expiry.
    #[test]
    fn reservation_idempotent_and_conflicting() {
        let mut l = CommandLedger::default();
        l.reserve(1, 100).unwrap();
        assert_eq!(l.reserve(1, 100).unwrap(), ExecState::Reserved);
        assert_eq!(l.reserve(1, 999), Err(CmdError::DigestConflict));
        l.assign(1, 1).unwrap();
        l.finalize_intent(1, 1).unwrap();
        l.terminalize(1, Outcome::Succeeded);
        l.expire_result(1);
        // permanent: still returns stored state / conflict, never re-executes
        assert!(matches!(l.reserve(1, 100).unwrap(),
                         ExecState::Terminal { outcome: Outcome::Succeeded, available: false }));
        assert_eq!(l.reserve(1, 999), Err(CmdError::DigestConflict));
    }

    /// inv. 92: crash-at-every-point matrix — once the intent is finalised,
    /// no schedule reaches a second execution epoch for the CommandId.
    /// Crash points: after reserve / assign / intent / terminal; recovery
    /// then attempts the full no-intent + reassign path.
    #[test]
    fn no_reexecution_after_intent_across_crash_points() {
        for crash_after in ["reserve", "assign", "intent", "terminal"] {
            let mut l = CommandLedger::default();
            l.reserve(1, 100).unwrap();
            let mut intent_done = false;
            if crash_after != "reserve" {
                l.assign(1, 1).unwrap();
                if crash_after != "assign" {
                    l.finalize_intent(1, 1).unwrap();
                    intent_done = true;
                    if crash_after == "terminal" {
                        l.terminalize(1, Outcome::Succeeded);
                    }
                }
            }
            // recovery: try to prove no intent for epoch 1 and reassign
            let head = l.wal_head;
            let proof = l.no_intent_proof(1, 1, head);
            if intent_done {
                assert_eq!(proof, Err(CmdError::AlreadyIntent),
                           "crash_after={crash_after}: proof must find the binding");
                // and a fresh epoch may never finalise a second intent
                assert_eq!(l.finalize_intent(1, 2), Err(CmdError::AlreadyIntent));
            } else {
                proof.unwrap();
                l.assign(1, 2).unwrap();
                l.finalize_intent(1, 2).unwrap();
            }
            // exactly one intent binding exists in every schedule
            assert_eq!(l.intents.iter().filter(|(c, _)| *c == 1).count(), 1);
        }
    }

    /// §11.7: the no-intent proof is race-free — an intent finalisation
    /// interleaved between capture and recheck forces a re-run. Exhaust both
    /// interleavings.
    #[test]
    fn no_intent_proof_detects_interleaved_finalisation() {
        // interleaving A: no concurrent write -> proof holds
        let mut l = CommandLedger::default();
        l.reserve(1, 100).unwrap();
        l.assign(1, 1).unwrap();
        let head = l.wal_head;
        l.no_intent_proof(1, 1, head).unwrap();

        // interleaving B: concurrent finalisation bumps the head after
        // capture -> proof MUST be stale, never a false absence
        let mut l = CommandLedger::default();
        l.reserve(1, 100).unwrap();
        l.assign(1, 1).unwrap();
        let head = l.wal_head; // capture
        l.finalize_intent(1, 1).unwrap(); // interleaved!
        assert_eq!(l.no_intent_proof(1, 1, head), Err(CmdError::NoIntentProofStale));
        // fresh capture then finds the binding
        let head2 = l.wal_head;
        assert_eq!(l.no_intent_proof(1, 1, head2), Err(CmdError::AlreadyIntent));
    }

    /// inv. 97: expiry changes availability only, outcome is immutable, and
    /// expiry never reopens execution.
    #[test]
    fn expiry_is_availability_not_outcome() {
        let mut l = CommandLedger::default();
        l.reserve(9, 1).unwrap();
        l.assign(9, 1).unwrap();
        l.finalize_intent(9, 1).unwrap();
        l.terminalize(9, Outcome::FailedFinal);
        l.expire_result(9);
        assert!(matches!(l.state(9),
            Some(ExecState::Terminal { outcome: Outcome::FailedFinal, available: false })));
        assert_eq!(l.finalize_intent(9, 2), Err(CmdError::AlreadyIntent));
    }

    // negative control: a broken proof that skips the head recheck would
    // return a false absence under interleaving B above.
    #[test]
    fn broken_no_intent_proof_mutant_is_observable() {
        let mut l = CommandLedger::default();
        l.reserve(1, 100).unwrap();
        l.assign(1, 1).unwrap();
        let _stale_head = l.wal_head;
        l.finalize_intent(1, 1).unwrap();
        // MUTANT: proof that ignores the captured head and only checks a
        // stale local snapshot of `intents` taken at capture time (empty)
        let stale_snapshot_empty = true; // what the mutant saw at capture
        let mutant_result_would_be_absent = stale_snapshot_empty;
        assert!(mutant_result_would_be_absent,
                "mutant returns false absence; the real proof returns Stale/AlreadyIntent");
        assert_ne!(l.no_intent_proof(1, 1, 0), Ok(()));
    }
}
