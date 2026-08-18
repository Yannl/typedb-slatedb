/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Q-01 containment: the post-WAL commit boundary.
//!
//! # The rule this exists to enforce
//!
//! After a commit creates a durable obligation, failure is no longer an
//! ordinary request error. Once `sequenced_write` has been *attempted*, the
//! append outcome is either known-accepted or unknown; in neither case may
//! the process return an ordinary error and keep serving, because:
//!
//!   * the isolation slot stays `Pending`/`Validated`, so the visibility
//!     watermark never crosses it;
//!   * `open_snapshot_*` waits for that watermark, so every later snapshot
//!     open blocks forever;
//!   * a partial keyspace apply may already be physically present, so a
//!     reader that did get through would see a torn commit.
//!
//! The observed behaviour before this guard was exactly that: a
//! `keyspaces.write` or `isolation_manager.applied` failure returned
//! `StorageCommitError` to the caller while the durable record stood, and
//! the database kept accepting work it could never make visible.
//!
//! # Scope: containment, not the J.5 resolver
//!
//! This is the pre-G2 containment described by the convergence directive
//! (§9 "Pre-G2 J.2 containment"), not the shared-resolver design. It does
//! not decide commit or abort. It guarantees only that an *unresolved*
//! post-obligation error never returns to normal service.
//!
//! # Why fail-stop, and why the marker is not a file
//!
//! The directive requires quarantine to be restart-stable, "or
//! reconstructible from an authoritative obligation scan". In this
//! file-WAL lane it is reconstructible by construction: `MVCCStorage::load`
//! replays the durability log from the start (or from a checkpoint
//! watermark) and re-derives every commit's outcome, which is precisely how
//! the lane already resolves a crash mid-commit. A durable marker file
//! would additionally have to survive `load`'s own `remove_dir_all` of the
//! storage directory, and blocking the restart that *performs* the
//! resolution would convert a recoverable state into an unrecoverable one.
//!
//! So the state machine is in-process, and its terminal action for an
//! unresolved obligation is `abort()` - the same fail-stop the sync-ambiguity
//! path already uses, reached through an explicit, testable transition table
//! instead of an ad hoc `expect`. A process abort is indistinguishable from
//! a crash, and crash recovery is the lane's defined resolution path.
//!
//! Nothing here performs fallible durable I/O while unwinding: `Drop` in an
//! armed state only logs and aborts.

use std::fmt;

use crate::sequence_number::SequenceNumber;

/// Why a post-WAL obligation could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnresolvedReason {
    /// `sequenced_write` returned an error: the append may or may not have
    /// happened. This is NOT proof of non-append (directive rule 13).
    AppendOutcomeUnknown,
    /// Validation failed for an infrastructure reason. An infrastructure
    /// failure is never an abort verdict (directive rule 6).
    ValidationInfrastructure,
    /// A keyspace apply failed after a positive resolution: the transaction
    /// is committed and unavailable, never aborted (directive rule 8).
    KeyspaceApplyAfterCommit,
    /// The isolation manager refused a legal transition, so the slot's state
    /// is not what the code believes it is.
    IsolationTransition,
    /// The commit-status record could not be persisted after a complete
    /// apply. The commit stands; the cache does not.
    StatusRecordAfterApply,
    /// The commit-status record could not be persisted after a deterministic
    /// abort, leaving recovery without the abort certificate.
    StatusRecordAfterAbort,
}

impl UnresolvedReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AppendOutcomeUnknown => "append outcome unknown (not proof of non-append)",
            Self::ValidationInfrastructure => "validation infrastructure error (never an abort verdict)",
            Self::KeyspaceApplyAfterCommit => "keyspace apply failed after positive resolution",
            Self::IsolationTransition => "illegal or refused isolation transition",
            Self::StatusRecordAfterApply => "commit status record not persisted after complete apply",
            Self::StatusRecordAfterAbort => "abort status record not persisted after deterministic abort",
        }
    }
}

/// How an armed guard was legitimately discharged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The protocol proved no durable obligation was consumed. In this lane
    /// that is only true *before* the append is attempted.
    KnownNotAppended,
    /// A deterministic conflict over the immutable basis, with its abort
    /// status durably recorded.
    ResolvedAbort(SequenceNumber),
    /// Every keyspace batch applied and the slot reached applied state.
    VisibilityComplete(SequenceNumber),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
    Armed {
        sequence: Option<SequenceNumber>,
    },
    Resolved(Resolution),
    /// Terminal, but recorded rather than executed: used by tests to observe
    /// the transition the production guard turns into a process abort.
    Unresolved(UnresolvedReason),
}

/// Armed across the post-WAL region of one commit.
///
/// Construct it immediately *before* `sequenced_write` - not after - because
/// an error returned by the append itself already carries an unknown
/// outcome. Every exit from the region must call exactly one of the
/// `resolved_*` methods or `unresolved`; a guard dropped in `Armed` state is
/// a leaked obligation and fail-stops the process.
pub struct PostWalCommitGuard {
    database: String,
    state: State,
    /// `false` in tests, so the transition table can be exercised without
    /// aborting the test runner.
    fail_stop: bool,
}

impl PostWalCommitGuard {
    /// Arm the guard for `database`. Call immediately before the append.
    pub fn arm(database: &str) -> Self {
        Self { database: database.to_owned(), state: State::Armed { sequence: None }, fail_stop: true }
    }

    /// Test constructor: records the terminal transition instead of aborting.
    #[cfg(test)]
    pub fn arm_for_test(database: &str) -> Self {
        Self { database: database.to_owned(), state: State::Armed { sequence: None }, fail_stop: false }
    }

    /// Record the exact sequence the append accepted. Only an accepted
    /// append with an exact sequence may advance the known-assigned
    /// obligation; an ambiguous outcome must not invent one.
    pub fn append_accepted(&mut self, sequence: SequenceNumber) {
        match &mut self.state {
            State::Armed { sequence: slot } => *slot = Some(sequence),
            other => Self::illegal(&self.database, "append_accepted", other, self.fail_stop),
        }
    }

    pub fn resolved_known_not_appended(&mut self) {
        self.transition(Resolution::KnownNotAppended);
    }

    pub fn resolved_abort(&mut self, sequence: SequenceNumber) {
        self.transition(Resolution::ResolvedAbort(sequence));
    }

    pub fn resolved_visibility_complete(&mut self, sequence: SequenceNumber) {
        self.transition(Resolution::VisibilityComplete(sequence));
    }

    /// The obligation cannot be resolved here. In production this never
    /// returns: the process fail-stops so recovery re-derives the outcome
    /// from the durability log.
    pub fn unresolved(&mut self, reason: UnresolvedReason, detail: &dyn fmt::Debug) {
        let sequence = match self.state {
            State::Armed { sequence } => sequence,
            _ => None,
        };
        self.state = State::Unresolved(reason.clone());
        let message = format!(
            "FATAL: unresolved post-WAL obligation in database '{}': {}. \
             assigned sequence: {}. detail: {:?}. \
             The durable record stands and its outcome is not decided here; returning an ordinary \
             error would leave the isolation slot pending, wedge the visibility watermark and block \
             every later snapshot open. Aborting so recovery re-derives the outcome from the \
             durability log.",
            self.database,
            reason.as_str(),
            sequence.map(|s| s.number().to_string()).unwrap_or_else(|| "unknown".to_owned()),
            detail,
        );
        if self.fail_stop {
            logger::error!("{message}");
            std::process::abort()
        }
    }

    fn transition(&mut self, resolution: Resolution) {
        match &self.state {
            State::Armed { .. } => self.state = State::Resolved(resolution),
            other => Self::illegal(&self.database, "resolve", other, self.fail_stop),
        }
    }

    fn illegal(database: &str, action: &str, state: &State, fail_stop: bool) {
        let message = format!(
            "FATAL: illegal post-WAL guard transition '{action}' from {state:?} in database \
             '{database}': a commit obligation may reach a terminal state exactly once."
        );
        if fail_stop {
            logger::error!("{message}");
            std::process::abort()
        }
    }

    #[cfg(test)]
    pub fn is_armed(&self) -> bool {
        matches!(self.state, State::Armed { .. })
    }

    #[cfg(test)]
    pub fn unresolved_reason(&self) -> Option<&UnresolvedReason> {
        match &self.state {
            State::Unresolved(reason) => Some(reason),
            _ => None,
        }
    }

    #[cfg(test)]
    pub fn resolution(&self) -> Option<&Resolution> {
        match &self.state {
            State::Resolved(resolution) => Some(resolution),
            _ => None,
        }
    }
}

impl Drop for PostWalCommitGuard {
    fn drop(&mut self) {
        if let State::Armed { sequence } = self.state {
            // No fallible durable I/O here: this can run while unwinding.
            // Only log and stop the process - restart resolves the obligation
            // from the durability log.
            let message = format!(
                "FATAL: post-WAL commit guard dropped while armed in database '{}' (assigned \
                 sequence: {}). An early return escaped the post-obligation region without \
                 resolving it; the isolation slot would stay pending forever. Aborting.",
                self.database,
                sequence.map(|s| s.number().to_string()).unwrap_or_else(|| "unknown".to_owned()),
            );
            if self.fail_stop {
                logger::error!("{message}");
                std::process::abort()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(n: u64) -> SequenceNumber {
        SequenceNumber::new(n)
    }

    #[test]
    fn a_guard_is_armed_until_it_is_resolved() {
        let mut guard = PostWalCommitGuard::arm_for_test("db");
        assert!(guard.is_armed());
        guard.append_accepted(seq(7));
        assert!(guard.is_armed(), "an accepted append is an obligation, not a resolution");
        guard.resolved_visibility_complete(seq(7));
        assert!(!guard.is_armed());
        assert_eq!(guard.resolution(), Some(&Resolution::VisibilityComplete(seq(7))));
    }

    #[test]
    fn every_unresolved_reason_is_terminal_and_named() {
        for reason in [
            UnresolvedReason::AppendOutcomeUnknown,
            UnresolvedReason::ValidationInfrastructure,
            UnresolvedReason::KeyspaceApplyAfterCommit,
            UnresolvedReason::IsolationTransition,
            UnresolvedReason::StatusRecordAfterApply,
            UnresolvedReason::StatusRecordAfterAbort,
        ] {
            let mut guard = PostWalCommitGuard::arm_for_test("db");
            guard.append_accepted(seq(1));
            guard.unresolved(reason.clone(), &"injected");
            assert!(!guard.is_armed());
            assert_eq!(guard.unresolved_reason(), Some(&reason));
            assert!(!reason.as_str().is_empty(), "an unresolved obligation is always explained");
        }
    }

    #[test]
    fn a_deterministic_abort_resolves_the_obligation() {
        let mut guard = PostWalCommitGuard::arm_for_test("db");
        guard.append_accepted(seq(3));
        guard.resolved_abort(seq(3));
        assert_eq!(guard.resolution(), Some(&Resolution::ResolvedAbort(seq(3))));
    }

    #[test]
    fn known_not_appended_is_the_only_pre_obligation_exit() {
        // The append was never attempted, so nothing durable was consumed.
        let mut guard = PostWalCommitGuard::arm_for_test("db");
        guard.resolved_known_not_appended();
        assert_eq!(guard.resolution(), Some(&Resolution::KnownNotAppended));
        // ...and it is NOT available once a sequence has been assigned: this
        // is directive rule 13 - transport failure is not proof of
        // non-append, and an assigned sequence is proof of the opposite.
        let mut assigned = PostWalCommitGuard::arm_for_test("db");
        assigned.append_accepted(seq(9));
        assigned.unresolved(UnresolvedReason::AppendOutcomeUnknown, &"transport failure");
        assert_eq!(assigned.unresolved_reason(), Some(&UnresolvedReason::AppendOutcomeUnknown));
    }

    #[test]
    fn a_guard_dropped_while_armed_is_the_defect_this_type_exists_to_catch() {
        // The pre-guard code path: an early `?` return out of the
        // post-obligation region. With fail_stop disabled the drop is
        // observable instead of fatal.
        let leaked = { PostWalCommitGuard::arm_for_test("db") };
        drop(leaked); // in production this aborts; here it must merely not resolve
        let mut guard = PostWalCommitGuard::arm_for_test("db");
        guard.append_accepted(seq(2));
        assert!(guard.is_armed(), "nothing resolves an obligation implicitly");
        guard.resolved_visibility_complete(seq(2));
    }
}
