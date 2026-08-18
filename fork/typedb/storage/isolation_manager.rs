/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// TODO: Check atomic Ordering constraints. We're using SeqCst where we don't have to
// TODO: Benchmark with many small commits to see if the read-write locks affect latency.

use std::{
    cmp::max,
    collections::VecDeque,
    error::Error,
    fmt,
    sync::{
        Arc, OnceLock, RwLock,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use logger::{error, result::ResultExt};
use primitive::maybe_owns::MaybeOwns;
use resource::constants::storage::TIMELINE_WINDOW_SIZE;

use crate::{
    durability_client::{DurabilityClient, DurabilityClientError},
    record::{CommitRecord, StatusRecord},
    recovery::status_resolver::{StatusConflict, resolve_status_history},
    sequence_number::SequenceNumber,
    write_batches::WriteBatches,
};

#[derive(Debug)]
pub(crate) struct IsolationManager {
    initial_sequence_number: SequenceNumber,
    timeline: Timeline,
}

impl fmt::Display for IsolationManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timeline[windows={}, watermark={}]", self.timeline.window_count(), self.watermark())
    }
}

impl IsolationManager {
    pub(crate) fn new(next_sequence_number: SequenceNumber) -> IsolationManager {
        IsolationManager {
            initial_sequence_number: next_sequence_number,
            timeline: Timeline::new(next_sequence_number),
        }
    }

    pub(crate) fn opened_for_read(&self, sequence_number: SequenceNumber) -> ReaderDropGuard {
        debug_assert!(
            sequence_number <= self.watermark(),
            "assertion `{} <= {}` failed",
            sequence_number,
            self.watermark()
        );
        self.timeline.record_reader(sequence_number)
    }

    pub(crate) fn applied(&self, sequence_number: SequenceNumber) -> Result<(), ExpectedWindowError> {
        self.timeline
            .try_get_window(sequence_number)
            .ok_or(ExpectedWindowError { sequence_number })?
            .set_applied(sequence_number);
        self.timeline.may_increment_watermark(sequence_number);
        Ok(())
    }

    pub(crate) fn load_validated(&self, sequence_number: SequenceNumber, commit_record: CommitRecord) {
        let window = self.timeline.get_or_create_window(sequence_number);
        window.insert_pending(sequence_number, commit_record);
        window.set_validated(sequence_number);
        drop(window);
        self.timeline.may_increment_watermark(sequence_number);
    }

    pub(crate) fn load_aborted(&self, sequence_number: SequenceNumber) {
        let window = self.timeline.get_or_create_window(sequence_number);
        window.set_aborted(sequence_number);
        drop(window);
        self.timeline.may_increment_watermark(sequence_number);
    }

    pub(crate) fn validate_commit(
        &self,
        sequence_number: SequenceNumber,
        commit_record: CommitRecord,
        durability_client: &impl DurabilityClient,
    ) -> Result<ValidatedCommit, DurabilityClientError> {
        let window = self.timeline.get_or_create_window(sequence_number);
        window.insert_pending(sequence_number, commit_record);
        let CommitStatus::Pending(commit_record) = window.get_status(sequence_number) else { unreachable!() };
        let isolation_conflict = self.validate_all_concurrent(sequence_number, &commit_record, durability_client)?;
        if isolation_conflict.is_none() {
            window.set_validated(sequence_number);
        } else {
            window.set_aborted(sequence_number);
            self.timeline.may_increment_watermark(sequence_number);
        }
        match isolation_conflict {
            Some(conflict) => Ok(ValidatedCommit::Conflict(conflict)),
            None => {
                let commit_record = match window.get_status(sequence_number) {
                    CommitStatus::Validated(commit_record) | CommitStatus::Applied(commit_record) => commit_record,
                    _ => panic!("get_commit_record called on uncommitted record"), // TODO: Do we want to be able to apply on pending?
                };
                Ok(ValidatedCommit::Write(WriteBatches::from_operations(sequence_number, commit_record.operations())))
            }
        }
    }

    fn validate_all_concurrent(
        &self,
        commit_sequence_number: SequenceNumber,
        commit_record: &CommitRecord,
        durability_client: &impl DurabilityClient,
    ) -> Result<Option<IsolationConflict>, DurabilityClientError> {
        // TODO: decide if we should block until all predecessors finish, allow out of order (non-Calvin model/traditional model)
        //       We could also validate against all predecessors even if they are validating and fail eagerly.
        // TODO: Should we validate from the timeline before going to disk?

        // Pre-collect all the ARCs so we can validate against them.
        let (windows, first_sequence_number_in_memory) =
            self.timeline.collect_concurrent_windows(commit_record.open_sequence_number(), commit_sequence_number);
        if commit_record.open_sequence_number().next() < first_sequence_number_in_memory {
            if let Some(conflict) =
                self.validate_concurrent_from_disk(commit_record, first_sequence_number_in_memory, durability_client)?
            {
                return Ok(Some(conflict));
            }
        }

        self.validate_concurrent_from_windows(
            commit_record,
            commit_sequence_number,
            &windows,
            first_sequence_number_in_memory,
        )
    }

    fn validate_concurrent_from_disk(
        &self,
        commit_record: &CommitRecord,
        stop_sequence_number: SequenceNumber,
        durability_client: &impl DurabilityClient,
    ) -> Result<Option<IsolationConflict>, DurabilityClientError> {
        for commit_status_result in Self::iterate_commit_status_from_disk(
            durability_client,
            commit_record.open_sequence_number().next(),
            stop_sequence_number,
        )? {
            let (sequence_number, commit_status) = commit_status_result?;
            let commit_dependency = match commit_status {
                DiskCommitStatus::Aborted => CommitDependency::Independent,
                DiskCommitStatus::Applied(predecessor_record) => commit_record.compute_dependency(&predecessor_record),
                DiskCommitStatus::MissingStatus => {
                    // R-02: a predecessor evicted from the timeline with NO
                    // durable status record is a missing certificate. Its
                    // verdict cannot be deterministically recomputed on the
                    // live path (that would require re-validating it against
                    // ITS predecessors mid-flight), so this is a typed
                    // refusal — never an unreachable!/panic and never a
                    // silent assumption of either verdict.
                    return Err(DurabilityClientError::MissingCommitStatus {
                        sequence_number: sequence_number.number(),
                    });
                }
            };
            if let Some(conflict) = handle_dependency(commit_dependency) {
                return Ok(Some(conflict));
            }
        }
        Ok(None)
    }

    fn validate_concurrent_from_windows(
        &self,
        commit_record: &CommitRecord,
        commit_sequence_number: SequenceNumber,
        windows: &[Arc<TimelineWindow<TIMELINE_WINDOW_SIZE>>],
        first_window_sequence_number: SequenceNumber,
    ) -> Result<Option<IsolationConflict>, DurabilityClientError> {
        let start_validation_index = max(commit_record.open_sequence_number().next(), first_window_sequence_number);
        debug_assert!(start_validation_index <= first_window_sequence_number + TIMELINE_WINDOW_SIZE);
        let mut window_index = 0;
        for validate_against in start_validation_index.number()..commit_sequence_number.number() {
            let validate_against = SequenceNumber::from(validate_against);
            let window = &windows[window_index];
            debug_assert!(window_index < windows.len());
            if let Some(conflict) = resolve_concurrent(commit_record, validate_against, window)? {
                return Ok(Some(conflict));
            }
            if validate_against + 1 >= window.end() {
                window_index += 1;
            }
        }
        Ok(None)
    }

    pub(crate) fn iterate_commit_status_from_disk(
        durability_client: &impl DurabilityClient,
        start_sequence_number: SequenceNumber,
        stop_sequence_number: SequenceNumber,
    ) -> Result<
        impl Iterator<Item = Result<(SequenceNumber, DiskCommitStatus), DurabilityClientError>>,
        DurabilityClientError,
    > {
        // R-02: status folding goes through the ONE shared resolver, the same
        // one recovery uses: identical duplicates converge, opposite verdicts
        // are an order-independent typed quarantine — never last-write-wins.
        // We can't stop early because status records may be out-of-order.
        let statuses = durability_client
            .iter_unsequenced_type_from::<StatusRecord>(start_sequence_number)?
            .map(|record| record.map(|record| (record.commit_record_sequence_number(), record.was_committed())));
        let is_committed = resolve_status_history(statuses.collect::<Result<Vec<_>, _>>()?).map_err(
            |StatusConflict { sequence_number }| DurabilityClientError::ConflictingCommitStatus {
                sequence_number: sequence_number.number(),
            },
        )?;

        Ok(durability_client.iter_sequenced_type_from::<CommitRecord>(start_sequence_number)?.map_while(
            move |result| match result {
                Ok((commit_sequence_number, commit_record)) => {
                    if commit_sequence_number >= stop_sequence_number {
                        None
                    } else {
                        let status = match is_committed.get(&commit_sequence_number) {
                            None => DiskCommitStatus::MissingStatus,
                            Some(true) => DiskCommitStatus::Applied(commit_record),
                            Some(false) => DiskCommitStatus::Aborted,
                        };
                        Some(Ok((commit_sequence_number, status)))
                    }
                }
                Err(err) => Some(Err(err)),
            },
        ))
    }

    pub(crate) fn watermark(&self) -> SequenceNumber {
        self.timeline.watermark()
    }

    pub fn reset(&mut self) {
        self.timeline = Timeline::new(self.initial_sequence_number);
    }
}

pub(crate) enum ValidatedCommit {
    Conflict(IsolationConflict),
    Write(WriteBatches),
}

fn resolve_concurrent(
    commit_record: &CommitRecord,
    predecessor_sequence_number: SequenceNumber,
    predecessor_window: &TimelineWindow<TIMELINE_WINDOW_SIZE>,
) -> Result<Option<IsolationConflict>, DurabilityClientError> {
    // S-P0-02: the Empty wait covers only the narrow race between a slot's
    // sequence number being allocated and `insert_pending` landing; it is
    // BOUNDED because a predecessor thread that dies inside that window
    // would otherwise pin this commit in a silent spin forever.
    predecessor_window.await_slot_occupied(predecessor_sequence_number)?;
    let commit_dependency = match predecessor_window.get_status(predecessor_sequence_number) {
        CommitStatus::Empty => unreachable!("A concurrent status should never be empty at commit time"),
        CommitStatus::Pending(predecessor_record) => match commit_record.compute_dependency(&predecessor_record) {
            CommitDependency::Independent => CommitDependency::Independent,
            result => {
                if predecessor_window.await_pending_status_commits(predecessor_sequence_number)? {
                    result
                } else {
                    CommitDependency::Independent
                }
            }
        },
        CommitStatus::Validated(predecessor_record) | CommitStatus::Applied(predecessor_record) => {
            commit_record.compute_dependency(&predecessor_record)
        }
        CommitStatus::Aborted => CommitDependency::Independent,
    };
    Ok(handle_dependency(commit_dependency))
}

fn handle_dependency(commit_dependency: CommitDependency) -> Option<IsolationConflict> {
    match commit_dependency {
        CommitDependency::Independent => (),
        CommitDependency::DependentPuts { puts } => puts.into_iter().for_each(DependentPut::apply),
        CommitDependency::Conflict(conflict) => return Some(conflict),
    }
    None
}

#[derive(Debug, Clone)]
pub(crate) enum DependentPut {
    Deleted { reinsert: Arc<AtomicBool> },
    Inserted { reinsert: Arc<AtomicBool> },
}

impl DependentPut {
    fn apply(self) {
        match self {
            DependentPut::Deleted { reinsert } => reinsert.store(true, Ordering::Release),
            DependentPut::Inserted { reinsert } => reinsert.store(false, Ordering::Release),
        }
    }
}

#[derive(Debug)]
pub(crate) enum CommitDependency {
    Independent,
    DependentPuts { puts: Vec<DependentPut> },
    Conflict(IsolationConflict),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IsolationConflict {
    DeletingRequiredKey,
    RequireDeletedKey,
    ExclusiveLock,
}

impl fmt::Display for IsolationConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IsolationConflict::DeletingRequiredKey => {
                write!(f, "Transaction deletes data a concurrent commit requires.")
            }
            IsolationConflict::RequireDeletedKey => write!(f, "Transaction uses data a concurrent commit deletes."),
            IsolationConflict::ExclusiveLock => write!(f, "Transaction uses a lock held by a concurrent commit."),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ExpectedWindowError {
    sequence_number: SequenceNumber,
}

impl fmt::Display for ExpectedWindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Unexpected internal error: could not find timeline window containing sequence number {}",
            self.sequence_number
        )
    }
}

impl Error for ExpectedWindowError {}

/// Timeline concept:
///   Timeline is made of Windows. Each Window stores a number of Slots.
///   Conceptually the timeline is one sequence of Slots, but we cut it into Windows for more efficient allocation/clean up/search.
///   Having windows also allows us to hold write-locks less often. If we decide we want a fixed
///   The timeline should not clean up old windows while a 'reader' (ie open snapshot) is open on a window or an older window.
///
///   On commit, we
///     1) notify the commit is pending, writing the commit record into the Slot for its commit sequence number.
///     2) when validation has finished, record into the Slot for its commit sequence number whether
///         it is sucessfully 'validated' or must be 'aborted'.
///
#[derive(Debug)]
struct Timeline {
    // We can adjust the Window size to amortise the cost of the read-write locks to maintain the timeline
    windows: RwLock<VecDeque<Arc<TimelineWindow<TIMELINE_WINDOW_SIZE>>>>,
    watermark: AtomicU64,
}

impl Timeline {
    // The whole of the timeline uses the underlying u64
    fn new(next_sequence_number: SequenceNumber) -> Timeline {
        let windows = VecDeque::from([Arc::new(TimelineWindow::new(next_sequence_number))]);
        // R-07: checked, not raw `- 1`. The first allocatable sequence number
        // is MIN.next(), so MIN never names a commit and a saturated origin
        // watermark is exact, never a release-mode wrap to u64::MAX.
        Timeline {
            windows: RwLock::new(windows),
            watermark: AtomicU64::new(next_sequence_number.number().saturating_sub(1)),
        }
    }

    fn may_free_windows(&self) {
        let watermark = self.watermark();
        let can_free_some =
            self.windows.read().unwrap_or_log().front().is_some_and(|f| f.get_readers() == 0 && watermark >= f.end());
        if can_free_some {
            let windows = &mut *self.windows.write().unwrap_or_log();
            while watermark >= windows.front().unwrap().end() && windows.front().unwrap().get_readers() == 0 {
                windows.pop_front();
            }
        }
    }

    fn may_increment_watermark(&self, sequence_number: SequenceNumber) {
        // R-07: canonical checked helpers instead of raw +/- 1. A sequence
        // number with no predecessor (MIN) can never be a commit, and a
        // candidate with no successor (MAX) simply stops the advance — no
        // debug-panic/release-wrap split anywhere on this path.
        let Some(predecessor) = sequence_number.try_previous() else {
            return; // MIN never names a commit; nothing to advance past
        };
        if self.watermark() != predecessor {
            return;
        }

        let mut candidate_watermark = sequence_number;
        {
            let mut window = self.try_get_window(sequence_number);
            while window.is_some() {
                let should_update = window.as_ref().is_some_and(|window| {
                    matches!(window.get_status(candidate_watermark), CommitStatus::Aborted | CommitStatus::Applied(_))
                });
                let Some(candidate_predecessor) = candidate_watermark.try_previous() else { break };
                if should_update
                    && self
                        .watermark
                        .compare_exchange(
                            candidate_predecessor.number(),
                            candidate_watermark.number(),
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        )
                        .is_ok()
                {
                    candidate_watermark = match candidate_watermark.try_next() {
                        Some(next) => next,
                        None => break, // top of the sequence space: refuse to advance further
                    };
                    if candidate_watermark >= window.as_ref().unwrap().end() {
                        drop(window.take());
                        window = self.try_get_window(candidate_watermark);
                    }
                } else {
                    break;
                }
            }
        }

        let watermark = match candidate_watermark.try_previous() {
            Some(watermark) => watermark, // Invariant
            None => return,
        };
        if let Some(watermark_window_end) = { self.try_get_window(predecessor).map(|w| w.end()) } {
            if watermark >= watermark_window_end {
                self.may_free_windows();
            }
        }
    }

    fn watermark(&self) -> SequenceNumber {
        SequenceNumber::from(self.watermark.load(Ordering::SeqCst))
    }

    fn record_reader(&self, sequence_number: SequenceNumber) -> ReaderDropGuard {
        if let Some(window) = self.try_get_window(sequence_number) {
            window.increment_readers();
            ReaderDropGuard { window: Some(window) }
        } else {
            // we only need to record readers against the timeline for windows that are still in-memory
            ReaderDropGuard { window: None }
        }
    }

    fn collect_concurrent_windows(
        &self,
        open_sequence_number: SequenceNumber,
        commit_sequence_number: SequenceNumber,
    ) -> (Vec<Arc<TimelineWindow<TIMELINE_WINDOW_SIZE>>>, SequenceNumber) {
        let windows = &*self.windows.read().unwrap_or_log();
        let first_concurrent_window_index = Self::resolve_window(windows, open_sequence_number.next()).unwrap_or(0);
        let last_concurrent_window_index =
            Self::resolve_window(windows, commit_sequence_number.previous()).unwrap_or(0);
        let mut concurrent_windows: Vec<Arc<TimelineWindow<TIMELINE_WINDOW_SIZE>>> = Vec::new();
        (first_concurrent_window_index..=last_concurrent_window_index).for_each(|window_index| {
            concurrent_windows.push(windows.get(window_index).unwrap().clone());
        });
        let start_index_of_first_concurrent_window = windows.get(first_concurrent_window_index).unwrap().start();
        (concurrent_windows, start_index_of_first_concurrent_window)
    }

    fn try_get_window(&self, sequence_number: SequenceNumber) -> Option<Arc<TimelineWindow<TIMELINE_WINDOW_SIZE>>> {
        let windows = self.windows.read().unwrap_or_log();
        let window_index = Self::resolve_window(&windows, sequence_number)?;
        Some(windows.get(window_index).unwrap().clone())
    }

    fn get_or_create_window(&self, sequence_number: SequenceNumber) -> Arc<TimelineWindow<TIMELINE_WINDOW_SIZE>> {
        let end = self.windows.read().unwrap_or_log().back().unwrap().end();
        if sequence_number >= end {
            self.create_windows_to(sequence_number);
        }
        if let Some(window) = self.try_get_window(sequence_number) {
            window
        } else {
            panic!();
        }
    }

    fn create_windows_to(&self, sequence_number: SequenceNumber) {
        let windows = &mut *self.windows.write().unwrap_or_log();
        loop {
            let end = windows.back().unwrap().end();
            if sequence_number >= end {
                let shared_new_window = Arc::new(TimelineWindow::new(end));
                windows.push_back(shared_new_window.clone());
            } else {
                break;
            }
        }
    }

    fn window_count(&self) -> usize {
        self.windows.read().unwrap_or_log().len()
    }

    fn resolve_window(
        windows: &VecDeque<Arc<TimelineWindow<TIMELINE_WINDOW_SIZE>>>,
        to_resolve: SequenceNumber,
    ) -> Option<usize> {
        let start = windows.front().unwrap().start();
        let end = windows.back().unwrap().end();
        if to_resolve >= start && to_resolve < end {
            let offset = to_resolve - start;
            Some(offset / TIMELINE_WINDOW_SIZE)
        } else {
            None
        }
    }
}

/// A spin wait carrying a containment bound (S-P0-02). It still spins — the
/// expected waits are the sub-microsecond insert race and short overlapping
/// validation chains — but every iteration checks its deadline, so a
/// predecessor that never transitions becomes a typed error instead of a
/// silent forever-spin. R-09: the predecessor waits pass the SHORT
/// [`crate::PREDECESSOR_WAIT_DEADLINE`], not the global 600 s storage
/// deadline, so the typed outcome is prompt.
struct BoundedSpin {
    state: &'static str,
    sequence_number: SequenceNumber,
    deadline: Duration,
    report_interval: Duration,
    started: Instant,
    last_report: Instant,
}

impl BoundedSpin {
    fn new(
        state: &'static str,
        sequence_number: SequenceNumber,
        deadline: Duration,
        report_interval: Duration,
    ) -> Self {
        let now = Instant::now();
        Self { state, sequence_number, deadline, report_interval, started: now, last_report: now }
    }

    fn tick(&mut self) -> Result<(), DurabilityClientError> {
        std::hint::spin_loop();
        let waited = self.started.elapsed();
        if waited >= self.deadline {
            return Err(DurabilityClientError::PredecessorWaitTimeout {
                predecessor: self.sequence_number.number(),
                state: self.state,
                waited_secs: waited.as_secs(),
            });
        }
        if self.last_report.elapsed() >= self.report_interval {
            self.last_report = Instant::now();
            error!(
                "commit validation has waited {}s for predecessor commit {} to leave state '{}' (deadline {}s)",
                waited.as_secs(),
                self.sequence_number.number(),
                self.state,
                self.deadline.as_secs(),
            );
        }
        Ok(())
    }
}

pub struct ReaderDropGuard {
    window: Option<Arc<TimelineWindow<TIMELINE_WINDOW_SIZE>>>,
}

impl Drop for ReaderDropGuard {
    fn drop(&mut self) {
        if let Some(window) = self.window.as_ref() {
            window.decrement_readers();
        }
    }
}

#[derive(Debug)]
struct TimelineWindow<const SIZE: usize> {
    start: SequenceNumber,
    slot_status: [AtomicU8; SIZE],
    commit_records: [OnceLock<CommitRecord>; SIZE],
    readers: AtomicU64,
}

impl<const SIZE: usize> TimelineWindow<SIZE> {
    fn new(start: SequenceNumber) -> TimelineWindow<SIZE> {
        let commit_records = [const { OnceLock::new() }; SIZE];
        let slot_status = [const { AtomicU8::new(0) }; SIZE];
        debug_assert_eq!(slot_status[0].load(Ordering::SeqCst), SlotMarker::Empty.as_u8());

        TimelineWindow { start, slot_status, commit_records, readers: AtomicU64::new(0) }
    }

    fn start(&self) -> SequenceNumber {
        self.start
    }

    fn end(&self) -> SequenceNumber {
        // R-07: checked window arithmetic. Capping the exclusive end at MAX
        // is exact, not lossy: allocation refuses u64::MAX (typed WAL
        // exhaustion), so no allocatable sequence number is ever excluded,
        // and the previous unchecked `+` panicked in debug and wrapped the
        // window end around to a TINY value in release at the top of the
        // sequence space.
        self.start.checked_window_end(TIMELINE_WINDOW_SIZE).unwrap_or(SequenceNumber::MAX)
    }

    fn insert_pending(&self, sequence_number: SequenceNumber, commit_record: CommitRecord) {
        let index = sequence_number - self.start;
        self.commit_records[index].set(commit_record).unwrap_or_log();
        self.slot_status[index].store(SlotMarker::Pending.as_u8(), Ordering::SeqCst);
    }

    fn set_validated(&self, sequence_number: SequenceNumber) {
        let index = sequence_number - self.start;
        self.slot_status[index].store(SlotMarker::Validated.as_u8(), Ordering::SeqCst);
    }

    fn set_aborted(&self, sequence_number: SequenceNumber) {
        let index = sequence_number - self.start;
        self.slot_status[index].store(SlotMarker::Aborted.as_u8(), Ordering::SeqCst);
    }

    fn set_applied(&self, sequence_number: SequenceNumber) {
        let index = sequence_number - self.start;
        self.slot_status[index].store(SlotMarker::Applied.as_u8(), Ordering::SeqCst);
    }

    fn get_status(&self, sequence_number: SequenceNumber) -> CommitStatus<'_> {
        let index = sequence_number - self.start;
        let status = SlotMarker::from(self.slot_status[index].load(Ordering::SeqCst));
        let lazy_record = || self.commit_records[index].get().unwrap();
        match status {
            SlotMarker::Empty => CommitStatus::Empty,
            SlotMarker::Aborted => CommitStatus::Aborted,
            SlotMarker::Pending => CommitStatus::Pending(MaybeOwns::Borrowed(lazy_record())),
            SlotMarker::Validated => CommitStatus::Validated(MaybeOwns::Borrowed(lazy_record())),
            SlotMarker::Applied => CommitStatus::Applied(MaybeOwns::Borrowed(lazy_record())),
        }
    }

    /// Bounded wait for the narrow allocation race in which a predecessor's
    /// slot is still `Empty` (sequence number allocated, `insert_pending`
    /// not yet landed). S-P0-02: previously an unbounded spin — a
    /// predecessor thread dying inside that window pinned every waiter
    /// forever with no diagnostic.
    fn await_slot_occupied(&self, sequence_number: SequenceNumber) -> Result<(), DurabilityClientError> {
        // R-09: predecessor waits are bounded by the SHORT predecessor
        // deadline, not the global 600 s storage deadline — a wedged
        // predecessor becomes a prompt typed unresolved outcome instead of
        // pinning this commit for minutes.
        self.await_slot_occupied_within(
            sequence_number,
            crate::PREDECESSOR_WAIT_DEADLINE,
            crate::STORAGE_WAIT_REPORT_INTERVAL,
        )
    }

    fn await_slot_occupied_within(
        &self,
        sequence_number: SequenceNumber,
        deadline: Duration,
        report_interval: Duration,
    ) -> Result<(), DurabilityClientError> {
        let mut wait = BoundedSpin::new("Empty", sequence_number, deadline, report_interval);
        while matches!(self.get_status(sequence_number), CommitStatus::Empty) {
            wait.tick()?;
        }
        Ok(())
    }

    /// Bounded wait for a `Pending` predecessor to reach a terminal
    /// validation state: `Ok(true)` for validated/applied, `Ok(false)` for
    /// aborted. S-P0-02: previously an unbounded spin — a predecessor
    /// wedged in validation blocked every dependent commit forever. Expiry
    /// is a typed validation-infrastructure error (the predecessor's
    /// verdict is UNKNOWN), which the commit path records as an unresolved
    /// obligation, never as an abort verdict.
    fn await_pending_status_commits(&self, sequence_number: SequenceNumber) -> Result<bool, DurabilityClientError> {
        // R-09: bounded by the SHORT predecessor deadline (see
        // crate::PREDECESSOR_WAIT_DEADLINE) — expiry is the typed
        // PredecessorWaitTimeout, an unresolved obligation, never an abort.
        self.await_pending_status_commits_within(
            sequence_number,
            crate::PREDECESSOR_WAIT_DEADLINE,
            crate::STORAGE_WAIT_REPORT_INTERVAL,
        )
    }

    fn await_pending_status_commits_within(
        &self,
        sequence_number: SequenceNumber,
        deadline: Duration,
        report_interval: Duration,
    ) -> Result<bool, DurabilityClientError> {
        debug_assert!(!matches!(self.get_status(sequence_number), CommitStatus::Empty));
        let mut wait = BoundedSpin::new("Pending", sequence_number, deadline, report_interval);
        loop {
            match self.get_status(sequence_number) {
                CommitStatus::Empty => unreachable!("Illegal state - commit status cannot move from pending to empty"),
                CommitStatus::Pending(_) => wait.tick()?,
                CommitStatus::Validated(_) | CommitStatus::Applied(_) => return Ok(true),
                CommitStatus::Aborted => return Ok(false),
            }
        }
    }

    fn get_readers(&self) -> u64 {
        self.readers.load(Ordering::Relaxed)
    }

    fn increment_readers(&self) {
        self.readers.fetch_add(1, Ordering::Relaxed);
    }

    fn decrement_readers(&self) -> u64 {
        self.readers.fetch_sub(1, Ordering::Relaxed) - 1 // Return the resulting number of readers
    }
}

#[derive(Debug)]
pub(crate) enum CommitStatus<'a> {
    Empty,
    Pending(MaybeOwns<'a, CommitRecord>),
    Validated(MaybeOwns<'a, CommitRecord>),
    Applied(MaybeOwns<'a, CommitRecord>),
    Aborted,
}

/// A predecessor commit's durable state as reconstructed from disk (R-02):
/// only the states the WAL can actually certify. `MissingStatus` means the
/// commit record exists but no status record certifies its verdict — the
/// caller must refuse with a typed error, never assume or panic.
#[derive(Debug)]
pub(crate) enum DiskCommitStatus {
    Applied(CommitRecord),
    Aborted,
    MissingStatus,
}

#[derive(Debug)]
enum SlotMarker {
    Empty,
    Pending,
    Validated,
    Applied,
    Aborted,
}

impl SlotMarker {
    const fn as_u8(&self) -> u8 {
        match self {
            SlotMarker::Empty => 0,
            SlotMarker::Pending => 1,
            SlotMarker::Validated => 2,
            SlotMarker::Applied => 3,
            SlotMarker::Aborted => 4,
        }
    }

    const fn from(value: u8) -> Self {
        match value {
            0 => SlotMarker::Empty,
            1 => SlotMarker::Pending,
            2 => SlotMarker::Validated,
            3 => SlotMarker::Applied,
            4 => SlotMarker::Aborted,
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        array,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        thread::{self, JoinHandle},
    };

    use assert as assert_true;

    use crate::{
        isolation_manager::{CommitStatus, ReaderDropGuard, TIMELINE_WINDOW_SIZE, Timeline},
        keyspace::{KeyspaceId, KeyspaceSet},
        record::{CommitRecord, CommitType},
        sequence_number::SequenceNumber,
        snapshot::{buffer::OperationsBuffer, snapshot_id::SnapshotId},
    };

    macro_rules! test_keyspace_set {
        {$($variant:ident => $id:literal : $name: literal),* $(,)?} => {
            #[derive(Clone, Copy)]
            enum TestKeyspaceSet { $($variant),* }
            impl KeyspaceSet for TestKeyspaceSet {
                fn iter() -> impl Iterator<Item = Self> { [$(Self::$variant),*].into_iter() }
                fn id(&self) -> KeyspaceId {
                    match *self { $(Self::$variant => KeyspaceId($id)),* }
                }
                fn name(&self) -> &'static str {
                    match *self { $(Self::$variant => $name),* }
                }
                fn prefix_length(&self) -> Option<usize> {
                    None
                }
            }
        };
    }

    test_keyspace_set! {
        Keyspace => 0: "keyspace",
    }

    struct MockTransaction {
        read_sequence_number: SequenceNumber,
        commit_sequence_number: SequenceNumber,
        reader_drop_guard: ReaderDropGuard,
    }

    impl MockTransaction {
        fn new(timeline: &Timeline, commit_sequence_number: SequenceNumber) -> MockTransaction {
            let read_sequence_number = timeline.watermark();
            let reader_drop_guard = timeline.record_reader(read_sequence_number);
            MockTransaction { read_sequence_number, commit_sequence_number, reader_drop_guard }
        }
    }

    fn create_timeline() -> Arc<Timeline> {
        Arc::new(Timeline::new(SequenceNumber::MIN.next()))
    }

    fn tx_start_commit(timeline: &Timeline, tx: &MockTransaction) {
        let window = timeline.get_or_create_window(tx.commit_sequence_number);
        window.insert_pending(tx.commit_sequence_number, _record(tx.read_sequence_number));
    }

    fn tx_finalise_commit_status(timeline: &Timeline, tx: MockTransaction, validation_result: bool) {
        let read_guard = tx.reader_drop_guard;
        let window = timeline.try_get_window(tx.commit_sequence_number).unwrap();
        if let CommitStatus::Pending(commit_record) = window.get_status(tx.commit_sequence_number) {
            if validation_result {
                window.set_validated(tx.commit_sequence_number);
                window.set_applied(tx.commit_sequence_number);
            } else {
                window.set_aborted(tx.commit_sequence_number);
            }
            let _sequence_number = commit_record.open_sequence_number();
            drop(window);
            drop(read_guard);
            timeline.may_increment_watermark(tx.commit_sequence_number);
        } else {
            unreachable!()
        }
    }

    fn _seq(from: u64) -> SequenceNumber {
        SequenceNumber::from(from)
    }

    fn _record(read_sequence_number: SequenceNumber) -> CommitRecord {
        CommitRecord::new(OperationsBuffer::new(), read_sequence_number, CommitType::Data, SnapshotId::new())
    }

    #[test]
    fn watermark_is_updated() {
        let timeline = &create_timeline();
        let tx1 = MockTransaction::new(&timeline, _seq(1));

        tx_start_commit(timeline, &tx1);
        let tx1_commit_sequence_number = tx1.commit_sequence_number;
        tx_finalise_commit_status(timeline, tx1, true);
        assert_eq!(tx1_commit_sequence_number, timeline.watermark());

        let tx2 = MockTransaction::new(&timeline, _seq(2));

        tx_start_commit(timeline, &tx2);
        let tx2_commit_sequence_number = tx2.commit_sequence_number;
        tx_finalise_commit_status(timeline, tx2, false);
        assert_eq!(tx2_commit_sequence_number, timeline.watermark());

        let tx3 = MockTransaction::new(&timeline, _seq(3));
        let tx4 = MockTransaction::new(&timeline, _seq(4));
        tx_start_commit(timeline, &tx3);
        tx_start_commit(timeline, &tx4);
        let tx4_commit_sequence_number = tx4.commit_sequence_number;
        tx_finalise_commit_status(timeline, tx4, true);
        assert_eq!(tx2_commit_sequence_number, timeline.watermark()); // tx3 is not yet committed, watermark does not move.
        tx_finalise_commit_status(timeline, tx3, true);
        assert_eq!(tx4_commit_sequence_number, timeline.watermark()); // Watermark goes up all the way to 4.
    }

    #[test]
    fn unused_windows_are_cleaned_up() {
        let timeline = &create_timeline();

        let tx_count = TIMELINE_WINDOW_SIZE + 2;
        for i in 1..tx_count {
            let tx = MockTransaction::new(&timeline, _seq(i as u64));
            tx_start_commit(timeline, &tx);
        }

        let stop_at = tx_count - 2;
        for i in 1..stop_at {
            let tx = MockTransaction::new(&timeline, _seq(i as u64));
            tx_finalise_commit_status(timeline, tx, true);
        }
        assert_true!(timeline.try_get_window(_seq(1)).is_some());
        for i in stop_at..tx_count {
            let tx = MockTransaction::new(&timeline, _seq(i as u64));
            tx_finalise_commit_status(timeline, tx, true);
        }
        assert_true!(timeline.try_get_window(_seq(1)).is_none());
    }

    #[test]
    fn watermark_keeps_window_pinned() {
        let timeline = create_timeline();
        let tx1 = MockTransaction::new(&timeline, _seq(1));
        tx_start_commit(&timeline, &tx1);
        let tx1_commit_sequence_number = tx1.commit_sequence_number;
        tx_finalise_commit_status(&timeline, tx1, true);

        let got_window = timeline.try_get_window(tx1_commit_sequence_number);
        assert_true!(got_window.is_some());
        drop(got_window);

        let mut i = tx1_commit_sequence_number + 1;
        while timeline.try_get_window(i).is_some() {
            let tx = MockTransaction::new(&timeline, i);
            tx_start_commit(&timeline, &tx);
            tx_finalise_commit_status(&timeline, tx, true);
            i += 1;
        }

        match timeline.try_get_window(timeline.watermark()) {
            Some(window) => assert_eq!(0, window.get_readers()),
            None => panic!(),
        };
    }

    #[test]
    fn test_highly_concurrent_correctness() {
        let timeline_and_counter = Arc::new((create_timeline(), AtomicU64::new(1)));
        const NUM_THREADS: usize = 32;
        const TRANSACTIONS_PER_THREAD: u64 = 1000;

        let join_handles: [JoinHandle<()>; NUM_THREADS] = array::from_fn(|_| {
            let timeline_and_counter = timeline_and_counter.clone();
            thread::spawn(move || {
                for _ in 0..TRANSACTIONS_PER_THREAD {
                    let (timeline, commit_sequence_number_counter) = &*timeline_and_counter;
                    let index = commit_sequence_number_counter.fetch_add(1, Ordering::SeqCst);
                    let tx = MockTransaction::new(&timeline, _seq(index));
                    tx_start_commit(timeline, &tx);
                    tx_finalise_commit_status(timeline, tx, true);
                }
            })
        });

        for join_handle in join_handles {
            join_handle.join().unwrap()
        }

        let expected_watermark = _seq(NUM_THREADS as u64 * TRANSACTIONS_PER_THREAD);
        let (timeline, _) = &*timeline_and_counter;
        assert_eq!(expected_watermark, timeline.watermark());
        let some_index_in_penultimate_window = expected_watermark - TIMELINE_WINDOW_SIZE - 1;
        timeline.may_free_windows();
        assert_true!(timeline.try_get_window(some_index_in_penultimate_window).is_none());
    }

    #[test]
    fn windows_are_dropped() {
        let timeline = create_timeline();
        // windows are verified as unused and dropped when the watermark moves onwards far enough

        for i in 1..TIMELINE_WINDOW_SIZE * 10 {
            let tx = MockTransaction::new(&timeline, _seq(i as u64));
            tx_start_commit(&timeline, &tx);
            tx_finalise_commit_status(&timeline, tx, true);
        }

        assert_eq!(timeline.window_count(), 1);
    }
}

#[cfg(test)]
mod predecessor_wait_tests {
    //! S-P0-02: the two predecessor waits on the commit-validation path are
    //! bounded and typed. Positive cases prove a predecessor that DOES
    //! transition is still observed exactly (Empty -> occupied, Pending ->
    //! validated/aborted); negative cases prove a predecessor that never
    //! transitions surfaces the typed `PredecessorWaitTimeout` within the
    //! injected deadline instead of spinning forever. Each bounded wait runs
    //! on a worker thread and its RESULT must arrive within a bound, so a
    //! mutant restoring the unbounded spin fails these tests rather than
    //! hanging them.

    use std::{
        sync::{Arc, mpsc},
        thread,
        time::Duration,
    };

    use resource::constants::storage::TIMELINE_WINDOW_SIZE;

    use super::TimelineWindow;
    use crate::{
        durability_client::DurabilityClientError,
        record::{CommitRecord, CommitType},
        sequence_number::SequenceNumber,
        snapshot::{buffer::OperationsBuffer, snapshot_id::SnapshotId},
    };

    fn window() -> Arc<TimelineWindow<TIMELINE_WINDOW_SIZE>> {
        Arc::new(TimelineWindow::new(SequenceNumber::new(1)))
    }

    fn record() -> CommitRecord {
        CommitRecord::new(OperationsBuffer::new(), SequenceNumber::new(0), CommitType::Data, SnapshotId::new())
    }

    const SHORT_DEADLINE: Duration = Duration::from_millis(200);
    const REPORT: Duration = Duration::from_millis(50);
    /// The wait's own deadline is 200ms; the test allows 10s for the result
    /// so only a genuinely unbounded wait can fail the arrival assertion.
    const RESULT_BOUND: Duration = Duration::from_secs(10);

    fn expect_timeout(outcome: Result<(), DurabilityClientError>, expected_state: &str) {
        match outcome {
            Err(DurabilityClientError::PredecessorWaitTimeout { state, .. }) => {
                assert_eq!(state, expected_state)
            }
            other => panic!("expected the typed PredecessorWaitTimeout for state '{expected_state}', got: {other:?}"),
        }
    }

    #[test]
    fn the_default_predecessor_wait_is_promptly_bounded_not_the_global_storage_deadline() {
        // R-09: the DEFAULT wait (no injected deadline) with a
        // never-resolving predecessor must return the typed timeout within
        // the short predecessor bound — never spin toward the global 600 s
        // storage deadline. This test runs the real default (~30 s), so a
        // mutant restoring STORAGE_WAIT_DEADLINE as the default fails it.
        assert_eq!(crate::PREDECESSOR_WAIT_DEADLINE, crate::STORAGE_WAIT_REPORT_INTERVAL, "reused, not invented");
        assert!(
            crate::PREDECESSOR_WAIT_DEADLINE.as_secs() * 10 <= crate::STORAGE_WAIT_DEADLINE.as_secs(),
            "the predecessor bound must be far below the global storage deadline"
        );

        let window = window();
        let (result_sender, result_receiver) = mpsc::channel();
        thread::spawn({
            let window = Arc::clone(&window);
            move || {
                let outcome = window.await_slot_occupied(SequenceNumber::new(1));
                let _ = result_sender.send(outcome);
            }
        });
        let outcome = result_receiver
            .recv_timeout(crate::PREDECESSOR_WAIT_DEADLINE + Duration::from_secs(30))
            .expect("the DEFAULT predecessor wait must expire within the short bound, not minutes");
        expect_timeout(outcome, "Empty");
    }

    #[test]
    fn an_empty_slot_that_never_fills_is_a_typed_timeout_within_the_deadline() {
        let window = window();
        let (result_sender, result_receiver) = mpsc::channel();
        thread::spawn({
            let window = Arc::clone(&window);
            move || {
                let outcome = window.await_slot_occupied_within(SequenceNumber::new(1), SHORT_DEADLINE, REPORT);
                let _ = result_sender.send(outcome);
            }
        });
        let outcome = result_receiver
            .recv_timeout(RESULT_BOUND)
            .expect("the bounded Empty wait must terminate by its deadline; an unbounded spin hangs here");
        expect_timeout(outcome, "Empty");
    }

    #[test]
    fn a_pending_predecessor_that_never_resolves_is_a_typed_timeout_within_the_deadline() {
        let window = window();
        window.insert_pending(SequenceNumber::new(1), record());
        let (result_sender, result_receiver) = mpsc::channel();
        thread::spawn({
            let window = Arc::clone(&window);
            move || {
                let outcome = window
                    .await_pending_status_commits_within(SequenceNumber::new(1), SHORT_DEADLINE, REPORT)
                    .map(|_| ());
                let _ = result_sender.send(outcome);
            }
        });
        let outcome = result_receiver
            .recv_timeout(RESULT_BOUND)
            .expect("the bounded Pending wait must terminate by its deadline; an unbounded spin hangs here");
        expect_timeout(outcome, "Pending");
    }

    #[test]
    fn a_predecessor_that_resolves_is_observed_exactly() {
        // Empty -> occupied: the waiter unblocks with Ok(()).
        let window = window();
        let filler = thread::spawn({
            let window = Arc::clone(&window);
            move || {
                thread::sleep(Duration::from_millis(20));
                window.insert_pending(SequenceNumber::new(1), record());
            }
        });
        window
            .await_slot_occupied_within(SequenceNumber::new(1), Duration::from_secs(30), REPORT)
            .expect("a slot that fills must be observed as occupied, not timed out");
        filler.join().unwrap();

        // Pending -> Validated: Ok(true).
        let validator = thread::spawn({
            let window = Arc::clone(&window);
            move || {
                thread::sleep(Duration::from_millis(20));
                window.set_validated(SequenceNumber::new(1));
            }
        });
        let validated = window
            .await_pending_status_commits_within(SequenceNumber::new(1), Duration::from_secs(30), REPORT)
            .expect("a resolving predecessor must not time out");
        assert!(validated, "a validated predecessor reports true");
        validator.join().unwrap();

        // Pending -> Aborted: Ok(false).
        let window = self::window();
        window.insert_pending(SequenceNumber::new(1), record());
        let aborter = thread::spawn({
            let window = Arc::clone(&window);
            move || {
                thread::sleep(Duration::from_millis(20));
                window.set_aborted(SequenceNumber::new(1));
            }
        });
        let validated = window
            .await_pending_status_commits_within(SequenceNumber::new(1), Duration::from_secs(30), REPORT)
            .expect("an aborting predecessor must not time out");
        assert!(!validated, "an aborted predecessor reports false");
        aborter.join().unwrap();
    }
}
