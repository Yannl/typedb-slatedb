# ADR-0008 — The pinned upstream test corpus is the conformance oracle; upstream defects get corrected expectations, never edits

**Status:** accepted (brief §5.10; operative across G1 baselines and the U2 sweep)

## Context

"The backend swap changes nothing" is the product's core promise. Options
for substantiating it: hand-written compatibility suites (measure what we
thought of), differential fuzzing (strong but unanchored to user-visible
behavior), or **running the complete upstream test corpus of the pinned
TypeDB commit against every backend and requiring result equality with
the RocksDB oracle lane**.

The corpus is machine-enumerated (no hand-asserted counts): discovery
parses cargo's compiler artifacts, and the runner reproduces Bazel
execution semantics (serial groups, isolated cwds, assembly-archive mode,
env, stacks). Two hazards shaped the policy:

1. **Discovery integrity is itself load-bearing.** A cargo package-id
   parsing defect collapsed most workspace crates onto one key and the
   dedupe silently dropped two executables from every early baseline —
   found by review, fixed, and the denominator grew from 104 to 106. A
   silent hole in the denominator falsifies every parity claim built on
   it.
2. **Upstream tests are not all sound.** Three defects surfaced at the
   pin: two `todo!()` stubs that fail on every backend; a fail-points
   harness racing its own fixed HTTP port; and a benchmark that queries a
   database whose storage directory its own setup deleted (passing on
   RocksDB only via POSIX unlink-while-open file descriptors — semantics
   no object-store engine, including production R2, can provide).

## Decision

- Backend parity is measured **structurally against the oracle baseline**:
  identical pass/fail/ignored profiles per target, full-corpus, zero
  tolerance for new failures and zero skipping/quarantining to get green.
- Upstream test files are **never edited** (port-ledger contract). A test
  proven defective gets a **corrected expectation**: a finding document
  with a deterministic bracket isolating the defect (e.g. the deleted-dir
  benchmark passes 2/2 on SlateDB the moment the directory survives), and
  the target is carried at that expectation for every lane.
- Discovery and runner defects are stop-the-line: fixed before any run
  whose numbers they would taint, and the denominator change is recorded
  in the comparison evidence.

## Consequences

- The U2 claim is precise: 106 executables, structural equality with the
  oracle everywhere except the documented upstream defects — and one
  strict improvement (fail-points passed on U2 where the oracle trips the
  port race).
- Corrected expectations are auditable artifacts, not tribal knowledge;
  each names the defect mechanism and the experiment that proves it.
- The cost is honesty about red: the dashboard shows real upstream
  failures instead of a doctored 100%, and every future lane (U3/U4)
  inherits the same corrected expectations explicitly.
