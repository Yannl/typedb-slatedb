# Finding: U0 baseline `test_fail_points` PASS was a false green (environment poisoning)

## Statement

The U0 baseline entry `typedb_server_bin:test_fail_points — 2 passed, 84.24s`
(pass2-fixedenv) is **invalid**. It was produced while a zombie
`typedb_server_bin` process (leaked by an earlier, mid-run-crashed pass-2
invocation; alive roughly 01:5x–02:24 session time) owned port 1729. The U1
full-sweep timeout on the same target is **not a fork regression** — it is the
first clean-environment measurement of the test's true runtime semantics.

## Mechanism of the false green

`tests/assembly/fail_points.rs::start_server_with_env` boots a server on port
1729 and probes readiness with a plain TCP connect. With the zombie holding
1729:

1. each failpoint-configured server crashed instantly on bind conflict;
2. the TCP readiness probe connected to the **zombie** and declared "started";
3. every console command talked to the zombie (which had **no** failpoints
   configured) and succeeded immediately;
4. `WaitForCheckpoint` (`wait_process_timeout`) returned instantly because the
   *watched* process (the bind-crashed server) was already dead;
5. `try_wait()` showed a crash, `assert_boots` connected to the zombie → PASS.

Every iteration therefore completed in ~1.5s regardless of failpoint
semantics — 22 failpoints × 2 tests + 2 archive extractions ≈ 84s. This is the
same zombie that poisoned `test_assembly` at 02:23 (WAL NotFound panic when
its deleted data dir was hit), documented in the U0 baseline notes.

## True (clean-environment) semantics, derived from the pinned code

- `fail_point!` is active in dev builds (`#[cfg(debug_assertions)]`).
- Checkpoint-class failpoints (7 of 22: `CHECKPOINT_*`, `UNFINISHED_CHECKPOINT`)
  are only evaluated when a checkpoint actually runs. `make_checkpoint_fn`
  checkpoints only when the watermark advanced; the per-database
  `IntervalRunner` ticks every `CHECKPOINT_INTERVAL = 60s` (create: immediate
  first tick, but watermark is still MIN then; load: first tick delayed a full
  interval). `CHECKPOINT_CLEANUP_PARTIAL_FAIL` additionally requires a
  *previous* checkpoint to exist.
- Therefore `test_fail_point_always` needs ~60–125s per checkpoint-class
  failpoint (observed live in a controlled reproduction: failpoint #10 reached
  at ~7m45s), and `test_fail_point_chance`
  (`90%5*print->panic`, ≤10 restarts × 6 runs × two 60s waits) can
  legitimately consume hours.
- Upstream itself declares `timeout = "eternal"` (Bazel: 3600s) for this
  target; the conformance runner's 1800s default was tighter than upstream's
  own ceiling.

## Fork implication: none

- The servers under test come from the assembly archive containing U0-era
  (pre-TB-patch) binaries.
- The harness's decision path uses only `fail_point::ALL`,
  `CHECKPOINT_INTERVAL` (both from unpatched crates) and process/TCP
  primitives.
- The full-corpus U1 sweep shows per-case structured equality with U0
  everywhere else (102/104 green; `test_recovery` red carried).

## Corrections applied

1. U0 baseline annotated: `test_fail_points` reclassified
   PASS → FALSE-GREEN-ENVIRONMENT-POISONED (this document is the evidence).
2. Runner timeout for this target corrected to the upstream Bazel ceiling
   (3600s), and a clean re-measurement launched
   (`docs/evidence/G3/failpoints-remeasure/`) to record the true U0-equivalent
   behavior at the pin. Its outcome (green within 3600s, or over-limit even at
   upstream's own ceiling) becomes the corrected baseline expectation for
   U1+ equality.
3. The stray-server reaping added to the runner during pass 2 (pre/post
   assembly-family pkill of `typedb-extracted/` trees) is the guard that
   prevents recurrence of this poisoning class.
4. No retry-green: the U1 timeout stands in the record; the corrected
   expectation comes from the re-measurement, not from rerunning until green.

## Addendum: clean re-measurement outcome (upstream ceiling, 3600s)

Result (`failpoints-remeasure/u0-results.json`): **FAIL in 1753s** —
`test_fail_point_chance` PASSED; `test_fail_point_always` FAILED with:

    Server process crashed for an unrelated reason:
    Exited with error: [SRO18] Could not serve HTTP on 0.0.0.0:8000.
    Cause: Os { AddrInUse }

Diagnosis: a second upstream harness defect. `build_server_cmd` varies the
gRPC port on retry (`--server.address=0.0.0.0:{port}`) but the HTTP listener
is always `0.0.0.0:8000`; consecutive server boots inside one test race on
that fixed port, and `start_server_with_env` treats the resulting AddrInUse
as an "unrelated" crash and panics. Ports 8000/1729 were verified free of
any non-test process (serial runner, stray reaping active), so the collision
was strictly between the test's own consecutive boots.

## Corrected baseline expectation

`typedb_server_bin:test_fail_points` at the pin =
**PRE-EXISTING-UPSTREAM-UNRELIABLE**, on two independent grounds:
1. fixed HTTP port 8000 across in-test server reboots → nondeterministic
   AddrInUse panic (observed in the clean re-measurement);
2. true runtime (~29min observed for the two tests; checkpoint-class
   failpoints inherently 60–125s each) rides near CI budgets.

Carried forward like the `test_recovery` todo!() pair: U1+ equality for this
target is measured structurally against this corrected expectation, not
against the poisoned 84s green. A fix (per-iteration HTTP port) would be an
upstream-test edit and is therefore deferred to the port ledger if ever
needed; the fork does not modify upstream tests.
