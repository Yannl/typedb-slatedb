# SlateDB fork: patch ledger

**Base:** crates.io `slatedb 0.15.0`, sha256
`35ca56b01922b15aa69fe3abb62cadc985d86032c9647e4606e211c4da751a76`
(source-lock node `SL`).
**Form:** a patch series, not a vendored tree. `fork/slatedb/patches/*.patch`
plus `UPSTREAM-PROVENANCE` reconstruct the exact tree; `python3
tools/fork/materialize_slatedb.py --check` verifies it, and a fork edit that
is not re-recorded fails that check.
**Status:** F4/F5 implemented and tested; **NOT** the normative decision.
ADR-0012 stages this as one candidate. See
`docs/evidence/G3/slatedb-external-epoch-spike.json` for the decision-spike
record this implementation is evidence *for*, not evidence *of*.

## What upstream 0.15.0 already has — and the correction it forces

The staged design (`docs/design/slatedb-external-epochs.md`) assumed the
fork would have to build exact-epoch claiming from the
`FenceableTransactionalObject` primitives. That assumption is **wrong at
this pin, and the correction shrinks the fork substantially**:

`slatedb-txn-obj 0.15.0` already exports
`FenceableTransactionalObject::init_with_epoch(delegate, timeout, clock,
epoch, get_epoch, set_epoch)` as a **public** function with exactly the
semantics V16 inv. 78–80 require — `epoch <= stored_epoch` returns `Fenced`
*before any write*, otherwise the exact value is CAS-written through the
same conditional-put machinery. SlateDB already uses it internally for the
compactions object (`compactions_store.rs`, `compactor_state_protocols.rs`).

What is missing upstream is only the **wiring**: nothing routes a
caller-supplied epoch to the *manifest's* writer/compactor epochs, and the
builder has no knob for one. That is what this patch adds.

## Patch 0001 — external, controller-issued epochs

Five files, ~300 added lines of which roughly half are tests.

| File | Change |
|---|---|
| `src/manifest/store.rs` | `FenceableManifest::init_writer_with_epoch` and `init_compactor_with_epoch`: thin wrappers over the existing public `init_with_epoch`, binding it to `Manifest.writer_epoch` / `Manifest.compactor_epoch`. Plus the qualifying-matrix tests. |
| `src/fence.rs` | `WriterFencer` carries `external_writer_epoch: Option<u64>`; `fence()` claims it exactly when set. When unset **and** the `external_epoch_required` feature is on, open is refused — a fallback here is how a fail-closed posture silently becomes optional. |
| `src/db/builder.rs` | `DbBuilder::with_external_writer_epoch(u64)`, plumbed to the fencer. |
| `src/error.rs` | `SlateDBError::ExternalEpochRequired`, surfaced as an invalid-argument error: a misconfiguration, not a data or transient fault, so retrying the same open unchanged fails identically. |
| `Cargo.toml` | declares the `external_epoch_required` feature (empty; posture only). |

### Why the epoch cannot stay internally allocated

`init_writer` computes `stored + 1` from whatever this process last read.
That is observe-and-bind: the number is derived from an observation, so it
cannot compose with a controller that is separately fencing the same actor —
both allocators race and the manifest keeps whichever landed last. With an
external epoch the controller decides the number, and the manifest either
claims exactly it or refuses. Replaying a spent epoch is refused rather than
bumped over, which is the property that makes controller fencing and storage
fencing the *same* fence rather than two racing ones.

## Executed evidence

Toolchain `rustc 1.93.0`, `cargo test --lib --no-default-features --features
test-util manifest::store`:

```
test result: ok. 34 passed; 0 failed; 0 ignored   (29 upstream + 5 new)
  external_writer_epoch_is_claimed_exactly                          ok
  a_replayed_or_stale_external_epoch_is_refused_before_any_write     ok
  a_successor_external_epoch_fences_the_incumbent                    ok
  external_epochs_are_exact_beyond_the_double_precision_cliff        ok
  external_compactor_epoch_revokes_a_running_compactor               ok
```

`cargo check --lib --no-default-features --features
external_epoch_required` — compiles; the refusal branch is live.

**Mutant executed** — `init_writer_with_epoch` reverted to internal
`init` (observe-and-bind restored, the external argument ignored):

```
test result: FAILED. 31 passed; 3 failed
  external_writer_epoch_is_claimed_exactly                        FAILED
  a_replayed_or_stale_external_epoch_is_refused_before_any_write   FAILED
  external_epochs_are_exact_beyond_the_double_precision_cliff      FAILED
```

restored → 34 passed.

Note which two tests do **not** fail under that mutant: a successor still
fences an incumbent, and a compactor is still revoked by a newer epoch.
That is the honest reading — internal allocation gives you *mutual
exclusion*; only external issuance gives you mutual exclusion **under an
authority the controller chose**. The tests distinguish the two.

## What this patch does not do

- It does not decide ADR-0012. The directive requires an exact-pin decision
  spike comparing this minimal patch against a provider-enforced
  publication firewall over stock SlateDB; this is Candidate A implemented
  and measured, not the verdict.
- It does not wire the production lane. `sources/typedb` still consumes
  crates.io; activating the fork needs a `[patch.crates-io]` entry under a
  production-lane profile, which stays closed until the decision is made
  and G2 passes.
- It does not issue epochs. The controller side (allocating an exact u64 per
  writer incarnation and handing it to open) is the U3.2 integration.
- The compactor orchestrator still constructs its own fenceable manifest via
  `init_compactor`; only the manifest-level twin exists here. Wiring
  `with_external_compactor_epoch` through `CompactorBuilder` is the same
  shape and is deliberately left for the decision.

## Patch 0002 — bounded L0 SST upload retry (S-P0-01)

Two files. Upstream `upload_segment_sst` retried EVERY upload error forever,
and its only escape — shutdown — was conditioned on `wal_enabled`. Our
adapter disables the SlateDB WAL (TypeDB's WAL owns recovery), so a
prolonged object-store outage pinned the uploader, flush and close in a
silent infinite loop (the Q-13 hazard observed live in the Candidate B
spike run).

| File | Change |
|---|---|
| `src/memtable_flusher/uploader.rs` | The retry loop terminates on every path: shutdown gives up immediately **regardless of `wal_enabled`** (with the WAL off, recovery is the external WAL's job); non-`Unavailable` errors (fenced/data/internal/invalid/closed) are terminal on first sight (`upload_error_is_terminal`); `Unavailable` errors retry up to `UPLOAD_ATTEMPT_BUDGET` (8) attempts and then FAIL the flush with the typed exhaustion error, which propagates through the handler into the executor's closed result — the database fail-stops instead of hanging. Plus tests (below). |
| `src/error.rs` | `SlateDBError::L0SstUploadRetriesExhausted { attempts, last_error }`, surfaced as `ErrorKind::Unavailable` at the public boundary. |

Executed evidence (`cargo test --lib --no-default-features --features
test-util,wal_disable memtable_flusher::uploader`):

```
test result: ok. 13 passed; 0 failed        (10 upstream + 3 new)
  upload_fails_loudly_within_the_attempt_budget_when_the_store_keeps_failing  ok
  should_stop_retrying_on_shutdown_when_wal_disabled                          ok
  only_unavailable_upload_errors_are_retryable                                ok
```

The budget test asserts the CLOSED RESULT carries
`L0SstUploadRetriesExhausted { attempts: 8 }` within a 30 s ceiling against
a permanently failing store with the WAL off — the exact configuration that
upstream spins on forever. **Mutant executed** — the upstream loop restored
verbatim (no budget, escape re-conditioned on `wal_enabled`):

```
test result: FAILED. 0 passed; 2 failed
  should_stop_retrying_on_shutdown_when_wal_disabled                        FAILED
  upload_fails_loudly_within_the_attempt_budget_when_the_store_keeps_failing FAILED
```

restored → green. (The 8 pre-existing `db_cache_manager` failures under
`--no-default-features --features test-util,wal_disable` fail identically
on the unpatched tree — baseline-equal, unrelated to this patch.)

## Patch 0003 — external epochs proven through the ENFORCED path (S-P0-07)

Test-only (`src/db/builder.rs`). Patch 0001's qualifying matrix invoked the
private `FenceableManifest::init_*_with_epoch` helpers directly, so a
mutant that ignores the `DbBuilder` field — leaving production opens on
internal observe-and-bind allocation — could survive. These tests open real
databases through the PUBLIC `Db::builder`:

- `dbbuilder_stores_the_exact_external_writer_epoch` — epoch 7 (then
  successor 8) stored exactly where internal allocation would produce 1;
- `a_stale_external_epoch_is_refused_by_the_real_builder_before_any_write`
  — replaying 7/6/0 is typed `Closed(Fenced)` with the stored epoch
  untouched;
- `the_top_of_the_epoch_space_still_fences_exactly` — MAX-1 and MAX claimed
  exactly; every replay after MAX (MAX, MAX-1, 0) fenced: the fence cannot
  be climbed by wrapping;
- `a_missing_external_epoch_is_refused_not_defaulted`
  (`external_epoch_required`) — an epoch-less open is a typed `Invalid`
  refusal and the stored epoch does not advance. This EXECUTES the refusal
  branch that patch 0001 had only cargo-checked.

**Mutant executed** — `with_external_writer_epoch` ignores its argument
(the exact builder-field-ignored mutant the audit named as surviving
helper-only proof):

```
test result: FAILED. 0 passed; 3 failed
  dbbuilder_stores_the_exact_external_writer_epoch                            FAILED
  a_stale_external_epoch_is_refused_by_the_real_builder_before_any_write      FAILED
  the_top_of_the_epoch_space_still_fences_exactly                             FAILED
```

restored → green (34/34 `manifest::store`, 11/11 `db::builder::tests`
default posture; the 4 epoch tests also pass under
`external_epoch_required`).

Still not done here (unchanged from 0001's honest list): compactor
orchestrator wiring, fenced Admin/clone/checkpoint operations, controller
epoch issuance, production-lane activation.

## Patch 0004 — ordinary builder tests supply external epochs (R5-STOR-04)

Test-only (`src/db/builder.rs`), six one-line hunks. The round-5 audit found
the fork's own suite was not green under `external_epoch_required`: five
UPSTREAM builder tests (`test_db_builder_starts_gc_by_default`,
`…disables_gc_when_gc_options_are_none`,
`test_shared_recorder_registers_object_store_metrics_…`,
`test_object_store_cache_does_not_cache_metadata_store_reads`,
`test_settings_configured_object_store_cache`) open real databases without
an epoch, so the fence — correctly — refused them (7/12 feature-on). Each
now presents epoch 1 for its fresh database; the sixth hunk is the reopen
inside `test_settings_configured_object_store_cache`, which must present
the successor epoch 2 because replaying the spent 1 is exactly what the
fence refuses. No assertion changed: the tests verify GC/metrics/cache
behavior as before, now as an authorized actor.

This matters beyond hygiene: the feature is being promoted from opt-in to
SHIPPED (the TypeDB `storage` crate now enables
`slatedb/external_epoch_required` unconditionally on its dependency —
`fork/typedb/storage/Cargo.toml` — attested by
`tools/fork/check_strict_epoch.py`), so feature-on is the configuration
that ships and its suite must be the green one.

Executed evidence (`rustc 1.93.0`, in the materialised fork):

```
cargo test --lib --features test-util,external_epoch_required db::builder
  test result: ok. 12 passed; 0 failed          (was 7 passed; 5 failed)
```

Two claims about the FULL feature-on suite have been made in this entry and
both are now retired; the retractions stay on the record.

* An early draft claimed `1940 passed; 0 failed`. That was simply wrong.
* The round-5 entry then recorded **1566 passed / 420 failed** and argued
  the failures were "correct behaviour, not breakage". The arithmetic was
  right; the conclusion was not. Those 420 tests were refused during an
  epoch-less OPEN, so their bodies never exercised reads, writes,
  compaction, manifest handling, recovery, GC, concurrency or fault
  behaviour under the feature that ships. Round 6 (R6-FORK-01) named it —
  "calling the final result a suite PASS invites false qualification" — and
  patch 0006 fixes it rather than re-describing it. The current number is
  **1993 passed / 0 failed**.

Patch 0004's six explicit epochs are now redundant with patch 0006's harness
issuer, which would supply them anyway. They are kept deliberately: an epoch
a test states is better documentation than one it inherits, and the issuer
only ever fills in for opens that name nothing.

## Patch 0005 — WITHDRAWN (number not reused)

Patch 0005 compiled three upstream tests
(`test_writer_paused_in_replay_wal_should_be_fenced_by_concurrent_open`,
`wal_replay_not_found_should_be_fenced_when_writer_epoch_advanced`,
`wal_replay_not_found_should_remain_not_found_when_writer_epoch_unchanged`)
only for the unfenced posture, on the reasoning that they assert INTERNAL
writer-epoch allocation and so describe behaviour that is "absent by design"
once the fence ships.

Re-measured with patch 0006's harness controller in place, **all three
pass feature-on**. The exclusion was premature. What those tests actually
assert is that a second writer holding a HIGHER epoch fences the incumbent
and that WAL replay resolves accordingly — which is equally true of
controller-issued epochs. They failed in round 5 by timeout only because
the second writer was refused at open, so the WAL SST the first waited on
never appeared. The harness issues epoch 1 then 2 for the same database:
exactly the values those tests assert.

The patch file is deleted. The number is deliberately **not reused**, so the
round-5 record (`docs/ledger/gates.json`,
`docs/reviews/deep-audit-2026-08-19-round5-response.md`) keeps pointing at
the thing it described rather than at different content.

## Patch 0006 — the upstream suite EXECUTES under the shipped fence (R6-FORK-01)

Four files, test-and-refusal only; no change to the epoch protocol itself.

| File | Change |
|---|---|
| `src/db/builder.rs` | `mod test_epoch_issuer` (`cfg(all(test, feature = "external_epoch_required"))`): a per-database, monotonic epoch issuer standing in for the controller. `build()` resolves the epoch through it, so an open that names none is ISSUED one instead of refused. Plus `without_controller_issued_epoch()` (test-only) to opt out, and the early refusal below. |
| `src/db/builder.rs` | `build()` now refuses an unauthorized open **before creating anything**, not just before claiming an epoch (see "what the negative suite found"). |
| `src/fence.rs` | `WriterFencerTestHarness::take_fencer()` hands the raw fencer a controller-issued epoch at the moment the test fences, which is what those tests' ordering requires. Plus the fencer-level negative test. |
| `src/clone.rs` | A clone manifest INHERITS its parent's writer epoch, so the issuer inherits the parent's high-water for the clone's path. Test-only; a real controller has the same obligation. |
| `src/error.rs` | one-line `dead_code` allow so the unfenced build is warning-clean. |
| `src/manifest/store.rs` | two `dead_code` allows: with the fence compiled in, `init_writer` (internal allocation) and `init_compactor_with_epoch` have no non-test caller, and the SHIPPED build was emitting warnings for them. |
| `tests/common/mod.rs` (new) + the four integration targets | the integration targets compile against the SHIPPED library, so the `cfg(test)` seam is invisible to them; they name their epochs through the PUBLIC `with_external_writer_epoch`, fed by the same deterministic per-database sequence. |

### Why a seam and not 420 edits

277 call sites in the crate open a database, and the audit's remedy is
explicitly "adapt upstream test helpers", not "rewrite upstream's suite".
The whole adaptation is therefore ONE decision point in `DbBuilder::build`
plus two ordering hooks (the raw fencer, and clone inheritance). Upstream's
tests are unmodified: no assertion, no expectation and no test name changed.

The issuer is **not** a fallback to upstream's `stored + 1`. It never reads
the manifest. It is a controller: it decides the number from its own
sequence, and the manifest still claims exactly that number or refuses. The
Nth open of a given database in a process claims epoch N — deterministic
per database, so tests that assert exact epochs (1 for the first writer, 2
for the writer that fences it) keep asserting exactly that. An epoch a test
supplies itself is never overridden, only OBSERVED, so explicit and issued
epochs compose into one monotonic sequence per database.

The seam is `cfg(test)`. It cannot exist in the shipped library: TypeDB's
`storage` crate consumes `slatedb` as a dependency, where `cfg(test)` is
off and `None` is still a refusal. `tools/fork/check_strict_epoch.py`
attests the feature is resolved into the ordinary build; the negative suite
below attests the refusal is still live.

That `cfg(test)` boundary has a consequence worth stating rather than
discovering later: it does NOT reach the crate's four INTEGRATION targets
(`tests/*.rs`), which are separate crates compiling against the shipped
library — exactly the posture a consumer is in. Round 5 never measured them.
They are 19 tests, and every one of them opened a database with no epoch, so
under the shipped fence they would all have been refused. They are adapted
here the honest way, through the public API: `tests/common/mod.rs` supplies
the same deterministic per-database sequence and each open names its epoch.
The gate now runs `--tests`, not `--lib`, so both kinds of target are inside
it.

### What the negative suite found

`negative_fence_an_epoch_less_open_creates_no_database` was written to assert
that a refused first open leaves nothing behind. It FAILED: upstream's
`build()` creates the database (a manifest at writer epoch 0) and only then
reaches the fencer, so an unauthorized client could create empty databases
it could never write to. Patch 0006 moves the refusal to the top of
`build()`. The fencer's own refusal is deliberately KEPT — it is reachable
from other callers, and `negative_fence_the_fencer_refuses_an_unnamed_epoch`
executes it directly so the deeper branch does not go dark.

### Executed evidence

Toolchain `rustc 1.93.0`, in the materialised fork.

```
cargo test --lib --features test-util
  test result: ok. 1988 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out

cargo test --lib --features test-util,external_epoch_required
  test result: ok. 1993 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out

cargo test --lib --features test-util,external_epoch_required negative_fence_
  test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 1989 filtered out
```

1989 leaves execute feature-off (1988 + the one upstream `ignored` test,
`g0_dirty_writes`). 1994 execute feature-on: the same 1989 **plus** the five
`cfg(external_epoch_required)` negative tests. The gate reconciles executed
leaf IDENTITIES, not counts, so the 420 formerly-refused bodies are proven to
have run by name.

**Exclusions: none.** Every test that executes feature-off also executes
feature-on. This is the measured result; the gate fails if a future change
makes it untrue and the omission is not enumerated with a reviewed reason.

### Mutants executed

*Fail-closed becomes optional* — the early refusal deleted AND the fencer's
`None` arm reverted to upstream's internal `init_writer`:

```
test result: FAILED. 2 passed; 3 failed
  negative_fence_a_missing_external_epoch_is_refused_not_defaulted  FAILED
  negative_fence_an_epoch_less_open_creates_no_database             FAILED
  negative_fence_the_fencer_refuses_an_unnamed_epoch                FAILED
```

*The harness reuses one epoch instead of issuing a successor* (`issue()`
returns a constant 1) — this is the mutant that would make the adapted
suite a sham, since a harness that hands every open the same number is not
a controller:

```
cargo test --lib --features test-util,external_epoch_required negative_fence_
  test result: FAILED. 4 passed; 1 failed
    negative_fence_harness_epochs_are_exact_and_monotonic_per_database FAILED

cargo test --lib --features test-util,external_epoch_required clone::tests
  test result: FAILED. 10 passed; 5 failed
```

The five upstream `clone::tests` failures matter more than the negative one:
they are unmodified upstream bodies, and they die because the epochs they
run on stopped being successors. That is the direct witness that those
bodies genuinely execute through the external-epoch path rather than merely
compiling. The FULL feature-on suite under this mutant does not fail fast —
it HANGS (writers fenced by a replayed epoch leave later assertions waiting)
and was aborted after ~6 minutes against a 46 s green baseline; the two runs
above are the deterministic kills. Both mutants reverted → green.

(The "builder field ignored" and "internal allocation restored" mutants for
the epoch protocol itself remain as executed under patches 0001 and 0003.)

## The gate: `tools/fork/check_strict_epoch_suite.py`

Reworked for R6-FORK-01, because the round-5 version's PASS did not mean
what a reader would assume. It used to run the feature-on suite, parse every
failure, and pass if each failure carried the expected refusal text. That
invariant earned its keep — it is how the three round-5 regressions were
found — but it let 1566/420 be reported as a suite PASS.

The gate now passes only when all four clauses hold:

1. **feature OFF, full suite fully green** — the upstream-regression oracle.
2. **feature ON, full suite fully green.** Not "green except expected
   refusals". A fence refusal here is now a FAILURE, reported as "an open
   with no epoch was not covered by the harness seam", not as an expectation.
3. **the negative fence suite green and matching its declared membership** —
   a test that quietly stops being part of the negative suite fails the gate.
4. **leaf reconciliation** — every leaf executed feature-off also executes
   feature-on, except names enumerated in `EXCLUSIONS` with a reviewed
   reason; every leaf executed feature-on but not feature-off is enumerated
   in `FEATURE_ON_ONLY`. A STALE exclusion (a name that does execute) fails
   the gate too, so the list cannot rot into a silent skip list.

`--quick` is the PR tier CI already runs (`.github/workflows/gates.yml`). It
is materially stronger than before without costing more: clause 2 — the
feature-on FULL suite, green — is exactly the "add the feature-on full suite
to CI" that R6-FORK-01 asks for, and `--quick` runs it in full along with the
negative suite. What it skips is the feature-off oracle and (consequently)
the leaf reconciliation, so its verdict is `PARTIAL` and names what it did
not prove. Only a full run prints `PASS`. The CI step's own comment still
describes the old `--quick` shape ("feature-on builder tests + the
fence-cause invariant") and should be updated by the workflow owner; no
tier-2 job running this gate WITHOUT `--quick` exists in that workflow yet.

`--evidence PATH` writes the executed leaf identities and counts as JSON,
which is the "record executed leaf identities" the audit asked for.

Executed (`python3 tools/fork/check_strict_epoch_suite.py`):

```
feature-OFF  full suite  : 1988 passed, 0 failed, 1 ignored (1989 leaves executed)
feature-ON   full suite  : 1993 passed, 0 failed, 1 ignored (1994 leaves executed)
feature-ON   negative suite: 5 passed, 0 failed (5 leaves executed)
leaf reconciliation      : feature-off 1989 - 0 excluded + 5 shipped-posture-only = 1994 vs feature-on 1994 executed
exclusions               : none — every test executed feature-off also executes feature-on
STRICT-EPOCH SUITE GATE: PASS
```

Two things the gate's own development is worth recording, because both are
the same failure mode this finding is about — a number that looks like
evidence and is not:

* An earlier draft parsed `test NAME ... ok` and silently dropped the 22
  `#[should_panic]` tests, which render as `test NAME - should panic ... ok`.
  Reconciliation would have compared 1967 against 1972 and still "balanced".
  The gate now also asserts `passed + failed + ignored == leaves parsed` and
  fails when the two disagree.
* A run on a contended machine produced NO `test result:` line at all, which
  the first draft rendered as "0 passed, 0 failed". The gate now reports a
  run that never measured anything as exactly that, with the output tail.

## What this series still does not do

Unchanged from patches 0001/0003, and still true:

- It does not decide ADR-0012.
- It does not wire the production lane's `[patch.crates-io]` entry.
- It does not issue epochs in production. The controller side (allocating an
  exact u64 per writer incarnation) is the U3.2 integration; the harness
  issuer added here is `cfg(test)` and is not that.
- The compactor orchestrator still constructs its own fenceable manifest via
  `init_compactor`; `with_external_compactor_epoch` through `CompactorBuilder`
  is still deliberately left for the decision.
- Doc-tests are not in the gate. `cargo test --doc` builds the rustdoc
  examples, which open databases with no epoch and are documentation of the
  UNFENCED public API; adapting them would change what the published docs
  show. They are the one target class still unmeasured under the fence, and
  they are named here rather than left to be found.
