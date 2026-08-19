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

An earlier draft of this entry claimed the FULL feature-on suite was
`1940 passed; 0 failed`. That claim was wrong and is retracted here: the
full feature-on suite is **1566 passed / 420 failed**, and those failures
are correct behaviour, not breakage — see patch 0005 and the gate below.

## Patch 0005 — internal-epoch tests are unfenced-posture only (R5-STOR-04)

Test-only (`src/db.rs`), three `#[cfg(not(feature = "external_epoch_required"))]`
gates. Once the fence SHIPS, "run the whole upstream suite feature-on" has
an exact and unflattering answer, and it needs stating plainly:

  * **feature OFF, full suite: 1988 passed / 0 failed.** The fork does not
    change upstream semantics outside its patch series. This is the
    no-regression gate.
  * **feature ON, `db::builder`: 12 passed / 0 failed** (was 7/5). This is
    the exact set the round-5 audit measured; patch 0004 closes it.
  * **feature ON, full suite: 1566 passed / 420 failed.** Upstream opens
    databases through the epoch-less builder in hundreds of tests; under
    the shipped posture the fence refuses precisely those opens. Making
    them "pass" would mean rewriting upstream's suite into a different
    suite, which is not what a thin fork should do.

Three of the original 423 failures were NOT the fence refusing:
`test_writer_paused_in_replay_wal_should_be_fenced_by_concurrent_open`,
`wal_replay_not_found_should_be_fenced_when_writer_epoch_advanced`,
`wal_replay_not_found_should_remain_not_found_when_writer_epoch_unchanged`.
They assert INTERNAL writer-epoch allocation semantics — a second writer
auto-advancing the manifest epoch and fencing the first — and they failed
by TIMEOUT (a spawned writer was refused, so the WAL SST they waited for
never appeared), which is why the refusal text never reached their output.
Under the shipped posture internal allocation does not exist, so the
behaviour they describe is absent by design; they are now compiled only
for the unfenced posture, where they still guard upstream semantics.

The gate that keeps this honest is `tools/fork/check_strict_epoch_suite.py`:
it runs all three clauses and asserts that under the shipped posture EVERY
failing upstream test fails *because the fence refused an unauthorized
epoch-less open*, and for no other reason. One failure with a different
cause fails the gate — which is exactly how the three tests above were
found. Executed: `STRICT-EPOCH SUITE GATE: PASS` (1988/0 off, 12/0 builder
on, 420/420 failures accounted for as fence refusals).

(The feature-off suite has one fewer fenced test: `a_missing_external_epoch_
is_refused_not_defaulted` is `cfg(external_epoch_required)`. The one ignored
test is upstream's `g0_dirty_writes`, unchanged by this series.)
