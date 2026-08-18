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
