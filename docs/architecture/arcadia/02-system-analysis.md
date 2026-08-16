# 2 — System Analysis

**Arcadia level:** SA. **Maturity:** stable.

The system as a **black box**: what it must do, and what crosses its boundary. Still no
internal structure and no technology — those are levels 3 and 4.

The system under consideration is deliberately drawn wider than the database. It is
*"a typed graph database service, plus the means to prove its behaviour did not change"*,
because [OC-5](01-operational-analysis.md) cannot be satisfied by a database alone.

## System boundary

```
        ┌─────────────────────────── SYSTEM ───────────────────────────┐
        │                                                              │
  ─────▶│  SF-1  accept and validate schema                            │
 client │  SF-2  accept writes, acknowledge only when durable          │
  ◀─────│  SF-3  answer queries consistently with the type system      │
        │  SF-4  persist state to durable storage                      │
        │  SF-5  recover state after abrupt termination                │
        │  SF-6  start on demand, release resources when idle          │
        │  SF-7  authenticate and authorise                            │
        │                                                              │
        │  SF-8  enumerate every behavioural case the system claims    │
        │  SF-9  execute that enumeration and classify every outcome   │
        │  SF-10 compare two executions and account for every case     │
        └──────────────────────────────────────────────────────────────┘
             ▲                    ▲                      ▲
      durable storage      execution platform     upstream corpus
        (actor)                (actor)                (actor)
```

## Actors at the boundary

| Actor | Direction | What crosses |
|---|---|---|
| **Client** | in/out | Schema, queries, results, errors, credentials |
| **Durable storage** | out/in | Object read/write; failure and latency behaviour differing materially from local disk |
| **Execution platform** | in/out | Lifecycle: start, idle, terminate; resource limits |
| **Upstream corpus** | in | The executable definition of correct behaviour, at a pinned revision |
| **Operator/CI** | in/out | Deployment triggers; evidence out |

Treating **durable storage** and the **execution platform** as *actors* rather than internals
is the load-bearing modelling choice. Both can fail, both impose semantics the system does not
control, and both are replaceable — which is exactly what levels 3 and 4 then have to absorb.

## System functions, with their real obligations

### SF-2 / SF-4 / SF-5 — durability

The obligation is not "write to storage". It is: **an acknowledgement must not precede
durability**, and **recovery must reconstruct exactly the acknowledged state**.

This is where the substrate change bites. It is also where the measured baseline found the
upstream corpus is *weakest*: `storage/tests/test_recovery.rs` L64-74 declares
`wal_missing_records_for_checkpoint_replay_fails` and `wal_missing_records_entire_replay_fails`
with bare `todo!()` bodies — two WAL-recovery tests that fail wherever they run.

So SF-5 is a function whose upstream verification is *known incomplete*. Any claim that
recovery behaviour is unchanged rests on a corpus that does not fully test recovery. That is a
system-level fact, not a testing detail, and it should drive additional verification rather
than being inherited silently.

### SF-6 — on-demand lifecycle

Implies the system may be stopped between any two requests and must resume correctly. This
converts what would be a deployment concern into a functional requirement on SF-4/SF-5.

### SF-8/SF-9/SF-10 — the conformance functions

These are system functions, not tooling, because [OC-5](01-operational-analysis.md) is a
capability the system must deliver.

* **SF-8 must enumerate, not sample.** The denominator is generated from the pinned corpus:
  258 targets and 4 757 leaf cases, with each Cucumber scenario and each failpoint counted
  individually rather than as one opaque case per harness.
* **SF-9 must classify every outcome.** Anything unreadable is `Unknown`, never a pass.
* **SF-10 must account for every case.** Executed + skipped + failed must reconcile to the
  denominator, and a reported case absent from the denominator is itself a failure.

Rationale and the twelve defects this strictness caught are in
[ADR-0003](../ADR/0003-conformance-runner-no-false-green.md) and the
[Phase B summary](../../evidence/phase-b/summary.md).

## Capability → function traceability

| Capability | Functions | Verification status |
|---|---|---|
| OC-1 model and query | SF-1, SF-3, SF-7 | measured: 4 158 behaviour scenarios pass at baseline |
| OC-2 durable persistence | SF-2, SF-4, SF-5 | **partial**: 44 failpoint cases pass; 2 WAL-recovery tests are `todo!()` upstream |
| OC-3 pay per use | SF-6 | not yet verifiable — no deployment exists |
| OC-4 no operations | SF-6, SF-7 | not yet verifiable |
| OC-5 substrate change is invisible | SF-8, SF-9, SF-10 | baseline established; comparison not yet possible |
| OC-6 local development | SF-6 + platform actor | planned, [ADR-0005](../ADR/0005-local-stack-and-dev-prod-parity.md) |

## Non-functional constraints

| Constraint | Statement | Status |
|---|---|---|
| **NFC-1** | Query semantics must be identical before and after the substrate change | the central claim; measurable via SF-8..10 |
| **NFC-2** | Upstream test sources are not edited to make them pass | held: fixtures are staged externally, no source patched |
| **NFC-3** | Build inputs are pinned and digested, including native toolchain | held: [`native-toolchain.json`](../../evidence/phase-a/native-toolchain.json) |
| **NFC-4** | Evidence records commands and digests, not narrative | held: per-phase manifests |
| **NFC-5** | Absence of a result is never reported as success | held, and enforced in code |

NFC-5 is the one that repeatedly paid: it is what made twelve harness defects visible instead
of producing a clean-looking baseline over 12 % of the corpus.
