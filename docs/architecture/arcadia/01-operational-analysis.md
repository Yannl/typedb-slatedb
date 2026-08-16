# 1 — Operational Analysis

**Arcadia level:** OA. **Maturity:** stable.

What the stakeholders need to accomplish, described *without reference to any system*. Nothing
here mentions TypeDB, SlateDB or Cloudflare — that is the point of the level. If a statement
below stops being true when the chosen technology changes, it belongs in
[System Analysis](02-system-analysis.md) instead.

## Operational entities

| Entity | Nature | What they are trying to do |
|---|---|---|
| **Application developer** | human | Model a richly-typed, highly-connected domain and query it, without operating database infrastructure |
| **Operator** | human | Keep a data service available and affordable; recover it after failure |
| **Data steward** | human | Load, migrate and validate domain data; trust that what was written is what is read |
| **Conformance auditor** | human or automated | Establish that a change to the storage substrate did not alter query behaviour |
| **Upstream maintainer** | external org | Continue evolving the database independently of this programme |

The last two are easy to omit and both shape the architecture more than the first three.

## Operational capabilities

* **OC-1 — Model and query a typed graph.** Express entities, relations, attributes and rules;
  ask questions whose answers depend on the type system, not just on stored rows.
* **OC-2 — Persist durably across failure.** A write acknowledged as committed survives
  process death, host loss and restart.
* **OC-3 — Pay in proportion to use.** Idle domains cost near nothing; no always-on capacity
  is provisioned for a workload that is intermittent.
* **OC-4 — Operate without operating.** No cluster to size, patch or babysit.
* **OC-5 — Change the substrate without changing behaviour.** Replace how bytes are stored
  while every existing query keeps returning what it returned before.
* **OC-6 — Develop and diagnose locally.** Reproduce and debug real behaviour on a laptop,
  without a cloud account in the loop.

## Operational activities

```
                 ┌──────────────────────────────────┐
  Application    │  OA-1 define schema              │
  developer  ───▶│  OA-2 write data                 │
                 │  OA-3 query, reason over types   │
                 └──────────────┬───────────────────┘
                                │ depends on
                 ┌──────────────▼───────────────────┐
  Operator   ───▶│  OA-4 deploy a domain            │
                 │  OA-5 observe cost and health    │
                 │  OA-6 recover after failure      │
                 └──────────────────────────────────┘
  Data       ───▶│  OA-7 bulk load / migrate        │
  steward        │  OA-8 validate what was stored   │
                 └──────────────────────────────────┘
  Conformance ──▶│  OA-9 establish a behavioural    │
  auditor        │        baseline                  │
                 │  OA-10 compare a change against  │
                 │        that baseline             │
                 └──────────────────────────────────┘
```

## The tension this programme exists to resolve

OC-3 and OC-4 (pay-per-use, no operations) point at serverless, ephemeral compute with remote
storage. OC-1 and OC-2 (typed graph, durable) are historically served by a stateful process
with a local disk and local durability guarantees.

The whole programme is an attempt to satisfy both, and **OC-5 is what makes it tractable**:
rather than build a new database, change only where bytes live, and prove the change is
behaviour-preserving.

That proof obligation is not a nice-to-have downstream of the engineering — it is the
constraint that shapes everything, which is why the auditor is an operational entity here and
not an afterthought.

## Why OA-9/OA-10 are load-bearing

Establishing a baseline (OA-9) sounds procedural. In practice it is the activity that
determines whether OC-5 can ever be claimed:

* A baseline assumed rather than measured makes every later difference ambiguous.
  Concretely, the measured baseline found two upstream tests failing in a released tag, on WAL
  recovery — the exact subsystem the substrate change touches
  ([Phase B summary](../../evidence/phase-b/summary.md)). Assumed green, those would have
  been read later as damage caused by the change.
* A comparison (OA-10) is only as good as the denominator it runs over, which is why the
  system-level requirement is *enumerate every case*, not *run the tests*.

## Constraints from the operational context

| Constraint | Origin | Consequence |
|---|---|---|
| Upstream keeps evolving | independent org | The fork must minimise divergence and re-prove conformance per pin |
| Behaviour is defined by an executable corpus, not prose | upstream practice | Conformance is measurable, and its completeness is itself auditable |
| Intermittent workloads | OC-3 | Cold start and scale-to-zero are functional concerns, not tuning |
| Remote storage has different failure modes than local disk | physics | Durability semantics must be re-established, not assumed inherited |

The last row is the one most easily missed and is developed at
[System Analysis](02-system-analysis.md) and in
[ADR-0005](../ADR/0005-local-stack-and-dev-prod-parity.md).
