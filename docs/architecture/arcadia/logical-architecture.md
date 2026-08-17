# Logical Architecture (LA)

*Arcadia perspective 3 — how the system works: logical components,
their interfaces, and the allocation of system functions (SF1–SF9 from
[system-analysis.md](system-analysis.md)) onto them. Technology choices
belong to the physical architecture.*

## The four planes (authority separation)

Every logical component lives in exactly one plane, and authority never
leaks across planes:

1. **Transaction plane** — the WAL's record sequence is the only
   authoritative history; commit outcomes are deterministic resolution
   over it. No cache, controller row, or storage manifest is commit
   authority.
2. **Materialisation plane** — keyspace state is replayable physical
   state; losing it loses nothing (ADR-0003).
3. **Control plane** — sessions, fencing, finalisation, admission,
   outbox: the write-authority arbiter for distributed modes.
4. **Build/proof plane** — catalogue, runners, models, lint: produces the
   evidence that the other planes obey their contracts (ADR-0008/0010).

## Logical components and allocated functions

### Transaction & materialisation planes (the database node)

| Component | Allocated | Responsibility |
|---|---|---|
| **Query Engine** (parse/compile/plan/execute) | SF1 | TypeQL semantics; upstream logic, untouched |
| **MVCC Storage** | SF1, SF3 | versioned keys (`key+seq+op`), snapshot reads at an open sequence, isolation validation |
| **Durability Client** | SF2 | append transaction intent, sync barriers, bounded replay iteration |
| **Storage Factory** | mode selection | resolves the storage profile once per process; typed refusal of unknown/unavailable modes (ADR-0002) |
| **Keyspace Engine** (abstract) | SF3, SF4 | ordered KV per keyspace: put/get/floor-read, atomic put-only batch, forward cursor (seek/advance/read-in-place), checkpoint-to-directory, reset/delete/estimates |
| **Recovery Manager** | SF4 | checkpoint write (per-keyspace + watermark metadata, atomic promotion) and restore (file sync + WAL roll-forward; fail-closed if the log is behind the checkpoint) |

The **Keyspace Engine interface** is the system's load-bearing seam: two
realisations (oracle and object-store) must be observationally equal
beneath MVCC. Its non-obvious contract points, each corpus- or
regression-pinned:

- floor read (`get_prev`) returns the last entry ≤ key — exactly;
- an empty batch is a no-op success;
- cursors are pooled **per snapshot**, so a recycled cursor's view is
  always at least as fresh as its snapshot's open point — MVCC sequence
  filtering above makes that sufficient;
- engine failures surface as typed errors; where a signature cannot carry
  one (floor read), the engine fails closed rather than reporting absence.

### Control plane

| Component | Allocated | Responsibility |
|---|---|---|
| **Session Registry / Fencing** | SF5 | per (database, generation) sessions; fencing is terminal; *every* response to a fenced session is the typed fenced error — checked **before** replay (ADR-0006) |
| **Finalisation Procedure** | SF2 (remote), SF5 | one atomic step: fence check → exact-once replay by operation id → status-singleton dedupe → admission budgets → allocation (contiguous LSN, monotone type-sequence, control-seq) → outbox insert; batches all-or-nothing |
| **Payload Data Path** | SF6 | content upload separate from control; conditional create-or-identical (ADR-0007); digest verification precedes finalisation |
| **Outbox** | SF7 | ordered by control-seq; at-least-once peek/ack; idempotent duplicate ack; drain exactly-once per control-seq |
| **Deterministic Reducer** | proof of SF2/SF7 | pure fold over published events; must reproduce the procedure's projection exactly (trace equivalence, contiguity enforced) |

### Build/proof plane

| Component | Allocated | Responsibility |
|---|---|---|
| **Corpus Catalogue & Runner** | SF8 | machine-enumerated denominator; Bazel-equivalent execution semantics; per-target structural results |
| **Reference Lanes** | SF8 | pure protocol models (WAL, fencing/epoch CAS, command ledger, outbox) with exhaustive schedules and mutant negative controls; deterministic spike controller; all trace-equal to the production procedure |
| **Source-Lock Lint** | SF8 precondition | every proof-critical input pinned and mechanically verified (ADR-0010) |
| **Platform Probes / G2 matrix** | SF9 | platform-fact measurement plans, runnable when credentials exist |

## Key logical interfaces

- **MVCC ↔ Keyspace Engine**: the seam above (`KeyspaceSet`, batch, cursor
  contracts).
- **Server ↔ Durability**: `DurabilityClient` (append / sync-barrier /
  iterate-snapshot); realised by the file WAL today, the remote protocol
  in U3/U4 — same interface, which is what makes the mode ladder safe.
- **Client ↔ Control plane** (remote modes): finalize / register / fence /
  exact-read / audit / outbox peek+ack — every response a typed outcome;
  ambiguity resolved by re-invoking with the identical operation identity,
  never by allocating a fresh one.
- **Checkpoint ↔ Recovery**: a checkpoint directory (per-keyspace payload
  + watermark) whose only consumer contract is "restore files, then
  replay from watermark" — engine-neutral by design.

## Behavioral invariants the architecture stands on

Fencing revokes reporting, never durability (inv. 38). Failed uploads
consume no identity. One physical record per status key. Command intent
binds forever (no second execution epoch after intent). Iterators bound to
fixed snapshots. All of these exist as executable checks in the reference
lanes, with negative controls proving the checks can fail.
