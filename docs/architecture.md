# Architecture

TypeDB, semantically identical to the pinned upstream commit, with its
keyspace storage on an object-store engine (SlateDB, consumed unmodified
from crates.io) and its durability on TypeDB's own WAL — locally today,
on Cloudflare (R2 + Durable Objects) once the platform-fact gate closes.
The one-sentence design stance: **the upstream test corpus is the oracle,
the WAL is the only durable truth, and every authority boundary is
explicit and fenced.**

This page is the entry point and map; the content lives one level down
and is deliberately not repeated here.

## The architecture description (Arcadia perspectives)

The system is described per the Arcadia/MBSE method (Thales), one
document per perspective — each owns its abstraction level:

| Perspective | Question it answers | Document |
|---|---|---|
| Operational Analysis | what do the users need, independent of any system? | [architecture/arcadia/operational-analysis.md](architecture/arcadia/operational-analysis.md) |
| System Analysis | what must the system do (black box: boundary, functions, chains, modes)? | [architecture/arcadia/system-analysis.md](architecture/arcadia/system-analysis.md) |
| Logical Architecture | how does it work (planes, logical components, interfaces, invariants)? | [architecture/arcadia/logical-architecture.md](architecture/arcadia/logical-architecture.md) |
| Physical Architecture | how is it built (technology, deployment topologies, constraints)? | [architecture/arcadia/physical-architecture.md](architecture/arcadia/physical-architecture.md) |
| EPBS | what is the product made of (configuration items, reconstruction)? | [architecture/arcadia/epbs.md](architecture/arcadia/epbs.md) |

Traceability spine: operational **needs** (N1–N5) → system **functions**
(SF1–SF9) → logical **components** → physical **components** →
configuration **items**. Each document carries its layer of that thread.

## The decisions (ADRs)

Why the architecture is this way — context, alternatives, consequences —
is recorded as decision records, indexed at
[architecture/ADR/README.md](architecture/ADR/README.md). Highlights:
consume-only SlateDB (ADR-0001), the keyspace-layer engine seam
(ADR-0002), WAL-only durability (ADR-0003), the sync bridge (ADR-0004),
the U2 engine posture and manifest-pinned checkpoints (ADR-0005),
fence-before-replay (ADR-0006), conditional-create payload immutability
(ADR-0007), the corpus-as-oracle method (ADR-0008), the local-first
parity ladder (ADR-0009), and Cargo-only federated builds (ADR-0010).

## Suggested reading order

- **New to the project**: operational analysis → system analysis → the
  ADR index → logical architecture.
- **Working on the storage engine**: ADR-0002/0003/0004/0005 → logical
  architecture (the keyspace seam) → physical architecture →
  [development.md](development.md).
- **Working on the control plane**: ADR-0006/0007 → logical architecture
  (control plane) → the reference lanes in `tools/`.
- **Operating or auditing**: EPBS → [operations.md](operations.md) →
  the evidence tree (`docs/evidence/`).

## Related non-architecture documents

[development.md](development.md) (how to build and test),
[operations.md](operations.md) (gates, runbooks, blockers),
[user-guide.md](user-guide.md) (for application developers),
[local-dev-parity-plan.md](local-dev-parity-plan.md) (the L0–L3 ladder in
operational detail), and the received contract under
`typedb-r2-implementation-package/` (the v16 brief the ADRs cite).
