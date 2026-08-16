# Architecture

Entry point. This file routes; it does not restate. Every claim lives in exactly one place,
and that place is linked from here.

## How the architecture is documented

Two complementary structures, deliberately kept apart:

* **[Arcadia perspectives](architecture/arcadia/)** — the *description* of the system, using
  the Thales Arcadia method's five levels. Each answers a different question and each is
  allowed to contradict a naive reading of the others, because they model different things.
* **[ADRs](architecture/ADR/)** — the *decisions*, each with the context that forced it and
  the alternatives rejected. An ADR is a record of a choice at a moment; an Arcadia file is a
  description of the current state.

If you want to know **what the system does**, read Arcadia. If you want to know **why it is
shaped that way**, read the ADRs. Neither repeats the other: Arcadia files link to ADRs for
rationale rather than summarising it.

## Read in this order

| # | Perspective | Question it answers | Maturity |
|---|---|---|---|
| 1 | [Operational Analysis](architecture/arcadia/01-operational-analysis.md) | What do stakeholders need to accomplish, independent of any system? | stable |
| 2 | [System Analysis](architecture/arcadia/02-system-analysis.md) | What must the system do, seen as a black box? | stable |
| 3 | [Logical Architecture](architecture/arcadia/03-logical-architecture.md) | How does it work, in principle, free of technology? | **provisional** |
| 4 | [Physical Architecture](architecture/arcadia/04-physical-architecture.md) | How is it built and deployed, with real technology? | **provisional** |
| 5 | [EPBS](architecture/arcadia/05-epbs.md) | What are the configuration items, and who owns each? | partial |

**Maturity is not decoration.** The programme is at gate G0/Phase B: the source graph is
locked and the upstream test baseline is measured, but *no storage-engine work has begun*.
Levels 1, 2 and 5 describe things that exist. Levels 3 and 4 describe an intended design that
has not been built or validated, and say so per section. Reading a provisional file as settled
is the main way this documentation could mislead.

## Decisions

| ADR | Subject |
|---|---|
| [0001](architecture/ADR/0001-repository-topology-and-orchestration.md) | Federated Cargo workspaces; no task runner at G0 |
| [0002](architecture/ADR/0002-bazel-evidence-mode.md) | Bazel evidence: Mode S implemented, Mode Q deferred |
| [0003](architecture/ADR/0003-conformance-runner-no-false-green.md) | How a composite harness reports leaf cases |
| [0004](architecture/ADR/0004-porting-the-static-checks.md) | Port the static checks rather than exclude them |
| [0005](architecture/ADR/0005-local-stack-and-dev-prod-parity.md) | Local stack in three layers; which parity is free |

## Other documentation

| Folder | Audience |
|---|---|
| [`docs/dev/`](dev/) | People working on this repository |
| [`docs/ops/`](ops/) | People running the gates and handling evidence |
| [`docs/user/`](user/) | People using the system — currently near-empty, and honest about why |

## Where the facts come from

Architecture documents make claims about upstream behaviour. Those claims are anchored, not
recalled:

* **Source pins** — [`source-lock/source-lock.json`](../source-lock/source-lock.json), 14
  resolved nodes with independent content digests, 5 unresolved and recorded against the gate
  each blocks.
* **Measured baseline** — [`docs/evidence/phase-b/summary.md`](evidence/phase-b/summary.md),
  the U0 run over 4 757 catalogued leaf cases.
* **Contract/source disagreements** —
  [`docs/evidence/phase-a/contradiction-records.md`](evidence/phase-a/contradiction-records.md),
  ten records, four of them upstream defects.

When an Arcadia file states something about TypeDB, SlateDB or Cloudflare, it cites the file
and line it was read from. Anything not so anchored is marked as an assumption.
