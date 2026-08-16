# User documentation

**There is nothing to use yet, and this folder says so rather than pretending otherwise.**

TypeDB-on-SlateDB is not deployable today. No storage-engine work has begun, no service runs,
and there is no endpoint to connect to. Writing usage instructions now would document features
that do not exist — and a user following them would find that out the hard way.

## What you are probably looking for

| If you want to… | Go to |
|---|---|
| Learn TypeQL, the schema model, or the drivers | [TypeDB's own documentation](https://typedb.com/docs) — this programme does not change any of it |
| Understand what this project is building | [`docs/architecture.md`](../architecture.md) |
| Work on the repository | [`docs/dev/`](../dev/) |
| Run the conformance gates | [`docs/ops/`](../ops/) |

## What this project will and will not change for you

The programme replaces **where bytes are stored**. It does not change the query language, the
type system, the schema model, or the drivers.

That is the entire point: if this succeeds, your queries behave exactly as they do on stock
TypeDB, and the only visible differences are operational — where it runs and what it costs. If
a query behaves differently, that is a defect, not a feature.

So the user-facing surface of this project is, by design, almost empty. The interesting
documentation is upstream's.

## What will live here, once it exists

| Document | Unblocked by |
|---|---|
| Connecting to a deployed instance | a deployment; `CF-ACCOUNT` |
| Configuration reference (bucket, credentials, limits) | the storage binding |
| Operational differences from stock TypeDB | measurements — latency and durability characteristics differ from local disk, and none are measured yet |
| Migration from a RocksDB-backed instance | the storage binding, and a migration path |
| Known limitations | honest answers, which require a running system |

The third and fifth rows are the ones that will matter most and are the least safe to guess at.
Object storage has different latency and failure behaviour from a local disk; until that is
measured on a real deployment, any statement about it here would be speculation dressed as
documentation.

## Current status

Gate G0/Phase B. The upstream test baseline is measured — 4 757 leaf cases over 258 targets —
which establishes what stock TypeDB does at the pinned revision. That is the reference the
eventual system must match. See [`docs/evidence/phase-b/summary.md`](../evidence/phase-b/summary.md).
