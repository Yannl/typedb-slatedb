# ADR-0013 — Shared SlateDB store with coalesced writes vs per-keyspace stores

**Status:** evaluated, **not adopted** — adoption gated on differential,
crash, and capacity evidence demonstrating a material advantage (V16
convergence audit F11).

## Context

The donor branch (`engine/slatedb-keyspace`) runs ONE SlateDB store per
database: keys carry a one-byte `KeyspaceId` prefix, and one logical
TypeDB commit coalesces every keyspace's mutations into one `WriteBatch` —
one object-store write per commit instead of up to N. Its motivation is
cost-correct on R2 (writes bill ~12.5× reads; per-keyspace commits
multiply PUT counts), and it also buys cross-keyspace commit atomicity at
the storage layer.

This branch runs one SlateDB store per keyspace (the RocksDB shape:
N independent column-family-like stores), proven baseline-equal through
the full corpus on U2 and U2S3.

## Comparison

| Axis | Shared store + coalesced writes | Per-keyspace (current) |
|---|---|---|
| TypeDB semantics | Cross-keyspace atomicity at storage layer (stronger than RocksDB baseline — a *semantic deviation* to prove harmless); iterator ranges must never leak across the 1-byte prefix boundary | Exactly the upstream shape; corpus-proven |
| Failure isolation | One corrupted store takes every keyspace | Blast radius = one keyspace |
| Checkpointing | One manifest pin covers the database — simpler global cut | N pins must form one CheckpointCut (audit F6 protocol handles this) |
| External epochs (ADR-0012) | One writer epoch per database | N epochs per database to mint/track |
| Compaction interference | One compactor; hot keyspace compactions rewrite cold keyspaces' overlapping levels | Per-keyspace compactors; no cross-interference |
| Write amplification / cost | ~1 PUT per commit; fewer manifests | Up to N PUTs per commit; N manifests polled |
| Memory | One block cache / memtable set | N × per-handle caches (~64 MiB each — documented budget) |
| Migration | Rekeying of every stored byte; dual-format readers during transition | none |

## Decision

Stay per-keyspace now. The corpus oracle property (structural equality
with upstream RocksDB behavior) is the programme's spine, and the shared
store changes storage-layer semantics (atomicity scope, iterator
boundaries, estimate scopes) in ways the oracle can detect but that take
a full differential + crash-matrix campaign to certify. The cost argument
is real but belongs to G2: it is a measured envelope, not a local
correctness fact, and R2 PUT pricing cuts both ways once the remote WAL
(which already batches at the controller) absorbs the hot write path.

Re-open when G2 measurements exist, with adoption criteria: (a) measured
PUT-cost or latency advantage ≥ a named threshold under representative
load; (b) differential corpus equality on the shared-store build; (c)
crash matrix covering torn coalesced commits; (d) checkpoint + epoch
design updated for the single-store shape.

Portable pieces adopted regardless of this decision: manifest-based size
estimates (observational, inv. 72), bounded retry/backoff, explicit cache
budgets (partially landed via `TYPEDB_S3_CACHE_BYTES`).
