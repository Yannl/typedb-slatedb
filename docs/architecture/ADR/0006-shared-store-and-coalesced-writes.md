# ADR-0006 — One shared store, keyspace-prefixed, with coalesced cross-keyspace writes

**Status:** accepted (engine-level); packaged as donor primitives 3 and 4
**Contract:** brief §I-74 (committed reads), §I-84/§I-96 (no delete-capable path), the
VisibilityWatermark contract, and the R2 operation-cost model
**Supersedes for the SlateDB lane:** the RocksDB assumption that each keyspace is a separate
physical database.

## The question

RocksDB gives TypeDB N independent column-family-like stores, and upstream `keyspace.rs`
treats each keyspace as its own database with its own write path. SlateDB is a single keyspace.
Two shapes are possible:

- **Per-keyspace:** open one SlateDB `Db` per TypeDB keyspace (N physical stores).
- **Shared store:** open one SlateDB `Db` and prefix every key with a one-byte keyspace id
  (`physical_key` in `engine/slatedb-keyspace/src/lib.rs`), so all keyspaces share one manifest,
  one WAL-less write path, one cache and one checkpoint root.

This ADR records why the shared store wins on an object store, and why one logical commit must
become one physical `WriteBatch` rather than one write per keyspace it touches.

## Decision

**Shared store, keyspace-prefixed, with cross-keyspace writes coalesced into a single
`WriteBatch`.** Ordering within a keyspace is preserved because the one-byte prefix is constant
across it (every range iterator and `seek_for_prev` depends on this); ranges between keyspaces
are disjoint because the prefixes differ. `KeyspaceSet::write` applies a `Batch` spanning any
number of keyspaces as one `db.write_with_options(...)` call.

## The comparison the brief asks for

| axis | per-keyspace (N stores) | shared store (this decision) |
|---|---|---|
| **Physical atomicity of a multi-keyspace commit** | none — N independent writes, any subset can land | one `WriteBatch`, all-or-nothing across every keyspace it touches |
| **Object-store writes per commit** | one PUT **per keyspace touched** (TypeDB's commit path writes several at once) | **one** PUT regardless of how many keyspaces the commit spans |
| **VisibilityWatermark behaviour** | N watermarks that can diverge; a reader can see keyspace A's half of a commit and not B's | one sequencer, one watermark; a committed memory-visible read (§I-74) observes the whole commit or none of it |
| **Checkpoint root shape** | N manifests to pin consistently; a checkpoint is only as atomic as the weakest of N pins | one manifest = one checkpoint root; `CheckpointScope::All` pins the whole database at one sequence number |
| **Compaction & cache interference** | N compactors competing for the same object store and the same billed-request budget; N cold caches | one compaction domain, one shared block cache — an agent's re-read of a just-written neighbourhood is one warm cache regardless of which keyspace it landed in |
| **Failure blast radius** | a corrupted manifest loses one keyspace, but a partial multi-keyspace commit is a cross-keyspace inconsistency TypeDB's replay must repair | a corrupted manifest loses the whole store; but there is no partial-commit state to repair, because commits are physically atomic |
| **External epoch handling** | N epoch domains to fence in lockstep on takeover | one epoch domain — one writer-epoch bump fences the whole database at once |
| **Memory / object / request amplification** | write amplification ×(keyspaces per commit); N sets of L0 SSTs and bloom filters to consult per logical read | one L0 fan; one filter lookup per physical key; request count tracks commits, not commits×keyspaces |

The decisive column is object-store writes per commit. TypeDB defines up to
`KEYSPACE_MAXIMUM_COUNT` keyspaces and its commit path writes to several at once, so the
per-keyspace shape multiplies Class A operations on the hottest path in the system by the
number of keyspaces a commit happens to touch — close to an order of magnitude, billed, forever.

## Why physical atomicity is a *safe* side effect, not a new guarantee

Coalescing makes a multi-keyspace commit land wholly or not at all. That is strictly *less* for
TypeDB's WAL replay to repair than the per-keyspace shape, where a crash mid-commit leaves some
keyspaces updated and others not. No caller can observe the absence of a partial state it would
otherwise have had to recover from — so the atomicity is free correctness, not a contract the
layer above now depends on and must be careful to preserve. The durability point is unchanged:
`write` returns once the write is *visible* (in the sequencer and memtable), not once it is
durable, exactly as upstream sets `disable_wal(true)` on RocksDB and leaves TypeDB's own
`durability` WAL as the sole authority.

## Consequences

- **One checkpoint root** simplifies the (still unimplemented — see
  `qualification.rs`) release-checkpoint protocol: there is one manifest to root a checkpoint
  in, not N to pin consistently.
- **One epoch domain** is what makes external, controller-scheduled fencing tractable: a single
  writer-epoch bump fences the whole database. Under the per-keyspace shape, takeover would have
  to fence N stores without a cross-store barrier.
- **The blast radius is the whole store.** This is the real cost of the decision, accepted
  because the manifest is committed with a conditional PUT (CAS) and the object store is the
  arbiter, so a torn manifest is a detected failure rather than silent corruption.

## Status of the differential / crash benchmark

The mission requires differential and crash benchmarks comparing the two shapes. The
**analytical** comparison above is complete and is what drives the decision. The **measured**
comparison is *not yet run in this environment*: it needs the local R2 simulator
(`build/simulator`) under an induced-crash harness, and is recorded here as an owned,
outstanding artifact rather than asserted with numbers that were not produced. The engine's
`tests/object_store_simulator.rs` already proves the coalesced write costs one write across all
keyspaces (`a_commit_spanning_every_keyspace_costs_one_write`) and that a second writer fences
the first — the two properties the benchmark would quantify rather than establish.

## Implementation anchors

- Keyspace prefixing and disjoint ranges: `engine/slatedb-keyspace/src/lib.rs`
  (`physical_key`, `logical_key`, `keyspace_end`).
- Coalesced write: `KeyspaceSet::write`, `Batch` / `Batch::put_prefixed`.
- One-write-per-commit proof: `tests/object_store_simulator.rs::a_commit_spanning_every_keyspace_costs_one_write`.
- Shared identity (which store the one manifest belongs to): `src/identity.rs` — see ADR context
  in `docs/donor/donor-package.md`.
