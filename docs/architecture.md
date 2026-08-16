# Architecture

This document describes the system as implemented on this branch. The
normative contract is the v16 brief
(`typedb-r2-implementation-package/.../typedb-r2-implementation-brief-v16.md`);
where this document and the brief diverge, an ADR records the owner decision
(currently: [ADR-0001](ADR-0001-slatedb-consume-only.md), consume-only
SlateDB).

## 1. What is being built

TypeDB is a strongly-typed database whose storage layer upstream is RocksDB
plus a local file write-ahead log. This project ports that storage layer to
run on Cloudflare:

- **Keyspaces** (the MVCC key-value substrate) move from RocksDB to SlateDB,
  an LSM engine whose backing store is an object store — locally a
  filesystem, in production Cloudflare R2.
- **Durability** moves from a local file WAL to a **remote WAL protocol**
  operated by a Durable Object controller, with payload bytes travelling a
  separate R2 data path.
- **Write authority** (which process may commit) becomes an explicit,
  epoch-fenced lease issued by the controller — not an assumption of
  single-process ownership.

The TypeQL/driver surface is unchanged; conformance gates prove it.

## 2. Planes

The design separates four planes with distinct authority:

1. **Transaction plane** — the external durability log (WAL records) is the
   authoritative transaction-intent history. Commit outcomes are the result
   of the pinned deterministic resolver over that log; no cached status,
   controller row, or storage manifest is ever commit authority on its own.
2. **Materialisation plane** — SlateDB state is *replayable physical
   state*: rebuildable from the WAL, hidden behind TypeDB's visibility
   watermark while partially applied. Losing it loses no data.
3. **Control plane** — `DatabaseControllerDO` (one per database): session
   registration and fencing, WAL-record finalisation (exact-once by
   operation identity), status singletons, admission budgets, and the
   at-least-once outbox that downstream consumers drain.
4. **Build/proof plane** — Cargo is the only Rust build/test authority
   (Bazel is never executed for a release); pnpm/wrangler own the Workers
   side; evidence artifacts under `docs/evidence/` record every gate.

## 3. The storage engine seam (fork side)

The entire backend swap happens **below** TypeDB's MVCC layer, at the
keyspace abstraction in the `storage` crate:

```
MVCCStorage
  └─ Keyspaces ── Keyspace { engine: KeyspaceEngine }
                     ├─ Rocks { Arc<DB>, read/write options }   (U0/U1 oracle)
                     └─ Slate(SlateKeyspace)                    (U2+, TB-P7)
       IteratorPool ── RawCursor (enum: RocksCursor | SlateCursor)
       WriteBatches ── KeyspaceWriteBatch (engine-neutral, put-only)
```

- **Profile selection**: `StorageFactory` (BT-P3) reads
  `TYPEDB_STORAGE_PROFILE` once per process (`resolved_backend_profile()`,
  cached — mixing engines in one process would corrupt a storage
  directory). Unknown or unavailable profiles fail closed with typed
  errors; nothing silently falls back.
- **Both engines are non-durable KV**: RocksDB runs `disable_wal(true)`;
  SlateDB runs `wal_enabled: false`. TypeDB's WAL is the sole durability
  authority. On reopen without a checkpoint, the storage directory is
  deleted and rebuilt from the WAL; with a checkpoint, the checkpoint files
  are restored and the WAL replayed from the checkpoint watermark.
- **MVCC batches are put-only** (logical deletes are tombstone-record
  puts), so the engine-neutral batch is an ordered put list, applied
  atomically per keyspace by both engines. An empty batch is a no-op on
  both (RocksDB semantics; SlateDB natively rejects it).

### The SlateDB adapter (TB-P7, `storage/keyspace/slate.rs`)

SlateDB is async; TypeDB storage calls are synchronous. One process-wide
Tokio runtime executes every SlateDB future; callers block on a plain std
channel — safe on any thread, including Tokio worker threads where
`Handle::block_on` would panic.

Semantics mapping:

| TypeDB needs | SlateDB provides |
|---|---|
| read-your-writes after non-durable put | `await_durable: false` writes + `dirty: true` / `DurabilityLevel::Memory` reads |
| forward cursor: seek-to-floor≥key, advance, read-in-place | forward scan + in-scan `seek`; fresh scan on any backward reposition |
| `seek_for_prev` floor lookup (`get_prev`) | descending scan over `..=key`, first item |
| atomic per-keyspace batch | `WriteBatch` + `write_with_options` |
| point-in-time checkpoint directory | `flush()` then file copy — compactor and GC are disabled, so the object store is quiescent between flushes |
| checkpoint restore | shared recursive file-sync (`restore_storage_from_checkpoint`), then normal open |

Cursor freshness: the `IteratorPool` is **per-snapshot**, so a recycled
cursor's scan is always at least as fresh as its snapshot's open point;
MVCC sequence filtering above the cursor makes that sufficient for
correctness.

Disabled SlateDB machinery (compactor, GC, engine WAL) is exactly the
ADR-0001 posture: the obligations the brief assigned to SlateDB source
patches (SL-P1..P4) live in configuration and in TypeDB-owned wrappers
instead.

## 4. The remote WAL protocol (control plane)

Implemented and tested in `control-plane/` (production TypeScript) with two
deterministic Rust reference lanes (`tools/remote-wal-spike`,
`tools/protocol-models`) that must stay trace-equivalent:

- **Payload data path**: clients PUT payload bytes to an R2-backed facade
  keyed by content; puts are conditional creates (`If-None-Match: *`) with
  create-or-identical semantics — two racing different-bytes uploads can
  never both win.
- **Finalisation**: one synchronous SQLite transaction in the DO:
  session fencing check first (brief inv. 38 — a fenced holder can never
  have a durable record *reported* back to it), then exact-once replay by
  operation id, then status-singleton dedupe, then admission budgets, then
  allocation (contiguous `AppendLsn`, monotone `TypeSequence`,
  `ControlSeq`) and outbox insertion — all-or-nothing for batches.
- **Outbox**: at-least-once peek/ack; redelivery without ack; duplicate ack
  idempotent; drains are exactly-once per `ControlSeq`.
- **Fencing**: sessions are registered per (database, generation); fencing
  is a terminal state; every protocol response to a fenced session is the
  typed `SESSION_FENCED`, including replays of records finalised before the
  fence (durability is never revoked — only reporting to the stale holder).

The pure models in `tools/protocol-models` (WAL, fencing/epoch, command
ledger, outbox) exhaustively check the invariants (LSN contiguity under
failed-upload interleavings, no-intent proofs, epoch CAS pause-fence-resume,
etc.) with mutant negative controls proving each checker can fail.

## 5. Consume-only SlateDB (ADR-0001)

SlateDB is a pinned crates.io dependency (`=0.15.0`,
`default-features = false`, `wal_disable`), checksum-locked in
`tools/Cargo.lock`, `fork/typedb/Cargo.lock`, and source-lock node `SL`.
There is no forked SlateDB tree. The brief's four planned SlateDB source
patches map to owned layers:

- external epoch fencing → controller lease protocol + (future) fencing
  `ObjectStore` wrapper; modelled in `tools/protocol-models/src/fencing_model.rs`;
- unfenced-admin bans → static checks + config;
- compactor lifecycle → disabled in-process; future standalone compactor
  runs under its own controller lease;
- fail-closed retry/iterator behavior → wrapper conversion at the
  `ObjectStore` boundary, verified at TB-P7 failpoint level.

If an obligation ever provably cannot be met at those layers, the remedy
order is upstream PR + version bump, then (only with a new ADR) a fork.

## 6. Conformance lanes and the parity ladder

Storage profiles: `U0` (pristine upstream), `U1` (fork + RocksDB oracle),
`U2` (fork + SlateDB LocalFS — live), `U3`/`U4` (remote WAL lanes, gated on
G2 platform measurements).

Deployment/testing fidelity ladder (see
[local-dev-parity-plan.md](local-dev-parity-plan.md)): `L0` native process,
`L1` real workerd + local R2 binding (running, E2E green), `L2` full
container topology under `wrangler dev` (needs Docker), `L3` real Cloudflare
staging (blocked on credentials; the only lane that can close gate G2).

The corpus authority is `tools/catalog/`: `generate_catalog.py` machine-
enumerates every upstream test target and leaf case; `run_u0.py` executes
the complete corpus against a chosen profile with Bazel-equivalent
serialisation/env; results are archived under `docs/evidence/`.
