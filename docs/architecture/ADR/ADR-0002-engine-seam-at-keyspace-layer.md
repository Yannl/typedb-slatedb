# ADR-0002 — The storage-engine seam lives at the keyspace layer, as an enum with process-wide profile selection

**Status:** accepted (implemented as TB-P7)
**Related:** ADR-0001 (consume-only SlateDB), ADR-0003 (durability authority), brief §12 (storage refactor)

## Context

TypeDB's storage crate stacks MVCC, snapshots, and isolation on top of a
thin key-value substrate: `Keyspaces` → `Keyspace` (put/get/floor-read/
batch/checkpoint) plus a pooled raw cursor (seek/advance/read-in-place).
Upstream, that substrate is hard-wired to RocksDB. Swapping the engine
could happen at several altitudes:

1. Replace the whole storage crate per backend (parallel implementations).
2. Introduce a `dyn`-trait KV abstraction threaded through the MVCC layer.
3. Keep the existing `Keyspace`/`RawCursor` types and make them **enums
   over engine variants**, selected once per process.
4. Impersonate the `rocksdb` crate API (explicitly prohibited by the brief).

Constraints that decided it: upstream test files must never be edited, so
every public type and signature reachable from tests has to stay stable;
the MVCC layer must remain byte-identical for the oracle profile so U1
keeps its baseline; and the conformance method requires both engines to be
selectable from the *same binary* (the corpus runs one build under
different `TYPEDB_STORAGE_PROFILE` values).

## Decision

Option 3. `Keyspace` holds a `KeyspaceEngine { Rocks{..}, Slate(..) }`;
`RawCursor` is `{ Rocks(RocksCursor), Slate(SlateCursor) }`; errors are
engine-neutral enums (`CursorError`, `KeyspaceError::Slate` variants).
`WriteBatches` carries an engine-neutral, put-only batch (MVCC deletes are
tombstone puts) converted to the native batch at apply time.

The profile is resolved from `TYPEDB_STORAGE_PROFILE` **once per process**
(`resolved_backend_profile()`, cached in a `OnceLock`) and every keyspace
open consults the cache. Unknown values and unavailable profiles are typed
errors — never a silent fallback.

## Consequences

- The RocksDB arm is the previous code moved verbatim; U1 measured
  baseline-equal after the refactor (the requirement that made this
  reviewable).
- The whole SlateDB adapter is one file (`storage/keyspace/slate.rs`);
  every other change is dispatch plumbing, enumerated in the port ledger.
- Enum dispatch means adding a third engine (e.g. the future U3 remote
  lane) is additive: new variant, new adapter file, no signature churn.
- Process-wide profile caching makes mixed-engine corruption of one
  storage directory impossible, at the cost of not supporting per-database
  engine selection in one process (not a requirement in any profile).
- No `dyn` indirection on the hot read path; the enum match is the entire
  overhead for the oracle lane.
