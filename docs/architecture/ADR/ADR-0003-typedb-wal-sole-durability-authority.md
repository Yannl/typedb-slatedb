# ADR-0003 — TypeDB's WAL is the sole durability authority; engine WALs are disabled on every backend

**Status:** accepted (brief §5.6 restated as an implementation decision; implemented in TB-P7)
**Related:** ADR-0005 (U2 SlateDB configuration), ADR-0001

## Context

Both candidate keyspace engines ship their own durability machinery:
RocksDB a write-ahead log, SlateDB a WAL flushed to object storage. TypeDB
also has its own WAL — the transaction-intent log that the whole
resolution model (and, in the distributed design, the remote WAL protocol)
treats as authoritative history. Running two durability layers means two
fsync paths, double write amplification, and — much worse — two sources of
truth that can disagree after a crash.

Upstream TypeDB already answers this for RocksDB: keyspaces are opened
with `disable_wal(true)` and documented as "a non-durable key-value
store". Crash recovery rebuilds keyspace state by replaying the TypeDB WAL
(from scratch, or from a checkpoint's watermark).

## Decision

Keep exactly that contract for every engine:

- RocksDB: `disable_wal(true)` (upstream behavior, unchanged).
- SlateDB: `wal_enabled: false` (a stock runtime setting behind the
  `wal_disable` cargo feature — no fork needed), writes with
  `await_durable: false`, reads with `dirty: true` +
  `DurabilityLevel::Memory` so read-your-writes holds without any
  durability wait.
- Recovery semantics are engine-independent: **keyspace stores are
  disposable**. No checkpoint → delete the storage dir, replay the TypeDB
  WAL from the start. Checkpoint → restore its files, replay the WAL tail
  from the checkpoint watermark. The WAL ahead of a checkpoint must never
  be truncated; recovery fails closed if it is.

## Consequences

- Commit latency on U2 is one memtable insert, not an object-store
  round-trip; the TypeDB WAL fsync (already on the commit path) is the
  only durability wait. This is also exactly the shape the future remote
  lanes need — the remote WAL replaces the file WAL, and the keyspace
  engine still owes no durability.
- A crash can lose any amount of un-checkpointed keyspace state without
  losing data; this is by construction, and the upstream recovery test
  suite plus the U2 corpus run exercise it.
- Clean close flushes the SlateDB memtable (belt-and-braces for
  checkpoint-less local restarts), but correctness never depends on it.
- Anyone adding an engine must uphold the same rule; enabling an engine
  WAL would silently double-write and is called out in the port ledger as
  a review tripwire.
