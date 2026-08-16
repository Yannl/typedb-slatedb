# ADR-0005 — U2 SlateDB posture: no compactor, no GC, unbounded L0, manifest-pinned checkpoints

**Status:** accepted (implemented in TB-P7 + hardening pass)
**Related:** ADR-0001 (SL-P2/SL-P3 obligations relocated to configuration), ADR-0003

## Context

The U2 lane runs SlateDB over a local filesystem object store as the
stepping stone to R2. Four engine behaviors needed a stance:

1. **Compaction.** SlateDB's in-process compactor rewrites files in the
   background. ADR-0001 relocated the brief's compactor-fencing patch
   (SL-P3) to "don't run an unfenced compactor at all".
2. **Garbage collection.** Same shape (SL-P2): GC deletes files; deletion
   under an unfenced actor is banned by the protocol design.
3. **L0 backpressure.** SlateDB defaults `l0_max_ssts = 8`; when L0 is
   full it stops dispatching memtable flushes until compaction shrinks
   L0. With no compactor this is a **permanent wedge**: after 8 flushes,
   `flush()` never resolves and eventually every put blocks.
4. **Checkpoints.** TypeDB checkpoints must be self-contained directory
   copies restorable by file sync (the contract RocksDB's `Checkpoint`
   hardlink tree satisfies), created **while commits continue**. A naive
   copy of a live SlateDB store races concurrent flushes: the copy can
   capture a newer manifest whose SSTs it missed → unopenable checkpoint.
   SlateDB's native checkpoint API pins state *within the same object
   store* and cannot produce an exportable directory.

## Decision

- `compactor_options = None`, `garbage_collector_options = None`,
  `compression_codec = None`, `flush_interval = None`.
- `l0_max_ssts = l0_max_ssts_per_key = 1_000_000` — liveness over read
  amplification, the same posture SlateDB's own compactor-less tests take
  (`l0_max_ssts = 10_000`). L0 growth is bounded in practice by the
  disposable-store recovery model (ADR-0003): stores are rebuilt compact
  from the WAL/checkpoint on reopen.
- **Checkpoints pin the manifest**: flush the memtable; record the latest
  manifest file; copy the whole store *excluding* the manifest directory;
  then copy exactly the pinned manifest. Because SSTs are immutable and
  GC is off, everything the pinned manifest references still exists during
  the copy; SSTs from concurrent later flushes are unreferenced extras.
  Restore uses the shared recursive file-sync path and replays the WAL
  from the checkpoint watermark (idempotent — same contract as RocksDB).

## Consequences

- The full fail-points suite — which fires kill-points through the
  checkpoint machinery — passes 2/2 on U2 (better than the oracle
  baseline, which trips an unrelated upstream port-race defect).
- Read amplification grows with L0 within a store's lifetime; scans slow
  down on long-lived heavily-written stores. Accepted for U2; the
  production lanes revisit compaction as a *fenced, controller-leased*
  process (ADR-0001's escape path), not by re-enabling the in-process
  compactor.
- Checkpoint cost is O(store size) file copy rather than O(1) hardlinks;
  correct-under-concurrency was the requirement, speed was not.
