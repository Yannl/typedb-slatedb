# ADR-0004 — One process-wide Tokio storage runtime with a spawn + std-channel sync bridge

**Status:** accepted (implemented in TB-P7; brief §12.7 "one process-wide storage runtime")

## Context

TypeDB's storage layer is synchronous — every read and commit is a plain
function call, from arbitrary threads: test threads, dedicated transaction
threads, and (in server context) Tokio worker threads of the network
runtime. SlateDB is async-only. Bridging options:

1. `Handle::block_on` on a shared runtime — **panics** when the caller is
   itself on a Tokio worker thread ("cannot block the current thread from
   within a runtime"); the server context makes this a live grenade.
2. `block_in_place` — only legal on multi-thread runtime workers, panics
   on current-thread runtimes and non-runtime threads; wrong shape.
3. A runtime per keyspace/database — thread explosion (10 keyspaces ×
   N databases), and SlateDB background tasks multiply it.
4. Async-ify TypeDB's storage API — an upstream-wide rewrite, prohibited
   by the minimal-patch discipline.
5. **Spawn the future onto one dedicated storage runtime and block the
   caller on a plain `std::sync::mpsc` channel.**

## Decision

Option 5. A single `OnceLock<tokio::runtime::Runtime>` (4 worker threads,
named `typedb-slate-storage`) executes every SlateDB future in the
process. `bridge()` spawns the future and does `receiver.recv()` — a pure
std blocking call that is legal on *any* thread, including Tokio workers,
where it blocks exactly as the equivalent RocksDB syscall would have.

Borrow-shaped operations (cursor `next`/`seek` need `&mut DbIterator`)
move the iterator **into** the spawned future and get it back in the
result tuple, keeping the `'static + Send` bound honest without unsafe.

Panic policy: a panicked storage task drops its sender; `bridge()` then
panics on the caller with context (fail closed) — except inside `Drop`,
where close is wrapped in `catch_unwind` because a drop during another
panic's unwind must not abort the process (ADR-0005's disposable-store
rule makes an unclean close lossless).

## Consequences

- Every adapter operation costs one spawn + channel round-trip (~µs).
  Measured corpus impact: ~1.1–1.2× the oracle's wall-clock on the
  heaviest suites once measured without build contention (soak run 2:
  behaviour-concept 258s vs 223s oracle; behaviour-query 123s vs 109s);
  zero timeouts in either full sweep.
- Blocking a network-runtime worker is as (un)acceptable as it was for
  RocksDB — no regression in kind, and the server's existing threading
  assumptions hold unchanged.
- All SlateDB background tasks (flusher etc.) share the same 4 threads;
  with the compactor and GC disabled (ADR-0005) that budget is ample.
- The runtime is never shut down; it dies with the process. Deliberate:
  keyspaces can be dropped and reopened at any point in the process
  lifetime, and a shared runtime must outlive all of them.
