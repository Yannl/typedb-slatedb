# Port ledger — fork/typedb

Contract rule (brief v16 / G3): **no upstream test edit outside this ledger.**
Every entry below is either a non-test source patch (TB-series), a
test-infrastructure change with a behavior-preservation argument, or a staged
runfile arrangement that reproduces Bazel semantics without touching test code.

## Upstream test files edited

None. Zero upstream test files (unit `#[cfg(test)]` modules, `tests/`
integration files, Cucumber `.feature` steps, failpoint tests) have been
modified at any point in this fork's history.

## Test-infrastructure changes (non-test-file)

1. `storage/tests/test_utils_storage/lib.rs` — `create_storage` now obtains
   its WAL through `storage::factory::StorageFactory` (BT-P3 injection point)
   instead of calling `WAL::create` directly.
   Behavior preservation: with `TYPEDB_STORAGE_PROFILE` unset the factory
   resolves to the identical `WAL::create(path, FsyncMetrics::disabled())`
   call; failure surfaces as an `expect` panic exactly as before.
   `load_storage` still accepts a caller-provided `WAL` (upstream tests build
   it directly; those sites are enumerated in
   `docs/evidence/G3/direct-constructor-inventory.md` as
   UPSTREAM-TEST-PINNED).

## Trait-signature changes visible to test code

1. `KeyspaceSet::rocks_configuration(&RocksResources) -> rocksdb::Options`
   replaced by `KeyspaceSet::tuning_profile() -> KeyspaceTuningProfile`
   (TB-P2). Every upstream test/bench `impl KeyspaceSet` used the trait
   default and did not override `rocks_configuration`; the new default
   (`KeyspaceTuningProfile::Default`) builds byte-identical `Options`
   (moved verbatim), so no test file needed edits and none were made.
2. `DurabilityClient::request_sync` / `WAL::request_sync` now return
   `mpsc::Receiver<Result<(), DurabilityServiceError>>` (TB-P3). No upstream
   test calls `request_sync` (verified by grep at the pin); commit-path
   callers inside `storage/storage.rs` were updated in the same patch.

## TB-P7 — SlateDB keyspace engine (U2 profile), consume-only per ADR-0001

Non-test source patches; zero upstream test files touched. SlateDB is an
unmodified crates.io dependency (`=0.15.0`, `default-features = false`,
`wal_disable`).

1. `storage/keyspace/slate.rs` (new) — the entire adapter: process-wide
   Tokio storage runtime + std-channel sync bridge, `SlateKeyspace`
   (put/get/get_prev/write/checkpoint/reset/estimates over a LocalFS object
   store; engine WAL off, compactor/GC off, dirty+Memory reads for
   read-your-writes), `SlateCursor` (RocksDB raw-iterator positioning
   semantics over forward-seek scans; fresh scan on backward seek).
2. `storage/keyspace/keyspace.rs` — `Keyspace` holds a `KeyspaceEngine`
   enum (Rocks | Slate); engine chosen once per process from
   `TYPEDB_STORAGE_PROFILE` via the BT-P3 factory. Rocks arm is the
   previous code moved verbatim; new typed error variants
   (`SlateDB`/`Factory`/`ProfileUnavailable`, `KeyspaceError::Slate`,
   `CreateSlateDBCheckpoint`).
3. `storage/keyspace/cursor.rs` — `RawCursor` is now the engine enum
   (`RocksCursor` unchanged inside); engine-neutral `CursorError`.
4. `storage/keyspace/raw_iterator.rs` / `iterator.rs` — cursor error type
   swapped to `CursorError`; mapping to `KeyspaceError` at the range
   iterator (rocks arm byte-identical behavior).
5. `storage/write_batches.rs` — engine-neutral `KeyspaceWriteBatch`
   (ordered put list; MVCC batches are put-only). RocksDB arm rebuilds the
   identical `WriteBatch` at apply time. Empty batch = no-op on both
   engines (RocksDB semantics; SlateDB would reject it as `Invalid`).
6. `storage/recovery/checkpoint.rs` — `restore_storage_from_checkpoint`
   made recursive. Behavior-preservation: RocksDB checkpoints are flat file
   sets, for which the recursion reduces exactly to the previous logic
   (including the `is_same_file` hardlink shortcut); SlateDB object stores
   are nested and require per-level sync.
7. `concept/thing/thing_manager.rs` — two type-inference disambiguations
   (`let vertex_bytes: &[u8] = ...` split) required because the enlarged
   dependency graph makes the previous `as_ref().try_into()` chain
   ambiguous. No behavior change (same deref, same conversion).
8. `storage/factory.rs` — U2 marked available; `resolved_backend_profile()`
   caches the env-resolved profile process-wide (mixing engines in one
   process would corrupt keyspace directories); file WAL declared available
   for U2 (TypeDB WAL remains durability authority under SlateDB).
9. `Cargo.toml` / `storage/Cargo.toml` / `Cargo.lock` — workspace dep
   `slatedb =0.15.0` (checksum-locked), storage crate gains
   `slatedb`/`tokio` deps.

Post-review hardening (same patch series):

10. `slate.rs` — `l0_max_ssts`/`l0_max_ssts_per_key` raised to 1M: with the
    compactor disabled the default 8-SST L0 backpressure would permanently
    stall flush dispatch (and then all puts) — liveness over read
    amplification, matching SlateDB's own compactor-less test settings.
11. `slate.rs` — checkpoints are manifest-pinned: flush, pin the latest
    manifest file, copy the store excluding the manifest dir, then copy
    exactly the pinned manifest. Immutable SSTs + disabled GC make the
    pinned state complete under concurrent commits (a naive full copy could
    capture a newer manifest whose SSTs the copy missed).
12. `slate.rs` — `get_prev` fails closed (panic) on scan errors: the
    Option-only signature cannot carry errors, and silent absence would
    reseed vertex ID allocators over live data.
13. `slate.rs` — `reset` deletes in 10k-key chunks (bounded memory);
    `Drop` wraps close in `catch_unwind` (a drop during another panic's
    unwind must not abort the process).
14. `keyspace.rs` — RocksDB tuning options are only built when a RocksDB
    profile is selected.
15. `iterator.rs` — `accept_value` end-bound comparison guards short keys:
    a key shorter than the end bound and not a prefix of it previously
    panicked on slicing (`key[0..end.len()]`); it now compares the
    overlapping prefix. Reachable on both engines (total-order cursors);
    behavior unchanged for every input that did not panic.

Verified: full `storage` crate suite baseline-equal on U2 vs the U1 oracle
(8 + 14+1ign + 4 + 5/2-todo-stubs + 10 + 6), re-verified after the
hardening pass on both profiles; U1 unchanged.

## Staged runfile arrangements (Bazel-equivalence, no test edits)

Recorded at BT-P2 (see `docs/evidence/G1/u0-baseline.json`):
- sibling symlink `sources/typedb_behaviour+` (migration.rs hardcoded Bazel
  sibling path),
- alias symlink `bazel-typedb/external/typedb_behaviour` (given.rs missing
  `+`),
- alias symlink `bazel-typedb/external/typedb_behaviour++` (variables.rs
  double `+`).
These reproduce the exact path spellings the pinned cargo lane expects; the
three upstream path defects remain unmodified in test sources.

## Formatting

All fork-touched files are rustfmt-clean under the pinned
`nightly-2026-04-15` toolchain with the workspace `rustfmt.toml`
(whitespace-only relative to their pre-format state; see
`docs/evidence/G3/static-checks.json`).
