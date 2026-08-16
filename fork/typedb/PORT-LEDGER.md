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
