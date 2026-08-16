# Finding: `typedb_server_bin:bench_iam` queries a deleted storage directory (POSIX unlink-while-open dependence)

## Statement

`bench_iam` (2 tests: `has_permission`, `list_permissions`) fails on the U2
(SlateDB LocalFS) profile with 0-answer results, and passes on U1 (RocksDB).
The divergence is **not** an adapter semantics gap: the upstream test's
`setup()` returns an `Arc<Database>` while dropping the `TempDir` guard for
the storage directory — `TempDir::drop` runs `remove_dir_all`, so every
query in the test body executes against a database whose entire on-disk
state has been deleted.

- **RocksDB** holds open file descriptors to its SSTs/WAL from open time;
  POSIX unlink-while-open keeps the data readable, so the test passes by
  leaning on filesystem semantics the test never states.
- **SlateDB over an object store** reads objects by path per request —
  the object-store model (locally `LocalFileSystem`, in production R2) has
  no unlink-while-open grace. No object-store engine can satisfy this test
  as written; production R2 could not either (deleting the bucket under a
  live database is exactly this scenario).

This executable was never part of any earlier baseline: it is one of the
two test executables restored by the cargo package-id discovery fix (the
old parser collapsed most crates onto `0.0.0` and the dedupe dropped it),
so its first-ever corpus measurement happened on this run.

## Bracket (all runs deterministic, `--test-threads 1`)

| Variant | Result |
|---|---|
| upstream binary, U1 (RocksDB) | 2/2 PASS |
| upstream binary, U2 (SlateDB) | 0/2 FAIL (assert 1 == 0) |
| verbatim clone, U2 | FAIL — even `match $p isa person, has email "…";` returns 0 rows |
| verbatim clone + `std::mem::forget(tmp_dir)` (directory kept), U2 | **2/2 PASS** (`plain=1`, `func=1`) |
| independent probe (same load + close/reopen + same queries, directory alive), U2 | all queries = 1, function calls included, pre- and post-reopen |

The single toggled variable is the existence of the storage directory at
query time. Reopen/recovery, WAL replay, checkpoint restore, the function
pipeline (`has_permission(...)`), and multi-constraint joins are all
correct on U2 when the directory exists.

## Corrected baseline expectation

`typedb_server_bin:bench_iam` =
**PRE-EXISTING-UPSTREAM-TEST-DEFECT (environment dependence)** on the U2+
object-store profiles: the test requires POSIX unlink-while-open semantics
from the storage engine's backing store. Carried like
`test_fail_points` (fixed-port defect) and the `test_recovery` `todo!()`
stubs: U2 structural equality is measured against this corrected
expectation. A fix (holding `TempDir` alive for the test's lifetime, one
line in `setup()`) would be an upstream-test edit and is deferred to the
port ledger policy; the fork does not modify upstream tests.

## Soak observation: the failure is nondeterministic on U2

The second full-corpus sweep (soak run 2) saw `bench_iam` **pass 2/2 on
U2** (2.0s) where run 1 failed 0/2 (14.9s). Consistent with the
mechanism: after the reopen, the replayed data sits in the SlateDB
memtable; the queries only lose sight of it if a checkpoint-interval
flush moves the memtable into (deleted) on-disk files before they run.
Whether that flush wins the race against the queries is timing-dependent
— i.e. on object-store engines this upstream defect degrades from
deterministic-fail to **flaky**, the same class as the `test_fail_points`
port-race on the oracle. The corrected expectation is unchanged (the
directory-alive bracket remains the decisive experiment).

## Note on observed failure shape

With the directory deleted, reads surface as empty results rather than
I/O errors in this scenario; the engine-level distinction (error vs empty)
is SlateDB-internal behavior over unlinked local files and is not relied
upon either way by the corrected expectation. The decisive fact is the
directory-alive bracket above.
