# Phase B summary — the U0 baseline

U0 is the answer to "what does pristine TypeDB actually do under Cargo, at this pin, on this
machine". It is not an assumption that upstream is green; it is a measurement, and it is the
only thing a later U1 run can be compared against.

Subject: TB `2256711abd53`, built and run on Rust `1.93.0` with the configuration in
`tools/u0-build-env.sh` / `conformance_runner::PARITY_BUILD_ENV`.
Source graph digest: `3b8bd2a72a5534d4f28c236053fcc473ba7b4f02fa3f36645c43b6020d6763ae`.

## Result

```
targets    : 114/114
leaf cases : 4758/4758
passed=4677  failed=49  ignored=29  unknown=3
verdict    : NOT GREEN
```

Every catalogued leaf case is accounted for: 4677 + 49 + 29 + 3 = 4758. No case is
unexecuted, and no executed case is missing from the catalogue. That reconciliation is the
part that took nine runs to earn — the counts themselves are easy to produce and worthless
until they close.

`NOT GREEN` is the correct verdict, and it is not a defect in the port. Nothing has been
ported yet.

## The 49 failures

| Count | Target(s) | Cause | Class |
|---:|---|---|---|
| 44 | `test_fail_points` | needs the assembled distribution archive | environmental |
| 2 | `test_assembly`, `test_admin_assembly` | same | environmental |
| 2 | `storage::test_recovery` | `todo!()` in upstream source | **upstream red** |
| 1 | `storage::bench_rocks` | requires CLI arguments it is not given | harness shape |

**The two `todo!()` tests are the important ones.** `storage/tests/test_recovery.rs` L64-74
declares `wal_missing_records_for_checkpoint_replay_fails` and
`wal_missing_records_entire_replay_fails`, each with a `// TODO:` comment and a bare
`todo!()` body. They panic wherever they run — Bazel included. These are not Cargo-migration
artifacts; they are two failing tests in a released tag, and they sit directly on WAL
recovery, which is precisely the subsystem a SlateDB storage backend replaces.

Had U0 been assumed green, these two would have surfaced during Phase C and read as
regressions caused by the SlateDB port, in the one area where that diagnosis is most
plausible and most expensive to chase.

**The 46 environmental failures** all fail at the same place: extracting
`$TYPEDB_ASSEMBLY_ARCHIVE` (`tests/assembly/assembly.rs` L48-51,
`fail_points.rs` L185-188). The archive is produced by Bazel's `//:assemble-typedb-all`,
which this lane cannot run. They need a Cargo-native assembly step before they can report
anything; until then they are honest failures rather than skips, and they are not counted as
passes.

**`bench_rocks`** reads required CLI arguments (`bench_rocks.rs` L174,
`get_arg_as::<String>(&arg_map, "database", true)`) and unwraps them. Bazel declares it
`rust_test`, but it is a manual benchmarking tool that needs an invocation the test harness
does not supply.

## The 29 declared-ignored

Scenarios their harness's own ignore predicate filters out. Which predicate applies depends
on the target, not the scenario — see CR-A-09. They are counted, never passed, and each
needs a catalogue exclusion entry with an owner before G1.

## The 3 unknowns

`release_validate_deps` (two expansions) and `tool/test/simulate-crash.sh` have no port yet.
The runner reports `Unknown` rather than guessing, which is the intended behaviour: an
unported check is not a passing check.

## What the nine runs cost, and bought

The first full run reported 608/4772 executed with 140 failures. Not one of those numbers
described upstream. Every one was a defect in the harness I had written:

| # | Defect | Effect if undetected |
|---|---|---|
| 1 | `--features bazel` passed to Cargo | 4159 scenarios never ran |
| 2 | checkstyle ignored `multiLines = "1, 2"` | 91 targets red for a check upstream passes |
| 3 | BUILD scan walked the staged fixture tree | denominator depended on whether a run had happened |
| 4 | `--nocapture` corrupted libtest statuses | 15 passing cases read as `Unknown` |
| 5 | verdicts pushed onto later lines by `tracing` | 38 passing cases read as `Unknown` |
| 6 | leaf ids collided on repeated scenario names | catalogue under-counted; extras looked uncatalogued |
| 7 | empty `Examples` cell left a trailing space | 9 catalogued cases never matched their results |
| 8 | zero-row outlines counted as runnable | 4 permanently-unexecutable denominator entries |
| 9 | `data` treated as "what runs" | 6 scenarios of an unreferenced feature counted |
| 10 | one ignore predicate assumed | 29 skips reported as holes |
| 11 | `license_type` ignored | ASF-licensed file failed for its own licence |
| 12 | globs crossed Bazel package boundaries | a file upstream never inspects failed a check |

Along the way the same strictness surfaced four defects in *upstream*: CR-A-07 (two
behaviour tests with no non-Bazel fixture path), CR-A-08 (two misspelled fixture paths that
only Cargo can reach), CR-A-10 (a feature file declared as data but referenced by nothing),
and the two `todo!()` recovery tests above.

The pattern worth keeping: a permissive runner would have reported green on most of these.
A runner that refuses to classify what it cannot read produced twelve loud failures instead,
each of which was real. The cost was nine iterations; the alternative was a baseline that
looked clean and meant nothing.

## Not yet done

* The 46 assembly-dependent failures need a Cargo-native assembly step (Phase C).
* The 29 declared-ignored need exclusion entries with owners.
* `release_validate_deps` and `simulate-crash.sh` need ports.
* `NATIVE` toolchain digests and the Mode Q Bazel snapshot remain open from G0.
