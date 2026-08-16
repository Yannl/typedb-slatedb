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
leaf cases : 4757/4757
passed=4679  failed=49  ignored=29  unknown=0
verdict    : NOT GREEN
```

Every catalogued leaf case is accounted for: 4679 + 49 + 29 = 4757. No case is unexecuted,
no executed case is missing from the catalogue, and nothing is unclassified. That
reconciliation is the part that took twelve runs to earn — the counts themselves are easy to
produce and worthless until they close.

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

**The 46 packaging failures are resolved.** They were reported as blocked on two unobtainable
artifacts. They were not.

`MODULE.bazel` L118-132 pulls TypeDB Console and Loader as pre-built artifacts with no URL or
checksum supplied, and I stopped there — treating "the build downloads a binary" as "the source
is unavailable". They are one Cargo workspace at `typedb/typedb-console`, tag `console-3.12.0`
(`0292fddf`), whose members are `["typeql-check", "common", "loader", "tool/runner", "console"]`
and whose VERSION reads exactly `3.12.0`. Console builds from source in two minutes.

`cargo xtask assemble` now produces `typedb-all-linux-x86_64.tar.gz` from components this lane
builds itself, with the layout read out of TB's root BUILD rather than guessed. Measured
against it:

| Target | Cases | Result |
|---|---:|---|
| `test_assembly` | 1 | pass |
| `test_fail_point_always` | 22 | pass |
| `test_fail_point_chance` | 22 | pass |

Two limits stand. The archive is a **semantic** reproduction — tar ordering, timestamps and
permission bits differ from Bazel's, so its digest is not upstream's. And the archive must be
staged as a bare filename in the working directory, because `fail_points.rs` L174-181 builds
its extract command by string surgery (`tar -xf $A && mv ${A%.tar.gz}-0.0.0 …`): `tar` writes
to the cwd while the `mv` keeps the variable's path prefix, so an absolute path cannot work.

**Historical note on the earlier reading.** These originally failed at extracting
`$TYPEDB_ASSEMBLY_ARCHIVE` (`tests/assembly/assembly.rs` L48-51, `fail_points.rs` L185-188).

These are *packaging* tests. They unpack the shippable tarball, start the server from it, and
drive it with `typedb console --script=…` (`fail_points.rs` L300-302). Console is a released
CLI used here as a **test client** — not a component this programme changes. The archive
needs it, so the tests need it, and all that is missing is a pinned URL and SHA-256.

TypeDB Loader is bundled in the same archive and is referenced by **no test at all** (0
occurrences under `tests/`). An earlier draft listed it as a blocker; that was inferred from
the packaging rule rather than checked against the tests, and it was wrong twice over — it
blocks nothing, and its source was available anyway.

**`bench_rocks`** reads required CLI arguments (`bench_rocks.rs` L174,
`get_arg_as::<String>(&arg_map, "database", true)`) and unwraps them. Bazel declares it
`rust_test`, but it is a manual benchmarking tool that needs an invocation the test harness
does not supply.

## The 29 declared-ignored

Scenarios their harness's own ignore predicate filters out. Which predicate applies depends
on the target, not the scenario — see CR-A-09. Each now carries an exclusion naming upstream
as owner, because the fork cannot un-skip a tag in the pinned corpus.

The gate distinguishes owned skips from unowned ones rather than counting every skip against
it. Holding U0 red forever for upstream's own decisions would teach people to read NOT GREEN
as the normal state, which is how a real regression gets waved through. A skip still never
counts as a pass, and an unowned skip still fails the gate.

## No unknowns

`release_validate_deps` is ported — the two checks `ValidateDeps.kt` actually makes, read
from `MODULE.bazel` and `VERSION`. `tool/test/simulate-crash.sh` is excluded: it needs
Docker, a Bazel-built image and Console, loops for ten minutes by design, and is referenced
by no BUILD rule or Rust source, so upstream CI does not run it either.

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

## The lesson that cost the most

Twelve of the defects above were mine, and the runner caught them because it refuses to
classify what it cannot read. The thirteenth was different: nothing caught it, because it was
not a defect in code. I read `native_artifact_files` in `MODULE.bazel`, found no URL, and
concluded the artifacts were unobtainable — reporting 46 tests as blocked on a missing input
that was a `git clone` away.

No amount of runner strictness detects that. "The build downloads a binary" is not "the source
is unavailable", and the failure mode is stopping at the first dead end and reporting it as the
answer. It surfaced only because someone asked whether the source existed.

## Not yet done
* The two `todo!()` recovery tests are upstream's to fix, and are the baseline they must be
  held to until then.
* `bench_rocks` needs either an invocation with its required arguments or a port record
  saying it is a manual tool.
* The Mode Q Bazel snapshot remains open from G0 (ADR-0002); it needs a Bazel-capable
  environment this one is not. `NATIVE` is closed.
