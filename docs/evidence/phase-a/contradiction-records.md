# Contradiction records — Phase A (G0)

Per `AGENTS.md` §4 and playbook J.9, a disagreement between the contract and the pinned
source is recorded with anchors and a minimal correction. It is never converted into a
silent exclusion.

Anchors are against the locked pins: TB `2256711abd532742dae8e822a9ad5cce63e69b1a`,
TBD `a5c51254088f343fb8b6a9668eaf99b35503dad4`,
TBDIST `ab5bfc90274e2d34569d5bc22558314b551cdecd`.

---

## CR-A-01 — Workspace member count is 42, not 41

**Contract claim.** Brief Appendix G.1 item 6: "Workspace: 41 members enumerated at root
`Cargo.toml` L157-159 (exact list frozen into the G0 catalogue). **I**."
Addendum A17.1 repeats "41 workspace members" as a source-verified fact, and `AGENTS.md`
§2 restates it.

**Observed.** TB `2256711a` root `Cargo.toml` **line 159** (a single line, not L157-159)
declares **42** members, all distinct:

```
database/tools, database, answer, util/test, util/project,
durability/tests/crash/streamer, durability/tests/crash/recoverer,
durability/tests/common, durability, ir, tests/behaviour/steps,
tests/behaviour/steps/params, tests/behaviour/service/http/http_steps, admin,
admin/client, encoding/tests, encoding, server, server/service/admin/proto, user,
function, storage/tests, storage, system, common/options, common/structural_equality,
common/logger, common/cache, common/bytes, common/lending_iterator, common/primitive,
common/fail_point, common/concurrency, common/iterator, common/error, concept/tests,
concept, diagnostics, executor, resource, query, compiler
```

`cargo metadata --locked --no-deps` reports 43 packages: the 42 members plus the root
package `typedb_server_bin`, which the workspace's own `[package]` section declares.

**Correction.** The member count is 42; the package count is 43. The generated
`source-lock.json` and the catalogue carry the enumerated list, so no downstream artifact
depends on the prose number. This is exactly the case the contract anticipated: brief §1.4
already states that prose counts are "a reconnaissance floor only … not a release
denominator until emitted by the versioned catalogue generator".

**Impact.** None on architecture. It does invalidate the use of "41" as a checksum for
"did we see the whole workspace", which is why the census is now machine-generated.

**Confirmed unaffected.** The other census numbers in Appendix G.2 reproduce exactly:
59 `[[test]]` and 8 `[[bench]]` targets across 13 manifests, root contributing 16 `[[test]]`
(including the two bench harnesses `bench_concurrency` and `bench_iam`) and 0 `[[bench]]`.

---

## CR-A-02 — `release_validate_deps` is a test-producing macro the census omits

**Contract claim.** Brief Appendix G.2 gives the "real target-level denominator" as the 59
`[[test]]` + 8 `[[bench]]` Cargo census, and §1.5's Mode Q/S requirement is that "every
relevant macro and external repository declaration is parsed/expanded … with zero unknown
target". §22.2 does list "release/dependency validations" as denominator members, but no
document names the macro or counts its targets.

**Observed.** TB root `BUILD` L647-656 calls `release_validate_deps(name =
"release-validate-deps", refs = "@typedb_workspace_refs//:refs.json", tagged_deps =
["@typeql+", "@typedb_protocol+"], tags = ["manual"], version_file = "VERSION")`.

At TBD `tool/release/deps/rules.bzl` this is a **macro** (L52) that expands to two test
targets:

* `_release_validate_deps_script_test` — `rule(implementation = …, test = True)` (L29-48),
  instantiated as `Release_validate_deps_gen`;
* `kt_jvm_test(name = "release-validate-deps", …)` (L62-70).

Both are Kotlin/JVM. Cargo cannot express either, and they appear in no Cargo manifest, so
a Cargo-only reading of the corpus misses them entirely. Upstream tags the call site
`manual` with the in-tree comment `# in order for bazel test //... to not fail`, so even a
`bazel test //...` sweep would not run them.

**Correction.** The macro is registered as test-producing in
`tools/corpus-catalog/src/starlark.rs::TEST_PRODUCING_RULES`, and the catalogue emits both
expansions as `origin = BAZEL_MACRO`, `port_status = SEMANTIC_PORT`, with
`declared_ignored = true` reflecting the upstream `manual` tag. The semantic port is a Rust
check over the same three inputs the Kotlin harness reads — workspace refs, the `VERSION`
file, and the tagged dependency list — which `cargo xtask source-lock` already resolves
(TQL tag `3.12.2` → `7f4cac93fa8eee8643aa9f75eb60cacb5a454842`, TPROTO tag `3.12.0` →
`0373c1ae106b1f68e80edb06c1b7375075fe62e2`).

**Impact.** Two targets and two leaf cases enter the denominator that the prose census
would have left out. The general lesson is applied structurally: the BUILD reader now fails
on any rule it has not been told about, instead of ignoring it, so the next unlisted macro
stops the catalogue rather than silently shrinking it.

---

## CR-A-03 — Cargo behaviour tests resolve fixtures through a Bazel symlink-farm path

**Contract claim.** Brief §22.5 requires backend/profile selection to be injected centrally
so upstream test files stay byte-identical, and Appendix E.3-15 asks for the Bazel
`data`/`env`/runfiles matrix. Neither states that the non-Bazel path is already wired into
the test sources.

**Observed.** Every behaviour entry point carries both paths in source, e.g. TB
`tests/behaviour/connection/database.rs` L17-23:

```rust
#[cfg(feature = "bazel")]
let path = "../typedb_behaviour+/connection/database.feature";

#[cfg(not(feature = "bazel"))]
let path = "bazel-typedb/external/typedb_behaviour+/connection/database.feature";
```

`bazel-typedb/` is Bazel's convenience symlink into its output base. It does not exist in a
pure-Cargo checkout, so under plain `cargo test` these targets fail on a missing fixture
rather than reporting a skip.

**Correction.** No source edit. The runner stages the pinned corpus at exactly
`<workspace>/bazel-typedb/external/typedb_behaviour+/` before execution
(`conformance-runner::stage_behaviour_corpus`) and asserts a known feature file exists
afterwards, so a staging failure stops the run instead of degrading into a test that
asserts on an absent file. These targets are classified `LAUNCHER_ADAPTED`: fixtures and
environment are reproduced externally, test sources unchanged.

**Impact.** Confirms the contract's expectation that assembly/behaviour targets can stay
byte-identical. It also fixes the classification: they are launcher-adapted, not
byte-identical, because the runner must supply something Bazel used to.

---

## CR-A-04 — One Cargo manifest is hand-maintained and outside the sync gate

**Contract claim.** Brief §21.10: "TypeDB's committed generated Cargo manifests are the
migration seed", and Appendix G.1-2 anchors the sync tool as the generator of Cargo
metadata.

**Observed.** TB `server/service/admin/proto/Cargo.toml` L1-13 is an explicit exception,
in its own words: "Hand-maintained — do NOT regenerate with the cargo sync tool", because
the sync tool's aspect "doesn't emit any build-dep information for lib/bin targets, so a
blind re-sync would drop `[build-dependencies]` (and also rewrite `[lib] path` and
`edition`)". It further records that `tool/rust/sync.sh` saves and restores this file
around the sync, and that "the CI `cargo-toml-sync` gate is intentionally disabled for the
same reason".

Concretely, this crate builds its protobufs two different ways: Bazel via
`rust_tonic_compile` (`server/service/admin/proto/BUILD` L16-20) and Cargo via `build.rs`
with `tonic-build ^0.12`. The Cargo path needs a `protoc` binary on `PATH`, which no
contract document lists among the pinned native tools.

**Correction.** Two things follow. First, the fork's manifest-ownership patch (TB-P0
family) must treat this file as already fork-owned and must not restore sync-tool
authority over it. Second, `protoc` is a required build input for the Cargo lane; it is
pinned at 32.1 (`sha256
e9c129c176bb7df02546c4cd6185126ca53c89e7d2f09511e209319704b5dd7e` for
`protoc-32.1-linux-x86_64.zip`) and carried in the `NATIVE` unresolved node until the full
native-toolchain digest set is locked.

**Impact.** Small but load-bearing: a naive "regenerate all manifests from the sync tool"
step in TB-P0 would silently break the admin proto crate's Cargo build.

---

## CR-A-06 — An upstream test file that upstream's own CI never runs

**Contract claim.** Brief Appendix G.2 treats the Cargo `[[test]]`/`[[bench]]` census and the
Bazel `rust_test` set as two readings of one corpus, and §21.10 frames the reconciliation as
a drift check between them. The implicit assumption is that the two sets differ only in
naming.

**Observed.** `executor/tests/execute_comparison_check.rs` exists in the tree. It is not
named by any rule in `executor/tests/BUILD`, which declares 11 `rust_test` targets covering
`compile_execute.rs`, `efficiency.rs`, `execute_expression.rs`, `execute_function.rs`,
`execute_has.rs`, `execute_isa.rs`, `execute_links.rs`, `execute_relation_index.rs`,
`execute_select.rs`, `pipelines.rs` and `writes.rs` — every sibling except this one. Since
`executor/tests/` is not a workspace member, Cargo auto-discovers the file as an integration
test of package `executor`.

So the file is compiled and linted by upstream's `rustfmt_test` / `checkstyle_test` globs,
but never executed by `bazel test`. It is the only Cargo-visible target in the whole
workspace for which no BUILD rule of any kind declares the name; the other 28 Cargo-only
entries are all explained by a `rust_library` or `rust_binary` at the same path
(`cargo-build-reconciliation.json` → `cargo_only_explained`).

**Correction.** None to the contract's architecture; the reconciler now explains every
Cargo-only target against the upstream rule that owns it, so this one is visibly different
in kind rather than buried in a list of names. The case stays in the denominator: the Cargo
lane will run it, so U0 must record what it does.

**Impact.** Practical and immediate. If this test is stale and fails, the U0 baseline is red
for a reason that has nothing to do with SlateDB — and a U1 run compared against a green
assumption would then look like a regression the port caused. Establishing U0 empirically,
rather than assuming upstream is green, is what makes that distinguishable. Its U0 outcome
is the baseline it will be held to, whatever that outcome is.

---

## CR-A-07 — Two behaviour tests resolve fixtures the Bazel way and only the Bazel way

**Contract claim.** CR-A-03 established that behaviour tests carry both a Bazel and a
non-Bazel fixture path, and that staging the corpus at
`bazel-typedb/external/typedb_behaviour+/` therefore satisfies the Cargo lane while keeping
every upstream source byte-identical. Brief §22.5 depends on that being true corpus-wide.

**Observed.** It is not true of two of them. `tests/behaviour/concept/migration/
data_validation.rs` L11-14 and `migration.rs` L11-14 read:

```rust
// Bazel specific path: when running the test in bazel, the external data from
// @typedb_behaviour is stored in a directory that is a sibling to
// the working directory.
assert!(Context::test("../typedb_behaviour+/concept/migration/data-validation.feature", true).await);
```

There is no `#[cfg(not(feature = "bazel"))]` alternative — unlike, say,
`connection/database.rs` L17-23, which has both. Under Cargo these two can never find their
feature files, and the first corrected U0 run failed them with `Failed to parse feature:
Could not read path: ../typedb_behaviour+/concept/migration/data-validation.feature`. The
harness exits 101 and produces zero scenarios, so the 1 877 catalogued scenarios of
`test_concept` and 1 773 of `test_query` were reported as unattributable rather than as
passes.

**Correction.** The runner stages the same pinned corpus at both conventions: under
`bazel-typedb/external/typedb_behaviour+/` for the non-Bazel branch, and as a sibling of the
workspace directory for these two. No upstream source is edited, so the byte-identical
classification survives; the launcher supplies what Bazel used to, which is what launcher
adaptation means.

**Impact.** Without it, two features (`concept/migration/data-validation.feature` and
`migration.feature`) are unreachable under Cargo, and — because a non-zero exit with no
failing scenario is deliberately unattributable — they poison the verdict for the two largest
behaviour targets rather than failing quietly on their own.

---

## CR-A-08 — Two upstream fixture paths are misspelled, and only Cargo can see it

**Contract claim.** Brief §22.5 and CR-A-03 both proceed on the basis that the non-Bazel
fixture path in each behaviour test is a working alternative to the Bazel one — that the
`#[cfg(not(feature = "bazel"))]` branch is maintained code.

**Observed.** It is not. Across `tests/behaviour/**`, the corpus is referenced by three
different names, and the run found each of them:

| Source | Non-Bazel path | Correct? |
|---|---|---|
| 92 files, e.g. `connection/database.rs` L20-21 | `bazel-typedb/external/typedb_behaviour+/…` | yes |
| `query/language/variables.rs` **L20** | `bazel-typedb/external/typedb_behaviour**++**/…` | **no** — one `+` too many |
| `query/language/given.rs` **L20** | `bazel-typedb/external/typedb_behaviour/…` | **no** — no `+` at all |

A count over the tree gives 94 occurrences of `typedb_behaviour+` and exactly 1 of
`typedb_behaviour++`.

Both defects sit in the branch selected when the `bazel` feature is **off**. Bazel builds
with `crate_features = ["bazel"]`, so upstream CI compiles the other branch and has never
executed either line. That is what allowed two typos to survive in a released tag: the Cargo
path is not merely a convenience, it is unexercised.

Observed effect in the third U0 run: `test_query` exits 101 with
`Failed to parse feature: Could not read path:
bazel-typedb/external/typedb_behaviour++/query/language/variables.feature`, failing
`language::variables::test_read_variables` and `language::given::test_write_given`. Because a
non-zero exit with no failing scenario is deliberately unattributable, all 1 773 catalogued
scenarios of that target were reported `Unknown` rather than passed.

**Correction.** No source edit — U0 is defined on the pristine pin, and patching it would
make it something else. The runner instead reads the fixture roots out of the test sources
and stages the pinned corpus at every one it finds, so the tests open what they ask for. The
implementation deliberately derives the list rather than hardcoding these three spellings, so
a fourth stages itself instead of failing a run.

**Impact.** Two upstream test files cannot pass under Cargo at this pin without launcher
help. More broadly, this is direct evidence for how much the migration rests on unexercised
code: the very branch the Cargo lane depends on contains bugs upstream CI cannot see. It also
argues that the fork should eventually fix these paths — a one-character change in each —
rather than carry the staging workaround forever. Tracked for the fork's patch series, not
applied to U0.

---

## CR-A-09 — "Is this scenario ignored?" has no answer without naming the harness

**Contract claim.** Brief §22.2 treats `declared_ignored` as a property of a leaf case, and
the catalogue schema carries it as one boolean per scenario. That presumes a single ignore
predicate over the corpus.

**Observed.** There are two, and they disagree:

| Harness | Source | Predicate |
|---|---|---|
| native (gRPC) | `tests/behaviour/steps/lib.rs` L268-269 | `tag == "ignore" \|\| tag == "ignore-typedb"` |
| HTTP driver | `tests/behaviour/service/http/http_steps/lib.rs` L243-245 | `t == "ignore" \|\| t == "ignore-typedb-http"` |

A scenario tagged `@ignore-typedb-http` is skipped by the HTTP suites and **executed** by the
native ones; `@ignore-typedb` does the reverse. Only bare `@ignore` suppresses everywhere.
The same feature files are consumed by both harnesses, so the same scenario is
simultaneously ignored and not ignored depending on which target is asking.

Observed effect: the fifth U0 run reported `driver/connection.feature` scenarios such as
"Driver can configure request timeout" (tagged `@ignore-typedb-http` at L63) as
**never executed** under `test_http_driver_connection`, because the catalogue — using a
single native predicate — counted them as runnable.

**Correction.** The corpus is parsed once per harness and behaviour targets under
`tests/behaviour/service/http` take the HTTP reading. `declared_ignored` is therefore
resolved per `(scenario, target)` rather than per scenario. Count moves from 26 to 31.

**Impact.** Mis-sizes the denominator in *both* directions if collapsed: HTTP-ignored
scenarios appear as unexecuted holes, and native-ignored ones would be written off as
declared skips under HTTP targets that really do run them — the second being the more
dangerous, since it hides real coverage loss behind an expected-skip label. Any future
harness added to the behaviour tree needs its own predicate registered here rather than
inheriting one.

---

## CR-A-10 — Bazel `data` says what is available, not what runs

**Contract claim.** Appendix E.3-15 asks for the Bazel `data`/`env`/runfiles matrix as the
way to know which fixtures a target consumes, which reads as though `data` defines a target's
corpus.

**Observed.** `data` defines *availability*. `test_query` declares
`@typedb_behaviour//query/functions:negation.feature` as data, but nothing opens it: the
directory `tests/behaviour/query/functions/` contains `basic.rs`, `definition.rs`,
`recursion.rs`, `signature.rs`, `structure.rs` and `usage.rs`, and no `negation.rs`. The
feature itself carries `# TODO: Port to 3.0` at L5 and 6 scenarios (one already `@ignore`).

Counting from `data` therefore placed 6 scenarios in the denominator that no entry point can
reach, and they sat in `not_executed` permanently.

**Correction.** A target's features are the intersection of its `data` and the
`Context::test("…")` string literals found in its source tree. Sources alone are not
sufficient either: the catalogue deliberately hashes sibling modules, and those belong to
neighbouring targets — using the source-derived set unfiltered inflated the Cucumber count
from 4 164 to 5 052. Available **and** opened gives 4 158.

**Impact.** Six phantom denominator entries removed. The general point is that the two
readings answer different questions, and the migration needs both: `data` alone over-counts
dead fixtures, sources alone leak across target boundaries.

---

## CR-A-05 — A decoy Rust version in the dependencies repo (no contract change)

Recorded because it is the kind of anchor that looks authoritative and is not.

TBD `builder/rust/versions.bzl` L7 declares `RUST_VERSION_TYPEDB = "1.81.0"` with
`edition = "2021"`. This is **not** the toolchain TypeDB uses. TB `MODULE.bazel` L32-49
calls `rust.toolchain(edition = "2024", versions = ["1.93.0"], rustfmt_version =
"nightly/2026-04-15")` and `rust_host_tools.host_tools(version = "1.93.0")` directly,
bypassing the helper. Every workspace manifest declares `edition = "2024"`, which 1.81.0
cannot compile.

The contract's parity lane of Rust `1.93.0` (brief §1.6, addendum A17.1) is **confirmed
correct**. The parity lane is installed and used for the U0 baseline.

---

## Non-contradiction: build configuration recorded, not assumed

The U0 baseline is built with debug info disabled
(`CARGO_PROFILE_{DEV,TEST}_DEBUG=0`, `CARGO_INCREMENTAL=0`; see
`tools/u0-build-env.sh`). This is a capacity decision, not a semantic one: a full
`--all-targets` DWARF build of the 43-package workspace exceeded 24 GB and exhausted this
machine's writable allowance before linking finished, whereas the same corpus builds in
6.6 GB without debug info. Test semantics — assertions, panics, libtest case discovery,
Cucumber scenario selection — are unaffected.

Brief §21.7 requires correctness options to be "typed, explicit, sanitized, hashed, and
attested" rather than inherited from defaults, so the settings live in a checked-in script
that both U0 and U1 source. The structured-equality claim of addendum A17.4(b) compares two
builds made with identical settings; it would be void if the lanes differed here.
