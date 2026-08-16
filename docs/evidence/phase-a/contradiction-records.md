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
