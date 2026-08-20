# Bazel parity evidence (G0)

Answers: *are the cargo-run TypeDB tests equivalent to TypeDB's native Bazel
tests, or is cargo a parallel reality?*

Bazel **8.5.1** (the version `sources/typedb/.bazelversion` pins) was installed
and run against the source-locked tree. `parity.json` is the verdict document;
`raw/` holds the unedited stdout/stderr, digested in `raw-manifest.json`.
`tools/bazel/bazel_parity.py` recomputes every number from scratch and writes
`parity-recomputed.json`.

## What could and could not be executed

| Bazel phase | Command | Result |
|---|---|---|
| Loading | `bazel query` | **works, complete** |
| Analysis | `bazel cquery` | **blocked** |
| Execution | `bazel test` / `bazel build` | **blocked** |

The blocker is not disk and not Bazel. `aspect_bazel_lib` **registers**
`bats_toolchains`, fetched from
`https://github.com/bats-core/bats-core/archive/v1.10.0.tar.gz`. The agent
egress policy denies that URL with **403 Forbidden**, and a *registered*
toolchain must be loaded before Bazel can resolve toolchains for **any**
configured target. So every `cquery`/`build`/`test` aborts during analysis,
including trivial ones (`bazel cquery //common/cache:cache`). Per the proxy
README a 403 is an organisation policy denial that must be reported, not
routed around. Two further walls sit behind it: `//:developer-id-certs` needs
`VaticleDeveloperIDCombined.p12` from TypeDB's private repo (**401**), and
`//:deploy-mac-installer-pkg` is an upstream mac-only `alias` whose `select()`
has no default condition, so plain `cquery //...` cannot analyse on Linux even
with unrestricted network.

`bazel query` needs no toolchains, so the **target enumeration below is
complete and real**; only per-test *execution* under Bazel is unavailable.

## Consequence for Mode-Q

`tools/modeq/validate_modeq.py` requires a bundle carrying raw `bazel cquery`
stdout with `exit_code == 0`. That artefact **cannot be produced in this
environment**, so `docs/evidence/G0/mode-q/` has deliberately **not** been
created: the validator maps an absent directory to `MODEQ: ABSENT` (exit 0,
G0 correctly held open), whereas any non-conforming file there would flip it
to `MODEQ: INVALID` (exit 1) and break the gate check. G0 stays `OPEN_RED`,
now with a measured reason rather than "bazel not installed".

## Findings

* The catalogue's 141 `STATIC_CHECK` labels are **exactly**
  `kind(checkstyle_test|rustfmt_test, //... - //bazel-typedb/...)` — 141/141,
  no diff. (Catalogue spells the root package `//.:x`; Bazel prints `//:x`.)
* All **85** Bazel `rust_test` targets map **1:1 and bijectively** onto cargo
  targets, matched by source path — not by name. **No Bazel test target is
  missing from cargo.**
* The catalogue's 114 `CARGO` entries are **exactly** the live
  `cargo metadata` lib+test+bench+bin set — 114/114, no diff.
* **Zero** upstream `#[test]` functions were dropped by the fork; 253 were
  added.

### Divergences (all named)

1. `//tool/test:simulate-crash` — catalogue's only `SHELL` target. **It is not
   a Bazel target.** `//tool/test:all` contains only `//tool/test:checkstyle`.
2. `//:Release_validate_deps_gen`, `//:release-validate-deps` — real Bazel test
   targets absent from the catalogue (release-note validation, not Rust tests).
3. `executor:test:execute_comparison_check` — upstream file (blob
   `ac77f5d3`) with **1 `#[test]`** that cargo runs and Bazel does not:
   `executor/tests/BUILD` declares no `rust_test` for it. Catalogued as CARGO.
4. `//bazel-typedb/external/typedb_behaviour{,+,++}` — untracked symlinks this
   project created pointing at `sources/typedb-behaviour`, so cargo finds the
   `.feature` corpus where Bazel runfiles would put it. They make Bazel see 39
   extra `checkstyle_test` packages under `//...` that upstream does not have.
   Excluded everywhere above; a plain `bazel query //...` will show them.
5. Toolchain skew: Bazel would use rust **1.93.0** (`MODULE.bazel`); there is
   no `rust-toolchain.toml`, so cargo runs use the ambient **1.94.1**.
6. 10 of the 85 `rust_test` targets have fork-modified sources of their own, so
   cargo and pinned-Bazel do not run identical bodies there. The largest is
   `//storage/tests:test_recovery`: 7 tests pinned, 18 in the working tree.

## Verdict

Restricted to the Rust test targets, **cargo is a faithful strict superset of
Bazel** — every Bazel `rust_test` has a cargo counterpart over the same
sources, plus `execute_comparison_check` and 253 fork-added tests. It is *not*
a parallel reality. The unproven part is behavioural, not structural: no test
was executed under Bazel, so identical *outcomes* remain unverified.

## Reproducing

```
tools/bazel/bazel_parity.py --bazel /home/user/.bazel-bin/bazel
```

Bazel 8.5.1 lives at `/home/user/.bazel-bin/` (sha256
`61d89402f0368e64b6c827be5de79d8e65382e8124c3cbb97325611a1851392e`, verified
against the release's own `.sha256`); its output base is `/home/user/.bazel-out`
(528 MB). Both are outside the repo and safe to `rm -rf`.

**Side effect to watch:** Bazel rewrites `sources/typedb/MODULE.bazel.lock`
during module resolution (+139/-2 lines here, from resolving the `git_override`
deps). It was restored to the pinned blob after these runs — re-check it with
`git -C sources/typedb status --porcelain MODULE.bazel.lock` after any Bazel
invocation, since `sources/**` is source-locked.
