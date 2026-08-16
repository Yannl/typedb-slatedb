# Repository layout

```
contract/            normative implementation package — read-only input
sources/             pinned upstream checkouts (git-ignored, reproducible)
fork/typedb/         working copy of TypeDB, upstream layout preserved
fork/slatedb/        working copy of SlateDB, upstream layout preserved
fixtures/            vendored typedb-behaviour corpus
tools/               fork-owned Cargo workspace
source-lock/         generated source-graph lock
build/               all build output (git-ignored)
docs/                architecture, dev, ops, user, evidence
```

## Why three Cargo workspaces

`fork/typedb`, `fork/slatedb` and `tools/` are separate workspaces, and this is deliberate.

A single root workspace spanning TypeDB and SlateDB would change **feature unification** and
**lock resolution** relative to upstream. The U0/U1 comparison would then be measuring a
dependency graph that upstream never builds, and a difference could be blamed on SlateDB when
it was caused by repository layout. See [ADR-0001](../architecture/ADR/0001-repository-topology-and-orchestration.md).

`tools/` builds on stable Rust independently of the 1.93.0 parity lane, so a tooling bug can
never be confused with corpus behaviour.

## `sources/` vs `fork/`

| | `sources/` | `fork/` |
|---|---|---|
| Contents | pristine upstream checkouts | working copies patches apply to |
| Git-tracked here | no | yes |
| Used by | U0 (the baseline) | U1 (the fork) |

U0 runs against `sources/typedb` **precisely because it must be pristine**. If you find
yourself editing anything under `sources/`, stop: that invalidates the baseline. The one
exception is fixture staging, which the runner does itself and which the source lock excludes
from the content digest.

## `tools/` crates

| Crate | Responsibility |
|---|---|
| `source-lock` | Resolve and digest the source graph; refuse dirty, mismatched or shallow shipping nodes |
| `corpus-catalog` | Generate the test denominator from BUILD files, Gherkin, failpoints, libtest listings |
| `conformance-runner` | Execute the catalogue; classify every outcome; decide the gate |
| `xtask` | Command surface |

The dependency direction is `xtask → {conformance-runner, corpus-catalog, source-lock}` and
`conformance-runner → corpus-catalog → source-lock`. Nothing depends on `xtask`.

## `build/`

| Path | Contents |
|---|---|
| `build/u0/` | the pristine-pin corpus build |
| `build/console/` | TypeDB Console, built from source |
| `build/assembly/` | the distribution archive |

Everything here is disposable and git-ignored. **Nothing is written beside the sources** —
an artifact dropped in a checkout pollutes the source graph digest, which happened once and
made the digest drift with every run.

The one exception is the assembly archive, which `fail_points.rs` requires as a bare filename
in the working directory. The runner stages a copy there and the source lock excludes it.
