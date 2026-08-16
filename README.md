# typedb-slatedb

TypeDB 3.x with a SlateDB-backed storage engine, deployable on Cloudflare's platform.

This repository is executing the R2 implementation programme defined in `contract/`. That
package is normative: where this README and the brief disagree, the brief wins.

**Current state: Phase A/B (gate G0).** No storage-engine work has begun. What exists is the
machinery that makes later claims checkable — a locked source graph, a machine-generated
test denominator, and a runner that refuses to report green on an incomplete run.

## Layout

```
contract/           the normative implementation package (read-only input)
sources/            pinned upstream checkouts, git-ignored, reproduced by the fetch scripts
fork/typedb/        working copy of TypeDB, upstream layout preserved
fork/slatedb/       working copy of SlateDB, upstream layout preserved
fixtures/           vendored typedb-behaviour corpus (read-only test data)
tools/              fork-owned Cargo workspace: xtask, corpus-catalog, conformance-runner, source-lock
source-lock/        generated source-graph lock
docs/architecture.md  architecture entry point (Arcadia perspectives + ADRs)
docs/architecture/    ADR/ and arcadia/ subfolders
docs/evidence/      per-phase artifacts and manifests
```

Three separate Cargo workspaces, deliberately. A root workspace spanning TypeDB and SlateDB
would change feature unification and lock resolution relative to upstream, which would make
the U0/U1 comparison meaningless. See ADR-0001.

## Commands

All commands run from the repository root.

```bash
# Materialise the pinned source graph (once, ~10 min).
bash contract/fetch-pinned-sources-v16.sh
bash contract/fetch-sources-extended.sh

# Resolve and digest the source graph; fails on a dirty, mismatched or shallow checkout.
cargo xtask source-lock

# Check the contract's internal consistency: patch ids, gate ids, schema compilability.
cargo xtask doc-lint

# Prove no BUILD rule is unaccounted for. Fails on any unknown macro.
cargo xtask verify-cargo-parity

# Build the machine-readable test denominator.
cargo xtask catalog-upstream-tests --with-libtest-listing

# Execute a profile against the catalogue and emit a coverage verdict.
cargo xtask test-upstream --profile U0

# Digest a phase's artifacts into a manifest.
cargo xtask evidence --phase phase-b
```

`cargo xtask` is an alias in `.cargo/config.toml`; every command also runs directly as
`cargo run --manifest-path tools/Cargo.toml -p xtask -- <command>`.

The U0/U1 corpus builds use the exact configuration in `tools/u0-build-env.sh`. Source it
before invoking cargo against `sources/typedb` or `fork/typedb` — the two lanes must be
built identically or the parity comparison compares two different builds.

## What the tooling is for

The programme's central claim is that a SlateDB-backed TypeDB passes the same tests as the
RocksDB-backed original. That claim is only as good as the denominator it is measured
against, so the denominator is generated, not asserted:

* **`source-lock`** resolves 14 upstream nodes to full commits and hashes their contents
  independently of git, then refuses to lock a graph containing a dirty checkout, a pin
  that does not match its tag, or a shallow clone of anything that ships.

* **`corpus-catalog`** reads TypeDB's BUILD files with a Starlark reader that errors on
  anything it does not recognise, keeps `select()` branches visible instead of collapsing
  them to the host platform, and resolves file-scope variables. It expands Gherkin
  `Examples:` tables into one leaf case per row, crosses the failpoint registry with its
  loop contexts, and reads libtest case lists off the built harnesses rather than parsing
  source text — so a `#[cfg]`-gated or macro-generated case cannot go missing.

* **`conformance-runner`** executes the catalogue and applies the rules that make a green
  meaningful: an unclassifiable outcome is `Unknown`, never a pass; a duplicate result
  never upgrades an earlier verdict; a zero-case target is a failure; and the run refuses
  to start if `SCENARIO_FILTER`, `FAILPOINTS` or `RUST_TEST_ARGS` are set in the ambient
  environment, because any of them would silently shrink the corpus.

Behaviour targets report per-scenario results rather than one pass for thousands of
scenarios; failpoint members are credited conservatively. See ADR-0003 for why each
composite harness is attributed the way it is.

## Evidence

`docs/evidence/<phase>/` holds raw artifacts and a `manifest.json` digesting them. Phase
summaries cite digests; they do not restate conclusions. Disagreements between the contract
and the pinned source are written up in `docs/evidence/phase-a/contradiction-records.md`
with source anchors — ten are recorded, four of them upstream defects rather than contract
errors, including two fixture paths misspelled in the branch Bazel CI never compiles.

Five source-graph nodes remain unresolved, each recorded against the gate it blocks rather
than assumed away. Three that were unresolved at the start — the native toolchain, TypeDB
Console and TypeDB Loader — have since been closed.

## Architecture

`docs/architecture.md` is the entry point. It routes to the five Arcadia perspectives
(`docs/architecture/arcadia/`) describing what the system does, and to the ADRs
(`docs/architecture/ADR/`) recording why it is shaped that way. The two do not repeat each
other. Levels 3 and 4 are marked provisional: no storage-engine work has begun, and reading
them as settled is the main way that documentation could mislead.
