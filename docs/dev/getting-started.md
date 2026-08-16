# Getting started

## Prerequisites

| Tool | Version | Why |
|---|---|---|
| Rust | 1.93.0 **and** a recent stable | 1.93.0 is the parity lane for the corpus; stable builds `tools/` |
| rustfmt | nightly-2026-04-15 | the exact formatter upstream pins; a different one is a different check |
| C/C++ toolchain | 13.3.0 here | `librocksdb-sys` compiles a large C++ tree |
| protoc | 32.1 | the Cargo build of `server/service/admin/proto` needs it |
| CMake, make, pkg-config, git | — | native dependencies |
| Docker | — | only for the container work (not yet started) |

```bash
rustup toolchain install 1.93.0
rustup toolchain install nightly-2026-04-15 --profile minimal --component rustfmt
```

`cargo xtask native-toolchain` records exactly what your machine will use, and fails loudly
if something is missing. Run it before wondering why a build behaves differently to CI.

## Disk and time

Budget honestly, because both surprised this project:

| | |
|---|---|
| Pinned sources | ~1.5 GB |
| U0 build tree | ~13 GB |
| Full corpus build | ~35 min cold |
| Full U0 run | ~90 min (`test_fail_points` alone is ~31 min) |

Debug info is **off** by default (`tools/u0-build-env.sh`). With it on, the workspace build
exceeded 24 GB and ran out of disk. That setting is recorded rather than assumed because it
must be identical across the U0 and U1 lanes.

## First run

```bash
# 1. Materialise the pinned sources (~10 min, network).
bash contract/fetch-pinned-sources-v16.sh
bash contract/fetch-sources-extended.sh

# 2. Build the tooling and check it.
cargo build  --manifest-path tools/Cargo.toml
cargo test   --manifest-path tools/Cargo.toml     # 73 tests

# 3. Lock and digest the inputs.
cargo xtask source-lock
cargo xtask native-toolchain

# 4. Cheap consistency checks (seconds).
cargo xtask doc-lint
cargo xtask verify-cargo-parity

# 5. Build the denominator (~35 min: it compiles every harness).
cargo xtask catalog-upstream-tests --with-libtest-listing

# 6. Optional — the packaging fixture, needed by 46 tests.
cargo build --release -p typedb-console --locked \
  --manifest-path sources/typedb-console/Cargo.toml
cargo xtask assemble

# 7. The baseline (~90 min).
cargo xtask test-upstream --profile U0
```

Steps 1–4 are the fast loop. Step 5 is the expensive one and only needs redoing when the
sources or the catalogue logic change.

## What "good" looks like

```
cargo xtask source-lock          → 14 nodes, 5 unresolved, no dirty/shallow shipping node
cargo xtask doc-lint             → findings: 0
cargo xtask verify-cargo-parity  → unknown BUILD rules: 0, unparsed: 0
cargo xtask catalog-upstream-tests → 258 targets, 4 757 leaf cases
```

If `source-lock` reports a node as dirty, you have modified a pinned checkout. Untracked
run residue (`typedb-logs/`, the staged fixture trees) does **not** count as dirty — only
tracked-file changes do.

## Running a subset while iterating

```bash
cargo xtask test-upstream --profile U0 --only test_connection
```

This prints a warning and marks the run as unable to support a coverage claim, which is
intentional: a filtered run is for iteration, never for evidence.

Do **not** set `SCENARIO_FILTER`, `FAILPOINTS` or `RUST_TEST_ARGS` in your shell. The runner
refuses to start if it sees them, because each would silently shrink the corpus and produce a
green over a subset.
