# Development guide

How to build, test, and change this repository. Read
[architecture.md](architecture.md) first for what the pieces are.

## Bootstrapping a fresh machine

`sources/` (the pinned upstream checkouts and fixtures) is deliberately not
committed — it is large and fully determined by
`source-lock/source-lock.json`. A fresh clone therefore has no checkouts,
and every Rust lane is unrunnable until they exist. Three commands fix that:

```sh
python3 tools/dev/doctor.py                        # what's missing, and the fix
python3 tools/source-lock/materialize_sources.py   # sources/ from the lock
python3 tools/source-lock/lint_source_lock.py      # LINT: PASS
```

`doctor.py` checks the native toolchain against lock node
`NATIVE_TOOLCHAIN` (the corpus build needs `protoc`, `cmake`, and a C/C++
toolchain — a missing `protoc` otherwise surfaces 20 minutes into a cold
build), the parity Rust toolchain against `RUST_PARITY`, the checkouts, and
`control-plane/node_modules`. `materialize_sources.py` is the inverse of the
lint: it clones every git node at its locked revision (verifying HEAD, tree
hash and cleanliness) and downloads the pinned fixtures (verifying sha256
before accepting the bytes). Both are idempotent.

Then, per lane:

```sh
cd control-plane && npm ci                         # control-plane lanes
cd sources/typedb && cargo +1.93.0 test --workspace --no-run   # ~40 min cold
```

## Toolchains

| Lane | Toolchain | Used for |
|---|---|---|
| Rust parity | `1.93.0` (pinned) | everything under `fork/typedb` / `sources/typedb` — the version the TypeDB pin declares |
| Rust tools | stable | `tools/` workspace |
| rustfmt | `nightly-2026-04-15` + workspace `rustfmt.toml` | formatting fork-touched files (statics enforce this) |
| Node | 22.x + npm | `control-plane/` |
| wrangler | pinned via `control-plane/package-lock.json` | workerd/L1 stack |

## Repo workspaces

Three independent build worlds (deliberately not one workspace — brief
§0.2.1):

- `fork/typedb` — the TypeDB soft-fork. **Never edit upstream test files**;
  every non-test patch needs a `PORT-LEDGER.md` entry with a
  behavior-preservation argument. Its `Cargo.toml` also carries the
  workspace-global `[patch.crates-io]` redirect to the SlateDB soft fork.
- `fork/slatedb` — the SlateDB soft-fork, carried as a **patch series over
  the digest-pinned 0.15.0 crate** (`patches/`, `UPSTREAM-PROVENANCE`,
  `PATCH-LEDGER.md`). Materialised to the git-ignored `sources/slatedb-fork`
  and consumed by path; see *Patch discipline (fork/slatedb)* below.
- `tools/` — corpus catalog/runner (`catalog/`), pure protocol models
  (`protocol-models/`), the deterministic remote-WAL spike + L1 client
  (`remote-wal-spike/`), the SlateDB semantics differential
  (`storage-diff-spike/`), source-lock lint (`source-lock/`).
- `control-plane/` — Worker entry, `DatabaseControllerDO`, its
  deterministic core (`src/controller/core/`), node + workerd test suites,
  and the L1 E2E script.

## The staging model (fork ↔ sources)

Upstream test execution happens in `sources/typedb` (a pinned git checkout)
so that the warm build cache and Bazel-equivalent runfile layout are
preserved:

1. Edit code in `fork/typedb/...`.
2. Stage: `python3 tools/fork/stage.py` copies every fork file that differs
   into `sources/typedb` (content comparison, not timestamps).
   `--check` reports STAGED / PRISTINE / MIXED without writing.
3. Build/test inside `sources/typedb` with the parity toolchain.
4. When done, `python3 tools/fork/stage.py --restore` puts the checkout back
   at the locked revision (build outputs are kept, so the warm
   `target/` cache survives) and the source-lock lint passes again.

(`tools/fork/materialize.sh` goes the other way: it reproduces `fork/typedb`
from the lock + patch series, for a from-scratch fork rebuild.)

`python3 tools/source-lock/lint_source_lock.py` must PASS before you
commit: it verifies every lock node (git revision + clean tree for
checkouts, version + checksum against the consumer `Cargo.lock` for the
registry-consumed SlateDB node).

## Running the test lanes

### Fork unit/integration tests (per profile)

```sh
cd sources/typedb
cargo +1.93.0 test -p storage                          # U1 (RocksDB oracle, default)
TYPEDB_STORAGE_PROFILE=U2 cargo +1.93.0 test -p storage  # U2 (SlateDB)
```

Two upstream `todo!()` stubs in `test_recovery` fail by construction on
every profile; the baseline records them.

### The full upstream corpus

```sh
# build every test executable once
cd sources/typedb && cargo +1.93.0 test --workspace --no-run

# run the complete corpus against a profile, archiving evidence
TYPEDB_STORAGE_PROFILE=U2 python3 tools/catalog/run_u0.py --reap \
    --out docs/evidence/G3/u2-full
```

The runner reproduces Bazel semantics (serial groups for assembly-family
targets, isolated staging cwds, archive mode via `TYPEDB_ASSEMBLY_ARCHIVE`,
generous stacks, short `TMPDIR`, and the
`bazel-typedb/external/typedb_behaviour+` convenience symlink that
behaviour suites read their Cucumber features through — created
unconditionally at startup, covered by upstream's `bazel-*` gitignore),
reaps stray server processes, and writes one JSON row per executable.
If you run behaviour suites via bare `cargo test` instead of the runner,
create that symlink once yourself (point it at `sources/typedb-behaviour`). The assembly archive must contain a
**current** server binary — rebuild it after fork changes:

```sh
python3 tools/catalog/package_assembly.py
```

### Control plane

```sh
cd control-plane
npm run typecheck
npm run test:controller          # node lane vs real SQLite (+ mutant control)
npm run test:workerd             # vitest-pool-workers: real workerd DO + R2
npx wrangler dev --local --port 8791 &   # then:
node scripts/local-stack-e2e.mjs http://127.0.0.1:8791   # 20-check E2E
```

### Tools workspace

```sh
cd tools && cargo test --workspace
```

`remote-wal-spike`'s `l1_stack` test self-boots a wrangler stack (leak-free
process-group reaping). `storage-diff-spike` is the SlateDB-vs-oracle
semantics differential — re-run it whenever the SlateDB pin moves.

### Static checks

```sh
python3 tools/catalog/run_static.py --out /tmp/static.json   # 141 checks
```

## Patch discipline (fork/typedb)

1. No upstream test-file edits, ever. Test-infrastructure changes need a
   ledger entry with a behavior-preservation argument.
2. Non-test patches carry stable IDs (TB-P*) and land with: the ledger
   entry, rustfmt-clean formatting under the pinned nightly, and green
   baselines on **both** U1 (oracle unchanged) and U2.
3. Dependency additions to the fork must be checksum-locked and mirrored in
   the source lock where they are proof-critical (see node `SL`).

## Patch discipline (fork/slatedb) — the SlateDB soft fork

SlateDB **is** patched, and the patched crate is what every product build
links (ADR-0012; ADR-0001's "never edit SlateDB" rule is superseded). The
fork is a *patch series over a digest-pinned crate*, never a vendored tree:

| Artifact | What it is |
|---|---|
| `fork/slatedb/patches/000{1..5}-*.patch` | the fork's entire identity, in review order |
| `fork/slatedb/UPSTREAM-PROVENANCE` | base crate + sha256, the patch list, and the **post-patch tree digest** |
| `fork/slatedb/PATCH-LEDGER.md` | per-patch rationale and upstream-contribution intent |
| `sources/slatedb-fork/` | materialised, git-ignored; reconstructed, never edited by hand |
| `[patch.crates-io]` in `fork/typedb/Cargo.toml` | the workspace-global redirect that makes the fork the resolved `slatedb` |

Rules:

1. **Never edit `sources/slatedb-fork/` in place.** It is regenerated by
   `python3 tools/fork/materialize_slatedb.py`; hand edits are erased and
   leave no reviewable record. Change the crate by adding or amending a
   patch in `fork/slatedb/patches/`, then re-record the post-patch tree
   digest.
2. **Minimal-patch rule.** Prefer the adapter
   (`fork/typedb/storage/keyspace/slate.rs`) over a SlateDB patch whenever
   the semantics are reachable through the public API. A patch is justified
   only when the mechanism itself is wrong for us — as with externally
   issued epochs, which no public API exposes.
3. **Upstream first.** Any patch that could be an upstream contribution is
   proposed upstream before it is carried here; the ledger entry records
   the upstream issue/PR or why there is none.
4. `python3 tools/fork/materialize_slatedb.py --check` must pass: it fails
   when a patch was edited without re-recording the digest. `git diff --check`
   does **not** police the patch bodies — a unified diff represents an empty
   context line as a single space, so `.gitattributes` disables whitespace
   linting for `*.patch` and the tree digest is the real integrity check.
5. `python3 tools/fork/check_strict_epoch.py` and
   `check_strict_epoch_suite.py` attest that the shipped
   `external_epoch_required` feature is actually resolved and actually
   enforced. Removing the feature is a **release-blocking** change, not a
   configuration tweak.

### Upgrading / rebasing the fork onto a new SlateDB release

1. Update the crate pin and its sha256 in `source-lock/source-lock.json`
   (node `SL`) and `fork/slatedb/UPSTREAM-PROVENANCE`.
2. Re-apply the series: `python3 tools/fork/materialize_slatedb.py`. Fix
   rejects **in the patch files**, never in the materialised tree.
3. Re-record the post-patch tree digest; `--check` must then pass.
4. Re-run the differential oracle (`tools/storage-diff-spike`, which
   deliberately links the *unpatched registry* crate) to show the fork did
   not change semantics it was not meant to change.
5. Re-run `python3 tools/fork/check_strict_epoch_suite.py`, the storage
   library and integration lanes, and the feature-on/feature-off SlateDB
   suites.
6. Re-run `python3 tools/ci/check_dependency_sources.py`: it re-derives the
   resolved source from `cargo metadata` and fails if the documentation and
   the graph have drifted apart.

**Risk ownership.** Carrying a storage-engine fork is a standing
maintenance liability: rebase cost on every upstream release, and a
divergence surface no upstream CI covers. It is owned by the storage lane
owner together with ADR-0012, and it is bounded by the minimal-patch and
upstream-first rules above.

## Debugging tips

- Fork test failures on U2 only: check the adapter's semantics mapping
  first (empty-batch no-op, cursor backward-seek fresh-scan, checkpoint
  restore recursion are the historical traps — all have regression
  coverage now).
- Typed errors deliberately hide sources in `Display`; match on the error
  enum variants to print inner `source` fields when diagnosing.
- The L1 stack logs to the wrangler process output; the E2E script prints
  one PASS/FAIL line per protocol check.
