# Development guide

How to build, test, and change this repository. Read
[architecture.md](architecture.md) first for what the pieces are.

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
  behavior-preservation argument.
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
2. Stage: copy changed files over `sources/typedb/...` (checksum copy; see
   `tools/fork/materialize.sh` for the from-scratch materialisation that
   reproduces `fork/typedb` from the lock + patches).
3. Build/test inside `sources/typedb` with the parity toolchain.
4. When done, restore `sources/typedb` to pristine
   (`git -C sources/typedb checkout -- . && git -C sources/typedb clean -fd`
   for staged new files) so the source-lock lint passes.

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
generous stacks, short `TMPDIR`), reaps stray server processes, and writes
one JSON row per executable. The assembly archive must contain a
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
3. SlateDB is never edited (ADR-0001). Engine-behavior gaps are handled in
   the adapter (`storage/keyspace/slate.rs`) or via upstream PR + version
   bump.
4. Dependency additions to the fork must be checksum-locked and mirrored in
   the source lock where they are proof-critical (see node `SL`).

## Debugging tips

- Fork test failures on U2 only: check the adapter's semantics mapping
  first (empty-batch no-op, cursor backward-seek fresh-scan, checkpoint
  restore recursion are the historical traps — all have regression
  coverage now).
- Typed errors deliberately hide sources in `Display`; match on the error
  enum variants to print inner `source` fields when diagnosing.
- The L1 stack logs to the wrangler process output; the E2E script prints
  one PASS/FAIL line per protocol check.
