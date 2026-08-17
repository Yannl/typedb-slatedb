# Corpus tooling: reusability and the A-branch denominator run

Two things live here: (1) the result of pointing the donor's test-denominator tooling at the
selected A-branch fork, and (2) exactly what makes the tooling checkout-independent and what
still couples it to this repo.

---

## 1. The A-branch denominator run

**Subject:** `A/fork/typedb` from a clean worktree of A-branch commit
`e20cff50081b9ae4b3c5f88e6d4ef89a88b06585`.
**Command (static stages, no build, no network):**

```
cargo run --manifest-path tools/Cargo.toml -p xtask -- \
  catalog-upstream-tests --typedb-root /home/user/a-branch/fork/typedb \
  --behaviour-root fixtures/typedb-behaviour --profile U0
```

The same command was run against the donor's own `fork/typedb` for an apples-to-apples
baseline (identical tool build, behaviour corpus and source-lock state).

### Denominators

| metric | A-branch fork | donor fork | delta |
|---|---|---|---|
| **target denominator** | **296** | 296 | 0 |
| **leaf denominator** | **4353** | 4353 | 0 |
| unknown macros / rules | **0** | 0 | 0 |
| unparsed BUILD files | **0** | 0 | 0 |
| declared-ignored (owned) | 30 | 30 | 0 |
| exclusions (owned) | 40 | 40 | 0 |
| Cargo↔BUILD matched | 85 | 85 | 0 |
| BUILD-only / Cargo-only | 0 / 43 | 0 / 43 | 0 |

Leaf breakdown (both forks): CUCUMBER 4158, STATIC_CHECK 143, FAILPOINT 44, SCRIPT 8.

### Set-level comparison

Target and leaf **sets** are identical, not just their counts: 296 shared targets (0 A-only, 0
donor-only), 4353 shared leaf cases (0 A-only, 0 donor-only).

### Semantic delta

**Zero at the denominator level.** A-branch did not shrink, extend, or restructure the upstream
test denominator — its BUILD graph, Cargo target set, Gherkin corpus expansion and failpoint
crossing are structurally identical to the pristine baseline. This is consistent with the
adversarial audit's finding that A's changes are confined to
`fork/typedb/storage/keyspace/slate.rs` + dispatch and the TypeScript control plane, touching
no BUILD file.

### Profile applicability matrix

The catalogue defines profiles U0–U4 (`U0` rocksdb-pristine / file-wal / no object-store;
`U1` rocksdb-adapter / fork-local; `U2` SlateDB over object-store; `U3`/`U4` remote-WAL
controller variants). The static catalogue is profile-independent — the same 296/4353
denominator applies to every profile; a profile selects *which backend executes* the leaves,
not *which leaves exist*. Establishing per-profile pass/fail requires the executing stage
(below), which was not run here.

### What this run does and does not establish

- **Establishes:** A's fork presents the full upstream denominator with zero unknown macros —
  there is no silently-shrunk corpus hiding behind A's headline pass rate. Every one of the
  4353 leaves the oracle defines is present to be run.
- **Does not establish:** that A *passes* them. That is A's own 105/106 claim, dissected in
  `a-branch-adversarial-report.md` §A14 (headline run single-commit at the tip's parent; a prior
  published run four-commit; the one red — `storage:test_recovery` — honest, matching the U1
  oracle). Confirming pass/fail independently needs the executing stage.

### Honest provenance caveat

The emitted catalogue records `source_lock_digest = b971ebe824…`, which is the **donor's**
source-lock digest, not one derived from A-branch's own `source-lock/source-lock.json`. So the
evidence is precisely: *"A-fork's BUILD/Cargo/fixture structure, catalogued under the donor's
source lock."* The counts are A's; the provenance root is the donor's. Binding the denominator
to A's own source lock requires the `--source-lock` override described below (A ships its own
lock, which the donor's `source-lock` stage did not regenerate). Do not present these counts as
A-provenance-sealed until that override is used with A's lock.

Artifacts: `docs/donor/a-branch-catalog/upstream-test-catalog-U0.json` (A fork),
`mine-fork-catalog-U0.json` (donor fork baseline), `cargo-build-reconciliation.json`.
The run wrote transiently into `docs/evidence/phase-b/`; that directory was restored to the
donor's own evidence afterward (`git checkout`), so no donor evidence was overwritten.

### What could NOT be run here, kept separate

- **The `source-lock` stage** requires the 14 pinned upstream `.git` checkouts under `sources/`
  and shells out to `git rev-parse`/`status`; it cannot run against a bare fork checkout. This
  is why the run reused the donor's existing lock rather than regenerating one for A.
- **The executing stages** (`test-upstream`) need every harness built and a staged fixture tree,
  plus real servers on ports; this is hours of build against A's full workspace and was out of
  scope for a static denominator audit. Baseline, infrastructure and implementation failures
  must be reported separately when it is run — an upstream baseline failure is never a
  candidate-backend pass.

---

## 2. What makes the tooling checkout-independent

The **subject tree is already parameterized**: `--typedb-root` / `--behaviour-root` on the
catalog and runner commands redirect every fork-relative read, which is why the A run above
worked with no code change.

### Delivered in this donor branch

The two highest-value couplings — the source-lock requirement and the evidence-overwrite
hazard — are now **implemented** on the `catalog-upstream-tests` command (default behaviour
unchanged; 74 tools tests green):

- `--fork-root <PATH>` — alias of `--typedb-root`, for cataloguing an arbitrary fork.
- `--source-lock <PATH>` — seal the catalogue under a chosen lock instead of the in-repo one.
- `--allow-missing-source-lock` — when no lock is present, seal under `hash_tree(fork_root)`, a
  recomputable 64-hex content digest of the fork tree, and write a
  `catalogue-provenance-<profile>.json` sidecar marking the seal fork-derived (so it cannot be
  confused with a pinned-graph digest despite sharing the field shape).
- `--evidence-dir <PATH>` — write catalogue/reconciliation evidence to a scratch dir instead of
  `docs/evidence/phase-b`, so a foreign-fork run cannot overwrite in-repo evidence (the hazard
  hit on the first A run above).

A fully fork-sealed A-branch catalogue produced with these flags is at
`docs/donor/a-branch-catalog/a-fork-sealed-catalog-U0.json` (digest
`3e360b23…`, provenance sidecar alongside).

**Note surfaced by this work:** A-branch's own `source-lock/source-lock.json` is a *hand-authored
document* (keys `document`, `status`, `policies`, …), **not** the machine-generated lock the
donor's `cargo xtask source-lock` emits — it carries no `source_graph_digest`. So sealing an
A-fork catalogue under A's own lock is not currently possible without first regenerating a
machine lock for A; the fork-tree digest is the honest substitute until then.

### Remaining couplings (documented, not yet implemented)

Two couplings still anchor the *other* subcommands (`test-upstream`, `negative-controls`,
`assemble`) to this repo's layout; the catalog command itself is already free:

| # | coupling | file:line | fix |
|---|---|---|---|
| 3 | subject-root resolution duplicated across the other subcommands | `runner.rs:20–24`, `negative.rs:81–85`, `assemble.rs:43–47` | hoist one `resolve_under_repo` helper; extend the `--fork-root` alias to them |
| 4 | hardcoded `/opt/protoc/bin` on PATH and target triple | `catalog.rs` (~177, 312), `native.rs:230` | add `--extra-path`, `--target-triple` (defaulted to today's values) |

Nothing in `conformance-runner` or `source-lock` needs changing for a *catalog-only* run —
`RunContext` is already fully injected. The one stage that genuinely cannot be pointed at a bare
fork is `source-lock` itself, whose 14-node graph (`tools/source-lock/src/lib.rs:284–354`) would
need to accept a caller-supplied node-spec list.

**Smallest fully-reusable catalogue invocation (works today):**

```
cargo xtask catalog-upstream-tests \
  --fork-root <other>/fork/typedb \
  --behaviour-root <abs>/fixtures/typedb-behaviour \
  --allow-missing-source-lock \
  --evidence-dir /tmp/catalog-out
```

The static stages — BUILD/Starlark reconciliation, scenario + `Examples:` expansion,
failpoint-registry crossing, static/doctest/shell target synthesis — then run with no build, no
network and no `sources/` tree, exactly as the A run above demonstrated.
