# Handoff — round 6 → round 7

**Written:** 2026-08-20
**Merged as:** `a779210` on `main` (PR #10), from branch
`claude/typedb-slatedb-r2-continue-ss62cz`
**Previous `main`:** `4261f0d`
**Reader:** a session with zero prior context. Assume you know nothing.

---

## 0. How to use this document

Read §1–§4 before touching anything. §5–§7 are the current state with the
commands that reproduce every number. §8 is the quality programme. §9 is
what to do first. §10 is the traps — read it, they cost real hours.

**The single most important thing to internalise:** this repository's
discipline is that *a number you did not produce is not evidence*. A
previous round shipped a gate that turned "1566 passed, 420 failed" into
`PASS`. Everything here was re-run independently before it was committed.
Keep doing that, including to your own subagents.

---

## 1. What this project is

A port of **TypeDB**'s storage layer onto **SlateDB** over **S3/R2**, with a
**Cloudflare Workers + Durable Objects** control plane serving a remote
write-ahead-log protocol.

Three moving parts:

- **The storage port.** TypeDB normally stores on RocksDB. This project adds
  a SlateDB-backed backend whose durable state lives in an S3-compatible
  object store. The central question the whole repository exists to answer
  is: *does swapping the storage engine change any observable TypeDB
  behaviour?*
- **The control plane.** A Cloudflare Worker plus Durable Objects that own
  WAL authority: issuing storage epochs, fencing stale writers, sequencing
  commits, and serving payload reads. This is TypeScript, and it is
  **production code**, not tooling.
- **The truth plane.** An unusually strict evidence system: a 23,138-row
  qualification plan, sealed evidence bundles, independent verifiers, and
  mutant suites that try to forge each kind of evidence and must fail.

### Vocabulary you will meet everywhere

| Term | Meaning |
|---|---|
| **leaf** | one individual test case (not a test binary, not a target) |
| **row** | one (leaf × profile) pair in the qualification plan; 23,138 of them |
| **profile / lane** | U0…U4 — a configuration the plan requires evidence under |
| **U0** | pristine upstream TypeDB, no fork patches staged |
| **U1** | fork tree, **classic RocksDB** backend — the *oracle* |
| **U2** | fork tree, **SlateDB** backend — the *candidate* |
| **U2S3** | U2 against a real S3 server (MinIO/RustFS); **not** a plan profile |
| **U3 / U4** | product profiles (remote WAL / full managed). **Not implemented** — the storage factory refuses at runtime with `ProfileUnavailable` |
| **fence / epoch** | a writer must present a controller-issued epoch; a stale epoch is refused. Shipped as SlateDB feature `external_epoch_required` |
| **staged / pristine** | `tools/fork/stage.py` copies `fork/typedb/**` over `sources/typedb`. "Staged" = fork applied |
| **mutant** | a deliberate forgery of evidence that a verifier must reject |
| **G0…G3** | release gates in `docs/ledger/gates.json` |

---

## 2. Repository map

```
contract/          normative brief + addendum. OUTRANKS all other prose.
fork/
  typedb/          our patches to TypeDB, as a file overlay (778 files)
  slatedb/patches/ our patches to SlateDB, as 7 numbered unified diffs
sources/           source-locked upstream checkouts (READ ONLY, never edit)
  typedb/          upstream TypeDB; stage.py overlays fork/typedb onto it
  typedb-pristine/ untouched TypeDB for the U0 lane
  slatedb-fork/    materialised from fork/slatedb/patches
  typedb-driver/   official drivers (Rust/Python/TS/Java/…)
  typedb-behaviour/ the official BDD corpus (.feature files)
control-plane/
  src/             PRODUCTION: the Worker + Durable Objects (43 files)
  probes/          tooling: the credentialed-probe harness, 26 controls
stack/             tooling: local dev stack, supervisor, fault proxy
tools/             Python + Rust tooling
  catalog/         the qualification plan and coverage joiner
  qualification/   leaf-granularity + cucumber evidence machinery
  drivers/         official-driver lanes
  evidence/        independent verifiers
  ledger/          the truth-plane linter and its mutants
  fork/            staging + the SlateDB fence gates
  modeq/           Mode-Q (Bazel cquery) producer + validator
  bazel/           Bazel-vs-cargo test-graph parity
  release/         build-once / test-that-artifact / promote-by-digest
  remote-wal-spike/ PRODUCTION: the managed Rust L1 client
xtask/             the deterministic quality controller (cargo xtask)
.quality/          quality policy, agent role contracts, architecture rules
docs/
  ledger/gates.json  THE machine-readable truth plane
  evidence/          sealed evidence bundles
  agent-handoff/     this directory
  operations.md      RENDERED from gates.json — never hand-edit
```

---

## 3. The two truth planes, and the rules

### Plane 1 — the evidence/ledger plane (predates the quality programme)

`docs/ledger/gates.json` is the authority on gate and lane state. It is
linted, and the linter has 16 mutants that must all die:

```bash
python3 tools/ledger/lint_ledger.py      # must PASS
python3 tools/ledger/ledger_mutants.py   # 16 mutants, 16 killed
```

`docs/operations.md` is **rendered** from it:

```bash
python3 tools/ledger/render_status.py    # after ANY gates.json change
```

The linter caught a hand-edit to `operations.md` during round 6 and was
right to. `gates.json` also carries `forbidden_claims` — regexes for
sentences the repository must never contain (e.g. calling G0 green).

### Plane 2 — the quality plane (new in round 6)

`cargo xtask quality {fast, pr --base SHA, full, policy-check --base SHA}`.
Four outcomes with distinct exit codes: `Pass`=0, `QualityFailure`=1,
`PolicyViolation`=2, `InfrastructureFailure`=3.

**A quality pass is not a gate closure and must never be written into
`gates.json`.** The two planes answer different questions.

### The working rules (each one earned by catching a real false-green)

1. **Never report a number you did not produce.** Re-run subagent claims.
2. **A tool that reports without gating is a defect.** `bazel_parity.py`
   always returned 0 until round 6 made it fail-closed.
3. **Turning a failing test into a skipped one is not a fix.** The doc-test
   gate carries a recorded floor (59 executed / 7 ignored) because
   cross-posture equality alone would not catch an example marked
   ```` ```ignore ````.
4. **Widening a rule after it refuses you is how evidence rots.** When the
   leaf harness refused a run, the fix was a one-entry, no-glob allowlist
   with its justifying check recorded — and a full re-run.
5. **Infrastructure failure is never a pass.** An absent tool produces a
   typed failure with a remediation command.
6. **Declared exclusions, never silent ones.** See OD-010 below.
7. **`COVERED` means an outcome was RECORDED, never that it passed.** The
   PASSED/IGNORED split is carried everywhere.

---

## 4. The disk constraint that shaped round 6

The container reported a 252 GB filesystem. The **writable allowance behaved
as ~37 GB**, and 35 GB was already spent. I hit absolute zero three times.

```
nominal filesystem   252 GB   (host disk — misleading, ignore it)
effective allowance  ~37 GB
sources/              19 GB   of which sources/typedb/target = 16 GB
free at handoff        2.1 GB
```

**Consequences, all measured:**

- the **U0 lane** needs a *second* full build tree beside the 16 GB one. It
  does not fit. That alone is ~4,700 uncoverable rows.
- every gate that **compiles** — clippy, tests, `llvm-cov`, `cargo-crap`,
  `cargo-mutants` — is refused up front by the controller's per-cost-class
  free-disk floor, rather than dying on ENOSPC mid-compile.
- a full Bazel build of TypeDB was never attemptable.

### Living inside ~37 GB — the measured strategy

A bigger machine may not be available, so this is the plan that fits. Every
number below was measured on this tree, not estimated.

**First, two things that are NOT the lever, so nobody wastes a day on them:**

- **Debug info is already off.** Stripping the largest test binary
  (245.3 MB) recovers **2.7 MB**. I assumed this was the big win; it is
  noise. Do not go hunting for `debug = 0`.
- **`cargo install` of the quality tools is affordable.** I predicted it
  would fail in 2.7 GB. It did not — built into a throwaway
  `CARGO_TARGET_DIR` and deleted between installs, peak was 82–357 MB each.
  Eight tools fit.

**What the 16 GB build tree actually is:**

```
136 executables   10.4 GB     <- the concentration
979 .rlib          3.4 GB
977 .rmeta         1.0 GB
 59 .so            0.2 GB
```

The 12 behaviour test binaries are **~245 MB each**, because each statically
links the whole server plus rocksdb plus slatedb. That is inherent to Rust
`[[test]]` targets; it is not waste and cannot be configured away.

**The four levers, in order of value:**

1. **`python3 tools/dev/cargo_gc.py` — reclaims 4.49 GB, repeatable.**
   Cargo never garbage-collects: every rebuild emits a new hash-suffixed
   artifact and leaves the old one forever. This tree held 136 executables
   for 100 distinct targets. Measured on this repository: **2.2 GB free →
   6.5 GB free**, and `cargo test -p xtask` still passed straight after
   (122 tests) — cargo simply relinked. Run it between phases, not once.
   `--dry-run` reports; `--include-libs` goes further when the squeeze is
   severe.
2. **Run lanes SEQUENTIALLY, never side by side.** This is what actually
   unblocks U0, and the earlier claim that U0 "does not fit" was wrong in an
   important way: U0 and U1/U2 never need to exist *at the same time*.
   Build a lane → run it → **seal its evidence** → `cargo clean` → switch
   the tree → rebuild. A sealed leaf bundle is ~5 MB; the build tree that
   produced it is 16 GB and is disposable. The evidence is the artifact,
   not the target directory. The cost is rebuild time, not disk.
3. **Build behaviour binaries one at a time.** `cargo test --test X`, seal,
   delete that binary, then the next. Peak goes from ~2.9 GB (all twelve)
   to ~245 MB (one).
4. **Coverage per package, not per workspace.** `cargo llvm-cov` needs its
   own instrumented tree, which is why the CRAP baseline never ran here.
   Use the documented split: `cargo llvm-cov --no-report` per package,
   keep only the small `.profraw`, `cargo clean` between packages, then
   `cargo llvm-cov report` at the end. Never ask for `--workspace` in one
   shot on this allowance.

**Standing habit:** check `df -h /` before any compile-heavy step, and run
`cargo_gc.py` when Avail drops below ~6 GB. The controller already refuses
heavy gates below its floor rather than dying on ENOSPC mid-compile, so a
refusal is information, not a failure to work around.

### Reclaiming space safely, if you must

```bash
df -h /                                        # "Avail" is the real number
rm -rf /tmp/minio-cache-* /tmp/objstore_cache_test_*   # always safe
find sources/typedb/target/debug/deps -type f ! -newermt "-4 hours" -delete
# ^ cargo never GCs stale artifacts; it rebuilds what it needs. Costs time,
#   never correctness. Do NOT delete a build tree another agent is using.
```

---

## 5. What is proven (with the command for each)

### 5.1 The central result: SlateDB changes no observable outcome

Same tree, same binaries, backend chosen at runtime:

```
U1 (classic RocksDB oracle)  vs  U2 (SlateDB)
  455 leaves compared — oracle 455, candidate 455
  {AGREE_PASSED: 454, AGREE_IGNORED: 1}
  0 regressions · 0 absent-on-candidate · 0 outcome-changed · 0 unexplained
```

```bash
python3 tools/qualification/leaf_diff.py \
  --oracle docs/evidence/G3/leaf/u1-full-1 \
  --oracle docs/evidence/G3/leaf/u1-http-2 \
  --candidate docs/evidence/G3/leaf/u2-full-1 --require-clean
```

**Pass BOTH u1 bundles as oracle.** `u1-full-1` refused four HTTP targets on
a loaded machine and `u1-http-2` is their clean re-run; passing only the
first makes those four look candidate-only and the differential goes red for
a reason that is not a regression.

### 5.2 Coverage: 0 → 9,056 of 23,138 rows

```bash
python3 tools/qualification/leaf_coverage.py \
  --leaf docs/evidence/G3/leaf/u1-full-1 \
  --leaf docs/evidence/G3/leaf/u1-http-2 \
  --leaf docs/evidence/G3/leaf/u2-full-1 \
  --cucumber docs/evidence/G3/leaf/cucumber-u1-1 \
  --cucumber docs/evidence/G3/leaf/cucumber-u2-1 \
  --min-covered 9056
# exit 1 = plan not satisfied (CORRECT and expected)
# exit 2 = the floor was breached — THAT is the regression signal
```

The denominator read 0 for three rounds because evidence was recorded at
**target** granularity ("storage: 209 passed") while a plan row is a single
**case**. Fixed at the level it was broken.

- **910 cargo-libtest rows** — all 455 catalogued leaves × 2 runnable lanes.
- **8,142 cucumber rows** — was 89% of the plan and 100% uncovered. Derived
  entirely from bytes already sealed; **nothing was re-run**. The blocker
  was never execution, it was the Scenario Outline **name join**: the
  catalogue names templates with placeholders, the runtime prints the
  substituted name (15/725 exact matches on one feature). Solved by porting
  cucumber-0.19.1's real `expand_scenario`, and proven three independent
  ways (catalogue agreement 4,099/4,099 *in order*; plan-anchor agreement
  4,099/4,099; runtime sequence agreement *element for element* in every
  log). **224 groups of examples substitute to identical strings** (largest
  group: 9) — name-based joining cannot distinguish them, so ordinal binding
  was forced by measurement, not preference.
- **4 official-driver rows COVERED** — 1,132 official behaviour scenarios
  across Rust/Python/TypeScript on both backends, 0 failures, 99/99 mutants
  killed. Lane separation rests on the archived on-disk witness
  `_system/backend-spec.marker` (`kind slatedb-r2` vs `kind classic`), not
  an environment variable.

### 5.3 The shipped SlateDB fence executes the full upstream suite

Round 5 reported PASS on 1566 passed / 420 failed. Now:

```bash
python3 tools/fork/check_strict_epoch_suite.py
# feature-OFF 2007/0 · feature-ON 2012/0 · negative 5/0
# leaf reconciliation 2013 = 2013 · exclusions: none
# doc examples 59/0 in BOTH postures, identical population
# STRICT-EPOCH SUITE GATE: PASS
```

`--quick` prints **PARTIAL**, never PASS, and only the full run may be cited
as evidence. A real security defect fell out of this work: upstream
`build()` created the manifest *before* consulting the fencer, so an
unauthorised client could create empty databases.

### 5.4 cargo is a verified strict superset of Bazel's test graph

```bash
python3 tools/bazel/bazel_parity.py       # fail-closed since round 6
# 85/85 Bazel rust_test targets map 1:1 and bijectively onto cargo targets
# catalogue static set == Bazel's, cargo set == live cargo metadata
# 0 upstream #[test] functions dropped by the fork; 253 added
```

Honest limit the tool prints on every run: this is **structural**
equivalence. No test was executed under Bazel, so identical *outcomes*
remain unproven.

### 5.5 Everything else that is green

```bash
cd control-plane && npx tsc --noEmit && npm test && npm run test:workerd
#   165/165 node · 80/80 workerd · tsc clean
cd control-plane && bash probes/self-test.sh          # all 26 controls
cd stack && npm test                                   # 104/104
cargo test --manifest-path tools/Cargo.toml --workspace --offline   # 0 failures
cd sources/typedb && cargo +1.93.0 test -p storage --tests --locked  # 261/0
python3 tools/release/release_mutants.py               # 24 killed, 0 survived
python3 tools/qualification/leaf_mutants.py --bundle docs/evidence/G3/leaf/u1-full-1
python3 tools/qualification/cucumber_mutants.py        # 21/21 held
python3 tools/ci/check_dependency_sources.py --self-test
python3 tools/ci/check_npm_advisories.py --lockfile    # 0 advisories
cd stack && node native-fidelity.mjs                   # ALL 6 PHASES PASS
```

---

## 6. What is red, and exactly whose problem it is

**Do not conflate these three categories.**

| Blocked by | What | Rows | Unblocked by |
|---|---|---|---|
| **Machine** | U0 pristine lane | ~4,700 | more disk, OR the sequential-lane strategy in §4 |
| **Machine** | CRAP/coverage/mutation baselines | — | more disk |
| **Machine + egress** | Bazel analysis, Mode-Q, 390 checkstyle rows | 390 | disk **and** egress to `github.com` |
| **Product** | U3 / U4 profiles | 9,480 | **writing the product code** |
| **Upstream** | failpoint leaves | 220 | TypeDB emitting one case per fail point |
| **Owner** | OD-008 confidentiality profile | — | a decision |

### Mode-Q / G0, precisely

`tools/modeq/produce_modeq.py` exists and is wired into
`release-qualification.yml`. It fails on *this* machine only because
`aspect_bazel_lib` registers `bats_toolchains` fetched from
`github.com/bats-core`, which the egress policy denies with **403**
(reproduced by hand with curl on both `github.com` and
`codeload.github.com`). A registered toolchain must load before Bazel
resolves toolchains for **any** configured target, so even a single-target
cquery aborts.

It also solves a second, network-independent wall:
`//:deploy-mac-installer-pkg` is an upstream mac-only alias whose `select()`
has no default, so `cquery kind(..., //...)` fails analysis on Linux
regardless. Narrowing the universe to `//... - //:*` dodges it but silently
drops **5** root-package test targets (228 → 223). The producer instead
enumerates in Bazel's **loading** phase (which works everywhere) and
configures only those labels, keeping all 228.

**It writes NOTHING on failure.** An absent bundle keeps `MODEQ: ABSENT` and
G0 honestly `OPEN_RED`; a half-written directory would make the validator
report `INVALID` and break the gate.

### The 220 failpoint rows

22 fail points are iterated **inside** a single `#[test]`, and libtest
prints one line for the case. Deriving 44 passes from one passing loop is
inference dressed as observation. **Deliberately not claimed.**

### The 78 checkstyle rows

They run TypeDB's Java Checkstyle with a Bazel-fetched MPL-header config. A
Python reimplementation would be a **substitute**, not the tool, so those
rows are not claimed on one. The other 63 static leaves are `rustfmt_test`
and *are* faithfully runnable with the same tool.

### OD-010 — a scoping decision you must respect

The owner ruled that cluster suites (3-node replication) are **out of
scope**: the change under qualification is the storage adapter, and the
claim is single-node **semantic parity**. The exclusion is declared and
bounded — the cluster suites stay enumerated, stay reported as not executed,
every affected row names OD-010 as its authority, and the decision
**explicitly forbids** claiming clustered/replicated/HA operation on its
strength. See `docs/owner-decisions.json`.

---

## 7. Where coverage can actually get to

| Lot | Rows | Cumulative | Unblocked by |
|---|---|---|---|
| covered today | 9,056 | 9,056 (39%) | — |
| U0 lane | ~4,700 | ~13,750 | disk |
| checkstyle via Bazel | 390 | ~14,140 | disk + egress |
| **realistic ceiling on a fresh machine** | | **~14,100 (61%)** | |
| U3 / U4 profiles | 9,480 | | **product code** |
| failpoints | 220 | | upstream |

**A bigger disk gets you to ~61%. The last ~39% is not a testing problem —
U3/U4 are product profiles that do not exist yet.** Say this plainly to the
owner rather than implying 100% is a scheduling matter.

`docs/evidence/G1/ceiling/coverage-ceiling.json` carries the arithmetic and
its caveat (it is an upper bound computed as leaves × runnable profiles, so
it does not model the plan's 43 predeclared exclusion rows).

---

## 8. The quality programme

The owner adopted the *Agentic Code Quality Enforcement Specification*:
a deterministic `cargo xtask` controller plus adversarial specialist agents.
Agents repair; **machine evidence gates**.

### Scope decision (owner, round 6)

| Tier | Code | Gates |
|---|---|---|
| **Production** | `fork/typedb/**`, `fork/slatedb/patches/**`, `tools/remote-wal-spike/**`, `control-plane/src/**` | full |
| **Tooling** | `control-plane/probes/**`, `stack/**`, all Python `tools/**` | fast only |

The correction that matters: **`control-plane/src/**` is production.** It is
the Worker and the Durable Objects that serve the WAL protocol —
`worker-entry.ts`, `database-controller.ts`, `procedures.ts`, `ed25519.ts`.
Excluding it as "just TypeScript tooling" would leave a real production
surface ungated.

### What exists (Phase 0, done and tested)

- `xtask/` — 122 tests (106 unit + 16 end-to-end), all passing.
- `.quality/policy.toml` — spec §26 values, the §12 protected list as
  concrete globs, and the scope manifest encoded **once**.
- **Anti-gaming, verified live:** the protected list is read from
  `git show <BASE>:.quality/policy.toml` and *unioned* with head. Deleting
  `"xtask/**"` from the list does **not** unprotect it — paths still match,
  attributed `from base` instead of `from base+head`, still exit 2.
- Waiver model, unified report + JSON Schema (validates Draft 2020-12),
  diff-to-gate matrix, tool presence/version detection.
- Seven role contracts in `.quality/agents/`, `AGENTS.md` at root.
- 33 architecture forbidden-edges, all derived from real `cargo metadata`,
  all currently satisfied.
- CI tiers wired into the three existing workflows; zizmor audit clean;
  all 80 action refs SHA-pinned; 29/29 checkouts `persist-credentials: false`.

### Installed at pinned versions

`cargo-nextest 0.9.143`, `cargo-llvm-cov 0.9.0`, `cargo-crap 0.4.3`,
`crap4rs 0.6.2`, `cargo-mutants 27.1.0`, `cargo-deny 0.20.2`,
`cargo-machete 0.9.2`, `cargo-hack 0.6.45`.

### What is Phase 1+ and needs the bigger machine

The trusted-base CRAP baseline (isolated worktree at `BASE_SHA`, cached on
`base_sha + policy_digest + toolchain_digest`) is **implemented but has
never executed** — treat it as unproven. Same for `llvm-cov`
instrumentation, differential `cargo-mutants`, Miri triggers, the feature
matrix, and property/fuzz targets.

### Real findings the controller surfaced — all four now CLOSED

`cargo xtask quality full` found four. They were **larger than first
reported**, and that understatement is itself worth remembering: the first
report said "E741 in one file and 7 files unformatted"; the measured truth
was **144 lints and 72 files**. All four are fixed:

- **`deny.toml` did not exist**, so `cargo deny` ran on defaults that allow
  nothing and rejected nine permissive license families. Now written from
  the exact set in the resolved graph. LGPL-2.1-or-later is deliberately
  NOT allowed even though it appears on `r-efi`: that crate is multi-licensed
  `MIT OR Apache-2.0 OR LGPL`, so the permissive side satisfies it, and
  blanket-allowing LGPL would silently permit copyleft for every future
  dependency. If a crate ever arrives LGPL-only, this gate SHOULD go red.
- **`cargo-machete`'s three unused deps are upstream's, not ours.**
  `tools/drivers/rust-behaviour/steps` is a *projection* of a Bazel target
  and mirrors its BUILD deps; upstream declares async-std/regex/smol there
  and never uses them. Deleting them would break the projection's fidelity,
  which `projection_check.py` exists to enforce. Documented ignore with an
  owner and a review condition (re-check when TDRIVER moves).
- **144 ruff lints → 0** and **72 unformatted files → 0**, with `ruff.toml`
  at line-length 100 (the width the code was actually written at). The 122
  E741 renames used a scope-exact AST renamer, never sed: 122 bindings, 304
  references, rewritten by byte offset. A naive text collision check flagged
  37 conflicts of which **all 10 plausible ones were false**.

The bar for the Python change was not "ruff is green" — that Python IS the
machinery that certifies everything else. All 22 validator/mutant suites
produced **byte-identical** output before and after, and an AST comparison
with identifiers masked shows 53 of 72 files are formatting-only.

---

## 9. First moves on the next machine

```bash
# 0. establish the real disk budget and reclaim what cargo abandoned
df -h /                         # Avail is the quota, not the filesystem
python3 tools/dev/cargo_gc.py --dry-run    # reclaims ~4.5 GB of stale artifacts

# 1. orient: is the fork staged or pristine?
python3 tools/fork/stage.py --check

# 2. re-establish the quality baseline the old box could not run
cargo xtask quality fast        # honest InfrastructureFailure for absent tools
cargo xtask quality full        # install what it names, then re-run
#    then fix the four real findings listed in §8

# 3. the lane the old box could not fit  (+~4,700 rows)
#    U0 = pristine TypeDB, no fork staged. Needs its own build tree.
#    Read tools/qualification/run_leaf.py first — it already knows how to
#    seal a lane; U0 is a new profile for it, not new machinery.

# 4. close G0 where egress allows it
python3 tools/modeq/produce_modeq.py --out docs/evidence/G0/mode-q
python3 tools/modeq/validate_modeq.py    # must print VALID, not ABSENT
python3 tools/modeq/modeq_mutants.py     # 11 must still die

# 5. Bazel native execution — the one thing still unproven about fidelity
#    §5.4 proves the graphs match structurally. Running `bazel test` on
#    targets that also run under cargo, and comparing per-test outcomes,
#    closes it behaviourally.
```

**Before trusting anything, re-run:**

```bash
python3 tools/ledger/lint_ledger.py && python3 tools/ledger/ledger_mutants.py
python3 tools/fork/check_strict_epoch_suite.py
python3 tools/bazel/bazel_parity.py
python3 tools/qualification/leaf_mutants.py --bundle docs/evidence/G3/leaf/u1-full-1
python3 tools/qualification/cucumber_mutants.py
```

---

## 10. Traps

Each of these cost real time. Three lines each is cheap insurance.

1. **`df` lies.** "Avail" is the quota, not the 252 GB filesystem. Watch
   Avail, not Used.
2. **`cargo xtask` must run from the repository root.** The alias in
   `.cargo/config.toml` names `--manifest-path tools/Cargo.toml`; there is
   no root `Cargo.toml`, so `cargo test -p xtask` from root fails — use
   `cargo test --manifest-path tools/Cargo.toml -p xtask`.
3. **`sources/typedb` may be STAGED.** `stage.py` overlays the fork onto it.
   Tests you run there may be testing the fork, not upstream. Check first;
   never run `--restore` while another lane is building.
4. **The leaf differential needs BOTH u1 bundles as oracle** (see §5.1).
5. **`--quick` on the fence gate prints PARTIAL, never PASS.** Only a full
   run may be cited.
6. **Patch files are whitespace-load-bearing.** A unified diff encodes an
   empty context line as a single space; "fixing" it corrupts the patch.
   They are exempted via `.gitattributes`, not edited.
7. **`docs/operations.md` is generated.** Hand-edit it and the ledger linter
   will catch you. Edit `gates.json`, then `render_status.py`.
8. **Only one driver lane per host.** Upstream hardcodes
   `Context::DEFAULT_ADDRESS = 127.0.0.1:1729`. Concurrent lanes collide.
9. **libtest interleaves concurrent cases into one stdout.** One archived
   log contains a physically *torn* line where a step line and a `Feature:`
   line fused. Any log scanner must survive this — there is a control for it.
10. **Python pin is 3.11.15** (`.prototools`), and CI now requests exactly
    that. The Rust pin is 1.93.0 while some sandboxes carry 1.94.1 ambient;
    all repo test commands use `cargo +1.93.0` explicitly.
11. **`policy-check` will refuse a change that touches `.quality/**` or
    `.github/workflows/**`.** That is correct: a change that edits the
    policy *is* a policy change. Route it separately; do not de-list the
    path.

---

## 11. Open items worth picking up early

- Two comprehensions removed as F841 dead code, `run_ids` in
  `run_cucumber_leaf.py` and `by_ref` in `verify_cucumber_leaf.py`, look
  like reconciliation checks someone intended to wire up and never did.
  Removing them preserved behaviour exactly, but if either was meant to
  catch something, that gap **predates** the cleanup and is still open.
- `.circleci/**` is not in ruff's default exclude, and `sources/**` was
  excluded only by ruff's *gitignore* default — which `--no-respect-gitignore`
  turns off. Both are now excluded explicitly. Watch for the same class of
  silent scope gap in other tool configs.
- **`//tool/test:simulate-crash`** is a catalogue entry with **no referent**
  in the pinned upstream tree (confirmed against Bazel's own graph). Kept
  rather than deleted, because silently removing a plan row is how a
  denominator shrinks. Decide what it should be.
- **`driver/migration.feature` and `driver/cluster.feature` have no plan
  leaves at all**, because `generate_catalog.py` only enumerates feature
  files referenced from `sources/typedb`. 18 migration scenarios really
  executed and cover nothing; recorded as `leaves_outside_plan`.
- **Two TypeScript driver rows stay PARTIAL** for in-scope reasons: deps
  resolved by npm because the shipped `pnpm-lock.yaml` is v8 while local
  pnpm is 10.x, and upstream `http-ts` emits no `index.d.cts` by its own
  BUILD TODO.
- **`zizmor` has no entry in `.quality/tools.lock.toml`** — it is pinned
  inline in the workflows (version + URL + sha256). It belongs in the lock.
- The 12 GB heavy-gate disk floor is blunt: it refuses clippy on the tiny
  `tools` workspace too. Per-workspace floors would be better once real
  numbers exist.
