# Handoff — round 6 → round 7

**Date:** 2026-08-20
**Branch:** `claude/typedb-slatedb-r2-continue-ss62cz`
**Base:** `4261f0d` (previous `main`)
**Audience:** the next implementation session, and the release owner

---

## 1. The one thing that dominated this session

**Disk.** The container reports a 252 GB filesystem, but the writable
allowance behaves as **~37 GB**, and 35 GB of it was already spent. I hit
absolute zero three times and had to reclaim space mid-run each time.

```
nominal filesystem   252 GB      (the host disk — misleading)
effective allowance  ~37 GB      (what can actually be written)
used at handoff       35 GB
free at handoff        2.7 GB
sources/              19 GB      of which sources/typedb/target is 16 GB
```

This is not a nuisance, it is a **hard cap on what can be proven**. Three
concrete consequences, all measured rather than estimated:

- the **U0 "pristine" lane** needs a SECOND full build tree beside the
  existing 16 GB one. It does not fit. That alone is 1,365 uncoverable
  plan rows.
- `cargo-llvm-cov` and `cargo-mutants` — the heart of the quality
  programme — need 1–2 GB each just to install, plus working space per
  campaign. Phase 0 could be built; the baselines could not be run.
- a full Bazel build of TypeDB was never attemptable.

**Ask for at least 150 GB on the next machine.** With that, U0, coverage,
mutation and Bazel all become possible in one session.

---

## 2. Where test coverage actually stands

```
covered today                            914 of 23,138 rows   4.0%
reachable ceiling in the OLD environment 9,396 rows          40.6%
needs a bigger machine or product work  14,310 rows
```

`docs/evidence/G1/ceiling/coverage-ceiling.json` carries the full
arithmetic and its caveat (it is an upper bound computed as
leaves × runnable profiles, so it does not model the plan's 43 predeclared
exclusion rows).

**COVERED means an outcome was RECORDED, never that it passed.** The split
is carried explicitly everywhere (908 PASSED, 2 IGNORED today), and
`plan_coverage.py` still exits nonzero printing `NOT SATISFIED`.

### What is proven

The question this project exists to answer is answered, for everything
currently measurable:

- **U1 (classic RocksDB) vs U2 (SlateDB), same tree, same binaries,
  backend chosen at runtime: 455 leaves compared, 454 AGREE_PASSED,
  1 AGREE_IGNORED, 0 regressions, 0 absent-on-candidate, 0
  outcome-changed.** Not one case passes on classic and fails on SlateDB.
- **All six official-driver rows execute**: 1,132 official behaviour
  scenarios across Rust/Python/TypeScript on both backends, 0 failures,
  99/99 mutants killed. Four rows are COVERED; the two TypeScript rows
  stay PARTIAL for real in-scope reasons (npm-vs-pnpm closure, and
  upstream emitting no `index.d.cts`).
- **The shipped SlateDB fence executes the full upstream suite**:
  feature-off 2007/0, feature-on 2012/0, empty exclusion list. Round 5
  had reported PASS on 1566/420.
- **cargo is a verified strict superset of Bazel's test graph**: all 85
  Bazel `rust_test` targets map 1:1 and bijectively onto cargo targets by
  source path; the fork dropped 0 upstream `#[test]` functions.

### What is not

- **20,495 cucumber rows.** All 47 feature files and all 4,099 scenarios
  are reachable via cargo, and per-scenario outcomes already sit in the
  sealed U1/U2 bundles. The blocker is the **Scenario Outline name join**:
  the catalogue names templates with placeholders, the runtime prints the
  substituted name (15/725 exact matches on one feature). A workstream on
  this was still running at handoff — check `tools/qualification/` and
  `docs/evidence/G3/leaf/cucumber-*` for what it left.
- **220 failpoint rows.** 22 fail points iterate INSIDE one `#[test]` and
  libtest prints one line. Covering them needs an **upstream** change, not
  a harness change. Deliberately not claimed.
- **78 checkstyle rows.** They run TypeDB's Java Checkstyle with a
  Bazel-fetched config. A Python reimplementation would be a substitute,
  not the tool, so those rows are not claimed on one. The other 63 static
  rows are `rustfmt_test` and ARE faithfully runnable.
- **1 script row.** `//tool/test:simulate-crash` has no referent in the
  pinned upstream tree — a catalogue defect, kept rather than deleted.

---

## 3. Blocked on the machine vs blocked on the product

Do not conflate these. They have different owners.

| Blocked by | What | Unblocked by |
|---|---|---|
| **Machine** | U0 pristine lane (1,365 rows) | more disk |
| **Machine** | coverage/CRAP/mutation baselines | more disk |
| **Machine** | Bazel analysis + Mode-Q bundle | egress to `github.com` (403 here) **and** disk |
| **Product** | U3 / U4 profiles | they refuse at runtime: `ProfileUnavailable` — not implemented |
| **Upstream** | 220 failpoint rows | upstream emitting one case per fail point |
| **Owner decision** | OD-008 confidentiality profile | still OPEN; blocks any "secure production" claim |

**Mode-Q / G0 specifically:** the producer now exists
(`tools/modeq/produce_modeq.py`) and is wired into
`release-qualification.yml`. It fails here only because
`aspect_bazel_lib` registers `bats_toolchains` fetched from
`github.com/bats-core`, which this egress policy denies with 403
(reproduced with curl on both `github.com` and `codeload.github.com`).
It writes NOTHING on failure, so Mode-Q stays ABSENT and G0 stays honestly
OPEN_RED rather than being broken by a half-written bundle.

---

## 4. Working rules this repository runs on

These are not style preferences. Every one of them was earned by catching
a real false-green, and the next session must keep them.

1. **Never claim a number you did not produce.** Round 5 shipped a gate
   that turned "1566 passed, 420 failed" into PASS. Everything an agent
   reports gets independently re-run before it is committed.
2. **A tool that reports without gating is a defect.** `bazel_parity.py`
   always returned 0 until it was made fail-closed this session.
3. **Turning a failing test into a skipped one is not a fix.** The
   doc-test gate carries a recorded floor (59 executed / 7 ignored)
   precisely because cross-posture equality alone would not catch an
   example marked ```` ```ignore ````.
4. **Widening a rule after it refuses you is how evidence rots.** When the
   leaf harness refused a run, the fix was a one-entry no-glob allowlist
   with its justifying check recorded, and a full re-run — not a broader
   rule.
5. **Infrastructure failure is never a pass.** An absent tool must produce
   a typed failure, not a silent skip.
6. **The status plane must match reality.** `docs/operations.md` is
   RENDERED from `docs/ledger/gates.json` by `render_status.py` — the
   ledger linter caught a hand-edit this session and was right to. Run
   `lint_ledger.py` and `ledger_mutants.py` after any truth-plane change.
7. **Declared exclusions, never silent ones.** OD-010 scopes the
   qualification claim to single-node semantic parity; the cluster suites
   stay enumerated, stay reported as not executed, and the decision
   explicitly forbids claiming HA on its strength.

---

## 5. The quality programme

The owner adopted the *Agentic Code Quality Enforcement Specification*
(deterministic `cargo xtask` controller + adversarial specialist agents;
machine evidence gates, agents repair).

**Scope decision (owner, this session):**

| Tier | Code | Gates |
|---|---|---|
| Production | `fork/typedb/**`, `fork/slatedb/patches/**`, `tools/remote-wal-spike/**`, `control-plane/src/**` | full |
| Tooling | `control-plane/probes/**`, `stack/**`, all Python `tools/**` | fast only |

Note the correction that matters: **`control-plane/src/**` is production**,
not test tooling. It is the Cloudflare Worker and the Durable Objects that
serve the WAL protocol (43 files: `worker-entry.ts`,
`database-controller.ts`, `procedures.ts`, `ed25519.ts`, …). Excluding it
would leave a real production surface ungated.

**What landed this session (Phase 0):** see the commits and
`.quality/` — the controller, policy, protected-path detection, waiver
model, unified report schema, agent role contracts, and CI tier wiring.

**What is Phase 1+ and needs the bigger machine:** the trusted-base CRAP
baseline, `cargo-llvm-cov` instrumentation, differential `cargo-mutants`,
Miri triggers, feature matrix, and the property/fuzz targets.

---

## 6. First moves on the new machine

```bash
# 0. confirm the constraint is actually gone
df -h /                      # expect >100 GB available, not 2.7

# 1. re-establish the baseline the old box could not run
cargo xtask quality full     # honest InfrastructureFailure for absent tools
                             # install what it names, then re-run

# 2. the lane the old box could not fit
#    U0 = pristine (unstaged) checkout; needs a second full build tree
python3 tools/fork/stage.py --check     # understand staged vs pristine first

# 3. close G0 where egress allows it
python3 tools/modeq/produce_modeq.py --out docs/evidence/G0/mode-q
python3 tools/modeq/validate_modeq.py   # must print VALID, not ABSENT

# 4. the 20,495-row prize
#    read docs/evidence/G3/leaf/cucumber-feasibility.json first —
#    the blocker is the Scenario Outline name join, not execution
```

Always re-run before trusting: `python3 tools/ledger/lint_ledger.py`,
`python3 tools/ledger/ledger_mutants.py`,
`python3 tools/fork/check_strict_epoch_suite.py`,
`python3 tools/bazel/bazel_parity.py`.
