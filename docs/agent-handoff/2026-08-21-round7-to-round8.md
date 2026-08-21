# Handoff — round 7 → round 8

**Written:** 2026-08-21
**Branch:** `claude/typedb-slatedb-round7-n5yozv`
**Previous `main`:** `4223d64`
**Supersedes in part:** `2026-08-20-round6-to-round7.md` — corrections are
marked **CORRECTION** and each says what the earlier document got wrong and how
it was measured this time.
**Reader:** a session with zero prior context. Read §1 before anything else.

---

## 0. The one-line state

Plan coverage **13,582 of 23,138 rows (58.7%)**, up from 9,056 (39%). The U0
lane exists for the first time. G0 is still `OPEN_RED` and Mode-Q is still
`ABSENT`. Nothing in the ledger claims otherwise.

---

## 1. READ THIS FIRST: the container starts EMPTY

**CORRECTION to round 6 §4.** Round 6's dominant constraint was disk: a 16 GB
build tree in a ~37 GB allowance. That is not what round 7 met. This container
began with **30 GB free, no `sources/` directory at all, and no toolchain
beyond rustc**. `sources/` is gitignored and materialised from `source-lock/`,
so a fresh container has *nothing* to build.

Bootstrap completeness was the constraint for most of the round — six
prerequisites were missing and none of them named itself. **But disk came back
at the very end and won**, so round 6's warning stands; see §4.6. The full
bootstrap sequence, in order, all of it verified:

```bash
df -h /                                          # 30 GB free here, not 2 GB
python3 tools/source-lock/materialize_sources.py # 9 git nodes + 2 artifacts, ~160 MB
python3 tools/fork/materialize_slatedb.py        # sources/slatedb-fork, else clippy dies
apt-get install -y protobuf-compiler             # else the whole cargo build fails
rustup override set 1.93.0                       # .prototools pin; ambient is 1.94.1
rustup component add clippy rustfmt llvm-tools-preview --toolchain 1.93.0
python3 tools/source-lock/lint_source_lock.py    # must PASS before you trust anything
```

Two more that no script fetches, because the lock marks them uncommitted cache
(`CACHED_ARTIFACTS` in `tools/source-lock/lint_source_lock.py`):

```bash
# RustFS — without it 5 of stack/'s 104 tests fail with PROVIDER_BINARY_ABSENT
curl -sSL -o /tmp/r.zip \
  https://github.com/rustfs/rustfs/releases/download/1.0.0-rc.2/rustfs-linux-x86_64-musl-v1.0.0-rc.2.zip
# archive sha256 must be dbe7b71892b7bcc7e24174321554b4cb39df450a6dcfbc2561ef59f7ab89e20e
unzip -o /tmp/r.zip -d /tmp/rfs
# binary sha256 must be d286e5f8939b6d444e50b94ae2994fe5a707a33a4ed075136c9ba0e4a5975a94
install -m755 /tmp/rfs/rustfs sources/rustfs/rustfs-1.0.0-rc.2

# the assembly archive — three U0/U1/U2 targets hard-link it and CRASH without it
python3 tools/catalog/package_assembly.py        # needs target/debug/typedb_{server,admin}_bin
```

**Both digests above were verified to match `source-lock/source-lock.json`
exactly on this machine.** So were all six binaries in
`docs/evidence/G0/toolchains.json`:

```bash
python3 - <<'PY'
import json,hashlib,pathlib
d=json.load(open('docs/evidence/G0/toolchains.json'))['binary_sha256']
for p,w in d.items():
    f=pathlib.Path(p); g=hashlib.sha256(f.read_bytes()).hexdigest() if f.exists() else 'ABSENT'
    print('MATCH ' if g==w else 'DIFFER', p)
PY
# /usr/bin/{cc,g++,ld,cmake,protoc,pkg-config} — all six MATCH
```

That is a strong statement worth keeping: **this machine's native toolchain is
byte-identical to the one that produced every prior round's evidence.**

### Time and disk actually measured in round 7

| step | wall | peak disk |
|---|---|---|
| materialise `sources/` | ~2 min | 160 MB |
| build all 106 U0 test executables | ~25 min | 12 GB target |
| run the U0 corpus | ~55 min | — |
| `cargo clean` afterwards | 10 s | **reclaims 11.5 GB** |
| install 8 pinned quality tools | ~35 min | <400 MB (throwaway target dir) |

`cargo_gc.py` reclaimed **0 MB** here — it collects stale hash-suffixed
artifacts, and a container that has built once has none. It is a repeat-session
tool, not a bootstrap one. Do not budget for it on a fresh box.

**One build tree at a time, always.** Round 7 ran U0 in `sources/typedb`
(12 GB), cleaned it, then let the quality controller build `fork/typedb`
(23 GB and still not enough — §4.6). Those two never have to coexist, and on
this allowance they cannot.

---

## 2. What round 7 produced

### 2.1 The U0 lane, first execution ever

```bash
python3 tools/qualification/run_leaf.py --profile U0 --out docs/evidence/G3/leaf/u0-full-1
python3 tools/qualification/verify_leaf.py docs/evidence/G3/leaf/u0-full-1 --seal
python3 tools/qualification/run_cucumber_leaf.py \
    --source docs/evidence/G3/leaf/u0-full-1 --out docs/evidence/G3/leaf/cucumber-u0-1
python3 tools/qualification/verify_cucumber_leaf.py docs/evidence/G3/leaf/cucumber-u0-1 --seal
```

| bundle | what | numbers |
|---|---|---|
| `u0-full-1` | executed libtest | 106/106 targets, 0 refused, 0 timed out; 455 leaves = 452 PASSED / 2 FAILED / 1 IGNORED; `tree_state` PRISTINE; `tree_stable_across_run` true |
| `cucumber-u0-1` | **derived**, nothing re-run | 47/47 features, 0 refused, 10 logs read; 4,071 leaves all PASSED; 28 NOT_RUN |

Roots: `1fb52e70dbd3507df8444f9500e5d0b8bd01e315390ceb9cdbd64bbe2cc5cf94` and
`13a82c609998e4325afc617b3d41dd4570e191d04933dafdbe66cd1f5b54baa7`.
Both verify CLEAN, 0 anomalies. `u0-full-1` also verifies CLEAN under
`--corroborate-tree` (see the trap in §4.3 first).

### 2.2 CORRECTION: "+4,700 rows from U0" is only half a truth

Round 6 §7 costed the U0 lane at ~4,700 rows. That number is right only if you
do **two** things. The libtest run alone moved coverage by **455**:

```
9,056  ->  9,511   after u0-full-1 alone
9,511  -> 13,582   after cucumber-u0-1 (derived from bytes u0-full-1 had already archived)
```

The cucumber derivation is the other 4,071 and it costs no execution at all. If
a future session runs a lane and reports a few hundred rows, it has not
finished — it has skipped `run_cucumber_leaf.py`.

Reproduce the current number exactly:

```bash
python3 tools/qualification/leaf_coverage.py \
  --leaf docs/evidence/G3/leaf/u0-full-1 \
  --leaf docs/evidence/G3/leaf/u1-full-1 \
  --leaf docs/evidence/G3/leaf/u1-http-2 \
  --leaf docs/evidence/G3/leaf/u2-full-1 \
  --cucumber docs/evidence/G3/leaf/cucumber-u0-1 \
  --cucumber docs/evidence/G3/leaf/cucumber-u1-1 \
  --cucumber docs/evidence/G3/leaf/cucumber-u2-1 \
  --min-covered 13582
# 13582 covered / 46 partial / 9510 uncovered of 23138 -> NOT SATISFIED, exit 1
```

Exit 1 is correct and expected. **Exit 2 means the floor was breached — that is
the regression signal.** The floor has been raised from 9,056 to 13,582.

By family: `cargo-libtest` 1,365 covered / 910 uncovered · `cucumber` 12,213 /
8,282 · `cargo-failpoint` 44 partial / 176 uncovered · `driver` 4 / 2 partial ·
`static` 141 uncovered · `script` 1 uncovered.

### 2.3 The baseline immediately earned its keep

`storage:test_recovery` **fails on pristine upstream**: 5 passed, 2 failed,
both panicking `not yet implemented` at `storage/tests/test_recovery.rs:73`.

```bash
grep -c '#\[test\]' sources/typedb/storage/tests/test_recovery.rs   # 7
grep -c 'todo!()'   sources/typedb/storage/tests/test_recovery.rs   # 2
grep -c '#\[test\]' fork/typedb/storage/tests/test_recovery.rs      # 18
grep -c 'todo!()'   fork/typedb/storage/tests/test_recovery.rs      # 0
```

The same target under U1 and U2 runs 18 cases, all passing. The fork implements
both stubs upstream left open and adds eleven further recovery tests. **Without
the U0 baseline those two names read as port regressions.** This is the whole
argument for the lane in one example.

Also measured, and deliberately not explained:
`typedb_server_bin:test_fail_points` takes **1943 s on pristine upstream against
271 s under U1**, passing 2/2 either way. The test bodies are identical between
the trees (`fork/typedb/tests/assembly/fail_points.rs` differs from upstream's
only by added diagnostic output), so the difference is behavioural, in how
quickly fail points crash the respective servers. Recorded as an observation.

---

## 3. Defects found and fixed

All three were invisible on any machine that had run the harness before, which
is why six rounds did not see them.

### 3.1 `source-lock/workspace-lock.json` was stale since round 6

`lint_source_lock.py` **failed on any fresh checkout**. Two fields drifted.
Proven to be staleness rather than a dirty tree by recomputing both at the
commit where the lock was last written:

```
tools/Cargo.toml    @e63a337 f5fe8427… == committed f5fe8427…   (HEAD: c909ff40…)
tools/Cargo.lock    @e63a337 1526f2ef… == committed 1526f2ef…   (HEAD: 01395dd1…)
fork_staging digest @e63a337 9cdc967e… == committed 9cdc967e…   (HEAD: 1c847428…)
```

Round 6 edited `fork/typedb/**` (`2142dff`, `d7c886c`) and `tools/Cargo.toml`
(`6c7ee61`) without regenerating. The same 778 file paths exist at both
commits, so round 6 *edited* fork files rather than adding or removing any.
Fixed with `generate_workspace_lock.py`; the lint now passes.

### 3.2 A build failure that hid its own cause

`run_u0.discover_executables` passed `stderr=subprocess.DEVNULL`, so a failed
build of the test executables surfaced only as a bare `CalledProcessError`
naming the command and nothing else. The real cause here was an absent
`protoc`. stderr is now captured and its tail raised with the command and cwd.

### 3.3 Fixture state was measured before the fixtures were staged

`run_leaf.py` called `lc.fixture_state()` **before**
`run_u0.ensure_behaviour_fixture()` — and the latter is what *creates* the
`bazel-typedb/external/typedb_behaviour*` links the former looks for.

```
fresh checkout: fixture_state() -> behaviour present = False   <- what got recorded
                ensure_behaviour_fixture() -> True
                fixture_state() -> behaviour present = True    <- the truth
```

`fixture_set_satisfied()` turns a false `present` into "this leaf is not
covered" for every leaf whose fixture set names it. The error under-claims
rather than over-claims, which is why it survived, but a leaf reported
uncovered when it was executed and observed is still false evidence and it
silently deflates the denominator. The call was moved below the block.

---

## 4. Open findings — NOT fixed, and why

Each of these is a judgement that belongs to the owner, not to the agent that
happened to trip over it. **In every case the agent producing the evidence
would also have been the one relaxing the rule that governs it.**

### 4.1 `cargo xtask quality` lints 742 files of upstream code

`rust.clippy` runs `cargo clippy --manifest-path fork/typedb/Cargo.toml
--workspace --all-targets --all-features -- -D warnings` and fails on
`resource/profile.rs:306` (`collapsible_if`). **That file is byte-identical to
upstream.**

The overlay's composition, measured:

```
fork/typedb, 778 files:  742 byte-identical to upstream
                          29 modified by the fork
                           7 fork-only
```

And the lint surface, attributed (`--message-format json`, deduplicated by
code+file+line):

```
696 clippy findings in the fork/typedb workspace
  651  in files byte-identical to upstream   (93.5%)
   44  fork-owned                            <- the ones actually ours
    1  generated build output
```

The 44 sit exactly where the port lives: `storage/keyspace/slate.rs` 14,
`storage/isolation_manager.rs` 12, `storage/factory.rs` 4, `durability/wal.rs`
2, `storage/keyspace/iterator.rs` 2, `storage/storage.rs` 2,
`concept/thing/thing_manager.rs` 2, `storage/tests/test_recovery.rs` 2,
`storage/recovery/checkpoint.rs` 1, `common/error/error.rs` 1.

Two reasons this was not "fixed":

1. Fixing the upstream-identical 651 would diverge the fork from upstream for
   cosmetic lints, growing the patch set from 36 paths to hundreds and
   polluting the very digest that gives the executed tree its identity.
2. Fixing the fork-owned 44 touches the SlateDB adapter, which would change
   `fork_staging.staged_tree_sha256` and put the sealed U1/U2 bundles out of
   correspondence with the tree — they would need re-running to stay current.

**The scope question is the real one, and it lives in `.quality/policy.toml`,
which is protected.** Someone must decide whether the Rust production tier
should lint files the fork does not modify.

### 4.2 One protected-path change is parked awaiting review

Commit `12dadff` fixes the single clippy error in `xtask/src/quality/exec.rs`
(`manual_range_contains`, inside `#[cfg(test)]`, exactly equivalent). `xtask/**`
is on the protected list, so:

```bash
cargo xtask quality policy-check --base 4223d64
# policy.protected  POLICY VIOLATION
# decision policy_violation (POLICY_CHANGE_REQUIRES_INDEPENDENT_REVIEW), exit 2
```

**That refusal is the machinery working, and it was not worked around.** No
path was removed from the protected list. The branch will fail `policy-check`
until the owner reviews that one commit. Note the finding was checked against
the *pinned* toolchain before being acted on: it first appeared under ambient
clippy 1.94.0, and was re-confirmed under clippy 0.1.93 after
`rustup override set 1.93.0`.

This was also, almost certainly, **clippy's first ever execution here** — round
6's disk floor refused every compiling gate.

### 4.3 A pristine bundle cannot be corroborated on the machine that made it

`executed_tree_identity()` decides `PRISTINE` with `if not entries`, where
`entries` is raw `git status --porcelain` — so it counts `RUNTIME_OUTPUT`
paths. Its own docstring says the opposite:

> running the server suites WRITES `typedb-logs/` into the checkout, so a run
> that started on a clean-by-that-definition tree finishes on a dirty one and
> its own before/after identity check would fire on its own log output

Because a U0 run necessarily writes `typedb-logs/`, both halves are
reproducible:

```bash
# with the run's own log dir present
python3 tools/qualification/verify_leaf.py docs/evidence/G3/leaf/u0-full-1 --corroborate-tree
# ANOMALY … currently DIRTY at the same revision … corroboration refuses the claim  -> REFUSED
rm -rf sources/typedb/typedb-logs
python3 tools/qualification/verify_leaf.py docs/evidence/G3/leaf/u0-full-1 --corroborate-tree
# LEAF BUNDLE VERIFY: CLEAN
```

This only bites U0, the only lane that runs on a pristine tree, which is why it
has never mattered. **The workaround used in round 7 was to delete
`sources/typedb/typedb-logs` before starting the run**, so `tree_before` is
genuinely `PRISTINE`; no code was changed. `tree_stable_across_run` was never at
risk — it compares `staged_delta_sha256`, which already excludes runtime output.

A fix would have to touch both the producer's classification and
`verify_leaf.py`'s `PRISTINE` refusal (which requires `diverging_paths` to be
empty, runtime output included). That is a two-file change to evidence
semantics and needs review.

### 4.4 A mutant that mutates nothing still reports SURVIVED

Against `u0-full-1`, `leaf_mutants.py` reports 14/16 with controls 6 and 6b
SURVIVED. Both forge "a dirty tree presented as clean" — and on a genuinely
pristine bundle they write values it already holds:

```
tree_state          set PRISTINE      is PRISTINE
dirty               set False         is False
staged_delta_files  set 0             is 0
diverging_paths     set []            is []
staged_delta_sha256 set sha256(b"")   is e3b0c442…  (== sha256 of nothing)
```

The only field that genuinely changes is `unstaged_fork_patches` (36 → []),
which `verify_leaf.py` does not check for a PRISTINE bundle. So the report is
ambiguous: it looks exactly like a real check having regressed.

**An attempted fix was written and then REVERTED.** Marking semantically-null
mutations `N/A` was regression-tested against `u1-full-1` and had silently
disabled control 10 ("COMPLETE sealing a root the bytes do not recompute to"),
which previously killed — because control 10 mutates only the `COMPLETE`
marker, which the snapshot did not cover. A tool that stops gating is the exact
failure this repository exists to prevent, so it was reverted rather than
shipped. The observation stands; the fix needs a sounder design (probably: the
harness should assert each mutation actually changed something it will then
check, per control, rather than a generic diff).

### 4.5 `release_mutants.py` reports 23/24 for want of a build artifact

`record-immutable` SURVIVES on a fresh container because
`sources/assembly-artifacts/typedb-all-linux-x86_64.tar.gz` is absent and the
`build` subcommand refuses at `ARTIFACT_MISSING` before ever reaching the
immutability check. Same class as §4.4: a control that never ran, reported as a
survivor. Build the archive first and it is 24/24.

### 4.6 `rust.tests` exhausts the disk, and calls it a QUALITY failure

The last act of the round. `cargo xtask quality fast` reached its `rust.tests`
gate, which runs

```
cargo test --no-run --message-format json-render-diagnostics --workspace --all-features
```

against `fork/typedb`, and died:

```
error: failed to write to `fork/typedb/target/debug/deps/rmetaFfMMj9/full.rmeta`:
       No space left on device (os error 28)
error: could not compile `http_steps` (lib)
```

Measured: `fork/typedb/target` had reached **~23 GB** and was still not
finished (`df` went to 100%, 856K free; deleting that one directory returned
23 GB). It started from 14 GB free, so **the floor let it start a build it
could not finish.** `--all-features` pulls in every behaviour test binary, and
each statically links the server plus rocksdb plus slatedb — round 6 measured
those at ~245 MB each.

Two things to fix, both the owner's:

1. **The per-cost-class free-disk floor is checked once, before the gate, and
   14 GB passed it.** A floor that admits a 23 GB build is not a floor. It
   needs a per-workspace number — round 6 already noted the existing 12 GB
   figure is blunt enough to refuse clippy on the tiny `tools` workspace.
2. **ENOSPC is reported as `quality_failure`, not `InfrastructureFailure`.**
   The final report reads `0 policy violation(s), 2 quality failure(s),
   0 infrastructure failure(s)`. AGENTS.md §3.7 insists an infrastructure
   failure is never a pass; the converse matters just as much, because a
   `quality_failure` sends the next agent hunting for a defect in code that
   compiles fine. "No space left on device" is the least ambiguous
   infrastructure signal there is and it should be typed as one, with the
   remediation being `cargo clean` on the other tree.

Practical consequence for round 8: **`rust.tests` on `fork/typedb` has never
completed here.** Do not treat its absence as a pass, and clean every other
build tree before attempting it.

---

## 5. Re-verified independently this round

Every one re-run, not inherited.

| check | result |
|---|---|
| `lint_ledger.py` | PASS (4 gates, 7 lanes, 38 actions, 4 status docs) |
| `ledger_mutants.py` | 16/16 killed |
| `leaf_diff.py` U1 vs U2 | **455 leaves, 0 regressions, 0 outcome-changed** |
| `leaf_mutants.py --bundle u1-full-1` | **16/16 — but only with the fork STAGED**, see §6.2 |
| `cucumber_mutants.py` | 21/21 |
| `evidence_mutants` · `evidence_v2_mutants` · `lock_mutants` | 32/32 · 15/15 · 7/7 |
| `modeq_mutants.py` | 11/11 killed |
| `driver_mutants.py` × rust/python/typescript slatedb | 16/16 each |
| `check_dependency_sources.py --self-test` | every mutant caught |
| `check_npm_advisories.py --lockfile` | 0 advisories, both workspaces |
| `materialize_slatedb.py --check` | OK, 6 patches, tree `2b00c887d433…` |
| control-plane | `tsc` clean · 165/165 node · 80/80 workerd |
| stack | **104/104** — after installing RustFS; 99/104 without it |
| `source-lock/lint_source_lock.py` | PASS *after* the §3.1 fix |

---

## 6. Traps — round 6's still apply. These are new.

1. **`df` no longer lies the same way.** Round 6's ~37 GB squeeze was not
   reproduced; this box had 30 GB free and ended with 25 GB. Measure, don't
   assume either way.
2. **`leaf_mutants.py` gives 16/16 only when `sources/typedb` is FORK-STAGED.**
   On a pristine tree control 6b survives, because corroboration only fires
   when the live tree contradicts the bundle's claim — and a forged `PRISTINE`
   matches a genuinely pristine checkout. This is lane state, not a defect.
   Check `python3 tools/fork/stage.py --check` before believing the number.
3. **The first `cargo xtask quality` on a fresh container fails `rust.tests`,
   and it is a cold start, not a bug.**
   `rust_client_full_protocol_against_the_managed_surface` asserts `wrangler
   dev` opens its port within a hard-coded 180 s
   (`tools/remote-wal-spike/tests/support/stack.rs:119`). Cold, wrangler
   exceeds it. Warm, **the same test passes in 3.0 s**. Run it once by hand
   before trusting the gate. Arguably the fixed 180 s budget is itself the
   defect.
4. **`os.link` on the assembly archive crashes the run near the end.**
   `run_leaf.py:117` hard-links `sources/assembly-artifacts/…tar.gz` for the
   three assembly-family targets, which are ordered LAST. Missing archive =
   `FileNotFoundError` after ~100 targets have already run. Build it first.
5. **`cargo xtask quality fast` takes well over 10 minutes.** Run it detached
   and poll; a foreground call will hit a tool timeout and look like a hang.
6. **An `until … pgrep -f "<pattern>"` wait loop matches its own shell.** Two
   waits in round 7 never terminated for this reason. Filter with
   `grep -v "bash -c"` or watch the log instead.

---

## 7. Mode-Q / G0 — CORRECTION to round 6 §6

Round 6 recorded the blocker as "this environment's egress policy denies that
fetch with 403". **The reason is more specific, and the distinction matters.**
The 403 body is:

```json
{"message":"GitHub access to this repository is not enabled for this session.
  Use add_repo to request access. …"}
```

It is the session's **GitHub repository scoping**, not a blanket egress policy.
Measured on this machine:

| route | result |
|---|---|
| `git ls-remote` / `git clone` of a public repo | **works** (anonymous git reads are served) |
| `github.com/<o>/<r>/releases/download/…` (release asset) | **works** — 302 → `release-assets.githubusercontent.com` |
| `github.com/<o>/<r>/archive/…tar.gz` | **403** |
| `codeload.github.com/<o>/<r>/tar.gz/…` | **403** |

That asymmetry is exactly wrong for Bazel: `http_archive` wants source
tarballs, which are the refused route. RustFS (84 MB) and Bazel 8.5.1 (64 MB)
both downloaded cleanly as release assets and both matched their recorded
sha256 — including the ledger's own pin
`61d89402f0368e64b6c827be5de79d8e65382e8124c3cbb97325611a1851392e`.

`bats-core` publishes no release-asset tarball (404), so the specific blocker
round 6 identified stands. `add_repo` for `bats-core/bats-core` returns
"read access is already available … anonymous git reads" and attaches nothing —
it does not open the HTTP archive route.

**A lead for round 8, untested:** the refused route is only needed to satisfy a
recorded sha256 in the Bazel Central Registry. A `--distdir` or
`--repository_cache` prefilled from `git clone` would bypass the network, but
only if the bytes hash identically — GitHub's generated tarballs are not
reproducible from `git archive` in general, so treat this as unlikely rather
than promising. **Do not promise G0 on it.**

Bazel 8.5.1 is installed at `/home/user/.bazel-bin/bazel` (the path
`tools/bazel/bazel_parity.py --bazel` defaults to) with the pinned digest
verified.

---

## 8. Where coverage can still go

| lot | rows | cumulative | blocked by |
|---|---|---|---|
| covered now | 13,582 | 13,582 (58.7%) | — |
| checkstyle via Bazel | 390 | ~13,972 | egress (§7) |
| remaining U0/U1/U2 tail | ~180 | ~14,150 | mostly failpoint granularity |
| **realistic ceiling** | | **~14,150 (61%)** | |
| U3 / U4 profiles | 9,196 | | **product code that does not exist** |
| failpoints | 176 | | upstream emitting one case per fail point |

**Round 6's ceiling estimate of ~61% survives contact with the U0 lane.** Say
this plainly to the owner: a bigger machine does not get past ~61%, because
U3/U4 are product profiles nobody has written yet. That is not a testing
problem and no amount of disk or egress changes it.

---

## 9. First moves for round 8

```bash
# 1. bootstrap completely — §1, all of it, in order. Nothing works before this.
# 2. confirm the floor has not moved backwards
python3 tools/qualification/leaf_coverage.py … --min-covered 13582   # exit 2 = regression
# 3. re-establish trust
python3 tools/ledger/lint_ledger.py && python3 tools/ledger/ledger_mutants.py
python3 tools/fork/stage.py --check          # STAGED before believing leaf_mutants
python3 tools/qualification/leaf_mutants.py --bundle docs/evidence/G3/leaf/u1-full-1
```

Then, in the order the owner's decisions unblock them:

1. **Get a ruling on §4.1** — whether the Rust production tier should lint
   files the fork does not modify. Until then `cargo xtask quality full` cannot
   go green, and the 44 fork-owned findings cannot be triaged without
   invalidating U1/U2's correspondence to the tree.
2. **Get `12dadff` reviewed** (§4.2), or the branch cannot pass `policy-check`.
3. **§4.3 and §4.4** are small, real, and both need a reviewer because the
   agent that hits them is the agent that would relax them.
4. **The strict-epoch suite was NOT re-run this round** —
   `python3 tools/fork/check_strict_epoch_suite.py` needs its own full build
   and the session ran out of room after U0. Round 6's numbers
   (feature-OFF 2007/0, feature-ON 2012/0, negative 5/0) are therefore
   *inherited, not re-verified*. Re-run it early.
5. `bazel_parity.py` was likewise not re-run; Bazel is now installed for it.

---

## 10. What did NOT happen this round, stated plainly

- **`cargo xtask quality full` never returned a clean result, and `fast` never
  returned a clean one either.** Its final state was two quality failures:
  `rust.clippy` (the upstream-lint scope question, §4.1) and `rust.tests`
  (out of disk, §4.6). `full` was never attempted, because `fast` never got
  past those. The clippy question blocks it regardless of machine.
- **Phase 1 of the quality programme — the CRAP baseline, per-package
  `llvm-cov`, differential mutation — was not started.** The eight tools are
  now installed and pinned, which is the prerequisite, but no baseline exists.
  Treat every Phase 1 claim as unproven, exactly as round 6 said.
- **Mode-Q was not produced and G0 was not closed.** `MODEQ: ABSENT`, G0
  `OPEN_RED`. The blocker was re-measured, not merely restated (§7).
- **The U1 lane's ledger `why` is still stale** — it says "104 rows, weak
  target-name identity", which the 455-leaf `u1-full-1` bundle superseded a
  round ago. Only the U0 entry was corrected, because that is the evidence this
  round produced. Someone should fix U1's.
