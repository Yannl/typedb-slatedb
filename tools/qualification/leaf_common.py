"""Leaf-granularity evidence: the shared facts, defined exactly once.

WHY THIS EXISTS
---------------
`tools/catalog/plan_coverage.py` reports 0 covered rows, and its docstring
names the reason honestly: the archived evidence records per-cargo-target
libtest SUMMARY COUNTS, never per-case outcomes, so a cargo-family leaf row
is at best PARTIAL and can never be covered. This module is the missing
granularity: libtest already prints one line per case
(`test <name> ... ok|FAILED|ignored|bench:`), which IS leaf granularity, and
nothing but a parser and a fail-closed reconciliation stood between that
output and a leaf-level evidence row.

The rules below are the ones an auditor re-runs. They are deliberately
unconditional, and every one of them exists because its absence is a way to
report green without running anything:

  1. A leaf outcome is only ever read out of an ARCHIVED LOG FILE whose
     sha256 is bound into the row. No leaf may be constructed from a summary,
     a count, or a name list.
  2. The per-case outcomes parsed from a log must RECONCILE EXACTLY with the
     `test result:` summary the same log prints, using the shared
     `tools/catalog/common.parse_libtest_counts` implementation. A log whose
     per-case lines and summary disagree is a contradiction, not evidence:
     the whole target is refused and contributes no leaves.
  3. `filtered_out` must be zero. A filtered run enumerates a SUBSET of the
     target's leaves while looking exactly like a full one.
  4. A target the catalogue says is case-bearing that produces zero parsed
     cases is refused (the vacuous-evidence rule plan_coverage.py already
     applies at target granularity, applied here at leaf granularity).
  5. A parsed case name is joined to a catalogue leaf ONLY by exact equality
     with that leaf's `display_name` UNDER THE SAME catalogue target_id.
     Names the catalogue does not carry are recorded as `extra_cases` and
     cover nothing; catalogue leaves the log does not name are recorded as
     `missing_cases` and cover nothing. Neither is ever guessed across
     targets.
  6. Identity is recorded, never asserted: the toolchain is measured, the
     executed tree is digested, and the tree's cleanliness is a THREE-state
     fact (PRISTINE / FORK_STAGED_EXACT / DIRTY) because a fork-staged
     checkout is neither pristine nor untrustworthy and calling it either is
     a lie.

The leaf id space is the plan's own: `<catalogue target_id>::<display_name>`
(e.g. `cargo:storage:test:test_recovery::test_recover_wal`). The broken
pre-fix `0.0.0:<target>` id space that plan_coverage.py reports as
UNJOINABLE is never produced here: every row carries the catalogue target id
AND the runner row id (`<package>:<target>`, `common.runner_row_id`) so the
join is exact on both sides.
"""

import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "catalog"))
import common  # noqa: E402

TB = REPO / "sources" / "typedb"
FORK = REPO / "fork" / "typedb"
CATALOG = REPO / "docs" / "evidence" / "G1" / "upstream-test-catalog.json"
PLAN = REPO / "docs" / "evidence" / "G1" / "qualification-plan-v2.json"
BEHAVIOUR = REPO / "sources" / "typedb-behaviour"

SCHEMA = "typedb-r2-leaf-evidence-v1"
RESULTS_NAME = "leaf-results.json"

# libtest's per-case line, in the default (pretty) format. One line per case,
# printed when the case completes, in every thread mode. This is the leaf
# granularity libtest has always had; nothing nightly is required.
CASE_RE = re.compile(
    r"^test (?P<name>\S+) \.\.\. (?P<res>ok|FAILED|ignored|bench:.*?)\s*$")

OUTCOME = {"ok": "PASSED", "FAILED": "FAILED", "ignored": "IGNORED"}
# summary key each outcome must reconcile against
SUMMARY_KEY = {"PASSED": "passed", "FAILED": "failed",
               "IGNORED": "ignored", "MEASURED": "measured"}


def parse_libtest_cases(text):
    """[(case_name, outcome, 1-based log line number)] from a raw libtest log.

    Reads ONLY the per-case lines. Deliberately does not fall back to the
    trailing `failures:` block or the terse format: a leaf outcome must come
    from a line that names both the case and its result, or it does not
    exist. Callers must reconcile the result against
    common.parse_libtest_counts before trusting it (see reconcile()).
    """
    out = []
    for i, line in enumerate(text.splitlines(), start=1):
        m = CASE_RE.match(line.rstrip("\r"))
        if not m:
            continue
        res = m.group("res")
        outcome = "MEASURED" if res.startswith("bench:") else OUTCOME.get(res)
        if outcome is None:
            continue
        out.append((m.group("name"), outcome, i))
    return out


def reconcile(cases, counts):
    """Fail-closed agreement between the per-case lines and the summary.

    Returns a list of refusal reasons; empty means the log is self-consistent
    and its per-case lines may be published as leaf outcomes. Any nonempty
    result refuses the WHOLE target: a log that miscounts one case is not a
    log that can be trusted about the others.
    """
    problems = []
    names = [c[0] for c in cases]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        problems.append(
            f"duplicate per-case line(s) for {dupes} - one execution cannot "
            f"vouch for two leaf outcomes")
    by_outcome = {}
    for _n, o, _l in cases:
        by_outcome[o] = by_outcome.get(o, 0) + 1
    for outcome, key in SUMMARY_KEY.items():
        got, want = by_outcome.get(outcome, 0), counts.get(key, 0)
        if got != want:
            problems.append(
                f"per-case lines name {got} {outcome} case(s) but the log's "
                f"own 'test result:' summary says {key}={want} - the case list "
                f"contradicts the log it was read from")
    if counts.get("filtered_out", 0):
        problems.append(
            f"the log reports filtered_out={counts['filtered_out']} - a "
            f"filtered run enumerates a SUBSET of the target's leaves while "
            f"looking exactly like a full one")
    return problems


def has_summary(text):
    """True when the log carries at least one libtest `test result:` line.
    A log without one is truncated (or the binary died mid-run) and can never
    be reconciled: no summary, no leaves."""
    return any(l.startswith("test result:") for l in text.splitlines())


# --------------------------------------------------------- executed identity

def _git(repo, *a):
    return subprocess.run(["git", "-C", str(repo), *a],
                          capture_output=True, text=True).stdout.strip()


def _tree_digest(root, rels):
    """sha256 over sorted (relative path, file sha256) pairs."""
    h = hashlib.sha256()
    for rel in sorted(rels):
        f = root / rel
        h.update(str(rel).encode() + b"\0")
        if f.is_file():
            h.update(common.sha256_file(f).encode())
        h.update(b"\n")
    return h.hexdigest()


def fork_tree_identity():
    """Digest of the fork patch set that gets staged into sources/typedb.

    `fork/typedb` is a WORKING TREE in the outer repository, and on this
    machine other work edits it concurrently. Its identity is therefore the
    bytes, not a commit: every file tools/fork/stage.py would stage, hashed.
    The outer-repo commit and dirty flag travel alongside so a reader can see
    both what the repository claims and what was actually on disk.
    """
    skip_dirs = {".git", "target", "node_modules"}
    fork_only = {"PORT-LEDGER.md", "UPSTREAM-PROVENANCE"}
    rels = []
    for p in sorted(FORK.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(FORK)
        if rel.parts[0] in skip_dirs or str(rel) in fork_only:
            continue
        rels.append(rel)
    return {
        "files": len(rels),
        "fork_tree_sha256": _tree_digest(FORK, rels),
        "outer_repo_commit": _git(REPO, "rev-parse", "HEAD"),
        "outer_repo_dirty": bool(_git(REPO, "status", "--porcelain")),
        "outer_repo_fork_paths_modified": [
            l[3:] for l in _git(REPO, "status", "--porcelain").splitlines()
            if l[3:].startswith("fork/")],
    }


def stage_state():
    """tools/fork/stage.py --check, executed - never assumed.

    Returns (state, first_line) where state is STAGED / PRISTINE / MIXED /
    UNKNOWN. STAGED means sources/typedb carries EVERY fork patch byte for
    byte and no stale staged file remains; that is the only condition under
    which a dirty checkout is still an exactly identified tree.
    """
    r = subprocess.run([sys.executable, str(REPO / "tools" / "fork" / "stage.py"),
                        "--check"], capture_output=True, text=True)
    line = (r.stdout.strip().splitlines() or [""])[0]
    for state in ("STAGED", "PRISTINE", "MIXED"):
        if line.startswith(state):
            return state, line
    return "UNKNOWN", (line or r.stderr.strip())


def executed_tree_identity():
    """What was actually built and run, with cleanliness as a THREE-state fact.

    `run_u0.executed_tree_identity()` records `dirty: bool(git status)`. On a
    fork lane that boolean is ALWAYS true - staging the fork is what makes the
    lane exist - so 'dirty' alone cannot distinguish 'the fork tree, exactly'
    from 'somebody left an edit in the checkout'. Both readings are recorded
    here so neither can be inferred wrongly:

      tree_state = PRISTINE           - no diff from the locked revision
                 = FORK_STAGED_EXACT  - every diff is a fork/typedb file,
                                        byte-identical to fork/typedb, with no
                                        stale staged files (stage.py --check
                                        says STAGED). Dirty w.r.t. the pin,
                                        and EXACTLY identified by
                                        (checkout_revision, fork_tree_sha256).
                 = DIRTY              - anything else. Never publishable.

    `dirty` keeps run_u0's exact meaning (git status is nonempty) so the two
    producers cannot be read as disagreeing.
    """
    status = subprocess.run(["git", "-C", str(TB), "status", "--porcelain"],
                            capture_output=True, text=True).stdout
    h = hashlib.sha256()
    for line in sorted(status.splitlines()):
        rel = line[3:].strip().strip('"')
        h.update(line.encode() + b"\0")
        f = TB / rel
        if f.is_file():
            h.update(f.read_bytes())
    state, state_line = stage_state()
    dirty = bool(status.strip())
    if not dirty:
        tree_state = "PRISTINE"
    elif state == "STAGED":
        tree_state = "FORK_STAGED_EXACT"
    else:
        tree_state = "DIRTY"
    return {
        "checkout_revision": _git(TB, "rev-parse", "HEAD"),
        "dirty": dirty,
        "tree_state": tree_state,
        "stage_check": state_line,
        "staged_delta_files": len([l for l in status.splitlines() if l.strip()]),
        "staged_delta_sha256": h.hexdigest(),
        "fork": fork_tree_identity(),
    }


def measured_toolchain(toolchain=common.TOOLCHAIN):
    out = subprocess.run(["cargo", toolchain, "--version"],
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"toolchain {toolchain} is not installed: {out.stderr.strip()}")
    rustc = subprocess.run(["rustc", toolchain, "--version"],
                           capture_output=True, text=True).stdout.strip()
    triple = ""
    for line in subprocess.run(["rustc", toolchain, "-vV"], capture_output=True,
                               text=True).stdout.splitlines():
        if line.startswith("host: "):
            triple = line[len("host: "):].strip()
    return {"cargo": out.stdout.strip(), "rustc": rustc, "target_triple": triple,
            "requested": toolchain.lstrip("+")}


def toolchain_id(tc, plan):
    """The plan's toolchain id this measurement corresponds to, or None.

    Matched by the plan's own recorded cargo/rustc/triple strings. A run on a
    compiler the plan does not name is NOT filed under the plan's lane: the
    row is emitted with toolchain_id null and covers nothing, which is the
    behaviour the u0 manifest's hardcoded 'rust 1.93.0 parity lane' string
    made impossible.
    """
    for tid, spec in (plan.get("toolchains") or {}).items():
        if (spec.get("cargo") == tc["cargo"] and spec.get("rustc") == tc["rustc"]
                and spec.get("target_triple") == tc["target_triple"]):
            return tid
    return None


def fixture_state():
    """What the fixtures ACTUALLY are on disk right now, measured.

    A leaf whose plan fixture set is not satisfied here must not be published
    as covered: the behaviour-driven suites fail in ~2s with '0 features /
    1 parsing error' when the fixture is missing, which is a false red, and
    a false red published as a leaf outcome is worse than no evidence.
    """
    archive = REPO / "sources" / "assembly-artifacts" / "typedb-all-linux-x86_64.tar.gz"
    script = TB / "tests" / "assembly" / "script.tql"
    links = [TB / "bazel-typedb" / "external" / "typedb_behaviour+",
             TB / "bazel-typedb" / "external" / "typedb_behaviour",
             TB / "bazel-typedb" / "external" / "typedb_behaviour++",
             REPO / "sources" / "typedb_behaviour+"]
    behaviour_ok = all((l / "connection" / "database.feature").exists() for l in links)
    return {
        "fixture:typedb-behaviour": {
            "present": behaviour_ok,
            "checkout": str(BEHAVIOUR.relative_to(REPO)),
            "checkout_revision": _git(BEHAVIOUR, "rev-parse", "HEAD"),
            "checkout_dirty": bool(_git(BEHAVIOUR, "status", "--porcelain")),
            "link_paths_serving_features": [
                str(l.relative_to(REPO)) for l in links
                if (l / "connection" / "database.feature").exists()],
        },
        "fixture:assembly-script.tql": {
            "present": script.is_file(),
            "sha256": common.sha256_file(script) if script.is_file() else None,
        },
        "assembly_archive": {
            "present": archive.is_file(),
            "sha256": common.sha256_file(archive) if archive.is_file() else None,
        },
    }


def fixture_set_satisfied(fs_id, plan, fixtures):
    """True when every fixture the plan's fixture SET names is present."""
    for fid in (plan.get("fixture_sets") or {}).get(fs_id, []):
        entry = fixtures.get(fid)
        if fid == "fixture:typedb-behaviour":
            if not (entry and entry.get("present")):
                return False
        elif fid == "fixture:assembly-script.tql":
            if not (entry and entry.get("present")):
                return False
        else:
            # console/loader archives ship inside the assembly archive
            if not fixtures.get("assembly_archive", {}).get("present"):
                return False
    return True


# ------------------------------------------------------------- bundle identity

def bundle_files(results_dir, bundle):
    """Every file this bundle's claims rest on: the results JSON and every
    raw log it names. Structurally the same rule as
    verdict.compute_bundle_root, over this schema's file names."""
    results_dir = pathlib.Path(results_dir)
    files = [results_dir / RESULTS_NAME]
    for t in bundle.get("targets", []):
        if t.get("raw_log"):
            p = pathlib.Path(t["raw_log"])
            files.append(p if p.is_absolute() else REPO / p)
    return files


def compute_bundle_root(results_dir, bundle):
    """sha256 over the sorted (repo-relative path, sha256) pairs of every file
    the bundle's leaf claims rest on. A post-hoc edit of ANY of them - the
    results JSON included - is a root mismatch, never a shrug."""
    pairs = {}
    for f in bundle_files(results_dir, bundle):
        if f.is_file():
            try:
                rel = f.resolve().relative_to(REPO.resolve()).as_posix()
            except ValueError:
                rel = str(f.resolve())
            pairs[rel] = common.sha256_file(f)
    h = hashlib.sha256()
    for rel in sorted(pairs):
        h.update(rel.encode() + b"\0" + pairs[rel].encode() + b"\n")
    return h.hexdigest(), pairs


def load_catalog_leaves(catalog=None):
    """(target_id -> {display_name -> leaf}, target_id -> catalogue target).

    LIBTEST leaves only. FAILPOINT leaves are deliberately excluded here: they
    are (failpoint x execution-context) products enumerated INSIDE two libtest
    cases, and libtest prints no line for them - see run_leaf.py's
    FAILPOINT_NOT_LEAF_OBSERVABLE note.
    """
    cat = json.loads(pathlib.Path(catalog or CATALOG).read_text())
    targets = {t["target_id"]: t for t in cat["targets"]}
    leaves = {}
    for lc in cat["leaf_cases"]:
        if lc["kind"] != "LIBTEST":
            continue
        leaves.setdefault(lc["target_id"], {})[lc["display_name"]] = lc
    return leaves, targets, cat


def rid_to_catalog_target(targets):
    """runner row id (`<pkg>:<target>`) -> catalogue target_id, via the ONE
    shared join (common.runner_row_id). Collisions are impossible by
    construction here because common.required_executable_targets() already
    stops the line on them; this map is built the same way so the two cannot
    drift."""
    out = {}
    for tid, t in targets.items():
        rid = common.runner_row_id(t)
        if rid:
            out[rid] = tid
    return out
