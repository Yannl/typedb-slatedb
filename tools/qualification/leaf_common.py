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
import importlib.util
import json
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

# Paths a RUN writes into the checkout that are not source and never compile:
# the server's own rolling log directory. They are excluded from the source
# delta digest (otherwise a bundle's tree identity would change mid-run
# because a test it ran wrote a log line) and are listed explicitly in the
# evidence, never silently dropped.
RUNTIME_OUTPUT_PREFIXES = ("typedb-logs/",)

# Paths that diverge from the pinned checkout yet PROVABLY enter neither the
# cargo lane's build nor the catalogue's denominator.
#
# WHY THIS LIST EXISTS, stated plainly rather than buried: the first full U2
# corpus run was REFUSED by this module's own tree rule, because a concurrent
# Bazel invocation on this shared machine rewrote
# `sources/typedb/MODULE.bazel.lock` while the run was in flight. Widening a
# rule after it refuses your result is exactly how evidence rots, so the
# widening is deliberately the narrowest possible shape: an explicit path
# list, no globs (a glob is how an exclusion quietly grows), each entry
# carrying the check that justifies it, every excluded path recorded BY NAME
# AND SHA256 in the evidence, and the verifier refusing any bundle that
# excludes a path this list does not name.
NON_CARGO_INPUTS = {
    "MODULE.bazel.lock":
        "Bazel's bzlmod dependency lockfile. No .rs, Cargo.toml or build.rs "
        "anywhere in the workspace mentions MODULE.bazel (grep -rln "
        "'MODULE.bazel' over --include=*.rs --include=*.toml --include=build.rs "
        "returns nothing), and no catalogue target names it in source_files, so "
        "it enters neither the cargo compilation nor the denominator. Bazel "
        "rewrites it whenever it resolves modules, which is what happened "
        "under the first U2 run.",
}


def _load_stage_module():
    """tools/fork/stage.py, imported for its own definition of what a staged
    fork tree is. Re-deriving that here would fork the truth: stage.py is the
    tool the brief names for `--check`, so its `differing()` is the authority
    on 'every fork patch is staged and nothing stale remains'."""
    spec = importlib.util.spec_from_file_location(
        "fork_stage", REPO / "tools" / "fork" / "stage.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
RESULTS_NAME = "leaf-results.json"

# libtest's per-case lines, in the default (pretty) format. Three real
# shapes, all observed in this repository's own archived logs - the third was
# found by this module's own reconciliation refusing two targets, which is
# what fail-closed is for:
#
#   test <name> ... ok                     the ordinary atomic line
#   test <name> - should panic ... ok      a #[should_panic] case
#   test <name> ... <leaked bytes>         a SPLIT line: with --test-threads 1
#   ...                                    libtest writes "test <name> ... "
#   ok                                     without a newline and the outcome
#                                          afterwards, so a SUBPROCESS the test
#                                          spawned (the extracted TypeDB server
#                                          printing its banner) lands between
#                                          the two halves.
#
# tracing/log output also carries ANSI colour, so lines are decoloured before
# matching. Nothing here loosens the guarantee: the split form is only ever
# closed while exactly one case is open, a second opener while one is pending
# is an error, and every reading is still reconciled against the log's own
# `test result:` summary before a single leaf is published.
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
CASE_OPEN_RE = re.compile(
    r"^test (?P<name>\S+)(?: - should panic)? \.\.\. (?P<rest>.*)$")
TERMINAL_RE = re.compile(r"^(?P<res>ok|FAILED|ignored|bench:.*)$")

OUTCOME = {"ok": "PASSED", "FAILED": "FAILED", "ignored": "IGNORED"}
# summary key each outcome must reconcile against
SUMMARY_KEY = {"PASSED": "passed", "FAILED": "failed",
               "IGNORED": "ignored", "MEASURED": "measured"}


def _outcome_of(res):
    if res.startswith("bench:"):
        return "MEASURED"
    if res.startswith("ignored"):
        return "IGNORED"
    return OUTCOME.get(res)


def parse_libtest_cases(text):
    """[(case_name, outcome, open_line, close_line)] from a raw libtest log.

    Line numbers are 1-based. `open_line` is the line that NAMES the case;
    `close_line` is the line that names its OUTCOME. They are the same line
    for the ordinary atomic form and differ for the split form above, and
    both are recorded so a verifier can read the claim back out of the bytes
    without either half being taken on trust.

    Returns (cases, problems). Structural problems travel alongside the
    cases because a log the parser cannot read UNAMBIGUOUSLY must refuse the
    whole target rather than silently yield fewer cases than it contains -
    silently yielding fewer is how a leaf quietly stops being covered.
    """
    out, problems = [], []
    pending = None
    for i, raw in enumerate(text.splitlines(), start=1):
        line = ANSI_RE.sub("", raw.rstrip("\r")).rstrip()
        m = CASE_OPEN_RE.match(line)
        if m:
            rest = m.group("rest").strip()
            term = TERMINAL_RE.match(rest)
            if term:
                oc = _outcome_of(term.group("res"))
                if oc:
                    out.append((m.group("name"), oc, i, i))
                    pending = None
                    continue
            if pending is not None:
                problems.append(
                    f"line {i} opens case {m.group('name')!r} while case "
                    f"{pending[0]!r} (opened at line {pending[1]}) is still "
                    f"unterminated - the log cannot be read unambiguously")
                pending = None
                continue
            pending = (m.group("name"), i)
            continue
        if pending is not None:
            term = TERMINAL_RE.match(line)
            if term:
                oc = _outcome_of(term.group("res"))
                if oc:
                    out.append((pending[0], oc, pending[1], i))
                    pending = None
    if pending is not None:
        problems.append(
            f"case {pending[0]!r} opened at line {pending[1]} never reached an "
            f"outcome line - the log is truncated or unreadable there")
    return out, problems


def reconcile(cases, counts, parse_problems=()):
    """Fail-closed agreement between the per-case lines and the summary.

    Returns a list of refusal reasons; empty means the log is self-consistent
    and its per-case lines may be published as leaf outcomes. Any nonempty
    result refuses the WHOLE target: a log that miscounts one case is not a
    log that can be trusted about the others.
    """
    problems = list(parse_problems)
    names = [c[0] for c in cases]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        problems.append(
            f"duplicate per-case line(s) for {dupes} - one execution cannot "
            f"vouch for two leaf outcomes")
    by_outcome = {}
    for _n, o, _open, _close in cases:
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
    bytes, not a commit: every file tools/fork/stage.py would stage (its own
    `fork_files()`, so the two cannot drift), hashed. The outer-repo commit
    and dirty flag travel alongside so a reader can see both what the
    repository claims and what was actually on disk.
    """
    stage = _load_stage_module()
    rels = list(stage.fork_files())
    status = _git(REPO, "status", "--porcelain")
    return {
        "files": len(rels),
        "fork_tree_sha256": _tree_digest(FORK, rels),
        "outer_repo_commit": _git(REPO, "rev-parse", "HEAD"),
        "outer_repo_dirty": bool(status),
        "outer_repo_fork_paths_modified": [
            l[3:] for l in status.splitlines() if l[3:].startswith("fork/")],
    }


def stage_state():
    """tools/fork/stage.py --check, executed - never assumed.

    Returns (state, first_line) where state is STAGED / PRISTINE / MIXED /
    UNKNOWN. Recorded verbatim in the evidence; the tree classification below
    additionally uses stage.py's own `differing()` so 'is every fork patch
    staged' is answered by the staging tool rather than re-derived here.
    """
    r = subprocess.run([sys.executable, str(REPO / "tools" / "fork" / "stage.py"),
                        "--check"], capture_output=True, text=True)
    line = (r.stdout.strip().splitlines() or [""])[0]
    for state in ("STAGED", "PRISTINE", "MIXED"):
        if line.startswith(state):
            return state, line
    return "UNKNOWN", (line or r.stderr.strip())


def executed_tree_identity():
    """What was actually built and run, with cleanliness as a CLASSIFIED fact.

    `run_u0.executed_tree_identity()` records `dirty: bool(git status)`. On a
    fork lane that boolean is ALWAYS true - staging the fork is what makes the
    lane exist - so 'dirty' alone cannot distinguish 'the fork tree, exactly'
    from 'somebody left an edit in the checkout'. Worse, running the server
    suites WRITES `typedb-logs/` into the checkout, so a run that started on a
    clean-by-that-definition tree finishes on a dirty one and its own
    before/after identity check would fire on its own log output.

    So every diverging path is CLASSIFIED, and the classification is recorded:

      FORK_PATCH       - byte-identical to the same path under fork/typedb
      RUNTIME_OUTPUT   - a path a RUN writes and no crate compiles
                         (RUNTIME_OUTPUT_PREFIXES); excluded from the source
                         delta digest, listed by name in the evidence
      NON_CARGO_INPUT  - a path in the explicit NON_CARGO_INPUTS list above,
                         which enters neither the cargo build nor the
                         denominator; excluded from the digest and recorded
                         with its sha256 AND the reason that justifies it
      UNEXPLAINED      - anything else: a source edit that is neither upstream
                         nor the fork. One of these makes the tree DIRTY.

    tree_state = PRISTINE           - nothing diverges from the locked revision
               = FORK_STAGED_EXACT  - every diverging SOURCE path is a
                                      FORK_PATCH and stage.py's own
                                      `differing()` reports no unstaged fork
                                      patch; the tree is dirty w.r.t. the pin
                                      and EXACTLY identified by
                                      (checkout_revision, fork_tree_sha256)
               = DIRTY              - anything else. Never publishable.

    `dirty` keeps run_u0's exact meaning (git status is nonempty) so the two
    producers cannot be read as disagreeing.
    """
    stage = _load_stage_module()
    status = subprocess.run(["git", "-C", str(TB), "status", "--porcelain"],
                            capture_output=True, text=True).stdout
    entries = [l for l in status.splitlines() if l.strip()]
    classified, source_entries = [], []
    for line in sorted(entries):
        rel = line[3:].strip().strip('"')
        f = TB / rel
        if any(rel.startswith(pfx) for pfx in RUNTIME_OUTPUT_PREFIXES):
            kind = "RUNTIME_OUTPUT"
        elif (FORK / rel).is_file() and f.is_file() and \
                (FORK / rel).read_bytes() == f.read_bytes():
            kind = "FORK_PATCH"
        elif rel in NON_CARGO_INPUTS:
            kind = "NON_CARGO_INPUT"
        else:
            kind = "UNEXPLAINED"
        entry = {"path": rel, "class": kind}
        if kind == "NON_CARGO_INPUT":
            # excluded paths are recorded by name, digest and reason, so the
            # exclusion is auditable rather than merely asserted
            entry["sha256"] = common.sha256_file(f) if f.is_file() else None
            entry["reason"] = NON_CARGO_INPUTS[rel]
        classified.append(entry)
        if kind not in ("RUNTIME_OUTPUT", "NON_CARGO_INPUT"):
            source_entries.append((line, rel, kind))
    h = hashlib.sha256()
    for line, rel, _kind in source_entries:
        f = TB / rel
        h.update(line.encode() + b"\0")
        if f.is_file():
            h.update(f.read_bytes())
    new, changed, _stale = stage.differing()
    unstaged = [str(r) for r in new + changed]
    unexplained = [c["path"] for c in classified if c["class"] == "UNEXPLAINED"]
    state, state_line = stage_state()
    if not entries:
        tree_state = "PRISTINE"
    elif not unexplained and not unstaged:
        tree_state = "FORK_STAGED_EXACT"
    else:
        tree_state = "DIRTY"
    return {
        "checkout_revision": _git(TB, "rev-parse", "HEAD"),
        "dirty": bool(entries),
        "tree_state": tree_state,
        "stage_check": state_line,
        "unstaged_fork_patches": unstaged,
        "unexplained_paths": unexplained,
        "runtime_output_paths": [c["path"] for c in classified
                                 if c["class"] == "RUNTIME_OUTPUT"],
        "non_cargo_input_paths": [c for c in classified
                                  if c["class"] == "NON_CARGO_INPUT"],
        "diverging_paths": classified,
        "staged_delta_files": len(source_entries),
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

def bundle_files(results_dir, bundle, repo=REPO):
    """Every file this bundle's claims rest on: the results JSON and every
    raw log it names. Structurally the same rule as
    verdict.compute_bundle_root, over this schema's file names.

    `repo` is the root a repo-relative `raw_log` resolves against. It is a
    parameter and not a constant only so the negative-control harness can
    verify a MUTATED COPY of a bundle in a temp tree with the real verifier,
    as a real subprocess - the property under test is that the verifier
    refuses the copy, and that test must not be able to touch the archive.
    """
    results_dir = pathlib.Path(results_dir)
    files = [results_dir / RESULTS_NAME]
    for t in bundle.get("targets", []):
        if t.get("raw_log"):
            p = pathlib.Path(t["raw_log"])
            files.append(p if p.is_absolute() else pathlib.Path(repo) / p)
    return files


def compute_bundle_root(results_dir, bundle, repo=REPO):
    """sha256 over the sorted (repo-relative path, sha256) pairs of every file
    the bundle's leaf claims rest on. A post-hoc edit of ANY of them - the
    results JSON included - is a root mismatch, never a shrug.

    Identical algorithm to verdict.compute_bundle_root and to the driver-lane
    seal plan_coverage.py recomputes: `sha256(rel \0 sha \n ...)` over
    sorted repo-relative paths."""
    repo = pathlib.Path(repo)
    pairs = {}
    for f in bundle_files(results_dir, bundle, repo):
        if f.is_file():
            try:
                rel = f.resolve().relative_to(repo.resolve()).as_posix()
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
