#!/usr/bin/env python3
"""Leaf-granularity evidence producer for the cargo test families.

WHAT PROBLEM THIS SOLVES
------------------------
`tools/catalog/plan_coverage.py` reports `0 covered / 107 partial / 23031
uncovered of 23138`. Its first honesty rule says why: the archived evidence
records per-cargo-target libtest SUMMARY COUNTS, so a cargo-family leaf row
is at best PARTIAL and is never covered. Nothing about that is a libtest
limitation - libtest prints one line per case in its default format, and
that line IS the leaf outcome. This producer archives those lines, binds
them to the bytes they came from, and joins them to the plan's own leaf id
space so the coverage report can move rows from PARTIAL to COVERED without
anybody guessing anything.

WHAT IT REFUSES (each refusal is a way to report green without running)
----------------------------------------------------------------------
  * a target whose log is missing or empty                -> no leaves
  * a target whose log carries no `test result:` summary  -> no leaves
    (truncated log, or the binary died before finishing)
  * a target whose per-case lines disagree with that
    summary, in either direction                          -> no leaves
  * a target whose log reports filtered_out > 0           -> no leaves
  * a target that names one case twice                    -> no leaves
  * a case-bearing catalogue target that produced zero
    parsed cases                                          -> no leaves
  * a case name the catalogue does not carry FOR THIS
    TARGET  -> recorded as an extra case, never joined to another target's
               leaf, never counted
  * a catalogue leaf the log never named -> recorded as missing, never
               counted (an unrun leaf is uncovered, not passed)
  * a tree that changed between the start and the end of the run -> the
    WHOLE bundle is refused: rows produced against two different trees
    cannot be filed under one identity
  * a toolchain the plan does not name -> toolchain_id is null and the
    bundle covers no plan row

FAILPOINT LEAVES ARE NOT LEAF-OBSERVABLE HERE, AND ARE NOT CLAIMED
------------------------------------------------------------------
The catalogue's 44 FAILPOINT leaves are the product of 22 fail points x 2
libtest cases (`test_fail_point_always`, `test_fail_point_chance` in
tests/assembly/fail_points.rs), each of which loops over `fail_point::ALL`
INSIDE a single #[test]. libtest prints one line for the case, none for the
iterations, so no per-failpoint outcome exists in the log. Deriving 44
"passed" leaves from a passing loop would be an inference dressed as an
observation, so this producer emits the 2 LIBTEST leaves of that target and
records the 44 FAILPOINT leaves as NOT_LEAF_OBSERVABLE with the exact reason.
They stay uncovered until the loop prints per-iteration outcomes.

USAGE
  python3 tools/qualification/run_leaf.py --profile U1 --out DIR
  python3 tools/qualification/run_leaf.py --profile U2 --out DIR --package storage
  python3 tools/qualification/run_leaf.py --probe-formats   # what libtest
      formats this pinned toolchain actually supports (executed, not assumed)
"""
import argparse
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "tools" / "catalog"))
import common  # noqa: E402
import run_u0  # noqa: E402  (executable discovery + fixture staging, reused)
import leaf_common as lc  # noqa: E402

TB = REPO / "sources" / "typedb"
DEFAULT_TIMEOUT = 3600
# This machine's single filesystem is shared with concurrent builds. A test
# that fails because the disk filled is a FALSE RED, and a false red published
# as a leaf outcome is worse than no evidence at all - so the run STOPS,
# loudly, rather than archiving one. The remaining targets are then honestly
# absent (uncovered), never wrongly failed.
DEFAULT_MIN_FREE_MB = 400


def free_mb(path=REPO):
    st = os.statvfs(path)
    return (st.f_bavail * st.f_frsize) // (1024 * 1024)


def run_one(e, out_dir, timeout):
    """Execute one test binary and archive its raw log.

    The process mechanics deliberately mirror `run_u0.run_one` (short TMPDIR
    for AF_UNIX path limits, 64MB min stack for deep behaviour recursion, cwd
    = package root, isolated runfiles dir + serial execution + stray reaping
    for the assembly family, whole-process-group kill on timeout, and the
    harness=false detection that re-runs a non-libtest binary bare). Exactly
    ONE thing differs, and it is the point of this tool: the libtest output
    format is `pretty`, which prints one line per case, instead of `terse`,
    which prints one character per case and destroys the leaf granularity
    the run already had.
    """
    rid = f"{e['package']}:{e['target']}"
    raw = out_dir / f"{e['package']}__{e['target']}.log"
    env = dict(common.CARGO_ENV)
    tmp = pathlib.Path("/tmp/leafrun") / f"{abs(hash(rid)) % 100000}"
    tmp.mkdir(parents=True, exist_ok=True)
    env["TMPDIR"] = str(tmp)
    env["RUST_MIN_STACK"] = str(64 * 1024 * 1024)
    cwd = pathlib.Path(e.get("package_root") or TB)
    if e["target"] in run_u0.ASSEMBLY_TARGETS:
        env.update(run_u0.ASSEMBLY_ENV)
        iso = out_dir / "iso" / e["target"]
        if iso.exists():
            shutil.rmtree(iso)
        (iso / "tests" / "assembly").mkdir(parents=True)
        os.link(REPO / "sources" / "assembly-artifacts" / "typedb-all-linux-x86_64.tar.gz",
                iso / "typedb-all-linux-x86_64.tar.gz")
        shutil.copy2(TB / "tests" / "assembly" / "script.tql",
                     iso / "tests" / "assembly" / "script.tql")
        cwd = iso

    def execute(argv):
        with open(raw, "wb") as logf:
            proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=logf,
                                    stderr=subprocess.STDOUT, start_new_session=True)
            try:
                return proc.wait(timeout=timeout), False
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
                return None, True

    def reap_strays():
        subprocess.run(["pkill", "-9", "-f", "typedb-extracted/"], capture_output=True)
        time.sleep(0.5)

    start = time.time()
    argv = [e["executable"], "--format", "pretty"]
    if e["target"] in run_u0.ASSEMBLY_TARGETS:
        reap_strays()
        argv += ["--test-threads", "1"]
    code, timed_out = execute(argv)
    if code not in (0, None):
        head = raw.read_text(errors="replace")[:400]
        if common.is_non_libtest_harness_error(head):
            code, timed_out = execute([e["executable"]])
    dur = time.time() - start
    if e["target"] in run_u0.ASSEMBLY_TARGETS:
        reap_strays()
        # the extracted runfiles tree is ~250MB per assembly target and is a
        # WORKING directory, not evidence: the log it produced is the evidence
        # and is already archived. Dropping it keeps a long corpus run from
        # filling the shared disk out from under itself.
        shutil.rmtree(out_dir / "iso" / e["target"], ignore_errors=True)
    shutil.rmtree(tmp, ignore_errors=True)
    return {
        "runner_row_id": rid,
        "cargo_package": e["package"],
        "cargo_target": e["target"],
        "executable_sha256": common.sha256_file(e["executable"]),
        "exit_code": code,
        "timed_out": timed_out,
        "duration_seconds": round(dur, 2),
        "raw_log": str(raw.relative_to(REPO)),
        "log_sha256": common.sha256_file(raw),
        "log_bytes": raw.stat().st_size,
    }


def analyse(row, out_dir, catalog_target_id, catalog_leaves, plan, fixtures):
    """Turn one archived log into leaf rows, or into a refusal with a reason.

    Everything here is derived from the LOG FILE, re-read from disk after the
    row bound its hash. No count, name or outcome is taken from the process
    that produced it.
    """
    log = REPO / row["raw_log"]
    text = log.read_text(errors="replace")
    counts = common.parse_libtest_counts(text)
    cases = lc.parse_libtest_cases(text)
    refusals = []
    if not text.strip():
        refusals.append("the archived log is EMPTY - a target that printed "
                        "nothing proves nothing about its leaves")
    elif not lc.has_summary(text):
        refusals.append("the archived log carries no libtest 'test result:' "
                        "summary line - it is truncated or the binary died "
                        "mid-run, and an unterminated run cannot be reconciled")
    else:
        refusals += lc.reconcile(cases, counts)
    if row["timed_out"]:
        refusals.append("the target TIMED OUT - a killed process's partial "
                        "output is never a complete leaf enumeration")
    # An ENOSPC anywhere in the output means the environment failed, not the
    # code under test. Publishing those case outcomes would archive false reds
    # (and false greens for whatever ran before the disk filled).
    if "No space left on device" in text:
        refusals.append("the log contains 'No space left on device' - the "
                        "environment failed during this target, so its case "
                        "outcomes describe the disk, not the code under test")

    declared = catalog_leaves.get(catalog_target_id, {})
    observed = {n for n, _o, _l in cases}
    if declared and not cases and not refusals:
        refusals.append(
            f"the catalogue records {len(declared)} leaf case(s) for this "
            f"target but the log names none - vacuous evidence: a binary that "
            f"ran nothing proves nothing about its leaves")

    extra = sorted(observed - set(declared))
    missing = sorted(set(declared) - observed)
    row.update({
        "catalog_target_id": catalog_target_id,
        "counts": counts,
        "parsed_cases": len(cases),
        "catalog_leaf_cases": len(declared),
        "extra_cases": extra,
        "missing_cases": missing,
        "refusals": refusals,
        "publishable": not refusals,
    })
    if refusals or catalog_target_id is None:
        return []

    leaves = []
    for name, outcome, line_no in cases:
        leaf = declared.get(name)
        if leaf is None:
            continue  # extra_cases: recorded above, never published as a leaf
        fs_id = leaf.get("fixture_set_id") or plan["leaves"].get(
            leaf["leaf_case_id"], {}).get("fixture_set_id", "fs:none")
        leaves.append({
            "leaf_case_id": leaf["leaf_case_id"],
            "catalog_target_id": catalog_target_id,
            "runner_row_id": row["runner_row_id"],
            "case_name": name,
            "outcome": outcome,
            "raw_log": row["raw_log"],
            "log_sha256": row["log_sha256"],
            "log_line": line_no,
            "fixture_set_id": fs_id,
            "fixture_set_satisfied": lc.fixture_set_satisfied(fs_id, plan, fixtures),
        })
    return leaves


def probe_formats(executable):
    """Which libtest output formats this PINNED toolchain actually supports.

    The brief allows `--format json` if the toolchain supports it. That is an
    empirical question about a stable 1.93.0 libtest, so it is answered by
    running the binary, not by recalling a release note.
    """
    out = {}
    for name, argv in (("pretty", ["--format", "pretty", "--list"]),
                       ("terse", ["--format", "terse", "--list"]),
                       ("json", ["--format", "json", "--list"]),
                       ("json+Z", ["-Z", "unstable-options", "--format", "json", "--list"])):
        r = subprocess.run([executable, *argv], capture_output=True, text=True,
                           timeout=120)
        out[name] = {"argv": argv, "returncode": r.returncode,
                     "head": (r.stdout or r.stderr).strip().splitlines()[:2]}
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", default=None,
                    help="storage profile to run under; must be a plan profile "
                         "(U0..U4) for the evidence to cover any plan row")
    ap.add_argument("--out", default=None)
    ap.add_argument("--package", action="append", default=None)
    ap.add_argument("--filter", default=None)
    ap.add_argument("--skip", action="append", default=[])
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--min-free-mb", type=int, default=DEFAULT_MIN_FREE_MB,
                    help="stop the run before a target whose execution would "
                         "risk running the shared disk out; an ENOSPC failure "
                         "is a false red and must never be archived as a leaf "
                         "outcome")
    ap.add_argument("--probe-formats", action="store_true",
                    help="report which libtest formats the pinned toolchain "
                         "supports, using a real compiled test binary")
    args = ap.parse_args()

    plan = json.loads(lc.PLAN.read_text())
    catalog_leaves, catalog_targets, catalog = lc.load_catalog_leaves()
    rid_map = lc.rid_to_catalog_target(catalog_targets)

    if args.probe_formats:
        execs = run_u0.discover_executables(args.package or ["storage"])
        e = next(x for x in execs if x["target"] == (args.filter or "storage"))
        print(json.dumps({"executable": e["executable"],
                          "toolchain": lc.measured_toolchain(),
                          "formats": probe_formats(e["executable"])}, indent=1))
        return 0

    if not args.profile or not args.out:
        ap.error("--profile and --out are required for a run")
    out_dir = pathlib.Path(args.out).resolve()
    if (out_dir / "COMPLETE").exists():
        sys.exit(f"{out_dir} carries a COMPLETE marker - it is a sealed leaf "
                 f"evidence bundle and this producer will not write into it. "
                 f"Use a fresh --out.")
    out_dir.mkdir(parents=True, exist_ok=True)

    profile = args.profile
    os.environ["TYPEDB_STORAGE_PROFILE"] = profile
    tc = lc.measured_toolchain()
    tc_id = lc.toolchain_id(tc, plan)
    fixtures = lc.fixture_state()
    tree_before = lc.executed_tree_identity()

    execs = run_u0.discover_executables(args.package)
    if args.filter:
        execs = [e for e in execs if args.filter in f"{e['package']}:{e['target']}"]
    execs = [e for e in execs
             if not any(s in f"{e['package']}:{e['target']}" for s in args.skip)]
    if not run_u0.ensure_behaviour_fixture():
        affected = run_u0.needs_behaviour_fixture(execs)
        if affected:
            sys.exit(f"sources/typedb-behaviour missing and {len(affected)} selected "
                     f"target(s) read Cucumber features through it - running them "
                     f"would archive false reds.")
    selection_complete = not (args.filter or args.skip or args.package)
    print(f"LEAF RUN profile={profile} targets={len(execs)} "
          f"tree_state={tree_before['tree_state']}", flush=True)

    targets, leaves = [], []
    aborted = None
    for i, e in enumerate(execs):
        rid = f"{e['package']}:{e['target']}"
        avail = free_mb()
        if avail < args.min_free_mb:
            aborted = (f"stopped before {rid}: only {avail} MB free on the "
                       f"shared filesystem (< --min-free-mb {args.min_free_mb}). "
                       f"A target that fails because the disk filled is a FALSE "
                       f"RED; the remaining {len(execs) - i} target(s) are "
                       f"honestly absent from this bundle instead.")
            print(f"ABORT: {aborted}", flush=True)
            break
        print(f"[{i+1}/{len(execs)}] {rid} ({avail}MB free) ...", end=" ", flush=True)
        row = run_one(e, out_dir, args.timeout)
        ctid = rid_map.get(rid)
        got = analyse(row, out_dir, ctid, catalog_leaves, plan, fixtures)
        leaves += got
        targets.append(row)
        print(f"rc={row['exit_code']} {row['parsed_cases']} case(s) -> "
              f"{len(got)} leaf/leaves"
              + (f"  REFUSED: {row['refusals'][0]}" if row["refusals"] else "")
              + f"  [{row['duration_seconds']}s]", flush=True)

    tree_after = lc.executed_tree_identity()
    bundle = {
        "schema": lc.SCHEMA,
        "profile": profile,
        "profile_in_plan": profile in plan["profiles"],
        "toolchain": tc,
        "toolchain_id": tc_id,
        "plan_root": plan.get("plan_root"),
        "catalog_sha256": common.sha256_file(lc.CATALOG),
        "source_lock_digest": catalog.get("source_lock_digest"),
        "selection": {"package": args.package, "filter": args.filter,
                      "skip": args.skip,
                      "complete": selection_complete and aborted is None,
                      "aborted": aborted,
                      "targets_selected": len(execs),
                      "targets_executed": len(targets)},
        "fixtures": fixtures,
        "executed_tree": tree_before,
        "executed_tree_after_run": tree_after,
        # Stability is asserted over the EXECUTED tree only - the checkout
        # revision and the source delta that produced the binaries. The
        # fork/typedb worktree is edited by other work on this machine and its
        # digest moving mid-run does NOT change what ran, so it is recorded as
        # a separate, informational fact rather than silently folded in (or
        # silently ignored).
        "tree_stable_across_run":
            tree_before["staged_delta_sha256"] == tree_after["staged_delta_sha256"]
            and tree_before["checkout_revision"] == tree_after["checkout_revision"],
        "fork_worktree_changed_during_run":
            tree_before["fork"]["fork_tree_sha256"]
            != tree_after["fork"]["fork_tree_sha256"],
        "started_utc": None,
        "targets": sorted(targets, key=lambda r: r["runner_row_id"]),
        "leaves": sorted(leaves, key=lambda r: r["leaf_case_id"]),
        "failpoint_leaves_not_observable": {
            "count": sum(1 for x in catalog["leaf_cases"] if x["kind"] == "FAILPOINT"),
            "reason": "the catalogue's FAILPOINT leaves are (fail point x libtest "
                      "case) products enumerated inside a `for fail_point in "
                      "fail_point::ALL` loop within two #[test] functions; libtest "
                      "prints one line for the case and none for the iterations, so "
                      "no per-failpoint outcome exists in the log. Claiming them "
                      "from a passing loop would be inference presented as "
                      "observation, so they are left UNCOVERED.",
        },
    }
    results = out_dir / lc.RESULTS_NAME
    results.write_text(json.dumps(bundle, indent=1) + "\n")
    # The root is computed OVER the results file and the logs, and is stored
    # OUTSIDE both - in the sidecar manifest, in the verdict, and in the
    # COMPLETE marker. verdict.py does exactly this (the root lives in
    # verdict.json, never in u0-results.json) and the reason is not
    # stylistic: a root written back into the file it hashes can never be
    # recomputed, so a self-referential seal is a seal that always mismatches
    # and therefore proves nothing.
    root, pairs = lc.compute_bundle_root(out_dir, bundle)
    # sidecar name and shape follow the convention plan_coverage.py already
    # consumes for the driver lane (`bundle-manifest.json`, {bundle_root,
    # files:{rel:sha}}); the root algorithm is byte-for-byte the one
    # verdict.compute_bundle_root uses (`rel\0sha\n` over sorted rels), so
    # every seal in this repository is recomputed the same way.
    (out_dir / "bundle-manifest.json").write_text(json.dumps(
        {"bundle_root": root, "files": pairs}, indent=1) + "\n")
    root2 = root

    refused = [t for t in targets if t["refusals"]]
    observation = {
        "targets": len(targets),
        "targets_refused": len(refused),
        "nonzero_exit_targets": sum(1 for t in targets
                                    if not t["timed_out"] and t["exit_code"] != 0),
        "timed_out_targets": sum(1 for t in targets if t["timed_out"]),
        "leaves": len(leaves),
        "leaves_passed": sum(1 for l in leaves if l["outcome"] == "PASSED"),
        "leaves_failed": sum(1 for l in leaves if l["outcome"] == "FAILED"),
        "leaves_ignored": sum(1 for l in leaves if l["outcome"] == "IGNORED"),
    }
    # The verdict file mirrors tools/catalog/verdict.py's shape: the raw
    # OBSERVATION always travels with the bundle root, and this producer never
    # adjudicates pass/fail - coverage is denominator progress, and a FAILED
    # leaf is covered evidence of a failure, not a hole.
    (out_dir / "leaf-verdict.json").write_text(json.dumps({
        "producer": "tools/qualification/run_leaf.py",
        "schema": lc.SCHEMA,
        "profile": profile,
        "profile_in_plan": bundle["profile_in_plan"],
        "toolchain_id": tc_id,
        "plan_root": plan.get("plan_root"),
        "catalog_sha256": bundle["catalog_sha256"],
        "executed_tree": tree_before,
        "tree_stable_across_run": bundle["tree_stable_across_run"],
        "selection": bundle["selection"],
        "observation": observation,
        "bundle_root": root,
        "statement": (
            "This bundle records per-case OUTCOMES, not a pass. A FAILED leaf "
            "here is evidence of a failure, and coverage counts recorded "
            "outcomes only."),
    }, indent=1) + "\n")
    print(json.dumps({
        "profile": profile, "profile_in_plan": bundle["profile_in_plan"],
        "toolchain_id": tc_id,
        "tree_state": tree_before["tree_state"],
        "tree_stable_across_run": bundle["tree_stable_across_run"],
        "targets": len(targets), "targets_refused": len(refused),
        "leaves_emitted": len(leaves),
        "leaves_passed": sum(1 for l in leaves if l["outcome"] == "PASSED"),
        "leaves_failed": sum(1 for l in leaves if l["outcome"] == "FAILED"),
        "leaves_ignored": sum(1 for l in leaves if l["outcome"] == "IGNORED"),
        "bundle_root": root2,
    }, indent=1))
    for t in refused:
        print(f"REFUSED {t['runner_row_id']}: {t['refusals']}", file=sys.stderr)
    if not bundle["tree_stable_across_run"]:
        print("REFUSED BUNDLE: the executed tree changed during the run; rows "
              "produced against two different trees cannot be filed under one "
              "identity", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
