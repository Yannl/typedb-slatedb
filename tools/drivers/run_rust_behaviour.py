#!/usr/bin/env python3
"""E-05 official-driver lane: execute the OFFICIAL TypeDB Rust driver
behaviour suite against a TypeDB server and archive LEAF-LEVEL evidence.

What this runner is for
-----------------------
The qualification plan carries six `driver:<driver>:<backend>` rows
(docs/evidence/G1/qualification-plan-v2.json). Every one of them was
NOT_IMPLEMENTED with the reason "official driver suite harness is not built".
This runner is that harness for the Rust driver. It does not lower the bar:
it produces per-SCENARIO outcomes joined onto the plan's own
`cucumber:<feature>::<scenario>` leaf ids, so a driver row can only move on
evidence that names every case it ran.

Why leaf level is the whole point
---------------------------------
The upstream suite is ONE libtest case per feature file: `test result: ok. 1
passed` after 43 scenarios. Recording that line would repeat exactly the
defect tools/catalog/plan_coverage.py already calls PARTIAL - target
granularity masquerading as coverage. This runner therefore parses the
cucumber writer stream per scenario (tools/drivers/cucumber_log.py) and
cross-checks it three ways before it will call anything executed:

  * the observed scenario SEQUENCE must equal the sequence an independent
    Gherkin enumeration of the feature file predicts, name for name, in order
    (tools/drivers/gherkin_leaves.py);
  * that enumeration's leaf-id list must equal the qualification plan's leaf-
    id list for the same feature file, and the plan's recorded source hash
    must equal the feature file's hash NOW;
  * the per-scenario tally must equal cucumber's own `[Summary]` stats, and
    the libtest result line must agree with the process exit code.

Any disagreement is a fail-closed anomaly. A missing `[Summary]` is a
TRUNCATED RUN. A suite that produced no scenarios is NOT vacuously green: it
is `NO_SCENARIOS`, an anomaly. A leaf the runner cannot tie to an observed
scenario is `NOT_RUN`, never assumed.

Provenance (R6-EVID-01)
-----------------------
Before anything runs, tools/drivers/projection_check.py must pass: locked
TDRIVER/BH revisions AND trees AND clean checkouts, every compiled path
inside the locked driver, dependency-resolution parity with the driver's own
Cargo.lock, and suite-set parity with the Bazel rust_behaviour_test
declarations. Test executables are resolved from `cargo --message-format=json`
- never a hardcoded target path - and each one's sha256 is recorded. The
server binary, its checkout identity (including fork dirt, explicitly), its
argv, and every readiness probe are recorded too.

Usage:
  python3 tools/drivers/run_rust_behaviour.py --lane fork-classic \
      --backend rocksdb --out docs/evidence/G1/drivers/rust-rocksdb-fork
  python3 tools/drivers/run_rust_behaviour.py --lane fork-slatedb \
      --backend slatedb --out docs/evidence/G1/drivers/rust-slatedb-fork
  python3 tools/drivers/run_rust_behaviour.py --list-suites

Exit code: 0 only when every required suite executed, every plan leaf it
covers produced a leaf outcome, and no anomaly was raised.
"""
import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import common                     # noqa: E402
import cucumber_log               # noqa: E402
import gherkin_leaves             # noqa: E402
import projection_check           # noqa: E402
import typedb_server              # noqa: E402

REPO = common.REPO
DRIVER = REPO / "sources" / "typedb-driver"
BEHAVIOUR = REPO / "sources" / "typedb-behaviour"
PROJ = REPO / "tools" / "drivers" / "rust-behaviour"
STEPS_LIB = DRIVER / "rust" / "tests" / "behaviour" / "steps" / "lib.rs"
TOOLCHAIN = "1.93.0"          # source-lock node RUST_PARITY

# Suites the runner does not require to be green, each with the EXACT external
# precondition that blocks it. A suite may live here only with a precondition
# a reader can check; "flaky" or "not yet" is not a precondition.
SUITE_PRECONDITIONS = {
    "test_cluster": (
        "requires a multi-node TypeDB cluster: the upstream test self-skips "
        "unless the `cluster` cargo feature is on (rust/tests/behaviour/driver/"
        "cluster.rs calls config::is_cluster()), and the steps then connect to "
        "Context::DEFAULT_CLUSTER_ADDRESSES 127.0.0.1:{11729,21729,31729}. "
        "TypeDB CE - the only server this repository builds - is single-node, "
        "so no cluster can be stood up here. Executed and observed: the binary "
        "prints 'Skipping Cluster tests in a non-clustered environment' and "
        "runs zero scenarios."),
}


def upstream_ignore_tags():
    """Read the driver's OWN skip policy out of its source, never a copy.

    Context::is_ignore_tag decides which scenarios the Rust suite refuses to
    run. Hardcoding that list here would let this runner quietly disagree with
    the code under test about the denominator, so it is extracted and the
    extraction fails closed.
    """
    text = STEPS_LIB.read_text()
    m = re.search(r"fn is_ignore_tag\([^)]*\)\s*->\s*bool\s*\{(.*?)\n    \}",
                  text, re.S)
    if not m:
        raise RuntimeError(f"{common.rel(STEPS_LIB)}: cannot locate "
                           f"Context::is_ignore_tag; refusing to guess which "
                           f"scenarios the driver skips")
    tags = re.findall(r't\s*==\s*"([^"]+)"', m.group(1))
    if not tags:
        raise RuntimeError(f"{common.rel(STEPS_LIB)}: is_ignore_tag names no "
                           f"tags; refusing to guess")
    return sorted(tags)


def discover_suites():
    """suite name -> {source, feature_ref} from the projection manifest and
    the upstream test sources. The feature ref is read out of the test source
    itself (the `typedb_behaviour+/<ref>` bazel path), which is the same
    anchor tools/catalog/generate_catalog.py used to build the plan."""
    import tomllib
    tdoc = tomllib.loads((PROJ / "tests" / "Cargo.toml").read_text())
    out = {}
    for t in tdoc.get("test", []):
        src = (PROJ / "tests" / t["path"]).resolve()
        text = src.read_text()
        refs = set(re.findall(r'typedb_behaviour\+/([^"]+\.feature)', text))
        if len(refs) != 1:
            raise RuntimeError(f"{common.rel(src)}: expected exactly one "
                               f"feature reference, found {sorted(refs)}")
        out[t["name"]] = {"source": common.rel(src), "feature_ref": refs.pop()}
    return dict(sorted(out.items()))


def cargo_build(target_dir, toolchain=TOOLCHAIN):
    """Build the projected test targets and resolve every test EXECUTABLE from
    cargo's own JSON message stream (R6-EVID-01: never a hardcoded
    target/debug path)."""
    env = dict(os.environ)
    env["CARGO_TARGET_DIR"] = str(target_dir)
    argv = ["cargo", f"+{toolchain}", "build", "--locked", "--tests",
            "--message-format=json-render-diagnostics"]
    p = subprocess.run(argv, cwd=PROJ, env=env, capture_output=True, text=True)
    executables = {}
    for line in p.stdout.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-artifact" or not msg.get("executable"):
            continue
        tgt = msg.get("target") or {}
        if "test" in (tgt.get("kind") or []) or msg.get("profile", {}).get("test"):
            executables[tgt.get("name")] = msg["executable"]
    return {
        "argv": argv, "cwd": common.rel(PROJ), "exit_code": p.returncode,
        "cargo_target_dir": str(target_dir),
        "stderr_tail": p.stderr[-4000:],
        "executables": executables,
    }


def toolchain_versions(toolchain=TOOLCHAIN):
    def v(*a):
        r = subprocess.run(a, capture_output=True, text=True)
        return r.stdout.strip() or r.stderr.strip()
    return {"requested": toolchain,
            "cargo": v("cargo", f"+{toolchain}", "--version"),
            "rustc": v("rustc", f"+{toolchain}", "--version"),
            "host": v("uname", "-srmo")}


def make_workdir(run_dir):
    """A working directory in which BOTH relative feature-file conventions the
    upstream test sources use resolve onto sources/typedb-behaviour:

        <work>/drv/rust                                   <- cwd of the binary
        ../../typedb-behaviour/...                        -> <work>/typedb-behaviour
        ../bazel-typedb-driver/external/typedb_behaviour  -> <work>/drv/...

    Both are symlinks to the locked corpus. Nothing under sources/ is touched:
    creating these links inside sources/typedb-driver would be an edit of a
    source-locked tree.
    """
    work = pathlib.Path(run_dir) / "work"
    if work.exists():
        shutil.rmtree(work)
    (work / "drv" / "rust").mkdir(parents=True)
    (work / "drv" / "bazel-typedb-driver" / "external").mkdir(parents=True)
    os.symlink(BEHAVIOUR, work / "typedb-behaviour")
    os.symlink(BEHAVIOUR,
               work / "drv" / "bazel-typedb-driver" / "external" / "typedb_behaviour")
    return work


def plan_leaf_ids(plan, ref):
    return sorted(k for k in plan["leaves"]
                  if k.startswith(f"cucumber:{ref}::"))


def run_suite(name, meta, executable, workdir, out_dir, timeout_s):
    log_path = out_dir / f"{name}.log"
    argv = [str(executable), "--nocapture"]
    t0 = time.time()
    timed_out = False
    with open(log_path, "wb") as fh:
        try:
            p = subprocess.run(argv, cwd=workdir / "drv" / "rust", stdout=fh,
                               stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                               timeout=timeout_s)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            rc, timed_out = None, True
    return {"suite_id": name, "argv": argv,
            "cwd": common.rel(workdir / "drv" / "rust"),
            "executable": str(executable),
            "executable_sha256": common.sha256_file(executable),
            "exit_code": rc, "timed_out": timed_out,
            "duration_seconds": round(time.time() - t0, 2),
            "raw_log": common.rel(log_path),
            "log_sha256": common.sha256_file(log_path),
            "log_bytes": log_path.stat().st_size}


def analyse_suite(row, meta, plan, ignore_tags, anomalies):
    """Join one suite's raw log onto plan leaves. Returns (row, leaf rows)."""
    name = row["suite_id"]
    ref = meta["feature_ref"]
    feature = BEHAVIOUR / ref
    row["feature_ref"] = ref
    row["feature_path"] = common.rel(feature)
    row["feature_sha256"] = common.sha256_file(feature)

    expected = gherkin_leaves.enumerate_leaves(feature, ref)
    mine = [e["leaf_case_id"] for e in expected]
    planned = plan_leaf_ids(plan, ref)
    row["leaves_enumerated"] = len(expected)
    row["leaves_in_plan"] = len(planned)
    if planned and sorted(mine) != planned:
        anomalies.append(
            f"{name}: independent Gherkin enumeration of {ref} disagrees with "
            f"the qualification plan's leaf ids "
            f"(+{sorted(set(mine) - set(planned))[:3]} "
            f"-{sorted(set(planned) - set(mine))[:3]})")
    for lid in planned:
        ph = plan["leaves"][lid].get("source_hash")
        if ph and ph != row["feature_sha256"]:
            anomalies.append(
                f"{name}: {ref} hashes to {row['feature_sha256']} but the plan "
                f"pinned {ph} - the corpus changed under the plan")
            break

    def ignored_by(leaf):
        for t in leaf["tags"]:
            if t.lstrip("@") in ignore_tags:
                return t
        return None

    runnable = [e for e in expected if ignored_by(e) is None]
    row["leaves_runnable"] = len(runnable)
    row["leaves_tag_skipped"] = len(expected) - len(runnable)

    text = pathlib.Path(REPO / row["raw_log"]).read_text(errors="replace")
    if not text.strip():
        anomalies.append(f"{name}: raw log is EMPTY - nothing was executed or "
                         f"the output was lost; an empty log is never evidence")
    parsed = cucumber_log.parse(text)
    observed = parsed["scenarios"]
    row["observed_scenarios"] = len(observed)
    row["summary"] = ({k: v for k, v in parsed["summary"].items() if k != "raw"}
                      if parsed["summary"] else None)
    row["libtest"] = parsed["libtest"]
    row["repeat_blocks"] = len(parsed["repeat_scenarios"])

    precondition = SUITE_PRECONDITIONS.get(name)
    if not observed and not parsed["saw_summary"]:
        if precondition:
            row["status"] = "NOT_EXECUTED_PRECONDITION_UNMET"
            row["precondition"] = precondition
            row["log_excerpt"] = text.strip()[:400]
        else:
            row["status"] = "NO_SCENARIOS"
            anomalies.append(
                f"{name}: the suite produced ZERO cucumber scenarios and no "
                f"[Summary]; a binary that ran nothing proves nothing about "
                f"its {len(runnable)} runnable leaves")
        leaves = [_leaf_row(e, name, ref, "NOT_RUN",
                            reason=row.get("precondition") or
                            "suite produced no scenarios", plan=plan,
                            ignored_tag=ignored_by(e)) for e in expected]
        return row, leaves

    row["status"] = "EXECUTED"
    if not parsed["saw_summary"]:
        row["status"] = "TRUNCATED"
        anomalies.append(
            f"{name}: no cucumber [Summary] in the log - the run was truncated "
            f"(killed, crashed, or the log was cut); its "
            f"{len(observed)} scenario block(s) are not a complete run")
    if row["timed_out"]:
        row["status"] = "TIMED_OUT"
        anomalies.append(f"{name}: timed out; a timeout is never ledgerable")

    # ---- sequence join, exact and ordered
    obs_names = [s["scenario_name"] for s in observed]
    exp_names = [e["display_name"] for e in runnable]
    if obs_names != exp_names:
        first = next((i for i, (a, b) in enumerate(zip(exp_names, obs_names))
                      if a != b), min(len(exp_names), len(obs_names)))
        anomalies.append(
            f"{name}: observed scenario sequence != the sequence enumerated "
            f"from {ref} (expected {len(exp_names)}, observed {len(obs_names)}; "
            f"first divergence at index {first}: "
            f"expected {exp_names[first:first + 1]}, "
            f"observed {obs_names[first:first + 1]})")

    # ---- summary cross-check
    s = parsed["summary"]
    if s:
        for key, got in (("features", len(observed)), ("scenarios", len(observed))):
            declared = (s.get(key) or {}).get("total")
            if declared != got:
                anomalies.append(f"{name}: cucumber [Summary] says {declared} "
                                 f"{key} but the log carries {got} scenario "
                                 f"block(s)")
        tally = {"passed": 0, "failed": 0, "skipped": 0}
        for sc in observed:
            tally[{"PASSED": "passed", "FAILED": "failed",
                   "SKIPPED": "skipped", "EMPTY": "failed"}[sc["status"]]] += 1
        declared = s.get("scenarios") or {}
        for k in ("passed", "failed", "skipped"):
            if declared.get(k, 0) != tally[k]:
                anomalies.append(
                    f"{name}: re-derived {tally[k]} {k} scenario(s) but the "
                    f"[Summary] declares {declared.get(k, 0)}")
        if s.get("parsing_errors"):
            anomalies.append(f"{name}: cucumber reported "
                             f"{s['parsing_errors']} parsing error(s)")
        if s.get("hook_errors"):
            anomalies.append(f"{name}: cucumber reported {s['hook_errors']} "
                             f"hook error(s)")

    # ---- libtest / exit-code consistency
    lt = parsed["libtest"]
    if lt is None and not row["timed_out"]:
        anomalies.append(f"{name}: no libtest `test result:` line - the process "
                         f"did not finish its single test case")
    elif lt is not None:
        if (lt["outcome"] == "ok") != (row["exit_code"] == 0):
            anomalies.append(f"{name}: libtest says {lt['outcome']!r} but the "
                             f"process exited {row['exit_code']}")
    if row["exit_code"] not in (0, None):
        anomalies.append(f"{name}: process exited {row['exit_code']}")

    # ---- leaf rows
    leaves = []
    obs_by_index = {i: sc for i, sc in enumerate(observed)}
    ri = 0
    for e in expected:
        tag = ignored_by(e)
        if tag is not None:
            leaves.append(_leaf_row(e, name, ref, "SKIPPED_IGNORED_TAG",
                                    reason=f"scenario carries {tag}, which "
                                           f"Context::is_ignore_tag skips",
                                    plan=plan, ignored_tag=tag))
            continue
        sc = obs_by_index.get(ri)
        ri += 1
        if sc is None or sc["scenario_name"] != e["display_name"]:
            leaves.append(_leaf_row(e, name, ref, "NOT_RUN",
                                    reason="no observed scenario block at this "
                                           "position with this name",
                                    plan=plan, ignored_tag=None))
            continue
        leaves.append(_leaf_row(e, name, ref, sc["status"], plan=plan,
                                ignored_tag=None, observed=sc))
    row["leaf_status_counts"] = _counts(leaves)
    return row, leaves


def _leaf_row(e, suite, ref, status, plan, ignored_tag, reason=None,
              observed=None):
    row = {
        "leaf_case_id": e["leaf_case_id"],
        "suite_id": suite,
        "feature_ref": ref,
        "display_name": e["display_name"],
        "feature_line": e["line"],
        "kind": e["kind"],
        "status": status,
        "in_plan": e["leaf_case_id"] in plan["leaves"],
    }
    if ignored_tag:
        row["ignored_tag"] = ignored_tag
    if reason:
        row["reason"] = reason
    if observed is not None:
        row.update({
            "steps_passed": observed["steps_passed"],
            "steps_failed": observed["steps_failed"],
            "steps_skipped": observed["steps_skipped"],
            "steps_total": observed["steps_total"],
            "log_line": observed["line_index"] + 1,
        })
    return row


def _counts(leaves):
    out = {}
    for l in leaves:
        out[l["status"]] = out.get(l["status"], 0) + 1
    return dict(sorted(out.items()))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lane", default="fork-classic",
                    choices=sorted(typedb_server.LANES))
    ap.add_argument("--backend", default=None,
                    help="plan backend column (rocksdb|slatedb); default is "
                         "derived from the lane's storage profile")
    ap.add_argument("--driver", default="rust")
    ap.add_argument("--out", type=pathlib.Path, required=False)
    ap.add_argument("--run-dir", type=pathlib.Path, default=None)
    ap.add_argument("--suite", action="append", default=None)
    ap.add_argument("--server-binary", default=None)
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--target-dir", type=pathlib.Path, default=None,
                    help="CARGO_TARGET_DIR for the projection build; default "
                         "<run-dir>/target")
    ap.add_argument("--list-suites", action="store_true")
    ap.add_argument("--shared-server", action="store_true",
                    help="run every suite against ONE server process instead "
                         "of a fresh one per suite (weaker isolation; recorded)")
    args = ap.parse_args()

    suites = discover_suites()
    if args.list_suites:
        print(json.dumps(suites, indent=1))
        return 0
    if args.out is None:
        ap.error("--out is required")

    backend = args.backend or {"U0": "rocksdb", "U1": "rocksdb",
                               "U2": "slatedb"}[typedb_server.LANES[args.lane][1]]
    out_dir = args.out if args.out.is_absolute() else REPO / args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    run_dir = args.run_dir or (pathlib.Path(
        os.environ.get("TMPDIR", "/tmp")) / f"driver-lane-{args.driver}-{backend}")
    run_dir.mkdir(parents=True, exist_ok=True)

    anomalies = []
    plan = json.loads(common.PLAN.read_text())
    plan_root_recomputed = common.plan_root_of_body(plan)
    if plan_root_recomputed != plan.get("plan_root"):
        anomalies.append(
            f"plan: self-declared plan_root {plan.get('plan_root')} does not "
            f"recompute from its own body ({plan_root_recomputed}) - forged plan")

    proj = projection_check.check()
    if not proj["ok"]:
        anomalies.extend(f"projection: {p}" for p in proj["problems"])

    ignore_tags = upstream_ignore_tags()

    build = None
    if not args.skip_build:
        build = cargo_build(args.target_dir or (run_dir / "target"))
        if build["exit_code"] != 0:
            anomalies.append(f"cargo build exited {build['exit_code']}: "
                             f"{build['stderr_tail'][-600:]}")
    else:
        build = {"skipped": True, "executables": {}}

    selected = args.suite or sorted(suites)
    unknown = [s for s in selected if s not in suites]
    if unknown:
        ap.error(f"unknown suite(s): {unknown}; known: {sorted(suites)}")

    workdir = make_workdir(run_dir)
    suite_rows, leaf_rows, server_records = [], [], []
    server = None
    try:
        if args.shared_server:
            server = typedb_server.TypeDBServer(
                args.lane, run_dir, binary=args.server_binary)
            server.start()
            shutil.copy(server.log_path, out_dir / "server.log")
        for name in selected:
            exe = build["executables"].get(name)
            if exe is None or not pathlib.Path(exe).is_file():
                anomalies.append(f"{name}: cargo produced no test executable")
                suite_rows.append({"suite_id": name, "status": "NOT_BUILT",
                                   "feature_ref": suites[name]["feature_ref"]})
                continue
            per = None
            if not args.shared_server:
                per_dir = run_dir / name
                per_dir.mkdir(parents=True, exist_ok=True)
                per = typedb_server.TypeDBServer(
                    args.lane, per_dir, binary=args.server_binary)
                per.start()
                shutil.copy(per.log_path, out_dir / f"server-{name}.log")
            row = run_suite(name, suites[name], exe, workdir, out_dir,
                            args.timeout)
            active = per or server
            row["server_alive_after_suite"] = active.alive()
            if not active.alive():
                anomalies.append(f"{name}: the TypeDB server died during the "
                                 f"suite; its results are not trustworthy")
            row, leaves = analyse_suite(row, suites[name], plan, ignore_tags,
                                        anomalies)
            suite_rows.append(row)
            leaf_rows.extend(leaves)
            if per is not None:
                rec = per.evidence()
                rec["suite_id"] = name
                rec["log"] = common.rel(out_dir / f"server-{name}.log")
                per.stop()
                rec["exit_code"] = per.proc.returncode
                shutil.copy(per.log_path, out_dir / f"server-{name}.log")
                rec["log_sha256"] = common.sha256_file(
                    out_dir / f"server-{name}.log")
                server_records.append(rec)
    finally:
        if server is not None:
            rec = server.evidence()
            server.stop()
            rec["exit_code"] = server.proc.returncode
            shutil.copy(server.log_path, out_dir / "server.log")
            rec["log"] = common.rel(out_dir / "server.log")
            rec["log_sha256"] = common.sha256_file(out_dir / "server.log")
            server_records.append(rec)

    # ---- denominator accounting
    ref_set = {suites[n]["feature_ref"] for n in selected}
    plan_leaves_in_scope = sorted(
        lid for ref in ref_set for lid in plan_leaf_ids(plan, ref))
    produced = {l["leaf_case_id"] for l in leaf_rows}
    missing = sorted(set(plan_leaves_in_scope) - produced)
    if missing:
        anomalies.append(f"{len(missing)} plan leaf/leaves in scope produced no "
                         f"leaf row at all, e.g. {missing[:3]}")
    fabricated = sorted(l["leaf_case_id"] for l in leaf_rows
                        if not l["in_plan"])
    counts = _counts(leaf_rows)
    in_plan_leaves = [l for l in leaf_rows if l["in_plan"]]
    covered = [l for l in in_plan_leaves
               if l["status"] in ("PASSED", "FAILED", "SKIPPED")]
    green = [l for l in in_plan_leaves if l["status"] == "PASSED"]

    results = {
        "schema": "typedb-r2-driver-lane-v1",
        "statement": (
            "LEAF-LEVEL execution evidence for one official-driver plan row. "
            "Every `leaves` entry is one cucumber scenario (or one Scenario "
            "Outline example) of the locked typedb-behaviour corpus, joined "
            "to the qualification plan's own leaf id. Emitting this file "
            "proves nothing on its own: tools/evidence/verify_drivers.py "
            "re-derives every row from the archived bytes with an independent "
            "implementation, and the bundle root binds them."),
        "row_id": f"driver:{args.driver}:{backend}",
        "driver": args.driver,
        "backend": backend,
        "lane": args.lane,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "plan": {"path": common.rel(common.PLAN),
                 "plan_root_declared": plan.get("plan_root"),
                 "plan_root_recomputed": plan_root_recomputed,
                 "sha256": common.sha256_file(common.PLAN)},
        "toolchain": toolchain_versions(),
        "projection_check": proj,
        "upstream_ignore_tags": ignore_tags,
        "build": build,
        "servers": server_records,
        "shared_server": bool(args.shared_server),
        "suites": suite_rows,
        "suite_preconditions": SUITE_PRECONDITIONS,
        "leaves": leaf_rows,
        "counts": {
            "suites_selected": len(selected),
            "suites_executed": sum(1 for r in suite_rows
                                   if r.get("status") == "EXECUTED"),
            "leaf_rows": len(leaf_rows),
            "leaf_rows_in_plan": len(in_plan_leaves),
            "leaf_rows_outside_plan": len(fabricated),
            "plan_leaves_in_scope": len(plan_leaves_in_scope),
            "plan_leaves_with_outcome": len(covered),
            "plan_leaves_passed": len(green),
            "by_status": counts,
        },
        "leaves_outside_plan": fabricated,
        "leaves_outside_plan_note": (
            "these scenarios really executed but the qualification plan has no "
            "row for them: tools/catalog/generate_catalog.py enumerates only "
            "feature files referenced from sources/typedb, and the server does "
            "not reference these. They are reported, never counted as covering "
            "a plan row, and never hidden."),
        "plan_leaves_without_outcome": missing,
        "anomalies": anomalies,
    }
    results_path = out_dir / "driver-results.json"
    results_path.write_text(json.dumps(results, indent=1) + "\n")

    consumed = [results_path, common.PLAN]
    consumed += [REPO / r["raw_log"] for r in suite_rows if r.get("raw_log")]
    consumed += [REPO / r["log"] for r in server_records if r.get("log")]
    root, pairs = common.compute_bundle_root(out_dir, consumed)
    (out_dir / "bundle-manifest.json").write_text(json.dumps(
        {"schema": "driver-lane-bundle-manifest-v1", "bundle_root": root,
         "files": dict(sorted(pairs.items()))}, indent=1) + "\n")

    green_run = not anomalies and covered and len(covered) == len(green)
    verdict = {
        "green": bool(green_run),
        "policy_verdict": "GREEN" if green_run else "RED",
        "row_id": results["row_id"],
        "bundle_root": root,
        "plan_root": plan.get("plan_root"),
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        "observation": {
            "suites_selected": len(selected),
            "suites_executed": results["counts"]["suites_executed"],
            "plan_leaves_in_scope": len(plan_leaves_in_scope),
            "plan_leaves_with_outcome": len(covered),
            "plan_leaves_passed": len(green),
            "leaf_status_counts": counts,
        },
        "statement": (
            "GREEN here means: every selected suite executed, every plan leaf "
            "in scope produced a leaf outcome, no anomaly was raised, and every "
            "one of those leaves passed. It says nothing about the plan rows "
            "this lane does not cover."),
    }
    (out_dir / "verdict.json").write_text(json.dumps(verdict, indent=1) + "\n")
    marker = out_dir / "COMPLETE"
    if green_run:
        marker.write_text(f"COMPLETE {root}\n")
    elif marker.exists():
        marker.unlink()

    print(json.dumps(verdict, indent=1))
    print(f"DRIVER LANE {results['row_id']} ({args.lane}): "
          f"{results['counts']['suites_executed']}/{len(selected)} suites "
          f"executed, {len(covered)}/{len(plan_leaves_in_scope)} plan leaves "
          f"with a leaf outcome, {len(green)} passed, "
          f"{len(anomalies)} anomaly(ies) -> "
          f"{'GREEN' if green_run else 'RED'}", file=sys.stderr)
    return 0 if green_run else 1


if __name__ == "__main__":
    sys.exit(main())
