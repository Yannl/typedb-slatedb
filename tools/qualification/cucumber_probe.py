#!/usr/bin/env python3
"""Feasibility, by EXECUTION, of leaf-granularity evidence for the 20,495
cucumber plan rows.

The plan's largest family is CUCUMBER: 4,099 scenarios x 5 profiles = 20,495
rows, every one of them UNCOVERED because "no leaf-level runner lane has
produced archived evidence". This tool answers - by running things, not by
reading code - the four questions that decide whether such a lane is
buildable, and at what cost:

  1. Do the behaviour scenarios execute here through cargo at all, and is
     every catalogued feature file reachable from a cargo test target?
  2. Can PER-SCENARIO outcomes be captured from a real run, and reconciled
     against a count the runtime itself prints (the way libtest leaf
     outcomes are reconciled against `test result:`)?
  3. Do the runtime's scenario names JOIN to the catalogue's leaf ids?
  4. What does a full 20,495-row run cost in wall clock?

What it does:
  * enumerates every behaviour cargo target's libtest cases with `--list`
    (authoritative, not inferred), and maps each case to the .feature file
    its source names;
  * optionally EXECUTES one case with `--exact --nocapture`, archives the
    raw log, and parses (a) every `Scenario:` / `Scenario Outline:` name and
    (b) the cucumber `[Summary]` block, then reconciles the two;
  * joins the observed scenario names against the catalogue's CUCUMBER leaf
    display names for that feature and reports the exact-match rate and what
    the mismatches are;
  * costs the full corpus from measured scenarios-per-second.

Usage:
  python3 tools/qualification/cucumber_probe.py --inventory --out FILE.json
  python3 tools/qualification/cucumber_probe.py --measure <pkg:target::case> \\
      --archive DIR --out FILE.json
"""
import argparse
import collections
import json
import pathlib
import re
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "tools" / "catalog"))
import common  # noqa: E402
import run_u0  # noqa: E402
import leaf_common as lc  # noqa: E402

TB = REPO / "sources" / "typedb"
BEHAVIOUR_ROOT = TB / "tests" / "behaviour"
FEATURE_RE = re.compile(
    r'"(?:\.\./typedb_behaviour\+/|bazel-typedb/external/typedb_behaviour\+*/)'
    r'([^"]+\.feature)"')
FN_RE = re.compile(r"async fn (\w+)\s*\(")
SCENARIO_RE = re.compile(r"^\s*Scenario(?: Outline)?: (.*)$", re.M)
SUMMARY_RE = re.compile(
    r"^\[Summary\]\s*$\n(?:^(?P<feat>\d+) features?\s*$\n)?"
    r"^(?P<sc>\d+) scenarios? \((?P<scdetail>[^)]*)\)\s*$\n"
    r"^(?P<st>\d+) steps? \((?P<stdetail>[^)]*)\)\s*$", re.M)


def source_index():
    """(module-path suffix, fn name) -> feature path, from the behaviour
    sources. Only files that literally name a .feature path are indexed, so
    nothing is inferred about a test that does not read a feature."""
    idx = {}
    for rs in sorted(BEHAVIOUR_ROOT.rglob("*.rs")):
        txt = rs.read_text(errors="replace")
        feats = FEATURE_RE.findall(txt)
        if not feats:
            continue
        fns = FN_RE.findall(txt)
        rel = rs.relative_to(BEHAVIOUR_ROOT)
        # module path as libtest prints it: directories under the target's
        # crate root, then the file stem, then the fn; `r#type` prints `type`
        mods = [p for p in rel.parts[1:-1]] + [rel.stem]
        mods = [m.lstrip("r#") for m in mods if m != "mod"]
        for fn in fns:
            idx[("::".join(mods + [fn]), rs)] = sorted(set(feats))
    return idx


def list_cases(executable):
    out = subprocess.run([executable, "--list"], capture_output=True, text=True)
    return [l.split(": test")[0] for l in out.stdout.splitlines()
            if l.endswith(": test")]


def inventory(catalog):
    scen = collections.Counter(x["target_id"] for x in catalog["leaf_cases"]
                               if x["kind"] == "CUCUMBER")
    src = source_index()
    execs = run_u0.discover_executables(None)
    rows, unmapped = [], []
    for e in execs:
        root = pathlib.Path(e.get("package_root") or TB)
        if root != TB and not str(root).startswith(str(BEHAVIOUR_ROOT)):
            continue
        cases = list_cases(e["executable"])
        if not cases:
            continue
        for case in cases:
            feats = None
            for (suffix, _rs), f in src.items():
                if case == suffix or case.endswith("::" + suffix):
                    feats = f
                    break
            if feats is None:
                continue
            rows.append({
                "runner_row_id": f"{e['package']}:{e['target']}",
                "case": case,
                "features": feats,
                "catalogued_scenarios": sum(
                    scen.get("cucumber-corpus:" + f, 0) for f in feats),
            })
    covered_features = {f for r in rows for f in r["features"]}
    missing = sorted(t for t in scen
                     if t.split(":", 1)[1] not in covered_features)
    return {
        "behaviour_cases": len(rows),
        "catalogued_features": len(scen),
        "catalogued_scenarios": sum(scen.values()),
        "features_reachable_via_cargo": len(covered_features & {
            t.split(":", 1)[1] for t in scen}),
        "catalogued_features_with_no_cargo_case": missing,
        "cases": sorted(rows, key=lambda r: (r["runner_row_id"], r["case"])),
    }


def measure(spec, archive, catalog):
    """Execute ONE behaviour libtest case with per-scenario output captured."""
    rid, _, case = spec.partition("::")
    pkg, _, tgt = rid.partition(":")
    execs = run_u0.discover_executables([pkg])
    e = next(x for x in execs if x["package"] == pkg and x["target"] == tgt)
    archive = pathlib.Path(archive)
    archive.mkdir(parents=True, exist_ok=True)
    log = archive / f"{pkg}__{tgt}__{case.replace('::', '_')}.log"
    env = dict(common.CARGO_ENV)
    env["TYPEDB_STORAGE_PROFILE"] = "U1"
    env["RUST_MIN_STACK"] = str(64 * 1024 * 1024)
    tmp = pathlib.Path("/tmp/cukeprobe") / case.replace("::", "_")[:40]
    tmp.mkdir(parents=True, exist_ok=True)
    env["TMPDIR"] = str(tmp)
    argv = [e["executable"], case, "--exact", "--nocapture", "--test-threads", "1"]
    t0 = time.time()
    with open(log, "wb") as f:
        rc = subprocess.call(argv, cwd=e.get("package_root") or TB, env=env,
                             stdout=f, stderr=subprocess.STDOUT)
    dur = time.time() - t0
    text = log.read_text(errors="replace")
    names = SCENARIO_RE.findall(text)
    m = SUMMARY_RE.search(text)
    counts = common.parse_libtest_counts(text)
    src = source_index()
    feats = None
    for (suffix, _rs), f in src.items():
        if case == suffix or case.endswith("::" + suffix):
            feats = f
            break
    cat = [x["display_name"] for x in catalog["leaf_cases"]
           if x["kind"] == "CUCUMBER"
           and x["target_id"] in {"cucumber-corpus:" + f for f in (feats or [])}]
    exact = sorted(set(names) & set(cat))
    outline_templates = sorted({re.sub(r" \[example \d+/\d+\]$", "", n)
                                for n in set(cat) - set(names)})
    summary = None
    if m:
        summary = {"features": int(m.group("feat") or 0),
                   "scenarios": int(m.group("sc")),
                   "scenario_detail": m.group("scdetail"),
                   "steps": int(m.group("st")),
                   "step_detail": m.group("stdetail")}
    return {
        "command": " ".join(argv),
        "cwd": str(pathlib.Path(e.get("package_root") or TB).relative_to(REPO)),
        "env": {"TYPEDB_STORAGE_PROFILE": "U1", "RUST_MIN_STACK": env["RUST_MIN_STACK"]},
        "exit_code": rc,
        "wall_seconds": round(dur, 2),
        "raw_log": str(log.relative_to(REPO)),
        "log_sha256": common.sha256_file(log),
        "libtest_counts": counts,
        "features": feats,
        "cucumber_summary": summary,
        "scenario_lines_parsed": len(names),
        "catalogued_scenarios_for_these_features": len(cat),
        "reconciles": bool(summary and summary["scenarios"] == len(names)
                           and len(names) == len(cat)),
        "names_matching_catalogue_exactly": len(exact),
        "names_not_matching": len(names) - len(exact),
        "catalogue_names_not_observed": len(set(cat) - set(names)),
        "unobserved_catalogue_name_templates": outline_templates[:10],
        "scenarios_per_second": round(len(names) / dur, 3) if dur else None,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--inventory", action="store_true")
    ap.add_argument("--measure", action="append", default=[],
                    help="<pkg>:<target>::<libtest case> to execute")
    ap.add_argument("--archive", default="docs/evidence/G3/leaf/cucumber-probe")
    ap.add_argument("--out", type=pathlib.Path, default=None)
    args = ap.parse_args()
    catalog = json.loads(lc.CATALOG.read_text())
    report = {"schema": "typedb-r2-cucumber-feasibility-v1",
              "toolchain": lc.measured_toolchain(),
              "executed_tree": lc.executed_tree_identity(),
              "catalog_sha256": common.sha256_file(lc.CATALOG),
              "plan_root": json.loads(lc.PLAN.read_text()).get("plan_root")}
    if args.inventory:
        report["inventory"] = inventory(catalog)
    if args.measure:
        report["measurements"] = [measure(s, args.archive, catalog)
                                  for s in args.measure]
    print(json.dumps(report, indent=1))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
