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
import os
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
import leaf_common as lc  # noqa: E402

TB = REPO / "sources" / "typedb"
BEHAVIOUR_ROOT = TB / "tests" / "behaviour"
FEATURE_RE = re.compile(
    r'"(?:\.\./typedb_behaviour\+/|bazel-typedb/external/typedb_behaviour\+*/)'
    r'([^"]+\.feature)"'
)
FN_RE = re.compile(r"async fn (\w+)\s*\(")
SCENARIO_RE = re.compile(r"^\s*Scenario(?: Outline)?: (.*)$", re.M)
SUMMARY_RE = re.compile(
    r"^\[Summary\]\s*$\n(?:^(?P<feat>\d+) features?\s*$\n)?"
    r"^(?P<sc>\d+) scenarios? \((?P<scdetail>[^)]*)\)\s*$\n"
    r"^(?P<st>\d+) steps? \((?P<stdetail>[^)]*)\)\s*$",
    re.M,
)


def _norm(case):
    """libtest prints raw identifiers verbatim (`r#type`, `r#match`); the
    source module path spells them the same way, so both sides are compared
    with the `r#` stripped."""
    return "::".join(c[2:] if c.startswith("r#") else c for c in case.split("::"))


def discover_with_src_path(packages=None):
    """Cargo's own view of every test target, INCLUDING its crate root path.

    `run_u0.discover_executables` drops `target.src_path`, and the crate root
    is exactly what turns a libtest case name into a source file: a case is
    `<modules under the crate root>::<fn>`. Asking cargo beats parsing BUILD
    files, because cargo is what actually compiled the binary being run.
    """
    cmd = ["cargo", common.TOOLCHAIN, "test", "--locked", "--no-run", "--message-format", "json"]
    cmd += (
        (["-p", p] for p in [])
        and []
        or ([x for p in (packages or []) for x in ("-p", p)] or ["--workspace"])
    )
    out = subprocess.check_output(
        cmd, cwd=TB, text=True, stderr=subprocess.DEVNULL, env=common.CARGO_ENV
    )
    execs = {}
    for line in out.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-artifact" or not msg.get("executable"):
            continue
        if not msg.get("profile", {}).get("test"):
            continue
        tgt = msg["target"]
        pkg = common.package_name_from_id(msg["package_id"])
        execs[(pkg, tgt["name"])] = {
            "package": pkg,
            "target": tgt["name"],
            "executable": msg["executable"],
            "src_path": tgt.get("src_path"),
            "package_root": str(pathlib.Path(msg["manifest_path"]).parent),
        }
    return execs


def feature_sources():
    """.rs file -> the .feature paths its source literally names."""
    out = {}
    for rs in sorted(BEHAVIOUR_ROOT.rglob("*.rs")):
        txt = rs.read_text(errors="replace")
        feats = sorted(set(FEATURE_RE.findall(txt)))
        if feats:
            out[rs] = feats
    return out


def module_path(src_root, rs):
    """The module path libtest prints for a fn in `rs`, given the crate root.

    Rust modules are named relative to the crate root FILE's directory; the
    crate root itself contributes no component, and `mod.rs` names its
    directory rather than itself. Raw identifiers (`r#type`, `r#match`) print
    verbatim, which is why comparison strips `r#` on both sides (_norm).
    """
    root = pathlib.Path(src_root)
    if rs == root:
        return []
    try:
        rel = rs.relative_to(root.parent)
    except ValueError:
        return None
    parts = list(rel.parts)
    if parts[-1] == "mod.rs":
        parts = parts[:-1]
    else:
        parts[-1] = parts[-1][:-3]
    return parts


def list_cases(executable):
    out = subprocess.run([executable, "--list"], capture_output=True, text=True)
    return [line.split(": test")[0] for line in out.stdout.splitlines() if line.endswith(": test")]


def case_feature_map(execs=None):
    """(runner_row_id, case) -> [feature paths], derived from cargo's crate
    roots and each binary's OWN `--list`. A case that maps to no feature file
    is reported, never silently dropped."""
    execs = execs if execs is not None else discover_with_src_path()
    fsrc = feature_sources()
    mapping, unmapped = {}, []
    for (pkg, tgt), e in sorted(execs.items()):
        root = pathlib.Path(e["package_root"])
        if root != TB and not str(root).startswith(str(BEHAVIOUR_ROOT)):
            continue
        if not e.get("src_path"):
            continue
        src_root = pathlib.Path(e["src_path"])
        if not str(src_root).startswith(str(BEHAVIOUR_ROOT)):
            continue
        by_case = {}
        for rs, feats in fsrc.items():
            mp = module_path(src_root, rs)
            if mp is None:
                continue
            txt = rs.read_text(errors="replace")
            for fn in FN_RE.findall(txt):
                by_case[_norm("::".join(mp + [fn]))] = feats
        for case in list_cases(e["executable"]):
            feats = by_case.get(_norm(case))
            key = (f"{pkg}:{tgt}", case)
            if feats is None:
                unmapped.append({"runner_row_id": key[0], "case": case})
            else:
                mapping[key] = feats
    return mapping, unmapped


def inventory(catalog):
    scen = collections.Counter(
        x["target_id"] for x in catalog["leaf_cases"] if x["kind"] == "CUCUMBER"
    )
    mapping, unmapped = case_feature_map()
    rows = [
        {
            "runner_row_id": rid,
            "case": case,
            "features": feats,
            "catalogued_scenarios": sum(scen.get("cucumber-corpus:" + f, 0) for f in feats),
        }
        for (rid, case), feats in sorted(mapping.items())
    ]
    covered = {f for r in rows for f in r["features"]}
    catalogued = {t.split(":", 1)[1] for t in scen}
    return {
        "behaviour_cases_mapped_to_a_feature": len(rows),
        "behaviour_cases_unmapped": unmapped,
        "catalogued_features": len(scen),
        "catalogued_scenarios": sum(scen.values()),
        "catalogued_features_reachable_via_cargo": len(covered & catalogued),
        "catalogued_scenarios_reachable_via_cargo": sum(
            scen["cucumber-corpus:" + f] for f in (covered & catalogued)
        ),
        "catalogued_features_with_no_cargo_case": sorted(
            "cucumber-corpus:" + f for f in (catalogued - covered)
        ),
        "cases": rows,
    }


def measure(spec, archive, catalog):
    """Execute ONE behaviour libtest case with per-scenario output captured."""
    rid, _, case = spec.partition("::")
    pkg, _, tgt = rid.partition(":")
    execs = discover_with_src_path()
    e = execs[(pkg, tgt)]
    archive = pathlib.Path(archive)
    archive = archive if archive.is_absolute() else REPO / archive
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
        rc = subprocess.call(
            argv, cwd=e.get("package_root") or TB, env=env, stdout=f, stderr=subprocess.STDOUT
        )
    dur = time.time() - t0
    text = log.read_text(errors="replace")
    names = SCENARIO_RE.findall(text)
    m = SUMMARY_RE.search(text)
    counts = common.parse_libtest_counts(text)
    mapping, _unmapped = case_feature_map(execs)
    feats = mapping.get((rid, case))
    cat = [
        x["display_name"]
        for x in catalog["leaf_cases"]
        if x["kind"] == "CUCUMBER"
        and x["target_id"] in {"cucumber-corpus:" + f for f in (feats or [])}
    ]
    exact = sorted(set(names) & set(cat))
    outline_templates = sorted(
        {re.sub(r" \[example \d+/\d+\]$", "", n) for n in set(cat) - set(names)}
    )
    summary = None
    if m:
        summary = {
            "features": int(m.group("feat") or 0),
            "scenarios": int(m.group("sc")),
            "scenario_detail": m.group("scdetail"),
            "steps": int(m.group("st")),
            "step_detail": m.group("stdetail"),
        }
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
        "reconciles": bool(
            summary and summary["scenarios"] == len(names) and len(names) == len(cat)
        ),
        "names_matching_catalogue_exactly": len(exact),
        "names_not_matching": len(names) - len(exact),
        "catalogue_names_not_observed": len(set(cat) - set(names)),
        "unobserved_catalogue_name_templates": outline_templates[:10],
        "scenarios_per_second": round(len(names) / dur, 3) if dur else None,
    }


def costing(catalog, inv, measurements, lane_bundles, cores):
    """What a full cucumber leaf lane costs, from MEASURED rates and from the
    behaviour targets' own archived durations - never from a guess.

    Two numbers, because two architectures are on the table:

      serial_per_lane   - every scenario one after another, the shape of the
                          `--exact --nocapture --test-threads 1` measurement
                          that produced the rate;
      parallel_per_lane - one PROCESS per libtest case (each case is exactly
                          one feature file, so each process writes a log that
                          needs no de-interleaving), `cores` at a time. Greedy
                          longest-first packing over the per-case scenario
                          counts at the same measured rate; the makespan is
                          bounded below by the single longest case, which is
                          reported separately because no core count beats it.
    """
    rates = [
        m["scenarios_per_second"]
        for m in measurements
        if m.get("reconciles") and m.get("scenarios_per_second")
    ]
    rate = min(rates) if rates else None
    per_case = sorted(
        (r["catalogued_scenarios"] for r in inv["cases"] if r["catalogued_scenarios"]), reverse=True
    )
    total = inv["catalogued_scenarios_reachable_via_cargo"]
    out = {
        "measured_rate_scenarios_per_second": rate,
        "rate_basis": [
            {
                "case": m["command"].split()[1],
                "scenarios": m["scenario_lines_parsed"],
                "wall_seconds": m["wall_seconds"],
                "rate": m["scenarios_per_second"],
            }
            for m in measurements
        ],
        "catalogued_scenarios": inv["catalogued_scenarios"],
        "scenarios_reachable_via_cargo": total,
        "cores_assumed": cores,
    }
    if rate:
        bins = [0.0] * cores
        for n in per_case:
            i = bins.index(min(bins))
            bins[i] += n / rate
        out["serial_seconds_per_lane"] = round(total / rate)
        out["parallel_seconds_per_lane"] = round(max(bins))
        out["longest_single_case_seconds"] = round(per_case[0] / rate) if per_case else 0
        out["longest_single_case_scenarios"] = per_case[0] if per_case else 0
    lanes = []
    for d in lane_bundles:
        b = json.loads((REPO / d / "leaf-results.json").read_text())
        cases = {r["runner_row_id"] for r in inv["cases"]}
        secs = sum(t["duration_seconds"] for t in b["targets"] if t["runner_row_id"] in cases)
        lanes.append(
            {
                "bundle": d,
                "profile": b["profile"],
                "behaviour_target_seconds_as_archived": round(secs, 1),
                "note": "measured in THIS repository's own archived lane "
                "run, with libtest's default per-case parallelism "
                "inside each target",
            }
        )
    out["archived_lane_behaviour_cost"] = lanes
    out["plan_rows_this_would_cover"] = {
        "rows_per_profile": inv["catalogued_scenarios"],
        "profiles_runnable_here": ["U1", "U2"],
        "profiles_not_runnable_here": {
            "U0": "requires the PRISTINE upstream checkout; the fork must be "
            "unstaged (tools/fork/stage.py --restore), which would break "
            "every other build in flight on this machine",
            "U3": 'storage factory refuses: ProfileUnavailable { profile: "U3" }',
            "U4": 'storage factory refuses: ProfileUnavailable { profile: "U4" }',
        },
        "rows_reachable_here": 2 * inv["catalogued_scenarios"],
        "rows_in_plan": 5 * inv["catalogued_scenarios"],
    }
    return out


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--inventory", action="store_true")
    ap.add_argument(
        "--measure", action="append", default=[], help="<pkg>:<target>::<libtest case> to execute"
    )
    ap.add_argument("--archive", default="docs/evidence/G3/leaf/cucumber-probe")
    ap.add_argument(
        "--lane-bundle",
        action="append",
        default=[],
        help="a sealed leaf bundle whose behaviour-target durations "
        "give the archived cost of the same work (repeatable)",
    )
    ap.add_argument("--cores", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--out", type=pathlib.Path, default=None)
    args = ap.parse_args()
    catalog = json.loads(lc.CATALOG.read_text())
    report = {
        "schema": "typedb-r2-cucumber-feasibility-v1",
        "toolchain": lc.measured_toolchain(),
        "executed_tree": lc.executed_tree_identity(),
        "catalog_sha256": common.sha256_file(lc.CATALOG),
        "plan_root": json.loads(lc.PLAN.read_text()).get("plan_root"),
    }
    if args.inventory:
        report["inventory"] = inventory(catalog)
    if args.measure:
        report["measurements"] = [measure(s, args.archive, catalog) for s in args.measure]
    if args.inventory and args.measure:
        report["costing"] = costing(
            catalog, report["inventory"], report["measurements"], args.lane_bundle, args.cores
        )
    print(json.dumps(report, indent=1))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
