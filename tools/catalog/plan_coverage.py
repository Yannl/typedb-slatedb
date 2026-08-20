#!/usr/bin/env python3
"""E-02 result side: join execution evidence onto the v2 qualification plan.

This tool answers ONE question exactly: of the plan's (leaf, profile,
fixture-set, toolchain) rows, how many have execution evidence, at what
granularity, and how many have none. It is a COVERAGE report, never a
verdict: pass/fail adjudication of the evidence itself belongs to
verdict.py / tools/evidence/verify_all.py, and even full coverage here
would say nothing about greenness.

Honesty rules, all deliberate:

  - the existing evidence records AGGREGATE cargo target rows (libtest
    summary counts), never individual leaf outcomes, so a cargo-family leaf
    row is AT BEST 'PARTIAL' (its target ran in the right lane) and is
    NEVER counted as covered;
  - evidence taken under a profile the plan does not require (the archived
    U2S3 lane - a historical, dirty-tree experimental run) covers NOTHING;
    it is reported separately as other-lane evidence, not folded in;
  - evidence rows whose target_id is in the broken pre-fix '0.0.0:<target>'
    id space cannot be joined without guessing and are reported as
    UNJOINABLE, contributing nothing (guessed joins are how denominators
    silently shrink);
  - a zero-case evidence row for a leaf-bearing target is VACUOUS evidence
    and covers nothing (a binary that ran nothing proves nothing about its
    leaves); zero-case targets are legitimate ONLY as predeclared plan
    exclusion rows;
  - CUCUMBER / STATIC_CHECK / SCRIPT leaves have no leaf-level runner
    lanes producing archived evidence at all: UNCOVERED, stated as such;
  - driver namespace rows (E-05) are NOT_IMPLEMENTED until an
    official-driver harness has actually EXECUTED their suite. That harness
    now exists for the Rust driver (tools/drivers/run_rust_behaviour.py), so
    a driver row's status is read from the RESULT-side ledger
    docs/evidence/G1/drivers/driver-row-status.json - never from the plan,
    which is the immutable denominator and whose body feeds plan_root. The
    ledger is not trusted either: this reporter RE-DERIVES the bundle seal
    (every file the sidecar manifest names is re-hashed here, the root is
    recomputed, and the COMPLETE marker and the verdict must both bind that
    exact root) before it will honour any status other than
    NOT_IMPLEMENTED. A row whose suite set was only partly executable is
    PARTIAL and names the blocked suites' preconditions - never covered;
  - the terminal line always states the plan is NOT SATISFIED unless every
    row is covered-at-leaf-granularity or excluded - which today none are.

Exit code: 0 only if the plan is satisfied (it is not); 1 otherwise. The
nonzero exit is the machine-readable honest statement of E-02.

Usage:
  python3 tools/catalog/plan_coverage.py
  python3 tools/catalog/plan_coverage.py --evidence DIR [--evidence DIR ...]
  python3 tools/catalog/plan_coverage.py --out docs/evidence/G1/plan-coverage-v2.json
"""
import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import common  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[2]


def common_rel(p):
    try:
        return pathlib.Path(p).resolve().relative_to(REPO).as_posix()
    except ValueError:
        return str(p)

PLAN = REPO / "docs" / "evidence" / "G1" / "qualification-plan-v2.json"
CATALOG = REPO / "docs" / "evidence" / "G1" / "upstream-test-catalog.json"
DEFAULT_EVIDENCE = [
    "docs/evidence/G1/u0-results-pass1",
    "docs/evidence/G1/u0-results-pass2-fixedenv",
    "docs/evidence/G3/u2s3-full-3",
]


def load_evidence(dirs, plan_profiles):
    """Index the evidence bundles by (plan_profile, 'pkg:target').

    Returns (same_lane, other_lane, notes) where same_lane maps
    (profile_id, rid) -> [evidence refs] for profiles the plan requires,
    other_lane maps rid -> [refs] for evidence under any other lane, and
    notes carries per-bundle honesty annotations (unjoinable rows, dirty
    trees, historical classification).
    """
    same_lane, other_lane, notes = {}, {}, []
    for d in dirs:
        d = pathlib.Path(d)
        rf = (d if d.is_absolute() else REPO / d) / "u0-results.json"
        if not rf.is_file():
            notes.append({"bundle": str(d), "error": "no u0-results.json"})
            continue
        data = json.loads(rf.read_text())
        profile = data.get("profile")
        rows = data["results"]
        unjoinable = [r["target_id"] for r in rows
                      if r["target_id"].startswith("0.0.0:")]
        trees = [t for t in
                 ([((r.get("run") or {}).get("executed_tree")) for r in rows]
                  + [(data.get("last_write_run") or {}).get("executed_tree")])
                 if t]
        # unknown provenance must never read as clean: dirty_tree is True,
        # False, or None (= the bundle predates tree recording entirely)
        dirty = any(t.get("dirty") for t in trees) if trees else None
        note = {
            "bundle": str(d),
            "profile": profile,
            "rows": len(rows),
            "profile_in_plan": profile in plan_profiles,
            "tree_provenance": "recorded" if trees else "UNRECORDED",
            "dirty_tree": dirty,
            "unjoinable_rows": len(unjoinable),
        }
        if not trees:
            note["provenance_note"] = (
                "this bundle records no executed-tree identity at all; "
                "'dirty_tree: null' means UNKNOWN, never clean")
        if unjoinable:
            note["unjoinable_reason"] = (
                "target ids in the broken pre-fix '0.0.0:<target>' id space "
                "cannot be joined to catalogue targets without guessing; "
                "they contribute NOTHING to coverage")
        if profile not in plan_profiles:
            note["lane_note"] = (
                f"profile {profile!r} is not a plan profile; this bundle's "
                f"rows are other-lane evidence and cover no plan row")
        notes.append(note)
        for r in rows:
            rid = r["target_id"]
            if rid.startswith("0.0.0:"):
                continue
            cases = (r.get("passed", 0) + r.get("failed", 0)
                     + r.get("ignored", 0) + r.get("measured", 0))
            ref = {"bundle": str(d), "profile": profile, "cases": cases,
                   "exit_code": r.get("exit_code"), "dirty_tree": dirty}
            if profile in plan_profiles:
                same_lane.setdefault((profile, rid), []).append(ref)
            else:
                other_lane.setdefault(rid, []).append(ref)
    return same_lane, other_lane, notes


DRIVER_STATUS = (REPO / "docs" / "evidence" / "G1" / "drivers"
                 / "driver-row-status.json")


def _sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def driver_row_status(plan):
    """row_id -> (status, reason). NOT_IMPLEMENTED unless a sealed, verified
    driver-lane bundle re-derives here.

    The seal is recomputed from the BYTES: every file the bundle's sidecar
    manifest names is re-hashed now, the root is recomputed over the same
    documented `rel\0sha\n` algorithm the rest of the chain uses, and the
    COMPLETE marker, the verdict and the ledger must all bind that same root.
    A ledger that merely asserts a status buys nothing.
    """
    import hashlib
    out = {}
    for dr in plan["driver_rows"]:
        out[dr["row_id"]] = ("NOT_IMPLEMENTED", dr.get("reason", ""))
    if not DRIVER_STATUS.is_file():
        return out
    try:
        ledger = json.loads(DRIVER_STATUS.read_text())
    except json.JSONDecodeError as e:
        return {k: ("NOT_IMPLEMENTED",
                    f"driver row status ledger does not parse: {e}")
                for k in out}
    if ledger.get("schema") != "typedb-r2-driver-row-status-v1":
        return {k: ("NOT_IMPLEMENTED",
                    f"driver row status ledger has unexpected schema "
                    f"{ledger.get('schema')!r}") for k in out}
    for row_id, entry in (ledger.get("rows") or {}).items():
        if row_id not in out:
            continue
        status = entry.get("status", "NOT_IMPLEMENTED")
        if status == "NOT_IMPLEMENTED":
            out[row_id] = ("NOT_IMPLEMENTED",
                           entry.get("blocked_precondition")
                           or "no precondition recorded")
            continue
        bdir = entry.get("evidence_bundle")
        problem = None
        if not bdir:
            problem = "ledger claims execution but names no evidence bundle"
        else:
            b = REPO / bdir
            man = b / "bundle-manifest.json"
            if not man.is_file():
                problem = f"{bdir}: no bundle-manifest.json"
            else:
                m = json.loads(man.read_text())
                pairs, missing, changed = {}, [], []
                for rel, sha in (m.get("files") or {}).items():
                    f = (b / rel[len("<out>/"):]) if rel.startswith("<out>/") \
                        else (REPO / rel)
                    if not f.is_file():
                        # bundles verify wherever they are checked out
                        alt = b / pathlib.Path(rel).name
                        f = alt if alt.is_file() else f
                    if not f.is_file():
                        missing.append(rel)
                        continue
                    got = _sha256_file(f)
                    pairs[rel] = got
                    if got != sha:
                        changed.append(rel)
                h = hashlib.sha256()
                for rel in sorted(pairs):
                    h.update(rel.encode() + b"\0" + pairs[rel].encode() + b"\n")
                root = h.hexdigest()
                marker = b / "COMPLETE"
                verdict = b / "verdict.json"
                if missing:
                    problem = (f"{bdir}: {len(missing)} file(s) the manifest "
                               f"names are absent, e.g. {missing[:2]}")
                elif changed:
                    problem = (f"{bdir}: {len(changed)} consumed file(s) no "
                               f"longer hash to the manifest, e.g. {changed[:2]}")
                elif root != m.get("bundle_root"):
                    problem = (f"{bdir}: recomputed root {root} != manifest "
                               f"root {m.get('bundle_root')}")
                elif not marker.is_file():
                    problem = f"{bdir}: no COMPLETE marker - never sealed green"
                elif marker.read_text().strip() != f"COMPLETE {root}":
                    problem = (f"{bdir}: COMPLETE does not bind the recomputed "
                               f"root {root}")
                elif not verdict.is_file():
                    problem = f"{bdir}: no verdict.json"
                else:
                    v = json.loads(verdict.read_text())
                    if v.get("policy_verdict") != "GREEN":
                        problem = (f"{bdir}: verdict is "
                                   f"{v.get('policy_verdict')!r}")
                    elif v.get("bundle_root") != root:
                        problem = (f"{bdir}: verdict binds root "
                                   f"{v.get('bundle_root')}, not {root}")
                    elif entry.get("bundle_root") != root:
                        problem = (f"{bdir}: ledger records root "
                                   f"{entry.get('bundle_root')}, not {root}")
        if problem:
            out[row_id] = ("NOT_IMPLEMENTED",
                           f"driver row status claimed {status} but the seal "
                           f"does not re-derive: {problem}")
            continue
        klass = entry.get("coverage_class")
        if klass == "COVERED":
            out[row_id] = ("COVERED",
                           f"official driver suite executed at leaf "
                           f"granularity; {entry.get('plan_leaves_with_outcome')} "
                           f"plan leaves carry a per-scenario outcome "
                           f"({bdir})")
        else:
            blocked = dict(entry.get("suites_blocked") or {})
            for c in (entry.get("caveats") or []):
                blocked[f"caveat:{c.get('id')}"] = c.get("detail")
            out[row_id] = ("PARTIAL",
                           f"official driver suite executed at leaf "
                           f"granularity for "
                           f"{entry.get('suites_executed')}/"
                           f"{entry.get('suites_selected')} suites "
                           f"({entry.get('plan_leaves_with_outcome')} plan "
                           f"leaves with a per-scenario outcome); blocked: "
                           + "; ".join(f"{k}: {v}" for k, v in blocked.items()))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--plan", type=pathlib.Path, default=PLAN)
    ap.add_argument("--catalog", type=pathlib.Path, default=CATALOG)
    ap.add_argument("--evidence", action="append", default=None,
                    help="results dir (repeatable); default: the three "
                         "committed bundles")
    ap.add_argument("--out", type=pathlib.Path, default=None,
                    help="also write the JSON report here")
    args = ap.parse_args()

    plan = json.loads(args.plan.read_text())
    catalog = json.loads(args.catalog.read_text())
    plan_profiles = set(plan["profiles"])
    targets = {t["target_id"]: t for t in catalog["targets"]}

    same_lane, other_lane, notes = load_evidence(
        args.evidence or DEFAULT_EVIDENCE, plan_profiles)

    def runner_rid(target_id):
        # the one shared join (common.runner_row_id) so this reporter's
        # denominator cannot skew from the collision-guarded producer's
        return common.runner_row_id(targets.get(target_id))

    leaves = plan["leaves"]
    counts = {}   # (family, status) -> n
    uncovered_reasons = {}
    partial_examples = []
    for leaf_id, profile_id, _fs, _tc in plan["rows"]:
        leaf = leaves[leaf_id]
        kind = leaf["kind"]
        rid = runner_rid(leaf["target_id"])
        if rid is None:
            family = {"CUCUMBER": "cucumber", "STATIC_CHECK": "static",
                      "SCRIPT": "script"}.get(kind, kind.lower())
            status = "UNCOVERED"
            reason = "no leaf-level runner lane has produced archived evidence"
        else:
            family = "cargo-" + kind.lower()
            refs = same_lane.get((profile_id, rid), [])
            live = [r for r in refs if r["cases"] > 0]
            vacuous = [r for r in refs if r["cases"] == 0]
            if live:
                # target-granularity evidence in the required lane: the
                # binary ran, but no leaf-level outcome exists -> PARTIAL,
                # NEVER covered
                status, reason = "PARTIAL", None
                if len(partial_examples) < 3:
                    partial_examples.append(
                        {"row": [leaf_id, profile_id], "evidence": live[:1]})
            elif vacuous:
                status = "UNCOVERED"
                reason = ("only zero-case (vacuous) evidence exists for the "
                          "target in this lane - a binary that ran nothing "
                          "proves nothing about its leaves")
            elif rid in other_lane:
                status = "UNCOVERED"
                reason = ("target evidence exists ONLY under a lane the plan "
                          "does not require (historical U2S3 dirty-tree "
                          "archive) - other-lane evidence covers no plan row")
            else:
                status = "UNCOVERED"
                reason = "no execution evidence for the target in any lane"
        counts[(family, status)] = counts.get((family, status), 0) + 1
        if reason:
            key = (family, reason)
            uncovered_reasons[key] = uncovered_reasons.get(key, 0) + 1

    driver_status = driver_row_status(plan)
    driver_rows_report = []
    for dr in plan["driver_rows"]:
        status, reason = driver_status[dr["row_id"]]
        counts[("driver", status)] = counts.get(("driver", status), 0) + 1
        driver_rows_report.append({"row_id": dr["row_id"], "status": status,
                                   "reason": reason})
        if status != "COVERED":
            key = ("driver", reason)
            uncovered_reasons[key] = uncovered_reasons.get(key, 0) + 1

    total_rows = len(plan["rows"]) + len(plan["driver_rows"])
    # cargo/cucumber/static/script rows: covered is 0 by construction - no
    # leaf-granularity evidence exists for them. Driver rows are the only
    # rows that can be covered today, and only through a bundle whose seal
    # re-derived above.
    covered = sum(n for (f, s), n in counts.items() if s == "COVERED")
    partial = sum(n for (f, s), n in counts.items() if s == "PARTIAL")
    uncovered = sum(n for (f, s), n in counts.items()
                    if s in ("UNCOVERED", "NOT_IMPLEMENTED"))

    by_family = {}
    for (family, status), n in sorted(counts.items()):
        by_family.setdefault(family, {})[status] = n

    report = {
        "schema": "plan-coverage-v2",
        "plan_root": plan.get("plan_root"),
        "plan_rows": len(plan["rows"]),
        "driver_rows": len(plan["driver_rows"]),
        "exclusion_rows": len(plan["exclusions"]),
        "total_denominator_rows": total_rows,
        "covered_rows": covered,
        "partial_rows": partial,
        "uncovered_rows": uncovered,
        "by_family": by_family,
        "uncovered_reasons": [
            {"family": f, "reason": r, "rows": n}
            for (f, r), n in sorted(uncovered_reasons.items())],
        "partial_examples": partial_examples,
        "evidence_bundles": notes,
        "driver_rows_detail": driver_rows_report,
        "driver_row_status_ledger": common_rel(DRIVER_STATUS),
        "partial_meaning": (
            "PARTIAL (cargo families) = the leaf's cargo target produced an "
            "aggregate libtest row in the required lane; the individual leaf "
            "outcome was never recorded. PARTIAL (driver family) = the "
            "official driver suite really executed at leaf granularity and "
            "its seal re-derived here, but at least one declared suite of "
            "that driver's official corpus could not run in this environment "
            "and names its exact external precondition. PARTIAL rows are NOT "
            "covered in either family."),
        "plan_satisfied": False,
        "statement": (
            f"THE PLAN IS NOT SATISFIED. {covered} of {total_rows} denominator "
            f"rows are covered at leaf granularity; {partial} are PARTIAL "
            f"(target-granularity aggregate evidence only); "
            f"{uncovered} are uncovered (including "
            f"{counts.get(('driver', 'NOT_IMPLEMENTED'), 0)} NOT_IMPLEMENTED "
            f"official-driver rows required by v17-A17.5; "
            f"{counts.get(('driver', 'COVERED'), 0)} driver row(s) are covered "
            f"and {counts.get(('driver', 'PARTIAL'), 0)} partial on executed, "
            f"independently re-derived leaf evidence). The plan is the "
            f"denominator of qualification, not a pass, and no claim of "
            f"qualification may cite this report as green."),
    }
    print(json.dumps(report, indent=1))
    if args.out:
        args.out.write_text(json.dumps(report, indent=1) + "\n")
    print(f"PLAN COVERAGE: {covered} covered / {partial} partial / "
          f"{uncovered} uncovered of {total_rows} rows -> NOT SATISFIED",
          file=sys.stderr)
    return 0 if (covered + 0 == total_rows) else 1


if __name__ == "__main__":
    sys.exit(main())
