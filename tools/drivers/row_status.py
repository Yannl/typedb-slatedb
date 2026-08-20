#!/usr/bin/env python3
"""Result-side status ledger for the plan's six official-driver rows.

Why the status does NOT live in the plan
----------------------------------------
docs/evidence/G1/qualification-plan-v2.json states of itself: "The plan is
immutable per plan_root: verdicts pin plan_root and any silent edit is a root
mismatch." That is not decoration. docs/evidence/G3/u2s3-full-3/verdict.json
pins plan_root 72020aa0...; tools/evidence/verify_all.py check 8 recomputes
the plan root from the plan's own canonical body and compares. Editing the
`driver_rows[].status` field would change the plan body and therefore the
plan root (measured: 72020aa0... -> 5b6fd968...), turning an archived, sealed,
green bundle red for a reason that has nothing to do with its bytes.

The plan is the DENOMINATOR; execution outcomes belong to the result side.
This tool is the result side for the driver namespace: it records, per row,
either an EXECUTED status backed by a bundle the INDEPENDENT verifier
(tools/evidence/verify_drivers.py) accepts, or NOT_IMPLEMENTED with the exact
external precondition that blocks it. tools/catalog/plan_coverage.py consumes
this ledger and re-checks the seal itself before honouring any row.

A row can only leave NOT_IMPLEMENTED here if a bundle for it exists, the
independent verifier returns zero anomalies, its COMPLETE marker binds the
recomputed root, and the bundle carries at least one plan leaf with a real
leaf outcome. Nothing in this file is taken on trust from the runner.

Usage:
  python3 tools/drivers/row_status.py --out docs/evidence/G1/drivers/driver-row-status.json
"""
import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "evidence"))
import common               # noqa: E402
import verify_drivers       # noqa: E402

REPO = common.REPO
DRIVERS_DIR = REPO / "docs" / "evidence" / "G1" / "drivers"
BLOCKED = REPO / "docs" / "evidence" / "G1" / "drivers" / "blocked-lanes.json"
ALL_ROWS = [f"driver:{d}:{b}" for d in ("rust", "python", "typescript")
            for b in ("rocksdb", "slatedb")]


def discover_bundles():
    out = {}
    for rf in sorted(DRIVERS_DIR.glob("*/driver-results.json")):
        try:
            data = json.loads(rf.read_text())
        except json.JSONDecodeError:
            continue
        if data.get("schema") != "typedb-r2-driver-lane-v1":
            continue
        out.setdefault(data.get("row_id"), []).append((rf.parent, data))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=pathlib.Path,
                    default=DRIVERS_DIR / "driver-row-status.json")
    args = ap.parse_args()

    plan = json.loads(common.PLAN.read_text())
    plan_rows = {r["row_id"]: r for r in plan["driver_rows"]}
    blocked = json.loads(BLOCKED.read_text()) if BLOCKED.is_file() else {}
    bundles = discover_bundles()

    rows = {}
    for row_id in ALL_ROWS:
        seed = plan_rows.get(row_id, {})
        entry = {
            "row_id": row_id,
            "plan_seed_status": seed.get("status"),
            "required_by": seed.get("required_by"),
            "status": "NOT_IMPLEMENTED",
            "coverage_class": "NOT_IMPLEMENTED",
        }
        found = bundles.get(row_id) or []
        if not found:
            b = blocked.get(row_id) or {}
            entry["blocked_precondition"] = b.get("precondition") or (
                "no evidence bundle exists for this row and no executed probe "
                "has recorded why - the row stays NOT_IMPLEMENTED")
            entry["blocked_evidence"] = b.get("evidence")
            rows[row_id] = entry
            continue
        # newest bundle wins, but every bundle is verified and reported
        checks = []
        for bdir, data in found:
            rep = verify_drivers.verify(bdir, REPO, qualification=True)
            checks.append({
                "bundle": common.rel(bdir),
                "bundle_root": rep["recomputed_bundle_root"],
                "sealed_complete": rep["sealed_complete"],
                "anomalies": rep["anomalies"],
                "rederived_verdict": rep["rederived_verdict"],
                "qualification_pass": rep["qualification_pass"],
                "plan_leaves_with_outcome": rep["rederived_executed_leaves"],
                "plan_leaves_passed": rep["rederived_passed_leaves"],
                "lane": data.get("lane"),
                "suites_selected": data["counts"]["suites_selected"],
                "suites_executed": data["counts"]["suites_executed"],
                "plan_leaves_in_scope": data["counts"]["plan_leaves_in_scope"],
                "suites_blocked": {
                    s["suite_id"]: s.get("precondition")
                    for s in data["suites"]
                    if s.get("status") == "NOT_EXECUTED_PRECONDITION_UNMET"},
                "leaves_outside_plan": data["counts"]["leaf_rows_outside_plan"],
            })
        entry["bundles"] = checks
        best = next((c for c in checks if c["qualification_pass"]), None)
        if best is None:
            entry["blocked_precondition"] = (
                "a bundle exists but the independent verifier refuses it: "
                + "; ".join(checks[0]["anomalies"][:3]))
            rows[row_id] = entry
            continue
        entry["evidence_bundle"] = best["bundle"]
        entry["bundle_root"] = best["bundle_root"]
        entry["plan_leaves_in_scope"] = best["plan_leaves_in_scope"]
        entry["plan_leaves_with_outcome"] = best["plan_leaves_with_outcome"]
        entry["plan_leaves_passed"] = best["plan_leaves_passed"]
        entry["suites_executed"] = best["suites_executed"]
        entry["suites_selected"] = best["suites_selected"]
        entry["suites_blocked"] = best["suites_blocked"]
        complete_suites = not best["suites_blocked"]
        entry["status"] = ("EXECUTED_LEAF" if complete_suites
                           else "EXECUTED_LEAF_PARTIAL_SUITES")
        entry["coverage_class"] = "COVERED" if complete_suites else "PARTIAL"
        entry["status_meaning"] = (
            "EXECUTED_LEAF: the official driver suite ran against a real "
            "TypeDB server and EVERY plan leaf in its scope carries a "
            "per-scenario outcome, verified independently from the archived "
            "bytes." if complete_suites else
            "EXECUTED_LEAF_PARTIAL_SUITES: the official driver suite ran and "
            "every plan leaf in the EXECUTED suites' scope carries a "
            "per-scenario outcome, but at least one declared suite of the "
            "official corpus could not run here; each such suite names its "
            "exact external precondition. The row is PARTIAL, never covered.")
        rows[row_id] = entry

    doc = {
        "schema": "typedb-r2-driver-row-status-v1",
        "statement": (
            "RESULT-side status of the plan's six official-driver rows. The "
            "plan itself is the immutable denominator and is NOT edited: its "
            "driver_rows keep their NOT_IMPLEMENTED seed, because the plan "
            "body feeds plan_root and archived verdicts pin that root. A row "
            "here is EXECUTED only because tools/evidence/verify_drivers.py "
            "re-derived its leaf outcomes from the archived bytes and "
            "returned zero anomalies; every other row names the exact "
            "external precondition that blocks it."),
        "plan": {"path": common.rel(common.PLAN),
                 "plan_root": plan.get("plan_root"),
                 "driver_rows_in_plan": len(plan["driver_rows"])},
        "rows": rows,
        "counts": {
            "total": len(ALL_ROWS),
            "executed_leaf": sum(1 for r in rows.values()
                                 if r["status"].startswith("EXECUTED_LEAF")),
            "covered": sum(1 for r in rows.values()
                           if r["coverage_class"] == "COVERED"),
            "partial": sum(1 for r in rows.values()
                           if r["coverage_class"] == "PARTIAL"),
            "not_implemented": sum(1 for r in rows.values()
                                   if r["status"] == "NOT_IMPLEMENTED"),
        },
    }
    out = args.out if args.out.is_absolute() else REPO / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=1) + "\n")
    print(json.dumps(doc["counts"], indent=1))
    for rid, r in rows.items():
        print(f"  {rid:26} {r['status']:32} {r.get('evidence_bundle') or r.get('blocked_precondition','')[:80]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
