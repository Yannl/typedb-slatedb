#!/usr/bin/env python3
"""Plan coverage WITH leaf-granularity evidence folded in.

`tools/catalog/plan_coverage.py` is the owner of the coverage rules, and it
is deliberately unable to count a cargo-family row as covered: no producer
had ever recorded a per-case outcome, so its docstring states the ceiling
("AT BEST 'PARTIAL' ... NEVER counted as covered"). This reporter does not
replace those rules and does not re-implement them: it IMPORTS
plan_coverage.py and calls its `load_evidence` and `driver_row_status`
verbatim, so the target-granularity lane rules, the unjoinable-id rule, the
vacuous-evidence rule and the driver-row seal check stay single-sourced.
The only thing added is the missing granularity:

    a plan row (leaf_case_id, profile_id, fixture_set_id, toolchain_id) is
    COVERED when a VERIFIED leaf bundle carries an outcome for exactly that
    leaf, under exactly that profile, with exactly that fixture set
    satisfied, on exactly that toolchain id.

"VERIFIED" is not a claim the bundle makes about itself: every bundle named
on the command line is re-verified here by tools/qualification/verify_leaf.py
- logs re-hashed, counts reparsed, every leaf outcome read back out of its
log line - and a bundle with ANY anomaly contributes ZERO rows and is
reported with its anomalies. A bundle whose profile the plan does not
require, whose toolchain the plan does not name, or whose tree is DIRTY
likewise contributes nothing.

`--cucumber DIR` folds in the same granularity for the CUCUMBER family, from
tools/qualification/run_cucumber_leaf.py: one recorded outcome per Gherkin
scenario, re-verified here by verify_cucumber_leaf.py under identical rules.
A cucumber row that stays uncovered now says WHY - either no verified bundle
carries that (scenario, profile), or the runner's own ignore-tag filter never
executed it, which is a scenario with no outcome rather than a passing one.

COVERED means "this leaf has a recorded outcome in this lane". It does NOT
mean the leaf passed: a FAILED leaf is covered evidence of a failure. The
report therefore always prints the outcome split alongside the coverage
count, and never says the plan is satisfied.

Usage:
  python3 tools/qualification/leaf_coverage.py --leaf DIR [--leaf DIR ...]
  python3 tools/qualification/leaf_coverage.py --leaf DIR --cucumber DIR \
      --out REPORT.json
"""

import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "tools" / "catalog"))
import common  # noqa: E402
import plan_coverage  # noqa: E402  (the owner of the coverage rules)
import cucumber_common as cc  # noqa: E402
import verify_cucumber_leaf  # noqa: E402
import verify_static_leaf  # noqa: E402
from leaf_evidence import load_leaf_evidence  # noqa: E402


def load_static_evidence(dirs, repo=REPO):
    """(leaf_index, notes) from STATIC_CHECK leaf bundles.

    Same contract as the other two loaders: every bundle is re-verified from
    its own bytes first — here by verify_static_leaf.py, which also re-derives
    each verdict from the pinned tree — and a bundle with any anomaly
    contributes NOTHING.
    """
    index, notes = {}, []
    for d in dirs:
        p = pathlib.Path(d)
        p = p if p.is_absolute() else pathlib.Path(repo) / p
        anomalies, facts = verify_static_leaf.verify(p, repo=repo)
        note = {**facts, "bundle": str(d), "anomalies": anomalies, "counted": False}
        if anomalies:
            note["reason"] = (
                f"{len(anomalies)} verification anomaly/anomalies - a bundle that does not "
                f"re-derive from its own bytes contributes NOTHING"
            )
            notes.append(note)
            continue
        body = json.loads((p / verify_static_leaf.RESULTS_NAME).read_text())
        profile = body["profile"]
        tc_id = body.get("toolchain_id")
        n = 0
        for leaf in body["leaves"]:
            if not leaf.get("fixture_set_satisfied"):
                continue
            index.setdefault((profile, leaf["leaf_case_id"]), []).append(
                {
                    "bundle": str(d),
                    "profile": profile,
                    "outcome": leaf["outcome"],
                    "fixture_set_id": leaf["fixture_set_id"],
                    "toolchain_id": tc_id,
                    "raw_log": leaf["raw_log"],
                    "log_line": leaf["log_line"],
                    "log_sha256": leaf["log_sha256"],
                }
            )
            n += 1
        note.update({"counted": True, "leaves_indexed": n})
        notes.append(note)
    return index, notes


def load_cucumber_evidence(dirs, plan, catalog, repo=REPO):
    """(leaf_index, not_run_index, notes) from cucumber leaf bundles.

    Same contract as load_leaf_evidence, one level finer: every bundle is
    RE-VERIFIED from its bytes by tools/qualification/verify_cucumber_leaf.py
    before a single row of it is counted, and a bundle with any anomaly
    contributes NOTHING. `not_run_index` carries the scenarios the runner's own
    ignore-tag filter never executed, so the report can say WHY those rows are
    uncovered instead of lumping them under "no evidence".
    """
    index, not_run, notes = {}, {}, []
    corpus = None
    for d in dirs:
        p = pathlib.Path(d)
        p = p if p.is_absolute() else pathlib.Path(repo) / p
        if corpus is None:
            corpus = cc.build_corpus_index(catalog, plan)
        anomalies, facts = verify_cucumber_leaf.verify(p, plan, catalog, repo=repo, corpus=corpus)
        note = {**facts, "bundle": str(d), "anomalies": anomalies, "counted": False}
        if anomalies:
            note["reason"] = (
                f"{len(anomalies)} verification anomaly/anomalies - "
                f"a bundle that does not re-derive from its own "
                f"bytes contributes NOTHING"
            )
            notes.append(note)
            continue
        bundle = json.loads((p / cc.RESULTS_NAME).read_text())
        profile = bundle["profile"]
        if profile not in plan["profiles"]:
            note["reason"] = (
                f"profile {profile!r} is not a plan profile; this "
                f"bundle's scenarios are other-lane evidence and "
                f"cover no plan row"
            )
            notes.append(note)
            continue
        tc_id = bundle.get("toolchain_id")
        if tc_id is None:
            note["reason"] = (
                "the toolchain matches no toolchain the plan "
                "names; a run on an unnamed compiler is not filed "
                "under the plan's lane"
            )
            notes.append(note)
            continue
        if not (p / "COMPLETE").is_file():
            note["reason"] = (
                "no COMPLETE marker - the bundle was never sealed; "
                "an unsealed bundle is a run in progress, not "
                "archived evidence"
            )
            notes.append(note)
            continue
        n = 0
        for leaf in bundle["leaves"]:
            if not leaf.get("fixture_set_satisfied"):
                continue
            key = (profile, leaf["leaf_case_id"])
            index.setdefault(key, []).append(
                {
                    "bundle": str(d),
                    "profile": profile,
                    "outcome": leaf["outcome"],
                    "outcome_derivation": leaf["outcome_derivation"],
                    "fixture_set_id": leaf["fixture_set_id"],
                    "toolchain_id": tc_id,
                    "raw_log": leaf["raw_log"],
                    "log_line": leaf["log_line"],
                    "log_sha256": leaf["log_sha256"],
                }
            )
            n += 1
        for x in bundle.get("not_run", []):
            not_run[(profile, x["leaf_case_id"])] = x["reason"]
        note.update(
            {
                "counted": True,
                "leaves_indexed": n,
                "scenarios_not_run": len(bundle.get("not_run") or []),
            }
        )
        notes.append(note)
    return index, not_run, notes


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--plan", type=pathlib.Path, default=plan_coverage.PLAN)
    ap.add_argument("--catalog", type=pathlib.Path, default=plan_coverage.CATALOG)
    ap.add_argument(
        "--evidence",
        action="append",
        default=None,
        help="target-granularity results dir (repeatable); default: "
        "plan_coverage.py's own committed bundles",
    )
    ap.add_argument(
        "--leaf", action="append", default=[], help="leaf evidence bundle dir (repeatable)"
    )
    ap.add_argument(
        "--cucumber",
        action="append",
        default=[],
        help="cucumber leaf evidence bundle dir (repeatable); each "
        "is re-verified by verify_cucumber_leaf.py before any "
        "row of it is counted",
    )
    ap.add_argument(
        "--static",
        action="append",
        default=[],
        help="STATIC_CHECK leaf evidence bundle dir (repeatable); each is "
        "re-verified by verify_static_leaf.py, which re-derives every "
        "verdict from the pinned tree, before any row of it is counted",
    )
    ap.add_argument("--out", type=pathlib.Path, default=None)
    ap.add_argument(
        "--min-covered",
        type=int,
        default=None,
        help="fail if fewer than N rows carry a leaf outcome. The "
        "plan is not satisfied and this command exits nonzero "
        "either way, so a CI job cannot use the exit code as a "
        "regression signal; this floor is what makes coverage "
        "ratchet forward instead of quietly sliding back.",
    )
    ap.add_argument(
        "--repo",
        default=str(REPO),
        help="root a repo-relative raw_log resolves against; only "
        "the negative-control harness passes this",
    )
    args = ap.parse_args()

    plan = json.loads(args.plan.read_text())
    catalog = json.loads(args.catalog.read_text())
    plan_profiles = set(plan["profiles"])
    targets = {t["target_id"]: t for t in catalog["targets"]}
    catalog_leaves = {}
    for lcase in catalog["leaf_cases"]:
        if lcase["kind"] == "LIBTEST":
            catalog_leaves.setdefault(lcase["target_id"], {})[lcase["display_name"]] = lcase

    same_lane, other_lane, notes = plan_coverage.load_evidence(
        args.evidence or plan_coverage.DEFAULT_EVIDENCE, plan_profiles
    )
    leaf_index, leaf_notes = load_leaf_evidence(
        args.leaf, plan, catalog_leaves, targets, repo=args.repo
    )
    cuke_index, cuke_not_run, cuke_notes = load_cucumber_evidence(
        args.cucumber, plan, catalog, repo=args.repo
    )
    static_index, static_notes = load_static_evidence(args.static, repo=args.repo)
    for other in (cuke_index, static_index):
        for k, v in other.items():
            leaf_index.setdefault(k, []).extend(v)

    leaves = plan["leaves"]
    counts, uncovered_reasons = {}, {}
    outcome_counts = {}
    covered_examples, divergence = [], []
    for leaf_id, profile_id, fs_id, tc_id in plan["rows"]:
        leaf = leaves[leaf_id]
        kind = leaf["kind"]
        rid = common.runner_row_id(targets.get(leaf["target_id"]))
        refs = leaf_index.get((profile_id, leaf_id), [])
        # a leaf row is only covered when the evidence's fixture set and
        # toolchain are the row's own, never merely "some run of that leaf"
        refs = [r for r in refs if r["fixture_set_id"] == fs_id and r["toolchain_id"] == tc_id]
        if rid is None:
            family = {"CUCUMBER": "cucumber", "STATIC_CHECK": "static", "SCRIPT": "script"}.get(
                kind, kind.lower()
            )
        else:
            family = "cargo-" + kind.lower()
        if refs:
            status, reason = "COVERED", None
            outs = {r["outcome"] for r in refs}
            for o in outs:
                outcome_counts[(family, o)] = outcome_counts.get((family, o), 0) + 1
            if len(outs) > 1:
                divergence.append({"row": [leaf_id, profile_id], "outcomes": sorted(outs)})
            if len(covered_examples) < 3:
                covered_examples.append({"row": [leaf_id, profile_id], "evidence": refs[:1]})
        elif rid is None and kind == "CUCUMBER":
            status = "UNCOVERED"
            reason = cuke_not_run.get((profile_id, leaf_id))
            if reason is None:
                reason = (
                    "no verified cucumber leaf bundle carries an outcome "
                    "for this scenario in this profile"
                )
        elif rid is None:
            status = "UNCOVERED"
            reason = "no leaf-level runner lane has produced archived evidence"
        else:
            tgt_refs = same_lane.get((profile_id, rid), [])
            live = [r for r in tgt_refs if r["cases"] > 0]
            vacuous = [r for r in tgt_refs if r["cases"] == 0]
            if live:
                status, reason = "PARTIAL", None
            elif vacuous:
                status = "UNCOVERED"
                reason = (
                    "only zero-case (vacuous) evidence exists for the "
                    "target in this lane - a binary that ran nothing "
                    "proves nothing about its leaves"
                )
            elif rid in other_lane:
                status = "UNCOVERED"
                reason = (
                    "target evidence exists ONLY under a lane the plan "
                    "does not require (historical U2S3 dirty-tree "
                    "archive) - other-lane evidence covers no plan row"
                )
            elif kind == "FAILPOINT":
                status = "UNCOVERED"
                reason = (
                    "FAILPOINT leaves are (fail point x libtest case) "
                    "products enumerated inside a loop within a single "
                    "#[test]; libtest prints no per-iteration line, so no "
                    "leaf outcome exists to archive"
                )
            else:
                status = "UNCOVERED"
                reason = "no execution evidence for the target in any lane"
        counts[(family, status)] = counts.get((family, status), 0) + 1
        if reason:
            uncovered_reasons[(family, reason)] = uncovered_reasons.get((family, reason), 0) + 1

    driver_status = plan_coverage.driver_row_status(plan)
    driver_detail = []
    for dr in plan["driver_rows"]:
        status, reason = driver_status[dr["row_id"]]
        counts[("driver", status)] = counts.get(("driver", status), 0) + 1
        driver_detail.append({"row_id": dr["row_id"], "status": status, "reason": reason})

    total_rows = len(plan["rows"]) + len(plan["driver_rows"])
    covered = sum(n for (_family, s), n in counts.items() if s == "COVERED")
    partial = sum(n for (_family, s), n in counts.items() if s == "PARTIAL")
    uncovered = sum(
        n for (_family, s), n in counts.items() if s in ("UNCOVERED", "NOT_IMPLEMENTED")
    )
    by_family = {}
    for (family, status), n in sorted(counts.items()):
        by_family.setdefault(family, {})[status] = n
    outcomes = {}
    for (family, o), n in sorted(outcome_counts.items()):
        outcomes.setdefault(family, {})[o] = n

    report = {
        "schema": "plan-coverage-v2-leaf",
        "derives_rules_from": "tools/catalog/plan_coverage.py (imported, not copied)",
        "plan_root": plan.get("plan_root"),
        "plan_rows": len(plan["rows"]),
        "driver_rows": len(plan["driver_rows"]),
        "exclusion_rows": len(plan["exclusions"]),
        "total_denominator_rows": total_rows,
        "covered_rows": covered,
        "partial_rows": partial,
        "uncovered_rows": uncovered,
        "by_family": by_family,
        "covered_row_outcomes": outcomes,
        "covered_meaning": (
            "COVERED = a verified leaf bundle carries an OUTCOME for exactly "
            "this (leaf, profile, fixture-set, toolchain) row. It does NOT "
            "mean the leaf passed - see covered_row_outcomes for the split. "
            "Coverage is denominator progress, never a pass."
        ),
        "leaf_outcome_divergence": divergence,
        "uncovered_reasons": [
            {"family": f, "reason": r, "rows": n} for (f, r), n in sorted(uncovered_reasons.items())
        ],
        "covered_examples": covered_examples,
        "target_granularity_bundles": notes,
        "leaf_bundles": leaf_notes,
        "cucumber_leaf_bundles": cuke_notes,
        "static_leaf_bundles": static_notes,
        "driver_rows_detail": driver_detail,
        "plan_satisfied": False,
        "statement": (
            f"THE PLAN IS NOT SATISFIED. {covered} of {total_rows} denominator "
            f"rows now carry a leaf-granularity outcome; {partial} are PARTIAL "
            f"(target-granularity aggregate evidence only); {uncovered} are "
            f"uncovered. Coverage counts recorded outcomes, not passes."
        ),
    }
    print(json.dumps(report, indent=1))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=1) + "\n")
    print(
        f"PLAN COVERAGE (leaf-aware): {covered} covered / {partial} partial / "
        f"{uncovered} uncovered of {total_rows} rows -> NOT SATISFIED",
        file=sys.stderr,
    )
    if args.min_covered is not None and covered < args.min_covered:
        print(
            f"LEAF COVERAGE FLOOR: FAIL — {covered} rows carry a leaf outcome, "
            f"below the recorded floor of {args.min_covered}. Coverage went "
            "BACKWARDS; lowering the floor requires a commit that says why.",
            file=sys.stderr,
        )
        return 2
    if args.min_covered is not None:
        print(f"LEAF COVERAGE FLOOR: PASS — {covered} >= {args.min_covered}")
    return 0 if covered == total_rows else 1


if __name__ == "__main__":
    sys.exit(main())
