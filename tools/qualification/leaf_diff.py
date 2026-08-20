#!/usr/bin/env python3
"""Backend equivalence at LEAF granularity: classic oracle vs SlateDB lane.

`tools/catalog/compare_u2s3.py` answers the equivalence question at TARGET
granularity: per cargo target, `<passed>/<failed>/<ignored> <outcome>` on the
SlateDB side against the RocksDB oracle, over the union of both sides. That
is the right shape, and this tool keeps every one of its rules - union of
both sides, a difference is a difference, an absent row is a divergence, a
classification must declare the exact expected values on both sides - and
moves them down one level, to the individual test case:

    for every leaf case the catalogue declares, what was its outcome on the
    classic backend and what was its outcome on the SlateDB backend?

Why that matters and the target-level comparison cannot say it: a target
whose profile is `18/0/0 ok` on both sides is EQUAL at target granularity
even if a different set of 18 cases passed on each side. Counts are not
identities. At leaf granularity a case that passes on classic and fails on
SlateDB is named, and a case that fails on BOTH is visibly upstream - not
ours - instead of being an undifferentiated red row.

Classifications, from the oracle's point of view:

  AGREE_PASSED / AGREE_IGNORED   - identical outcome, nothing to explain
  AGREE_FAILED                   - fails on BOTH backends: an UPSTREAM
                                   defect, not a regression of this port
  REGRESSION                     - PASSED on the oracle, FAILED on the
                                   candidate. THIS is the finding that
                                   matters; any occurrence fails the run
  REPAIRED                       - FAILED on the oracle, PASSED on the
                                   candidate (reported, never celebrated:
                                   it is still a behaviour difference)
  OUTCOME_CHANGED                - any other outcome pair
  ABSENT_ON_CANDIDATE            - the oracle ran it and the candidate did
                                   not: the corpus shrank, which is exactly
                                   as much a divergence as a red
  ABSENT_ON_ORACLE               - present only on the candidate; for
                                   fork-only tests this is expected and is
                                   declared per case, never assumed

Usage:
  python3 tools/qualification/leaf_diff.py --oracle DIR --candidate DIR \
      [--scope-package storage --scope-package durability ...] --out FILE
"""

import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "tools" / "catalog"))
import leaf_common as lc  # noqa: E402
import verify_leaf  # noqa: E402

# Cases that exist on the candidate side only, declared with the exact reason.
# Anything not declared here is UNEXPLAINED, exactly like an unclassified
# target in compare_u2s3.py.
EXPECTED_CANDIDATE_ONLY = {}


def load(d, plan, cl, ct):
    p = pathlib.Path(d)
    p = p if p.is_absolute() else REPO / p
    anomalies, facts = verify_leaf.verify(p, plan, cl, ct)
    if anomalies:
        for a in anomalies:
            print(f"ANOMALY {d}: {a}", file=sys.stderr)
        sys.exit(
            f"{d} does not verify from its own bytes ({len(anomalies)} "
            f"anomaly/anomalies); a differential over unverified evidence "
            f"is worthless"
        )
    return json.loads((p / lc.RESULTS_NAME).read_text()), facts


def load_side(dirs, plan, cl, ct):
    """Merge one lane's sealed bundles into a single view.

    A lane can legitimately be archived as several bundles - a sealed bundle
    is never reopened, so re-running targets a first pass refused produces a
    second one. Merging is exact-union only: two bundles of different
    profiles, a duplicate target row, or two rows for one leaf are all
    refusals, never a silent last-one-wins.
    """
    merged, facts = None, []
    for d in dirs:
        b, f = load(d, plan, cl, ct)
        facts.append({"dir": d, **f})
        if merged is None:
            merged = dict(b)
            merged["targets"] = list(b["targets"])
            merged["leaves"] = list(b["leaves"])
            continue
        if b["profile"] != merged["profile"]:
            sys.exit(
                f"{d} is profile {b['profile']!r} but the side already "
                f"holds {merged['profile']!r} - one side, one lane"
            )
        by_rid = {t["runner_row_id"]: i for i, t in enumerate(merged["targets"])}
        for t in b["targets"]:
            rid = t["runner_row_id"]
            if rid in by_rid:
                prev = merged["targets"][by_rid[rid]]
                # The ONLY legitimate duplicate is the re-run case: a first
                # bundle REFUSED the target (published no leaf) and a later
                # bundle ran it successfully. Two PUBLISHABLE rows for one
                # target would mean two executions both claiming its leaves,
                # which is exactly the double-count this merge must refuse.
                if prev.get("publishable") and t.get("publishable"):
                    sys.exit(
                        f"{d}: target {rid} is publishable in BOTH bundles "
                        f"on this side - two executions cannot both vouch "
                        f"for one target's leaves"
                    )
                if t.get("publishable"):
                    merged["targets"][by_rid[rid]] = t
                    merged.setdefault("_supersedes", []).append(
                        {
                            "target": rid,
                            "refused_row_replaced_from": prev.get("raw_log"),
                            "refusals": prev.get("refusals"),
                            "rerun_from": d,
                        }
                    )
                continue
            by_rid[rid] = len(merged["targets"])
            merged["targets"].append(t)
        seen_l = {x["leaf_case_id"] for x in merged["leaves"]}
        for x in b["leaves"]:
            if x["leaf_case_id"] in seen_l:
                sys.exit(
                    f"{d}: leaf {x['leaf_case_id']} already present on this "
                    f"side - two outcomes for one leaf cannot be merged"
                )
            merged["leaves"].append(x)
    return merged, facts


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--oracle",
        required=True,
        action="append",
        help="leaf bundle for the classic (RocksDB) backend lane "
        "(repeatable: a lane may be archived as more than one "
        "sealed bundle, e.g. when refused targets were re-run)",
    )
    ap.add_argument(
        "--candidate",
        required=True,
        action="append",
        help="leaf bundle for the SlateDB backend lane (repeatable)",
    )
    ap.add_argument(
        "--scope-package",
        action="append",
        default=None,
        help="restrict the comparison to these cargo packages "
        "(repeatable); default: every package both sides ran",
    )
    ap.add_argument("--out", type=pathlib.Path, default=None)
    ap.add_argument(
        "--require-clean",
        action="store_true",
        help="also fail when the two lanes compared ZERO leaves. A "
        "differential over an empty intersection reports "
        "'0 regressions' and means nothing.",
    )
    args = ap.parse_args()

    plan = json.loads(lc.PLAN.read_text())
    cl, ct, _cat = lc.load_catalog_leaves()
    o, o_facts = load_side(args.oracle, plan, cl, ct)
    c, c_facts = load_side(args.candidate, plan, cl, ct)

    if o["profile"] == c["profile"]:
        sys.exit(
            f"both bundles are profile {o['profile']!r} - a differential needs two different lanes"
        )

    scope = set(args.scope_package or [])

    def in_scope(rid):
        return (not scope) or rid.split(":", 1)[0] in scope

    def index(bundle):
        return {
            leaf["leaf_case_id"]: leaf
            for leaf in bundle["leaves"]
            if in_scope(leaf["runner_row_id"])
        }

    oracle, candidate = index(o), index(c)
    # target rows in scope, so an ABSENT case can say whether its TARGET ran
    o_targets = {t["runner_row_id"]: t for t in o["targets"] if in_scope(t["runner_row_id"])}
    c_targets = {t["runner_row_id"]: t for t in c["targets"] if in_scope(t["runner_row_id"])}

    rows, tally = [], {}
    for lid in sorted(set(oracle) | set(candidate)):
        a, b = oracle.get(lid), candidate.get(lid)
        if a and b:
            oa, ob = a["outcome"], b["outcome"]
            if oa == ob:
                kind = f"AGREE_{oa}"
            elif oa == "PASSED" and ob == "FAILED":
                kind = "REGRESSION"
            elif oa == "FAILED" and ob == "PASSED":
                kind = "REPAIRED"
            else:
                kind = "OUTCOME_CHANGED"
        elif a and not b:
            kind = "ABSENT_ON_CANDIDATE"
        else:
            kind = "ABSENT_ON_ORACLE"
        tally[kind] = tally.get(kind, 0) + 1
        if kind in ("AGREE_PASSED", "AGREE_IGNORED"):
            continue
        row = {
            "leaf_case_id": lid,
            "oracle": {
                "profile": o["profile"],
                "outcome": a["outcome"] if a else "ABSENT",
                "log": a["raw_log"] if a else None,
                "log_line": a["log_line"] if a else None,
            },
            "candidate": {
                "profile": c["profile"],
                "outcome": b["outcome"] if b else "ABSENT",
                "log": b["raw_log"] if b else None,
                "log_line": b["log_line"] if b else None,
            },
            "classification": kind,
        }
        if kind == "AGREE_FAILED":
            row["reading"] = (
                "fails on BOTH backends - an upstream defect of "
                "the pinned revision, not a regression introduced "
                "by the SlateDB port"
            )
        elif kind == "REGRESSION":
            row["reading"] = (
                "PASSES on the classic backend and FAILS on the "
                "SlateDB backend - a backend-attributable "
                "regression; stop the line"
            )
        elif kind == "ABSENT_ON_CANDIDATE":
            t = (a or {}).get("runner_row_id")
            row["reading"] = (
                f"the oracle recorded this case and the candidate "
                f"did not; candidate target row for {t}: "
                f"{'present' if t in c_targets else 'ABSENT'}"
            )
        elif kind == "ABSENT_ON_ORACLE":
            row["reading"] = EXPECTED_CANDIDATE_ONLY.get(
                lid, "UNEXPLAINED - present only on the candidate lane"
            )
        rows.append(row)

    # cases the log named that the CATALOGUE does not carry (e.g. fork-only
    # tests) never became leaves on either side; they are reported so the
    # comparison cannot silently ignore a whole module of new tests
    extra = {}
    for side, bundle, tmap in (("oracle", o, o_targets), ("candidate", c, c_targets)):
        for rid, t in tmap.items():
            if t.get("extra_cases"):
                extra.setdefault(rid, {})[side] = t["extra_cases"]

    regressions = [r for r in rows if r["classification"] == "REGRESSION"]
    absent = [r for r in rows if r["classification"] == "ABSENT_ON_CANDIDATE"]
    unexplained_extra = [
        r
        for r in rows
        if r["classification"] == "ABSENT_ON_ORACLE"
        and str(r.get("reading", "")).startswith("UNEXPLAINED")
    ]
    changed = [r for r in rows if r["classification"] == "OUTCOME_CHANGED"]

    out = {
        "schema": "typedb-r2-leaf-differential-v1",
        "claim": (
            f"Every individual upstream test case in scope has the SAME outcome "
            f"on the SlateDB backend lane ({c['profile']}) as on the classic "
            f"RocksDB oracle lane ({o['profile']}), except where a difference is "
            f"named below. Cases that fail on BOTH lanes are upstream defects of "
            f"the pinned revision, not regressions of this port."
        ),
        "oracle_refused_targets_superseded_by_rerun": o.get("_supersedes", []),
        "candidate_refused_targets_superseded_by_rerun": c.get("_supersedes", []),
        "oracle_bundles": o_facts,
        "candidate_bundles": c_facts,
        "scope_packages": sorted(scope) or "ALL",
        "leaves_compared": len(set(oracle) | set(candidate)),
        "oracle_leaves": len(oracle),
        "candidate_leaves": len(candidate),
        "tally": dict(sorted(tally.items())),
        "differences": rows,
        "non_catalogued_cases_by_target": extra,
        "regressions": len(regressions),
        "absent_on_candidate": len(absent),
        "unexplained_candidate_only": len(unexplained_extra),
        "outcome_changed": len(changed),
        "method": (
            "union of both sides over the plan's leaf id space "
            "(<catalogue target_id>::<display_name>); each side's outcome is "
            "read back out of its own archived log line by "
            "tools/qualification/verify_leaf.py before the comparison runs. A "
            "case absent from either side is a difference, never a skip."
        ),
    }
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(out, indent=1) + "\n")
    print(
        json.dumps(
            {k: v for k, v in out.items() if k not in ("differences", "claim", "method")}, indent=1
        )
    )
    for r in rows:
        print(
            f"{r['classification']:22s} {r['leaf_case_id']}  "
            f"{o['profile']}={r['oracle']['outcome']} "
            f"{c['profile']}={r['candidate']['outcome']}",
            file=sys.stderr,
        )
    bad = len(regressions) + len(absent) + len(unexplained_extra) + len(changed)
    print(
        f"LEAF DIFFERENTIAL: {len(regressions)} regression(s), "
        f"{len(absent)} absent-on-candidate, {len(changed)} outcome-changed, "
        f"{len(unexplained_extra)} unexplained candidate-only over "
        f"{len(set(oracle) | set(candidate))} leaf case(s)",
        file=sys.stderr,
    )
    # `rows` is the DIFFERENCES list, so an empty `rows` is the GOOD case.
    # The degenerate case this guards is an empty INTERSECTION: two lanes that
    # share no comparable leaf report "0 regressions" and prove nothing.
    if args.require_clean and not (set(oracle) & set(candidate)):
        print(
            "LEAF DIFFERENTIAL: FAIL — the two lanes share no comparable "
            "leaf. An empty comparison reports zero regressions and proves "
            "nothing about the backend.",
            file=sys.stderr,
        )
        return 2
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
