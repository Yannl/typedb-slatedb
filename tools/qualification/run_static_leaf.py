#!/usr/bin/env python3
"""Produce a sealed leaf bundle for the catalogue's 141 STATIC_CHECK cases.

WHY THIS EXISTS
---------------
`plan_coverage.py` has said the same thing about these rows for four rounds:

    CUCUMBER / STATIC_CHECK / SCRIPT leaves have no leaf-level runner lanes
    producing archived evidence at all: UNCOVERED, stated as such.

Cucumber got its lane. Static did not, even though `tools/catalog/run_static.py`
has run the checks all along — it writes a flat report, and a flat report is
not evidence a coverage reporter can count: nothing binds it to a profile, a
toolchain, a tree, or the catalogue's leaf ids, and nothing re-derives it.

This is that lane. One STATIC_CHECK target is one leaf (the catalogue's
`<target_id>::check`), so the bundle is 141 targets and 141 leaves.

WHAT THE LOG CARRIES, AND WHY
-----------------------------
Per target, a text log in the same spirit as libtest's output — the bytes the
verifier re-derives from:

    STATIC-CHECK <target_id>
    RULE         checkstyle | rustfmt
    TOOLCHAIN    <rustfmt toolchain, or none>
    FILE         <sha256> <tree-relative path>      (one per checked file)
    FAILURE      <finding>                          (zero or more)
    RESULT       <PASS|FAIL> files=<n> failures=<m>

The FILE lines are the point. A static check's verdict means nothing without
the inputs it read: "PASS, 4 files" is unfalsifiable, while "PASS over these
four files at these four digests" is checkable against the pinned tree, and
`verify_static_leaf.py` checks exactly that. It also re-derives the RESULT from
the FAILURE lines, and re-runs both predicates itself, so a producer cannot
report a pass it did not earn.

The checks themselves are NOT reimplemented here: `run_static.py` owns them,
this module archives them. It gained a `files` field for this, so the resolved
file set has one definition.

usage:
  python3 tools/qualification/run_static_leaf.py --out docs/evidence/G3/leaf/static-u0-1
"""

import argparse
import hashlib
import json
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "tools" / "catalog"))

import common  # noqa: E402
import leaf_common as lc  # noqa: E402
import run_static  # noqa: E402

TB = REPO / "sources" / "typedb"
SCHEMA = "typedb-r2-static-leaf-evidence-v1"
# Static checks read source files; they start no server and touch no store, so
# every profile that shares this tree would produce the identical verdict.
# U0 is the pristine-upstream profile and the only one the plan gives static
# rows to — claiming more than U0 from one execution would be exactly the
# other-lane borrowing plan_coverage refuses.
PROFILE = "U0"
FIXTURE_SET = "fs:none"


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def log_name(target_id: str) -> str:
    """`static:util/test/BUILD:rustfmt_test` -> `static__util-test-BUILD__rustfmt_test.log`."""
    _, build_rel, rule = target_id.split(":", 2)
    return f"static__{build_rel.replace('/', '-')}__{rule}.log"


def rule_of(target_id: str) -> str:
    return "rustfmt" if target_id.rsplit(":", 1)[-1].startswith("rustfmt") else "checkstyle"


def render_log(target_id: str, result: dict) -> str:
    rule = rule_of(target_id)
    lines = [
        f"STATIC-CHECK {target_id}",
        f"RULE         {rule}",
        f"TOOLCHAIN    {run_static.RUSTFMT_TOOLCHAIN if rule == 'rustfmt' else 'none'}",
    ]
    for rel in result.get("files") or []:
        path = TB / rel
        lines.append(f"FILE         {sha256_file(path)} {rel}")
    for f in result.get("failures") or []:
        # one finding per line: a multi-line finding would break the grammar
        # the verifier re-derives the verdict from
        lines.append(f"FAILURE      {' | '.join(str(f).splitlines())}")
    n_files = len(result.get("files") or [])
    n_fail = len(result.get("failures") or [])
    lines.append(f"RESULT       {result['status']} files={n_files} failures={n_fail}")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument(
        "--only",
        action="append",
        default=None,
        help="restrict to these target ids (debugging; a partial bundle is "
        "marked partial and covers only what it ran)",
    )
    args = ap.parse_args()
    out_dir = args.out if args.out.is_absolute() else REPO / args.out
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"REFUSED: {out_dir} exists and is not empty — a sealed bundle is never reopened")
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)

    catalog = json.loads(lc.CATALOG.read_text())
    leaves_by_target: dict[str, list[dict]] = {}
    for leaf in catalog["leaf_cases"]:
        if leaf["kind"] == "STATIC_CHECK":
            leaves_by_target.setdefault(leaf["target_id"], []).append(leaf)
    target_ids = sorted(leaves_by_target)
    if args.only:
        target_ids = [t for t in target_ids if t in set(args.only)]
    if not target_ids:
        print("REFUSED: no STATIC_CHECK targets selected")
        return 2

    plan = json.loads(lc.PLAN.read_text())
    tc = lc.measured_toolchain()
    tc_id = lc.toolchain_id(tc, plan)
    tree_before = lc.executed_tree_identity()
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    try:
        _argv, rustfmt_identity = run_static.resolve_rustfmt()
    except RuntimeError as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 2

    checkstyle = [t for t in target_ids if rule_of(t) == "checkstyle"]
    rustfmt = [t for t in target_ids if rule_of(t) == "rustfmt"]
    results: dict[str, dict] = {}
    for tid in checkstyle:
        results[tid] = run_static.run_checkstyle(tid)
    for r in run_static.run_rustfmt_batch(rustfmt):
        results[r["target_id"]] = r

    targets, leaves = [], []
    for tid in target_ids:
        result = results[tid]
        text = render_log(tid, result)
        path = out_dir / log_name(tid)
        path.write_text(text)
        refusals = []
        if result["status"] == "ERROR":
            refusals.append(f"the check could not run: {result.get('detail')}")
        if not (result.get("files") or []):
            # A rule that resolved no files decided nothing. run_static.py
            # calls that PASS; a LEAF bundle must not, because a leaf whose
            # check read nothing is the vacuous evidence plan_coverage refuses
            # for zero-case cargo targets.
            refusals.append("the rule resolved NO files, so its verdict is about nothing")
        targets.append(
            {
                "runner_row_id": tid,
                "catalog_target_id": tid,
                "rule": rule_of(tid),
                "raw_log": str(path.relative_to(REPO)),
                "log_sha256": sha256_file(path),
                "log_bytes": path.stat().st_size,
                "files_checked": len(result.get("files") or []),
                "status": result["status"],
                "failures": len(result.get("failures") or []),
                "refusals": refusals,
                "publishable": not refusals,
            }
        )
        if refusals:
            continue
        result_line = len(text.splitlines())
        for leaf in leaves_by_target[tid]:
            leaves.append(
                {
                    "leaf_case_id": leaf["leaf_case_id"],
                    "catalog_target_id": tid,
                    "runner_row_id": tid,
                    "case_name": leaf["display_name"],
                    "outcome": "PASSED" if result["status"] == "PASS" else "FAILED",
                    "raw_log": str(path.relative_to(REPO)),
                    "log_sha256": sha256_file(path),
                    "log_line": result_line,
                    "outcome_line": result_line,
                    "fixture_set_id": FIXTURE_SET,
                    "fixture_set_satisfied": True,
                }
            )

    tree_after = lc.executed_tree_identity()
    body = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "profile_in_plan": True,
        "toolchain": tc,
        "toolchain_id": tc_id,
        "plan_root": plan.get("plan_root"),
        "catalog_sha256": common.sha256_file(lc.CATALOG),
        "rustfmt_toolchain": run_static.RUSTFMT_TOOLCHAIN,
        # R8-P2-01: WHICH binary ran, and what it reports itself to be — not
        # which one the code expected to find. A bundle produced on a machine
        # with a different CARGO_HOME is now distinguishable from one produced
        # here, instead of both saying only "nightly-2026-04-15".
        "rustfmt_identity": rustfmt_identity,
        "selection": {"targets": len(target_ids), "partial": bool(args.only)},
        "executed_tree": tree_before,
        "executed_tree_after_run": tree_after,
        "tree_stable_across_run": tree_before == tree_after,
        "started_utc": started,
        "targets": targets,
        "leaves": sorted(leaves, key=lambda r: r["leaf_case_id"]),
    }
    (out_dir / "static-leaf-results.json").write_text(json.dumps(body, indent=1) + "\n")

    files = {
        str(p.relative_to(REPO)): sha256_file(p) for p in sorted(out_dir.iterdir()) if p.is_file()
    }
    root = hashlib.sha256(
        "".join(f"{k}\n{v}\n" for k, v in sorted(files.items())).encode()
    ).hexdigest()
    (out_dir / "bundle-manifest.json").write_text(
        json.dumps({"bundle_root": root, "files": files}, indent=1) + "\n"
    )
    (out_dir / "COMPLETE").write_text(f"COMPLETE {root}\n")

    passed = sum(1 for leaf in leaves if leaf["outcome"] == "PASSED")
    print(
        f"STATIC LEAF BUNDLE {out_dir}: {len(targets)} target(s), "
        f"{sum(1 for t in targets if not t['publishable'])} refused, "
        f"{len(leaves)} leaves, {passed} PASSED, {len(leaves) - passed} FAILED, root {root}"
    )
    print(
        "now run tools/qualification/verify_static_leaf.py — this producer does not judge itself."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
