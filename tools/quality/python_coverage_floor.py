#!/usr/bin/env python3
"""Branch-coverage floors for CHANGED code, and no regression against a trusted
base (R8-P1-06 item 3).

The audit is explicit about what NOT to build: "Avoid a single repository-wide
percentage that incentivizes trivial tests." A global number can be lifted by
adding assertions to whatever is easiest, and it says nothing about the code
this change actually touched.

So there are two rules here and neither is a repository percentage.

  FLOOR      every module this change TOUCHED, that the run measures and that
             is not a reviewed exclusion, must reach the declared branch-rate
             floor. This is the rule that bites on new and edited code, where
             the tests are cheapest to write and most valuable to have.

  NO-REGRESSION  no measured module may fall below the branch rate recorded in
             `.quality/python-coverage-baseline.json`, and a module that was
             measured at the baseline and is no longer measured at all is a
             regression too — quietly dropping a module from the run is the
             cheapest way to raise an average.

BRANCH rate, not line rate, on purpose: a line-covered `if` whose false arm is
never taken is a reducer nobody has tested, and reducers are what this
repository's verifiers are made of.

The baseline is protected policy. Lowering a number in it is a reviewed act,
which is the property that makes "no regression" mean anything.

usage:
  python3 tools/quality/python_coverage_floor.py --base <sha>
  python3 tools/quality/python_coverage_floor.py            # no-regression only
  python3 tools/quality/python_coverage_floor.py --write-baseline
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import xml.etree.ElementTree as ET

REPO = pathlib.Path(__file__).resolve().parents[2]
BASELINE = REPO / ".quality" / "python-coverage-baseline.json"
DEFAULT_XML = REPO / "artifacts" / "quality" / "python-tools.xml"

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import python_inventory  # noqa: E402

# Floating-point coverage rates re-derived from a different run of the same
# tests can differ in the last digit. A tolerance smaller than one branch of a
# one-branch module is small enough to catch a real regression and large enough
# not to fail on arithmetic.
EPSILON = 0.005


def rel(path: pathlib.Path) -> str:
    """Repo-relative when it can be, absolute otherwise.

    A bare `.relative_to(REPO)` raises for any path outside the tree — which a
    caller may legitimately pass (a report written to a temp directory, a
    bundle copied elsewhere). Crashing while FORMATTING a message is the worst
    place to crash: the finding is already known and gets lost.
    """
    return str(path.relative_to(REPO)) if path.is_relative_to(REPO) else str(path)


def rates(coverage_xml: pathlib.Path) -> dict[str, float]:
    """Repo-relative module -> branch rate, resolved the same way the inventory
    resolves its own measured set, so the two never disagree about a path."""
    if not coverage_xml.is_file():
        return {}
    root = ET.parse(coverage_xml).getroot()
    sources = [(s.text or "").strip() for s in root.findall("./sources/source")]
    out: dict[str, float] = {}
    for cls in root.iter("class"):
        filename = cls.get("filename") or ""
        for candidate in [str(pathlib.Path(s) / filename) for s in sources] + [filename]:
            resolved = pathlib.Path(candidate)
            if not resolved.is_absolute():
                resolved = REPO / resolved
            if not resolved.exists():
                continue
            try:
                key = str(resolved.resolve().relative_to(REPO))
            except ValueError:
                break
            out[key] = float(cls.get("branch-rate") or 0.0)
            break
    return out


def changed_python(base: str) -> list[str]:
    proc = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD"],
        capture_output=True,
        text=True,
        cwd=REPO,
    )
    if proc.returncode != 0:
        raise SystemExit(f"git diff against {base} failed: {proc.stderr.strip()}")
    return [p for p in proc.stdout.split() if p.endswith(".py")]


def load_baseline() -> dict:
    if not BASELINE.is_file():
        return {"schema": "typedb-python-coverage-baseline-v1", "floor_changed": 0.0, "modules": {}}
    return json.loads(BASELINE.read_text())


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--coverage-xml", type=pathlib.Path, default=DEFAULT_XML)
    ap.add_argument(
        "--base", default=None, help="trusted base revision; enables the changed-code floor"
    )
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument(
        "--floor", type=float, default=None, help="override the declared floor (writing only)"
    )
    args = ap.parse_args()

    measured = rates(args.coverage_xml)
    if not measured:
        print(
            f"PYTHON COVERAGE FLOOR: FAIL — no coverage report at "
            f"{args.coverage_xml} (the tests did not run, or ran without --cov-branch)"
        )
        return 1

    baseline = load_baseline()
    excluded = set(python_inventory.exclusions())

    if args.write_baseline:
        baseline = {
            "schema": "typedb-python-coverage-baseline-v1",
            "why": (
                "R8-P1-06: the branch rates a change may not fall below, and the floor every "
                "CHANGED measured module must reach. PROTECTED: lowering a number here is a "
                "reviewed act, which is what makes 'no regression' mean anything."
            ),
            "floor_changed": args.floor
            if args.floor is not None
            else baseline.get("floor_changed", 0.0),
            "as_of_commit": subprocess.run(
                ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=REPO
            ).stdout.strip(),
            "modules": {k: round(v, 4) for k, v in sorted(measured.items())},
        }
        BASELINE.write_text(json.dumps(baseline, indent=1) + "\n")
        print(
            f"{rel(BASELINE)}: recorded {len(measured)} module(s), "
            f"floor_changed={baseline['floor_changed']}"
        )
        return 0

    failures: list[str] = []
    floor = float(baseline.get("floor_changed", 0.0))
    recorded = baseline.get("modules", {})

    # 1. no regression, per module
    for module, was in sorted(recorded.items()):
        if module not in measured:
            failures.append(
                f"REGRESSION  {module} was measured at the baseline ({was:.1%} branch) and is not "
                f"measured now — dropping a module from the run is the cheapest way to raise an "
                f"average, so it counts as a regression"
            )
            continue
        now = measured[module]
        if now + EPSILON < was:
            failures.append(f"REGRESSION  {module} branch coverage fell {was:.1%} -> {now:.1%}")

    # 2. floor on changed code
    checked_changed = 0
    if args.base:
        for module in changed_python(args.base):
            if module in excluded or module not in measured:
                continue
            checked_changed += 1
            if measured[module] + EPSILON < floor:
                failures.append(
                    f"FLOOR       {module} is touched by this change and reaches {measured[module]:.1%} "
                    f"branch coverage, below the declared floor of {floor:.1%}"
                )

    summary = (
        f"PYTHON COVERAGE FLOOR: {len(measured)} measured module(s), "
        f"{len(recorded)} baselined, {checked_changed} changed module(s) held to the "
        f"{floor:.0%} branch floor"
    )
    if failures:
        print(f"{summary}\n")
        for f in failures:
            print(f"  {f}")
        print(
            f"\nPYTHON COVERAGE FLOOR: FAIL — {len(failures)} finding(s). Raise the tests, or "
            f"change {rel(BASELINE)} through review; it is protected policy."
        )
        return 1
    print(f"{summary}\nPYTHON COVERAGE FLOOR: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
