#!/usr/bin/env python3
"""Python source inventory and instrumentation completeness (R8-P1-06).

The round-8 audit's finding, stated as a number: `py.pytest` reported "63 %
coverage" over FOUR imported modules while the project carried 81 Python files
and 2 test files. The percentage was arithmetically correct and told the reader
almost nothing, because its DENOMINATOR was "whatever pytest happened to
import" rather than "the Python this project ships".

This tool replaces that denominator with a declared one and makes the gap
explicit rather than invisible. Every `.py` file under the policy's Python
projects is exactly one of:

  MEASURED    the coverage run instrumented it (it appears in the XML report)
  EXCLUDED    it is listed in `.quality/python-coverage-exclusions.toml` with
              an owner, a reason and an expiry that a human agreed to
  UNMEASURED  neither — which FAILS, because an unmeasured module in a
              repository that reports a coverage percentage is a module the
              percentage silently spoke for

The exclusion list is deliberately uncomfortable to read. That is the point:
the audit's complaint was not the number, it was that nothing said which
modules the number covered. A long, dated, owned list of "this producer is
exercised by an evidence lane, not by pytest" is a true statement about this
project; "63 %" was not.

The report it prints is the one R8-P1-06 item 7 asks for: numerator,
denominator, included modules, excluded modules and test count.

usage:
  python3 tools/quality/python_inventory.py --coverage-xml artifacts/quality/python-tools.xml
  python3 tools/quality/python_inventory.py --write-exclusions   # seed the list
"""

import argparse
import json
import pathlib
import re
import sys
import tomllib
import xml.etree.ElementTree as ET

REPO = pathlib.Path(__file__).resolve().parents[2]
POLICY = REPO / ".quality" / "policy.toml"
EXCLUSIONS = REPO / ".quality" / "python-coverage-exclusions.toml"
SKIP_DIRS = {"__pycache__", ".venv", "node_modules", "target", ".git"}


def python_projects() -> list[str]:
    """The Python project roots the POLICY declares — never a hardcoded list."""
    policy = tomllib.loads(POLICY.read_text())
    roots = []
    for rule in policy.get("scope", {}).get("rule", []):
        project = rule.get("python_project")
        if project and project not in roots:
            roots.append(project)
    return roots


def inventory() -> list[str]:
    """Every Python source file in scope, repo-relative and sorted."""
    out = []
    for project in python_projects():
        for path in sorted((REPO / project).rglob("*.py")):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            out.append(str(path.relative_to(REPO)))
    return sorted(out)


def measured(coverage_xml: pathlib.Path) -> set[str]:
    """Modules the coverage run actually instrumented."""
    if not coverage_xml.is_file():
        return set()
    root = ET.parse(coverage_xml).getroot()
    sources = [(s.text or "").strip() for s in root.findall("./sources/source")]
    out = set()
    for cls in root.iter("class"):
        filename = cls.get("filename") or ""
        # coverage.py writes filenames RELATIVE to <sources>, so a bare
        # `fork/stage.py` is `tools/fork/stage.py`. Both forms are resolved
        # against the repository so the inventory keys always agree.
        candidates = [str(pathlib.Path(s) / filename) for s in sources] + [filename]
        for candidate in candidates:
            resolved = pathlib.Path(candidate)
            if not resolved.is_absolute():
                resolved = REPO / resolved
            if not resolved.exists():
                continue
            try:
                out.add(str(resolved.resolve().relative_to(REPO)))
            except ValueError:
                continue
            break
    return out


def exclusions() -> dict[str, dict]:
    if not EXCLUSIONS.is_file():
        return {}
    data = tomllib.loads(EXCLUSIONS.read_text())
    return {e["path"]: e for e in data.get("exclusion", [])}


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument(
        "--coverage-xml", type=pathlib.Path, default=REPO / "artifacts/quality/python-tools.xml"
    )
    ap.add_argument(
        "--json", type=pathlib.Path, default=REPO / "artifacts/quality/python-inventory.json"
    )
    ap.add_argument(
        "--write-exclusions",
        action="store_true",
        help="seed the exclusion list from the current unmeasured set (then EDIT the reasons)",
    )
    args = ap.parse_args()

    files = inventory()
    tests = [f for f in files if re.search(r"(^|/)test_[^/]*\.py$|_test\.py$", f)]
    instrumented = measured(args.coverage_xml)
    excluded = exclusions()

    unmeasured = [f for f in files if f not in instrumented and f not in excluded]
    stale = [p for p in excluded if p not in files]

    if args.write_exclusions:
        lines = [
            "# Python coverage exclusions (R8-P1-06).",
            "#",
            "# PROTECTED FILE.",
            "#",
            "# Every entry names a module the coverage run does NOT instrument, and says",
            "# why that is acceptable, who agreed, and when it must be revisited. The list",
            "# exists so the gap is READABLE: before it, a coverage percentage was reported",
            "# over whatever pytest happened to import, and nothing said what that was.",
            "#",
            "# `tools/quality/python_inventory.py` fails on any in-scope module that is",
            "# neither measured nor listed here, and on any entry here that no longer",
            "# names a real file. Neither can drift into silence.",
            "",
            "schema = 1",
        ]
        for f in unmeasured:
            lines += [
                "",
                "[[exclusion]]",
                f'path = "{f}"',
                'reason = "TODO: state why this module is not instrumented by the pytest run."',
                'owner = "quality-controller"',
                'review_after = "2026-11-20"',
            ]
        EXCLUSIONS.write_text("\n".join(lines) + "\n")
        print(
            f"{EXCLUSIONS.relative_to(REPO)}: seeded {len(unmeasured)} exclusion(s) — now write the reasons"
        )
        return 0

    report = {
        "schema": "typedb-python-inventory-v1",
        "projects": python_projects(),
        "denominator_modules": len(files),
        "measured_modules": len([f for f in files if f in instrumented]),
        "excluded_modules": len([f for f in files if f in excluded]),
        "unmeasured_modules": len(unmeasured),
        "test_files": len(tests),
        "coverage_xml": str(args.coverage_xml.relative_to(REPO))
        if args.coverage_xml.is_relative_to(REPO)
        else str(args.coverage_xml),
        "measured": sorted(f for f in files if f in instrumented),
        "excluded": sorted(f for f in files if f in excluded),
        "unmeasured": unmeasured,
    }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=1) + "\n")

    print(
        f"PYTHON INVENTORY: {report['measured_modules']} measured / "
        f"{report['excluded_modules']} excluded / {report['unmeasured_modules']} UNMEASURED "
        f"of {report['denominator_modules']} in-scope modules across {report['projects']}; "
        f"{report['test_files']} test file(s)"
    )
    print(f"report: {args.json.relative_to(REPO)}")

    problems = []
    for f in unmeasured:
        problems.append(f"UNMEASURED  {f} is neither instrumented nor excluded")
    for p in stale:
        problems.append(f"STALE       {p} is excluded but is not an in-scope module any more")
    for path, entry in sorted(excluded.items()):
        for field in ("reason", "owner", "review_after"):
            if not entry.get(field):
                problems.append(f"INCOMPLETE  exclusion for {path} has no {field}")
        if str(entry.get("reason", "")).startswith("TODO"):
            problems.append(
                f"INCOMPLETE  exclusion for {path} still carries the seeded TODO reason"
            )
    if problems:
        print(f"\nPYTHON INVENTORY: FAIL — {len(problems)} problem(s):", file=sys.stderr)
        for p in problems[:80]:
            print(f"  {p}", file=sys.stderr)
        if len(problems) > 80:
            print(f"  ... and {len(problems) - 80} more", file=sys.stderr)
        return 1
    print("PYTHON INVENTORY: PASS — every in-scope module is measured or explicitly excluded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
