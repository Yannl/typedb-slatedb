#!/usr/bin/env python3
"""Ledger SEMANTIC verify (R8-P0-02): re-derive every current fact, from evidence.

`lint_ledger.py` is the cheap SCHEMA lint. It proves the ledger's shape: ids
are unique, enums are closed, commits exist and are ancestors, referenced paths
exist, the rendered block matches, and — since round 8 — that no current fact
has a second mutable home. What it cannot prove is whether the numbers in the
one canonical home are TRUE.

That gap is what the round-8 audit found. The audited ledger asserted
`G0 = OPEN` in one field and `OPEN_RED` in another, `13,723 / 23,138` in one
place and `914 / 23,138 with 22,115 uncovered` in another, and a
forbidden-claim reason stating "Mode-Q evidence is absent" beside a Mode-Q
bundle that validated. The linter and all sixteen existing mutants passed that
document, because a number typed into JSON is structurally indistinguishable
from a number that was measured.

So this tool does not read the ledger's numbers and check them against each
other. It RE-RUNS the producers named in the ledger and compares:

    current.coverage   <- tools/qualification/leaf_coverage.py, over exactly
                          the bundles current.coverage names
    current.mode_q     <- tools/modeq/validate_modeq.py, plus an independent
                          re-read of the bundle's own root and target count
    current.drivers    <- the driver rows of the same coverage run
    current.gates      <- a reducer over each gate's blockers and the OPEN
                          owner decisions it names

A mismatch is a failure whichever side is wrong: the ledger may be stale, or
the evidence may have moved. Both are the same defect — a machine authority
that no longer describes its own evidence.

This is deliberately SEPARATE from the schema lint and deliberately slower
(the coverage re-derivation re-verifies every named bundle). CI runs both;
they are named differently so a green "ledger lint" is never mistaken for a
green "ledger semantic verify".

usage:
  python3 tools/ledger/verify_ledger_semantics.py
  python3 tools/ledger/verify_ledger_semantics.py --only mode_q --only gates
  python3 tools/ledger/verify_ledger_semantics.py --emit      # print derived facts
"""

import argparse
import json
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
LEDGER = REPO / "docs" / "ledger" / "gates.json"


def run(argv: list[str], timeout: int = 3600) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, cwd=REPO, timeout=timeout)


# --------------------------------------------------------------------- mode Q


def derive_mode_q(ledger: dict, failures: list[str]) -> dict:
    """Re-run the Mode-Q validator AND re-read the bundle's own facts.

    Two independent readings on purpose. The validator answers "is this bundle
    internally consistent and does it crosswalk"; the direct re-read answers
    "what does it actually say". A ledger that names a validating bundle while
    recording a different root or target count is caught by the second even
    though the first passes.
    """
    claim = ledger["current"]["mode_q"]
    bundle = REPO / claim["bundle"]
    derived: dict = {"bundle": claim["bundle"]}

    proc = run([sys.executable, "tools/modeq/validate_modeq.py", "--dir", str(bundle)])
    state = "INVALID"
    for line in proc.stdout.splitlines():
        if line.startswith("MODEQ: ") and line.split(": ", 1)[1] in ("VALID", "ABSENT", "INVALID"):
            state = line.split(": ", 1)[1]
    derived["state"] = state
    if state != claim["state"]:
        failures.append(
            f"current.mode_q.state says {claim['state']!r}; validate_modeq.py re-derives "
            f"{state!r} from {claim['bundle']}\n{proc.stdout[-800:]}"
        )

    body_path = bundle / "modeq.json"
    if not body_path.is_file():
        failures.append(f"current.mode_q.bundle {claim['bundle']} has no modeq.json to re-read")
        return derived
    body = json.loads(body_path.read_text())
    derived["bundle_root"] = body.get("root")
    derived["targets"] = len(body.get("targets") or [])
    derived["bazel_version"] = (body.get("bazel") or {}).get("version")
    derived["bazel_binary_sha256"] = (body.get("bazel") or {}).get("binary_sha256")
    for field in ("bundle_root", "targets", "bazel_version", "bazel_binary_sha256"):
        if claim.get(field) != derived.get(field):
            failures.append(
                f"current.mode_q.{field} says {claim.get(field)!r}; the bound bundle says "
                f"{derived.get(field)!r}"
            )
    return derived


# ------------------------------------------------------------------- coverage

SUMMARY_RE = re.compile(
    r"PLAN COVERAGE \(leaf-aware\): (\d+) covered / (\d+) partial / (\d+) uncovered of (\d+) rows"
)


def coverage_run(ledger: dict, failures: list[str]):
    """One coverage run over EXACTLY the bundles the ledger names."""
    claim = ledger["current"]["coverage"]
    argv = [sys.executable, "tools/qualification/leaf_coverage.py"]
    for b in claim.get("leaf_bundles", []):
        argv += ["--leaf", b]
    for b in claim.get("cucumber_bundles", []):
        argv += ["--cucumber", b]
    for b in claim.get("static_bundles", []):
        argv += ["--static", b]
    missing = [
        b
        for b in claim.get("leaf_bundles", [])
        + claim.get("cucumber_bundles", [])
        + claim.get("static_bundles", [])
        if not (REPO / b).is_dir()
    ]
    if missing:
        failures.append(f"current.coverage names bundles that do not exist: {missing}")
        return None, None
    proc = run(argv)
    # leaf_coverage.py prints its JSON report on stdout and its human summary on
    # STDERR, and exits nonzero while the plan is unsatisfied — which it is, by
    # design, and will be until every profile exists. Neither is an error here:
    # what this verifier compares is the re-derived NUMBERS.
    match = SUMMARY_RE.search(proc.stdout + proc.stderr)
    if match is None:
        failures.append(
            "leaf_coverage.py produced no parsable summary line — the coverage claim cannot be "
            f"re-derived (exit {proc.returncode})\n{(proc.stdout + proc.stderr)[-1500:]}"
        )
        return None, None
    report = None
    start = proc.stdout.find("{")
    if start >= 0:
        try:
            report, _end = json.JSONDecoder().raw_decode(proc.stdout[start:])
        except ValueError:
            report = None
    return match, report


def derive_coverage(match, ledger: dict, failures: list[str]) -> dict:
    claim = ledger["current"]["coverage"]
    derived = {
        "covered": int(match.group(1)),
        "partial": int(match.group(2)),
        "uncovered": int(match.group(3)),
        "total": int(match.group(4)),
    }
    for field, value in derived.items():
        if claim.get(field) != value:
            failures.append(
                f"current.coverage.{field} says {claim.get(field)!r}; a fresh run of "
                f"{claim['derived_by']} over the named bundles re-derives {value}"
            )
    return derived


def derive_drivers(report, ledger: dict, failures: list[str]) -> dict:
    claim = ledger["current"]["drivers"]
    if report is None:
        failures.append(
            "the coverage run produced no JSON report, so driver rows cannot be re-derived"
        )
        return {}
    rows = report.get("driver_rows_detail") or []
    derived = {
        "covered": sum(1 for r in rows if r["status"] == "COVERED"),
        "partial": sum(1 for r in rows if r["status"] == "PARTIAL"),
        "total": len(rows),
    }
    for field, value in derived.items():
        if claim.get(field) != value:
            failures.append(
                f"current.drivers.{field} says {claim.get(field)!r}; the bound driver evidence "
                f"re-derives {value}"
            )
    return derived


# ---------------------------------------------------------------------- gates


def derive_gates(ledger: dict, failures: list[str]) -> dict:
    """The gate-state reducer, over evidence rather than over an assertion.

    Conservative and one-directional by design: it does not compute the exact
    state (a gate can be open for reasons no machine sees), it refuses the
    states the evidence cannot support. Owner-decision status is read from the
    registry the ledger names, so marking a decision resolved in the gate row
    alone changes nothing.
    """
    registry_rel = ledger.get("owner_decisions_registry")
    statuses: dict[str, str] = {}
    if registry_rel and (REPO / registry_rel).is_file():
        for entry in json.loads((REPO / registry_rel).read_text()).get("entries", []):
            statuses[entry.get("id")] = entry.get("status")
    elif registry_rel:
        failures.append(f"owner decision registry {registry_rel} is missing")

    derived = {}
    for gid, row in ledger["current"]["gates"].items():
        blockers = list(row.get("blockers") or []) + list(row.get("blocking_findings") or [])
        open_decisions = [
            d for d in (row.get("owner_decisions") or []) if statuses.get(d) == "OPEN"
        ]
        may_be_closed = not blockers and not open_decisions
        derived[gid] = {
            "state": row.get("state"),
            "blockers": len(blockers),
            "open_owner_decisions": open_decisions,
            "may_be_closed": may_be_closed,
        }
        if row.get("state") == "CLOSED" and not may_be_closed:
            failures.append(
                f"current.gates.{gid}: CLOSED, but {len(blockers)} blocker(s) and OPEN owner "
                f"decisions {open_decisions} are still recorded"
            )
        for d in row.get("owner_decisions") or []:
            if d not in statuses:
                failures.append(
                    f"current.gates.{gid}: names owner decision {d}, which the registry "
                    f"{registry_rel} does not contain"
                )
    return derived


# ----------------------------------------------------------------------- main


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument(
        "--only",
        action="append",
        choices=["coverage", "mode_q", "drivers", "gates"],
        default=None,
        help="re-derive only these facts (default: all)",
    )
    ap.add_argument("--ledger", type=pathlib.Path, default=LEDGER)
    ap.add_argument("--emit", action="store_true", help="print the DERIVED facts as JSON")
    args = ap.parse_args()

    try:
        ledger = json.loads(args.ledger.read_text())
    except Exception as error:
        print(f"LEDGER SEMANTIC VERIFY: FAIL - ledger unreadable: {error}")
        return 1
    if "current" not in ledger:
        print("LEDGER SEMANTIC VERIFY: FAIL - no canonical `current` section (R8-P0-02)")
        return 1

    wanted = set(args.only or ["coverage", "mode_q", "drivers", "gates"])
    failures: list[str] = []
    derived: dict = {}

    if "mode_q" in wanted:
        derived["mode_q"] = derive_mode_q(ledger, failures)
    if wanted & {"coverage", "drivers"}:
        match, report = coverage_run(ledger, failures)
        if match is not None and "coverage" in wanted:
            derived["coverage"] = derive_coverage(match, ledger, failures)
        if "drivers" in wanted:
            derived["drivers"] = derive_drivers(report, ledger, failures)
    if "gates" in wanted:
        derived["gates"] = derive_gates(ledger, failures)

    if args.emit:
        print(json.dumps(derived, indent=1))

    if failures:
        print("LEDGER SEMANTIC VERIFY: FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"LEDGER SEMANTIC VERIFY: PASS ({', '.join(sorted(wanted))} re-derived from evidence)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
