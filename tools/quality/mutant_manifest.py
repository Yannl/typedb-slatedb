#!/usr/bin/env python3
"""Run every executed mutant suite and record ONE normalized manifest (R8-P1-06).

The round-8 audit's item 5: "Convert critical mutant suites into collected tests
or produce one normalized manifest proving they ran."

This repository's strongest controls are not unit tests. They are mutant
suites: each takes a REAL sealed evidence bundle, applies exactly one mutation
the way a diligent forger would — refreshing every shallower binding so nothing
is left obviously inconsistent — and then runs the independent verifier as a
real subprocess, requiring a nonzero exit that names the defect. A mutant that
survives is a verifier that would accept a forgery.

The problem the audit named is that they were invoked ad hoc. Nothing bound
their verdicts to a commit, and a suite that was never run looked exactly like
one that passed. This produces that binding: one manifest, per suite, with the
command, the exit code, the killed/survived/not-applicable counts and the
commit — and it FAILS if any suite fails or if any suite could not run at all.

`--fast` skips the suites whose subject is an expensive re-derivation, so the
inner loop can still run the cheap ones; the manifest records which were
skipped, because "we did not run it" must never read as "it held".

usage:
  python3 tools/quality/mutant_manifest.py
  python3 tools/quality/mutant_manifest.py --fast
"""

import argparse
import json
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
OUT = REPO / "artifacts" / "quality" / "python-mutants.json"

# (id, argv, slow?) — every executed mutant suite in the repository.
SUITES = [
    ("ledger.schema", ["tools/ledger/ledger_mutants.py"], False),
    ("ledger.semantic", ["tools/ledger/ledger_semantic_mutants.py"], True),
    ("static.leaf", ["tools/qualification/static_mutants.py"], False),
    ("cucumber.leaf", ["tools/qualification/cucumber_mutants.py"], True),
    ("leaf", ["tools/qualification/leaf_mutants.py"], True),
    ("modeq", ["tools/modeq/modeq_mutants.py"], False),
    ("drivers", ["tools/evidence/verify_drivers.py", "--mutants"], True),
    # R8-P1-07: the environment model's own negative controls. Slow, because
    # each mutant builds a real denied environment (a mount namespace, a
    # dropped capability, a virtualenv) rather than flipping a test hook.
    ("capability", ["tools/quality/capability_mutants.py"], True),
]

# The shapes these suites print their tallies in. Deliberately several, because
# the suites were written independently and normalising them by EDITING them
# would be a bigger change than reading them.
TALLY_PATTERNS = [
    re.compile(r"(?P<killed>\d+)\s*/\s*(?P<total>\d+)\s+(?:controls?\s+)?(?:held|killed)"),
    re.compile(r"mutants:\s*(?P<killed>\d+)\s*/\s*(?P<total>\d+)\s+killed"),
    # "26 mutants executed, 25 killed" — the DENOMINATOR comes first here, and
    # naming the groups the other way round (as this pattern first did) reports
    # a suite with a survivor as 26/26.
    re.compile(r"(?P<total>\d+)\s+mutants?\s+executed,\s*(?P<killed>\d+)\s+killed"),
    # "modeq mutants: all 11 killed" — no denominator of its own, because "all"
    # IS the denominator.
    re.compile(r"all\s+(?P<killed>\d+)\s+killed"),
]
SURVIVED_RE = re.compile(r"\((?P<survived>\d+)\s+SURVIVED", re.I)
NA_RE = re.compile(r"(?P<na>\d+)\s+NOT[ _]APPLICABLE", re.I)


def head_sha() -> str:
    r = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=REPO)
    return r.stdout.strip() if r.returncode == 0 else "<unknown>"


def run_suite(argv: list[str]) -> dict:
    script = REPO / argv[0]
    if not script.is_file():
        return {"status": "ABSENT", "detail": f"{argv[0]} does not exist"}
    proc = subprocess.run(
        [sys.executable, str(script), *argv[1:]],
        capture_output=True,
        text=True,
        cwd=REPO,
        timeout=7200,
    )
    text = proc.stdout + proc.stderr
    killed = total = survived = na = None
    for pattern in TALLY_PATTERNS:
        m = pattern.search(text)
        if m:
            killed = int(m.group("killed"))
            # "all N killed" states the count once: killed IS the denominator.
            total = int(m.group("total")) if "total" in m.groupdict() else killed
            break
    if m := SURVIVED_RE.search(text):
        survived = int(m.group("survived"))
    if m := NA_RE.search(text):
        na = int(m.group("na"))
    return {
        "status": "PASS" if proc.returncode == 0 else "FAIL",
        "exit_code": proc.returncode,
        "killed": killed,
        "total": total,
        "survived": survived,
        "not_applicable": na,
        "tail": text.strip().splitlines()[-1][:300] if text.strip() else "",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument(
        "--fast", action="store_true", help="skip the slow suites (recorded as SKIPPED)"
    )
    args = ap.parse_args()

    results = {}
    failures = []
    for suite_id, argv, slow in SUITES:
        command = "python3 " + " ".join(argv)
        if slow and args.fast:
            results[suite_id] = {"status": "SKIPPED", "command": command, "why": "--fast"}
            print(f"  SKIPPED  {suite_id:18} ({command})")
            continue
        print(f"  running  {suite_id:18} ({command}) ...")
        row = run_suite(argv)
        row["command"] = command
        results[suite_id] = row
        tally = (
            f"{row.get('killed')}/{row.get('total')} killed"
            if row.get("total") is not None
            else "no tally parsed"
        )
        print(f"  {row['status']:8} {suite_id:18} {tally}")
        if row["status"] != "PASS":
            failures.append(f"{suite_id}: {row['status']} — {row.get('detail') or row.get('tail')}")
        elif row.get("total") is None:
            # A suite whose tally cannot be read has not been PROVEN to have
            # run its controls: a zero-mutant run also exits 0. The manifest
            # exists to make "they ran, and this many held" checkable, so an
            # unparsable tally is a manifest failure, not a quiet pass.
            row["status"] = "UNCOUNTED"
            failures.append(
                f"{suite_id}: exited 0 but printed no tally this manifest can read, so the number "
                f"of controls that held is unknown — add its shape to TALLY_PATTERNS"
            )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(
            {
                "schema": "typedb-python-mutant-manifest-v1",
                "head_sha": head_sha(),
                "fast": args.fast,
                "suites": results,
            },
            indent=1,
            sort_keys=True,
        )
        + "\n"
    )
    ran = sum(1 for r in results.values() if r["status"] == "PASS")
    skipped = sum(1 for r in results.values() if r["status"] == "SKIPPED")
    print(f"\nmutant manifest: {ran}/{len(SUITES) - skipped} suite(s) held; {skipped} skipped")
    print(f"manifest: {OUT.relative_to(REPO)}")
    if failures:
        for f in failures:
            print(f"MUTANT MANIFEST: FAIL — {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
