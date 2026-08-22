#!/usr/bin/env python3
"""Semantic mutants for the ledger's current facts (R8-P0-02).

`ledger_mutants.py` proves the SCHEMA lint: ids, enums, transitions, rendered
drift, and — since round 8 — the single-canonical-home rule. Those are cheap and
they run on every commit.

They are not enough, and the round-8 audit showed exactly why: the audited
ledger asserted `13,723 / 23,138` in one place and `914 / 23,138` in another,
and sixteen structural mutants passed it. A number typed into JSON is
structurally indistinguishable from a number that was measured. The only thing
that can tell them apart is re-running the measurement.

So this suite is the model of static-mutant control 11, applied to the truth
plane: each mutant edits the ledger the way a DILIGENT FORGER would — updating
every shallower field so nothing is internally inconsistent — and then requires
`verify_ledger_semantics.py` to catch it by RE-DERIVING the value from the
evidence the ledger itself names.

It is deliberately slow (each coverage mutant re-verifies every named bundle),
which is why it is a separate entry point from the schema lint.

usage:
  python3 tools/ledger/ledger_semantic_mutants.py
  python3 tools/ledger/ledger_semantic_mutants.py --fast   # skip coverage mutants
"""

import argparse
import copy
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
LEDGER_REL = "docs/ledger/gates.json"
VERIFIER = REPO / "tools" / "ledger" / "verify_ledger_semantics.py"


def verify(ledger_path: pathlib.Path, only: list[str]) -> tuple[int, str]:
    argv = [sys.executable, str(VERIFIER), "--ledger", str(ledger_path)]
    for o in only:
        argv += ["--only", o]
    proc = subprocess.run(argv, capture_output=True, text=True, cwd=REPO, timeout=7200)
    return proc.returncode, proc.stdout + proc.stderr


# ------------------------------------------------------------------- mutations
#
# Each takes the parsed ledger and mutates it IN PLACE. Every one leaves the
# document internally consistent — that is the point: a forger who left an
# obvious inconsistency would already be caught by the schema lint.


def m_gate_state_in_one_projection(ledger):
    """Report mutant 1: change G0 in only one projection.

    With `current` as the single home there IS only one projection, so the lie
    has to be told there — and the reducer then contradicts it against the
    gate's own recorded blockers.
    """
    ledger["current"]["gates"]["G0"]["state"] = "CLOSED"


def m_coverage_forged_down(ledger):
    """Report mutant 2: change 13,723 to 914, updating every shallow copy.

    There is no shallow copy left to update — the guarded-pattern rule removed
    them — so the forgery is confined to the canonical field, and only a fresh
    coverage run over the named bundles can contradict it.
    """
    cov = ledger["current"]["coverage"]
    moved = cov["covered"] - 914
    cov["covered"] = 914
    cov["uncovered"] += moved  # keep the split accounting for the denominator


def m_coverage_split_broken(ledger):
    """Report mutant 3: change uncovered without preserving the identity."""
    ledger["current"]["coverage"]["uncovered"] += 100


def m_mode_q_declared_absent(ledger):
    """Report mutant 4: declare Mode-Q absent while the bound bundle validates."""
    ledger["current"]["mode_q"]["state"] = "ABSENT"


def m_driver_row_status_forged(ledger):
    """Report mutant 5: change a driver row status without changing evidence."""
    ledger["current"]["drivers"]["covered"] = 6
    ledger["current"]["drivers"]["partial"] = 0


def m_mode_q_root_forged(ledger):
    """Report mutant 6: forge every shallower field, leave the evidence root.

    The bundle root recorded in the ledger is changed to a well-formed digest
    that nothing computes to. Nothing else in the document disagrees.
    """
    ledger["current"]["mode_q"]["bundle_root"] = "0" * 64


def m_older_coverage_bundle(ledger):
    """Report mutant 7: point at a valid but OLDER coverage bundle.

    `u1-full-1` is swapped for `u1-http-2`'s sibling set minus one lane — a
    smaller, perfectly valid evidence set — while the recorded numbers stay.
    """
    cov = ledger["current"]["coverage"]
    cov["leaf_bundles"] = [b for b in cov["leaf_bundles"] if not b.endswith("u2-full-1")]


def m_owner_decision_resolved_only_here(ledger):
    """Report mutant 8: mark an OPEN owner decision resolved only in the gate.

    The gate reducer reads decision status from the REGISTRY, so dropping the
    reference here cannot resolve anything — and naming a decision the registry
    does not carry is itself refused.
    """
    ledger["current"]["gates"]["G1"]["owner_decisions"] = ["OD-021-RESOLVED"]


MUTANTS = [
    (
        "gate-state-forged-against-its-own-blockers",
        m_gate_state_in_one_projection,
        ["gates"],
        "CLOSED, but",
    ),
    (
        "owner-decision-resolved-only-in-the-gate-row",
        m_owner_decision_resolved_only_here,
        ["gates"],
        "does not contain",
    ),
    (
        "mode-q-declared-absent-while-its-bundle-validates",
        m_mode_q_declared_absent,
        ["mode_q"],
        "validate_modeq.py re-derives",
    ),
    (
        "mode-q-root-forged-with-every-shallow-field-consistent",
        m_mode_q_root_forged,
        ["mode_q"],
        "the bound bundle says",
    ),
    (
        "coverage-split-does-not-account-for-the-denominator",
        m_coverage_split_broken,
        ["coverage"],
        "re-derives",
    ),
    (
        "coverage-forged-down-to-the-round-6-numerator",
        m_coverage_forged_down,
        ["coverage"],
        "re-derives 13723",
    ),
    (
        "coverage-claimed-from-an-older-smaller-bundle-set",
        m_older_coverage_bundle,
        ["coverage"],
        "re-derives",
    ),
    (
        "driver-rows-forged-against-their-bound-evidence",
        m_driver_row_status_forged,
        ["drivers"],
        "the bound driver evidence re-derives",
    ),
]

# Which mutants need the slow coverage re-derivation.
SLOW = {"coverage", "drivers"}


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument(
        "--fast",
        action="store_true",
        help="skip the mutants that need a full coverage re-derivation",
    )
    args = ap.parse_args()

    pristine = json.loads((REPO / LEDGER_REL).read_text())
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="ledger-semantic-mutants-"))
    killed, survived, skipped = 0, [], []
    try:
        # baseline: the real ledger must VERIFY, or the harness proves nothing
        baseline = tmp / "baseline.json"
        baseline.write_text(json.dumps(pristine, indent=1) + "\n")
        only_all = sorted({o for _n, _m, o, _e in MUTANTS for o in o})
        if args.fast:
            only_all = [o for o in only_all if o not in SLOW]
        rc, out = verify(baseline, only_all)
        if rc != 0:
            print("HARNESS BROKEN: the unmutated ledger fails semantic verification:\n" + out)
            return 1
        print(f"  BASELINE the real ledger re-derives cleanly ({', '.join(only_all)})")

        for name, mutate, only, needle in MUTANTS:
            if args.fast and set(only) & SLOW:
                skipped.append(name)
                print(f"  SKIPPED  {name} (--fast: needs a coverage re-derivation)")
                continue
            ledger = copy.deepcopy(pristine)
            mutate(ledger)
            path = tmp / f"{name}.json"
            path.write_text(json.dumps(ledger, indent=1) + "\n")
            rc, out = verify(path, only)
            if rc == 0:
                survived.append(f"{name} — the verifier ACCEPTED it")
                print(f"  SURVIVED {name}")
            elif needle not in out:
                survived.append(f"{name} — rejected, but not for the expected reason")
                print(f"  KILLED*  {name} (expected {needle!r})")
                print(f"           got: {out.strip().splitlines()[-1][:200]}")
            else:
                killed += 1
                print(f"  KILLED   {name}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    total = len(MUTANTS) - len(skipped)
    print(
        f"\nledger semantic mutants: {killed}/{total} killed"
        + (f" ({len(survived)} SURVIVED)" if survived else "")
        + (f", {len(skipped)} skipped by --fast" if skipped else "")
    )
    for s in survived:
        print(f"SURVIVED: {s}", file=sys.stderr)
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
