#!/usr/bin/env python3
"""One fail-closed verdict policy, shared by every evidence producer.

The defect class this module exists to kill: a producer that writes red rows
into an evidence file and then exits zero, so CI (and a reader skimming the
process result) records a green run over a red corpus. Both current producers
had it - `run_static.py` wrote FAIL/ERROR rows with rc=0, and `run_u0.py` had
no terminal verdict at all.

The rules are deliberately few and deliberately unconditional:

  1. A run is GREEN only if every row is accounted for by policy.
  2. The ONLY policy that may tolerate an anomaly is the committed
     flake/exclusion ledger (`docs/evidence/flake-ledger.json`), matched by
     exact target id AND exact counts AND exact exit code.
  3. Anything not matched - a failure, an ignore, a nonzero exit, a timeout,
     a crash rc, a required target that produced no row, a required target
     that produced a row with zero cases - is RED.
  4. There is no flag that turns a red verdict green. A partial selection
     narrows the *denominator* (and says so in the verdict), never the bar.

`verdict_exit_code()` is what a producer returns from `main()`.
"""
import datetime
import json
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[2]
LEDGER = REPO / "docs" / "evidence" / "flake-ledger.json"


def load_ledger(path=None):
    """target_id -> entry. Expired entries are dropped AND reported: an
    expired exclusion must stop the line, never silently keep excluding."""
    path = path or LEDGER
    problems = []
    entries = {}
    if not path.exists():
        return entries, problems
    for e in json.loads(path.read_text()).get("entries", []):
        tid = e.get("target_id")
        if not tid:
            problems.append("ledger: entry with no target_id")
            continue
        if not e.get("reason"):
            problems.append(f"ledger: {tid} has no reason - exclusions must be explained")
        expiry = e.get("expiry")
        if not expiry:
            problems.append(f"ledger: {tid} has no expiry - open-ended exclusions are forbidden")
            continue
        if datetime.date.fromisoformat(expiry) < datetime.date.today():
            problems.append(f"ledger: {tid} expired ({expiry}) - re-justify or retire it")
            continue
        entries[tid] = e
    return entries, problems


def _cases(row):
    return (row.get("passed", 0) + row.get("failed", 0)
            + row.get("ignored", 0) + row.get("measured", 0))


def classify_rows(results, ledger, expected_case_bearing=None):
    """Anomaly list for a set of executable result rows.

    `expected_case_bearing` is the set of target ids the catalogue says
    contain at least one leaf case. A row for such a target that reports zero
    cases is red: it is indistinguishable from a binary that silently ran
    nothing, which is exactly how a corpus shrinks without anyone noticing.
    """
    anomalies = []
    matched = set()
    for r in sorted(results, key=lambda x: x["target_id"]):
        tid = r["target_id"]
        entry = ledger.get(tid)
        if entry is not None:
            matched.add(tid)
        exp_failed = entry.get("expected_failed", 0) if entry else 0
        exp_ignored = entry.get("expected_ignored", 0) if entry else 0
        exp_rc = entry.get("expected_exit_code", 0) if entry else 0

        if r.get("timed_out"):
            anomalies.append(f"{tid}: TIMED OUT - never ledgerable, always a defect")
            continue
        rc = r.get("exit_code")
        if rc != exp_rc:
            anomalies.append(
                f"{tid}: exit code {rc!r} but policy expects {exp_rc!r}"
                + ("" if entry else " (no ledger entry)"))
        failed, ignored = r.get("failed", 0), r.get("ignored", 0)
        if failed != exp_failed:
            anomalies.append(
                f"{tid}: {failed} failed case(s), policy expects {exp_failed}"
                + ("" if entry else " (no ledger entry)"))
        if ignored != exp_ignored:
            anomalies.append(
                f"{tid}: {ignored} ignored case(s), policy expects {exp_ignored}"
                + ("" if entry else " (no ledger entry)"))
        if entry and entry.get("cases") is not None:
            # the ledger names the exact cases; their count must agree with
            # the counts it also declares, or the entry is self-inconsistent
            if len(entry["cases"]) != exp_failed + exp_ignored:
                anomalies.append(
                    f"ledger: {tid} names {len(entry['cases'])} case(s) but declares "
                    f"{exp_failed} failed + {exp_ignored} ignored")
        if expected_case_bearing is not None and tid in expected_case_bearing \
                and _cases(r) == 0:
            anomalies.append(
                f"{tid}: ran to completion with ZERO cases although the catalogue "
                f"records leaf cases for it - the corpus silently shrank here")
    for tid in sorted(set(ledger) - matched):
        anomalies.append(
            f"ledger: entry for {tid} matched no row in this run - stale "
            f"exclusions must be retired, not carried")
    return anomalies


def denominator_anomalies(results, required_target_ids, declared_exclusions=None):
    """Exact set equality between what had to run and what did run."""
    declared = dict(declared_exclusions or {})
    ran = {r["target_id"] for r in results}
    required = set(required_target_ids)
    out = []
    for tid in sorted(required - ran):
        reason = declared.get(tid)
        if not reason:
            out.append(f"denominator: required target {tid} produced NO result row")
    for tid in sorted(ran - required):
        out.append(f"denominator: {tid} produced a result row but is not a required target")
    for tid in sorted(declared):
        if tid in ran:
            out.append(f"denominator: {tid} is declared not-executed but produced a row anyway")
    # Whether an exclusion's SUBJECT resolves to a real catalogue target is a
    # catalogue question, not a run question: validate_catalog.py owns it, and
    # duplicating it here only produced false anomalies for targets that are
    # legitimately absent from the executable denominator.
    return out


def verdict_exit_code(anomalies, complete_selection, out_dir=None, extra=None):
    """Write verdict.json (+ a COMPLETE marker on green) and return 0/1."""
    green = not anomalies and complete_selection
    verdict = {
        "green": green,
        "complete_selection": complete_selection,
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        **(extra or {}),
    }
    if out_dir is not None:
        out_dir = pathlib.Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "verdict.json").write_text(json.dumps(verdict, indent=1) + "\n")
        marker = out_dir / "COMPLETE"
        if green:
            marker.write_text(
                json.dumps({"green": True,
                            "written_by": "tools/catalog/verdict.py"}, indent=1) + "\n")
        elif marker.exists():
            # a re-run that goes red must not leave a stale green marker behind
            marker.unlink()
    return 0 if green else 1
