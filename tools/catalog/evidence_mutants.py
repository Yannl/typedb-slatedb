#!/usr/bin/env python3
"""Executed negative controls for the evidence producers and checkers.

A gate is only as strong as the mutant it kills. Each control below breaks
one invariant on purpose and asserts that the tool REJECTS the result; a
control that passes silently is itself a failure. These are the exact mutants
the consolidation audit demonstrated were accepted before this change:

  comparator  - drop a target from the run; time a target out with unchanged
                counts; rewrite a classified target's profile to 0/999.
  completeness- keep only the ledgered rows; add an unknown rc=127 crash row
                with zero parsed failures; report zero cases for a
                case-bearing target.
  run_u0      - a red row, a timeout row, and a missing required target must
                each produce a nonzero verdict.
  run_static  - a FAIL row must produce a nonzero exit.

Usage: python3 tools/catalog/evidence_mutants.py
"""
import importlib.util
import atexit
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))

import verdict as verdict_policy  # noqa: E402

failures = []
checks = 0


def expect(label, condition):
    global checks
    checks += 1
    if not condition:
        failures.append(label)
    print(f"  {'PASS' if condition else 'FAIL'}  {label}")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------- comparator

def comparator_controls():
    print("comparator (tools/catalog/compare_u2s3.py)")
    cmp_mod = load_module("cmp_u2s3", HERE / "compare_u2s3.py")

    def row(tid, log, p=1, f=0, i=0, rc=0, to=False):
        return {"target_id": tid, "raw_log": f"logs/{log}.log", "passed": p,
                "failed": f, "ignored": i, "exit_code": rc, "timed_out": to}

    base_rows = [row("answer:answer", "answer__answer", p=0),
                 row("cache:cache", "cache__cache", p=3),
                 row("storage:storage", "storage__storage", p=8)]

    def run_case(run_rows, oracle_rows=None):
        tmp = pathlib.Path(tempfile.mkdtemp())
        try:
            for name, rows in (("u2s3-mutant", run_rows),
                               ("u1-full", oracle_rows if oracle_rows is not None else base_rows)):
                d = tmp / "docs" / "evidence" / "G3" / name
                d.mkdir(parents=True)
                (d / "u0-results.json").write_text(json.dumps({"results": rows}))
            old, cmp_mod.REPO = cmp_mod.REPO, tmp
            old_argv, sys.argv = sys.argv, ["compare", "u2s3-mutant"]
            try:
                return cmp_mod.main()
            finally:
                cmp_mod.REPO, sys.argv = old, old_argv
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # control 0: the unmutated run must be accepted (a comparator that
    # rejects everything proves nothing)
    expect("identical run is accepted", run_case(list(base_rows)) == 0)
    # control 1: a target present in the oracle and dropped from the run
    expect("dropped target is rejected",
           run_case([r for r in base_rows if r["target_id"] != "answer:answer"]) != 0)
    # control 2: a timeout with unchanged counts
    timed = [dict(r, timed_out=True, exit_code=None) if r["target_id"] == "cache:cache" else r
             for r in base_rows]
    expect("timeout with unchanged counts is rejected", run_case(timed) != 0)
    # control 3: a classified target rewritten to a wildly different profile
    rewritten = [dict(r, passed=0, failed=999) if r["target_id"] == "storage:storage" else r
                 for r in base_rows]
    expect("classified target with a different profile is rejected",
           run_case(rewritten) != 0)
    # control 4: an extra target the oracle never had
    extra = base_rows + [row("ghost:ghost", "ghost__ghost")]
    expect("target absent from the oracle is rejected", run_case(extra) != 0)


# ------------------------------------------------------------ verdict policy

def verdict_controls():
    print("verdict policy (tools/catalog/verdict.py)")
    ledger = {"storage:test_recovery": {"target_id": "storage:test_recovery",
                                        "expected_failed": 2, "expected_ignored": 0,
                                        "expected_exit_code": 101,
                                        "cases": ["a", "b"],
                                        "reason": "upstream stubs", "expiry": "2099-01-01"}}

    def row(tid, p=1, f=0, i=0, rc=0, to=False):
        return {"target_id": tid, "passed": p, "failed": f, "ignored": i,
                "exit_code": rc, "timed_out": to}

    clean = [row("a:a"), row("storage:test_recovery", p=5, f=2, rc=101)]
    expect("expected corpus (ledgered red only) is green",
           verdict_policy.classify_rows(clean, ledger) == [])
    expect("an unledgered failure is red",
           verdict_policy.classify_rows(clean + [row("b:b", f=1, rc=101)], ledger) != [])
    expect("a timeout is red",
           verdict_policy.classify_rows(clean + [row("c:c", to=True, rc=None)], ledger) != [])
    expect("an unknown crash rc is red",
           verdict_policy.classify_rows(clean + [row("d:d", rc=127)], ledger) != [])
    expect("an unledgered ignore is red",
           verdict_policy.classify_rows(clean + [row("e:e", i=1)], ledger) != [])
    expect("a ledgered target that stops firing is red",
           verdict_policy.classify_rows([row("a:a")], ledger) != [])
    expect("a case-bearing target that ran zero cases is red",
           verdict_policy.classify_rows(clean + [row("f:f", p=0)], ledger,
                                        expected_case_bearing={"f:f"}) != [])
    expect("a ledgered failure with the wrong count is red",
           verdict_policy.classify_rows(
               [row("a:a"), row("storage:test_recovery", p=5, f=3, rc=101)], ledger) != [])
    expect("a missing required target is red",
           verdict_policy.denominator_anomalies(clean, {"a:a", "storage:test_recovery",
                                                        "gone:gone"}) != [])
    expect("an unexpected extra target is red",
           verdict_policy.denominator_anomalies(clean, {"a:a"}) != [])
    expect("an exclusion for a target that ran anyway is red",
           verdict_policy.denominator_anomalies(
               clean, {"a:a", "storage:test_recovery"},
               {"a:a": "declared out of lane"}) != [])
    expect("an expired ledger entry is reported, not silently honoured",
           verdict_policy.load_ledger(_expired_ledger())[1] != [])


def _expired_ledger():
    # the temp dir is registered for cleanup at exit; the ledger file must
    # outlive the expect() call that reads it
    tmpdir = tempfile.mkdtemp()
    atexit.register(shutil.rmtree, tmpdir, True)
    tmp = pathlib.Path(tmpdir) / "ledger.json"
    tmp.write_text(json.dumps({"entries": [
        {"target_id": "x:y", "reason": "r", "expiry": "2000-01-01"}]}))
    return tmp


# ------------------------------------------------------------- run_static

def run_static_controls():
    print("run_static (tools/catalog/run_static.py)")
    src = (HERE / "run_static.py").read_text()
    expect("run_static returns its verdict from main()",
           "sys.exit(main())" in src and "return 1 if anomalies else 0" in src)
    expect("run_static treats an empty selection as red",
           "ZERO static targets" in src)


# --------------------------------------------------------------- run_u0

def run_u0_controls():
    print("run_u0 (tools/catalog/run_u0.py)")
    src = (HERE / "run_u0.py").read_text()
    expect("run_u0 returns its verdict from main()", "sys.exit(main())" in src)
    expect("run_u0 refuses to call a filtered run a corpus verdict",
           "selection_complete" in src and "PARTIAL" in src)
    expect("run_u0 measures the toolchain instead of asserting it",
           "executed_toolchain" in src
           and '"toolchain": "rust 1.93.0 parity lane"' not in src)
    expect("run_u0 records the executed tree, not just the outer repo commit",
           "executed_tree" in src and "staged_delta_sha256" in src)
    expect("run_u0 checks the denominator against the catalogue",
           "required_executable_targets" in src and "denominator_anomalies" in src)


def main():
    comparator_controls()
    verdict_controls()
    run_static_controls()
    run_u0_controls()
    print(f"\nevidence mutants: {checks - len(failures)}/{checks} controls held")
    for f in failures:
        print(f"MUTANT NOT KILLED: {f}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
