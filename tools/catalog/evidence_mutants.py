#!/usr/bin/env python3
"""Executed negative controls for the evidence producers and checkers.

A gate is only as strong as the mutant it kills. Each control below breaks
one invariant on purpose and asserts that the tool REJECTS the result; a
control that passes silently is itself a failure.

The E-P0-06/07/10 audit proved the earlier controls that merely GREPPED
source strings ("does run_u0.py contain 'executed_tree'?") were pseudo
evidence: every behavioral mutation of the archived bundle still re-derived
GREEN. Those grep controls are gone. In their place, the bundle controls
below run the REAL CLI (`run_u0.py --verdict-only`) as a subprocess against
a temp copy of the sealed archive docs/evidence/G3/u2s3-full-3 with exactly
one mutation applied, and require a nonzero exit naming the defect:

  bundle     - delete a log; truncate a log (reparse mismatch); duplicate a
               row; reduce a nonzero passed count; forge a log path; forge a
               provenance digest in the results JSON; ghost ledger cases;
               wrong-profile ledger; duplicate ledger target; stale COMPLETE
               root after tampering; a sealed dir refuses live re-runs.
  comparator - drop a target from the run; time a target out with unchanged
               counts; rewrite a classified target's profile to 0/999.
  verdict    - unledgered failure/ignore/timeout/crash, stale ledger entry,
               zero-case case-bearing target, denominator drift.
  common     - two catalogue targets collapsing onto one runner row id.

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
        return {
            "target_id": tid,
            "raw_log": f"logs/{log}.log",
            "passed": p,
            "failed": f,
            "ignored": i,
            "exit_code": rc,
            "timed_out": to,
        }

    base_rows = [
        row("answer:answer", "answer__answer", p=0),
        row("cache:cache", "cache__cache", p=3),
        row("storage:storage", "storage__storage", p=8),
    ]

    def run_case(run_rows, oracle_rows=None):
        tmp = pathlib.Path(tempfile.mkdtemp())
        try:
            for name, rows in (
                ("u2s3-mutant", run_rows),
                ("u1-full", oracle_rows if oracle_rows is not None else base_rows),
            ):
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
    expect(
        "dropped target is rejected",
        run_case([r for r in base_rows if r["target_id"] != "answer:answer"]) != 0,
    )
    # control 2: a timeout with unchanged counts
    timed = [
        dict(r, timed_out=True, exit_code=None) if r["target_id"] == "cache:cache" else r
        for r in base_rows
    ]
    expect("timeout with unchanged counts is rejected", run_case(timed) != 0)
    # control 3: a classified target rewritten to a wildly different profile
    rewritten = [
        dict(r, passed=0, failed=999) if r["target_id"] == "storage:storage" else r
        for r in base_rows
    ]
    expect("classified target with a different profile is rejected", run_case(rewritten) != 0)
    # control 4: an extra target the oracle never had
    extra = base_rows + [row("ghost:ghost", "ghost__ghost")]
    expect("target absent from the oracle is rejected", run_case(extra) != 0)


# ------------------------------------------------------------ verdict policy


def verdict_controls():
    print("verdict policy (tools/catalog/verdict.py)")
    ledger = {
        "storage:test_recovery": {
            "target_id": "storage:test_recovery",
            "expected_failed": 2,
            "expected_ignored": 0,
            "expected_exit_code": 101,
            "cases": ["a", "b"],
            "reason": "upstream stubs",
            "expiry": "2099-01-01",
        }
    }

    def row(tid, p=1, f=0, i=0, rc=0, to=False):
        return {
            "target_id": tid,
            "passed": p,
            "failed": f,
            "ignored": i,
            "exit_code": rc,
            "timed_out": to,
        }

    clean = [row("a:a"), row("storage:test_recovery", p=5, f=2, rc=101)]
    expect(
        "expected corpus (ledgered red only) is green",
        verdict_policy.classify_rows(clean, ledger) == [],
    )
    expect(
        "an unledgered failure is red",
        verdict_policy.classify_rows(clean + [row("b:b", f=1, rc=101)], ledger) != [],
    )
    expect(
        "a timeout is red",
        verdict_policy.classify_rows(clean + [row("c:c", to=True, rc=None)], ledger) != [],
    )
    expect(
        "an unknown crash rc is red",
        verdict_policy.classify_rows(clean + [row("d:d", rc=127)], ledger) != [],
    )
    expect(
        "an unledgered ignore is red",
        verdict_policy.classify_rows(clean + [row("e:e", i=1)], ledger) != [],
    )
    expect(
        "a ledgered target that stops firing is red",
        verdict_policy.classify_rows([row("a:a")], ledger) != [],
    )
    expect(
        "a case-bearing target that ran zero cases is red",
        verdict_policy.classify_rows(
            clean + [row("f:f", p=0)], ledger, expected_case_bearing={"f:f"}
        )
        != [],
    )
    expect(
        "a ledgered failure with the wrong count is red",
        verdict_policy.classify_rows(
            [row("a:a"), row("storage:test_recovery", p=5, f=3, rc=101)], ledger
        )
        != [],
    )
    expect(
        "a missing required target is red",
        verdict_policy.denominator_anomalies(clean, {"a:a", "storage:test_recovery", "gone:gone"})
        != [],
    )
    expect(
        "an unexpected extra target is red",
        verdict_policy.denominator_anomalies(clean, {"a:a"}) != [],
    )
    expect(
        "an exclusion for a target that ran anyway is red",
        verdict_policy.denominator_anomalies(
            clean, {"a:a", "storage:test_recovery"}, {"a:a": "declared out of lane"}
        )
        != [],
    )
    expect(
        "an expired ledger entry is reported, not silently honoured",
        verdict_policy.load_ledger(_expired_ledger())[1] != [],
    )


def _expired_ledger():
    # the temp dir is registered for cleanup at exit; the ledger file must
    # outlive the expect() call that reads it
    tmpdir = tempfile.mkdtemp()
    atexit.register(shutil.rmtree, tmpdir, True)
    tmp = pathlib.Path(tmpdir) / "ledger.json"
    tmp.write_text(
        json.dumps({"entries": [{"target_id": "x:y", "reason": "r", "expiry": "2000-01-01"}]})
    )
    return tmp


# ----------------------------------------------------- catalogue join (E-P0-03)


def join_controls():
    print("catalogue join (tools/catalog/common.py)")
    import common

    base = {
        "targets": [
            {
                "target_id": "cargo:x:unit:t",
                "origin": "CARGO",
                "cargo_package": "x",
                "cargo_target": "t",
            },
            {
                "target_id": "cargo:x:integration:t",
                "origin": "CARGO",
                "cargo_package": "x",
                "cargo_target": "t",
            },
        ],
        "leaf_cases": [],
        "exclusions": [],
    }
    try:
        common.required_executable_targets(base)
        collided = False
    except SystemExit:
        collided = True
    expect("two catalogue targets collapsing onto one runner row id stop the line", collided)
    ok = dict(base)
    ok["targets"] = [base["targets"][0]]
    try:
        required, _, _ = common.required_executable_targets(ok)
        expect("a collision-free catalogue still joins", required == {"x:t"})
    except SystemExit:
        expect("a collision-free catalogue still joins", False)


# ----------------------------------------------- bundle (E-P0-06/07/10, REAL CLI)

ARCHIVE_REL = pathlib.Path("docs") / "evidence" / "G3" / "u2s3-full-3"


def bundle_controls():
    """Run the REAL `run_u0.py --verdict-only` CLI as a subprocess against a
    temp copy of the sealed archive, one mutation per control. Every mutation
    that regenerates a consumed file also regenerates the sidecar manifest
    (hash + root) the way a diligent forger would - each control then proves
    the NEXT layer still catches it. Nothing here greps source: a control
    holds only if the actual process exits nonzero and names the defect."""
    print("bundle (REAL CLI: run_u0.py --verdict-only over a mutated archive copy)")
    import verdict as vp

    pristine = pathlib.Path(tempfile.mkdtemp(prefix="mutant-pristine-"))
    atexit.register(shutil.rmtree, pristine, True)
    (pristine / "tools" / "catalog").mkdir(parents=True)
    for f in ("common.py", "verdict.py", "run_u0.py"):
        shutil.copy2(HERE / f, pristine / "tools" / "catalog" / f)
    (pristine / "docs" / "evidence" / "G1").mkdir(parents=True)
    shutil.copy2(
        REPO / "docs" / "evidence" / "flake-ledger.json",
        pristine / "docs" / "evidence" / "flake-ledger.json",
    )
    shutil.copy2(
        REPO / "docs" / "evidence" / "G1" / "upstream-test-catalog.json",
        pristine / "docs" / "evidence" / "G1" / "upstream-test-catalog.json",
    )
    src_archive = REPO / ARCHIVE_REL
    dst_archive = pristine / ARCHIVE_REL
    dst_archive.mkdir(parents=True)
    for f in src_archive.iterdir():
        if f.is_file():  # logs, results, manifest, markers; never iso/
            shutil.copy2(f, dst_archive / f.name)

    def run_cli(tree, live=False):
        argv = [
            sys.executable,
            str(tree / "tools" / "catalog" / "run_u0.py"),
            "--out",
            str(tree / ARCHIVE_REL),
        ]
        if not live:
            argv.insert(2, "--verdict-only")
        p = subprocess.run(argv, capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr

    def refresh_manifest(tree, log_names=()):
        """What a diligent forger does after tampering: recompute the sidecar
        hashes and root so only DEEPER bindings can still catch the edit."""
        ad = tree / ARCHIVE_REL
        m = json.loads((ad / "log-manifest.json").read_text())
        for name in log_names:
            m["logs"][name] = vp.common.sha256_file(ad / name)
        rows = json.loads((ad / "u0-results.json").read_text())["results"]
        m["bundle_root"], _ = vp.compute_bundle_root(
            ad, rows, ledger_path=tree / "docs" / "evidence" / "flake-ledger.json", repo=tree
        )
        (ad / "log-manifest.json").write_text(json.dumps(m, indent=1) + "\n")

    def control(label, mutate, needle=None, live=False, expect_green=False):
        tree = pathlib.Path(tempfile.mkdtemp(prefix="mutant-"))
        try:
            shutil.copytree(pristine, tree, dirs_exist_ok=True)
            if mutate:
                mutate(tree)
            rc, out = run_cli(tree, live=live)
            if expect_green:
                held = rc == 0
            else:
                held = rc != 0 and (needle is None or needle in out)
            expect(label, held)
            if not held:
                print(f"    rc={rc} output tail: {out[-600:]}", file=sys.stderr)
        finally:
            shutil.rmtree(tree, ignore_errors=True)

    def edit_rows(tree, fn):
        rf = tree / ARCHIVE_REL / "u0-results.json"
        data = json.loads(rf.read_text())
        fn(data["results"])
        rf.write_text(json.dumps(data, indent=1) + "\n")

    def edit_ledger(tree, fn):
        lf = tree / "docs" / "evidence" / "flake-ledger.json"
        data = json.loads(lf.read_text())
        fn(data["entries"])
        lf.write_text(json.dumps(data, indent=2) + "\n")

    # control of controls: the unmutated archive must re-derive GREEN, or
    # every rejection below proves nothing
    control("intact archive copy re-derives GREEN", None, expect_green=True)

    control(
        "deleted raw log is rejected",
        lambda t: (t / ARCHIVE_REL / "storage__storage.log").unlink(),
        needle="does not exist",
    )

    def truncate(tree):
        log = tree / ARCHIVE_REL / "storage__storage.log"
        log.write_text("".join(log.read_text(errors="replace").splitlines(True)[:5]))
        refresh_manifest(tree, ["storage__storage.log"])

    control(
        "truncated log (manifest regenerated) fails the count reparse",
        truncate,
        needle="reparses to",
    )

    def duplicate_row(tree):
        edit_rows(tree, lambda rows: rows.append(dict(rows[0])))
        refresh_manifest(tree)

    control("duplicated result row is rejected", duplicate_row, needle="duplicate result row")

    def reduce_passed(tree):
        def fn(rows):
            r = next(r for r in rows if r["passed"] > 1)
            r["passed"] = 1

        edit_rows(tree, fn)
        refresh_manifest(tree)

    control(
        "reduced nonzero passed count fails the count reparse", reduce_passed, needle="reparses to"
    )

    def forge_log_path(tree):
        edit_rows(
            tree, lambda rows: rows[0].__setitem__("raw_log", str(ARCHIVE_REL / "ghost__ghost.log"))
        )
        refresh_manifest(tree)

    control("forged (nonexistent) log path is rejected", forge_log_path, needle="does not exist")

    def forge_provenance(tree):
        # E-P0-10 class: forged executable digest. The binary is gone (reaped),
        # so the digest itself cannot be re-measured; what CAN be caught is the
        # edit of the sealed results file - its hash is inside the bundle root.
        edit_rows(tree, lambda rows: rows[0].__setitem__("executable_sha256", "0" * 64))
        # deliberately NO refresh: the forger who edits only the JSON

    control(
        "forged executable digest breaks the recorded bundle root",
        forge_provenance,
        needle="sidecar manifest root",
    )

    def ghost_cases(tree):
        def fn(entries):
            e = next(e for e in entries if e["target_id"] == "storage:test_recovery")
            e["fingerprint"]["failed"] = ["ghost_case_one", "ghost_case_two"]
            e["cases"] = ["ghost_case_one", "ghost_case_two"]

        edit_ledger(tree, fn)
        refresh_manifest(tree)  # the ledger is part of the root

    control("ledger naming ghost failing cases is rejected", ghost_cases, needle="ghosts")

    def wrong_profile(tree):
        edit_ledger(
            tree,
            lambda entries: next(
                e for e in entries if e["target_id"] == "storage:test_recovery"
            ).__setitem__("profile", ["U9-nonexistent-lane"]),
        )
        refresh_manifest(tree)

    control(
        "ledger tolerance bound to the wrong profile is rejected",
        wrong_profile,
        needle="this run's profile",
    )

    def dup_ledger(tree):
        edit_ledger(tree, lambda entries: entries.append(dict(entries[0])))
        refresh_manifest(tree)

    control("duplicate ledger target is rejected", dup_ledger, needle="duplicate entry")

    # stale COMPLETE root: seal the copy with its true root, verify the seal
    # is accepted, then tamper a log AND regenerate the manifest - only the
    # sealed root still tells the truth
    sealed = pathlib.Path(tempfile.mkdtemp(prefix="mutant-sealed-"))
    try:
        shutil.copytree(pristine, sealed, dirs_exist_ok=True)
        ad = sealed / ARCHIVE_REL
        rows = json.loads((ad / "u0-results.json").read_text())["results"]
        root, _ = vp.compute_bundle_root(
            ad, rows, ledger_path=sealed / "docs" / "evidence" / "flake-ledger.json", repo=sealed
        )
        (ad / "COMPLETE").write_text(f"COMPLETE {root}\n")
        rc, out = run_cli(sealed)
        expect("root-bound COMPLETE over intact bytes is accepted", rc == 0)
        with open(ad / "storage__storage.log", "a") as f:
            f.write("\n")  # count-neutral tamper
        # the forger regenerates the manifest but cannot rewrite the sealed root
        m = json.loads((ad / "log-manifest.json").read_text())
        m["logs"]["storage__storage.log"] = vp.common.sha256_file(ad / "storage__storage.log")
        m["bundle_root"], _ = vp.compute_bundle_root(
            ad, rows, ledger_path=sealed / "docs" / "evidence" / "flake-ledger.json", repo=sealed
        )
        (ad / "log-manifest.json").write_text(json.dumps(m, indent=1) + "\n")
        rc, out = run_cli(sealed)
        expect(
            "log tampered after sealing is rejected by the COMPLETE root",
            rc != 0 and "COMPLETE binds root" in out,
        )
        # and the live runner must refuse to write into the sealed dir at all
        rc, out = run_cli(sealed, live=True)
        expect("live run into a sealed (COMPLETE) dir is refused", rc != 0 and "sealed" in out)
    finally:
        shutil.rmtree(sealed, ignore_errors=True)


def main():
    bundle_controls()
    comparator_controls()
    verdict_controls()
    join_controls()
    print(f"\nevidence mutants: {checks - len(failures)}/{checks} controls held")
    for f in failures:
        print(f"MUTANT NOT KILLED: {f}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
