#!/usr/bin/env python3
"""Symmetric, exact comparison of a SlateDB-over-S3 corpus run against the
U1 RocksDB oracle baseline.

The previous comparator accepted three mutants an oracle comparison must
never accept, and each one is closed by a specific rule here:

  1. It iterated the U2S3 side only, so a target present in the ORACLE and
     missing from the run compared equal by never being looked at. Removing
     `answer:answer` from the run was accepted.
     -> the comparison walks the UNION of both sides; a target absent from
        either side is a difference.

  2. Its per-target profile was `(passed, failed, ignored)` and ignored the
     process outcome, so a target that TIMED OUT with unchanged counts (a
     timeout typically leaves 0/0/0, but a partially-parsed log keeps the
     previous numbers) compared equal to a clean run.
     -> the profile carries the process outcome (`ok` / `rc=<n>` / `TIMEOUT`)
        alongside the counts.

  3. Its classifications were free prose keyed by target id, so ANY profile
     for a classified target was "explained" - changing `storage:storage` to
     0 passed / 999 failed stayed accepted.
     -> a classification declares the EXACT expected profiles on both sides.
        A classified target whose measured profile differs from the declared
        one is UNEXPLAINED, exactly like an unclassified one.

Usage: compare_u2s3.py <run-dir-name>   (under docs/evidence/G3/)
"""

import argparse
import json
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

# Every entry declares the EXACT expected profile on both sides. The profile
# spelling is "<passed>/<failed>/<ignored> <outcome>", outcome being `ok`,
# `rc=<n>` or `TIMEOUT`. "ABSENT" means the side has no row at all.
EXPLAINED = {
    "storage:storage": {
        "u2s3": ["18/0/0 ok"],
        "u1": ["8/0/0 ok"],
        "reason": "additive port-layer tests, counted rather than assumed: the U1 "
        "oracle's 8 are the upstream storage lib's unit tests; the U2S3 "
        "run's 18 are those 8 plus the 10 #[test] functions in "
        "fork/typedb/storage/keyspace/slate.rs (retry_channel_tests, "
        "read_contract_tests, posture_tests, materialization_tests) - a "
        "module that does not exist on the RocksDB baseline at all. "
        "8 + 10 = 18 exactly, so zero baseline tests changed outcome. "
        "Adding a control to slate.rs moves this number and the comparison "
        "goes red until the declaration is updated: that is the intended "
        "behaviour, not a nuisance.",
    },
    "storage:test_recovery": {
        "u2s3": ["5/2/0 rc=101"],
        "u1": ["5/2/0 rc=101"],
        "reason": "baseline-identical: the 2 failures are upstream todo!() stubs "
        "(wal_missing_records_*) that fail on every backend.",
    },
    "storage:test_isolation": {
        "u2s3": ["14/0/1 ok"],
        "u1": ["14/0/1 ok"],
        "reason": "baseline-identical: g0_dirty_writes is #[ignore] upstream.",
    },
    "typedb_server_bin:test_fail_points": {
        "u2s3": ["2/0/0 ok"],
        "u1": ["0/0/0 TIMEOUT"],
        "reason": "corrected expectation: the U1 baseline row is itself a 1800s "
        "TIMEOUT; the corrected oracle profile is U2's measured 2 passed / "
        "0 failed at a raised timeout (u2-full: 2099s at 3600s).",
    },
    "typedb_server_bin:bench_concurrency": {
        "u2s3": ["0/0/0 ok"],
        "u1": ["ABSENT"],
        "reason": "absent from the U1 baseline: the executable was dropped by the "
        "pre-fix (package,target) dedupe collapse and first measured on "
        "the U2 run; it contains 0 test cases on every lane.",
    },
    "typedb_server_bin:bench_iam": {
        "u2s3": ["2/0/0 ok"],
        "u1": ["ABSENT"],
        "reason": "absent from the U1 baseline (same dedupe collapse) and GREEN on "
        "U2S3 where U2 is red: the upstream environment defect (the test "
        "queries a database whose TempDir storage dir was deleted at the "
        "end of setup) cannot trigger when keyspace data lives in the "
        "object store, so U2S3 matches U0/RocksDB directly.",
    },
}


def target_name(r):
    # the U1 baseline manifest predates the package-id discovery fix (every
    # package reads `0.0.0`), so the only stable cross-run identity is the
    # TARGET name from the archived log `<package>__<target>.log`. Duplicate
    # target names exist (two 0-case test_utils_* scaffolding targets), so
    # rows group into multisets per name and profiles compare as multisets.
    return r["raw_log"].rsplit("/", 1)[-1].rsplit("__", 1)[-1][: -len(".log")]


def outcome(r):
    if r.get("timed_out"):
        return "TIMEOUT"
    rc = r.get("exit_code")
    return "ok" if rc == 0 else f"rc={rc}"


def profile_of(r):
    return f"{r['passed']}/{r['failed']}/{r['ignored']} {outcome(r)}"


def profiles(rows):
    return sorted(profile_of(r) for r in rows) if rows else ["ABSENT"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "run_dir",
        nargs="?",
        default="u2s3-full",
        help="evidence dir under docs/evidence/G3 to compare against the U1 oracle",
    )
    run_dir = parser.parse_args().run_dir
    u2s3 = json.loads((REPO / f"docs/evidence/G3/{run_dir}/u0-results.json").read_text())
    u1 = json.loads((REPO / "docs/evidence/G3/u1-full/u0-results.json").read_text())

    def by_target(run):
        out = {}
        for r in run["results"]:
            out.setdefault(target_name(r), []).append(r)
        return out

    a, b = by_target(u2s3), by_target(u1)

    green = red = timeout = 0
    cases = {"passed": 0, "failed": 0, "ignored": 0}
    for r in u2s3["results"]:
        ok = r["exit_code"] == 0 and not r["timed_out"]
        green += ok
        red += not ok
        timeout += bool(r["timed_out"])
        for k in cases:
            cases[k] += r[k]

    diffs = []
    # UNION of both sides: a target that exists only in the oracle is a
    # missing execution, which is exactly as much a divergence as a red one.
    for name in sorted(set(a) | set(b)):
        run_rows, base_rows = a.get(name), b.get(name)
        run_profile, base_profile = profiles(run_rows), profiles(base_rows)
        if run_rows and base_rows and run_profile == base_profile:
            continue
        tid = (run_rows or base_rows)[0]["target_id"]
        exp = EXPLAINED.get(tid)
        if exp and run_profile == sorted(exp["u2s3"]) and base_profile == sorted(exp["u1"]):
            classification = f"EXPLAINED: {exp['reason']}"
        elif exp:
            classification = (
                f"UNEXPLAINED - stop the line: a classification exists for this "
                f"target but declares u2s3={sorted(exp['u2s3'])} u1={sorted(exp['u1'])}, "
                f"and the measured profiles are u2s3={run_profile} u1={base_profile}"
            )
        elif not run_rows:
            classification = (
                "UNEXPLAINED - stop the line: present in the U1 oracle "
                "and ABSENT from this run (the corpus shrank)"
            )
        else:
            classification = "UNEXPLAINED - stop the line"
        diffs.append(
            {
                "target": tid,
                "u2s3_profile": " + ".join(run_profile),
                "u1_profile": " + ".join(base_profile),
                "u1_timed_out": bool(base_rows and any(x["timed_out"] for x in base_rows)),
                "classification": classification,
            }
        )

    unexplained = [d for d in diffs if d["classification"].startswith("UNEXPLAINED")]
    out = {
        "claim": "U2S3 (SlateDB keyspaces over an S3-compatible object store - local "
        "MinIO standing in for Cloudflare R2 - with file WAL) runs the "
        "complete applicable upstream TypeDB test corpus with a pass/fail "
        "profile structurally equal to the U1 RocksDB oracle baseline, under "
        "the declared corrected expectations for known upstream-defective "
        "targets",
        "u2s3_run": f"docs/evidence/G3/{run_dir}/u0-results.json",
        "u1_baseline": "docs/evidence/G3/u1-full/u0-results.json",
        "s3_endpoint": "MinIO (S3 API) at 127.0.0.1:9000, bucket typedb-keyspaces",
        "u2s3_summary": {
            "executables": len(u2s3["results"]),
            "green": green,
            "red": red,
            "timeout": timeout,
            "cases_passed": cases["passed"],
            "cases_failed": cases["failed"],
            "cases_ignored": cases["ignored"],
        },
        "method": "union-of-both-sides per-target profile multiset equality, where a "
        "profile is <passed>/<failed>/<ignored> plus the process outcome "
        "(ok | rc=<n> | TIMEOUT), joined on target name (the U1 manifest "
        "predates the package-id discovery fix). Every inequality must match "
        "a classification that declares the exact expected profiles on both "
        "sides, or the comparison fails.",
        "divergent_targets": diffs,
        "unexplained_count": len(unexplained),
    }
    path = REPO / (
        "docs/evidence/G3/u2s3-vs-oracle-comparison.json"
        if run_dir == "u2s3-full"
        else f"docs/evidence/G3/{run_dir}-vs-oracle-comparison.json"
    )
    path.write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out["u2s3_summary"], indent=1))
    print(f"divergent: {len(diffs)}, unexplained: {len(unexplained)}")
    for d in unexplained:
        print(
            f"UNEXPLAINED {d['target']}: u2s3={d['u2s3_profile']} u1={d['u1_profile']}",
            file=sys.stderr,
        )
    return 1 if unexplained else 0


if __name__ == "__main__":
    sys.exit(main())
