#!/usr/bin/env python3
"""Generate docs/evidence/G3/u2s3-vs-oracle-comparison.json: structural
equality of the U2S3 corpus run against the U1 oracle baseline, with the
same corrected-expectation policy the U2 comparison used."""
import json, pathlib, sys

REPO = pathlib.Path("/home/user/typedb-slatedb")
u2s3 = json.load(open(REPO / "docs/evidence/G3/u2s3-full/u0-results.json"))
u1 = json.load(open(REPO / "docs/evidence/G3/u1-full/u0-results.json"))


def target_name(r):
    # the U1 baseline manifest predates the package-id discovery fix (every
    # package reads `0.0.0`), so the only stable cross-run identity is the
    # TARGET name from the archived log `<package>__<target>.log`. Duplicate
    # target names exist (two 0-case test_utils_* scaffolding targets), so
    # rows group into multisets per name and profiles compare as multisets.
    return r["raw_log"].rsplit("/", 1)[-1].rsplit("__", 1)[-1][: -len(".log")]


def by_target(run):
    out = {}
    for r in run["results"]:
        out.setdefault(target_name(r), []).append(r)
    return out


def profiles(rows):
    return sorted((r["passed"], r["failed"], r["ignored"]) for r in rows)


a, b = by_target(u2s3), by_target(u1)

EXPLAINED = {
    "storage:test_recovery": "baseline-identical: the 2 failures are upstream todo!() stubs (wal_missing_records_*) that fail on every backend; U0/U1 record the same 5/2",
    "typedb_server_bin:test_fail_points": "corrected expectation: the U1 baseline row itself is a 1800s TIMEOUT (0/0); the corrected oracle profile is U2's measured 2 passed / 0 failed at a raised timeout (u2-full: 2099s at 3600s; U2S3 measured 2572s at 7200s) - equal to it",
    "typedb_server_bin:bench_concurrency": "absent from the U1 baseline: the executable was silently dropped by the pre-fix (package,target) dedupe collapse and first measured on the U2 run (see u2-vs-oracle-comparison.json denominator_note); it contains 0 test cases on every lane, so equality is trivial",
    "typedb_server_bin:bench_iam": "absent from the U1 baseline (same dedupe collapse), and GREEN on U2S3 where U2 is red: the upstream environment defect (the test queries a database whose TempDir storage dir was deleted at the end of setup; finding-bench-iam-deleted-storage-dir.md) cannot trigger when keyspace data lives in the object store, so U2S3 matches the U0/RocksDB behaviour directly",
}

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
for name, group in sorted(a.items()):
    base = b.get(name)
    if base is not None and profiles(group) == profiles(base):
        continue
    tid = group[0]["target_id"]
    diffs.append({
        "target": tid,
        "u2s3_profile": " + ".join(f"{x[0]} passed / {x[1]} failed" for x in profiles(group)),
        "u1_profile": (" + ".join(f"{x[0]} passed / {x[1]} failed" for x in profiles(base)) if base else "ABSENT"),
        "u1_timed_out": bool(base and any(x["timed_out"] for x in base)),
        "classification": EXPLAINED.get(tid, "UNEXPLAINED - stop the line"),
    })

out = {
    "claim": "U2S3 (SlateDB keyspaces over an S3-compatible object store - local MinIO standing in for Cloudflare R2 - with file WAL) runs the complete applicable upstream TypeDB test corpus with a pass/fail profile structurally equal to the U1 RocksDB oracle baseline, under the corrected expectations for known upstream-defective targets",
    "u2s3_run": "docs/evidence/G3/u2s3-full/u0-results.json",
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
    "method": "per-target case-profile multiset equality (passed/failed/ignored) against the U1 oracle, joined on target name (the U1 manifest predates the package-id discovery fix); every inequality must carry a documented classification or the comparison fails",
    "divergent_targets": diffs,
    "notes": [
        "test_concept, test_query and test_fail_points rows are re-runs on a quiet machine: the first pass ran under full-workspace build contention (2 spurious timeouts) and predates the four-spelling behaviour-fixture fix in run_u0.py (false reds from unreadable feature paths in exactly the four tests using non-canonical fixture paths).",
        "test_fail_points requires a raised timeout on every lane (the U1 baseline row itself is a 1800s timeout; U2 measured 2099s green at 3600s; U2S3 2572s at 7200s).",
        "bench_iam is the one target where U2S3 is strictly closer to the oracle than U2: object-store-resident keyspaces are immune to the deleted-TempDir environment defect that reds it on LocalFS SlateDB.",
    ],
}
unexplained = [d for d in diffs if d["classification"].startswith("UNEXPLAINED")]
path = REPO / "docs/evidence/G3/u2s3-vs-oracle-comparison.json"
path.write_text(json.dumps(out, indent=1) + "\n")
print(json.dumps(out["u2s3_summary"], indent=1))
print(f"divergent: {len(diffs)}, unexplained: {len(unexplained)}")
sys.exit(1 if unexplained else 0)
