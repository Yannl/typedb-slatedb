#!/usr/bin/env python3
"""BT-P2 (partial): U0 pristine-baseline runner.

Runs every compiled test executable of the pinned TypeDB workspace under the
Rust parity lane, one executable at a time (libtest's own in-binary
parallelism is upstream behaviour and is preserved), with:

  - no retries (a failure is recorded, never converted to PASS);
  - per-executable timeout (kills the whole process group);
  - serial groups honored by the one-at-a-time execution order;
  - raw stdout/stderr archived per target, normalized JSON results emitted.

Usage: run_u0.py [--filter SUBSTR] [--skip SUBSTR ...] [--out DIR]
"""
import argparse
import json
import os
import pathlib
import signal
import subprocess
import sys
import time

REPO = pathlib.Path(__file__).resolve().parents[2]
TB = REPO / "sources" / "typedb"
TOOLCHAIN = "+1.93.0"
DEFAULT_TIMEOUT = 1800

ENV_BASE = {
    **os.environ,
    "CARGO_INCREMENTAL": "0",
    "CARGO_PROFILE_DEV_DEBUG": "false",
    "CARGO_PROFILE_TEST_DEBUG": "false",
}

# targets that need the assembly archive staged in cwd
ASSEMBLY_TARGETS = {"test_assembly", "test_fail_points"}
ASSEMBLY_ENV = {"TYPEDB_ASSEMBLY_ARCHIVE": "typedb-all-linux-x86_64.tar.gz"}
# execution order: fast crates first, server-binding suites last
ORDER_LAST = ("test_behaviour", "test_http", "test_assembly", "test_fail_points")


def discover_executables():
    out = subprocess.check_output(
        ["cargo", TOOLCHAIN, "test", "--workspace", "--locked", "--no-run",
         "--message-format", "json"],
        cwd=TB, text=True, stderr=subprocess.DEVNULL, env=ENV_BASE)
    execs = []
    for line in out.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") == "compiler-artifact" and msg.get("executable"):
            tgt = msg["target"]
            pkg = msg["package_id"].split("#")[-1].split("@")[0]
            if "/" in pkg:
                pkg = pkg.rsplit("/", 1)[-1]
            execs.append({"package": pkg, "target": tgt["name"],
                          "kind": tgt["kind"], "executable": msg["executable"]})
    seen = {}
    for e in execs:
        seen[(e["package"], e["target"])] = e
    ordered = sorted(seen.values(), key=lambda e: (
        any(e["target"].startswith(p) for p in ORDER_LAST), e["package"], e["target"]))
    return ordered


def run_one(e, out_dir, timeout):
    tid = f"{e['package']}:{e['target']}"
    raw = out_dir / f"{e['package']}__{e['target']}.log"
    env = dict(ENV_BASE)
    tmp = out_dir / "tmp" / f"{e['package']}__{e['target']}"
    tmp.mkdir(parents=True, exist_ok=True)
    env["TMPDIR"] = str(tmp)
    if e["target"] in ASSEMBLY_TARGETS:
        env.update(ASSEMBLY_ENV)
    start = time.time()
    with open(raw, "wb") as logf:
        proc = subprocess.Popen(
            [e["executable"], "--format", "terse"],
            cwd=TB, env=env, stdout=logf, stderr=subprocess.STDOUT,
            start_new_session=True)
        try:
            code = proc.wait(timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            code = None
            timed_out = True
    dur = time.time() - start
    text = raw.read_text(errors="replace")
    tail = text[-2000:]
    # parse libtest summary lines: "test result: ok. X passed; Y failed; Z ignored; ..."
    passed = failed = ignored = measured = filtered = 0
    for line in text.splitlines():
        if line.startswith("test result:"):
            import re
            for n, key in re.findall(r"(\d+) (passed|failed|ignored|measured|filtered out)", line):
                n = int(n)
                if key == "passed":
                    passed += n
                elif key == "failed":
                    failed += n
                elif key == "ignored":
                    ignored += n
                elif key == "measured":
                    measured += n
                else:
                    filtered += n
    return {
        "target_id": tid,
        "executable": e["executable"],
        "exit_code": code,
        "timed_out": timed_out,
        "duration_seconds": round(dur, 2),
        "passed": passed,
        "failed": failed,
        "ignored": ignored,
        "measured": measured,
        "filtered_out": filtered,
        "raw_log": str(raw.relative_to(REPO)),
        "tail": tail if (code != 0 or timed_out) else None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--filter", default=None)
    ap.add_argument("--skip", action="append", default=[])
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--out", default=str(REPO / "docs" / "evidence" / "G1" / "u0-results"))
    args = ap.parse_args()

    out_dir = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    execs = discover_executables()
    if args.filter:
        execs = [e for e in execs if args.filter in f"{e['package']}:{e['target']}"]
    execs = [e for e in execs
             if not any(s in f"{e['package']}:{e['target']}" for s in args.skip)]
    print(f"U0: {len(execs)} test executables", flush=True)
    results = []
    for i, e in enumerate(execs):
        print(f"[{i+1}/{len(execs)}] {e['package']}:{e['target']} ...",
              end=" ", flush=True)
        r = run_one(e, out_dir, args.timeout)
        results.append(r)
        status = ("TIMEOUT" if r["timed_out"]
                  else "OK" if r["exit_code"] == 0 else f"FAIL({r['exit_code']})")
        print(f"{status} {r['passed']}p/{r['failed']}f/{r['ignored']}i "
              f"in {r['duration_seconds']}s", flush=True)
        (out_dir / "u0-results.json").write_text(
            json.dumps({"profile": "U0",
                        "toolchain": "rust 1.93.0 parity lane",
                        "results": results}, indent=1) + "\n")
    total = {
        "executables": len(results),
        "green": sum(1 for r in results if r["exit_code"] == 0),
        "red": sum(1 for r in results if r["exit_code"] not in (0, None)),
        "timeout": sum(1 for r in results if r["timed_out"]),
        "cases_passed": sum(r["passed"] for r in results),
        "cases_failed": sum(r["failed"] for r in results),
        "cases_ignored": sum(r["ignored"] for r in results),
    }
    (out_dir / "u0-summary.json").write_text(json.dumps(total, indent=2) + "\n")
    print(json.dumps(total, indent=2))


if __name__ == "__main__":
    main()
