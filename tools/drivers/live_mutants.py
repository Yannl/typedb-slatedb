#!/usr/bin/env python3
"""EXECUTION-time negative controls for the driver-lane runner.

tools/drivers/driver_mutants.py attacks an archived bundle. These mutants
attack the RUNNER: they put it in situations where a careless harness would
still emit a green-looking bundle, and require it to refuse. Each one is
actually executed - the runner is invoked, its exit code and output captured,
and the output directory inspected for a COMPLETE seal that must not be there.

Mutants:
  server_binary_missing   the TypeDB server binary does not exist
  server_port_occupied    something else already holds 127.0.0.1:1729, which
                          the upstream driver steps hardcode
  suite_never_built       no test executable was produced for the suite
                          (--skip-build against an empty target directory)

A mutant is KILLED when the runner exits nonzero AND leaves no COMPLETE
marker AND (where it produced a bundle at all) that bundle records the
refusal. A runner that writes `COMPLETE` after any of these is broken.

Usage:
  python3 tools/drivers/live_mutants.py --run-dir /tmp/live-mutants \
      --out docs/evidence/G1/drivers/live-mutants.json
"""
import argparse
import json
import pathlib
import socket
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import common  # noqa: E402

REPO = common.REPO
RUNNER = REPO / "tools" / "drivers" / "run_rust_behaviour.py"
TARGET = REPO / "target" / "drivers-proj"


def invoke(out_dir, run_dir, extra, timeout=1800):
    argv = [sys.executable, str(RUNNER), "--lane", "fork-classic",
            "--suite", "test_database", "--out", str(out_dir),
            "--run-dir", str(run_dir), "--target-dir", str(TARGET)] + extra
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return {"argv": argv, "exit_code": p.returncode,
            "stdout_tail": p.stdout[-1500:], "stderr_tail": p.stderr[-1500:]}


def judge(name, res, out_dir, expect_substring):
    complete = (out_dir / "COMPLETE").is_file()
    verdict_file = out_dir / "verdict.json"
    verdict = (json.loads(verdict_file.read_text())
               if verdict_file.is_file() else None)
    text = res["stdout_tail"] + res["stderr_tail"]
    killed = (res["exit_code"] != 0 and not complete
              and (verdict is None or verdict.get("policy_verdict") == "RED"))
    return {
        "mutant": name,
        "exit_code": res["exit_code"],
        "sealed_COMPLETE": complete,
        "recorded_verdict": (verdict or {}).get("policy_verdict"),
        "expected_message_present": expect_substring in text,
        "message_excerpt": next(
            (l for l in text.splitlines() if expect_substring in l),
            text.strip().splitlines()[-1] if text.strip() else ""),
        "outcome": "KILLED" if killed and expect_substring in text
                   else "SURVIVED",
        "argv": res["argv"],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", type=pathlib.Path, required=True)
    ap.add_argument("--out", type=pathlib.Path, default=None)
    args = ap.parse_args()
    args.run_dir.mkdir(parents=True, exist_ok=True)
    results = []

    with tempfile.TemporaryDirectory(prefix="live-mutants-") as td:
        td = pathlib.Path(td)

        # 1) the server binary does not exist
        out1 = td / "server_binary_missing"
        r = invoke(out1, args.run_dir / "m1",
                   ["--server-binary", str(td / "no-such-typedb-server")])
        results.append(judge("server_binary_missing", r, out1,
                             "server binary absent"))

        # 2) something else holds the hardcoded driver port
        out2 = td / "server_port_occupied"
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", 1729))
            s.listen(1)
            r = invoke(out2, args.run_dir / "m2", [])
            results.append(judge("server_port_occupied", r, out2,
                                 "already bound"))
        except OSError as e:
            results.append({"mutant": "server_port_occupied",
                            "outcome": "SKIPPED",
                            "reason": f"could not bind 1729 to stage the "
                                      f"mutant: {e}"})
        finally:
            s.close()

        # 3) no test executable was ever produced
        out3 = td / "suite_never_built"
        r = invoke(out3, args.run_dir / "m3",
                   ["--skip-build", "--target-dir", str(td / "empty-target")])
        results.append(judge("suite_never_built", r, out3,
                             "cargo produced no test executable"))

    killed = sum(1 for x in results if x["outcome"] == "KILLED")
    survived = sum(1 for x in results if x["outcome"] == "SURVIVED")
    skipped = sum(1 for x in results if x["outcome"] == "SKIPPED")
    doc = {"schema": "driver-lane-live-mutants-v1",
           "statement": ("Execution-time negative controls: the runner itself "
                         "is put in each situation and must refuse. A COMPLETE "
                         "marker after any of these would mean the lane can "
                         "seal a bundle without a server or without a suite."),
           "mutants": results,
           "summary": {"total": len(results), "killed": killed,
                       "survived": survived, "skipped": skipped}}
    print(json.dumps(doc, indent=1))
    if args.out:
        out = args.out if args.out.is_absolute() else REPO / args.out
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(doc, indent=1) + "\n")
    print(f"LIVE MUTANTS: {killed} killed, {survived} survived, "
          f"{skipped} skipped", file=sys.stderr)
    return 0 if survived == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
