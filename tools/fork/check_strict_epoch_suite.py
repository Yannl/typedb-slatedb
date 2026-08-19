#!/usr/bin/env python3
"""Fenced-posture suite gate for the SlateDB fork (R5-STOR-04).

The strict `external_epoch_required` fence now SHIPS (see
tools/fork/check_strict_epoch.py). That changes what "the fork's suite is
green" can honestly mean, and the round-5 audit's request to "run the full
patched SlateDB suite feature-on" needs an exact answer rather than an
optimistic one:

  * feature OFF, full suite  -> must be FULLY green. This is the
    no-regression gate: the fork must not change upstream semantics for
    anything outside its patch series.
  * feature ON, builder tests -> must be FULLY green. These are the tests
    the audit measured (it found 7/12); patch 0004 supplies epochs at the
    five upstream builder sites that opened databases without one.
  * feature ON, full suite   -> NOT fully green, and that is CORRECT.
    Hundreds of upstream tests open databases through the epoch-less
    builder path on purpose; under the shipped posture the fence refuses
    exactly those opens. Rewriting them all would mean patching upstream's
    test suite into a different suite.

So the invariant this script enforces is the one that actually matters:
under the shipped posture EVERY failing upstream test must fail BECAUSE
THE FENCE REFUSED AN UNAUTHORIZED OPEN, and for no other reason. A single
failure with a different cause is a real regression and fails this gate.

    python3 tools/fork/check_strict_epoch_suite.py            # full gate
    python3 tools/fork/check_strict_epoch_suite.py --quick    # skip feature-off

Exit 0 only when every clause above holds.
"""
import argparse
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
FORK = REPO / "sources" / "slatedb-fork"

# The exact refusal the fence raises. Anything else failing under the
# shipped posture is a genuine regression, not the fence doing its job.
FENCE_REFUSAL = "external writer epoch required: internal allocation is observe-and-bind"

TEST_RESULT = re.compile(r"^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed", re.M)
FAILED_CASE = re.compile(r"^---- (\S+) stdout ----$", re.M)


def run(args: list[str]) -> tuple[int, str]:
    proc = subprocess.run(
        ["cargo", "+1.93.0", "test", *args],
        cwd=FORK, capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


def counts(output: str) -> tuple[int, int]:
    passed = failed = 0
    for p, f in TEST_RESULT.findall(output):
        passed += int(p)
        failed += int(f)
    return passed, failed


def failing_blocks(output: str) -> dict[str, str]:
    """name -> its stdout block, so each failure's CAUSE can be inspected."""
    blocks: dict[str, str] = {}
    marks = [(m.group(1), m.start()) for m in FAILED_CASE.finditer(output)]
    for i, (name, start) in enumerate(marks):
        end = marks[i + 1][1] if i + 1 < len(marks) else len(output)
        blocks[name] = output[start:end]
    return blocks


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="skip the feature-off full suite")
    args = ap.parse_args()

    if not FORK.exists():
        print(f"FAIL: {FORK} absent — run tools/fork/materialize_slatedb.py first", file=sys.stderr)
        return 2

    failures: list[str] = []

    # 1. feature OFF, full suite: upstream semantics preserved.
    if not args.quick:
        rc, out = run(["--lib", "--features", "test-util"])
        passed, failed = counts(out)
        if rc != 0 or failed != 0:
            failures.append(f"feature-OFF full suite is not green: {passed} passed, {failed} failed")
        print(f"feature-OFF  full suite : {passed} passed, {failed} failed")

    # 2. feature ON, builder module: the audit's measured set.
    rc, out = run(["--lib", "--features", "test-util,external_epoch_required", "db::builder"])
    passed, failed = counts(out)
    if rc != 0 or failed != 0 or passed == 0:
        failures.append(f"feature-ON builder tests are not green: {passed} passed, {failed} failed")
    print(f"feature-ON   db::builder: {passed} passed, {failed} failed")

    # 3. feature ON, full suite: every failure must be the fence refusing.
    rc, out = run(["--lib", "--features", "test-util,external_epoch_required"])
    passed, failed = counts(out)
    blocks = failing_blocks(out)
    print(f"feature-ON   full suite : {passed} passed, {failed} failed "
          f"({len(blocks)} failure blocks captured)")
    if failed != len(blocks):
        failures.append(
            f"could not account for every failure: {failed} reported, {len(blocks)} blocks parsed")
    foreign = sorted(name for name, body in blocks.items() if FENCE_REFUSAL not in body)
    if foreign:
        failures.append(
            f"{len(foreign)} feature-ON failure(s) are NOT the fence refusal — genuine regressions:\n    "
            + "\n    ".join(foreign[:20]))
    else:
        print(f"feature-ON   every one of the {len(blocks)} failures is the fence refusing an "
              f"unauthorized epoch-less open (expected under the shipped posture)")

    if failures:
        print("STRICT-EPOCH SUITE GATE: FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("STRICT-EPOCH SUITE GATE: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
