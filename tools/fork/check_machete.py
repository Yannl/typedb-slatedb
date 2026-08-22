#!/usr/bin/env python3
"""Reconcile `cargo machete` against the fork's GENERATED manifests (R8-P1-05).

`cargo machete --with-metadata fork/typedb` exits 1 with unused-dependency
findings across ~23 crates. Every one of them is in a manifest this repository
did not write: upstream generates the fork's `Cargo.toml` files from Bazel, and
that generation emits the full Bazel dependency set — including dependencies
reached only through macros, build scripts, feature-gated code or re-exports,
which a static scan cannot see.

Three ways to make the gate green, and only one is honest:

  * `--fix`, which cargo-machete itself warns removes false positives too, and
    would break the build;
  * editing `[package.metadata.cargo-machete]` into 23 upstream manifests,
    which is exactly the "hand-editing generated files" the round-8 audit told
    us not to do, and which every upstream bump would undo;
  * recording the reconciled set ONCE, here, with a reason and a date, and
    failing on anything NEW.

This is the third. The baseline is per crate and per dependency, so:

  * a NEW unused dependency — in upstream's manifests or, far more
    importantly, in a crate this project actually authors — FAILS;
  * a finding that disappears also fails, because a stale allowance is an
    allowance nobody is looking at any more;
  * the analysis is required to be COMPLETE: cargo-machete's exit 2 (error)
    and any parse failure are refusals, never "no findings". A tool that
    printed analysis errors and returned zero must not count as coverage.

usage:
  python3 tools/fork/check_machete.py            # verify against the baseline
  python3 tools/fork/check_machete.py --write    # regenerate the baseline
"""

import argparse
import json
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
FORK = REPO / "fork" / "typedb"
BASELINE = FORK / "machete-baseline.json"

CRATE_RE = re.compile(r"^(?P<crate>[A-Za-z0-9_\-]+) -- (?P<manifest>\S+):$")


def run_machete() -> dict[str, list[str]]:
    """`{crate: [unused dependency, ...]}`, or a refusal."""
    proc = subprocess.run(
        ["cargo", "machete", "--with-metadata", str(FORK.relative_to(REPO))],
        capture_output=True,
        text=True,
        cwd=REPO,
    )
    combined = proc.stdout + proc.stderr
    if proc.returncode not in (0, 1):
        print(
            f"REFUSED: cargo machete exited {proc.returncode} (error, not a finding). The analysis "
            f"did not complete, so its silence is not evidence:\n{combined[-2000:]}",
            file=sys.stderr,
        )
        raise SystemExit(3)
    if "Analyzing dependencies" not in combined:
        print(
            f"REFUSED: cargo machete produced no analysis banner; the output cannot be trusted to "
            f"be a complete run:\n{combined[-2000:]}",
            file=sys.stderr,
        )
        raise SystemExit(3)
    findings: dict[str, list[str]] = {}
    current = None
    for line in combined.splitlines():
        m = CRATE_RE.match(line.strip())
        if m:
            current = m.group("crate")
            findings[current] = []
            continue
        if current and line.startswith("\t"):
            findings[current].append(line.strip())
        elif line.strip() == "":
            continue
        elif not line.startswith("\t"):
            current = None
    return {k: sorted(v) for k, v in findings.items() if v}


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--write", action="store_true", help="regenerate the baseline")
    args = ap.parse_args()

    findings = run_machete()

    if args.write:
        BASELINE.write_text(
            json.dumps(
                {
                    "schema": "typedb-fork-machete-baseline-v1",
                    "why": (
                        "R8-P1-05. Upstream generates this fork's Cargo.toml files from Bazel, and "
                        "that generation emits the full Bazel dependency set - including "
                        "dependencies reached only through macros, build scripts, feature-gated "
                        "code or re-exports, which cargo-machete's static scan cannot see. This "
                        "file records the reconciled set so a NEW finding, especially one in a "
                        "crate this project authors, fails the gate."
                    ),
                    "regenerate_with": "python3 tools/fork/check_machete.py --write",
                    "crates": findings,
                },
                indent=1,
                sort_keys=True,
            )
            + "\n"
        )
        total = sum(len(v) for v in findings.values())
        print(
            f"{BASELINE.relative_to(REPO)}: {len(findings)} crate(s), {total} reconciled finding(s)"
        )
        return 0

    if not BASELINE.is_file():
        print(
            f"MACHETE: FAIL - {BASELINE.relative_to(REPO)} is absent; run --write", file=sys.stderr
        )
        return 1
    baseline = json.loads(BASELINE.read_text())["crates"]
    problems: list[str] = []
    for crate in sorted(set(findings) | set(baseline)):
        now, was = set(findings.get(crate, [])), set(baseline.get(crate, []))
        for dep in sorted(now - was):
            problems.append(f"NEW    {crate}: `{dep}` is unused and is not in the reconciled set")
        for dep in sorted(was - now):
            problems.append(f"STALE  {crate}: `{dep}` is reconciled but is no longer reported")
    if problems:
        print("MACHETE: FAIL - the unused-dependency set has moved")
        for p in problems:
            print(f"  {p}")
        print(
            "\nA NEW entry in a crate this project authors is a real finding: remove the "
            "dependency. A new entry in a generated upstream manifest, or a stale one, is "
            "reconciled by re-running `--write` and saying so in the commit."
        )
        return 1
    total = sum(len(v) for v in findings.values())
    print(
        f"MACHETE: PASS ({len(findings)} crate(s), {total} finding(s), all reconciled against "
        f"{BASELINE.relative_to(REPO)}; 0 new, 0 stale)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
