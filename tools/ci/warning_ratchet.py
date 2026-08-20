#!/usr/bin/env python3
"""R6-HYGIENE-01 - a one-way ratchet toward `-D warnings`.

Two crates in this repository can be held at `-D warnings` today: the tools
workspace's `protocol-models` and `storage-diff-spike`. The product crate
(`storage`, inside the TypeDB soft fork) cannot: it compiles with a material
warning set inherited from upstream plus our own port, and flipping it to deny
would turn CI red on code we do not own and cannot fix in one pass.

The honest middle is a RATCHET, not a suppression. This tool parses
`cargo … --message-format=json` output, counts warnings per (crate, lint), and
compares them against a committed baseline:

  * a NEW lint that has no baseline entry  -> FAIL
  * an EXISTING lint whose count INCREASED -> FAIL
  * a count that DECREASED                 -> FAIL under --strict, telling you
                                              to re-record: an unratcheted
                                              improvement silently restores the
                                              old headroom
  * a baseline entry that reached 0        -> FAIL under --strict: delete it and
                                              deny the lint instead

The number may only ever go down, and it goes down by editing the baseline in
the same commit that fixes the warnings. That is what turns "we should clean
this up" into a gate.

Usage
-----
    cargo check -p storage --lib --message-format=json > check.json
    warning_ratchet.py --input check.json --crate storage
    warning_ratchet.py --input check.json --crate storage --record
    warning_ratchet.py --self-test

Exit codes: 0 within baseline, 1 regression, 2 usage/IO.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE_PATH = REPO_ROOT / "tools" / "ci" / "warning-baseline.json"
SCHEMA = "typedb-r2/warning-baseline@1"


def parse_warnings(stream_text: str) -> dict[str, int]:
    """Count warnings per lint code from a cargo JSON message stream."""
    counts: dict[str, int] = {}
    seen: set[tuple] = set()
    for line in stream_text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-message":
            continue
        body = msg.get("message") or {}
        if body.get("level") != "warning":
            continue
        code = (body.get("code") or {}).get("code") or "uncoded"
        # cargo re-emits identical diagnostics per target; dedupe on the exact
        # (code, rendered) pair so a two-target check is not counted twice.
        key = (code, body.get("rendered", "")[:400])
        if key in seen:
            continue
        seen.add(key)
        counts[code] = counts.get(code, 0) + 1
    return counts


def load_baseline(path: Path) -> dict:
    if not path.exists():
        return {"schema": SCHEMA, "document": "", "crates": {}}
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("schema") != SCHEMA:
        raise SystemExit(f"{path}: schema must be {SCHEMA!r}")
    return doc


def compare(baseline: dict, crate: str, counts: dict[str, int], strict: bool) -> list[str]:
    entry = (baseline.get("crates") or {}).get(crate)
    if entry is None:
        return [
            f"crate {crate!r} has no recorded warning baseline. Record one with --record in the same "
            f"commit that reviews the warnings; an unrecorded crate is not a passing crate."
        ]
    recorded: dict[str, int] = entry.get("lints", {})
    problems: list[str] = []
    for code, n in sorted(counts.items()):
        allowed = recorded.get(code)
        if allowed is None:
            problems.append(
                f"{crate}: NEW lint {code} x{n} has no baseline entry - fix it, or record it with a reason"
            )
        elif n > allowed:
            problems.append(
                f"{crate}: {code} regressed {allowed} -> {n} (the ratchet only turns one way)"
            )
        elif strict and n < allowed:
            problems.append(
                f"{crate}: {code} improved {allowed} -> {n} but the baseline still allows {allowed}. "
                f"Re-record it (--record) so the headroom is actually given up."
            )
    if strict:
        for code, allowed in sorted(recorded.items()):
            if code not in counts:
                problems.append(
                    f"{crate}: baseline still allows {code} x{allowed} but it no longer occurs - delete the entry"
                )
    return problems


def self_test() -> int:
    failures = 0
    base = {
        "schema": SCHEMA,
        "crates": {"demo": {"lints": {"dead_code": 3, "unused_variables": 1}, "reason": "fixture"}},
    }
    cases = [
        ("CONTROL: counts at the baseline pass", {"dead_code": 3, "unused_variables": 1}, False, 0),
        (
            "MUTANT a lint regresses above its baseline",
            {"dead_code": 4, "unused_variables": 1},
            False,
            1,
        ),
        (
            "MUTANT a brand-new lint appears",
            {"dead_code": 3, "unused_variables": 1, "unreachable_code": 1},
            False,
            1,
        ),
        (
            "MUTANT an improvement is not re-recorded (strict)",
            {"dead_code": 1, "unused_variables": 1},
            True,
            1,
        ),
        ("MUTANT a baseline entry became dead (strict)", {"dead_code": 3}, True, 1),
        ("MUTANT an unrecorded crate", None, False, 1),
    ]
    for name, counts, strict, expect in cases:
        if counts is None:
            problems = compare(base, "not-recorded", {}, strict)
        else:
            problems = compare(base, "demo", counts, strict)
        ok = len(problems) == expect
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")
        if not ok:
            print(f"       expected {expect} problem(s), got {problems}")
            failures += 1

    stream = "\n".join(
        [
            json.dumps(
                {
                    "reason": "compiler-message",
                    "message": {"level": "warning", "code": {"code": "dead_code"}, "rendered": "a"},
                }
            ),
            json.dumps(
                {
                    "reason": "compiler-message",
                    "message": {"level": "warning", "code": {"code": "dead_code"}, "rendered": "a"},
                }
            ),
            json.dumps(
                {
                    "reason": "compiler-message",
                    "message": {"level": "warning", "code": {"code": "dead_code"}, "rendered": "b"},
                }
            ),
            json.dumps(
                {
                    "reason": "compiler-message",
                    "message": {"level": "error", "code": {"code": "E0001"}, "rendered": "c"},
                }
            ),
            "not json at all",
        ]
    )
    got = parse_warnings(stream)
    ok = got == {"dead_code": 2}
    print(
        f"  {'ok  ' if ok else 'FAIL'} the parser dedupes re-emitted diagnostics and ignores errors/noise"
    )
    if not ok:
        print(f"       got {got}")
        failures += 1

    print()
    if failures:
        print(f"warning-ratchet self-test: {failures} case(s) FAILED")
        return 1
    print("warning-ratchet self-test: the ratchet only turns one way")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--input", help="cargo --message-format=json output (default: stdin)")
    ap.add_argument("--crate", help="crate name this stream belongs to")
    ap.add_argument("--baseline", default=str(BASELINE_PATH))
    ap.add_argument(
        "--record", action="store_true", help="write the observed counts into the baseline"
    )
    ap.add_argument(
        "--reason", default="", help="why these warnings are tolerated (required with --record)"
    )
    ap.add_argument(
        "--strict",
        action="store_true",
        help="also fail on unratcheted improvements and dead entries",
    )
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.crate:
        ap.error("--crate is required")

    text = Path(args.input).read_text(encoding="utf-8") if args.input else sys.stdin.read()
    counts = parse_warnings(text)
    baseline_path = Path(args.baseline)
    baseline = load_baseline(baseline_path)

    if args.record:
        if not args.reason:
            ap.error(
                "--record requires --reason: an unexplained baseline is a suppression, not a ratchet"
            )
        baseline.setdefault("crates", {})[args.crate] = {"lints": counts, "reason": args.reason}
        baseline_path.write_text(
            json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(
            f"recorded {sum(counts.values())} warning(s) across {len(counts)} lint(s) for {args.crate}"
        )
        return 0

    problems = compare(baseline, args.crate, counts, args.strict)
    total = sum(counts.values())
    print(f"{args.crate}: {total} warning(s) across {len(counts)} lint(s)")
    for code, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"    {n:>4}  {code}")
    print()
    if problems:
        print(f"WARNING RATCHET: FAIL ({len(problems)})")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("WARNING RATCHET: PASS (no lint exceeded its recorded baseline)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
