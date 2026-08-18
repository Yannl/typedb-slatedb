#!/usr/bin/env python3
"""Document-authority linter (audit §2.4/PR0).

Fails when:
  1. the ledger is malformed or missing required structure;
  2. the rendered gate table in docs/operations.md drifts from the ledger
     (status prose must be generated from machine truth, never hand-edited);
  3. any STATUS document contains a forbidden claim — a lower-authority
     green assertion that contradicts an open higher-authority requirement
     (the patterns live in the ledger itself, so tightening policy is a
     ledger change, not a linter change);
  4. a gate the ledger marks OPEN_RED/OPEN is described as green in a
     status document.

Historical review documents record what was believed at the time; only the
LIVE status surfaces are linted (list below).
"""
import json
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
LEDGER = REPO / "docs" / "ledger" / "gates.json"

# the live status surfaces; reviews/ archives are historical records
STATUS_DOCS = [
    "docs/operations.md",
    "docs/handoff-live-validation.md",
    "docs/tasks/NEXT-SESSION.md",
    "README.md",
]

REQUIRED_GATE_STATES = {"OPEN_RED", "OPEN", "NOT_READY_TO_EXECUTE", "NOT_REACHABLE"}


def main() -> int:
    failures: list[str] = []
    try:
        ledger = json.loads(LEDGER.read_text())
    except Exception as error:  # malformed ledger is a hard failure
        print(f"LEDGER LINT: FAIL - ledger unreadable: {error}")
        return 1

    for key in ("gates", "lanes", "actions", "forbidden_claims", "adopted_audit"):
        if key not in ledger:
            failures.append(f"ledger missing required key: {key}")
    for g in ledger.get("gates", []):
        if g.get("state") not in REQUIRED_GATE_STATES:
            failures.append(f"gate {g.get('id')}: state {g.get('state')!r} not a recognised gate state")

    # 2. rendered-block drift
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import render_status  # noqa: E402
    operations = (REPO / "docs" / "operations.md").read_text()
    if render_status.BEGIN not in operations or render_status.END not in operations:
        failures.append("docs/operations.md is missing the generated gate-table markers")
    else:
        current = operations.split(render_status.BEGIN, 1)[1].split(render_status.END, 1)[0]
        expected = render_status.render().split(render_status.BEGIN, 1)[1].split(render_status.END, 1)[0]
        if current != expected:
            failures.append("docs/operations.md gate table drifted from the ledger - run tools/ledger/render_status.py")

    # 3. forbidden claims in live status docs. The GENERATED block is exempt:
    # it is the ledger's own rendered truth (which quotes the raw observation
    # and names stale claims in order to forbid them).
    for rel in STATUS_DOCS:
        p = REPO / rel
        if not p.exists():
            continue
        text = p.read_text()
        if render_status.BEGIN in text and render_status.END in text:
            head, rest = text.split(render_status.BEGIN, 1)
            text = head + rest.split(render_status.END, 1)[1]
        for rule in ledger.get("forbidden_claims", []):
            for m in re.finditer(rule["pattern"], text):
                failures.append(f"{rel}: forbidden claim {m.group(0)!r} - {rule['reason']}")

    if failures:
        print("LEDGER LINT: FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"LEDGER LINT: PASS ({len(ledger['gates'])} gates, {len(ledger['lanes'])} lanes, "
          f"{len(ledger['actions'])} actions, {len(STATUS_DOCS)} status docs scanned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
