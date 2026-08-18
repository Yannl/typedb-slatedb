#!/usr/bin/env python3
"""Document-authority linter (audit §2.4/PR0; extended for round-3 E-07).

Fails when:
  1. the ledger is malformed or missing required structure;
  2. the rendered gate table in docs/operations.md drifts from the ledger
     (status prose must be generated from machine truth, never hand-edited);
  3. any STATUS document contains a forbidden claim — a lower-authority
     green assertion that contradicts an open higher-authority requirement
     (the patterns live in the ledger itself, so tightening policy is a
     ledger change, not a linter change);
  4. a gate the ledger marks OPEN_RED/OPEN is described as green in a
     status document;
  5. (E-07) any gate/lane/action id is duplicated; any lane/action status
     is outside its enum; any commit hash an action cites does not exist
     in this repository or is not an ancestor of HEAD (short hashes are
     resolved by git); any docs/ path the ledger references does not
     exist. All fail-closed: an unverifiable claim is a failing claim
     (in CI this requires a full-history checkout — see gates.yml).

Historical review documents record what was believed at the time; only the
LIVE status surfaces are linted (list below).
"""
import json
import pathlib
import re
import subprocess
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

# E-07: closed enums. A new state is a deliberate policy change (edit here),
# never a typo that silently parses.
LANE_STATES = {
    "OPEN",
    "RED",
    "HISTORICAL_EXPERIMENTAL_NON_QUALIFYING",
    "TYPED_UNAVAILABLE_BY_DESIGN",
    "NOT_IMPLEMENTED",
}
ACTION_STATUSES = {
    "OPEN",
    "IN_PROGRESS",
    "BLOCKED_WITH_LOCAL_PARTIALS",
    "DONE",
    "DONE_WITH_RECORDED_REMAINDER",
}


def check_semantics(ledger: dict, failures: list[str]) -> None:
    """Round-3 E-07: unique ids, status enums, commit ancestry, evidence paths."""
    # unique ids per namespace
    for key in ("gates", "lanes", "actions"):
        ids = [item.get("id") for item in ledger.get(key, [])]
        for dup in sorted({i for i in ids if ids.count(i) > 1}):
            failures.append(f"duplicate {key[:-1]} id: {dup}")
        if any(not isinstance(i, str) or not i for i in ids):
            failures.append(f"{key}: every entry needs a non-empty string id")

    # status enums (gates are checked against REQUIRED_GATE_STATES above)
    for lane in ledger.get("lanes", []):
        if lane.get("state") not in LANE_STATES:
            failures.append(f"lane {lane.get('id')}: state {lane.get('state')!r} not in the lane-state enum")
    for action in ledger.get("actions", []):
        if action.get("status") not in ACTION_STATUSES:
            failures.append(f"action {action.get('id')}: status {action.get('status')!r} not in the action-status enum")

    # every commit an action cites must exist AND be an ancestor of HEAD —
    # a ledger claim about a commit this repository does not contain is a
    # forgery or a paste error, both fail-closed. Short hashes tolerated
    # (git resolves them); an ambiguous short hash fails like a missing one.
    def git_ok(*args: str) -> bool:
        return (
            subprocess.run(
                ["git", "-C", str(REPO), *args],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        )

    for action in ledger.get("actions", []):
        for commit in action.get("commits") or []:
            if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{7,40}", commit):
                failures.append(f"action {action.get('id')}: commit {commit!r} is not a hex hash")
                continue
            if not git_ok("cat-file", "-e", f"{commit}^{{commit}}"):
                failures.append(
                    f"action {action.get('id')}: commit {commit} does not exist in this repository "
                    "(if this is a shallow CI clone, the workflow must fetch full history)"
                )
            elif not git_ok("merge-base", "--is-ancestor", commit, "HEAD"):
                failures.append(f"action {action.get('id')}: commit {commit} is not an ancestor of HEAD")

    # every docs/ path referenced anywhere in the ledger must exist
    def walk_strings(value):
        if isinstance(value, dict):
            for v in value.values():
                yield from walk_strings(v)
        elif isinstance(value, list):
            for v in value:
                yield from walk_strings(v)
        elif isinstance(value, str):
            yield value

    referenced: set[str] = set()
    for s in walk_strings({k: v for k, v in ledger.items() if k != "forbidden_claims"}):
        # forbidden_claims hold regex patterns, not paths; everything else
        # naming a docs/ path is a claim that the path exists.
        for m in re.finditer(r"docs/[A-Za-z0-9._/\-]+", s):
            referenced.add(m.group(0).rstrip("."))
    for rel in sorted(referenced):
        if not (REPO / rel).exists():
            failures.append(f"ledger references evidence path {rel} which does not exist")


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

    # round-3 E-07 semantic checks (ids, enums, commit ancestry, evidence paths)
    check_semantics(ledger, failures)

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
