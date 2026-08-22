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
     (in CI this requires a full-history checkout — see gates.yml);
  6. (round-5 R5-REL-01) present-state/history contradictions:
     a closed action (DONE / DONE_WITH_RECORDED_REMAINDER) with no commits;
     a `closes` claim on an action that is not closed; a gate or lane whose
     structured `blocking_findings` names a finding id some closed action's
     `closes` records as closed (the "old blocker described as live beside
     a later done action" defect — checked on STRUCTURED ids, never by
     fuzzy prose matching); and impossible status transitions against the
     last COMMITTED ledger: a closed action reopening or an action row
     disappearing entirely (history may be corrected, never erased).
     Mutants for every check live in tools/ledger/ledger_mutants.py and
     are executed in CI.

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

REQUIRED_GATE_STATES = {"OPEN_RED", "OPEN", "NOT_READY_TO_EXECUTE", "NOT_REACHABLE", "CLOSED"}
# The states that ASSERT a gate is finished. A gate with any blocker or any
# OPEN owner decision may not be in one of these — see `check_gate_state_reducer`.
CLOSED_GATE_STATES = {"CLOSED"}

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
# the statuses that assert "this action's work is closed"; everything else is
# still in flight. Used by the R5-REL-01 checks below.
CLOSED_ACTION_STATUSES = {"DONE", "DONE_WITH_RECORDED_REMAINDER"}
# structured finding ids (SI-G0-1, C-P0-01, R4-CF-02, E-P0-08, ...)
FINDING_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-]*")


def historical_sections(node, path="") -> list[str]:
    """JSON paths of every sub-object explicitly marked `historical: true`.

    A historical section records what was believed at an earlier commit. It is
    EXEMPT from the single-canonical-current-fact rule below, and in exchange it
    must say when it was true and what replaced it.
    """
    found = []
    if isinstance(node, dict):
        if node.get("historical") is True:
            found.append(path)
        for k, v in node.items():
            found.extend(historical_sections(v, f"{path}.{k}" if path else k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            found.extend(historical_sections(v, f"{path}[{i}]"))
    return found


def strings_outside(node, exclude_paths: set[str], path="") -> list[tuple[str, str]]:
    """(json path, string) for every string NOT under one of `exclude_paths`."""
    if any(path == e or path.startswith(e + ".") or path.startswith(e + "[") for e in exclude_paths):
        return []
    if isinstance(node, str):
        return [(path, node)]
    out = []
    if isinstance(node, dict):
        for k, v in node.items():
            out.extend(strings_outside(v, exclude_paths, f"{path}.{k}" if path else k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out.extend(strings_outside(v, exclude_paths, f"{path}[{i}]"))
    return out


def check_single_canonical_current(ledger: dict, failures: list[str]) -> None:
    """R8-P0-02: exactly ONE mutable copy of every current fact.

    The round-8 audit found this document asserting, simultaneously and with
    every existing check passing: `gates[G0].state = OPEN` and
    `q_dispositions.G0 = OPEN_RED`; `current coverage 13,723 / 23,138` in one
    place and `914 / 23,138 with 22,115 uncovered` in another; and a
    forbidden-claim reason saying "G0 is OPEN_RED while Mode-Q evidence is
    absent" while the bound Mode-Q bundle validated. Sixteen mutants passed the
    contradictory file, because every one of them tested STRUCTURE.

    The rule this enforces is not "these three fields agree" — that would be a
    check against the three defects that happened. It is: a current fact has ONE
    home (`current`), and any other field restating a value `current` owns is
    refused, whether or not it currently agrees. Agreement between two mutable
    copies is a coincidence with a maintenance schedule.
    """
    current = ledger.get("current")
    if not isinstance(current, dict):
        failures.append("ledger is missing the canonical `current` fact section (R8-P0-02)")
        return

    coverage = current.get("coverage") or {}
    parts = ("covered", "partial", "uncovered")
    if all(isinstance(coverage.get(k), int) for k in (*parts, "total")):
        total = sum(coverage[k] for k in parts)
        if total != coverage["total"]:
            failures.append(
                f"current.coverage: covered+partial+uncovered = {total} but total is "
                f"{coverage['total']} — the split must account for the whole denominator"
            )
    else:
        failures.append("current.coverage must carry integer covered/partial/uncovered/total")

    for gid, row in (current.get("gates") or {}).items():
        if row.get("state") not in REQUIRED_GATE_STATES:
            failures.append(f"current.gates.{gid}: state {row.get('state')!r} not a recognised gate state")

    # every historical section must say when it was true and what replaced it
    for path in historical_sections(ledger):
        node = ledger
        for key in re.findall(r"[^.\[\]]+", path):
            node = node[int(key)] if key.isdigit() and isinstance(node, list) else node[key]
        for required in ("as_of_commit", "superseded_by"):
            if not node.get(required):
                failures.append(
                    f"{path}: historical sections must carry {required} — a superseded fact that "
                    f"does not say what replaced it reads as current"
                )

    # the guarded values: one home each.
    #
    # A CLOSED action row is historical by construction: it records what was
    # done, cites the commits that did it, and the transition checks refuse it
    # reopening or disappearing. Its prose is therefore a dated record, not a
    # current claim, and is exempt — an action still IN FLIGHT is not.
    exempt = {"current"} | set(historical_sections(ledger))
    for i, act in enumerate(ledger.get("actions", [])):
        if act.get("status") in CLOSED_ACTION_STATUSES and (act.get("commits") or []):
            exempt.add(f"actions[{i}]")
    for guard in current.get("guarded_patterns", []):
        pattern, owner = guard["pattern"], guard["owner"]
        for path, text in strings_outside(ledger, exempt):
            m = re.search(pattern, text)
            if m:
                failures.append(
                    f"{path}: states {m.group(0)!r}, which is owned by {owner} (R8-P0-02). "
                    f"A current fact has exactly one home; reference {owner} or mark the section "
                    f"historical: true with as_of_commit and superseded_by."
                )
    # values that are no longer true anywhere
    for stale in current.get("superseded_values", []):
        for path, text in strings_outside(ledger, exempt):
            m = re.search(stale["pattern"], text)
            if m:
                failures.append(
                    f"{path}: states {m.group(0)!r} — {stale['was']}, superseded by "
                    f"{stale['superseded_by']} (R8-P0-02)"
                )


def render_forbidden_reason(ledger: dict, rule: dict) -> str:
    """R8-P0-02: forbidden-claim reasons are GENERATED from canonical state.

    The audited file carried the reason "G0 is OPEN_RED while Mode-Q evidence is
    absent" beside a canonical row saying G0 is OPEN and a Mode-Q bundle that
    validates. A hand-written reason is a third copy of current truth.
    """
    source = rule.get("generated_from")
    if not source:
        return rule.get("reason", "")
    node = ledger
    for key in source.split("."):
        node = (node or {}).get(key, {})
    if source.startswith("current.gates."):
        gid = source.rsplit(".", 1)[-1]
        blockers = node.get("blockers") or []
        findings = node.get("blocking_findings") or []
        detail = "; ".join(findings + blockers) or "no recorded blocker"
        return f"{gid} is {node.get('state')} — remaining: {detail}"
    return rule.get("reason", "")


def check_generated_reasons(ledger: dict, failures: list[str]) -> None:
    for i, rule in enumerate(ledger.get("forbidden_claims", [])):
        if "generated_from" not in rule:
            continue
        expected = render_forbidden_reason(ledger, rule)
        if rule.get("reason") not in (None, expected):
            failures.append(
                f"forbidden_claims[{i}]: reason is hand-written but declares "
                f"generated_from={rule['generated_from']!r}; expected {expected!r}"
            )


def check_gate_state_reducer(ledger: dict, failures: list[str]) -> None:
    """R8-P0-02: the gate state is REDUCED from its blockers and the OPEN owner
    decisions it depends on — never asserted independently of them.

    The reducer is deliberately one-directional and conservative: it does not
    claim to compute the exact state, it refuses the states the evidence cannot
    support. A gate with a live blocking finding cannot be merely OPEN; a gate
    with any blocker or any OPEN owner decision cannot be CLOSED.
    """
    current = ledger.get("current") or {}
    decisions = {}
    registry = REPO / (ledger.get("owner_decisions_registry") or "")
    if registry.is_file():
        try:
            for entry in json.loads(registry.read_text()).get("entries", []):
                decisions[entry.get("id")] = entry.get("status")
        except Exception as error:
            failures.append(f"owner decision registry unreadable: {error}")
    for gid, row in (current.get("gates") or {}).items():
        state = row.get("state")
        blockers = list(row.get("blockers") or []) + list(row.get("blocking_findings") or [])
        open_decisions = [
            oid for oid in (row.get("owner_decisions") or []) if decisions.get(oid) == "OPEN"
        ]
        for oid in row.get("owner_decisions") or []:
            if oid not in decisions:
                failures.append(
                    f"current.gates.{gid}: names owner decision {oid}, which the registry "
                    f"{ledger.get('owner_decisions_registry')} does not contain"
                )
        if state in CLOSED_GATE_STATES and (blockers or open_decisions):
            failures.append(
                f"current.gates.{gid}: state {state} with live blockers {blockers} and OPEN owner "
                f"decisions {open_decisions} — a closed gate has neither"
            )


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
            failures.append(
                f"lane {lane.get('id')}: state {lane.get('state')!r} not in the lane-state enum"
            )
    for action in ledger.get("actions", []):
        if action.get("status") not in ACTION_STATUSES:
            failures.append(
                f"action {action.get('id')}: status {action.get('status')!r} not in the action-status enum"
            )

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
                failures.append(
                    f"action {action.get('id')}: commit {commit} is not an ancestor of HEAD"
                )

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


def check_present_state_contradictions(ledger: dict, failures: list[str]) -> None:
    """Round-5 R5-REL-01: the ledger must not mix historical action completion
    with a contradictory present gate state.

    Structured, conservative checks only — no prose scanning:
      - a closed action must cite the commits that closed it;
      - `closes` (the finding ids an action fully closed) is only meaningful
        on a closed action;
      - a gate/lane `blocking_findings` id that some closed action `closes`
        is a live contradiction: the blocker is either still live (then the
        action lied) or closed (then the gate text is stale). Reconcile the
        DATA; the linter refuses both.
    """

    def id_list_ok(owner: str, field: str, value) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list) or not all(
            isinstance(x, str) and FINDING_ID_RE.fullmatch(x) for x in value
        ):
            failures.append(
                f"{owner}: {field} must be a list of structured finding ids (got {value!r})"
            )
            return []
        return value

    closed_by: dict[str, str] = {}
    for action in ledger.get("actions", []):
        aid = action.get("id")
        status = action.get("status")
        closes = id_list_ok(f"action {aid}", "closes", action.get("closes"))
        if status in CLOSED_ACTION_STATUSES and not (action.get("commits") or []):
            failures.append(
                f"action {aid}: status {status} with no commits - a closed "
                f"action must cite the commits that closed it"
            )
        if closes and status not in CLOSED_ACTION_STATUSES:
            failures.append(
                f"action {aid}: lists closes={closes} but status {status!r} is "
                f"not a closed status - only a closed action closes a finding"
            )
        if status in CLOSED_ACTION_STATUSES:
            for f in closes:
                closed_by.setdefault(f, aid)

    # R8-P0-02: gate blocking findings live in the canonical `current` section;
    # lanes still carry their own.
    owners: list[tuple[str, str, object]] = [
        (f"gate {gid}", "current.gates", row.get("blocking_findings"))
        for gid, row in ((ledger.get("current") or {}).get("gates") or {}).items()
    ]
    owners += [
        (f"lane {entry.get('id')}", "lanes", entry.get("blocking_findings"))
        for entry in ledger.get("lanes", [])
    ]
    for owner, _where, value in owners:
        for f in id_list_ok(owner, "blocking_findings", value):
            if f in closed_by:
                failures.append(
                    f"{owner}: names finding {f} as still "
                    f"blocking, but closed action {closed_by[f]} records "
                    f"it closed - the gate state and the action history "
                    f"contradict; reconcile the ledger data"
                )


def check_committed_transitions(ledger: dict, failures: list[str]) -> None:
    """Round-5 R5-REL-01: impossible status transitions, fail-closed.

    The baseline is the last COMMITTED ledger: HEAD's copy when the working
    file differs from it (an edit under review), otherwise first-parent
    HEAD~1's copy (so every CI run validates the transition the commit under
    test actually made). Against that baseline: a closed action may never
    silently reopen, and an action row may never disappear — history is
    corrected by follow-up rows, not erased. No baseline (initial commit,
    file not yet tracked) skips the check; an unreadable baseline fails.
    """
    rel = "docs/ledger/gates.json"

    def show(ref: str):
        r = subprocess.run(
            ["git", "-C", str(REPO), "show", f"{ref}:{rel}"], capture_output=True, text=True
        )
        return r.stdout if r.returncode == 0 else None

    head_text = show("HEAD")
    if head_text is None:
        return  # not yet tracked: nothing to compare against
    baseline_text = head_text if head_text != LEDGER.read_text() else show("HEAD~1")
    if baseline_text is None:
        return  # initial commit
    try:
        baseline = json.loads(baseline_text)
    except Exception as error:
        failures.append(f"last committed ledger is unreadable: {error}")
        return
    current_actions = {a.get("id"): a for a in ledger.get("actions", [])}
    for prev in baseline.get("actions", []):
        pid = prev.get("id")
        cur = current_actions.get(pid)
        if cur is None:
            failures.append(
                f"action {pid}: present in the last committed ledger but "
                f"DELETED here - history rows may be corrected, never erased"
            )
            continue
        if (
            prev.get("status") in CLOSED_ACTION_STATUSES
            and cur.get("status") not in CLOSED_ACTION_STATUSES
        ):
            failures.append(
                f"action {pid}: impossible status transition "
                f"{prev.get('status')} -> {cur.get('status')} - a closed "
                f"action cannot silently reopen; record a NEW action for the "
                f"regression instead"
            )


def main() -> int:
    failures: list[str] = []
    try:
        ledger = json.loads(LEDGER.read_text())
    except Exception as error:  # malformed ledger is a hard failure
        print(f"LEDGER LINT: FAIL - ledger unreadable: {error}")
        return 1

    for key in ("current", "gates", "lanes", "actions", "forbidden_claims", "adopted_audit"):
        if key not in ledger:
            failures.append(f"ledger missing required key: {key}")
    # R8-P0-02: a gate NARRATIVE row may not carry a state — the state lives in
    # `current.gates` and only there.
    for g in ledger.get("gates", []):
        if "state" in g:
            failures.append(
                f"gate {g.get('id')}: narrative rows must not carry `state` (R8-P0-02); the "
                f"canonical state is current.gates.{g.get('id')}.state"
            )
    declared = {g.get("id") for g in ledger.get("gates", [])}
    canonical = set((ledger.get("current") or {}).get("gates") or {})
    for missing in sorted(declared - canonical):
        failures.append(f"gate {missing}: no canonical state in current.gates")
    for extra in sorted(canonical - declared):
        failures.append(f"current.gates.{extra}: no narrative gate row declares this id")

    # round-3 E-07 semantic checks (ids, enums, commit ancestry, evidence paths)
    check_semantics(ledger, failures)

    # round-5 R5-REL-01: present-state vs history contradictions, and
    # impossible transitions against the last committed ledger
    check_present_state_contradictions(ledger, failures)
    check_committed_transitions(ledger, failures)

    # round-8 R8-P0-02: one canonical current fact set, generated forbidden
    # reasons, and a gate state reduced from its own blockers
    check_single_canonical_current(ledger, failures)
    check_generated_reasons(ledger, failures)
    check_gate_state_reducer(ledger, failures)

    # 2. rendered-block drift
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import render_status  # noqa: E402

    operations = (REPO / "docs" / "operations.md").read_text()
    if render_status.BEGIN not in operations or render_status.END not in operations:
        failures.append("docs/operations.md is missing the generated gate-table markers")
    else:
        current = operations.split(render_status.BEGIN, 1)[1].split(render_status.END, 1)[0]
        expected = (
            render_status.render().split(render_status.BEGIN, 1)[1].split(render_status.END, 1)[0]
        )
        if current != expected:
            failures.append(
                "docs/operations.md gate table drifted from the ledger - run tools/ledger/render_status.py"
            )

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
            reason = render_forbidden_reason(ledger, rule)
            for m in re.finditer(rule["pattern"], text):
                failures.append(f"{rel}: forbidden claim {m.group(0)!r} - {reason}")
        # R8-P0-02 / R8-P2-06: a live status document may not restate a current
        # fact either. The generated block (stripped above) is where these
        # values belong; a hand-typed copy elsewhere in the same file is the
        # "13,582 rows" / "G0 red" / "Mode-Q absent" staleness the round-8 audit
        # found still readable as current.
        current = ledger.get("current") or {}
        for guard in current.get("guarded_patterns", []):
            for m in re.finditer(guard["pattern"], text):
                failures.append(
                    f"{rel}: states {m.group(0)!r}, which is owned by {guard['owner']} "
                    f"(R8-P0-02). Live status prose must read it from the generated block."
                )
        for stale in current.get("superseded_values", []):
            for m in re.finditer(stale["pattern"], text):
                failures.append(
                    f"{rel}: states {m.group(0)!r} — {stale['was']}, superseded by "
                    f"{stale['superseded_by']} (R8-P2-06)"
                )

    if failures:
        print("LEDGER LINT: FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(
        f"LEDGER LINT: PASS ({len(ledger['gates'])} gates, {len(ledger['lanes'])} lanes, "
        f"{len(ledger['actions'])} actions, {len(STATUS_DOCS)} status docs scanned)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
