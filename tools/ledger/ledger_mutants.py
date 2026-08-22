#!/usr/bin/env python3
"""Behavioral mutants for the ledger linter (round-5 R5-REL-01).

Grepping the linter for check names proves nothing; each protection below is
proved by EXECUTING the linter over a deliberately bad ledger and requiring
it to fail with the intended diagnostic. A mutant that survives (linter
passes, or fails for an unrelated reason) fails this script.

Method: a disposable `git worktree` of HEAD (so commit-ancestry checks see
the real repository history), overlaid with the CURRENT working-tree
versions of the ledger, the rendered status, and the ledger tools (so the
mutants always test the linter as it is being edited, before commit). Each
mutant rewrites the worktree's ledger/status copy, runs the real linter as a
subprocess, and must observe (a) a nonzero exit and (b) the specific
diagnostic of the check that mutant exists to prove. The unmutated baseline
must PASS first, or the harness itself is broken.
"""

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
LEDGER_REL = "docs/ledger/gates.json"
OVERLAY = [
    "docs/ledger/gates.json",
    "docs/operations.md",
    "docs/handoff-live-validation.md",
    "docs/tasks/NEXT-SESSION.md",
    "README.md",
    "docs/owner-decisions.json",
    "tools/ledger/lint_ledger.py",
    "tools/ledger/render_status.py",
]

GIT_IDENT = {
    "GIT_AUTHOR_NAME": "ledger-mutants",
    "GIT_AUTHOR_EMAIL": "ledger-mutants@invalid",
    "GIT_COMMITTER_NAME": "ledger-mutants",
    "GIT_COMMITTER_EMAIL": "ledger-mutants@invalid",
}


def run_linter(wt: pathlib.Path):
    r = subprocess.run(
        [sys.executable, str(wt / "tools" / "ledger" / "lint_ledger.py")],
        capture_output=True,
        text=True,
        cwd=wt,
    )
    return r.returncode, r.stdout + r.stderr


def main() -> int:
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="ledger-mutants-"))
    wt = tmp / "wt"
    subprocess.run(
        ["git", "-C", str(REPO), "worktree", "add", "--detach", str(wt), "HEAD"],
        check=True,
        capture_output=True,
    )
    failures: list[str] = []
    executed: list[str] = []
    try:
        # R8-P2-06: overlay every LIVE DOCUMENT the guard scans, derived from
        # the guard's own globs rather than from a second list here. The
        # worktree is checked out at HEAD, so a document fixed in the working
        # tree would otherwise still carry its stale number inside the mutant
        # harness — every mutant would then "die for the wrong reason" and the
        # suite would report a failure that is really a staleness in its own
        # fixture. Deriving the set means the harness cannot fall behind the
        # guard as the guard widens.
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
        import lint_ledger  # noqa: E402

        for rel in list(dict.fromkeys(OVERLAY + lint_ledger.live_documents())):
            source = REPO / rel
            if not source.is_file():
                continue
            (wt / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, wt / rel)
        pristine_ledger = (wt / LEDGER_REL).read_text()
        pristine_ops = (wt / "docs" / "operations.md").read_text()

        # a dangling commit that EXISTS in the shared object db but is no
        # ancestor of HEAD (for the ancestry mutant)
        import os

        dangling = subprocess.run(
            [
                "git",
                "-C",
                str(wt),
                "commit-tree",
                "HEAD^{tree}",
                "-m",
                "ledger-mutants: dangling non-ancestor",
            ],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, **GIT_IDENT},
        ).stdout.strip()

        # baseline: the unmutated overlay must PASS
        rc, out = run_linter(wt)
        if rc != 0:
            print("HARNESS BROKEN: the unmutated ledger fails the linter:\n" + out)
            return 1

        def mutate_ledger(fn):
            ledger = json.loads(pristine_ledger)
            fn(ledger)
            (wt / LEDGER_REL).write_text(json.dumps(ledger, indent=1) + "\n")

        def action(ledger, aid):
            return next(a for a in ledger["actions"] if a["id"] == aid)

        def gate(ledger, gid):
            """R8-P0-02: the canonical gate row lives in `current.gates`."""
            return ledger["current"]["gates"][gid]

        def gate_narrative(ledger, gid):
            return next(g for g in ledger["gates"] if g["id"] == gid)

        MUTANTS = [
            (
                "duplicate-gate-id",
                lambda ledger: ledger["gates"].append(dict(ledger["gates"][0])),
                "duplicate gate id",
            ),
            (
                "duplicate-lane-id",
                lambda ledger: ledger["lanes"].append(dict(ledger["lanes"][0])),
                "duplicate lane id",
            ),
            (
                "duplicate-action-id",
                lambda ledger: ledger["actions"].append(dict(ledger["actions"][0])),
                "duplicate action id",
            ),
            (
                "lane-state-outside-enum",
                lambda ledger: ledger["lanes"][0].__setitem__("state", "GREEN"),
                "not in the lane-state enum",
            ),
            (
                "action-status-outside-enum",
                lambda ledger: action(ledger, "PR0").__setitem__("status", "FINISHED"),
                "not in the action-status enum",
            ),
            (
                "done-action-with-no-commits",
                lambda ledger: action(ledger, "R4-A").__setitem__("commits", []),
                "a closed action must cite the commits that closed it",
            ),
            (
                "done-action-citing-nonexistent-commit",
                lambda ledger: action(ledger, "R4-A").__setitem__(
                    "commits", ["1234567890abcdef1234567890abcdef12345678"]
                ),
                "does not exist in this repository",
            ),
            (
                "done-action-citing-non-ancestor-commit",
                lambda ledger: action(ledger, "R4-A").__setitem__("commits", [dangling]),
                "is not an ancestor of HEAD",
            ),
            (
                "gate-blocking-finding-closed-by-done-action",
                # PR4b (DONE) closes C-P0-01; a gate that still calls it
                # blocking is the audit's "old blocker beside a later done
                # action" contradiction
                lambda ledger: gate(ledger, "G1")["blocking_findings"].append("C-P0-01"),
                "records it closed",
            ),
            (
                "closes-claim-on-unclosed-action",
                lambda ledger: action(ledger, "PR6").__setitem__("closes", ["R4-CF-00"]),
                "not a closed status",
            ),
            (
                "closed-action-silently-reopened",
                lambda ledger: action(ledger, "R4-A").__setitem__("status", "OPEN"),
                "impossible status transition",
            ),
            (
                "action-row-erased-from-history",
                lambda ledger: ledger["actions"].__setitem__(
                    slice(None), [a for a in ledger["actions"] if a["id"] != "PR0"]
                ),
                "history rows may be corrected, never erased",
            ),
            (
                "ledger-edit-without-rerender",
                lambda ledger: gate_narrative(ledger, "G1").__setitem__(
                    "why", gate_narrative(ledger, "G1")["why"] + " (mutated)"
                ),
                "gate table drifted from the ledger",
            ),
            # ---------------------------------------------------------------
            # R8-P0-02 semantic mutants. The model is static-mutant control 11:
            # update every SHALLOW binding and require an independent
            # re-derivation — or the single-home rule — to catch the lie.
            # The five that need evidence re-derivation live in
            # tools/ledger/ledger_semantic_mutants.py; these are the ones the
            # cheap schema lint must catch by itself.
            # ---------------------------------------------------------------
            (
                "current-gate-state-copied-into-a-second-field",
                # the exact round-8 defect: `gates[G0].state = OPEN` beside
                # `q_dispositions.G0 = OPEN_RED`
                lambda ledger: ledger["q_dispositions"].__setitem__("G0", "OPEN_RED"),
                "owned by current.gates.G0.state",
            ),
            (
                "current-gate-state-restated-in-live-prose",
                lambda ledger: gate_narrative(ledger, "G0").__setitem__(
                    "why", gate_narrative(ledger, "G0")["why"] + " G0 is OPEN_RED."
                ),
                "owned by current.gates.G0.state",
            ),
            (
                "coverage-count-copied-into-a-second-field",
                lambda ledger: ledger["q_dispositions"].__setitem__(
                    "mutant_probe", "coverage is 13,723 of 23,138 rows"
                ),
                "owned by current.coverage.covered",
            ),
            (
                "superseded-count-revived-as-current",
                lambda ledger: ledger["q_dispositions"].__setitem__(
                    "mutant_probe", "execution coverage is 914 of 23,138 rows"
                ),
                "the round-6 leaf coverage numerator",
            ),
            (
                "coverage-split-does-not-account-for-the-denominator",
                lambda ledger: ledger["current"]["coverage"].__setitem__("uncovered", 9000),
                "must account for the whole denominator",
            ),
            (
                "historical-section-without-what-superseded-it",
                lambda ledger: ledger["q_dispositions"]["evidence_denominator"].pop(
                    "superseded_by"
                ),
                "historical sections must carry superseded_by",
            ),
            (
                "gate-narrative-row-regrows-a-state-field",
                lambda ledger: gate_narrative(ledger, "G0").__setitem__("state", "CLOSED"),
                "narrative rows must not carry `state`",
            ),
            (
                "canonical-gate-state-outside-enum",
                lambda ledger: gate(ledger, "G0").__setitem__("state", "GREEN"),
                "not a recognised gate state",
            ),
            (
                "gate-closed-while-its-own-blockers-are-live",
                lambda ledger: gate(ledger, "G0").__setitem__("state", "CLOSED"),
                "a closed gate has neither",
            ),
            (
                "forbidden-claim-reason-hand-written-over-the-generated-one",
                lambda ledger: ledger["forbidden_claims"][0].__setitem__(
                    "reason", "G0 is OPEN_RED while Mode-Q evidence is absent"
                ),
                "reason is hand-written but declares generated_from",
            ),
            (
                "gate-names-an-owner-decision-the-registry-does-not-have",
                lambda ledger: gate(ledger, "G1").__setitem__("owner_decisions", ["OD-999"]),
                "does not contain",
            ),
            (
                "ledger-references-missing-evidence-path",
                lambda ledger: ledger["q_dispositions"].__setitem__(
                    "mutant_probe", "see docs/evidence/DOES-NOT-EXIST.json"
                ),
                "does not exist",
            ),
        ]

        for name, fn, expect in MUTANTS:
            (wt / LEDGER_REL).write_text(pristine_ledger)
            (wt / "docs" / "operations.md").write_text(pristine_ops)
            mutate_ledger(fn)
            rc, out = run_linter(wt)
            executed.append(name)
            if rc == 0:
                failures.append(f"mutant '{name}' SURVIVED (linter passed)")
            elif expect not in out:
                failures.append(
                    f"mutant '{name}' died for the WRONG reason "
                    f"(expected {expect!r} in output):\n{out}"
                )

        # forbidden-claim mutant lives in the STATUS DOC, not the ledger
        (wt / LEDGER_REL).write_text(pristine_ledger)
        (wt / "docs" / "operations.md").write_text(pristine_ops + "\nOverall U3.0 is green now.\n")
        rc, out = run_linter(wt)
        executed.append("forbidden-claim-in-status-doc")
        if rc == 0:
            failures.append("mutant 'forbidden-claim-in-status-doc' SURVIVED")
        elif "forbidden claim" not in out:
            failures.append(
                f"mutant 'forbidden-claim-in-status-doc' died for the WRONG reason:\n{out}"
            )
        # R8-P2-06: the scan covers EVERY live document, not the four status
        # paths. The audit found `13,582 rows`, `G0 red` and `Mode-Q absent`
        # still readable as current in a workflow comment and a planning
        # document — files nobody thinks of as status, and which therefore
        # never got corrected. Each subject below is a file OUTSIDE the four,
        # and each must be refused.
        for name, rel, injected, expect in (
            (
                "stale-number-in-a-planning-document",
                "docs/local-dev-parity-plan.md",
                "\n\nLeaf coverage today is 13,723 of 23,138 rows.\n",
                "owned by current.coverage",
            ),
            (
                "stale-gate-state-in-a-workflow-comment",
                ".github/workflows/gates.yml",
                "\n# note: G0 is OPEN_RED, so the release job is expected to refuse.\n",
                "owned by current.gates.G0.state",
            ),
            (
                "superseded-count-revived-in-a-design-adjacent-live-document",
                "docs/development.md",
                "\n\nThe uncovered remainder is 22,115 rows.\n",
                "superseded by",
            ),
            (
                "forbidden-claim-in-a-document-outside-the-four-status-paths",
                "docs/user-guide.md",
                "\n\nOverall U3.0 is green now.\n",
                "forbidden claim",
            ),
        ):
            (wt / LEDGER_REL).write_text(pristine_ledger)
            (wt / "docs" / "operations.md").write_text(pristine_ops)
            target = wt / rel
            pristine_target = target.read_text()
            target.write_text(pristine_target + injected)
            rc, out = run_linter(wt)
            target.write_text(pristine_target)
            executed.append(name)
            if rc == 0:
                failures.append(f"mutant {name!r} SURVIVED (linter passed)")
            elif expect not in out:
                failures.append(
                    f"mutant {name!r} died for the WRONG reason (expected {expect!r}):\n{out}"
                )

        # A live document may declare itself HISTORICAL — but only by naming a
        # commit that exists and is an ancestor. A marker that names nothing is
        # provenance-shaped text with no provenance, and would otherwise be the
        # one-line way to switch the whole guard off.
        (wt / LEDGER_REL).write_text(pristine_ledger)
        (wt / "docs" / "operations.md").write_text(pristine_ops)
        target = wt / "docs" / "development.md"
        pristine_target = target.read_text()
        target.write_text(
            "<!-- HISTORICAL AS OF deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -->\n"
            + pristine_target
            + "\n\nThe uncovered remainder is 22,115 rows.\n"
        )
        rc, out = run_linter(wt)
        target.write_text(pristine_target)
        executed.append("historical-marker-naming-a-commit-that-does-not-exist")
        if rc == 0:
            failures.append(
                "mutant 'historical-marker-naming-a-commit-that-does-not-exist' SURVIVED: a "
                "document can disclaim itself out of the guard without dating itself"
            )
        elif "not a commit in this repository" not in out:
            failures.append(
                "mutant 'historical-marker-naming-a-commit-that-does-not-exist' died for the "
                f"WRONG reason:\n{out}"
            )
    finally:
        subprocess.run(
            ["git", "-C", str(REPO), "worktree", "remove", "--force", str(wt)], capture_output=True
        )
        shutil.rmtree(tmp, ignore_errors=True)

    for f in failures:
        print(f"LEDGER MUTANTS: FAIL - {f}")
    # The tally names the SURVIVORS, not the roster. Printing every executed
    # name after the word "killed" is how a failing suite reads like a passing
    # one at a glance: the round-8 run reported
    # "25 killed: ..., current-gate-state-copied-into-a-second-field, ..."
    # while that very mutant was the one that survived.
    survived = {name for name in executed if any(repr(name) in f for f in failures)}
    killed = [name for name in executed if name not in survived]
    verdict = "FAIL" if failures else "PASS"
    print(
        f"LEDGER MUTANTS: {verdict} "
        f"({len(executed)} mutants executed, {len(killed)} killed"
        + (f", {len(survived)} NOT killed: {', '.join(sorted(survived))}" if survived else "")
        + ")"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
