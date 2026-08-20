#!/usr/bin/env python3
"""Shipped-posture suite gate for the SlateDB fork (R6-FORK-01).

WHAT THIS GATE'S "PASS" MEANS
-----------------------------
The strict `external_epoch_required` fence SHIPS (see
tools/fork/check_strict_epoch.py). The round-5 version of this script ran the
feature-on suite, parsed every failure, and passed if each failure carried the
expected missing-epoch refusal. That invariant did find three genuine
regressions hiding among the refusals — but it let a run of **1,566 passed /
420 failed** be reported as a suite PASS, and the round-6 audit was right that
this "invites false qualification": those 420 tests were refused during an
epoch-less OPEN, so their bodies never exercised reads, writes, compaction,
manifest handling, recovery, GC, concurrency, or fault behaviour under the
feature that actually ships.

This gate therefore passes only when ALL of the following hold:

  1. feature OFF, EVERY test target -> fully green. The upstream-regression
     oracle: the fork must not change upstream semantics outside its series.
     "Every target" means `--tests`: the library suite AND the four
     integration targets, which round 5 never measured at all.
  2. feature ON, EVERY test target  -> fully green. Not "green except for
     expected refusals" — GREEN. Patch 0006 gives the crate's own test build a
     harness controller that issues a deterministic per-database epoch to any
     open that does not name one, so upstream test BODIES execute under the
     shipped fence; the integration targets, which compile against the SHIPPED
     library and cannot see that seam, name their epochs explicitly.
  3. the dedicated NEGATIVE fence suite -> green and non-empty. The seam in
     (2) could hide the very refusal it works around; these tests opt out of
     it and prove an omitted epoch still fails closed.
  4. LEAF RECONCILIATION -> every test executed feature-off is also executed
     feature-on, except the tests enumerated in EXCLUSIONS below, each with a
     reviewed reason; and every test executed feature-on but not feature-off is
     enumerated in FEATURE_ON_ONLY. This is the clause that proves the
     formerly-skipped bodies RAN: it compares executed leaf identities, not
     just counts, so a test that silently stops being compiled is caught.

Anything less prints FAIL.

`--quick` is the PR-tier shape used by CI: it still runs clauses 2 and 3 in
full — every feature-on target must be green, which is the expensive and
load-bearing clause R6-FORK-01 asks CI to add — and skips clause 1 (and
therefore clause 4, which needs feature-off's leaf list). Its verdict is
`PARTIAL`, never the bare word `PASS`, and it names what it did not prove.
Only a full run prints `PASS`.

    python3 tools/fork/check_strict_epoch_suite.py
    python3 tools/fork/check_strict_epoch_suite.py --quick
    python3 tools/fork/check_strict_epoch_suite.py --evidence out.json
"""

import argparse
import json
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
FORK = REPO / "sources" / "slatedb-fork"
TOOLCHAIN = "+1.93.0"
FEATURES_OFF = "test-util"
FEATURES_ON = "test-util,external_epoch_required"

# Recorded doc-example population. Cross-posture equality alone is NOT enough:
# marking an example ```ignore``` lowers the executed count in BOTH postures
# equally, so it would sail through an equality check. These are the floor and
# ceiling, and they may only move in the commit that explains why — the same
# discipline the EXCLUSIONS list carries.
DOC_MIN_EXECUTED = 59
DOC_MAX_IGNORED = 7

# Tests that are genuinely INAPPLICABLE under the shipped posture. Each entry
# must name an exact leaf identity and a reviewed reason: "it fails" is not a
# reason, and an early-open failure is not by itself evidence of
# inapplicability. The gate REQUIRES that every name here is executed
# feature-off and absent feature-on — a stale exclusion fails the gate rather
# than silently widening it.
#
# This list is currently EMPTY, and that is the measured result, not an
# aspiration. Round 5 excluded three tests
# (`test_writer_paused_in_replay_wal_should_be_fenced_by_concurrent_open`,
# `wal_replay_not_found_should_be_fenced_when_writer_epoch_advanced`,
# `wal_replay_not_found_should_remain_not_found_when_writer_epoch_unchanged`)
# on the grounds that they assert INTERNAL writer-epoch allocation. Re-measured
# with the harness controller in place, they pass: what they actually assert is
# that a second writer holding a higher epoch fences the first, which is true
# of controller-issued epochs too — the harness issues 1 then 2 for the same
# database, exactly the values those tests expect. Patch 0005 is withdrawn.
EXCLUSIONS: dict[str, str] = {}

# Tests that exist ONLY under the shipped posture (they are `cfg`-gated on the
# feature), so they legitimately appear feature-on and not feature-off.
FEATURE_ON_ONLY: dict[str, str] = {
    "lib::db::builder::tests::negative_fence_a_missing_external_epoch_is_refused_not_defaulted": "negative fence: an epoch-less open is a typed Invalid refusal and does not advance the stored epoch",
    "lib::db::builder::tests::negative_fence_an_epoch_less_open_creates_no_database": "negative fence: an epoch-less FIRST open is refused before any manifest is created",
    "lib::db::builder::tests::negative_fence_a_harness_issued_epoch_cannot_be_replayed": "negative fence: replaying an epoch the harness already claimed is Fenced, so the harness does not weaken the fence",
    "lib::db::builder::tests::negative_fence_harness_epochs_are_exact_and_monotonic_per_database": "witness: the Nth harness-issued open of a database claims epoch N exactly, so the adapted suite runs on external epochs",
    "lib::fence::tests::negative_fence_the_fencer_refuses_an_unnamed_epoch": "negative fence: WriterFencer refuses an unnamed epoch on its own, independently of the builder's early refusal",
}

# The negative suite is selected by this substring filter; every test in
# FEATURE_ON_ONLY that is part of the fence proof carries the prefix.
NEGATIVE_FILTER = "negative_fence_"

TEST_RESULT = re.compile(
    r"^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored", re.M
)
# `#[should_panic]` tests render as `test NAME - should panic ... ok`, so the
# suffix is optional here. Getting this wrong silently drops 22 leaves and
# would make the reconciliation clause lie in the safe-looking direction.
TEST_LEAF = re.compile(r"^test (\S+)(?: - should panic)? \.\.\. (ok|FAILED|ignored)", re.M)
FAILED_CASE = re.compile(r"^---- (\S+) stdout ----$", re.M)
# `cargo test` announces each test BINARY before running it. Leaf identities are
# qualified with the binary so the library suite and the four integration
# targets cannot collide (or, worse, silently dedupe) in the reconciliation.
TARGET = re.compile(r"^\s+Running (?:unittests )?(\S+) \(", re.M)

# The exact refusal the fence raises. Kept only to explain a failure, never to
# excuse one: under this gate a fence refusal in the full feature-on suite is a
# BUG in the harness seam, not an expected outcome.
FENCE_REFUSAL = "external writer epoch required: internal allocation is observe-and-bind"


def run_doc(features: str) -> tuple[int, str]:
    """Run the rustdoc examples.

    A published example is a claim about the API, and this fork ships
    `external_epoch_required` ON: an example that opens a database without
    naming a writer epoch documents something the shipped posture refuses.
    Round 6 measured 16 passed / 43 FAILED here while every test BODY was
    green, so doc-tests get their own clause rather than riding along.
    """
    args = ["cargo", TOOLCHAIN, "test", "--doc", "--features", features]
    proc = subprocess.run(args, cwd=FORK, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def doc_counts(out: str) -> tuple[int, int, int]:
    """(passed, failed, ignored) summed over the doc-test summary lines."""
    passed = failed = ignored = 0
    for line in out.splitlines():
        if line.startswith("test result:"):
            for n, key in re.findall(r"(\d+) (passed|failed|ignored)", line):
                if key == "passed":
                    passed += int(n)
                elif key == "failed":
                    failed += int(n)
                else:
                    ignored += int(n)
    return passed, failed, ignored


def run(features: str, filt: str | None = None) -> tuple[int, str]:
    """Run EVERY test target: the library suite and the integration targets.

    `--tests` rather than `--lib`. The round-5 measurement was library-only,
    and an integration target is exactly where a fence that ships would bite a
    consumer first — it compiles against the shipped library, with no
    `cfg(test)` seam available to it.
    """
    # --no-fail-fast: cargo stops after the first failing BINARY by default, so
    # a single library failure would hide the integration targets entirely and
    # the reconciliation would report them as "did not execute".
    args = ["cargo", TOOLCHAIN, "test", "--tests", "--no-fail-fast", "--features", features]
    if filt:
        args.append(filt)
    # stderr MERGED into stdout, not concatenated after it. cargo announces each
    # test binary ("Running tests/db.rs (...)") on stderr while libtest reports
    # results on stdout; concatenating puts every marker after every result and
    # the leaf-to-binary attribution silently collapses to nothing.
    proc = subprocess.run(
        args, cwd=FORK, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    return proc.returncode, proc.stdout


def target_label(binary_path: str) -> str:
    """`src/lib.rs` -> `lib`; `tests/db.rs` -> `db`."""
    name = binary_path.rsplit("/", 1)[-1]
    return "lib" if name == "lib.rs" else name.removesuffix(".rs")


def accounted_for(
    label: str, passed: int, failed: int, ignored: int, leaf_names: dict[str, str]
) -> str | None:
    """Every counted test must also appear as a named leaf.

    The reconciliation clause compares leaf IDENTITIES, so a parsing gap would
    show up as tests that "did not execute" — a false accusation pointing away
    from the real fault. Check the two numbers agree first.
    """
    total = passed + failed + ignored
    if total == len(leaf_names):
        return None
    return (
        f"{label}: {total} tests reported but {len(leaf_names)} leaf identities parsed — "
        f"the output could not be accounted for, so reconciliation cannot be trusted"
    )


def ran_at_all(label: str, rc: int, output: str) -> str | None:
    """A run that never reached a `test result:` line did not measure anything.

    Reporting that as "0 passed, 0 failed" would be the same class of mistake
    this gate exists to correct: an absence of evidence rendered as a number.
    A harness that is OOM-killed or starved on a shared machine looks exactly
    like this, so say so and show the tail.
    """
    if TEST_RESULT.search(output):
        return None
    tail = "\n".join(line for line in output.splitlines()[-12:] if line.strip())
    return (
        f"{label}: cargo exited {rc} without producing a `test result:` line — the suite "
        f"did not run, so nothing was measured (a killed or starved test harness looks "
        f"like this). Last output:\n      " + tail.replace("\n", "\n      ")
    )


def counts(output: str) -> tuple[int, int, int]:
    passed = failed = ignored = 0
    for p, f, i in TEST_RESULT.findall(output):
        passed += int(p)
        failed += int(f)
        ignored += int(i)
    return passed, failed, ignored


def leaves(output: str) -> dict[str, str]:
    """Executed leaf identities -> outcome. This is the coverage evidence.

    Identities are `<target>::<test path>`, so `lib::db::tests::foo` and an
    integration test of the same name stay distinct.
    """
    marks = [(target_label(m.group(1)), m.start()) for m in TARGET.finditer(output)]
    found: dict[str, str] = {}
    for i, (label, start) in enumerate(marks):
        end = marks[i + 1][1] if i + 1 < len(marks) else len(output)
        for name, outcome in TEST_LEAF.findall(output[start:end]):
            found[f"{label}::{name}"] = outcome
    return found


def failing_blocks(output: str) -> dict[str, str]:
    blocks: dict[str, str] = {}
    marks = [(m.group(1), m.start()) for m in FAILED_CASE.finditer(output)]
    for i, (name, start) in enumerate(marks):
        end = marks[i + 1][1] if i + 1 < len(marks) else len(output)
        blocks[name] = output[start:end]
    return blocks


def describe_failures(output: str) -> str:
    blocks = failing_blocks(output)
    if not blocks:
        return ""
    fenced = sorted(n for n, b in blocks.items() if FENCE_REFUSAL in b)
    other = sorted(n for n in blocks if n not in fenced)
    lines = []
    if fenced:
        lines.append(
            f"    {len(fenced)} failed at the FENCE (an open with no epoch reached the "
            f"fence — the harness seam did not cover it):"
        )
        lines += [f"      {n}" for n in fenced[:20]]
    if other:
        lines.append(f"    {len(other)} failed for another reason (genuine regression):")
        lines += [f"      {n}" for n in other[:20]]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--quick",
        action="store_true",
        help="PR tier: run the feature-on full suite and the negative suite, but "
        "skip the feature-off oracle and the leaf reconciliation. Verdict is "
        "PARTIAL, never PASS.",
    )
    ap.add_argument(
        "--evidence",
        metavar="PATH",
        help="write executed leaf identities and counts to PATH as JSON",
    )
    args = ap.parse_args()

    if not FORK.exists():
        print(f"FAIL: {FORK} absent — run tools/fork/materialize_slatedb.py first", file=sys.stderr)
        return 2

    failures: list[str] = []
    evidence: dict = {
        "gate": "R6-FORK-01 shipped-posture suite gate",
        "toolchain": TOOLCHAIN,
        "exclusions": EXCLUSIONS,
        "feature_on_only": FEATURE_ON_ONLY,
    }
    off_leaves: dict[str, str] = {}

    # ---- clause 1: feature OFF, full suite -> upstream-regression oracle ----
    if not args.quick:
        rc, out = run(FEATURES_OFF)
        did_not_run = ran_at_all("feature-OFF all targets", rc, out)
        if did_not_run:
            failures.append(did_not_run)
        passed, failed, ignored = counts(out)
        off_leaves = leaves(out)
        print(
            f"feature-OFF  all targets : {passed} passed, {failed} failed, {ignored} ignored "
            f"({len(off_leaves)} leaves executed)"
        )
        if rc != 0 or failed != 0 or passed == 0:
            failures.append(
                f"feature-OFF all targets are not green: {passed} passed, {failed} failed"
            )
            detail = describe_failures(out)
            if detail:
                failures.append(detail)
        gap = accounted_for("feature-OFF all targets", passed, failed, ignored, off_leaves)
        if gap:
            failures.append(gap)
        evidence["feature_off"] = {
            "passed": passed,
            "failed": failed,
            "ignored": ignored,
            "leaves": sorted(off_leaves),
        }

    # ---- clause 2: feature ON, full suite -> must be GREEN, not "expected" ----
    rc, out = run(FEATURES_ON)
    did_not_run = ran_at_all("feature-ON all targets", rc, out)
    if did_not_run:
        failures.append(did_not_run)
    on_passed, on_failed, on_ignored = counts(out)
    on_leaves = leaves(out)
    print(
        f"feature-ON   all targets : {on_passed} passed, {on_failed} failed, {on_ignored} ignored "
        f"({len(on_leaves)} leaves executed)"
    )
    if rc != 0 or on_failed != 0 or on_passed == 0:
        failures.append(
            f"feature-ON all targets are not green: {on_passed} passed, {on_failed} failed. "
            f"A refusal here is NOT an expected outcome — it means an open with no epoch was "
            f"not covered by the harness seam (patch 0006), or a real regression."
        )
        detail = describe_failures(out)
        if detail:
            failures.append(detail)
    gap = accounted_for("feature-ON all targets", on_passed, on_failed, on_ignored, on_leaves)
    if gap:
        failures.append(gap)
    evidence["feature_on"] = {
        "passed": on_passed,
        "failed": on_failed,
        "ignored": on_ignored,
        "leaves": sorted(on_leaves),
    }

    # ---- clause 3: the dedicated negative fence suite ----
    rc, out = run(FEATURES_ON, NEGATIVE_FILTER)
    did_not_run = ran_at_all("negative fence suite", rc, out)
    if did_not_run:
        failures.append(did_not_run)
    neg_passed, neg_failed, _ = counts(out)
    neg_leaves = leaves(out)
    expected_neg = {n for n in FEATURE_ON_ONLY if NEGATIVE_FILTER in n}
    print(
        f"feature-ON   negative suite: {neg_passed} passed, {neg_failed} failed "
        f"({len(neg_leaves)} leaves executed)"
    )
    if rc != 0 or neg_failed != 0 or neg_passed == 0:
        failures.append(
            f"negative fence suite is not green: {neg_passed} passed, {neg_failed} failed"
        )
    if set(neg_leaves) != expected_neg:
        failures.append(
            "negative fence suite does not match its declared membership:\n"
            f"    ran but undeclared : {sorted(set(neg_leaves) - expected_neg)}\n"
            f"    declared but absent: {sorted(expected_neg - set(neg_leaves))}"
        )
    evidence["negative_suite"] = {
        "passed": neg_passed,
        "failed": neg_failed,
        "leaves": sorted(neg_leaves),
    }

    # ---- clause 4: leaf reconciliation -> the bodies actually ran ----
    if not args.quick:
        missing = set(off_leaves) - set(on_leaves)
        extra = set(on_leaves) - set(off_leaves)
        declared_excluded = set(EXCLUSIONS)
        declared_extra = set(FEATURE_ON_ONLY)

        undeclared_missing = sorted(missing - declared_excluded)
        stale_exclusions = sorted(declared_excluded - missing)
        undeclared_extra = sorted(extra - declared_extra)
        stale_extra = sorted(declared_extra - extra)

        print(
            f"leaf reconciliation      : feature-off {len(off_leaves)} - "
            f"{len(EXCLUSIONS)} excluded + {len(FEATURE_ON_ONLY)} shipped-posture-only "
            f"= {len(off_leaves) - len(EXCLUSIONS) + len(FEATURE_ON_ONLY)} "
            f"vs feature-on {len(on_leaves)} executed"
        )
        if undeclared_missing:
            failures.append(
                f"{len(undeclared_missing)} test(s) execute feature-OFF but NOT feature-ON and are "
                f"not enumerated in EXCLUSIONS (add an exact id and a reviewed reason, or fix the "
                f"harness seam):\n    " + "\n    ".join(undeclared_missing[:20])
            )
        if stale_exclusions:
            failures.append(
                "EXCLUSIONS names test(s) that DO execute feature-ON — the exclusion is stale and "
                "must be removed:\n    " + "\n    ".join(stale_exclusions)
            )
        if undeclared_extra:
            failures.append(
                "test(s) execute feature-ON but not feature-OFF and are not enumerated in "
                "FEATURE_ON_ONLY:\n    " + "\n    ".join(undeclared_extra[:20])
            )
        if stale_extra:
            failures.append(
                "FEATURE_ON_ONLY names test(s) that did not execute feature-ON:\n    "
                + "\n    ".join(stale_extra)
            )
        for name, reason in EXCLUSIONS.items():
            if not reason.strip():
                failures.append(f"exclusion {name} carries no reason")

        evidence["reconciliation"] = {
            "feature_off_leaves": len(off_leaves),
            "feature_on_leaves": len(on_leaves),
            "excluded": sorted(EXCLUSIONS),
            "shipped_posture_only": sorted(FEATURE_ON_ONLY),
            "undeclared_missing": undeclared_missing,
            "undeclared_extra": undeclared_extra,
        }

    # ---- clause 4: rustdoc examples hold under the SHIPPED posture ----
    # Green alone is not enough here. The cheap way to make a failing example
    # "pass" is to delete it, `ignore` it, or cfg-gate it away under the
    # feature — so the enforced invariant is that the feature-on and
    # feature-off doc runs execute the SAME NUMBER of examples and ignore the
    # same number. A vanished example changes the counts and fails the gate.
    doc_on_rc, doc_on_out = run_doc(FEATURES_ON)
    on_p, on_f, on_i = doc_counts(doc_on_out)
    print(f"feature-ON   doc examples: {on_p} passed, {on_f} failed, {on_i} ignored")
    if doc_on_rc != 0 or on_f != 0 or on_p == 0:
        failures.append(
            f"feature-ON doc examples are not green: {on_p} passed, {on_f} failed. "
            "The fork publishes rustdoc examples that the posture it ships would "
            "refuse."
        )
    evidence["doc_feature_on"] = {"passed": on_p, "failed": on_f, "ignored": on_i}
    if on_p < DOC_MIN_EXECUTED:
        failures.append(
            f"doc examples executed under the shipped posture dropped to {on_p}, "
            f"below the recorded floor of {DOC_MIN_EXECUTED}. An example was "
            "removed or marked ```ignore``` rather than fixed; lowering the floor "
            "requires a commit that says why."
        )
    if on_i > DOC_MAX_IGNORED:
        failures.append(
            f"doc examples ignored under the shipped posture rose to {on_i}, above "
            f"the recorded ceiling of {DOC_MAX_IGNORED}. Turning a failing example "
            "into a skipped one is not a fix."
        )

    if not args.quick:
        doc_off_rc, doc_off_out = run_doc(FEATURES_OFF)
        off_p, off_f, off_i = doc_counts(doc_off_out)
        print(f"feature-OFF  doc examples: {off_p} passed, {off_f} failed, {off_i} ignored")
        evidence["doc_feature_off"] = {"passed": off_p, "failed": off_f, "ignored": off_i}
        if doc_off_rc != 0 or off_f != 0 or off_p == 0:
            failures.append(
                f"feature-OFF doc examples are not green: {off_p} passed, {off_f} failed"
            )
        if (on_p, on_i) != (off_p, off_i):
            failures.append(
                f"doc example population differs between postures: feature-off "
                f"{off_p} passed/{off_i} ignored vs feature-on {on_p} passed/{on_i} "
                "ignored. One form of every example must run in BOTH postures; a "
                "differing count means an example was removed, ignored or "
                "cfg-gated away rather than fixed."
            )
        else:
            print(
                f"doc reconciliation       : identical population in both postures "
                f"({on_p} executed, {on_i} ignored)"
            )

    if EXCLUSIONS:
        print("exclusions (inapplicable under the shipped posture):")
        for name, reason in sorted(EXCLUSIONS.items()):
            print(f"  - {name}\n      {reason}")
    else:
        print(
            "exclusions               : none — every test executed feature-off also "
            "executes feature-on"
        )

    if args.evidence:
        pathlib.Path(args.evidence).write_text(json.dumps(evidence, indent=2) + "\n")
        print(f"evidence written to {args.evidence}")

    if failures:
        print("STRICT-EPOCH SUITE GATE: FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    if args.quick:
        print(
            "STRICT-EPOCH SUITE GATE: PARTIAL — the feature-ON full suite and the negative "
            "fence suite are green, but the feature-OFF upstream-regression oracle and the "
            "leaf reconciliation were NOT run. This is not a qualification result; only a "
            "full run (no --quick) prints PASS."
        )
        return 0
    print("STRICT-EPOCH SUITE GATE: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
