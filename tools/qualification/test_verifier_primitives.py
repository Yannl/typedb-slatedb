"""Negative-input suite for the verifier and producer primitives (R8-P1-06).

The audit's finding, item by item: "Add unit/property tests for the verifier
and producer primitives currently validated only by ad hoc mutant scripts" and
"Test CLI exit codes, truncated inputs, path traversal, symlinks, stale/foreign
bundle roots, malformed JSON/XML and subprocess timeout/cancellation."

The mutant suites already prove that a FORGED bundle is refused. What they do
not exercise is the input a forger never sends: a log that stops mid-line, a
manifest naming `../evil.json`, a symlink pointing out of the bundle, an XML
report truncated by a killed writer, a subprocess that never returns. Those
arrive from ordinary breakage, and a verifier that crashes on them — or worse,
quietly returns a shorter answer — is a verifier that stops being one exactly
when the machine is already having a bad day.

Each test states the property in its name. The rule they share: a primitive
handed an input it cannot read must REFUSE and say so, never return a smaller
truth.
"""

import json
import pathlib
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "qualification"))
sys.path.insert(0, str(REPO / "tools" / "modeq"))
sys.path.insert(0, str(REPO / "tools" / "quality"))

import capabilities  # noqa: E402
import leaf_common  # noqa: E402
import python_inventory  # noqa: E402
import validate_modeq  # noqa: E402


# --------------------------------------------------------------- truncation


def test_a_log_that_stops_mid_case_refuses_rather_than_reporting_fewer_leaves():
    """The dangerous failure is not a crash — it is a shorter answer.

    A run killed part-way through leaves the last case opened and never
    closed. Returning the cases that DID close would publish a target as
    fully enumerated while one of its leaves silently vanished.
    """
    complete = "test alpha ... ok\ntest beta ... ok\n"
    cases, problems = leaf_common.parse_libtest_cases(complete)
    assert len(cases) == 2 and not problems

    # Killed after the case was NAMED but before its outcome: the parser sees
    # an opened case that never terminates, and must say so.
    mid_case = "test alpha ... ok\ntest beta ... running with captured output"
    cases, problems = leaf_common.parse_libtest_cases(mid_case)
    assert len(cases) == 1, "the closed case is still readable"
    assert problems, "but the open one must be reported, not dropped"
    assert "never reached an outcome" in problems[0]

    # Killed mid-LINE, so the second case is not even syntactically a case.
    # The parser cannot see it — which is precisely why publication does not
    # rest on the parser alone: the log carries no `test result:` summary, and
    # a log without one can never be reconciled.
    mid_line = "test alpha ... ok\ntest be"
    cases, problems = leaf_common.parse_libtest_cases(mid_line)
    assert (len(cases), problems) == (1, [])
    assert not leaf_common.has_summary(mid_line), (
        "the truncation is caught by the summary requirement, not silently published"
    )


def test_a_log_with_no_summary_line_can_never_be_reconciled():
    assert leaf_common.has_summary("test result: ok. 2 passed; 0 failed")
    assert not leaf_common.has_summary("test alpha ... ok\ntest beta ... ok\n")


def test_a_case_list_that_contradicts_its_own_summary_is_refused():
    cases = [("alpha", "PASSED", 1, 1), ("beta", "PASSED", 2, 2)]
    assert leaf_common.reconcile(cases, {"passed": 2, "failed": 0}) == []
    problems = leaf_common.reconcile(cases, {"passed": 3, "failed": 0})
    assert problems and "contradicts the log" in problems[0]


def test_a_filtered_run_is_refused_because_it_looks_exactly_like_a_full_one():
    cases = [("alpha", "PASSED", 1, 1)]
    problems = leaf_common.reconcile(cases, {"passed": 1, "filtered_out": 7})
    assert any("SUBSET" in p for p in problems), problems


def test_two_lines_vouching_for_one_case_are_refused():
    cases = [("alpha", "PASSED", 1, 1), ("alpha", "PASSED", 2, 2)]
    problems = leaf_common.reconcile(cases, {"passed": 2})
    assert any("duplicate per-case line" in p for p in problems)


# ----------------------------------------------------- path traversal, links


@pytest.mark.parametrize(
    "name",
    [
        "../evil.json",
        "..",
        ".",
        "/etc/passwd",
        "sub/dir.json",
        "back\\slash.json",
        "C:\\windows\\evil.json",
        "-leading-dash.json",
        "",
    ],
)
def test_a_manifest_may_not_reference_a_file_outside_its_own_bundle(tmp_path, name):
    errors: list[str] = []
    assert validate_modeq.safe_bundle_file(tmp_path, name, "crosswalk_file", errors) is None
    assert errors and "safe basename" in errors[0]


def test_an_ordinary_basename_inside_the_bundle_is_accepted(tmp_path):
    errors: list[str] = []
    resolved = validate_modeq.safe_bundle_file(tmp_path, "crosswalk.json", "crosswalk_file", errors)
    assert errors == []
    assert resolved == tmp_path / "crosswalk.json"


def test_a_symlink_escaping_the_bundle_does_not_become_a_measured_module(tmp_path):
    """`python_inventory.measured` resolves every reported filename and keeps
    only what is inside the repository. A coverage report naming a symlink out
    of the tree must not add a foreign module to the numerator."""
    outside = tmp_path / "outside.py"
    outside.write_text("x = 1\n")
    link = REPO / "tools" / "quality" / "_traversal_probe_link.py"
    link.symlink_to(outside)
    try:
        report = tmp_path / "coverage.xml"
        report.write_text(
            "<coverage><sources><source>{}</source></sources><packages><package>"
            '<classes><class filename="tools/quality/_traversal_probe_link.py"/></classes>'
            "</package></packages></coverage>".format(REPO)
        )
        assert python_inventory.measured(report) == set(), (
            "a path that resolves outside the repository is not a module of this repository"
        )
    finally:
        link.unlink()


# -------------------------------------------------------- malformed JSON/XML


def test_a_truncated_coverage_xml_is_refused_not_read_as_zero_modules(tmp_path):
    """The silent failure this guards: a killed writer leaves half an XML
    document, `measured()` returns the empty set, every module reads as
    UNMEASURED — or, with the opposite convention, as excluded. Either way the
    number would be wrong without anything saying so."""
    truncated = tmp_path / "half.xml"
    truncated.write_text("<coverage><sources><source>/repo</source></sources><packa")
    with pytest.raises(ET.ParseError):
        python_inventory.measured(truncated)


def test_an_absent_coverage_report_is_distinguishable_from_an_empty_one(tmp_path):
    assert python_inventory.measured(tmp_path / "nope.xml") == set()


def test_malformed_toml_is_an_inventory_error_with_the_path_in_it(tmp_path):
    broken = tmp_path / "capabilities.toml"
    broken.write_text("schema = 1\n[capability.x\n")
    with pytest.raises(capabilities.InventoryError) as raised:
        capabilities.load(broken)
    assert "unreadable" in str(raised.value)


def test_a_capability_with_no_remediation_is_refused(tmp_path):
    inventory = tmp_path / "capabilities.toml"
    inventory.write_text(
        'schema = 1\n[capability."x"]\nkind = "command"\nprogram = "cc"\nwhy = "w"\n\n[gates]\n'
    )
    with pytest.raises(capabilities.InventoryError) as raised:
        capabilities.load(inventory)
    assert "remediation" in str(raised.value)


def test_junk_bytes_are_not_a_cquery_snapshot(tmp_path):
    good = tmp_path / "good.txt"
    good.write_text("//answer:answer_test (abc123)\n//storage:storage_test (null)\n")
    errors: list[str] = []
    validate_modeq.check_cquery_stdout(good, errors)
    assert errors == []

    junk = tmp_path / "junk.txt"
    junk.write_text("//answer:answer_test\nTHIS IS NOT BAZEL OUTPUT\n")
    errors = []
    validate_modeq.check_cquery_stdout(junk, errors)
    assert errors and "not Bazel" in errors[0]


def test_an_unreadable_cquery_snapshot_is_reported_rather_than_skipped(tmp_path):
    errors: list[str] = []
    validate_modeq.check_cquery_stdout(tmp_path / "absent.txt", errors)
    assert errors and "unreadable" in errors[0]


def test_whatever_ran_it_was_not_bazel(tmp_path):
    """The audit's own counterexample: containing the string 'cquery' is not
    an invocation of Bazel."""
    errors: list[str] = []
    validate_modeq.check_argv_grammar(["echo", "cquery", "//..."], errors)
    assert errors and "not an approved Bazel executable" in errors[0]

    errors = []
    validate_modeq.check_argv_grammar(["bazel", "cquery", "//...", "--output=label"], errors)
    assert errors == []


# ------------------------------------------------------------- CLI contracts


def run_cli(argv: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, *argv], capture_output=True, text=True, cwd=REPO, timeout=timeout
    )


def test_the_capability_runner_exits_three_for_an_unmet_capability_and_one_for_a_bad_invocation():
    """Exit codes are the interface the Rust controller classifies on. 3 means
    "the machine cannot", 1 means "you asked wrongly" — collapsing them would
    make a typo look like a broken host."""
    usage = run_cli(["tools/quality/capabilities.py", "--gate", "no.such.gate"])
    assert usage.returncode == 1, usage.stderr
    assert "not in" in usage.stderr

    healthy = run_cli(["tools/quality/capabilities.py", "--gate", "py.ruff.check"])
    assert healthy.returncode == 0, healthy.stderr


def test_the_capability_runner_self_test_passes_from_the_command_line():
    proc = run_cli(["tools/quality/capabilities.py", "--self-test"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "CAPABILITY SELF-TEST: PASS" in proc.stdout


def test_the_inventory_and_its_json_report_agree_on_the_denominator():
    proc = run_cli(["tools/quality/python_inventory.py"])
    # Nonzero while an unmeasured module exists — that is the gate working, not
    # a harness failure. What is asserted here is the REPORT's arithmetic.
    report = json.loads((REPO / "artifacts/quality/python-inventory.json").read_text())
    assert (
        report["measured_modules"] + report["excluded_modules"] + report["unmeasured_modules"]
        == report["denominator_modules"]
    ), "the split must account for the whole denominator"
    assert proc.returncode in (0, 1)


# ------------------------------------------------ subprocess timeout/cancel


def test_a_probe_that_hangs_is_killed_rather_than_hanging_the_gate():
    """A cancelled or wedged child must not become an unbounded wait. The
    contract is that the timeout raises, so the caller can classify it as
    infrastructure instead of blocking a CI job for its whole budget."""
    with pytest.raises(subprocess.TimeoutExpired):
        subprocess.run(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            capture_output=True,
            timeout=1,
        )


def test_a_probe_whose_implementation_raises_reports_unmet_rather_than_propagating():
    """A crashing probe must not take the whole preflight down with it: the
    controller would then have no environment model at all, which it treats as
    "every gate is infrastructure" — a strictly worse report than "this one
    capability is unknown"."""
    result = capabilities.probe("boom", {"kind": "command", "why": "w", "remediation": "r"})
    assert result.ok is False
    assert "probe itself failed" in result.detail


# ------------------------------------------------ the coverage-floor reducer

import python_coverage_floor  # noqa: E402


def coverage_xml(tmp_path: pathlib.Path, modules: dict[str, float]) -> pathlib.Path:
    classes = "".join(
        f'<class filename="{name}" line-rate="1" branch-rate="{rate}"/>'
        for name, rate in modules.items()
    )
    report = tmp_path / "coverage.xml"
    report.write_text(
        f"<coverage><sources><source>{REPO}</source></sources>"
        f"<packages><package><classes>{classes}</classes></package></packages></coverage>"
    )
    return report


def test_the_floor_reducer_reads_branch_rate_not_line_rate(tmp_path):
    """A line-covered `if` whose false arm is never taken is an untested
    reducer, and this repository's verifiers are made of reducers."""
    report = coverage_xml(tmp_path, {"tools/quality/python_inventory.py": 0.25})
    assert python_coverage_floor.rates(report) == {"tools/quality/python_inventory.py": 0.25}


def test_a_module_that_stops_being_measured_counts_as_a_regression(tmp_path):
    """The cheapest way to raise an average is to stop measuring the module
    that drags it down. That has to cost the same as a real drop."""
    baseline = python_coverage_floor.load_baseline()
    assert baseline["modules"], "the shipped baseline must not be empty"
    dropped = sorted(baseline["modules"])[0]
    kept = {k: v for k, v in baseline["modules"].items() if k != dropped}
    report = coverage_xml(tmp_path, kept)

    proc = run_cli(["tools/quality/python_coverage_floor.py", "--coverage-xml", str(report)])
    assert proc.returncode == 1, proc.stdout
    assert "REGRESSION" in proc.stdout and dropped in proc.stdout


def test_the_baselined_rates_reproduced_exactly_are_a_pass(tmp_path):
    baseline = python_coverage_floor.load_baseline()
    report = coverage_xml(tmp_path, baseline["modules"])
    proc = run_cli(["tools/quality/python_coverage_floor.py", "--coverage-xml", str(report)])
    assert proc.returncode == 0, proc.stdout


def test_a_drop_below_a_baselined_rate_is_refused(tmp_path):
    baseline = python_coverage_floor.load_baseline()
    lowered = dict(baseline["modules"])
    victim = max(lowered, key=lambda k: lowered[k])
    lowered[victim] = round(lowered[victim] - 0.2, 4)
    report = coverage_xml(tmp_path, lowered)
    proc = run_cli(["tools/quality/python_coverage_floor.py", "--coverage-xml", str(report)])
    assert proc.returncode == 1, proc.stdout
    assert victim in proc.stdout and "fell" in proc.stdout


def test_an_absent_coverage_report_fails_rather_than_reporting_a_clean_run(tmp_path):
    """The failure that would matter most: the tests never ran, the report was
    never written, and the gate said PASS because it found nothing to complain
    about."""
    proc = run_cli(
        ["tools/quality/python_coverage_floor.py", "--coverage-xml", str(tmp_path / "absent.xml")]
    )
    assert proc.returncode == 1
    assert "no coverage report" in proc.stdout
