"""Unit tests for the coverage-completeness reducers (R8-P1-06 item 4).

These two modules decide what a coverage number MEANS: one fixes the
denominator, the other decides whether a change may lower it. They were
introduced to answer the audit's finding that "63 % over four imported
modules" said almost nothing — so they had better be right, and right about
their edge cases rather than only about the happy path this repository
currently happens to be in.

Every test drives the real entry points in process, against synthetic reports,
and none of them reads the repository's live numbers: a test that asserted
today's percentages would fail the next time someone writes a test, which is
the opposite of what it should reward.
"""

import json
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "quality"))

import python_coverage_floor  # noqa: E402
import python_inventory  # noqa: E402


def measure_all(path: pathlib.Path, minus: str | None = None) -> pathlib.Path:
    """A report that instruments every in-scope module except `minus`.

    Without it these tests drown: 95 UNMEASURED findings scroll the one finding
    under test off the end of a deliberately truncated list.
    """
    return write_xml(path, {f: 1.0 for f in python_inventory.inventory() if f != minus})


def write_xml(
    path: pathlib.Path, modules: dict[str, float], source: str | None = None
) -> pathlib.Path:
    classes = "".join(
        f'<class filename="{name}" line-rate="1" branch-rate="{rate}"/>'
        for name, rate in modules.items()
    )
    path.write_text(
        f"<coverage><sources><source>{source or REPO}</source></sources>"
        f"<packages><package><classes>{classes}</classes></package></packages></coverage>"
    )
    return path


# ------------------------------------------------------------------ inventory


def test_the_python_projects_come_from_policy_not_from_a_hardcoded_list():
    projects = python_inventory.python_projects()
    assert projects, "the policy must declare at least one python project"
    assert all(isinstance(p, str) and not p.startswith("/") for p in projects)


def test_the_inventory_skips_vendored_and_generated_trees():
    files = python_inventory.inventory()
    assert files == sorted(files), "the inventory is sorted so two runs are comparable"
    assert not any("/.venv/" in f or "__pycache__" in f or "/node_modules/" in f for f in files)
    assert "tools/quality/python_inventory.py" in files


def test_a_coverage_filename_relative_to_its_declared_source_resolves(tmp_path):
    """coverage.py writes filenames relative to <sources>, so `quality/x.py`
    under source `<repo>/tools` is `tools/quality/x.py`. Getting this wrong
    makes every module look unmeasured."""
    report = write_xml(
        tmp_path / "c.xml",
        {"quality/python_inventory.py": 1.0},
        source=str(REPO / "tools"),
    )
    assert python_inventory.measured(report) == {"tools/quality/python_inventory.py"}


def test_a_coverage_filename_naming_nothing_real_is_ignored_rather_than_counted(tmp_path):
    report = write_xml(tmp_path / "c.xml", {"quality/ghost_module.py": 1.0})
    assert python_inventory.measured(report) == set()


def test_the_three_categories_are_disjoint_and_add_up(tmp_path, monkeypatch, capsys):
    """The defect this catches is the one the tool itself had: a module both
    instrumented and excluded was counted twice, so measured + excluded +
    unmeasured exceeded the denominator."""
    files = python_inventory.inventory()
    victim = "tools/quality/python_inventory.py"
    assert victim in files
    report = write_xml(tmp_path / "c.xml", {victim: 1.0})
    exclusions = tmp_path / "exclusions.toml"
    exclusions.write_text(
        "schema = 1\n\n[[exclusion]]\n"
        f'path = "{victim}"\nreason = "r"\nowner = "o"\nreview_after = "2026-11-20"\n'
    )
    monkeypatch.setattr(python_inventory, "EXCLUSIONS", exclusions)
    out = tmp_path / "inventory.json"
    monkeypatch.setattr(
        sys, "argv", ["python_inventory.py", "--coverage-xml", str(report), "--json", str(out)]
    )
    rc = python_inventory.main()
    capsys.readouterr()
    body = json.loads(out.read_text())
    assert (
        body["measured_modules"] + body["excluded_modules"] + body["unmeasured_modules"]
        == body["denominator_modules"]
    )
    assert body["redundant_exclusions"] == 1, "measured wins, and the stale entry is reported"
    assert rc == 1, "an exclusion that is no longer true is a finding"


def test_an_exclusion_naming_a_file_that_no_longer_exists_is_refused(tmp_path, monkeypatch, capsys):
    exclusions = tmp_path / "exclusions.toml"
    exclusions.write_text(
        'schema = 1\n\n[[exclusion]]\npath = "tools/gone/deleted.py"\nreason = "r"\n'
        'owner = "o"\nreview_after = "2026-11-20"\n'
    )
    monkeypatch.setattr(python_inventory, "EXCLUSIONS", exclusions)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python_inventory.py",
            "--coverage-xml",
            str(measure_all(tmp_path / "c.xml")),
            "--json",
            str(tmp_path / "out.json"),
        ],
    )
    assert python_inventory.main() == 1
    err = capsys.readouterr().err
    assert "STALE" in err and "tools/gone/deleted.py" in err


def test_an_exclusion_that_still_carries_its_seeded_todo_is_refused(tmp_path, monkeypatch, capsys):
    exclusions = tmp_path / "exclusions.toml"
    exclusions.write_text(
        'schema = 1\n\n[[exclusion]]\npath = "tools/quality/python_inventory.py"\n'
        'reason = "TODO: state why this module is not instrumented by the pytest run."\n'
        'owner = "o"\nreview_after = "2026-11-20"\n'
    )
    monkeypatch.setattr(python_inventory, "EXCLUSIONS", exclusions)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python_inventory.py",
            "--coverage-xml",
            str(measure_all(tmp_path / "c.xml", minus="tools/quality/python_inventory.py")),
            "--json",
            str(tmp_path / "out.json"),
        ],
    )
    assert python_inventory.main() == 1
    assert "seeded TODO" in capsys.readouterr().err


def test_an_exclusion_missing_its_owner_is_refused(tmp_path, monkeypatch, capsys):
    exclusions = tmp_path / "exclusions.toml"
    exclusions.write_text(
        'schema = 1\n\n[[exclusion]]\npath = "tools/quality/python_inventory.py"\n'
        'reason = "a real reason"\nreview_after = "2026-11-20"\n'
    )
    monkeypatch.setattr(python_inventory, "EXCLUSIONS", exclusions)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python_inventory.py",
            "--coverage-xml",
            str(measure_all(tmp_path / "c.xml", minus="tools/quality/python_inventory.py")),
            "--json",
            str(tmp_path / "out.json"),
        ],
    )
    assert python_inventory.main() == 1
    assert "has no owner" in capsys.readouterr().err


# -------------------------------------------------------------- coverage floor


def test_the_floor_tool_refuses_a_run_with_no_report_rather_than_passing(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(
        sys, "argv", ["python_coverage_floor.py", "--coverage-xml", str(tmp_path / "absent.xml")]
    )
    assert python_coverage_floor.main() == 1
    assert "no coverage report" in capsys.readouterr().out


def test_a_changed_module_below_the_floor_is_refused(tmp_path, monkeypatch, capsys):
    module = "tools/quality/python_coverage_floor.py"
    report = write_xml(tmp_path / "c.xml", {module: 0.10})
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"floor_changed": 0.55, "modules": {}}))
    monkeypatch.setattr(python_coverage_floor, "BASELINE", baseline)
    monkeypatch.setattr(python_coverage_floor, "changed_python", lambda base: [module])
    monkeypatch.setattr(
        sys,
        "argv",
        ["python_coverage_floor.py", "--coverage-xml", str(report), "--base", "HEAD~1"],
    )
    assert python_coverage_floor.main() == 1
    out = capsys.readouterr().out
    assert "FLOOR" in out and module in out


def test_a_changed_module_at_the_floor_passes(tmp_path, monkeypatch, capsys):
    module = "tools/quality/python_coverage_floor.py"
    report = write_xml(tmp_path / "c.xml", {module: 0.55})
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"floor_changed": 0.55, "modules": {}}))
    monkeypatch.setattr(python_coverage_floor, "BASELINE", baseline)
    monkeypatch.setattr(python_coverage_floor, "changed_python", lambda base: [module])
    monkeypatch.setattr(
        sys,
        "argv",
        ["python_coverage_floor.py", "--coverage-xml", str(report), "--base", "HEAD~1"],
    )
    assert python_coverage_floor.main() == 0
    assert "PASS" in capsys.readouterr().out


def test_a_changed_module_that_is_a_reviewed_exclusion_is_not_held_to_the_floor(
    tmp_path, monkeypatch, capsys
):
    """The exclusion list is the reviewed answer to "this module is not
    measured". Holding an unmeasured module to a coverage floor would be
    asking for a number nobody records."""
    module = sorted(python_inventory.exclusions())[0]
    report = write_xml(tmp_path / "c.xml", {"tools/quality/python_coverage_floor.py": 1.0})
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"floor_changed": 0.99, "modules": {}}))
    monkeypatch.setattr(python_coverage_floor, "BASELINE", baseline)
    monkeypatch.setattr(python_coverage_floor, "changed_python", lambda base: [module])
    monkeypatch.setattr(
        sys,
        "argv",
        ["python_coverage_floor.py", "--coverage-xml", str(report), "--base", "HEAD~1"],
    )
    assert python_coverage_floor.main() == 0


def test_a_changed_module_that_is_not_measured_at_all_is_not_silently_passed(tmp_path):
    """It is the INVENTORY's job to refuse an unmeasured module, and it does.
    The floor tool must not also invent a rate for it — two tools guessing
    differently about the same module is how a number stops meaning anything."""
    assert python_coverage_floor.rates(write_xml(tmp_path / "c.xml", {})) == {}


def test_writing_the_baseline_records_the_commit_it_was_true_at(tmp_path, monkeypatch, capsys):
    report = write_xml(tmp_path / "c.xml", {"tools/quality/python_inventory.py": 0.4242})
    baseline = tmp_path / "baseline.json"
    monkeypatch.setattr(python_coverage_floor, "BASELINE", baseline)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python_coverage_floor.py",
            "--coverage-xml",
            str(report),
            "--write-baseline",
            "--floor",
            "0.6",
        ],
    )
    assert python_coverage_floor.main() == 0
    capsys.readouterr()
    body = json.loads(baseline.read_text())
    assert body["floor_changed"] == 0.6
    assert body["modules"] == {"tools/quality/python_inventory.py": 0.4242}
    assert len(body["as_of_commit"]) == 40, "a baseline that does not say WHEN is not a baseline"


def test_the_epsilon_absorbs_re_derivation_noise_but_not_a_real_drop(tmp_path, monkeypatch, capsys):
    module = "tools/quality/python_inventory.py"
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"floor_changed": 0.0, "modules": {module: 0.5}}))
    monkeypatch.setattr(python_coverage_floor, "BASELINE", baseline)

    for rate, expected in ((0.4990, 0), (0.4000, 1)):
        report = write_xml(tmp_path / f"c{rate}.xml", {module: rate})
        monkeypatch.setattr(
            sys, "argv", ["python_coverage_floor.py", "--coverage-xml", str(report)]
        )
        assert python_coverage_floor.main() == expected, f"rate {rate}"
        capsys.readouterr()


def test_changed_python_asks_git_and_keeps_only_python(monkeypatch):
    monkeypatch.setattr(
        python_coverage_floor.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(
            a[0], 0, stdout="tools/a.py\ndocs/b.md\ntools/c.py\n", stderr=""
        ),
    )
    assert python_coverage_floor.changed_python("HEAD~1") == ["tools/a.py", "tools/c.py"]


def test_a_failing_git_diff_stops_the_gate_rather_than_reporting_no_changed_files(monkeypatch):
    """Treating a git failure as "nothing changed" would silently disable the
    floor on exactly the runs where the repository state is odd."""
    monkeypatch.setattr(
        python_coverage_floor.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 128, stdout="", stderr="bad revision"),
    )
    with pytest.raises(SystemExit):
        python_coverage_floor.changed_python("nope")
