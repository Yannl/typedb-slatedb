"""Unit tests for the environment model's probe primitives (R8-P1-06 item 4).

`capability_mutants.py` proves that a DENIED environment is reported as denied.
What it cannot reach, because it runs the whole runner in a subprocess, is the
per-probe behaviour: what each probe returns for a subject that is present, for
one that is absent, and for one that is present but unusable. Those three
answers are the whole contract, and until now they were only ever observed
through an aggregate exit code.

These run IN PROCESS and never touch the machine's real configuration.
"""

import json
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "quality"))

import capabilities  # noqa: E402


# ------------------------------------------------------------- probe by kind


def test_a_command_probe_answers_with_the_resolved_path_or_says_it_is_absent():
    ok, detail = capabilities.probe_command({"program": "sh"})
    assert ok and detail.endswith("sh")

    ok, detail = capabilities.probe_command({"program": "definitely-not-a-real-program"})
    assert not ok and "not on PATH" in detail


def test_a_header_probe_compiles_rather_than_looking_for_a_file():
    ok, detail = capabilities.probe_c_header({"header": "stdlib.h", "language": "c"})
    assert ok and "compiles" in detail

    ok, detail = capabilities.probe_c_header({"header": "no_such_header_xyz.h", "language": "c"})
    assert not ok and "cannot compile" in detail


def test_a_header_probe_with_no_compiler_says_so_instead_of_claiming_the_header_is_missing(
    monkeypatch,
):
    """The two are different facts and lead to different fixes: install the
    compiler, or install the headers."""
    monkeypatch.setenv("CC", "definitely-not-a-compiler")
    ok, detail = capabilities.probe_c_header({"header": "stdlib.h", "language": "c"})
    assert not ok and "no c compiler" in detail


def test_a_library_probe_loads_rather_than_stats():
    ok, detail = capabilities.probe_shared_library({"candidates": ["libc.so.6"]})
    assert ok and "loads" in detail

    ok, detail = capabilities.probe_shared_library({"candidates": ["libnothing.so.999"]})
    assert not ok and "none of" in detail and "could be loaded" in detail


def test_a_library_probe_honours_its_declared_env_hint(monkeypatch, tmp_path):
    """A hint pointing somewhere empty must not make an otherwise loadable
    library report missing — the hint is a place to look FIRST, not instead."""
    monkeypatch.setenv("LIBCLANG_PATH", str(tmp_path))
    ok, _ = capabilities.probe_shared_library(
        {"candidates": ["libc.so.6"], "env_hint": "LIBCLANG_PATH"}
    )
    assert ok


def test_a_cargo_subcommand_probe_distinguishes_absent_cargo_from_absent_subcommand(monkeypatch):
    ok, detail = capabilities.probe_cargo_subcommand(
        {"subcommand": "definitely-no-such-subcommand"}
    )
    assert not ok

    monkeypatch.setenv("PATH", "")
    ok, detail = capabilities.probe_cargo_subcommand({"subcommand": "nextest"})
    assert not ok and "cargo is not on PATH" in detail


def test_an_npm_probe_reads_the_projects_own_tree_not_a_global_install(tmp_path):
    ok, detail = capabilities.probe_npm_bin({"bin": "oxlint", "project": "control-plane"})
    assert ok and detail.startswith("control-plane/node_modules/.bin")

    ok, detail = capabilities.probe_npm_bin({"bin": "no-such-tool", "project": "control-plane"})
    assert not ok and "not executable" in detail


def test_a_python_module_probe_reports_the_interpreter_it_asked():
    ok, detail = capabilities.probe_python_module({"module": "json"})
    assert ok and "system interpreter" in detail

    ok, detail = capabilities.probe_python_module({"module": "no_such_module_xyz"})
    assert not ok and "not importable" in detail


def test_a_venv_module_probe_says_the_venv_is_absent_rather_than_the_module(monkeypatch, tmp_path):
    monkeypatch.setattr(capabilities, "VENV_PYTHON", tmp_path / "nope" / "bin" / "python3")
    ok, detail = capabilities.probe_python_module({"module": "pytest", "venv": True})
    assert not ok and "venv is absent" in detail


def test_the_kernel_probes_answer_on_this_machine():
    ok, detail = capabilities.probe_network_namespace({})
    assert isinstance(ok, bool) and "CLONE_NEWNET" in detail

    ok, detail = capabilities.probe_af_unix({})
    assert ok and "works under" in detail

    ok, detail = capabilities.probe_proc_supervision({})
    assert ok and "status readable" in detail


def test_the_af_unix_probe_reports_the_directory_it_could_not_use(monkeypatch, tmp_path):
    monkeypatch.setenv("TMPDIR", str(tmp_path / "does-not-exist"))
    ok, detail = capabilities.probe_af_unix({})
    assert not ok and "no socket directory can be created" in detail


def test_a_path_probe_answers_relative_to_the_repository():
    ok, _ = capabilities.probe_path({"path": ".quality/capabilities.toml"})
    assert ok
    ok, detail = capabilities.probe_path({"path": "no/such/thing"})
    assert not ok and "is absent" in detail


# -------------------------------------------------------- inventory and gates


def test_the_shipped_inventory_declares_a_why_and_a_remediation_for_every_capability():
    inventory = capabilities.load()
    for cid, spec in inventory["capability"].items():
        assert spec.get("why"), cid
        assert spec.get("remediation"), cid
        assert spec["kind"] in capabilities.PROBES, cid


def test_required_for_deduplicates_across_gates_and_preserves_order():
    inventory = capabilities.load()
    both = capabilities.required_for(inventory, ["rust.clippy", "rust.tests"])
    assert len(both) == len(set(both)), "a capability required twice is probed once"
    assert set(capabilities.required_for(inventory, ["rust.clippy"])) <= set(both)


def test_an_unknown_gate_is_refused_rather_than_treated_as_needing_nothing():
    with pytest.raises(capabilities.InventoryError) as raised:
        capabilities.required_for(capabilities.load(), ["no.such.gate"])
    assert "not in" in str(raised.value)


def test_an_inventory_whose_gate_needs_an_undeclared_capability_is_refused(tmp_path):
    broken = tmp_path / "capabilities.toml"
    broken.write_text(
        'schema = 1\n[capability."x"]\nkind = "path"\npath = "."\nwhy = "w"\n'
        'remediation = "r"\n\n[gates]\n"a.b" = ["ghost"]\n'
    )
    with pytest.raises(capabilities.InventoryError) as raised:
        capabilities.load(broken)
    assert "undeclared capabilities" in str(raised.value)


def test_an_inventory_with_no_capabilities_at_all_is_refused(tmp_path):
    empty = tmp_path / "capabilities.toml"
    empty.write_text("schema = 1\n[gates]\n")
    with pytest.raises(capabilities.InventoryError):
        capabilities.load(empty)


# ---------------------------------------------------------------- entry point


def test_the_runner_exits_zero_and_emits_a_gate_map_when_everything_is_met(capsys):
    code = capabilities.main(["--gates", "py.ruff.check,rust.deny", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["unmet"] == []
    assert set(payload["requires"]) == {"py.ruff.check", "rust.deny"}
    assert [p["id"] for p in payload["probed"]] == ["cargo.deny"]


def test_the_runner_prints_the_why_and_the_fix_for_an_unmet_capability(
    capsys, monkeypatch, tmp_path
):
    inventory = tmp_path / "capabilities.toml"
    inventory.write_text(
        'schema = 1\n[capability."fixture.missing"]\nkind = "path"\npath = "no/such/thing"\n'
        'why = "the lanes read it"\nremediation = "materialise it"\n\n'
        '[gates]\n"a.b" = ["fixture.missing"]\n'
    )
    monkeypatch.setattr(capabilities, "INVENTORY", inventory)
    code = capabilities.main(["--gate", "a.b"])
    out = capsys.readouterr()
    assert code == capabilities.EXIT_CAPABILITY_UNAVAILABLE
    assert "the lanes read it" in out.out and "materialise it" in out.out
    assert "UNMET" in out.err


def test_the_audit_view_lists_gates_that_declare_nothing(capsys):
    assert capabilities.main(["--audit"]) == 0
    out = capsys.readouterr().out
    assert "declare no external capability" in out


def test_a_broken_inventory_is_a_usage_failure_not_a_missing_capability(
    capsys, monkeypatch, tmp_path
):
    """Exit 1, not 3: "you asked wrongly" and "the machine cannot" lead to
    different fixes, and the controller classifies on exactly this."""
    broken = tmp_path / "capabilities.toml"
    broken.write_text("this is not toml [[[")
    monkeypatch.setattr(capabilities, "INVENTORY", broken)
    assert capabilities.main(["--all"]) == 1
    assert "CAPABILITIES: FAIL" in capsys.readouterr().err


def test_the_self_test_runs_from_the_entry_point(capsys):
    assert capabilities.main(["--self-test"]) == 0
    assert "CAPABILITY SELF-TEST: PASS" in capsys.readouterr().out
