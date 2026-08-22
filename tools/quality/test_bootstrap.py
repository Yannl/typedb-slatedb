#!/usr/bin/env python3
"""Executed controls for the quality bootstrap (R8-P0-04).

The claim is not "there is an installer". It is: **a runner that starts with
nothing undeclared can reach actual gate execution, and one that cannot is told
so as INFRASTRUCTURE with the exact remediation.** Every test below runs the
real script as a subprocess and asserts against what it did.

The clean-runner control is the one that matters. It copies the repository's
lock into a shadow tree with an EMPTY Python environment and requires the
bootstrap to report every Python tool as missing, exit 3, and name the
remediation — which is the state a fresh `ubuntu-24.04` is in, and the state the
audited workflows silently ran gates in.
"""

import json
import pathlib
import shutil
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
BOOTSTRAP = REPO / "tools" / "quality" / "bootstrap.py"
LOCK = REPO / ".quality" / "tools.lock.toml"
PY_LOCK = REPO / ".quality" / "requirements.lock"
PY_IN = REPO / ".quality" / "requirements.in"


def run(*args, cwd=None, env=None):
    return subprocess.run(
        [sys.executable, str(BOOTSTRAP), *args],
        capture_output=True,
        text=True,
        cwd=cwd or REPO,
        env=env,
    )


@pytest.fixture()
def shadow(tmp_path):
    """A repository-shaped tree carrying only what the bootstrap reads."""
    root = tmp_path / "repo"
    (root / ".quality").mkdir(parents=True)
    (root / "tools" / "quality").mkdir(parents=True)
    shutil.copy(LOCK, root / ".quality" / "tools.lock.toml")
    shutil.copy(PY_LOCK, root / ".quality" / "requirements.lock")
    shutil.copy(PY_IN, root / ".quality" / "requirements.in")
    shutil.copy(BOOTSTRAP, root / "tools" / "quality" / "bootstrap.py")
    return root


def run_in(root, *args):
    return subprocess.run(
        [sys.executable, str(root / "tools" / "quality" / "bootstrap.py"), *args],
        capture_output=True,
        text=True,
        cwd=root,
    )


# The conditions under which an install control could not RUN, as pip reports
# them: the index was unreachable, or the machine ran out of disk mid-install.
# These are the ONLY reasons such a control may decline to conclude, and it
# declines out loud — a skip, never a pass, because a control that did not
# execute proves nothing. Anything else nonzero is a real finding about the
# bootstrap. (Both were observed on this machine: the fork's build tree is 20 GB
# and an ENOSPC install failure reads exactly like a broken bootstrap.)
COULD_NOT_RUN = (
    "Temporary failure in name resolution",
    "Failed to establish a new connection",
    "Connection reset by peer",
    "Read timed out",
    "ProxyError",
    "SSLError",
    "503 Server Error",
    "502 Server Error",
    "No matching distribution found",
    "No space left on device",
    "Errno 28",
    "Disk quota exceeded",
)


def skip_if_the_control_could_not_run(proc) -> None:
    combined = proc.stdout + proc.stderr
    hit = next((marker for marker in COULD_NOT_RUN if marker in combined), None)
    if hit is not None:
        pytest.skip(
            f"this control could not execute: {hit!r}. That is INFRASTRUCTURE — an unreachable "
            f"package index or a full disk — not a verdict about the bootstrap, and it is reported "
            f"as a skip rather than a pass because a control that did not run proves nothing."
        )


def test_the_plan_names_a_command_for_every_tool_in_the_lock():
    import tomllib

    lock = tomllib.loads(LOCK.read_text())
    proc = run("--plan")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for name in lock["tool"]:
        assert f"tool.{name}" in proc.stdout, f"the plan does not mention tool.{name}"
    # and nothing is silently absent: a tool with no recipe must SAY so
    for line in proc.stdout.splitlines():
        if line.strip().startswith("tool."):
            assert line.split(maxsplit=1)[1].strip(), f"a tool line with no action: {line!r}"


def test_a_clean_runner_with_no_python_environment_refuses_as_infrastructure(shadow):
    # The state a fresh ubuntu-24.04 is in, and the state the audited workflows
    # ran gates in without noticing.
    proc = run_in(shadow, "--check", "--only", "tool.pip-audit", "--only", "tool.ruff")
    assert proc.returncode == 3, (
        "a runner missing required tools must report INFRASTRUCTURE (exit 3), got "
        f"{proc.returncode}:\n{proc.stdout + proc.stderr}"
    )
    combined = proc.stdout + proc.stderr
    assert "REFUSED" in combined
    assert "remediation" in combined, "a refusal must carry the lock's remediation, not just a name"


def test_a_clean_runner_installs_from_the_hash_locked_closure_and_then_verifies(shadow):
    proc = run_in(shadow, "--install", "--only", "tool.ruff", "--only", "tool.pip-audit")
    skip_if_the_control_could_not_run(proc)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    venv = shadow / ".quality" / ".venv"
    assert venv.is_dir(), "the bootstrap must create the repository-owned Python environment"
    manifest = json.loads(
        (shadow / "artifacts" / "quality" / "bootstrap-manifest.json").read_text()
    )
    by_id = {row["id"]: row for row in manifest["tools"]}
    assert by_id["tool.ruff"]["status"] == "ok"
    assert by_id["tool.ruff"]["detected"] == by_id["tool.ruff"]["pinned"], (
        "the detected version is re-read, not assumed"
    )
    assert by_id["tool.pip-audit"]["status"] == "ok"


def test_the_manifest_root_changes_when_the_tool_set_does(shadow):
    skip_if_the_control_could_not_run(run_in(shadow, "--install", "--only", "tool.ruff"))
    first = json.loads((shadow / "artifacts" / "quality" / "bootstrap-manifest.json").read_text())
    run_in(shadow, "--check", "--only", "tool.ruff", "--only", "tool.pip-audit")
    second = json.loads((shadow / "artifacts" / "quality" / "bootstrap-manifest.json").read_text())
    assert first["bootstrap_root"] != second["bootstrap_root"], (
        "the root must bind the exact tool set; if it did not, a report could name a root that "
        "says nothing about which tools reached the gates"
    )


def test_a_substituted_python_artefact_is_refused_by_the_hash_lock(shadow):
    # `--require-hashes` is the whole point of the lock: pin the version and a
    # substituted artefact still installs; pin the DIGEST and it cannot.
    lock = shadow / ".quality" / "requirements.lock"
    text = lock.read_text()
    at = text.index("--hash=sha256:")
    forged = text[: at + len("--hash=sha256:")] + "0" * 64 + text[at + len("--hash=sha256:") + 64 :]
    lock.write_text(forged)
    proc = run_in(shadow, "--install", "--only", "tool.ruff")
    combined = proc.stdout + proc.stderr
    assert proc.returncode == 3, f"a forged digest must not reach a green bootstrap:\n{combined}"


def test_the_lock_is_the_only_source_of_tools():
    # There is no way to ask the bootstrap to install something the lock does
    # not declare: adding a tool is a protected-policy change, not an argument.
    proc = run("--check", "--only", "tool.not-in-the-lock")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "tool.not-in-the-lock" not in proc.stdout


def test_every_lock_entry_carries_a_remediation():
    import tomllib

    lock = tomllib.loads(LOCK.read_text())
    for kind in ("toolchain", "tool"):
        for name, cfg in (lock.get(kind) or {}).items():
            assert cfg.get("remediation"), (
                f"{kind}.{name} has no remediation; a refusal that cannot say what to do next sends "
                f"the next reader hunting"
            )
