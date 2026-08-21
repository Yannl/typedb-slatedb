#!/usr/bin/env python3
"""A run's own output is not a fork patch.

`fork_files()` decides three things at once: which files staging carries, what
`staged_file_count`/`staged_tree_sha256` bind (generate_workspace_lock.py), and
what identifies the executed tree (leaf_common.py). Counting `typedb-logs/`
among them made `lint_source_lock.py` fail after every run that started a
server inside `fork/typedb` — which the quality controller now does on every
`rust.tests` — and reported the logs as four unstaged fork patches.

This is a REGRESSION test for exactly that: it fails if the exclusion is moved
back to the destination side alone.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import stage  # noqa: E402


def test_a_runs_own_logs_are_not_fork_files(tmp_path, monkeypatch):
    (tmp_path / "server").mkdir()
    (tmp_path / "server" / "lib.rs").write_text("fn main() {}\n")
    logs = tmp_path / "typedb-logs"
    logs.mkdir()
    for hour in ("17", "18"):
        (logs / f"typedb.log.2026-08-21-{hour}").write_text("Ready!\n")
    monkeypatch.setattr(stage, "FORK", tmp_path)

    assert [p.as_posix() for p in stage.fork_files()] == ["server/lib.rs"]


def test_the_exclusion_is_the_shared_definition(tmp_path, monkeypatch):
    """Not a hard-coded 'typedb-logs': whatever RUNTIME_OUTPUT_PREFIXES says.

    leaf_common.py imports that tuple from here, so a prefix added for one and
    not the other is the drift this indirection exists to prevent.
    """
    monkeypatch.setattr(stage, "RUNTIME_OUTPUT_PREFIXES", ("run-scratch/",))
    (tmp_path / "run-scratch").mkdir()
    (tmp_path / "run-scratch" / "x.tmp").write_text("")
    (tmp_path / "typedb-logs").mkdir()
    (tmp_path / "typedb-logs" / "kept.log").write_text("")
    monkeypatch.setattr(stage, "FORK", tmp_path)

    assert [p.as_posix() for p in stage.fork_files()] == ["typedb-logs/kept.log"]
