"""Unit tests for the Mode-Q bundle validator (R8-P1-06 item 4).

`modeq_mutants.py` proves that eleven specific forgeries are refused, and it
does that well. What it does not do is exercise the validator as a FUNCTION:
every control runs the CLI over a mutated copy, so a branch that no forgery
happens to visit — a missing manifest, junk JSON, a bundle directory that is
not there, the crosswalk bijection arithmetic — has never been executed by a
test at all. This is the gate deciding whether G0 may close; "eleven forgeries
bounce off it" is not the same as "it works".

The real sealed bundle is the positive subject: a validator whose happy path is
only ever exercised by mutating something is a validator nobody has watched
accept a true bundle.
"""

import json
import pathlib
import shutil
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "modeq"))

import validate_modeq  # noqa: E402

BUNDLE = REPO / "docs" / "evidence" / "G0" / "mode-q"


@pytest.fixture
def copy_of_the_real_bundle(tmp_path):
    """A writable copy, so a test may break one thing and leave the rest true.

    Mutating a field in a bundle that is otherwise VALID is the only way to
    know which error a branch reports: a synthetic bundle fails for so many
    reasons at once that no individual assertion means anything.
    """
    target = tmp_path / "mode-q"
    shutil.copytree(BUNDLE, target)
    return target


def manifest_of(bundle: pathlib.Path) -> dict:
    return json.loads((bundle / "modeq.json").read_text())


def rewrite(bundle: pathlib.Path, doc: dict) -> None:
    (bundle / "modeq.json").write_text(json.dumps(doc, indent=1))


# ------------------------------------------------------------- the true case


def test_the_sealed_bundle_this_repository_ships_validates():
    assert BUNDLE.is_dir(), "the Mode-Q bundle the ledger binds must exist"
    assert validate_modeq.validate_bundle(BUNDLE) == []


def test_an_untouched_copy_of_it_also_validates(copy_of_the_real_bundle):
    """The negative control for every test below: if a plain copy were
    refused, each mutation would 'fail' for a reason that was already there."""
    assert validate_modeq.validate_bundle(copy_of_the_real_bundle) == []


# ------------------------------------------------------- structural refusals


def test_a_bundle_with_no_manifest_is_junk_and_says_so(tmp_path):
    errors = validate_modeq.validate_bundle(tmp_path)
    assert len(errors) == 1 and "missing" in errors[0]


def test_a_manifest_that_is_not_json_is_refused_rather_than_crashing(tmp_path):
    (tmp_path / "modeq.json").write_text("{ not json")
    errors = validate_modeq.validate_bundle(tmp_path)
    assert len(errors) == 1 and "not valid JSON" in errors[0]


def test_a_manifest_that_is_not_an_object_is_refused(tmp_path):
    (tmp_path / "modeq.json").write_text("[1, 2, 3]")
    assert validate_modeq.validate_bundle(tmp_path) == ["modeq.json is not a JSON object"]


def test_a_truncated_manifest_is_refused(tmp_path):
    """The realistic breakage, not a forgery: a writer killed mid-flush."""
    whole = (BUNDLE / "modeq.json").read_text()
    (tmp_path / "modeq.json").write_text(whole[: len(whole) // 2])
    errors = validate_modeq.validate_bundle(tmp_path)
    assert errors and "not valid JSON" in errors[0]


def test_the_wrong_schema_version_is_refused(copy_of_the_real_bundle):
    doc = manifest_of(copy_of_the_real_bundle)
    doc["schema"] = "modeq-bundle/v2"
    rewrite(copy_of_the_real_bundle, doc)
    errors = validate_modeq.validate_bundle(copy_of_the_real_bundle)
    assert any("schema must be" in e for e in errors)


# ------------------------------------------------------- identity refusals


def test_a_bazel_digest_that_is_not_a_sha256_is_refused(copy_of_the_real_bundle):
    doc = manifest_of(copy_of_the_real_bundle)
    doc["bazel"]["binary_sha256"] = "not-a-digest"
    rewrite(copy_of_the_real_bundle, doc)
    assert any("binary_sha256" in e for e in validate_modeq.validate_bundle(copy_of_the_real_bundle))


def test_a_missing_bazel_object_is_refused(copy_of_the_real_bundle):
    doc = manifest_of(copy_of_the_real_bundle)
    del doc["bazel"]
    rewrite(copy_of_the_real_bundle, doc)
    assert any("missing 'bazel' object" in e for e in validate_modeq.validate_bundle(copy_of_the_real_bundle))


def test_an_empty_bazel_version_is_refused(copy_of_the_real_bundle):
    doc = manifest_of(copy_of_the_real_bundle)
    doc["bazel"]["version"] = "   "
    rewrite(copy_of_the_real_bundle, doc)
    assert any("bazel.version missing" in e for e in validate_modeq.validate_bundle(copy_of_the_real_bundle))


# ----------------------------------------------------------- the CLI surface


def test_the_cli_reports_valid_for_the_sealed_bundle(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["validate_modeq.py", "--dir", str(BUNDLE)])
    code = validate_modeq.main()
    out = capsys.readouterr().out
    assert "MODEQ: VALID" in out, out
    assert code == 0


def test_the_cli_reports_absent_for_a_directory_that_does_not_exist(capsys, monkeypatch, tmp_path):
    """ABSENT is not INVALID, and the difference is load-bearing: an absent
    bundle leaves the gate honestly unclosed, while an invalid one says
    somebody produced something that does not hold together."""
    monkeypatch.setattr(sys, "argv", ["validate_modeq.py", "--dir", str(tmp_path / "nope")])
    validate_modeq.main()
    assert "MODEQ: ABSENT" in capsys.readouterr().out


def test_the_cli_reports_invalid_for_a_broken_bundle(capsys, monkeypatch, copy_of_the_real_bundle):
    (copy_of_the_real_bundle / "modeq.json").write_text("{ not json")
    monkeypatch.setattr(sys, "argv", ["validate_modeq.py", "--dir", str(copy_of_the_real_bundle)])
    code = validate_modeq.main()
    out = capsys.readouterr().out
    assert "MODEQ: INVALID" in out
    assert code != 0
