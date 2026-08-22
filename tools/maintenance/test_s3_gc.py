#!/usr/bin/env python3
"""Executed controls for the report-only GC tool (R8-P2-05).

The claim is not "the code no longer writes --user". It is: **a same-host
observer reading this process tree cannot see the bucket credential.** Only an
executed test can establish that, because it is a property of the argv the
child is actually spawned with — so these tests put a fake `curl` on PATH that
records its OWN `/proc/self/cmdline` and its config, and then assert against
what it recorded.

The second control is the mirror image and matters just as much: the credential
must still REACH curl. A "fix" that hides the secret by not sending it turns a
leak into a silent authentication failure.
"""

import os
import pathlib
import subprocess
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import s3_gc  # noqa: E402

SECRET = 's3cr3t-value-with-"quote"-and-\\backslash'
KEY_ID = "AKIA-test-key"

FAKE_CURL = r"""#!/usr/bin/env python3
import os, pathlib, sys
out = pathlib.Path(os.environ["FAKE_CURL_RECORD"])
argv = pathlib.Path(f"/proc/{os.getpid()}/cmdline").read_bytes().decode().split("\0")
config = ""
for i, a in enumerate(sys.argv):
    if a == "--config":
        config = pathlib.Path(sys.argv[i + 1]).read_text()
out.write_text(repr({"argv": argv, "config": config}))
sys.stdout.write("<ListBucketResult></ListBucketResult>")
"""


@pytest.fixture()
def fake_curl(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    curl = bin_dir / "curl"
    curl.write_text(FAKE_CURL)
    curl.chmod(0o755)
    record = tmp_path / "record.txt"
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_CURL_RECORD", str(record))
    return record


def observed(record):
    return eval(record.read_text())  # noqa: S307 — our own fixture's output


def test_the_bucket_secret_never_appears_in_the_child_process_argv(fake_curl):
    s3_gc.s3_request("https://example.invalid", "bucket", "auto", KEY_ID, SECRET, "GET")
    seen = observed(fake_curl)
    joined = " ".join(seen["argv"])
    assert SECRET not in joined, (
        "the bucket secret is readable in /proc/<pid>/cmdline for the life of the request:\n"
        f"{joined}"
    )
    assert "--user" not in seen["argv"], "the credential flag must not be in argv at all"
    assert any(a.startswith("/dev/fd/") for a in seen["argv"]), (
        f"the credential must travel on a private fd, argv was {seen['argv']}"
    )


def test_the_credential_still_reaches_curl_unmangled(fake_curl):
    # The mirror control: hiding a secret by not sending it is not a fix.
    s3_gc.s3_request("https://example.invalid", "bucket", "auto", KEY_ID, SECRET, "GET")
    seen = observed(fake_curl)
    assert seen["config"].startswith("user = "), (
        f"no user directive reached curl: {seen['config']!r}"
    )
    # curl's config quoting: a value's own quotes and backslashes are escaped,
    # so assert the ESCAPED form is what was written and that it round-trips.
    body = seen["config"].strip()[len('user = "') : -1]
    unescaped = body.replace('\\"', '"').replace("\\\\", "\\")
    assert unescaped == f"{KEY_ID}:{SECRET}", (
        f"the credential was mangled in transit: {unescaped!r}"
    )


@pytest.mark.usefixtures("fake_curl")
def test_the_config_fd_is_closed_after_the_request():
    before = len(os.listdir(f"/proc/{os.getpid()}/fd"))
    for _ in range(8):
        s3_gc.s3_request("https://example.invalid", "bucket", "auto", KEY_ID, SECRET, "GET")
    after = len(os.listdir(f"/proc/{os.getpid()}/fd"))
    assert after <= before + 1, f"file descriptors leaked across requests: {before} -> {after}"


def test_delete_is_refused_unconditionally_and_names_what_is_missing():
    proc = subprocess.run(
        [sys.executable, str(HERE / "s3_gc.py"), "--delete", "m01ABC"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0, "delete must never succeed before G13"
    assert "docs/evidence/G13/delete-authority-gate.json" in proc.stderr
    assert "no delete implementation" in proc.stderr


def test_the_tool_contains_no_delete_request_at_all():
    # The docstring's central claim, checked against the source rather than
    # trusted: no HTTP DELETE method is constructed anywhere in this file.
    text = (HERE / "s3_gc.py").read_text()
    body = text.split('"""', 2)[-1]  # skip the module docstring
    assert '"DELETE"' not in body and "'DELETE'" not in body, (
        "the module claims to contain no delete request, but one is constructed in the code"
    )


# ---------------------------------------------------------------------------
# R8-P2-05: the versioned namespace codec, with fixtures for BOTH the legacy
# path-derived shape and the controller-derived one.
#
# The audit's finding was that this tool reimplemented the layout — segment
# indices and a `startswith("m")` — so it covered only the shape that exists
# today and would have silently mis-attributed every object once the
# controller seam was wired. These fixtures are the two shapes, decoded
# through the declaration the Rust adapter is held against.
# ---------------------------------------------------------------------------

import namespace_codec  # noqa: E402

LEGACY_KEY = "typedb/=stmp=sdata.db=sks_A/fv1/m0001abcdef/keyspace/wal/00000000000000000001.sst"
CONTROLLER_KEY = "typedb/prod/acme-corp/db-7/g0003/m0001abcdef/data/keyspace/manifest/x.manifest"


def test_the_legacy_host_path_namespace_decodes_to_its_original_directory():
    fields = namespace_codec.parse(LEGACY_KEY, "typedb")
    assert fields == {
        "version": "v1-legacy-path",
        "keyspace": "/tmp/data.db/ks_A",
        "format_version": "fv1",
        "materialisation": "m0001abcdef",
    }


def test_the_controller_derived_namespace_decodes_to_its_identifiers():
    fields = namespace_codec.parse(CONTROLLER_KEY, "typedb")
    assert fields == {
        "version": "v2-controller",
        "environment": "prod",
        "tenant": "acme-corp",
        "database_id": "db-7",
        "generation": "g0003",
        "materialisation": "m0001abcdef",
        "keyspace": "data",
    }


def test_neither_shape_can_be_read_as_the_other():
    """The whole point of declaring both: a v1 key that decoded as v2 would
    attribute one database's objects to another, which for a GC report is the
    difference between an inventory and a hazard."""
    assert namespace_codec.parse(LEGACY_KEY, "typedb")["version"] == "v1-legacy-path"
    assert namespace_codec.parse(CONTROLLER_KEY, "typedb")["version"] == "v2-controller"


def test_a_key_matching_no_declared_version_is_refused_rather_than_guessed():
    for key in (
        "typedb/only/two/keyspace/x",
        "elsewhere/prod/acme/db/g/m01/data/keyspace/x",
        "typedb/=stmp=sks/fv1/NOT-A-MATERIALISATION/keyspace/x",
        "typedb/=stmp=sks/v1/m01/keyspace/x",
        "typedb/=stmp=sks/fv1/m01/NOT-keyspace/x",
    ):
        with pytest.raises(namespace_codec.NamespaceError):
            namespace_codec.parse(key, "typedb")


def test_the_report_skips_a_key_it_cannot_decode_instead_of_inventing_a_row():
    assert s3_gc.materialization_of("typedb/garbage", "typedb") is None
    assert s3_gc.materialization_of(LEGACY_KEY, "typedb")[0] == "v1-legacy-path"
    assert s3_gc.materialization_of(CONTROLLER_KEY, "typedb")[0] == "v2-controller"


@pytest.mark.parametrize(
    "raw",
    ["/tmp/data.db/ks_A", "a=b c", "плохой/путь", "", "=", "/", "ключ=значение/x"],
)
def test_the_segment_encoding_round_trips_every_byte_string(raw):
    """Injectivity is the property the namespace rests on: distinct byte
    strings must never share an encoding, or two databases share a prefix."""
    assert namespace_codec.decode_segment(namespace_codec.encode_segment(raw)) == raw


@pytest.mark.parametrize("bad", ["=q", "=x", "=xZZ", "=x1", "a/b", "a b"])
def test_a_segment_the_encoder_could_never_emit_is_refused(bad):
    with pytest.raises(namespace_codec.NamespaceError):
        namespace_codec.decode_segment(bad)


def test_the_prefix_builder_is_the_inverse_of_the_parser():
    fields = {
        "environment": "prod",
        "tenant": "acme-corp",
        "database_id": "db-7",
        "generation": "g0003",
        "materialisation": "m0001abcdef",
        "keyspace": "data",
    }
    prefix = namespace_codec.object_prefix(fields, "typedb", "v2-controller")
    decoded = namespace_codec.parse(f"{prefix}/keyspace/manifest/x.manifest", "typedb")
    assert {k: v for k, v in decoded.items() if k != "version"} == fields


def test_building_a_prefix_for_an_undeclared_version_or_missing_field_is_refused():
    with pytest.raises(namespace_codec.NamespaceError):
        namespace_codec.object_prefix({}, "typedb", "v99-imaginary")
    with pytest.raises(namespace_codec.NamespaceError):
        namespace_codec.object_prefix({"environment": "prod"}, "typedb", "v2-controller")


def test_the_report_aggregates_per_materialisation_and_never_issues_a_delete(monkeypatch, capsys):
    """The end-to-end shape of report mode, with the network replaced: the
    listing is aggregated per materialisation, both namespace versions appear,
    and the only thing the tool does with the result is print it."""
    listing = [
        (LEGACY_KEY, 100, "2026-08-01T00:00:00Z"),
        (LEGACY_KEY.replace("00001.sst", "00002.sst"), 40, "2026-08-02T00:00:00Z"),
        (CONTROLLER_KEY, 7, "2026-08-03T00:00:00Z"),
        ("typedb/undecodable", 999, "2026-08-04T00:00:00Z"),
    ]
    monkeypatch.setattr(s3_gc, "list_all", lambda *a, **k: iter(listing))
    for name, value in (
        ("TYPEDB_S3_ENDPOINT", "http://127.0.0.1:9000"),
        ("TYPEDB_S3_BUCKET", "b"),
        ("TYPEDB_S3_ACCESS_KEY_ID", "k"),
        ("TYPEDB_S3_SECRET_ACCESS_KEY", "s"),
    ):
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["s3_gc.py"])

    s3_gc.main()
    out = capsys.readouterr().out
    assert "v1-legacy-path" in out and "v2-controller" in out
    assert "2 materialisations" in out, out
    assert "140" in out, "the two legacy objects are summed, not listed"
    assert "999" not in out, "an undecodable key contributes to no row"
    assert "no delete request at all" in out


def test_an_empty_bucket_says_so_rather_than_printing_an_empty_table(monkeypatch, capsys):
    monkeypatch.setattr(s3_gc, "list_all", lambda *a, **k: iter([]))
    for name, value in (
        ("TYPEDB_S3_ENDPOINT", "http://127.0.0.1:9000"),
        ("TYPEDB_S3_BUCKET", "b"),
        ("TYPEDB_S3_ACCESS_KEY_ID", "k"),
        ("TYPEDB_S3_SECRET_ACCESS_KEY", "s"),
    ):
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["s3_gc.py"])
    s3_gc.main()
    assert "no materialisations under" in capsys.readouterr().out


def test_a_missing_required_environment_variable_names_itself(monkeypatch):
    monkeypatch.delenv("TYPEDB_S3_ENDPOINT", raising=False)
    with pytest.raises(SystemExit) as raised:
        s3_gc.env("TYPEDB_S3_ENDPOINT")
    assert "TYPEDB_S3_ENDPOINT" in str(raised.value)
