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
