"""Release lanes: the tests that run against ONE built artifact.

A lane is a named Python implementation, never an argv from a manifest.
That is deliberate: if a lane were "whatever command the manifest names",
one manifest edit could point a required lane at `/bin/true` and promotion
would still see a green required lane. The manifest may only SELECT among
the implementations below, so an unknown lane id is a refusal.

Every lane receives the extracted artifact tree plus the release record and
returns (passed: bool, log: str). Lanes must not consult the repository
working tree for anything they claim about the artifact — testing the exact
shipped bytes rather than the sources they came from is the entire point.
"""

import contextlib
import http.client
import os
import signal
import socket
import subprocess
import time

# The layout the Bazel `assemble-typedb-all` archive is required to have;
# tools/catalog/package_assembly.py reproduces it from Cargo-built binaries.
EXPECTED_FILES = {
    "LICENSE": {"executable": False},
    "typedb": {"executable": True},
    "server/config.yml": {"executable": False},
    "server/typedb_server_bin": {"executable": True},
    "admin/typedb_admin_bin": {"executable": True},
    "console/typedb_console_bin": {"executable": True},
    "loader/typedb_loader_bin": {"executable": True},
}

# What `--version` must actually prove for each binary. A dynamic-link
# failure is the false green this guards against: the loader writes
# "error while loading shared libraries" to stderr and exits 127, which a
# naive "did it print anything?" check reads as success. Both binaries that
# implement --version must exit 0; the two that do not must still reach
# their own clap parser and say so, which no loader failure can fake.
VERSION_EXPECTATIONS = {
    "server/typedb_server_bin": {"exit": 0, "must_contain": "server "},
    "console/typedb_console_bin": {"exit": 0, "must_contain": "."},
    "admin/typedb_admin_bin": {"exit": None, "must_contain": "Usage: typedb_admin_bin"},
    "loader/typedb_loader_bin": {"exit": None, "must_contain": "Usage: typedb_loader_bin"},
}

LOADER_FAILURE_MARKERS = (
    "error while loading shared libraries",
    "cannot execute binary file",
    "Exec format error",
    "No such file or directory",
)


def lane_artifact_layout(tree, _record):
    """The extracted artifact has exactly the required layout.

    Missing files, non-executable binaries, symlinks (a symlink out of the
    tree is how an "artifact" smuggles in host state) and unexpected extra
    members are all failures.
    """
    log = []
    ok = True
    seen = set()
    for path in sorted(tree.rglob("*")):
        rel = path.relative_to(tree).as_posix()
        if path.is_symlink():
            log.append(f"FAIL symlink member: {rel}")
            ok = False
            continue
        if path.is_dir():
            continue
        seen.add(rel)
        spec = EXPECTED_FILES.get(rel)
        if spec is None:
            log.append(f"FAIL unexpected member: {rel}")
            ok = False
            continue
        executable = bool(path.stat().st_mode & 0o111)
        if executable != spec["executable"]:
            log.append(f"FAIL {rel}: executable={executable} want={spec['executable']}")
            ok = False
        else:
            log.append(f"ok   {rel} ({path.stat().st_size} bytes, executable={executable})")
    for rel in sorted(set(EXPECTED_FILES) - seen):
        log.append(f"FAIL missing member: {rel}")
        ok = False
    log.append(f"members inspected: {len(seen)}")
    # the verdict line is parsed by release.py, which requires the log's last
    # line to END with ": PASS" or ": FAIL" — counts go on their own line
    log.append(f"layout: {'PASS' if ok else 'FAIL'}")
    return ok, "\n".join(log)


def lane_artifact_exec(tree, _record):
    """Every shipped binary loads and reaches its own argument parser.

    A tarball whose payload cannot run is not a release candidate, and no
    source-side test establishes this: it is a property of the shipped
    bytes on the target platform.
    """
    log = []
    ok = True
    for rel, expect in sorted(VERSION_EXPECTATIONS.items()):
        binary = tree / rel
        try:
            r = subprocess.run(
                [str(binary), "--version"],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(tree),
                env={**os.environ, "HOME": str(tree)},
            )
        except OSError as err:
            log.append(f"FAIL {rel}: could not execute: {err}")
            ok = False
            continue
        except subprocess.TimeoutExpired:
            log.append(f"FAIL {rel}: --version timed out")
            ok = False
            continue
        out = r.stdout + r.stderr
        first = out.strip().splitlines()[0][:200] if out.strip() else "(no output)"
        problems = []
        if any(marker in out for marker in LOADER_FAILURE_MARKERS):
            problems.append("dynamic-loader failure")
        if r.returncode == 127:
            problems.append("exit 127 (loader/not-found)")
        if expect["exit"] is not None and r.returncode != expect["exit"]:
            problems.append(f"exit {r.returncode} want {expect['exit']}")
        if expect["must_contain"] not in out:
            problems.append(f"output lacks {expect['must_contain']!r}")
        if problems:
            ok = False
            log.append(f"FAIL {rel}: {'; '.join(problems)}; first-line={first!r}")
        else:
            log.append(f"ok   {rel}: exit={r.returncode} first-line={first!r}")
    log.append(f"exec: {'PASS' if ok else 'FAIL'}")
    return ok, "\n".join(log)


def _free_port():
    """A port free at this instant.

    Inherently a hint, not a reservation — another process can take it
    between close and bind. The lane treats a bind failure as a lane
    failure with the server's own message rather than retrying forever, so
    a collision is visible instead of silently green.
    """
    with contextlib.closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _health(port, timeout_s=3.0):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout_s)
    try:
        conn.request("GET", "/health")
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        conn.close()


def lane_artifact_health(tree, _record):
    """The shipped server starts from the shipped config and serves /health.

    This is the strongest claim a release-artifact lane can make on its
    own: the exact bytes being promoted boot, parse their own configuration
    and answer a request. It is NOT product qualification — U3/U4, the
    official driver suites and the full leaf plan are separate lanes this
    pipeline does not pretend to replace.
    """
    binary = tree / "server" / "typedb_server_bin"
    data = tree / "_release_lane_data"
    logs = tree / "_release_lane_logs"
    data.mkdir(exist_ok=True)
    logs.mkdir(exist_ok=True)
    grpc_port, http_port = _free_port(), _free_port()
    argv = [
        str(binary),
        "--config",
        str(tree / "server" / "config.yml"),
        "--storage.data-directory",
        str(data),
        "--server.listen-address",
        f"127.0.0.1:{grpc_port}",
        "--server.http.enabled",
        "true",
        "--server.http.listen-address",
        f"127.0.0.1:{http_port}",
        "--diagnostics.reporting.errors",
        "false",
        "--diagnostics.reporting.metrics",
        "false",
        "--diagnostics.monitoring.enabled",
        "false",
        "--logging.directory",
        str(logs),
    ]
    log = [f"argv: {argv}"]
    out_path = logs / "server-stdout.log"
    with open(out_path, "wb") as out:
        child = subprocess.Popen(
            argv,
            stdout=out,
            stderr=subprocess.STDOUT,
            cwd=str(tree),
            start_new_session=True,
            env={**os.environ, "HOME": str(tree)},
        )
        try:
            status = None
            deadline = time.monotonic() + 120  # generous: a cold binary on a loaded box
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    break
                try:
                    status = _health(http_port)
                    # TypeDB CE answers /health with 204 No Content; any 2xx is
                    # the server telling us it is serving, which is the claim
                    # this lane makes. Pinning 200 exactly would have made a
                    # healthy server look dead.
                    if status is not None and 200 <= status < 300:
                        break
                except OSError:
                    status = None
                time.sleep(0.5)
            healthy = status is not None and 200 <= status < 300
            if child.poll() is not None and not healthy:
                log.append(f"FAIL server exited rc={child.returncode} before ready")
            log.append(f"/health on 127.0.0.1:{http_port} -> {status}")
        finally:
            if child.poll() is None:
                # the server is its own process group (start_new_session)
                with contextlib.suppress(OSError):
                    os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(OSError):
                        os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=30)
    tail = out_path.read_text("utf-8", "replace")[-4000:]
    log += [
        "--- server output (last 4000 bytes) ---",
        tail,
        f"health: {'PASS' if healthy else 'FAIL'}",
    ]
    return healthy, "\n".join(log)


LANES = {
    "artifact-layout": lane_artifact_layout,
    "artifact-exec": lane_artifact_exec,
    "artifact-health": lane_artifact_health,
}
