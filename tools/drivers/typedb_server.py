#!/usr/bin/env python3
"""TypeDB server lifecycle for the official-driver qualification lane.

The Rust driver's behaviour steps hardcode `Context::DEFAULT_ADDRESS =
"127.0.0.1:1729"` (rust/tests/behaviour/steps/lib.rs), so this lane cannot
pick an ephemeral port. It therefore REFUSES to run when 1729 is already
bound rather than attaching to somebody else's server: evidence attributed to
an unknown process is not evidence.

Readiness is an authenticated, driver-visible fact, never a sleep: the HTTP
`/health` endpoint must answer 204 AND `/v1/version` must return the version
document AND the gRPC port must accept a TCP connection. Every probe attempt
is recorded, and a server that exits before readiness raises immediately with
its captured stdout, so "the suite reported nothing because nothing started"
can never be mistaken for a pass.
"""

import json
import pathlib
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import common  # noqa: E402

REPO = common.REPO
GRPC_PORT = 1729  # fixed by Context::DEFAULT_ADDRESS upstream
HTTP_PORT = 8729
LOOPBACK = "127.0.0.1"

# What the storage layer must have actually built, per profile. This is the
# ON-DISK witness (`<data>/_system/backend-spec.marker`, written by the fork's
# storage factory), not the environment variable this runner set. An env var
# says what was ASKED for; the marker says what was BUILT. Evidence for a
# "slatedb" plan row that rests only on `TYPEDB_STORAGE_PROFILE=U2` would be
# indistinguishable from a run in which the profile was ignored.
EXPECTED_BACKEND_KIND = {"U0": "classic", "U1": "classic", "U2": "slatedb-r2"}

LANES = {
    # lane -> (checkout, storage profile env, source-lock node, description)
    "fork-classic": (
        "sources/typedb",
        "U1",
        "TB",
        "fork server, RocksDB keyspaces + file WAL (plan profile U1)",
    ),
    "fork-slatedb": (
        "sources/typedb",
        "U2",
        "TB",
        "fork server, SlateDB LocalFS keyspaces + file WAL (plan profile U2)",
    ),
    "pristine": (
        "sources/typedb-pristine",
        "U0",
        "TB",
        "pristine upstream checkout, RocksDB + file WAL (plan profile U0)",
    ),
}


class ServerError(RuntimeError):
    pass


def port_free(port, host=LOOPBACK):
    with socket.socket() as s:
        s.settimeout(1.0)
        return s.connect_ex((host, port)) != 0


def _http(url, timeout=3.0):
    req = urllib.request.Request(url)
    # the agent proxy must never see loopback traffic
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as r:
        return r.status, r.read()


class TypeDBServer:
    def __init__(self, lane, run_dir, binary=None, grpc_port=GRPC_PORT, http_port=HTTP_PORT):
        if lane not in LANES:
            raise ServerError(f"unknown lane {lane!r}; known: {sorted(LANES)}")
        self.lane = lane
        checkout, self.profile, self.lock_node, self.description = LANES[lane]
        self.checkout = REPO / checkout
        self.run_dir = pathlib.Path(run_dir)
        self.binary = (
            pathlib.Path(binary)
            if binary
            else (self.checkout / "target" / "debug" / "typedb_server_bin")
        )
        self.grpc_port, self.http_port = grpc_port, http_port
        self.proc = None
        self.probes: list[dict[str, object]] = []
        self.log_path = self.run_dir / "server.log"
        # Set by start()/wait_ready(), declared here. evidence() used to read
        # them with `getattr(self, ..., None)`, which is the same admission
        # written in a way that cannot be checked: a typo in the attribute name
        # would have archived None for the server's own argv.
        self.argv: list[str] | None = None
        self._out = None
        self.ready_after_s: float | None = None
        self.version: object | None = None

    # ---------------------------------------------------------------- facts
    def identity(self):
        ident = {
            "lane": self.lane,
            "description": self.description,
            "storage_profile_env": self.profile,
            "binary": common.rel(self.binary),
            "binary_exists": self.binary.is_file(),
            "grpc_address": f"{LOOPBACK}:{self.grpc_port}",
            "http_address": f"{LOOPBACK}:{self.http_port}",
            "checkout": common.checkout_identity(self.checkout),
            "source_lock_node": common.source_lock_node(self.lock_node),
        }
        if self.binary.is_file():
            st = self.binary.stat()
            ident["binary_sha256"] = common.sha256_file(self.binary)
            ident["binary_size"] = st.st_size
            ident["binary_mtime"] = int(st.st_mtime)
        return ident

    # ------------------------------------------------------------ lifecycle
    def start(self, timeout_s=180):
        if not self.binary.is_file():
            raise ServerError(
                f"server binary absent at {common.rel(self.binary)} - build it "
                f"(cargo build -p typedb_server_bin in {common.rel(self.checkout)}) "
                f"or pass --server-binary"
            )
        for port, what in ((self.grpc_port, "gRPC"), (self.http_port, "HTTP")):
            if not port_free(port):
                raise ServerError(
                    f"{what} port {port} is already bound. The upstream driver "
                    f"steps hardcode {LOOPBACK}:{GRPC_PORT}, so this lane cannot "
                    f"move; it refuses to attach to a server it did not start."
                )
        data = self.run_dir / "server-data"
        logs = self.run_dir / "server-logs"
        for d in (data, logs):
            if d.exists():
                shutil.rmtree(d)
            d.mkdir(parents=True)
        env = dict(**{k: v for k, v in __import__("os").environ.items()})
        env["TYPEDB_STORAGE_PROFILE"] = self.profile
        cfg = self.checkout / "server" / "config.yml"
        argv = [
            str(self.binary),
            "--config",
            str(cfg),
            "--storage.data-directory",
            str(data),
            "--server.listen-address",
            f"{LOOPBACK}:{self.grpc_port}",
            "--server.http.enabled",
            "true",
            "--server.http.listen-address",
            f"{LOOPBACK}:{self.http_port}",
            "--diagnostics.reporting.errors",
            "false",
            "--diagnostics.reporting.metrics",
            "false",
            "--diagnostics.monitoring.enabled",
            "false",
            "--logging.directory",
            str(logs),
        ]
        self.argv = argv
        out = open(self.log_path, "wb")
        self._out = out
        self.proc = subprocess.Popen(
            argv,
            stdout=out,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
        )
        started = time.time()
        deadline = started + timeout_s
        while time.time() < deadline:
            rc = self.proc.poll()
            if rc is not None:
                raise ServerError(
                    f"server exited rc={rc} before becoming ready; captured "
                    f"output:\n{self.log_path.read_text()[-4000:]}"
                )
            probe: dict[str, object] = {"t": round(time.time() - started, 2)}
            try:
                st, _ = _http(f"http://{LOOPBACK}:{self.http_port}/health")
                probe["health_status"] = st
                st2, body = _http(f"http://{LOOPBACK}:{self.http_port}/v1/version")
                probe["version_status"] = st2
                probe["version_body"] = body.decode()[:200]
                probe["grpc_accepts"] = not port_free(self.grpc_port)
                self.probes.append(probe)
                if st == 204 and st2 == 200 and probe["grpc_accepts"]:
                    self.ready_after_s = probe["t"]
                    self.version = json.loads(body.decode())
                    return self
            except (urllib.error.URLError, OSError, ValueError) as e:
                probe["error"] = f"{type(e).__name__}: {e}"
                self.probes.append(probe)
            time.sleep(1.0)
        self.stop()
        raise ServerError(
            f"server never became ready within {timeout_s}s; last probes: "
            f"{json.dumps(self.probes[-3:])}; log tail:\n"
            f"{self.log_path.read_text()[-4000:]}"
        )

    def backend_witness(self):
        """Read and check the on-disk backend identity the server wrote."""
        marker = self.run_dir / "server-data" / "_system" / "backend-spec.marker"
        out: dict[str, object] = {
            "marker_path": str(marker),
            "present": marker.is_file(),
            "expected_kind": EXPECTED_BACKEND_KIND.get(self.profile),
        }
        if not marker.is_file():
            out["problem"] = (
                f"no backend-spec.marker under the server data directory: the "
                f"backend the server actually built cannot be witnessed, so a "
                f"{self.profile} claim would rest on the environment variable "
                f"alone"
            )
            return out
        text = marker.read_text()
        out["marker_text"] = text
        out["marker_sha256"] = common.sha256_bytes(text.encode())
        fields = {}
        for line in text.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                fields[parts[0]] = parts[1].strip()
        out["fields"] = fields
        out["kind"] = fields.get("kind")
        if out["kind"] != out["expected_kind"]:
            out["problem"] = (
                f"server built backend kind {out['kind']!r} but profile "
                f"{self.profile} requires {out['expected_kind']!r} - the "
                f"storage profile was not honoured"
            )
        # a second, independent witness: RocksDB keyspaces are CFs on disk
        # (CURRENT/MANIFEST/*.sst); a SlateDB keyspace is a `keyspace` object
        # tree. Layout cannot be faked by an env var either.
        ks = self.run_dir / "server-data" / "_system" / "storage"
        sample = sorted(p.name for p in ks.glob("*"))[:3]
        out["keyspace_sample"] = {n: sorted(q.name for q in (ks / n).glob("*"))[:8] for n in sample}
        return out

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def returncode(self):
        """The server's exit status, or None if it was never started.

        Callers used to read `server.proc.returncode` directly, which is a
        None dereference on a server that failed to start — precisely the case
        where the evidence record matters most.
        """
        return self.proc.returncode if self.proc is not None else None

    def stop(self):
        rc = None
        if self.proc is not None:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=30)
            rc = self.proc.returncode
        if self._out is not None:
            try:
                self._out.close()
            except OSError:
                pass
        return rc

    def evidence(self):
        e = self.identity()
        e.update(
            {
                "argv": self.argv,
                "ready_probes": self.probes,
                "ready_after_seconds": self.ready_after_s,
                "version_endpoint": self.version,
                "log": common.rel(self.log_path),
                "log_sha256": (
                    common.sha256_file(self.log_path) if self.log_path.is_file() else None
                ),
                "exit_code": (self.proc.returncode if self.proc is not None else None),
                "backend_witness": self.backend_witness(),
            }
        )
        return e
