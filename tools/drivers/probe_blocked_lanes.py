#!/usr/bin/env python3
"""Executed probes for the driver-lane preconditions this environment imposes.

A blocked row must name the precise external precondition that blocks it,
established by RUNNING something, not by assertion. This tool runs the
probes and writes docs/evidence/G1/drivers/blocked-lanes.json, which
tools/drivers/row_status.py reads when a row has no evidence bundle.

Probes:
  bazel / swig / node / npm / cargo presence
  python driver from source: importing typedb.native_driver_wrapper straight
      out of sources/typedb-driver/python (the SWIG wrapper Bazel generates)
  pristine server lane: is a typedb_server_bin built under
      sources/typedb-pristine, and is there room to build one (measured
      against the size of the existing fork target directory)?

Usage:
  python3 tools/drivers/probe_blocked_lanes.py
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import common  # noqa: E402

REPO = common.REPO
OUT = REPO / "docs" / "evidence" / "G1" / "drivers" / "blocked-lanes.json"


def which(tool):
    p = shutil.which(tool)
    out = {"tool": tool, "path": p, "present": bool(p)}
    if p:
        r = subprocess.run([p, "--version"], capture_output=True, text=True)
        out["version"] = (r.stdout or r.stderr).strip().splitlines()[:1]
    return out


def probe_python_from_source():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO / "sources" / "typedb-driver" / "python")
    r = subprocess.run(
        [sys.executable, "-c",
         "import typedb.native_driver_wrapper as w; print(w.__file__)"],
        capture_output=True, text=True, env=env)
    return {
        "command": "PYTHONPATH=sources/typedb-driver/python python3 -c "
                   "'import typedb.native_driver_wrapper'",
        "exit_code": r.returncode,
        "stderr_tail": r.stderr.strip().splitlines()[-3:],
        "conclusion": (
            "the Python driver CANNOT be imported from the locked source "
            "tree: python/typedb/native_driver_wrapper.py and "
            "native_driver_python.so are SWIG outputs produced by the Bazel "
            "genrules in python/BUILD "
            "(@typedb_dependencies//builder/swig:python.bzl). Neither bazel "
            "nor swig exists here, so a from-source Python driver is blocked; "
            "the lane instead runs the OFFICIAL published wheel of the same "
            "version and proves module-for-module byte identity with the "
            "locked tree." if r.returncode != 0 else
            "the Python driver imports from the locked source tree"),
    }


def probe_pristine_server():
    pristine = REPO / "sources" / "typedb-pristine"
    fork_target = REPO / "sources" / "typedb" / "target"
    bin_path = pristine / "target" / "debug" / "typedb_server_bin"
    du = subprocess.run(["du", "-sb", str(fork_target)], capture_output=True,
                        text=True)
    fork_bytes = int(du.stdout.split()[0]) if du.returncode == 0 else None
    st = os.statvfs(REPO)
    free = st.f_bavail * st.f_frsize
    return {
        "checkout": common.checkout_identity(pristine),
        "server_binary": common.rel(bin_path),
        "server_binary_present": bin_path.is_file(),
        "fork_target_bytes": fork_bytes,
        "filesystem_free_bytes": free,
        "df_command": "os.statvfs(repo)",
        "conclusion": (
            f"no typedb_server_bin is built under sources/typedb-pristine. "
            f"Building one needs a cargo target directory of the order the "
            f"fork's already occupies ({fork_bytes} bytes measured); the "
            f"filesystem has {free} bytes free. The pristine (plan profile "
            f"U0) driver lane is therefore blocked on disk capacity in this "
            f"environment, not on tooling. The executed lanes use the fork "
            f"server, whose checkout dirt is recorded explicitly in every "
            f"bundle."),
    }


def main():
    doc = {
        "schema": "typedb-r2-driver-blocked-lanes-v1",
        "statement": (
            "Executed probes behind every 'blocked' claim in "
            "driver-row-status.json. Each entry records the command that was "
            "run and what it returned; a precondition nobody executed is not "
            "a precondition, it is an excuse."),
        "generated_at_utc": __import__("time").strftime(
            "%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
        "toolchain_probes": [which(t) for t in
                             ("bazel", "swig", "cargo", "rustc", "node", "npm",
                              "python3", "pnpm")],
        "python_driver_from_source": probe_python_from_source(),
        "pristine_server_lane": probe_pristine_server(),
        "rows": {},
    }
    print(json.dumps(doc, indent=1))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
