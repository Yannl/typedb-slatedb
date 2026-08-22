#!/usr/bin/env python3
"""The ONE probe implementation for the ONE environment model (R8-P1-07).

The round-8 audit found two defects that are really the same defect.

The first: a missing native header made a Rust child exit nonzero, and the
controller — seeing a nonzero exit with no recognised substring — reported
`QualityFailure`. That sends the next reader hunting for a defect in code that
was never compiled. Recognising the message would only move the fragility: a
compiler that words the error differently, or a different missing component,
lands in the same wrong half of the report.

The second: `tools/dev/doctor.py` checked a small, DIFFERENT subset of the
environment from the one the controller requires. Two environment models can
disagree, and a doctor that says "every lane is runnable" before a gate refuses
for a missing capability is worse than no doctor at all.

So the capability set is DECLARED once, in `.quality/capabilities.toml`, and
probed once, here. `cargo xtask quality` runs this as a preflight before it
invokes anything, and reports an unmet capability as InfrastructureFailure
(exit 3) naming the remediation from the inventory. `tools/dev/doctor.py`
imports this module and reports the same probes. Neither has its own list.

The probes are STRUCTURAL: a header is probed by compiling it, a shared library
by loading it, a namespace by entering one, a socket by binding one. None of
them reads an error message.

usage:
  python3 tools/quality/capabilities.py --all
  python3 tools/quality/capabilities.py --gate rust.tests
  python3 tools/quality/capabilities.py --gates rust.tests,ts.oxlint --json
  python3 tools/quality/capabilities.py --audit        # gates declaring nothing
  python3 tools/quality/capabilities.py --self-test

exit codes:
  0  every probed capability is satisfied
  3  at least one is not (EXIT_CAPABILITY_UNAVAILABLE — the same code the gate
     commands use, so the controller classifies it structurally)
  1  the inventory or the invocation is wrong
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import tomllib

REPO = pathlib.Path(__file__).resolve().parents[2]
INVENTORY = REPO / ".quality" / "capabilities.toml"
VENV_PYTHON = REPO / ".quality" / ".venv" / "bin" / "python3"

EXIT_CAPABILITY_UNAVAILABLE = 3

CLONE_NEWNET = 0x40000000


class Result:
    __slots__ = ("id", "ok", "detail", "remediation", "why", "kind")

    def __init__(self, cid: str, kind: str, ok: bool, detail: str, spec: dict):
        self.id = cid
        self.kind = kind
        self.ok = ok
        self.detail = detail
        self.remediation = spec.get("remediation", "")
        self.why = spec.get("why", "")

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "ok": self.ok,
            "detail": self.detail,
            "why": self.why,
            "remediation": self.remediation,
        }


# ----------------------------------------------------------------- the probes


def probe_command(spec: dict) -> tuple[bool, str]:
    program = spec["program"]
    found = shutil.which(program)
    return (bool(found), found or f"`{program}` is not on PATH")


def probe_c_header(spec: dict) -> tuple[bool, str]:
    """Compile a one-line translation unit. Presence on disk is not the property
    that matters: a header the active compiler cannot reach through its own
    include path is exactly as fatal, and is what an unusual sysroot produces.
    """
    language = spec.get("language", "c")
    compiler = os.environ.get("CXX" if language == "c++" else "CC") or (
        "c++" if language == "c++" else "cc"
    )
    if shutil.which(compiler) is None:
        return False, f"no {language} compiler (`{compiler}`) to probe <{spec['header']}> with"
    suffix = ".cpp" if language == "c++" else ".c"
    with tempfile.TemporaryDirectory() as tmp:
        src = pathlib.Path(tmp) / f"probe{suffix}"
        src.write_text(f"#include <{spec['header']}>\nint main(void) {{ return 0; }}\n")
        proc = subprocess.run(
            [compiler, "-fsyntax-only", str(src)],
            capture_output=True,
            text=True,
            timeout=120,
        )
    if proc.returncode == 0:
        return True, f"<{spec['header']}> compiles with {compiler}"
    tail = (proc.stderr or proc.stdout or "").strip().splitlines()
    return (
        False,
        f"{compiler} cannot compile <{spec['header']}>: {tail[0] if tail else 'no output'}",
    )


def probe_shared_library(spec: dict) -> tuple[bool, str]:
    """dlopen, not stat. bindgen loads libclang at build time; a file that is
    present but unloadable (wrong architecture, missing transitive dependency)
    fails the build with a message that names no missing package.
    """
    candidates = list(spec.get("candidates", []))
    hint = spec.get("env_hint")
    searched = []
    if hint and os.environ.get(hint):
        base = pathlib.Path(os.environ[hint])
        searched = [str(base / c) for c in candidates] + [str(base)]
    for name in searched + candidates:
        try:
            ctypes.CDLL(name)
            return True, f"{name} loads"
        except OSError:
            continue
    return False, "none of " + ", ".join(candidates) + " could be loaded"


def probe_cargo_subcommand(spec: dict) -> tuple[bool, str]:
    sub = spec["subcommand"]
    if shutil.which("cargo") is None:
        return False, "cargo is not on PATH, so `cargo {sub}` cannot be probed".format(sub=sub)
    try:
        proc = subprocess.run(
            ["cargo", sub, "--version"], capture_output=True, text=True, timeout=120
        )
    except (OSError, subprocess.SubprocessError) as error:
        return False, f"`cargo {sub} --version` could not run: {error}"
    if proc.returncode == 0:
        return True, (proc.stdout or proc.stderr).strip().splitlines()[0]
    return False, f"`cargo {sub} --version` exited {proc.returncode}"


def probe_npm_bin(spec: dict) -> tuple[bool, str]:
    """Resolved from the PROJECT's dependency tree. A globally installed copy is
    a different version than the lockfile pins, and a gate that silently used it
    would report on a tool the repository never chose.
    """
    binary = REPO / spec["project"] / "node_modules" / ".bin" / spec["bin"]
    if binary.exists() and os.access(binary, os.X_OK):
        return True, str(binary.relative_to(REPO))
    return False, f"{spec['bin']} is not executable in {spec['project']}/node_modules/.bin"


def probe_python_module(spec: dict) -> tuple[bool, str]:
    interpreter = str(VENV_PYTHON) if spec.get("venv") else sys.executable
    if spec.get("venv") and not VENV_PYTHON.is_file():
        return False, f"the repository-owned venv is absent ({VENV_PYTHON.relative_to(REPO)})"
    proc = subprocess.run(
        [interpreter, "-c", f"import {spec['module']} as m; print(getattr(m,'__version__',''))"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode == 0:
        version = proc.stdout.strip()
        where = "venv" if spec.get("venv") else "system interpreter"
        return True, f"{spec['module']} {version} in the {where}".rstrip()
    return False, f"{spec['module']} is not importable by {interpreter}"


def probe_network_namespace(_spec: dict) -> tuple[bool, str]:
    """Enter one in a forked child. Reading a capability bit would answer a
    different question: what decides the outcome is whether this process, under
    whatever sandbox it is in, can actually get a private net namespace.
    """
    pid = os.fork()
    if pid == 0:  # child
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            code = 0 if libc.unshare(CLONE_NEWNET) == 0 else 1
        except Exception:
            code = 1
        os._exit(code)
    _, status = os.waitpid(pid, 0)
    if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0:
        return True, "unshare(CLONE_NEWNET) succeeded in a forked child"
    return False, "unshare(CLONE_NEWNET) was refused (no CAP_SYS_ADMIN, or userns disabled)"


def probe_af_unix(_spec: dict) -> tuple[bool, str]:
    """Bind and connect a socket where the gates actually put theirs.

    `TMPDIR` is read DIRECTLY rather than through `tempfile.gettempdir()`,
    which silently falls back to /tmp when the configured directory is not
    writable. Falling back is the wrong answer here: the supervision code
    builds its socket paths from TMPDIR, so a TMPDIR that cannot host a socket
    is a real denial, and a probe that quietly used a different directory would
    report a capability the gate does not have.
    """
    base = os.environ.get("TMPDIR") or tempfile.gettempdir()
    try:
        directory = tempfile.mkdtemp(prefix="cap-probe-", dir=base)
    except OSError as error:
        return False, f"no socket directory can be created under TMPDIR ({base}): {error}"
    try:
        path = os.path.join(directory, "probe.sock")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(path)
                server.listen(1)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.connect(path)
                    conn, _ = server.accept()
                    conn.close()
        except OSError as error:
            return False, f"AF_UNIX bind/connect under {base} failed: {error}"
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    return True, f"AF_UNIX bind/connect works under {base}"


def probe_proc_supervision(_spec: dict) -> tuple[bool, str]:
    """Supervision reads a CHILD's status, so the probe reads a child's status.
    /proc/self is readable under hidepid too; the restriction that breaks
    supervision only shows on another process.
    """
    if not pathlib.Path("/proc/self/status").is_file():
        return False, "/proc/self/status is not readable"
    child = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdin.read()"], stdin=subprocess.PIPE
    )
    try:
        status = pathlib.Path(f"/proc/{child.pid}/status")
        readable = status.is_file()
        detail = (
            f"/proc/{child.pid}/status readable"
            if readable
            else f"/proc/{child.pid}/status is hidden (hidepid?), so child supervision cannot see its own children"
        )
    finally:
        if child.stdin:
            child.stdin.close()
        child.wait(timeout=30)
    return readable, detail


def probe_path(spec: dict) -> tuple[bool, str]:
    target = REPO / spec["path"]
    return (target.exists(), f"{spec['path']} {'exists' if target.exists() else 'is absent'}")


PROBES = {
    "command": probe_command,
    "c_header": probe_c_header,
    "shared_library": probe_shared_library,
    "cargo_subcommand": probe_cargo_subcommand,
    "npm_bin": probe_npm_bin,
    "python_module": probe_python_module,
    "network_namespace": probe_network_namespace,
    "af_unix": probe_af_unix,
    "proc_supervision": probe_proc_supervision,
    "path": probe_path,
}


# ------------------------------------------------------------------ inventory


class InventoryError(Exception):
    pass


def load(path: pathlib.Path = INVENTORY) -> dict:
    try:
        inventory = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise InventoryError(f"{path} is unreadable: {error}") from error
    caps = inventory.get("capability") or {}
    gates = inventory.get("gates") or {}
    if not caps:
        raise InventoryError(f"{path} declares no capabilities")
    for cid, spec in caps.items():
        kind = spec.get("kind")
        if kind not in PROBES:
            raise InventoryError(f"capability {cid!r} declares unknown probe kind {kind!r}")
        for required in ("why", "remediation"):
            if not spec.get(required):
                raise InventoryError(
                    f"capability {cid!r} has no {required!r}: an unmet capability that cannot "
                    f"say what it blocks or how to fix it stops a run without helping anyone"
                )
    for gate, needs in gates.items():
        unknown = [n for n in needs if n not in caps]
        if unknown:
            raise InventoryError(f"gate {gate!r} requires undeclared capabilities {unknown}")
    return inventory


def probe(cid: str, spec: dict) -> Result:
    try:
        ok, detail = PROBES[spec["kind"]](spec)
    except Exception as error:  # a probe that crashes is an unmet capability
        ok, detail = False, f"the probe itself failed: {error!r}"
    return Result(cid, spec["kind"], ok, detail, spec)


def probe_many(inventory: dict, ids) -> list[Result]:
    caps = inventory["capability"]
    return [probe(cid, caps[cid]) for cid in ids]


def required_for(inventory: dict, gates: list[str]) -> list[str]:
    table = inventory.get("gates") or {}
    unknown = [g for g in gates if g not in table]
    if unknown:
        raise InventoryError(
            f"gate(s) {unknown} are not in {INVENTORY.name}. Every gate declares its capabilities "
            f"explicitly — an unlisted gate is an undeclared environment dependency, not an empty one"
        )
    seen: list[str] = []
    for gate in gates:
        for cid in table[gate]:
            if cid not in seen:
                seen.append(cid)
    return seen


# ------------------------------------------------------------------ self-test


def self_test() -> int:
    """Controls over the probe runner itself, executed on demand.

    Each asserts a property this file would otherwise only claim: that the
    inventory validates, that a probe kind cannot be invented silently, that a
    crashing probe reports UNMET rather than propagating, and that a gate not in
    the inventory is refused rather than treated as needing nothing.
    """
    checks: list[tuple[str, bool, str]] = []

    try:
        inventory = load()
        checks.append(
            (
                "the shipped inventory validates",
                True,
                f"{len(inventory['capability'])} capabilities",
            )
        )
    except InventoryError as error:
        checks.append(("the shipped inventory validates", False, str(error)))
        inventory = {"capability": {}, "gates": {}}

    for name, mutate, expect in (
        (
            "an unknown probe kind is refused",
            lambda inv: inv["capability"].__setitem__(
                "x", {"kind": "vibes", "why": "w", "remediation": "r"}
            ),
            "unknown probe kind",
        ),
        (
            "a capability with no remediation is refused",
            lambda inv: inv["capability"].__setitem__(
                "x", {"kind": "command", "program": "cc", "why": "w"}
            ),
            "no 'remediation'",
        ),
        (
            "a gate requiring an undeclared capability is refused",
            lambda inv: inv["gates"].__setitem__("x.y", ["nope"]),
            "undeclared capabilities",
        ),
    ):
        mutated = json.loads(json.dumps(load()))
        mutate(mutated)
        with tempfile.TemporaryDirectory() as tmp:
            copy = pathlib.Path(tmp) / "capabilities.toml"
            copy.write_text(_to_toml(mutated))
            try:
                load(copy)
                checks.append((name, False, "the mutated inventory was ACCEPTED"))
            except InventoryError as error:
                checks.append((name, expect in str(error), str(error)[:120]))

    crashing = probe("boom", {"kind": "command", "why": "w", "remediation": "r"})
    checks.append(
        (
            "a probe that raises reports UNMET",
            not crashing.ok and "probe itself failed" in crashing.detail,
            crashing.detail[:80],
        )
    )

    try:
        required_for(load(), ["no.such.gate"])
        checks.append(("an unlisted gate is refused, not treated as empty", False, "accepted"))
    except InventoryError as error:
        checks.append(
            ("an unlisted gate is refused, not treated as empty", "not in" in str(error), "")
        )

    failed = 0
    for name, ok, detail in checks:
        print(
            f"  {'ok  ' if ok else 'FAIL'}  {name}" + (f" — {detail}" if detail and not ok else "")
        )
        failed += 0 if ok else 1
    print(
        f"\nCAPABILITY SELF-TEST: {'PASS' if not failed else 'FAIL'} ({len(checks) - failed}/{len(checks)})"
    )
    return 0 if not failed else 1


def _to_toml(data: dict) -> str:
    """Minimal writer for the self-test's mutated inventories."""
    out = ["schema = 1"]
    for cid, spec in data.get("capability", {}).items():
        out.append(f"\n[capability.{json.dumps(cid)}]")
        for key, value in spec.items():
            out.append(f"{key} = {json.dumps(value)}")
    out.append("\n[gates]")
    for gate, needs in data.get("gates", {}).items():
        out.append(f"{json.dumps(gate)} = {json.dumps(needs)}")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--all", action="store_true", help="probe every declared capability")
    ap.add_argument("--gate", action="append", default=[], help="probe what this gate requires")
    ap.add_argument("--gates", default=None, help="comma-separated gate ids")
    ap.add_argument("--json", action="store_true", help="machine-readable result map")
    ap.add_argument("--audit", action="store_true", help="list gates that declare no capability")
    ap.add_argument("--self-test", action="store_true", help="controls over this runner")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        inventory = load()
    except InventoryError as error:
        print(f"CAPABILITIES: FAIL — {error}", file=sys.stderr)
        return 1

    if args.audit:
        empty = [g for g, needs in inventory["gates"].items() if not needs]
        print(f"{len(empty)} of {len(inventory['gates'])} gates declare no external capability:")
        for gate in empty:
            print(f"  {gate}")
        return 0

    gates = list(args.gate) + [g for g in (args.gates or "").split(",") if g]
    try:
        ids = (
            list(inventory["capability"])
            if args.all or not gates
            else required_for(inventory, gates)
        )
    except InventoryError as error:
        print(f"CAPABILITIES: FAIL — {error}", file=sys.stderr)
        return 1

    results = probe_many(inventory, ids)
    unmet = [r for r in results if not r.ok]

    if args.json:
        print(
            json.dumps(
                {
                    "gates": gates,
                    # the gate -> capability map travels WITH the results, so the
                    # controller never parses the inventory a second time: one
                    # file, one reader, one answer.
                    "requires": {
                        g: list(inventory["gates"][g]) for g in (gates or inventory["gates"])
                    },
                    "probed": [r.as_dict() for r in results],
                    "unmet": [r.id for r in unmet],
                },
                indent=1,
            )
        )
    else:
        for r in results:
            print(f"  {'ok  ' if r.ok else 'MISSING'}  {r.id:<28} {r.detail}")
        if unmet:
            print()
            for r in unmet:
                print(f"  {r.id}: {r.why}\n      fix: {r.remediation}")

    if unmet:
        scope = ", ".join(gates) if gates else "the whole inventory"
        print(
            f"CAPABILITIES: {len(unmet)} of {len(results)} UNMET for {scope} — "
            f"{', '.join(r.id for r in unmet)}",
            file=sys.stderr,
        )
        return EXIT_CAPABILITY_UNAVAILABLE
    print(f"CAPABILITIES: {len(results)} probed, all satisfied", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
