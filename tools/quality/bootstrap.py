#!/usr/bin/env python3
"""Install every tool the quality controller may invoke, from the machine lock.

R8-P0-04. The round-8 audit's finding was precise and uncomfortable: the three
CI jobs advertised as the authoritative quality predicate installed Python,
Node, Rust and a handful of apt packages, and then ran a controller that needs
about twenty more tools — cargo-nextest, cargo-deny, cargo-machete, cargo-hack,
cargo-llvm-cov, cargo-mutants, cargo-semver-checks, Miri, cargo-fuzz, Ruff,
basedpyright, pytest, pip-audit, oxlint, knip, dependency-cruiser, Stryker,
jscpd, and the crap family. `.quality/tools.lock.toml` DETECTED them and
printed a remediation; it was never an installer. "Pinned but not installed" is
not hermetic execution, and the npm quality tools were not even in the
committed lockfiles, so `npm ci` could not make `npx --no-install` find them.

This is the missing installer, and it is the ONE entry point every quality tier
calls. Its contract:

  * every tool comes from the lock, never from an argument. Adding a tool is a
    protected-policy change to `.quality/tools.lock.toml`, not an edit here;
  * installation is by DECLARED RECIPE (`install = [...]` in the lock), so what
    a runner executes is reviewable in the same protected file as the pin;
  * after installing, every tool is RE-DETECTED and re-checked against its pin.
    A cache restore is an optimisation and never evidence: `--check` re-verifies
    from scratch, and the install path verifies after itself;
  * the Python environment is hash-locked. `.quality/requirements.lock` pins the
    complete transitive closure by SHA-256 and is installed with
    `--require-hashes --no-deps`, so a substituted artefact is refused by pip
    before it is unpacked;
  * a missing tool is exit 3 — the controller's INFRASTRUCTURE code — carrying
    the exact remediation from the lock. Never a silent skip, never a pass;
  * the result is a BOOTSTRAP MANIFEST with a root digest, so a quality report
    can name the exact tool set that produced it.

usage:
  python3 tools/quality/bootstrap.py --check          # verify only (exit 3 if short)
  python3 tools/quality/bootstrap.py --install        # install what is missing, then verify
  python3 tools/quality/bootstrap.py --plan           # print what --install would run
  python3 tools/quality/bootstrap.py --self-test      # prove a clean runner reaches the gates
  python3 tools/quality/bootstrap.py --relock-python  # re-resolve requirements.lock from .in
"""

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tomllib

REPO = pathlib.Path(__file__).resolve().parents[2]
LOCK = REPO / ".quality" / "tools.lock.toml"
PY_IN = REPO / ".quality" / "requirements.in"
PY_LOCK = REPO / ".quality" / "requirements.lock"
MANIFEST = REPO / "artifacts" / "quality" / "bootstrap-manifest.json"

# R8-P0-04: the Python quality tools live in a REPOSITORY-OWNED virtualenv, not
# in the host interpreter.
#
# Measured on this project's own container: installing the lock into the system
# Python failed with "Cannot uninstall PyYAML 6.0.1, RECORD file not found. The
# package was installed by debian." A distribution-managed interpreter is not a
# surface a hermetic bootstrap may fight over - and a bootstrap whose result
# depends on which packages the base image happened to ship is the opposite of
# what R8-P0-04 asks for. The venv makes the closure in `requirements.lock` the
# WHOLE truth about which Python tools run.
PY_VENV = REPO / ".quality" / ".venv"
PY_VENV_BIN = PY_VENV / ("Scripts" if sys.platform == "win32" else "bin")

# Must match xtask/src/quality/exec.rs::EXIT_CAPABILITY_UNAVAILABLE and the
# controller's own infrastructure exit code.
EXIT_INFRASTRUCTURE = 3

# The sentinel recipe meaning "this tool comes from the hash-locked Python
# environment", which is installed once for all of them.
PYTHON_LOCK_RECIPE = ["python-lock"]

VERSION_RE = re.compile(r"(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?)")


def load_lock() -> dict:
    return tomllib.loads(LOCK.read_text())


def tool_env() -> dict:
    """The environment every detection and every gate command must see.

    The repository's own Python venv comes FIRST on PATH, so `ruff`,
    `basedpyright`, `pytest`, `pip-audit` and friends resolve to the hash-locked
    closure rather than to whatever the base image installed.
    """
    env = dict(os.environ)
    if PY_VENV_BIN.is_dir():
        env["PATH"] = f"{PY_VENV_BIN}{os.pathsep}{env.get('PATH', '')}"
        env["VIRTUAL_ENV"] = str(PY_VENV)
    return env


def detect(entry: dict) -> tuple[bool, str]:
    """Run the lock's own detect command. Returns (ran, raw output)."""
    argv = entry.get("detect") or []
    if not argv:
        return False, "no detect command in the lock"
    cwd = REPO / entry["cwd"] if entry.get("cwd") else REPO
    # R8-P0-04: a tool declared to come from the hash-locked closure must be
    # DETECTED IN THAT CLOSURE, not merely somewhere on PATH.
    #
    # Found by this repository's own control
    # (test_a_substituted_python_artefact_is_refused_by_the_hash_lock): with a
    # forged digest, pip correctly refused to install `ruff` — and the
    # bootstrap then detected the base image's own `ruff 0.15.8`, at the pinned
    # version, and reported the tool ok. A hash lock that can be satisfied by
    # whatever the host happened to ship is not a hash lock.
    if list(entry.get("install") or []) == PYTHON_LOCK_RECIPE and argv[0] not in (
        "python3",
        "python",
    ):
        binary = PY_VENV_BIN / argv[0]
        if not binary.exists():
            return False, (
                f"{argv[0]} is not in the repository's hash-locked Python environment "
                f"({PY_VENV.relative_to(REPO)}). A copy elsewhere on PATH is NOT this tool: it was "
                f"not installed from {PY_LOCK.relative_to(REPO)} and its bytes are unverified."
            )
        argv = [str(binary), *argv[1:]]
    try:
        if argv[0] in ("python3", "python") and PY_VENV_BIN.is_dir():
            argv = [str(PY_VENV_BIN / "python3"), *argv[1:]]
        proc = subprocess.run(
            argv, capture_output=True, text=True, cwd=cwd, timeout=300, env=tool_env()
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return False, f"{error}"
    out = (proc.stdout + proc.stderr).strip()
    return proc.returncode == 0, out


def parse_version(text: str) -> str | None:
    m = VERSION_RE.search(text)
    return m.group(1) if m else None


def semver(v: str) -> tuple:
    return tuple(int(p) for p in re.split(r"[.\-+]", v)[:3] if p.isdigit())


def satisfied(entry: dict, ran: bool, out: str) -> tuple[bool, str]:
    """Does the detected tool satisfy its pin? Returns (ok, detail)."""
    if not ran:
        return False, f"not present or not runnable: {out[:200]}"
    mode = entry.get("mode", "exact")
    if mode == "presence":
        return True, out.splitlines()[0] if out else "present"
    found = parse_version(out)
    if found is None:
        return False, f"no version in {out[:120]!r}"
    want = entry["version"]
    if mode == "exact":
        return (found == want), f"detected {found}, pinned {want}"
    if mode == "minimum":
        return (semver(found) >= semver(want)), f"detected {found}, minimum {want}"
    return False, f"unknown mode {mode!r} in the lock"


def recipes(lock: dict) -> list[tuple[str, dict]]:
    """Every lock entry, toolchains first (a tool may need them)."""
    out = [(f"toolchain.{n}", c) for n, c in (lock.get("toolchain") or {}).items()]
    out += [(f"tool.{n}", c) for n, c in (lock.get("tool") or {}).items()]
    return out


def install_python_lock(dry: bool) -> tuple[bool, str]:
    """The hash-locked Python environment, in one step for every Python tool."""
    pip = PY_VENV_BIN / "pip"
    argv = [
        str(pip),
        "install",
        "--disable-pip-version-check",
        "--require-hashes",
        "--no-deps",
        "-r",
        str(PY_LOCK.relative_to(REPO)),
    ]
    if dry:
        return True, "python3 -m venv .quality/.venv && " + " ".join(argv)
    if not PY_LOCK.is_file():
        return False, f"{PY_LOCK.relative_to(REPO)} is absent; run --relock-python"
    if not pip.is_file():
        made = subprocess.run(
            [sys.executable, "-m", "venv", str(PY_VENV)], capture_output=True, text=True, cwd=REPO
        )
        if made.returncode != 0:
            return (
                False,
                f"could not create {PY_VENV.relative_to(REPO)}:\n{made.stdout + made.stderr}",
            )
    proc = subprocess.run(argv, capture_output=True, text=True, cwd=REPO)
    return proc.returncode == 0, (proc.stdout + proc.stderr)[-2000:]


def run_recipe(entry: dict, dry: bool) -> tuple[bool, str]:
    argv = list(entry["install"])
    cwd = REPO / entry["install_cwd"] if entry.get("install_cwd") else REPO
    if argv == PYTHON_LOCK_RECIPE:
        return install_python_lock(dry)
    if dry:
        where = f" (in {entry['install_cwd']})" if entry.get("install_cwd") else ""
        return True, " ".join(argv) + where
    proc = subprocess.run(argv, capture_output=True, text=True, cwd=cwd, env=tool_env())
    return proc.returncode == 0, (proc.stdout + proc.stderr)[-2000:]


def manifest_root(rows: list[dict]) -> str:
    """A digest over the exact tool identities this bootstrap produced.

    Framed per field so no two different tool sets can produce one digest, and
    recorded in the quality report so a verdict names the tools that reached it.
    """
    h = hashlib.sha256()
    h.update(b"typedb.quality.bootstrap-manifest.v1\x00")
    for row in sorted(rows, key=lambda r: r["id"]):
        for field in (row["id"], row.get("pinned") or "", row.get("detected") or "", row["status"]):
            h.update(len(field).to_bytes(8, "big"))
            h.update(field.encode())
    return h.hexdigest()


def relock_python() -> int:
    """Re-resolve the complete closure from `.quality/requirements.in`.

    The digests are computed from the artefacts pip itself downloads, never
    typed. This needs network access and is an explicit, separate action: a
    lock that regenerates as a side effect of installing is not a lock.
    """
    import shutil
    import tempfile

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="requirements-relock-"))
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "download", "--dest", str(tmp), "-r", str(PY_IN)],
            capture_output=True,
            text=True,
            cwd=REPO,
        )
        if proc.returncode != 0:
            print(
                f"REFUSED: pip download failed:\n{(proc.stdout + proc.stderr)[-2000:]}",
                file=sys.stderr,
            )
            return 1
        rows = []
        for artefact in sorted(tmp.iterdir()):
            digest = hashlib.sha256(artefact.read_bytes()).hexdigest()
            if artefact.name.endswith(".whl"):
                parts = artefact.name.split("-")
                name, version = parts[0].replace("_", "-").lower(), parts[1]
            else:
                m = re.match(r"^(.+)-([0-9][^-]*)\.tar\.gz$", artefact.name)
                if m is None:
                    print(f"REFUSED: cannot parse artefact name {artefact.name}", file=sys.stderr)
                    return 1
                name, version = m.group(1).replace("_", "-").lower(), m.group(2)
            rows.append((name, version, digest))
        head = PY_LOCK.read_text().split("\n\n", 1)[0] if PY_LOCK.is_file() else ""
        body = "\n".join(f"{n}=={v} \\\n    --hash=sha256:{h}" for n, v, h in sorted(rows))
        PY_LOCK.write_text(head + "\n\n" + body + "\n")
        print(f"{PY_LOCK.relative_to(REPO)}: {len(rows)} pinned artefacts")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument(
        "--check", action="store_true", help="verify only; exit 3 if anything is short"
    )
    mode.add_argument("--install", action="store_true", help="install what is missing, then verify")
    mode.add_argument("--plan", action="store_true", help="print the commands --install would run")
    mode.add_argument(
        "--self-test", action="store_true", help="prove a clean runner reaches the gates"
    )
    mode.add_argument(
        "--relock-python", action="store_true", help="re-resolve requirements.lock from .in"
    )
    ap.add_argument("--only", action="append", default=None, help="restrict to these lock ids")
    args = ap.parse_args()

    if args.relock_python:
        return relock_python()

    lock = load_lock()
    entries = recipes(lock)
    if args.only:
        wanted = set(args.only)
        entries = [(i, c) for i, c in entries if i in wanted or i.split(".", 1)[-1] in wanted]

    if args.plan or args.self_test:
        print("bootstrap plan (every command comes from .quality/tools.lock.toml):")
        seen = set()
        for lock_id, entry in entries:
            recipe = entry.get("install")
            if not recipe:
                print(f"  {lock_id:34} NO INSTALL RECIPE — declared as host-provided")
                continue
            ok, shown = run_recipe(entry, dry=True)
            if shown in seen:
                print(f"  {lock_id:34} (covered by an earlier step)")
                continue
            seen.add(shown)
            print(f"  {lock_id:34} {shown}")
        if args.plan:
            return 0

    installed_python = False
    rows: list[dict] = []
    short: list[str] = []
    for lock_id, entry in entries:
        ran, out = detect(entry)
        ok, detail = satisfied(entry, ran, out)
        if not ok and args.install:
            recipe = entry.get("install")
            if recipe:
                if list(recipe) == PYTHON_LOCK_RECIPE and installed_python:
                    pass  # one install serves every Python tool
                else:
                    print(f"  installing {lock_id} ...")
                    done, log = run_recipe(entry, dry=False)
                    installed_python = installed_python or list(recipe) == PYTHON_LOCK_RECIPE
                    if not done:
                        print(f"    install failed:\n{log}", file=sys.stderr)
            # RE-DETECT: an install is not evidence, the detection is
            ran, out = detect(entry)
            ok, detail = satisfied(entry, ran, out)
        rows.append(
            {
                "id": lock_id,
                "pinned": str(entry.get("version") or ""),
                "mode": entry.get("mode", "exact"),
                "detected": (parse_version(out) or "") if ran else "",
                "raw": out.splitlines()[0][:200] if out else "",
                "status": "ok" if ok else ("advisory" if entry.get("advisory") else "MISSING"),
                "advisory": bool(entry.get("advisory")),
                "conditional": bool(entry.get("conditional")),
                "detail": detail,
            }
        )
        if not ok and not entry.get("advisory") and not entry.get("conditional"):
            short.append(
                f"{lock_id}: {detail}\n      remediation: {entry.get('remediation', '<none in the lock>')}"
            )

    root = manifest_root(rows)
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(
        json.dumps(
            {
                "schema": "typedb-quality-bootstrap-manifest-v1",
                "lock": str(LOCK.relative_to(REPO)),
                "python_lock": str(PY_LOCK.relative_to(REPO)),
                "bootstrap_root": root,
                "tools": rows,
            },
            indent=1,
        )
        + "\n"
    )

    ok_count = sum(1 for r in rows if r["status"] == "ok")
    print(f"\nbootstrap: {ok_count}/{len(rows)} tools satisfy their pins; root {root}")
    print(f"manifest: {MANIFEST.relative_to(REPO)}")
    for row in rows:
        if row["status"] != "ok":
            flag = (
                "advisory"
                if row["advisory"]
                else ("conditional" if row["conditional"] else "REQUIRED")
            )
            print(f"  {row['status']:8} {row['id']:34} ({flag}) {row['detail']}")

    if short:
        print(
            f"\nREFUSED: {len(short)} required tool(s) are missing or mismatched. The gates that need "
            f"them cannot run, and a run without them proves nothing (exit {EXIT_INFRASTRUCTURE}):",
            file=sys.stderr,
        )
        for s in short:
            print(f"  - {s}", file=sys.stderr)
        return EXIT_INFRASTRUCTURE
    return 0


if __name__ == "__main__":
    sys.exit(main())
