#!/usr/bin/env python3
"""Check that this machine can run every local lane — before you find out
40 minutes into a build that `protoc` is missing.

Everything checked here is already asserted somewhere in the repo: the
native toolchain set is lock node NATIVE_TOOLCHAIN, the parity compiler is
node RUST_PARITY, the checkouts are what lint_source_lock.py demands. The
doctor just asks the questions in one place, before the lanes do, and says
what to run when an answer is wrong.

    python3 tools/dev/doctor.py            # report, exit 1 if a lane is unrunnable
    python3 tools/dev/doctor.py --quiet    # only problems

Exit codes: 0 = every lane runnable, 1 = something required is missing.
A recorded-version mismatch is a WARN, not a failure: the lock records the
environment the evidence was produced in, and a different patch level is a
fact worth seeing, not a stop sign.
"""
import argparse
import json
import pathlib
import re
import shutil
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
LOCK = REPO / "source-lock" / "source-lock.json"

# lock NATIVE_TOOLCHAIN member -> (executable, version argv, regex capturing version)
NATIVE = {
    "cc": ("gcc", ["gcc", "--version"], r"(\d+\.\d+\.\d+)"),
    "c++": ("g++", ["g++", "--version"], r"(\d+\.\d+\.\d+)"),
    "cmake": ("cmake", ["cmake", "--version"], r"(\d+\.\d+\.\d+)"),
    "protoc": ("protoc", ["protoc", "--version"], r"(\d+\.\d+\.\d+)"),
    "pkg-config": ("pkg-config", ["pkg-config", "--version"], r"(\d+\.\d+)"),
    "node": ("node", ["node", "--version"], r"v?(\d+\.\d+\.\d+)"),
    "python": ("python3", ["python3", "--version"], r"(\d+\.\d+\.\d+)"),
}

# tools with no lock entry that lanes still need
EXTRA = {
    "git": ["git", "--version"],
    "curl": ["curl", "--version"],
    "make": ["make", "--version"],
}

INSTALL_HINT = {
    "protoc": "apt-get install -y protobuf-compiler",
    "cmake": "apt-get install -y cmake",
    "cc": "apt-get install -y build-essential",
    "c++": "apt-get install -y build-essential",
    "make": "apt-get install -y build-essential",
}


def version_of(argv, pattern) -> str | None:
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(pattern, (out.stdout or "") + (out.stderr or ""))
    return m.group(1) if m else None


class Report:
    def __init__(self, quiet: bool):
        self.quiet = quiet
        self.failures = []
        self.warnings = []

    def ok(self, what, detail=""):
        if not self.quiet:
            print(f"  OK    {what:<34} {detail}")

    def warn(self, what, detail):
        self.warnings.append(f"{what}: {detail}")
        print(f"  WARN  {what:<34} {detail}")

    def fail(self, what, detail, fix=None):
        self.failures.append((what, detail, fix))
        print(f"  FAIL  {what:<34} {detail}")


def check_native(rep: Report, lock: dict) -> None:
    recorded = {}
    for n in lock["nodes"]:
        if n["id"] == "NATIVE_TOOLCHAIN":
            recorded = n.get("members", {})
    print("native toolchain (lock node NATIVE_TOOLCHAIN)")
    for member, (exe, argv, pattern) in NATIVE.items():
        if shutil.which(exe) is None:
            rep.fail(member, f"{exe} not on PATH", INSTALL_HINT.get(member))
            continue
        got = version_of(argv, pattern)
        want = recorded.get(member, "")
        want_v = re.search(r"(\d+\.\d+(\.\d+)?)", want)
        if got and want_v and not want_v.group(1).startswith(got) \
                and not got.startswith(want_v.group(1)):
            rep.warn(member, f"{got} (lock recorded {want_v.group(1)})")
        else:
            rep.ok(member, got or "present")
    for name, argv in EXTRA.items():
        if shutil.which(argv[0]) is None:
            rep.fail(name, f"{argv[0]} not on PATH", INSTALL_HINT.get(name))
        else:
            rep.ok(name, version_of(argv, r"(\d+\.\d+(?:\.\d+)?)") or "present")


def check_rust(rep: Report, lock: dict) -> None:
    print("rust toolchains")
    parity = next((n["version"] for n in lock["nodes"] if n["id"] == "RUST_PARITY"), None)
    if shutil.which("rustup") is None:
        rep.fail("rustup", "not on PATH",
                 "curl https://sh.rustup.rs -sSf | sh")
        return
    installed = subprocess.run(["rustup", "toolchain", "list"],
                               capture_output=True, text=True).stdout
    if parity and parity not in installed:
        rep.fail(f"rust {parity} (parity lane)", "not installed",
                 f"rustup toolchain install {parity}")
    else:
        rep.ok(f"rust {parity} (parity lane)", "installed")
    rep.ok("rust stable (tools workspace)",
           "installed" if "stable" in installed else "missing — tools/ lane only")
    # the static lane shells out to the pinned nightly rustfmt
    nightly = re.search(r"RUSTFMT_TOOLCHAIN = \"([^\"]+)\"",
                        (REPO / "tools" / "catalog" / "run_static.py").read_text())
    if nightly:
        if nightly.group(1) in installed:
            rep.ok(f"rustfmt {nightly.group(1)}", "installed")
        else:
            rep.fail(f"rustfmt {nightly.group(1)} (static lane)", "not installed",
                     f"rustup toolchain install {nightly.group(1)} "
                     f"--profile minimal --component rustfmt")


def check_sources(rep: Report) -> None:
    print("pinned sources")
    lint = subprocess.run([sys.executable,
                           str(REPO / "tools" / "source-lock" / "lint_source_lock.py")],
                          capture_output=True, text=True)
    first = (lint.stdout.strip().splitlines() or ["no output"])[0]
    missing = [l for l in lint.stdout.splitlines() if "missing at" in l]
    if missing:
        rep.fail("sources/ materialisation", f"{len(missing)} node(s) missing",
                 "python3 tools/source-lock/materialize_sources.py")
    elif lint.returncode != 0:
        # a lint failure that is not a missing checkout is a real drift signal,
        # but it does not stop a lane from running — surface it, don't block.
        rep.warn("source-lock lint", first + " (see: lint_source_lock.py)")
    else:
        rep.ok("source-lock lint", first)

    archive = REPO / "sources" / "assembly-artifacts" / "typedb-all-linux-x86_64.tar.gz"
    if archive.exists():
        rep.ok("assembly archive", "present (corpus assembly lane runnable)")
    else:
        rep.warn("assembly archive",
                 "absent — build the fork, then python3 tools/catalog/package_assembly.py")


def check_node_deps(rep: Report) -> None:
    print("control-plane")
    if (REPO / "control-plane" / "node_modules").is_dir():
        rep.ok("node_modules", "installed")
    else:
        rep.fail("node_modules", "not installed", "cd control-plane && npm ci")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quiet", action="store_true", help="print only problems")
    args = ap.parse_args()

    lock = json.loads(LOCK.read_text())
    rep = Report(args.quiet)
    check_native(rep, lock)
    check_rust(rep, lock)
    check_sources(rep)
    check_node_deps(rep)

    print()
    if rep.failures:
        print(f"DOCTOR: {len(rep.failures)} problem(s) — lanes are not all runnable")
        for what, detail, fix in rep.failures:
            print(f"  - {what}: {detail}")
            if fix:
                print(f"      fix: {fix}")
        return 1
    print(f"DOCTOR: every local lane is runnable"
          f"{f' ({len(rep.warnings)} warning(s))' if rep.warnings else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
