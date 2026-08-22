#!/usr/bin/env python3
"""Check that this machine can run every local lane — before you find out
40 minutes into a build that `protoc` is missing.

R8-P1-07: THERE IS ONE ENVIRONMENT MODEL. The audited doctor carried its own
list of native tools and its own probes, and checked a different subset from
the one `cargo xtask quality` requires. Two lists can disagree, and a doctor
that reports "every local lane is runnable" moments before a gate refuses for a
missing component is worse than no doctor at all.

So the environment half of this report is not written here. It is
`.quality/capabilities.toml`, probed by `tools/quality/capabilities.py` — the
same declarations and the same probes the controller consults before it invokes
anything. What remains here is what is genuinely doctor-specific: the rust
toolchains the lanes pin, the source-lock materialisation, and the recorded
versions the evidence was produced against.

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

sys.path.insert(0, str(REPO / "tools" / "quality"))
import capabilities  # noqa: E402


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


def check_capabilities(rep: Report, lock: dict) -> None:
    """The controller's own environment model, reported here verbatim.

    Every entry is probed by `tools/quality/capabilities.py`, which is what
    `cargo xtask quality` runs as its preflight. Agreement between doctor and
    the gate is therefore structural rather than a matter of keeping two lists
    in step.
    """
    print("environment (.quality/capabilities.toml — the controller's own model)")
    try:
        inventory = capabilities.load()
    except capabilities.InventoryError as error:
        rep.fail(
            "capability inventory",
            str(error),
            "python3 tools/quality/capabilities.py --self-test",
        )
        return

    recorded = {}
    for node in lock["nodes"]:
        if node["id"] == "NATIVE_TOOLCHAIN":
            recorded = node.get("members", {})

    for result in capabilities.probe_many(inventory, list(inventory["capability"])):
        spec = inventory["capability"][result.id]
        if not result.ok:
            rep.fail(result.id, result.detail, spec.get("remediation"))
            continue
        member = spec.get("lock_member")
        note = version_note(spec, recorded.get(member, "")) if member else None
        if note:
            rep.warn(result.id, note)
        else:
            rep.ok(result.id, result.detail)


def version_note(spec: dict, want: str) -> str | None:
    """A recorded-version difference, or None. The lock records the environment
    the sealed evidence was produced in; a different patch level is a fact worth
    printing, not a reason to stop a lane."""
    argv, pattern = spec.get("version_argv"), spec.get("version_pattern")
    if not (argv and pattern and want):
        return None
    got = version_of(argv, pattern)
    want_v = re.search(r"(\d+\.\d+(\.\d+)?)", want)
    if not (got and want_v):
        return None
    if want_v.group(1).startswith(got) or got.startswith(want_v.group(1)):
        return None
    return f"{got} (source-lock recorded {want_v.group(1)})"


def check_rust(rep: Report, lock: dict) -> None:
    print("rust toolchains")
    parity = next((n["version"] for n in lock["nodes"] if n["id"] == "RUST_PARITY"), None)
    if shutil.which("rustup") is None:
        rep.fail("rustup", "not on PATH", "curl https://sh.rustup.rs -sSf | sh")
        return
    installed = subprocess.run(
        ["rustup", "toolchain", "list"], capture_output=True, text=True
    ).stdout
    if parity and parity not in installed:
        rep.fail(
            f"rust {parity} (parity lane)", "not installed", f"rustup toolchain install {parity}"
        )
    else:
        rep.ok(f"rust {parity} (parity lane)", "installed")
    if "stable" in installed:
        rep.ok("rust stable (tools workspace)", "installed")
    else:
        rep.fail(
            "rust stable (tools workspace)", "not installed", "rustup toolchain install stable"
        )
    # the static lane shells out to the pinned nightly rustfmt. IMPORT the
    # pin rather than regex-scraping run_static's source: a constant rename
    # made the scrape miss silently and doctor skipped the check entirely.
    sys.path.insert(0, str(REPO / "tools" / "catalog"))
    from run_static import RUSTFMT_TOOLCHAIN  # noqa: E402

    if RUSTFMT_TOOLCHAIN in installed:
        rep.ok(f"rustfmt {RUSTFMT_TOOLCHAIN}", "installed")
    else:
        rep.fail(
            f"rustfmt {RUSTFMT_TOOLCHAIN} (static lane)",
            "not installed",
            f"rustup toolchain install {RUSTFMT_TOOLCHAIN} --profile minimal --component rustfmt",
        )


def check_sources(rep: Report) -> None:
    print("pinned sources")
    lint = subprocess.run(
        [sys.executable, str(REPO / "tools" / "source-lock" / "lint_source_lock.py")],
        capture_output=True,
        text=True,
    )
    first = (lint.stdout.strip().splitlines() or ["no output"])[0]
    missing = [line for line in lint.stdout.splitlines() if "missing at" in line]
    if missing:
        rep.fail(
            "sources/ materialisation",
            f"{len(missing)} node(s) missing",
            "python3 tools/source-lock/materialize_sources.py",
        )
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
        rep.warn(
            "assembly archive",
            "absent — build the fork, then python3 tools/catalog/package_assembly.py",
        )


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--quiet", action="store_true", help="print only problems")
    args = ap.parse_args()

    lock = json.loads(LOCK.read_text())
    rep = Report(args.quiet)
    check_capabilities(rep, lock)
    check_rust(rep, lock)
    check_sources(rep)

    print()
    if rep.failures:
        print(f"DOCTOR: {len(rep.failures)} problem(s) — lanes are not all runnable")
        for what, detail, fix in rep.failures:
            print(f"  - {what}: {detail}")
            if fix:
                print(f"      fix: {fix}")
        return 1
    print(
        f"DOCTOR: every local lane is runnable"
        f"{f' ({len(rep.warnings)} warning(s))' if rep.warnings else ''}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
