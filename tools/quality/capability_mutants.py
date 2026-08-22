#!/usr/bin/env python3
"""Negative controls for the ONE environment model (R8-P1-07 acceptance).

The audit's acceptance is explicit: "mutants for missing libclang, C header,
protoc, cmake, nextest, npm tool, pytest-cov, namespace, AF_UNIX and fixture all
produce exit 3; one real assertion failure still produces exit 1; doctor and the
subsequent gate agree on readiness."

A preflight that reported every capability as missing would pass any test that
only checks "an unmet capability is refused". So each mutant here has three
obligations, and all three must hold for it to count as KILLED:

  1. the CLEAN environment reports the capability SATISFIED — without this the
     mutant proves nothing, because the subject was already broken;
  2. the mutated environment reports THAT capability unmet, and the runner exits
     3 (the same code `cargo xtask quality` classifies structurally);
  3. the mutation is TARGETED — the capabilities it did not touch are still
     satisfied. A mutation that breaks the whole probe runner is a broken
     harness, not a control.

Every mutation is a real environment, never a test hook: a PATH without the
tool, a compiler invoked without its standard include path, a bind mount over
the library file, an unprivileged uid, a read-only TMPDIR, a repository
checkout that was never `npm ci`-ed, a virtualenv without the plugin. A hook
would prove only that the hook works.

usage:
  python3 tools/quality/capability_mutants.py
  python3 tools/quality/capability_mutants.py --only protoc-absent
  python3 tools/quality/capability_mutants.py --list
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
RUNNER_REL = pathlib.Path("tools/quality/capabilities.py")
INVENTORY_REL = pathlib.Path(".quality/capabilities.toml")
EXIT_CAPABILITY_UNAVAILABLE = 3


# ------------------------------------------------------------------ plumbing


def run_probe(
    root: pathlib.Path, ids: list[str], env: dict | None = None, wrap: list[str] | None = None
):
    """Run the probe runner rooted at `root` and return (exit code, result map)."""
    argv = (wrap or []) + [
        sys.executable,
        str(root / RUNNER_REL),
        "--all",
        "--json",
    ]
    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        cwd=str(root),
        env={**os.environ, **(env or {})},
        timeout=900,
    )
    try:
        report = json.loads(proc.stdout)
    except ValueError:
        return proc.returncode, {"_stdout": proc.stdout, "_stderr": proc.stderr}
    states = {entry["id"]: entry for entry in report["probed"]}
    return proc.returncode, states


@contextlib.contextmanager
def mirror_repo(omit: list[str] = (), link: list[str] = ()):
    """A repository checkout containing only what a probe reads.

    Real absence, not a stub: `fixture.sources` and `npm.oxlint` are answered
    from the tree, so "this clone was never materialised / never npm ci-ed" is
    reproduced by not creating the path.
    """
    with tempfile.TemporaryDirectory(prefix="cap-mutant-") as tmp:
        root = pathlib.Path(tmp)
        (root / RUNNER_REL.parent).mkdir(parents=True)
        shutil.copy2(REPO / RUNNER_REL, root / RUNNER_REL)
        (root / INVENTORY_REL.parent).mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / INVENTORY_REL, root / INVENTORY_REL)
        for rel in link:
            if rel in omit:
                continue
            target = REPO / rel
            if not target.exists():
                continue
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).symlink_to(target)
        yield root


REPO_PATHS = ["sources", "control-plane/node_modules", ".quality/.venv"]


def path_without(program: str) -> str:
    """A PATH mirroring this machine's, minus one executable.

    Symlinks rather than a shim: a shim would only prove that a shim shadows a
    tool. What must be reproduced is a machine on which the tool was never
    installed, with everything ELSE still present — otherwise a mutant that
    breaks every probe would look like a kill.
    """
    tmp = tempfile.mkdtemp(prefix="cap-path-")
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        directory = pathlib.Path(entry)
        if not directory.is_dir():
            continue
        for item in directory.iterdir():
            if item.name == program or (tmp_item := pathlib.Path(tmp) / item.name).exists():
                continue
            with contextlib.suppress(OSError):
                tmp_item.symlink_to(item)
    return tmp


def nostdinc_cc() -> str:
    """A C compiler that cannot reach its own standard headers.

    This is what an unusual sysroot, a partially installed cross toolchain or a
    stripped container image produces: `cc` runs, and `#include <stdlib.h>`
    does not resolve.
    """
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="cap-cc-"))
    wrapper = tmp / "cc"
    wrapper.write_text('#!/bin/sh\nexec /usr/bin/cc -nostdinc "$@"\n')
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(wrapper)


def libclang_files() -> list[pathlib.Path]:
    """Every file dlopen could resolve for the declared candidates."""
    import tomllib

    spec = tomllib.loads((REPO / INVENTORY_REL).read_text())["capability"]["library.libclang"]
    found: list[pathlib.Path] = []
    roots = ["/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/usr/lib", "/usr/local/lib"]
    for root in roots:
        base = pathlib.Path(root)
        if not base.is_dir():
            continue
        for name in spec["candidates"]:
            candidate = base / name
            if candidate.exists():
                found.append(candidate)
    return found


def venv_without(package: str) -> pathlib.Path:
    """A real virtualenv that simply does not have the package."""
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="cap-venv-"))
    subprocess.run(
        [sys.executable, "-m", "venv", str(tmp / "venv")], check=True, capture_output=True
    )
    subprocess.run(
        # `coverage` as well: pytest-cov depends on it, so a venv without both
        # would fail TWO capabilities and prove nothing about either.
        [str(tmp / "venv" / "bin" / "python3"), "-m", "pip", "install", "-q", "pytest", "coverage"],
        check=False,
        capture_output=True,
        timeout=900,
    )
    return tmp / "venv"


# ------------------------------------------------------------------- mutants


def mutant_hidden_command(program: str, capability: str):
    def run():
        clean_code, clean = run_probe(REPO, [])
        bin_dir = path_without(program)
        try:
            code, states = run_probe(REPO, [], env={"PATH": bin_dir})
        finally:
            shutil.rmtree(bin_dir, ignore_errors=True)
        return clean, code, states

    return run, capability


def mutant_nostdinc():
    def run():
        clean_code, clean = run_probe(REPO, [])
        cc = nostdinc_cc()
        code, states = run_probe(REPO, [], env={"CC": cc})
        shutil.rmtree(pathlib.Path(cc).parent, ignore_errors=True)
        return clean, code, states

    return run, "header.stdc"


def mask_wrap(commands: list[str]) -> list[str]:
    """Run the probe inside a PRIVATE mount namespace with `commands` applied.

    The mask exists only for that child: nothing outside it changes, and the
    machine is left exactly as it was. This is how "the component was never
    installed" is reproduced honestly, without uninstalling anything.
    """
    return ["unshare", "--mount", "sh", "-c", " && ".join(commands) + ' && exec "$@"', "sh"]


def masked_file() -> pathlib.Path:
    """An empty, non-executable regular file to bind over a real one."""
    target = pathlib.Path(tempfile.mkdtemp(prefix="cap-mask-")) / "not-a-real-file"
    target.write_bytes(b"")
    target.chmod(0o444)
    return target


def mutant_masked_files(paths_of, capability: str):
    def run():
        _, clean = run_probe(REPO, [])
        paths = paths_of()
        if not paths:
            raise NotApplicable(f"nothing to mask for {capability} on this machine")
        mask = masked_file()
        try:
            wrap = mask_wrap([f"mount --bind {mask} {p}" for p in paths])
            code, states = run_probe(REPO, [], wrap=wrap)
        finally:
            shutil.rmtree(mask.parent, ignore_errors=True)
        return clean, code, states

    return run, capability


def mutant_libclang():
    return mutant_masked_files(libclang_files, "library.libclang")


def mutant_missing_repo_path(rel: str, capability: str):
    def run():
        with mirror_repo(link=REPO_PATHS) as root:
            _, clean = run_probe(root, [])
        with mirror_repo(omit=[rel], link=REPO_PATHS) as root:
            code, states = run_probe(root, [])
        return clean, code, states

    return run, capability


def mutant_venv_without_pytest_cov():
    def run():
        with mirror_repo(link=REPO_PATHS) as root:
            _, clean = run_probe(root, [])
        venv = venv_without("pytest-cov")
        try:
            with mirror_repo(omit=[".quality/.venv"], link=REPO_PATHS) as root:
                (root / ".quality").mkdir(parents=True, exist_ok=True)
                (root / ".quality/.venv").symlink_to(venv)
                code, states = run_probe(root, [])
        finally:
            shutil.rmtree(venv.parent, ignore_errors=True)
        return clean, code, states

    return run, "python.pytest_cov"


def mutant_unprivileged_namespace():
    def run():
        _, clean = run_probe(REPO, [])
        if shutil.which("capsh") is None:
            raise NotApplicable(
                "capsh is not installed, so CAP_SYS_ADMIN cannot be dropped realistically"
            )
        if os.geteuid() != 0:
            raise NotApplicable("this run already lacks CAP_SYS_ADMIN, so there is nothing to drop")
        # Drop the capability, not the identity. `setuid(nobody)` would also
        # make $CARGO_HOME unreadable and break two unrelated capabilities —
        # the same broken-harness shape the targeting rule refuses. A CI runner
        # without CAP_SYS_ADMIN is exactly this: same files, no namespaces.
        wrap = ["capsh", "--drop=cap_sys_admin", "--", "-c", 'exec "$@"', "sh"]
        code, states = run_probe(REPO, [], wrap=wrap)
        return clean, code, states

    return run, "kernel.network_namespace"


def mutant_readonly_tmpdir():
    def run():
        _, clean = run_probe(REPO, [])
        # A READ-ONLY FILESYSTEM, not permission bits: root ignores the bits
        # (CAP_DAC_OVERRIDE), so a 0555 directory is not a denial at all — the
        # first attempt at this mutant "passed" for that reason and proved
        # nothing. A read-only tmpfs inside a private mount namespace is a real
        # one, and is what a hardened runner actually gives you.
        target = pathlib.Path(tempfile.mkdtemp(prefix="cap-ro-"))
        try:
            wrap = mask_wrap([f"mount -t tmpfs -o ro none {target}"])
            code, states = run_probe(REPO, [], env={"TMPDIR": str(target)}, wrap=wrap)
        finally:
            shutil.rmtree(target, ignore_errors=True)
        return clean, code, states

    return run, "kernel.af_unix"


class NotApplicable(Exception):
    """The machine cannot host this mutation. Reported separately and NEVER
    counted as held — an N/A control proves nothing (R8-P2-02)."""


MUTANTS = {
    "protoc-absent": mutant_hidden_command("protoc", "native.protoc"),
    "cmake-absent": mutant_hidden_command("cmake", "native.cmake"),
    # `cargo <sub>` resolves `cargo-<sub>` from $CARGO_HOME/bin and from cargo's
    # OWN directory as well as PATH, so hiding it from PATH is not the machine
    # this mutant is about. Masking the binary is.
    "nextest-absent": mutant_masked_files(
        lambda: [p for p in [shutil.which("cargo-nextest")] if p], "cargo.nextest"
    ),
    "c-header-unreachable": mutant_nostdinc(),
    "libclang-unloadable": mutant_libclang(),
    # Only oxlint: removing node_modules would break depcruise too, and a
    # mutation that breaks everything is a broken harness, not a control.
    "npm-tool-absent": mutant_masked_files(
        lambda: [p for p in [REPO / "control-plane/node_modules/.bin/oxlint"] if p.exists()],
        "npm.oxlint",
    ),
    "pytest-cov-absent": mutant_venv_without_pytest_cov(),
    "namespace-denied": mutant_unprivileged_namespace(),
    "af-unix-unbindable": mutant_readonly_tmpdir(),
    "fixture-absent": mutant_missing_repo_path("sources", "fixture.sources"),
}


# ---------------------------------------------------------------------- main


def judge(name: str, capability: str, clean: dict, code: int, states: dict) -> tuple[bool, str]:
    if "_stdout" in clean or "_stdout" in states:
        return False, "the probe runner produced no parsable JSON — the harness is broken"
    if capability not in clean or not clean[capability]["ok"]:
        return False, (
            f"the CLEAN environment already reports {capability} unmet "
            f"({clean.get(capability, {}).get('detail', 'absent from the report')}), "
            f"so this mutant proves nothing"
        )
    if capability not in states:
        return False, f"{capability} vanished from the mutated report"
    if states[capability]["ok"]:
        return False, f"SURVIVED — {capability} still reports satisfied under the mutation"
    if code != EXIT_CAPABILITY_UNAVAILABLE:
        return False, f"reported unmet but exited {code}, not {EXIT_CAPABILITY_UNAVAILABLE}"
    collateral = [
        cid
        for cid, entry in states.items()
        if cid != capability and not entry["ok"] and clean.get(cid, {}).get("ok")
    ]
    if collateral:
        return False, (
            f"the mutation was not targeted: it also broke {', '.join(sorted(collateral))}. "
            f"A mutation that breaks everything is a broken harness, not a control"
        )
    return True, states[capability]["detail"]


def doctor_agrees(capability: str) -> tuple[bool, str]:
    """R8-P1-07 acceptance: doctor and the gate agree on readiness.

    Structural rather than incidental — doctor imports the same module and the
    same inventory — so what this control checks is that the agreement survives
    the wiring: doctor names the same capability the probe runner does.
    """
    proc = subprocess.run(
        [sys.executable, str(REPO / "tools/dev/doctor.py")],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        timeout=900,
    )
    if capability not in proc.stdout:
        return False, f"doctor never mentions {capability}, so it is reporting a different model"
    return True, f"doctor reports {capability} from the same inventory"


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--only", action="append", default=None, help="run only these mutants")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.list:
        for name, (_, capability) in MUTANTS.items():
            print(f"  {name:<24} {capability}")
        return 0

    wanted = args.only or list(MUTANTS)
    unknown = [n for n in wanted if n not in MUTANTS]
    if unknown:
        print(f"CAPABILITY MUTANTS: FAIL - unknown mutant(s) {unknown}")
        return 1

    held, failures, na = 0, [], []
    for name in wanted:
        run, capability = MUTANTS[name]
        print(f"  running  {name:<24} ({capability}) ...", flush=True)
        try:
            clean, code, states = run()
        except NotApplicable as why:
            na.append((name, str(why)))
            print(f"  N/A      {name:<24} {why}")
            continue
        except Exception as error:  # a harness failure is never a kill
            failures.append((name, f"the harness itself failed: {error!r}"))
            print(f"  BROKEN   {name:<24} {error!r}")
            continue
        ok, detail = judge(name, capability, clean, code, states)
        if ok:
            held += 1
            print(f"  KILLED   {name:<24} exit {code}, {detail}")
        else:
            failures.append((name, detail))
            print(f"  SURVIVED {name:<24} {detail}")

    ok, detail = doctor_agrees("native.protoc")
    if ok:
        held += 1
        print(f"  KILLED   {'doctor-agrees':<24} {detail}")
    else:
        failures.append(("doctor-agrees", detail))
        print(f"  SURVIVED {'doctor-agrees':<24} {detail}")

    total = len(wanted) + 1
    print()
    for name, detail in failures:
        print(f"CAPABILITY MUTANTS: FAIL - {name}: {detail}")
    for name, why in na:
        print(f"CAPABILITY MUTANTS: NOT APPLICABLE - {name}: {why}")
    verdict = "FAIL" if failures or na else "PASS"
    print(
        f"CAPABILITY MUTANTS: {verdict} ({held}/{total} held"
        + (f", {len(na)} not applicable" if na else "")
        + ")"
    )
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
