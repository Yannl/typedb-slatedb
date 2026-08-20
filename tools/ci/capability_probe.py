#!/usr/bin/env python3
"""R6-CI-01 - ENVIRONMENT-BLOCKED is a distinct non-green state.

The §11 gate matrix ends with a rule that is easy to nod at and hard to
implement: *"No job may use `continue-on-error` for a release predicate.
Environment-BLOCKED is a distinct non-green state requiring a capable runner,
not a pass and not a source failure."*

GitHub Actions offers exactly four job conclusions - success, failure,
skipped, cancelled - so "blocked" has to be built. The two obvious shortcuts
are both wrong:

  * `continue-on-error: true`  -> the job is GREEN. A gate that cannot run
    must never read as a gate that ran.
  * `if: <capable>`            -> the job is SKIPPED, which required-checks
    treat as satisfied. Same false green, one layer down.

The mechanism here instead:

  1. This probe runs FIRST and answers, per capability, whether this runner
     can execute the lane at all. It emits `blocked.json` and sets a step
     output.
  2. The real gate job runs only when the probe says CAPABLE.
  3. A separate `environment-blocked` job runs only when the probe says
     BLOCKED, and FAILS with exit code 75 (EX_TEMPFAIL) after printing a
     `::error title=ENVIRONMENT-BLOCKED::` annotation and uploading
     `blocked.json`.

So the run is RED - never green, never silently skipped - and the redness is
classified: a distinct job name, a distinct exit code, and a machine-readable
artifact naming the missing capability and the runner it needs. A source
failure looks nothing like it.

Usage
-----
    capability_probe.py --require docker --require disk:40
    capability_probe.py --require rustfs --json --out blocked.json
    capability_probe.py --require docker --gate    # exit 75 + annotation
    capability_probe.py --list                     # everything it can see
    capability_probe.py --self-test

Exit codes: 0 capable, 75 BLOCKED (with --gate), 78 BLOCKED (without --gate,
for scripting), 2 usage.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

EX_BLOCKED_GATE = 75  # EX_TEMPFAIL: the environment, not the source, is at fault
EX_BLOCKED_QUERY = 78  # EX_CONFIG: same verdict, non-gating call sites
REPO_ROOT = Path(__file__).resolve().parents[2]


def _which(name: str) -> str | None:
    return shutil.which(name)


def probe_docker() -> dict:
    exe = _which("docker")
    if exe is None:
        return {"available": False, "detail": "docker is not on PATH"}
    try:
        proc = subprocess.run(
            [exe, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "detail": f"docker present but not usable: {exc}"}
    if proc.returncode != 0:
        return {
            "available": False,
            "detail": f"docker daemon unreachable: {proc.stderr.strip()[:200]}",
        }
    return {"available": True, "detail": f"docker server {proc.stdout.strip()}"}


def probe_proc_visibility() -> dict:
    """R6-LOCAL-02: the supervisor authenticates children via /proc start ticks."""
    try:
        stat = Path(f"/proc/{os.getpid()}/stat").read_text(encoding="utf-8")
    except OSError as exc:
        return {"available": False, "detail": f"/proc/<pid>/stat unreadable: {exc}"}
    if len(stat.split()) < 22:
        return {
            "available": False,
            "detail": "/proc/<pid>/stat is truncated; start-tick authentication impossible",
        }
    return {"available": True, "detail": "/proc/<pid>/stat exposes start ticks"}


def probe_network_egress() -> dict:
    try:
        with socket.create_connection(("registry.npmjs.org", 443), timeout=10):
            return {"available": True, "detail": "TCP 443 to registry.npmjs.org succeeded"}
    except OSError as exc:
        return {"available": False, "detail": f"no egress to registry.npmjs.org:443 ({exc})"}


def probe_disk(min_gb: float) -> dict:
    usage = shutil.disk_usage(REPO_ROOT)
    free_gb = usage.free / (1024**3)
    return {
        "available": free_gb >= min_gb,
        "detail": f"{free_gb:.1f} GiB free at {REPO_ROOT} (need {min_gb:g})",
        "value_gb": round(free_gb, 1),
    }


def probe_mem(min_gb: float) -> dict:
    total_kb = None
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                total_kb = int(line.split()[1])
                break
    except OSError:
        pass
    if total_kb is None:
        return {"available": False, "detail": "cannot read /proc/meminfo"}
    total_gb = total_kb / (1024**2)
    return {
        "available": total_gb >= min_gb,
        "detail": f"{total_gb:.1f} GiB RAM (need {min_gb:g})",
        "value_gb": round(total_gb, 1),
    }


def probe_locked_binary(node: str, env_var: str) -> dict:
    """A source-locked provider binary (RustFS / MinIO) must be materialised."""
    override = os.environ.get(env_var)
    if override and Path(override).exists():
        return {"available": True, "detail": f"{env_var}={override}"}
    candidate = REPO_ROOT / "sources" / node
    if candidate.exists() and any(candidate.iterdir()):
        return {"available": True, "detail": f"materialised at sources/{node}"}
    return {
        "available": False,
        "detail": f"sources/{node} is not materialised and {env_var} is unset; "
        f"run `python3 tools/source-lock/materialize_sources.py` on a runner with egress",
    }


def probe_toolchain(name: str) -> dict:
    exe = _which(name)
    return {
        "available": exe is not None,
        "detail": f"{name} at {exe}" if exe else f"{name} is not on PATH",
    }


PROBES = {
    "docker": (probe_docker, "Docker daemon (real Cloudflare Container lane, CF-02)"),
    "proc": (
        probe_proc_visibility,
        "/proc start-tick visibility (supervisor child authentication)",
    ),
    "egress": (probe_network_egress, "outbound HTTPS to the package registries"),
    "rustfs": (lambda: probe_locked_binary("rustfs", "RUSTFS_BIN"), "source-locked RustFS binary"),
    "minio": (
        lambda: probe_locked_binary("minio", "MINIO_BIN"),
        "source-locked MinIO comparator binary",
    ),
    "cargo": (lambda: probe_toolchain("cargo"), "Rust toolchain"),
    "node": (lambda: probe_toolchain("node"), "Node runtime"),
    "npm": (lambda: probe_toolchain("npm"), "npm"),
    "git": (lambda: probe_toolchain("git"), "git"),
}


def run_probe(spec: str) -> tuple[str, dict]:
    """`docker`, or a parameterised `disk:40` / `mem:8`."""
    if ":" in spec:
        name, _, arg = spec.partition(":")
        if name == "disk":
            return spec, {
                **probe_disk(float(arg)),
                "capability": spec,
                "description": f"at least {arg} GiB free disk",
            }
        if name == "mem":
            return spec, {
                **probe_mem(float(arg)),
                "capability": spec,
                "description": f"at least {arg} GiB RAM",
            }
        raise SystemExit(f"unknown parameterised capability {name!r} (known: disk, mem)")
    if spec not in PROBES:
        raise SystemExit(
            f"unknown capability {spec!r} (known: {', '.join(sorted(PROBES))}, disk:N, mem:N)"
        )
    fn, description = PROBES[spec]
    return spec, {**fn(), "capability": spec, "description": description}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--require", action="append", default=[], metavar="CAP")
    ap.add_argument("--lane", default=os.environ.get("GITHUB_JOB", "unnamed-lane"))
    ap.add_argument("--runner-hint", default="a runner with the capability above")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="write the verdict document here (blocked.json)")
    ap.add_argument(
        "--gate", action="store_true", help="exit 75 with a GitHub error annotation when BLOCKED"
    )
    ap.add_argument(
        "--github-output",
        action="store_true",
        help="also append blocked=true|false to $GITHUB_OUTPUT",
    )
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    specs = args.require or (sorted(PROBES) if args.list else [])
    if not specs:
        ap.error("nothing to probe: pass --require CAP (repeatable) or --list")

    results = {}
    for spec in specs:
        name, result = run_probe(spec)
        results[name] = result

    missing = [n for n, r in results.items() if not r["available"]]
    verdict = {
        "schema": "typedb-r2/environment-capability@1",
        "lane": args.lane,
        "outcome": "ENVIRONMENT_BLOCKED" if missing else "CAPABLE",
        "missing": missing,
        "needs_runner": args.runner_hint if missing else None,
        "probes": results,
        "note": (
            "ENVIRONMENT_BLOCKED means this runner cannot execute the lane. It is NOT a pass "
            "(the gate did not run) and NOT a source failure (nothing in the repository is wrong). "
            "The lane must be re-run on a capable runner before any release predicate depending on "
            "it may be considered satisfied."
        ),
    }
    if args.out:
        Path(args.out).write_text(json.dumps(verdict, indent=2) + "\n", encoding="utf-8")
    if args.github_output and os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
            fh.write(f"blocked={'true' if missing else 'false'}\n")
            fh.write(f"missing={','.join(missing)}\n")

    if args.json:
        print(json.dumps(verdict, indent=2))
    else:
        for name, r in results.items():
            print(f"  {'CAPABLE' if r['available'] else 'BLOCKED'}  {name}: {r['detail']}")
        print(f"\n{verdict['outcome']}" + (f" - missing: {', '.join(missing)}" if missing else ""))

    if not missing:
        return 0
    if args.gate:
        print(
            f"::error title=ENVIRONMENT-BLOCKED::lane '{args.lane}' cannot run here: missing "
            f"{', '.join(missing)}. This is NOT a pass and NOT a source failure - re-run on "
            f"{args.runner_hint}. Details in blocked.json.",
            file=sys.stderr,
        )
        return EX_BLOCKED_GATE
    return EX_BLOCKED_QUERY


def self_test() -> int:
    """Behavioral controls over the classification itself."""
    failures = 0
    cases = [
        ("a capability that is certainly present classifies CAPABLE", ["git"], None),
        ("an impossible disk requirement classifies BLOCKED", ["disk:999999"], "disk:999999"),
        ("an impossible memory requirement classifies BLOCKED", ["mem:999999"], "mem:999999"),
    ]
    for name, specs, expect_missing in cases:
        results = dict(run_probe(s) for s in specs)
        missing = [n for n, r in results.items() if not r["available"]]
        ok = (missing == []) if expect_missing is None else (missing == [expect_missing])
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")
        if not ok:
            print(f"       missing={missing}, results={results}")
            failures += 1

    # The gate's exit code must be the BLOCKED code, and must differ from both
    # success (0) and the generic failure code a source error would produce (1).
    proc = subprocess.run(
        [
            sys.executable,
            str(Path(__file__)),
            "--require",
            "disk:999999",
            "--gate",
            "--lane",
            "selftest",
        ],
        capture_output=True,
        text=True,
    )
    ok = proc.returncode == EX_BLOCKED_GATE and "ENVIRONMENT-BLOCKED" in proc.stderr
    print(
        f"  {'ok  ' if ok else 'FAIL'} the gate exits {EX_BLOCKED_GATE} with a classified annotation (got {proc.returncode})"
    )
    if not ok:
        failures += 1
    ok = EX_BLOCKED_GATE not in (0, 1)
    print(
        f"  {'ok  ' if ok else 'FAIL'} BLOCKED is distinguishable from success (0) and source failure (1)"
    )
    if not ok:
        failures += 1

    proc = subprocess.run(
        [sys.executable, str(Path(__file__)), "--require", "git", "--gate", "--lane", "selftest"],
        capture_output=True,
        text=True,
    )
    ok = proc.returncode == 0
    print(f"  {'ok  ' if ok else 'FAIL'} a capable environment exits 0 (got {proc.returncode})")
    if not ok:
        failures += 1

    print()
    if failures:
        print(f"capability-probe self-test: {failures} case(s) FAILED")
        return 1
    print("capability-probe self-test: BLOCKED is a distinct, classified, non-green outcome")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
