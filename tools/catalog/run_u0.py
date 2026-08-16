#!/usr/bin/env python3
"""BT-P2 (partial): U0 pristine-baseline runner.

Runs every compiled test executable of the pinned TypeDB workspace under the
Rust parity lane, one executable at a time (libtest's own in-binary
parallelism is upstream behaviour and is preserved), with:

  - no retries (a failure is recorded, never converted to PASS);
  - per-executable timeout (kills the whole process group);
  - serial groups honored by the one-at-a-time execution order;
  - raw stdout/stderr archived per target, normalized JSON results emitted.

Usage: run_u0.py [--filter SUBSTR] [--skip SUBSTR ...] [--out DIR]
"""
import argparse
import json
import os
import pathlib
import signal
import subprocess
import sys
import time

REPO = pathlib.Path(__file__).resolve().parents[2]
TB = REPO / "sources" / "typedb"
TOOLCHAIN = "+1.93.0"
DEFAULT_TIMEOUT = 1800

ENV_BASE = {
    **os.environ,
    "CARGO_INCREMENTAL": "0",
    "CARGO_PROFILE_DEV_DEBUG": "false",
    "CARGO_PROFILE_TEST_DEBUG": "false",
}

# targets that need the assembly archive staged in cwd
ASSEMBLY_TARGETS = {"test_assembly", "test_fail_points", "test_admin_assembly"}
ASSEMBLY_ENV = {"TYPEDB_ASSEMBLY_ARCHIVE": "typedb-all-linux-x86_64.tar.gz"}
# execution order: fast crates first, server-binding suites last
ORDER_LAST = ("test_behaviour", "test_http", "test_assembly", "test_fail_points")


def package_name_from_id(package_id):
    """Package name from a cargo package-id spec (`url[#[name@]version]`).

    Cargo omits the `name@` part of the fragment when the name equals the
    final path segment of the url, so `...typedb/concept#0.0.0` means package
    `concept` while `...storage/tests#test_utils_storage@0.0.0` means package
    `test_utils_storage`. Parsing the fragment alone collapses most workspace
    crates onto the bare version string.
    """
    url, _, frag = package_id.partition("#")
    if "@" in frag:
        return frag.split("@")[0]
    return url.rstrip("/").rsplit("/", 1)[-1]


def discover_executables(packages=None):
    cmd = ["cargo", TOOLCHAIN, "test", "--locked", "--no-run",
           "--message-format", "json"]
    if packages:
        for p in packages:
            cmd += ["-p", p]
    else:
        cmd += ["--workspace"]
    out = subprocess.check_output(
        cmd, cwd=TB, text=True, stderr=subprocess.DEVNULL, env=ENV_BASE)
    execs = []
    for line in out.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") == "compiler-artifact" and msg.get("executable"):
            # only true libtest harnesses: profile.test == true. Plain bin
            # artifacts also carry an executable and must never be run here
            # (running the real server main as a "test" is a false result).
            if not msg.get("profile", {}).get("test"):
                continue
            tgt = msg["target"]
            pkg = package_name_from_id(msg["package_id"])
            manifest = msg["manifest_path"]
            execs.append({"package": pkg, "target": tgt["name"],
                          "kind": tgt["kind"], "executable": msg["executable"],
                          "package_root": str(pathlib.Path(manifest).parent)})
    seen = {}
    for e in execs:
        seen[(e["package"], e["target"])] = e
    ordered = sorted(seen.values(), key=lambda e: (
        any(e["target"].startswith(p) for p in ORDER_LAST), e["package"], e["target"]))
    return ordered


def sha256_file(p):
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def run_one(e, out_dir, timeout, reap=False):
    tid = f"{e['package']}:{e['target']}"
    exe_sha = sha256_file(e["executable"])
    raw = out_dir / f"{e['package']}__{e['target']}.log"
    env = dict(ENV_BASE)
    # short TMPDIR: long paths break SUN_LEN for Unix-domain-socket tests
    tmp = pathlib.Path("/tmp/u0") / f"{abs(hash(tid)) % 100000}"
    tmp.mkdir(parents=True, exist_ok=True)
    env["TMPDIR"] = str(tmp)
    # Bazel test threads get generous stacks; deep-recursion behaviour
    # scenarios (functions/recursion) need more than libtest's default.
    env["RUST_MIN_STACK"] = str(64 * 1024 * 1024)
    # cargo semantics: tests run with cwd = package root
    cwd = pathlib.Path(e.get("package_root") or TB)
    if e["target"] in ASSEMBLY_TARGETS:
        env.update(ASSEMBLY_ENV)
        # isolated working dir per assembly-family test (Bazel gives each
        # test a private runfiles tree; extraction into a shared cwd races)
        iso = out_dir / "iso" / e["target"]
        if iso.exists():
            import shutil as _sh
            _sh.rmtree(iso)
        (iso / "tests" / "assembly").mkdir(parents=True)
        os.link(REPO / "sources" / "assembly-artifacts" / "typedb-all-linux-x86_64.tar.gz",
                iso / "typedb-all-linux-x86_64.tar.gz")
        import shutil as _sh
        _sh.copy2(TB / "tests" / "assembly" / "script.tql",
                  iso / "tests" / "assembly" / "script.tql")
        cwd = iso
    start = time.time()

    def execute(argv):
        with open(raw, "wb") as logf:
            proc = subprocess.Popen(
                argv, cwd=cwd, env=env, stdout=logf, stderr=subprocess.STDOUT,
                start_new_session=True)
            try:
                return proc.wait(timeout=timeout), False
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
                return None, True

    def reap_strays():
        # v14 runner rule: kill and reap complete process trees. Assembly
        # tests spawn `typedb-extracted/typedb server`; a panicking test
        # leaks it, and a zombie server holding the gRPC/diagnostics ports
        # poisons every later assembly run.
        # match only the extracted-server process paths, never this runner's
        # own command line (which carries package names as arguments)
        subprocess.run(["pkill", "-9", "-f", "typedb-extracted/"],
                       capture_output=True)
        time.sleep(0.5)

    argv = [e["executable"], "--format", "terse"]
    if e["target"] in ASSEMBLY_TARGETS or e["target"] == "test_admin_assembly":
        reap_strays()
        # serial group: the tests inside these binaries extract/spawn a
        # server in the shared per-target cwd; Bazel's sandbox equivalent is
        # one test at a time (catalogue serial_group assembly-server)
        argv += ["--test-threads", "1"]
    code, timed_out = execute(argv)
    # Non-libtest harnesses (harness = false) reject libtest flags; detect the
    # argument error and run the harness bare. This is harness detection, not
    # a retry: a libtest run that FAILED its tests is never re-executed.
    if code not in (0, None):
        head = raw.read_text(errors="replace")[:400]
        if "Unrecognized option" in head or "unexpected argument" in head \
                or "error: Found argument" in head:
            code, timed_out = execute([e["executable"]])
    dur = time.time() - start
    text = raw.read_text(errors="replace")
    tail = text[-2000:]
    # parse libtest summary lines: "test result: ok. X passed; Y failed; Z ignored; ..."
    passed = failed = ignored = measured = filtered = 0
    for line in text.splitlines():
        if line.startswith("test result:"):
            import re
            for n, key in re.findall(r"(\d+) (passed|failed|ignored|measured|filtered out)", line):
                n = int(n)
                if key == "passed":
                    passed += n
                elif key == "failed":
                    failed += n
                elif key == "ignored":
                    ignored += n
                elif key == "measured":
                    measured += n
                else:
                    filtered += n
    if e["target"] in ASSEMBLY_TARGETS or e["target"] == "test_admin_assembly":
        reap_strays()
    if reap:
        # free disk: the binary is reproducible from the pinned source +
        # toolchain; its digest is recorded above.
        try:
            os.unlink(e["executable"])
        except OSError:
            pass
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    return {
        "target_id": tid,
        "executable": e["executable"],
        "executable_sha256": exe_sha,
        "exit_code": code,
        "timed_out": timed_out,
        "duration_seconds": round(dur, 2),
        "passed": passed,
        "failed": failed,
        "ignored": ignored,
        "measured": measured,
        "filtered_out": filtered,
        "raw_log": str(raw.relative_to(REPO)) if raw.is_relative_to(REPO) else str(raw),
        "tail": tail if (code != 0 or timed_out) else None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--filter", default=None)
    ap.add_argument("--skip", action="append", default=[])
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--reap", action="store_true",
                    help="delete each test executable after running it")
    ap.add_argument("--package", action="append", default=None,
                    help="restrict cargo compilation/discovery to these packages")
    ap.add_argument("--out", default=str(REPO / "docs" / "evidence" / "G1" / "u0-results"))
    args = ap.parse_args()

    out_dir = pathlib.Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    execs = discover_executables(args.package)
    if args.filter:
        execs = [e for e in execs if args.filter in f"{e['package']}:{e['target']}"]
    execs = [e for e in execs
             if not any(s in f"{e['package']}:{e['target']}" for s in args.skip)]
    print(f"U0: {len(execs)} test executables", flush=True)
    # merge with any prior results in this out dir (latest run per target wins)
    prior = {}
    rf = out_dir / "u0-results.json"
    if rf.exists():
        for r in json.loads(rf.read_text())["results"]:
            prior[r["target_id"]] = r
    results = []
    for i, e in enumerate(execs):
        print(f"[{i+1}/{len(execs)}] {e['package']}:{e['target']} ...",
              end=" ", flush=True)
        r = run_one(e, out_dir, args.timeout, reap=args.reap)
        results.append(r)
        status = ("TIMEOUT" if r["timed_out"]
                  else "OK" if r["exit_code"] == 0 else f"FAIL({r['exit_code']})")
        print(f"{status} {r['passed']}p/{r['failed']}f/{r['ignored']}i "
              f"in {r['duration_seconds']}s", flush=True)
        merged = dict(prior)
        for rr in results:
            merged[rr["target_id"]] = rr
        (out_dir / "u0-results.json").write_text(
            json.dumps({"profile": "U0",
                        "toolchain": "rust 1.93.0 parity lane",
                        "results": sorted(merged.values(),
                                          key=lambda x: x["target_id"])}, indent=1) + "\n")
    total = {
        "executables": len(results),
        "green": sum(1 for r in results if r["exit_code"] == 0),
        "red": sum(1 for r in results if r["exit_code"] not in (0, None)),
        "timeout": sum(1 for r in results if r["timed_out"]),
        "cases_passed": sum(r["passed"] for r in results),
        "cases_failed": sum(r["failed"] for r in results),
        "cases_ignored": sum(r["ignored"] for r in results),
    }
    (out_dir / "u0-summary.json").write_text(json.dumps(total, indent=2) + "\n")
    print(json.dumps(total, indent=2))


if __name__ == "__main__":
    main()
