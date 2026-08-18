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
import hashlib
import pathlib
import shutil
import signal
import subprocess
import sys
import time

REPO = pathlib.Path(__file__).resolve().parents[2]
TB = REPO / "sources" / "typedb"
TOOLCHAIN = "+1.93.0"
DEFAULT_TIMEOUT = 1800
CATALOG = REPO / "docs" / "evidence" / "G1" / "upstream-test-catalog.json"

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import common  # noqa: E402
import verdict as verdict_policy  # noqa: E402
from common import package_name_from_id, sha256_file  # noqa: E402

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


def executed_toolchain():
    """The toolchain string must be MEASURED, never asserted.

    The manifest used to hardcode "rust 1.93.0 parity lane" whatever compiler
    actually produced the binaries, so a run made on a different rustc filed
    itself under the pinned lane's name. That is precisely the class of claim
    this project is not allowed to make.
    """
    out = subprocess.run(["cargo", TOOLCHAIN, "--version"],
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"toolchain {TOOLCHAIN} is not installed: {out.stderr.strip()}")
    rustc = subprocess.run(["rustc", TOOLCHAIN, "--version"],
                           capture_output=True, text=True).stdout.strip()
    return {"cargo": out.stdout.strip(), "rustc": rustc,
            "requested": TOOLCHAIN.lstrip("+")}


def executed_tree_identity():
    """What was actually built, not what the outer repository says it is.

    `sources/typedb` is the PINNED checkout with the fork staged on top of it
    (tools/fork/stage.py). The outer-repo commit alone therefore does not
    identify the executed tree: two different fork states stage into the same
    upstream revision. Record the checkout revision, whether it is dirty, and
    a digest over the staged working tree so a result row names the bytes
    that produced it.
    """
    def git(*a):
        return subprocess.run(["git", "-C", str(TB), *a],
                              capture_output=True, text=True).stdout.strip()
    status = subprocess.run(["git", "-C", str(TB), "status", "--porcelain"],
                            capture_output=True, text=True).stdout
    h = hashlib.sha256()
    # `git status --porcelain` lists exactly the staged-fork delta against the
    # pinned revision; hashing the delta's contents (not just its names) makes
    # the identity sensitive to a silent edit of an already-staged file.
    for line in sorted(status.splitlines()):
        rel = line[3:].strip().strip('"')
        h.update(line.encode() + b"\0")
        f = TB / rel
        if f.is_file():
            h.update(f.read_bytes())
    return {
        "checkout_revision": git("rev-parse", "HEAD"),
        "dirty": bool(status.strip()),
        "staged_delta_files": len([l for l in status.splitlines() if l.strip()]),
        "staged_delta_sha256": h.hexdigest(),
    }


def required_executable_targets():
    """The shared denominator join (common.required_executable_targets),
    fronted by the missing-catalogue case this runner tolerates."""
    if not CATALOG.exists():
        return None, None, {}
    return common.required_executable_targets(json.loads(CATALOG.read_text()))


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
            shutil.rmtree(iso)
        (iso / "tests" / "assembly").mkdir(parents=True)
        os.link(REPO / "sources" / "assembly-artifacts" / "typedb-all-linux-x86_64.tar.gz",
                iso / "typedb-all-linux-x86_64.tar.gz")
        shutil.copy2(TB / "tests" / "assembly" / "script.tql",
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
    if e["target"] in ASSEMBLY_TARGETS:
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
        if common.is_non_libtest_harness_error(head):
            code, timed_out = execute([e["executable"]])
    dur = time.time() - start
    text = raw.read_text(errors="replace")
    tail = text[-2000:]
    # parse libtest summary lines with the SHARED parser (common.py): the
    # bundle verifier re-derives these counts from the archived log with the
    # same implementation, so a later edit of either side is a contradiction
    counts = common.parse_libtest_counts(text)
    # bind the log bytes to this row NOW, before anything downstream can
    # touch them - a row whose hash no longer matches its log is red
    log_sha = sha256_file(raw)
    if e["target"] in ASSEMBLY_TARGETS:
        reap_strays()
    if reap:
        # free disk: the binary is reproducible from the pinned source +
        # toolchain; its digest is recorded above.
        try:
            os.unlink(e["executable"])
        except OSError:
            pass
        shutil.rmtree(tmp, ignore_errors=True)
    return {
        "target_id": tid,
        "executable": e["executable"],
        "executable_sha256": exe_sha,
        "exit_code": code,
        "timed_out": timed_out,
        "duration_seconds": round(dur, 2),
        "passed": counts["passed"],
        "failed": counts["failed"],
        "ignored": counts["ignored"],
        "measured": counts["measured"],
        "filtered_out": counts["filtered_out"],
        "raw_log": str(raw.relative_to(REPO)) if raw.is_relative_to(REPO) else str(raw),
        "log_sha256": log_sha,
        "tail": tail if (code != 0 or timed_out) else None,
    }


def ensure_behaviour_fixture():
    """Bazel-equivalent runfiles: behaviour suites read Cucumber features via
    the literal path `bazel-typedb/external/typedb_behaviour+/...` relative to
    the workspace root (the convenience-symlink layout Bazel would create).
    The catalogue records this as fixture:typedb-behaviour with exactly that
    destination; upstream's .gitignore covers `bazel-*`, so the link never
    dirties the pinned checkout. Without it every behaviour-driven target
    fails in ~2s with '0 features / 1 parsing error' — a false red.

    Returns True when the fixture is usable. When it is not, the caller
    decides: a run that selected behaviour-driven targets must stop (running
    them would archive false reds), while a run that selected none may
    proceed — an environment with only the storage checkout materialised can
    still run `--package storage`.
    """
    behaviour = REPO / "sources" / "typedb-behaviour"
    # Upstream path inconsistencies (pinned revision) — consume-only
    # (ADR-0008) means the fixture serves EVERY spelling rather than editing
    # upstream; each missing link fails its exact tests with '0 features /
    # 1 parsing error', a false red:
    #  - `external/typedb_behaviour+`: the canonical spelling (45 tests);
    #  - `external/typedb_behaviour` (no `+`): query/language/given.rs only;
    #  - `external/typedb_behaviour++` (double): query/language/variables.rs;
    #  - `sources/typedb_behaviour+` NEXT TO the checkout:
    #    concept/migration/{migration,data_validation}.rs carry no
    #    #[cfg(not(feature="bazel"))] fallback at all, so under cargo their
    #    bazel-sibling path `../typedb_behaviour+/...` resolves against the
    #    package root's parent — the sources/ directory.
    links = [
        TB / "bazel-typedb" / "external" / "typedb_behaviour+",
        TB / "bazel-typedb" / "external" / "typedb_behaviour",
        TB / "bazel-typedb" / "external" / "typedb_behaviour++",
        REPO / "sources" / "typedb_behaviour+",
    ]
    usable = True
    for link in links:
        probe = link / "connection" / "database.feature"
        if probe.exists():
            continue  # symlink or a real copy — either serves the features
        if not behaviour.is_dir():
            return False
        link.parent.mkdir(parents=True, exist_ok=True)
        if link.is_symlink():
            link.unlink()  # dangling or wrong target
        elif link.exists():
            # a real dir/file that does NOT serve the features: refuse to guess
            sys.exit(f"{link} exists but has no features under it - "
                     f"remove it (the runner will recreate the symlink)")
        os.symlink(os.path.relpath(behaviour, link.parent), link)
        usable = usable and probe.exists()
    return usable


def needs_behaviour_fixture(execs):
    """Targets whose sources read Cucumber features via the fixture path.

    Every such test lives either in the root package (typedb_server_bin's
    test_http_* / test_behaviour_* suites) or under tests/behaviour/*;
    membership by package root is a conservative superset of the exact set.
    """
    tb = str(TB)
    behaviour_prefix = str(TB / "tests" / "behaviour")
    return [e for e in execs
            if str(e.get("package_root", "")) == tb  # root pkg exactly, not the whole workspace
            or str(e.get("package_root", "")).startswith(behaviour_prefix)]


def reverdict(out_dir, fresh=False):
    """Recompute a run's verdict from its immutable results.

    A verdict is a function of (results, policy, denominator). When the policy
    or the catalogue is repaired, the honest move is to re-derive the verdict
    over the SAME archived rows - not to re-run a two-hour corpus, and not to
    leave a verdict standing that was computed against a denominator now known
    to be wrong. The results file, the logs, and the COMPLETE marker are never
    touched: a re-reader verifies a sealed archive, it does not reseal it.
    E-P0-06/10: the rows are no longer trusted - verify_bundle reopens,
    re-hashes, and REPARSES every log, and recomputes the bundle root against
    the sidecar manifest and any root the COMPLETE marker binds.

    `fresh` (--re-evaluate): write a NEW verdict-<timestamp>.json instead of
    rewriting verdict.json, so nothing that already exists changes at all.
    """
    results_file = out_dir / "u0-results.json"
    if not results_file.exists():
        sys.exit(f"no results at {results_file}")
    data = json.loads(results_file.read_text())
    results = data["results"]
    ledger, anomalies = verdict_policy.load_ledger()
    required, case_bearing, excluded = required_executable_targets()
    anomalies += verdict_policy.classify_rows(results, ledger,
                                              expected_case_bearing=case_bearing)
    if required is not None:
        anomalies += verdict_policy.denominator_anomalies(results, required, excluded)
    bundle_anoms, warnings, bundle_root = verdict_policy.verify_bundle(
        out_dir, results, ledger, file_profile=data.get("profile"))
    anomalies += bundle_anoms
    observation = verdict_policy.compute_observation(results)
    ledgered = sum(1 for r in results if r.get("target_id") in ledger)
    fname = ("verdict.json" if not fresh else
             f"verdict-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json")
    rc = verdict_policy.verdict_exit_code(
        anomalies, True, out_dir,
        observation=observation, warnings=warnings, bundle_root=bundle_root,
        verdict_filename=fname, write_complete=False,
        extra={"producer": ("tools/catalog/run_u0.py --re-evaluate" if fresh
                            else "tools/catalog/run_u0.py --verdict-only"),
               # E-04: pin the policy inputs so a later ledger/plan edit is a
               # detectable mismatch, never a silent reclassification
               "policy_roots": verdict_policy.compute_policy_roots(),
               "re_derived_from": (str(results_file.relative_to(REPO))
                                   if results_file.is_relative_to(REPO) else str(results_file)),
               "denominator_checked": required is not None,
               "executables": len(results)})
    for a in anomalies:
        print(f"ANOMALY: {a}", file=sys.stderr)
    for w in warnings:
        print(f"WARNING: {w}", file=sys.stderr)
    print(f"BUNDLE ROOT: {bundle_root}", file=sys.stderr)
    print(verdict_policy.human_line(observation, rc == 0, ledgered)
          + f"; {len(anomalies)} anomaly/anomalies, re-derived over "
          f"{len(results)} archived row(s)", file=sys.stderr)
    return rc


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
    ap.add_argument("--verdict-only", action="store_true",
                    help="re-derive the verdict from an existing results file without "
                         "re-running anything (use after a catalogue or policy repair)")
    ap.add_argument("--re-evaluate", action="store_true",
                    help="like --verdict-only, but write a NEW verdict-<timestamp>.json "
                         "and touch NOTHING that already exists (the only way to derive "
                         "a fresh verdict over a sealed archive without altering it)")
    args = ap.parse_args()

    if args.verdict_only or args.re_evaluate:
        return reverdict(pathlib.Path(args.out).resolve(), fresh=args.re_evaluate)

    out_dir = pathlib.Path(args.out).resolve()
    # A dir carrying COMPLETE is a SEALED archive: its marker binds a bundle
    # root over exact bytes. Writing new rows or logs into it would silently
    # retire the evidence the seal vouches for, so the live path refuses -
    # there is no override flag, and the refusal comes BEFORE any toolchain
    # or tree probing so nothing else can mask it. Re-derive with
    # --verdict-only/--re-evaluate, or run into a fresh --out.
    if (out_dir / "COMPLETE").exists():
        sys.exit(f"{out_dir} already contains a COMPLETE marker - it is a sealed "
                 f"evidence bundle and the live runner will not write into it. "
                 f"Use a fresh --out for a new run, or --verdict-only / "
                 f"--re-evaluate to re-derive its verdict without touching it.")

    # What this run actually exercised. The output directory name used to be
    # the only record of the profile, which makes a misfiled run
    # indistinguishable from a real one; the archive digest matters for the
    # same reason (assembly tests run whatever binary is packaged there).
    # Stamped into EVERY ROW this run produces — never onto merged prior rows,
    # whose provenance is their own (a merged results file may mix runs made
    # under different archives or commits; per-row stamping keeps each row
    # telling the truth about itself).
    profile = os.environ.get("TYPEDB_STORAGE_PROFILE") or "U0/U1 (unset: RocksDB oracle)"
    archive = REPO / "sources" / "assembly-artifacts" / "typedb-all-linux-x86_64.tar.gz"
    tree = executed_tree_identity()
    run_manifest = {
        "profile": profile,
        "toolchain": executed_toolchain(),
        "storage_profile_env": os.environ.get("TYPEDB_STORAGE_PROFILE"),
        "assembly_archive_sha256": sha256_file(archive) if archive.exists() else None,
        "repo_commit": subprocess.run(
            ["git", "-C", str(REPO), "rev-parse", "HEAD"],
            capture_output=True, text=True).stdout.strip(),
        "repo_dirty": bool(subprocess.run(
            ["git", "-C", str(REPO), "status", "--porcelain"],
            capture_output=True, text=True).stdout.strip()),
        "executed_tree": tree,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    execs = discover_executables(args.package)
    if args.filter:
        execs = [e for e in execs if args.filter in f"{e['package']}:{e['target']}"]
    execs = [e for e in execs
             if not any(s in f"{e['package']}:{e['target']}" for s in args.skip)]
    if not ensure_behaviour_fixture():
        affected = needs_behaviour_fixture(execs)
        if affected:
            sys.exit(
                f"sources/typedb-behaviour missing and {len(affected)} selected "
                f"target(s) read Cucumber features through it "
                f"(e.g. {affected[0]['package']}:{affected[0]['target']}) - "
                f"running them would archive false reds. "
                f"Run tools/source-lock/materialize_sources.py first.")
        print("note: behaviour fixture unavailable; no selected target needs it",
              flush=True)
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
        r["run"] = run_manifest  # provenance travels with the row it belongs to
        results.append(r)
        status = ("TIMEOUT" if r["timed_out"]
                  else "OK" if r["exit_code"] == 0 else f"FAIL({r['exit_code']})")
        print(f"{status} {r['passed']}p/{r['failed']}f/{r['ignored']}i "
              f"in {r['duration_seconds']}s", flush=True)
        merged = dict(prior)
        for rr in results:
            merged[rr["target_id"]] = rr
        (out_dir / "u0-results.json").write_text(
            json.dumps({"profile": profile,
                        "toolchain": run_manifest["toolchain"],
                        "last_write_run": run_manifest,
                        "results": sorted(merged.values(),
                                          key=lambda x: x["target_id"])}, indent=1) + "\n")
    total = {
        **run_manifest,
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

    # ---- terminal verdict (Q-30) -------------------------------------
    # Until now this producer archived red rows and exited zero, so a failed
    # corpus was indistinguishable from a passed one to anything that reads
    # process results. The verdict below is the only exit path.
    ledger, anomalies = verdict_policy.load_ledger()
    required, case_bearing, excluded = required_executable_targets()
    selection_complete = not (args.filter or args.skip or args.package)
    anomalies += verdict_policy.classify_rows(
        results, ledger,
        expected_case_bearing=case_bearing if selection_complete else None)
    denominator_checked = False
    if selection_complete and required is not None:
        anomalies += verdict_policy.denominator_anomalies(results, required, excluded)
        denominator_checked = True
    # E-P0-06/10: verify the ARCHIVED bundle (the merged rows the results file
    # carries - that file is what any future reader consumes), reopening and
    # reparsing every log, then bind everything under one root.
    archived = json.loads((out_dir / "u0-results.json").read_text())["results"] \
        if (out_dir / "u0-results.json").exists() else results
    bundle_anoms, warnings, bundle_root = verdict_policy.verify_bundle(
        out_dir, archived, ledger, file_profile=profile, unsealed_ok=True)
    anomalies += bundle_anoms
    observation = verdict_policy.compute_observation(results)
    ledgered = sum(1 for r in results if r.get("target_id") in ledger)
    # write order matters: verdict.json first, COMPLETE (sealing the root) LAST
    rc = verdict_policy.verdict_exit_code(
        anomalies, selection_complete, out_dir,
        observation=observation, warnings=warnings, bundle_root=bundle_root,
        extra={"producer": "tools/catalog/run_u0.py",
               # E-04: pin the policy inputs so a later ledger/plan edit is a
               # detectable mismatch, never a silent reclassification
               "policy_roots": verdict_policy.compute_policy_roots(),
               "run": run_manifest,
               "denominator_checked": denominator_checked,
               "executables": len(results),
               "selection": {"filter": args.filter, "skip": args.skip,
                             "package": args.package}})
    for a in anomalies:
        print(f"ANOMALY: {a}", file=sys.stderr)
    for w in warnings:
        print(f"WARNING: {w}", file=sys.stderr)
    if not selection_complete:
        print("VERDICT: PARTIAL (a filtered/skipped/package-scoped run can never "
              "be a corpus verdict)", file=sys.stderr)
    print(f"BUNDLE ROOT: {bundle_root}", file=sys.stderr)
    print(verdict_policy.human_line(observation, rc == 0, ledgered)
          + f"; {len(anomalies)} anomaly/anomalies", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
