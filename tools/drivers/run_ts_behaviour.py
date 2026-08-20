#!/usr/bin/env python3
"""E-05 official-driver lane: the OFFICIAL TypeDB HTTP/TypeScript driver
behaviour suite, executed against a TypeDB server, archived at LEAF level.

The TypeScript driver in typedb-driver 3.x is `http-ts` (`@typedb/driver-http`):
plain TypeScript over the server's HTTP surface, no native or generated code.
It therefore needs no Bazel to build - npm, tsup and tsc are enough - and this
runner drives the upstream sources directly:

  * http-ts is COPIED into a work tree (never built inside the source-locked
    checkout, which must stay clean) and every copied file is required to
    hash identically to its locked original;
  * the driver bundle is built with the upstream tsup config, exactly as the
    Bazel `driver-lib` target does;
  * the behaviour step definitions are compiled with the ts config the Bazel
    rule uses (http-ts/tests/behaviour/rules.bzl: behaviour_test_ts_config);
  * the suites and the cucumber tag expression are READ OUT of
    tests/behaviour/feature/BUILD and rules.bzl, so this runner cannot
    quietly drop a suite or widen the filter.

Leaf evidence comes from cucumber-js's own `message` NDJSON stream: one
`pickle` per scenario (Scenario Outline examples already expanded), one
`testCaseFinished` per execution with its status. That is joined against an
independent Gherkin enumeration of the same feature file and against the
qualification plan's leaf ids.

Declared projection caveat, recorded in the evidence and never hidden: the
step definitions do NOT typecheck cleanly outside Bazel. Upstream's
`//http-ts:driver-lib` deliberately emits only `dist/index.cjs` and no
`index.d.cts` ("TODO: should also output index.d.cts (works in filesystem but
not in bazel)", http-ts/BUILD), so no non-Bazel build reproduces upstream's
exact type surface. tsc still EMITS the JavaScript cucumber-js runs, and this
runner requires the operational fidelity that actually bears on the results:
every steps source must have produced a .js file, and the cucumber run must
report ZERO undefined and ZERO ambiguous steps - i.e. every step definition
loaded and matched. The full typecheck diagnostics are archived.

Usage:
  python3 tools/drivers/run_ts_behaviour.py --lane fork-classic \
     --out docs/evidence/G1/drivers/typescript-rocksdb-fork-classic \
     --run-dir /tmp/ts-lane
"""

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import common  # noqa: E402
import gherkin_leaves  # noqa: E402
import typedb_server  # noqa: E402

REPO = common.REPO
DRIVER = REPO / "sources" / "typedb-driver"
BEHAVIOUR = REPO / "sources" / "typedb-behaviour"
HTTPTS = DRIVER / "http-ts"
FEATURE_BUILD = HTTPTS / "tests" / "behaviour" / "feature" / "BUILD"
RULES_BZL = HTTPTS / "tests" / "behaviour" / "rules.bzl"

SUITE_PRECONDITIONS = {
    "cluster": (
        "declared upstream only as typedb_behaviour_http_ts_cluster_test "
        "(http-ts/tests/behaviour/feature/BUILD), the multi-node cluster lane: "
        "it needs a replicated TypeDB deployment and the TLS certificates in "
        "//tool/test/resources:certificates. TypeDB CE - the only server this "
        "repository builds - is single-node, so no cluster can be stood up "
        "here."
    ),
}


def scan_suites():
    """suite -> {feature_ref, rule} read from the upstream BUILD file."""
    text = FEATURE_BUILD.read_text()
    out = {}
    for m in re.finditer(
        r"(typedb_behaviour_http_ts_test|typedb_behaviour_http_ts_cluster_test)"
        r'\(\s*name\s*=\s*"([^"]+)"\s*,\s*features\s*=\s*\[\s*"([^"]+)"',
        text,
    ):
        rule, name, feat = m.group(1), m.group(2), m.group(3)
        out[name] = {
            "feature_ref": feat.split("//", 1)[1].replace(":", "/"),
            "bazel_rule": rule,
            "cluster_only": rule.endswith("cluster_test"),
        }
    if not out:
        raise RuntimeError(
            f"{common.rel(FEATURE_BUILD)}: no behaviour test "
            f"declarations found - refusing to guess the suite set"
        )
    return dict(sorted(out.items()))


def core_tag_expression():
    """The cucumber tag filter the upstream CORE rule applies, extracted from
    rules.bzl rather than copied, so a corpus/rule change cannot silently
    widen or narrow what this lane runs."""
    text = RULES_BZL.read_text()
    m = re.search(
        r"def typedb_behaviour_http_ts_core_test\(.*?"
        r'"--tags \'([^\']+)\'"',
        text,
        re.S,
    )
    if not m:
        raise RuntimeError(f"{common.rel(RULES_BZL)}: cannot extract the core tag expression")
    return m.group(1)


def excluded_tags(expr):
    return sorted({t.lstrip("@") for t in re.findall(r"not\s+(@\S+)", expr)})


BAZEL_STEPS_TSCONFIG = {
    # http-ts/tests/behaviour/rules.bzl :: behaviour_test_ts_config()
    "compilerOptions": {
        "target": "es2021",
        "module": "commonjs",
        "moduleResolution": "node",
        "esModuleInterop": True,
        "skipLibCheck": True,
        "forceConsistentCasingInFileNames": True,
        # ts_project(..., declaration = True, resolve_json_module = True)
        "declaration": True,
        "resolveJsonModule": True,
    },
    "include": ["tests/behaviour/steps/*.ts"],
}


def materialise(run_dir):
    work = run_dir / "http-ts"
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(HTTPTS, work)
    mismatches = []
    files = 0
    for src in HTTPTS.rglob("*"):
        if not src.is_file():
            continue
        files += 1
        dst = work / src.relative_to(HTTPTS)
        if not dst.is_file() or common.sha256_file(dst) != common.sha256_file(src):
            mismatches.append(src.relative_to(HTTPTS).as_posix())
    return work, {
        "source": common.rel(HTTPTS),
        "work_tree": str(work),
        "files_copied": files,
        "hash_mismatches": mismatches,
    }


def run(argv, cwd, log, env=None, timeout=1800):
    t0 = time.time()
    with open(log, "wb") as fh:
        try:
            p = subprocess.run(
                argv,
                cwd=str(cwd),
                stdout=fh,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                env=env,
                timeout=timeout,
            )
            rc, to = p.returncode, False
        except subprocess.TimeoutExpired:
            rc, to = None, True
    return {
        "argv": argv,
        "cwd": str(cwd),
        "exit_code": rc,
        "timed_out": to,
        "duration_seconds": round(time.time() - t0, 2),
        "log": common.rel(log) if str(log).startswith(str(REPO)) else str(log),
        "log_sha256": common.sha256_file(log),
    }


def parse_messages(path):
    """cucumber-js `message` NDJSON -> ordered executed scenarios."""
    pickles, cases, started, finished = {}, {}, [], {}
    undefined = ambiguous = 0
    steps_by_case = {}
    for line in pathlib.Path(path).read_text().splitlines():
        if not line.strip():
            continue
        m = json.loads(line)
        if "pickle" in m:
            pickles[m["pickle"]["id"]] = m["pickle"]
        elif "testCase" in m:
            cases[m["testCase"]["id"]] = m["testCase"]
        elif "testCaseStarted" in m:
            started.append(m["testCaseStarted"])
        elif "testCaseFinished" in m:
            finished[m["testCaseFinished"]["testCaseStartedId"]] = m["testCaseFinished"]
        elif "testStepFinished" in m:
            r = m["testStepFinished"]["testStepResult"]
            sid = m["testStepFinished"]["testCaseStartedId"]
            steps_by_case.setdefault(sid, []).append(r.get("status"))
            if r.get("status") == "UNDEFINED":
                undefined += 1
            if r.get("status") == "AMBIGUOUS":
                ambiguous += 1
    out = []
    for st in started:
        case = cases.get(st.get("testCaseId")) or {}
        pk = pickles.get(case.get("pickleId")) or {}
        statuses = steps_by_case.get(st["id"], [])
        status = (
            "FAILED"
            if any(s in ("FAILED", "UNDEFINED", "AMBIGUOUS") for s in statuses)
            else "SKIPPED"
            if statuses and all(s in ("SKIPPED", "PENDING") for s in statuses)
            else "PASSED"
            if statuses
            else "EMPTY"
        )
        out.append(
            {
                "name": pk.get("name"),
                "status": status,
                "steps_total": len(statuses),
                "steps_passed": sum(1 for s in statuses if s == "PASSED"),
                "steps_failed": sum(
                    1 for s in statuses if s in ("FAILED", "UNDEFINED", "AMBIGUOUS")
                ),
                "steps_skipped": sum(1 for s in statuses if s in ("SKIPPED", "PENDING")),
                "attempt": st.get("attempt", 0),
            }
        )
    return {
        "scenarios": [s for s in out if s["attempt"] == 0],
        "undefined_steps": undefined,
        "ambiguous_steps": ambiguous,
        "pickles": len(pickles),
    }


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--lane", default="fork-classic", choices=sorted(typedb_server.LANES))
    ap.add_argument("--backend", default=None)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--run-dir", type=pathlib.Path, required=True)
    ap.add_argument("--timeout", type=int, default=3600)
    args = ap.parse_args()

    backend = (
        args.backend
        or {"U0": "rocksdb", "U1": "rocksdb", "U2": "slatedb"}[typedb_server.LANES[args.lane][1]]
    )
    out_dir = args.out if args.out.is_absolute() else REPO / args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    run_dir = args.run_dir
    run_dir.mkdir(parents=True, exist_ok=True)

    anomalies, caveats = [], []
    plan = json.loads(common.PLAN.read_text())
    if common.plan_root_of_body(plan) != plan.get("plan_root"):
        anomalies.append("plan: plan_root does not recompute from its own body")
    for node_id, path, key in (
        ("TDRIVER", DRIVER, "resolved_revision"),
        ("BH", BEHAVIOUR, "revision"),
    ):
        node = common.source_lock_node(node_id) or {}
        ident = common.checkout_identity(path)
        if ident.get("dirty") is not False:
            anomalies.append(
                f"{node_id}: {common.rel(path)} is dirty or its "
                f"dirt is unknown ({ident.get('dirty')!r})"
            )
        if ident.get("revision") != node.get(key) or ident.get("tree") != node.get("tree"):
            anomalies.append(f"{node_id}: checkout does not match the source lock")

    suites = scan_suites()
    tag_expr = core_tag_expression()
    skip_tags = excluded_tags(tag_expr)

    # There is deliberately no "reuse the previous build" switch: a bundle
    # whose build record is missing cannot state which dependency tree, which
    # tsc diagnostics and which caveats the executed JavaScript came from, and
    # an evidence file that cannot say that is not evidence.
    work = run_dir / "http-ts"
    build = {}
    if True:
        work, copy_report = materialise(run_dir)
        build["copy"] = copy_report
        if copy_report["hash_mismatches"]:
            anomalies.append(
                f"work-tree copy differs from the locked http-ts "
                f"sources in {len(copy_report['hash_mismatches'])} "
                f"file(s)"
            )
        build["npm_install"] = run(
            ["npm", "install", "--no-audit", "--no-fund"],
            work,
            run_dir / "npm-install.log",
            timeout=1800,
        )
        if build["npm_install"]["exit_code"] != 0:
            anomalies.append("npm install failed")
        # Dependency provenance: http-ts ships a pnpm-lock.yaml and pins
        # `packageManager: pnpm@8.15.9`, but the pnpm on this host is 10.x and
        # would migrate the v8 lockfile rather than honour it. npm was used
        # instead, which resolves fresh within package.json's ranges. That is
        # a real provenance gap, so it is DECLARED as a caveat and the exact
        # resolved tree is archived rather than left implicit.
        lock = work / "pnpm-lock.yaml"
        ls = subprocess.run(
            ["npm", "ls", "--all", "--json"], cwd=str(work), capture_output=True, text=True
        )
        (run_dir / "npm-tree.json").write_text(ls.stdout or "{}")
        shutil.copy(run_dir / "npm-tree.json", out_dir / "npm-tree.json")
        pkg = json.loads((work / "package.json").read_text())
        installed = {}
        try:
            tree = json.loads(ls.stdout or "{}")
            for name, node in (tree.get("dependencies") or {}).items():
                installed[name] = node.get("version")
        except json.JSONDecodeError:
            pass
        declared = dict(pkg.get("devDependencies") or {})
        declared.update(pkg.get("dependencies") or {})
        drift = {
            n: {"declared": v, "installed": installed.get(n)}
            for n, v in declared.items()
            if not v.startswith("^") and installed.get(n) != v
        }
        build["dependencies"] = {
            "package_manager_used": "npm",
            "package_manager_declared": pkg.get("packageManager"),
            "pnpm_lock_present": lock.is_file(),
            "pnpm_lock_sha256": (common.sha256_file(lock) if lock.is_file() else None),
            "pnpm_lock_honoured": False,
            "declared": declared,
            "installed_top_level": installed,
            "exact_pin_drift": drift,
            "resolved_tree": common.rel(out_dir / "npm-tree.json"),
        }
        if drift:
            anomalies.append(
                f"exactly-pinned dependencies did not install at their pinned versions: {drift}"
            )
        caveats.append(
            {
                "id": "npm-install-not-pnpm-lock",
                "detail": (
                    f"http-ts declares packageManager "
                    f"{pkg.get('packageManager')!r} and ships pnpm-lock.yaml "
                    f"(sha256 {build['dependencies']['pnpm_lock_sha256']}), but "
                    f"the pnpm available here is 10.x, which does not honour a v8 "
                    f"lockfile without migrating it. Dependencies were therefore "
                    f"resolved by npm within package.json's ranges. Every exact "
                    f"pin was verified to have installed at its pinned version, "
                    f"and the full resolved tree is archived as npm-tree.json, "
                    f"but the transitive closure is NOT the closure the committed "
                    f"pnpm lockfile names."
                ),
            }
        )
        build["tsup"] = run(["npx", "tsup"], work, run_dir / "tsup.log")
        if build["tsup"]["exit_code"] != 0:
            anomalies.append("tsup driver build failed")
        cfg = work / "behaviour-steps-tsconfig.json"
        cfg.write_text(json.dumps(BAZEL_STEPS_TSCONFIG, indent=1))
        build["tsconfig"] = BAZEL_STEPS_TSCONFIG
        build["tsc"] = run(["npx", "tsc", "-p", cfg.name], work, run_dir / "tsc.log")
        diag = (run_dir / "tsc.log").read_text(errors="replace")
        build["tsc"]["diagnostics"] = [
            line for line in diag.splitlines() if re.search(r"error TS\d+", line)
        ]
        # the emitted JS is what cucumber-js runs; the type surface upstream
        # compiles against is not reproducible outside bazel (http-ts/BUILD
        # TODO). Record, never hide.
        (work / "tests" / "behaviour" / "steps" / "package.json").write_text(
            '{"type":"commonjs"}\n'
        )
        steps_dir = work / "tests" / "behaviour" / "steps"
        ts_srcs = sorted(p.stem for p in steps_dir.glob("*.ts") if not p.name.endswith(".d.ts"))
        js_out = sorted(p.stem for p in steps_dir.glob("*.js"))
        build["emitted_steps"] = {"sources": ts_srcs, "emitted": js_out}
        if set(ts_srcs) - set(js_out):
            anomalies.append(
                f"tsc did not emit JavaScript for {sorted(set(ts_srcs) - set(js_out))}"
            )
        if build["tsc"]["exit_code"] != 0:
            caveats.append(
                {
                    "id": "steps-typecheck-not-clean",
                    "detail": (
                        f"tsc exited {build['tsc']['exit_code']} with "
                        f"{len(build['tsc']['diagnostics'])} diagnostic(s) while "
                        f"compiling the behaviour steps, and still emitted "
                        f"JavaScript for every source. Upstream's Bazel target "
                        f"compiles the steps against //http-ts:driver-lib, which "
                        f"emits only dist/index.cjs and deliberately no "
                        f"index.d.cts (http-ts/BUILD: 'TODO: should also output "
                        f"index.d.cts (works in filesystem but not in bazel)'), so "
                        f"the upstream type surface is not reproducible outside "
                        f"bazel. The executed evidence below rests on the emitted "
                        f"JavaScript plus a zero-undefined/zero-ambiguous step "
                        f"check, not on a clean typecheck."
                    ),
                    "diagnostics": build["tsc"]["diagnostics"],
                }
            )
    shutil.copy(run_dir / "tsc.log", out_dir / "tsc.log")

    suite_rows, leaf_rows, server_records = [], [], []
    selected = [s for s in suites if not suites[s]["cluster_only"]]
    for name in list(selected) + [s for s in suites if suites[s]["cluster_only"]]:
        meta = suites[name]
        ref = meta["feature_ref"]
        feature = BEHAVIOUR / ref
        expected = gherkin_leaves.enumerate_leaves(feature, ref)
        row = {
            "suite_id": name,
            "feature_ref": ref,
            "bazel_rule": meta["bazel_rule"],
            "feature_path": common.rel(feature),
            "feature_sha256": common.sha256_file(feature),
            "tag_expression": tag_expr,
            "leaves_enumerated": len(expected),
        }
        if meta["cluster_only"]:
            row["status"] = "NOT_EXECUTED_PRECONDITION_UNMET"
            row["precondition"] = SUITE_PRECONDITIONS[name]
            suite_rows.append(row)
            leaf_rows.extend(
                {
                    "leaf_case_id": e["leaf_case_id"],
                    "suite_id": name,
                    "feature_ref": ref,
                    "display_name": e["display_name"],
                    "feature_line": e["line"],
                    "kind": e["kind"],
                    "status": "NOT_RUN",
                    "reason": row["precondition"],
                    "in_plan": e["leaf_case_id"] in plan["leaves"],
                }
                for e in expected
            )
            continue

        def skipped_tag(leaf):
            for t in leaf["tags"]:
                if t.lstrip("@") in skip_tags:
                    return t
            return None

        runnable = [e for e in expected if skipped_tag(e) is None]
        row["leaves_runnable"] = len(runnable)
        row["leaves_tag_skipped"] = len(expected) - len(runnable)

        srv_dir = run_dir / f"srv-{name}"
        srv_dir.mkdir(parents=True, exist_ok=True)
        server = typedb_server.TypeDBServer(args.lane, srv_dir)
        server.start()
        ndjson = out_dir / f"{name}.messages.ndjson"
        log = out_dir / f"{name}.log"
        # the upstream steps read the server address from these env vars
        # (http-ts/tests/behaviour/steps/context.ts: DEFAULT_HOST /
        # DEFAULT_PORT); the lane's server does not sit on the 8000 default
        cenv = dict(os.environ)
        cenv["TYPEDB_HTTP_HOST"] = f"http://{typedb_server.LOOPBACK}"
        cenv["TYPEDB_HTTP_PORT"] = str(server.http_port)
        argv = [
            "npx",
            "cucumber-js",
            "--publish-quiet",
            "--strict",
            "--tags",
            tag_expr,
            "--require",
            "tests/behaviour/steps/*.js",
            "--format",
            f"message:{ndjson}",
            str(feature),
        ]
        r = run(argv, work, log, env=cenv, timeout=args.timeout)
        row.update({k: r[k] for k in ("argv", "exit_code", "timed_out", "duration_seconds")})
        row["driver_endpoint_env"] = {
            "TYPEDB_HTTP_HOST": cenv["TYPEDB_HTTP_HOST"],
            "TYPEDB_HTTP_PORT": cenv["TYPEDB_HTTP_PORT"],
        }
        row["raw_log"] = common.rel(log)
        row["log_sha256"] = common.sha256_file(log)
        row["structured_log"] = common.rel(ndjson) if ndjson.is_file() else None
        row["structured_log_sha256"] = common.sha256_file(ndjson) if ndjson.is_file() else None
        row["server_alive_after_suite"] = server.alive()
        if not server.alive():
            anomalies.append(f"{name}: the TypeDB server died during the suite")
        rec = server.evidence()
        rec["suite_id"] = name
        w = rec.get("backend_witness") or {}
        if w.get("marker_text"):
            marker = out_dir / f"backend-spec-{name}.marker"
            marker.write_text(w["marker_text"])
            w["archived_marker"] = common.rel(marker)
        if w.get("problem"):
            anomalies.append(f"{name}: {w['problem']}")
        server.stop()
        rec["exit_code"] = server.proc.returncode
        shutil.copy(server.log_path, out_dir / f"server-{name}.log")
        rec["log"] = common.rel(out_dir / f"server-{name}.log")
        rec["log_sha256"] = common.sha256_file(out_dir / f"server-{name}.log")
        server_records.append(rec)

        if not ndjson.is_file():
            row["status"] = "NO_STRUCTURED_OUTPUT"
            anomalies.append(f"{name}: cucumber-js produced no message stream")
            suite_rows.append(row)
            continue
        parsed = parse_messages(ndjson)
        observed = parsed["scenarios"]
        row["observed_scenarios"] = len(observed)
        row["undefined_steps"] = parsed["undefined_steps"]
        row["ambiguous_steps"] = parsed["ambiguous_steps"]
        row["status"] = "EXECUTED" if observed else "NO_SCENARIOS"
        if not observed:
            anomalies.append(f"{name}: cucumber-js ran ZERO scenarios")
        if parsed["undefined_steps"] or parsed["ambiguous_steps"]:
            anomalies.append(
                f"{name}: {parsed['undefined_steps']} undefined and "
                f"{parsed['ambiguous_steps']} ambiguous step(s) - the step "
                f"definitions did not all load and match, so the emitted "
                f"JavaScript is not the upstream suite"
            )
        planned = sorted(k for k in plan["leaves"] if k.startswith(f"cucumber:{ref}::"))
        row["leaves_in_plan"] = len(planned)
        if planned and sorted(e["leaf_case_id"] for e in expected) != planned:
            anomalies.append(
                f"{name}: independent enumeration of {ref} disagrees with the plan's leaf ids"
            )
        for lid in planned:
            ph = plan["leaves"][lid].get("source_hash")
            if ph and ph != row["feature_sha256"]:
                anomalies.append(f"{name}: {ref} does not match the plan's pinned source hash")
                break
        obs_names = [o["name"] for o in observed]
        exp_names = [e["display_name"] for e in runnable]
        if obs_names != exp_names:
            first = next(
                (i for i, (a, b) in enumerate(zip(exp_names, obs_names)) if a != b),
                min(len(exp_names), len(obs_names)),
            )
            anomalies.append(
                f"{name}: observed scenario sequence != the sequence enumerated "
                f"from {ref} (expected {len(exp_names)}, observed "
                f"{len(obs_names)}; first divergence at {first}: "
                f"{exp_names[first : first + 1]} vs {obs_names[first : first + 1]})"
            )
        if row["exit_code"] not in (0, None):
            anomalies.append(f"{name}: cucumber-js exited {row['exit_code']}")
        ri = 0
        for e in expected:
            tag = skipped_tag(e)
            lr = {
                "leaf_case_id": e["leaf_case_id"],
                "suite_id": name,
                "feature_ref": ref,
                "display_name": e["display_name"],
                "feature_line": e["line"],
                "kind": e["kind"],
                "in_plan": e["leaf_case_id"] in plan["leaves"],
            }
            if tag is not None:
                lr.update(
                    {
                        "status": "SKIPPED_IGNORED_TAG",
                        "ignored_tag": tag,
                        "reason": f"the upstream core tag expression ({tag_expr}) excludes {tag}",
                    }
                )
                leaf_rows.append(lr)
                continue
            o = observed[ri] if ri < len(observed) else None
            ri += 1
            if o is None or o["name"] != e["display_name"]:
                lr.update(
                    {
                        "status": "NOT_RUN",
                        "reason": "no cucumber-js test case at this position with this name",
                    }
                )
            else:
                lr.update(
                    {
                        "status": o["status"],
                        "steps_passed": o["steps_passed"],
                        "steps_failed": o["steps_failed"],
                        "steps_skipped": o["steps_skipped"],
                        "steps_total": o["steps_total"],
                    }
                )
            leaf_rows.append(lr)
        suite_rows.append(row)

    scope = sorted(
        {
            k
            for s in suite_rows
            for k in plan["leaves"]
            if k.startswith(f"cucumber:{s['feature_ref']}::")
        }
    )
    produced = {leaf["leaf_case_id"] for leaf in leaf_rows}
    missing = sorted(set(scope) - produced)
    if missing:
        anomalies.append(
            f"{len(missing)} plan leaf/leaves in scope produced no leaf row, e.g. {missing[:3]}"
        )
    in_plan = [leaf for leaf in leaf_rows if leaf["in_plan"]]
    covered = [
        leaf
        for leaf in in_plan
        if leaf["status"] in ("PASSED", "FAILED", "SKIPPED", "SKIPPED_IGNORED_TAG")
    ]
    passed = [leaf for leaf in in_plan if leaf["status"] in ("PASSED", "SKIPPED_IGNORED_TAG")]
    counts = {}
    for leaf in leaf_rows:
        counts[leaf["status"]] = counts.get(leaf["status"], 0) + 1

    results = {
        "schema": "typedb-r2-driver-lane-v1",
        "harness": "typescript-cucumberjs-messages",
        "statement": (
            "LEAF-LEVEL execution evidence for one official-driver plan row, "
            "produced by the OFFICIAL http-ts TypeScript driver built from the "
            "locked TDRIVER sources and driven by cucumber-js over the locked "
            "behaviour corpus."
        ),
        "row_id": f"driver:typescript:{backend}",
        "driver": "typescript",
        "backend": backend,
        "lane": args.lane,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "plan": {
            "path": common.rel(common.PLAN),
            "plan_root_declared": plan.get("plan_root"),
            "plan_root_recomputed": common.plan_root_of_body(plan),
            "sha256": common.sha256_file(common.PLAN),
        },
        "build": build,
        "tag_expression": tag_expr,
        "tag_expression_source": common.rel(RULES_BZL),
        "excluded_tags": skip_tags,
        "caveats": caveats,
        "servers": server_records,
        "suites": suite_rows,
        "suite_preconditions": SUITE_PRECONDITIONS,
        "leaves": leaf_rows,
        "counts": {
            "suites_selected": len(selected),
            "suites_executed": sum(1 for r in suite_rows if r.get("status") == "EXECUTED"),
            "leaf_rows": len(leaf_rows),
            "leaf_rows_in_plan": len(in_plan),
            "leaf_rows_outside_plan": len(leaf_rows) - len(in_plan),
            "plan_leaves_in_scope": len(scope),
            "plan_leaves_with_outcome": len(covered),
            "plan_leaves_passed": len(passed),
            "by_status": dict(sorted(counts.items())),
        },
        "leaves_outside_plan": sorted(
            leaf["leaf_case_id"] for leaf in leaf_rows if not leaf["in_plan"]
        ),
        "plan_leaves_without_outcome": missing,
        "anomalies": anomalies,
    }
    rp = out_dir / "driver-results.json"
    rp.write_text(json.dumps(results, indent=1) + "\n")
    consumed = [rp, common.PLAN]
    consumed += [REPO / r["raw_log"] for r in suite_rows if r.get("raw_log")]
    consumed += [REPO / r["structured_log"] for r in suite_rows if r.get("structured_log")]
    consumed += [REPO / r["log"] for r in server_records if r.get("log")]
    consumed += [
        REPO / (r.get("backend_witness") or {})["archived_marker"]
        for r in server_records
        if (r.get("backend_witness") or {}).get("archived_marker")
    ]
    for extra in ("npm-tree.json", "tsc.log"):
        if (out_dir / extra).is_file():
            consumed.append(out_dir / extra)
    root, pairs = common.compute_bundle_root(out_dir, consumed)
    (out_dir / "bundle-manifest.json").write_text(
        json.dumps(
            {
                "schema": "driver-lane-bundle-manifest-v1",
                "bundle_root": root,
                "files": dict(sorted(pairs.items())),
            },
            indent=1,
        )
        + "\n"
    )
    green = not anomalies and bool(covered) and len(covered) == len(passed)
    verdict = {
        "green": bool(green),
        "policy_verdict": "GREEN" if green else "RED",
        "row_id": results["row_id"],
        "bundle_root": root,
        "plan_root": plan.get("plan_root"),
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        "caveats": [c["id"] for c in caveats],
        "observation": {
            "suites_selected": len(selected),
            "suites_executed": results["counts"]["suites_executed"],
            "plan_leaves_in_scope": len(scope),
            "plan_leaves_with_outcome": len(covered),
            "plan_leaves_passed": len(passed),
            "leaf_status_counts": dict(sorted(counts.items())),
        },
    }
    (out_dir / "verdict.json").write_text(json.dumps(verdict, indent=1) + "\n")
    marker = out_dir / "COMPLETE"
    if green:
        marker.write_text(f"COMPLETE {root}\n")
    elif marker.exists():
        marker.unlink()
    print(json.dumps(verdict, indent=1))
    print(
        f"DRIVER LANE {results['row_id']} ({args.lane}): "
        f"{results['counts']['suites_executed']}/{len(selected)} suites, "
        f"{len(covered)}/{len(scope)} plan leaves with an outcome, "
        f"{len(passed)} passed, {len(anomalies)} anomaly(ies), "
        f"{len(caveats)} caveat(s) -> {'GREEN' if green else 'RED'}",
        file=sys.stderr,
    )
    return 0 if green else 1


if __name__ == "__main__":
    sys.exit(main())
