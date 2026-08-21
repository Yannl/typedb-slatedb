#!/usr/bin/env python3
"""E-05 official-driver lane: the OFFICIAL TypeDB PYTHON driver behaviour
suite, executed against a TypeDB server, archived at LEAF level.

How this lane differs from the Rust one, and why that is recorded
-----------------------------------------------------------------
The Python driver cannot be built from sources/typedb-driver in this
environment: python/typedb/native_driver_wrapper.py and the native
`native_driver_python.so` are SWIG outputs produced by Bazel
(`@typedb_dependencies//builder/swig:python.bzl`, python/BUILD), and neither
bazel nor swig exists here. What CAN be used is the OFFICIAL published
artifact for the same version the source lock pins (TDRIVER tag 3.12.3), and
this runner proves it is the locked driver rather than assuming it:

  * the wheel's sha256 and its resolved PyPI URL are recorded;
  * EVERY pure-Python module inside the wheel is compared byte-for-byte
    against sources/typedb-driver/python/typedb/**. Any difference at all is
    a hard refusal. The only files the wheel may carry that the locked tree
    does not are the Bazel/SWIG products (`native_driver_wrapper.py`, the
    `.so`) and Bazel-generated empty `__init__.py` markers, and even those
    are enumerated in the evidence.

The BEHAVIOUR harness is the upstream one, reconstructed exactly as
python/tests/behaviour/behave_rule.bzl builds it: a directory holding the
background `environment.py`, the feature file, and a `steps/` directory with
the step modules the suite's Bazel target names - then `behave` over that
directory. The suite composition is READ OUT of the upstream BUILD files, so
this runner cannot quietly drop a step module or a suite.

Leaf evidence: behave's own JSON formatter emits one element per scenario
(and one per Scenario Outline example, located at the example ROW line), so
the leaf join is structural rather than scraped. It is still cross-checked
against an independent Gherkin enumeration of the same feature file and
against the qualification plan's leaf ids.

Usage:
  python3 tools/drivers/run_python_behaviour.py --lane fork-classic \
     --out docs/evidence/G1/drivers/python-rocksdb-fork-classic
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
PYROOT = DRIVER / "python"
BHROOT = PYROOT / "tests" / "behaviour"
DRIVER_VERSION = (DRIVER / "VERSION").read_text().strip()

SUITE_PRECONDITIONS = {
    "driver/cluster": (
        "declared upstream only as typedb_behaviour_py_test_cluster "
        "(python/tests/behaviour/driver/cluster/BUILD), i.e. the multi-node "
        "cluster lane: it targets 127.0.0.1:11729 and needs three TypeDB "
        "servers with replication. TypeDB CE - the only server this "
        "repository builds - is single-node, so no cluster can be stood up "
        "here."
    ),
}


# ------------------------------------------------------- BUILD file scanning


def _strings(text):
    return re.findall(r'"([^"]*)"', text)


def scan_calls(text):
    """Top-level `callee(...)` declarations via a balanced-paren walk that is
    quote- and comment-aware. A regex over whole calls silently misses
    reformatted declarations; this cannot."""
    calls, i, n = [], 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "#":
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        if ch in "\"'":
            j = i + 1
            while j < n and text[j] != ch:
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            continue
        m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", text[i:])
        if not m:
            i += 1
            continue
        callee = m.group(0)
        j = i + len(callee)
        while j < n and text[j] in " \t\r\n":
            j += 1
        if j >= n or text[j] != "(":
            i += len(callee)
            continue
        depth, k = 0, j
        while k < n:
            c = text[k]
            if c == "#":
                nl = text.find("\n", k)
                k = n if nl == -1 else nl
                continue
            if c in "\"'":
                k += 1
                while k < n and text[k] != c:
                    k += 2 if text[k] == "\\" else 1
                k += 1
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        if depth != 0:
            raise RuntimeError("unbalanced parentheses in a BUILD declaration")
        calls.append((callee, text[j + 1 : k]))
        i = k + 1
    return calls


def arg_list(args_text, key):
    m = re.search(rf"{key}\s*=\s*\[", args_text)
    if not m:
        return None
    depth, i = 0, m.end() - 1
    while i < len(args_text):
        if args_text[i] == "[":
            depth += 1
        elif args_text[i] == "]":
            depth -= 1
            if depth == 0:
                break
        i += 1
    return _strings(args_text[m.end() : i])


def arg_str(args_text, key):
    m = re.search(rf'{key}\s*=\s*"([^"]*)"', args_text)
    return m.group(1) if m else None


def scan_python_behaviour():
    """-> {suite_id: {feature_ref, step_files, build_file, cluster_only}}."""
    libs = {}  # label -> [files]
    suites = {}
    for build in sorted(BHROOT.rglob("BUILD")):
        pkg = build.parent.relative_to(PYROOT).as_posix()  # tests/behaviour/...
        label_pkg = "//python/" + pkg
        for callee, args in scan_calls(build.read_text()):
            if callee == "py_library":
                name = arg_str(args, "name")
                srcs = arg_list(args, "srcs") or []
                libs[f"{label_pkg}:{name}"] = [build.parent / s for s in srcs]
    for build in sorted(BHROOT.rglob("BUILD")):
        pkg_dir = build.parent
        label_pkg = "//python/" + pkg_dir.relative_to(PYROOT).as_posix()
        for callee, args in scan_calls(build.read_text()):
            if callee not in (
                "typedb_behaviour_py_test",
                "typedb_behaviour_py_test_cluster",
                "typedb_behaviour_py_test_core",
            ):
                continue
            feats = arg_list(args, "feats") or []
            if len(feats) != 1:
                raise RuntimeError(f"{build}: expected one feats entry, got {feats}")
            ref = feats[0].split("//", 1)[1].replace(":", "/")
            steps = []
            for lab in arg_list(args, "steps") or []:
                lab = f"{label_pkg}{lab}" if lab.startswith(":") else lab
                files = libs.get(lab)
                if files is None:
                    raise RuntimeError(
                        f"{build}: steps label {lab!r} does not "
                        f"resolve to a py_library in this tree"
                    )
                steps.extend(files)
            suite_id = pkg_dir.relative_to(BHROOT).as_posix()
            suites[suite_id] = {
                "feature_ref": ref,
                "build_file": common.rel(build),
                "bazel_rule": callee,
                "cluster_only": callee == "typedb_behaviour_py_test_cluster",
                "step_files": [common.rel(f) for f in steps],
            }
    return dict(sorted(suites.items()))


# --------------------------------------------------------- wheel provenance


def wheel_provenance(venv):
    site = next(iter((venv / "lib").glob("python3*/site-packages")))
    pkg = site / "typedb"
    src = PYROOT / "typedb"
    identical, differing, only_wheel, only_source = [], [], [], []
    sfiles = {p.relative_to(src).as_posix() for p in src.rglob("*.py")}
    wfiles = {p.relative_to(pkg).as_posix() for p in pkg.rglob("*.py")}
    for f in sorted(sfiles | wfiles):
        a, b = src / f, pkg / f
        if not a.is_file():
            only_wheel.append(
                {"file": f, "bytes": b.stat().st_size, "sha256": common.sha256_file(b)}
            )
        elif not b.is_file():
            only_source.append(f)
        elif common.sha256_file(a) == common.sha256_file(b):
            identical.append(f)
        else:
            differing.append(f)
    dist = next(iter(site.glob("typedb_driver-*.dist-info")), None)
    meta = {}
    if dist is not None:
        for line in (dist / "METADATA").read_text(errors="replace").splitlines():
            if line.startswith(("Name:", "Version:")):
                k, v = line.split(":", 1)
                meta[k.strip()] = v.strip()
    native = sorted(p.name for p in pkg.iterdir() if p.suffix == ".so")
    return {
        "site_packages": str(site),
        "metadata": meta,
        "locked_driver_version": DRIVER_VERSION,
        "identical_to_locked_source": len(identical),
        "differing_from_locked_source": differing,
        "only_in_wheel": [f["file"] for f in only_wheel],
        "only_in_wheel_nonempty": [f for f in only_wheel if f["bytes"] > 0],
        "only_in_locked_source": only_source,
        "native_extensions": [{"file": n, "sha256": common.sha256_file(pkg / n)} for n in native],
        "note": (
            "The published wheel is used because the Python driver's SWIG "
            "wrapper and native extension are Bazel outputs and neither bazel "
            "nor swig exists in this environment. Every pure-Python module in "
            "the wheel is compared byte-for-byte with the locked TDRIVER tree; "
            "the only files the wheel may add are Bazel-generated package "
            "markers and the SWIG products, which are enumerated above."
        ),
    }


IANA_AREAS = (
    "Africa",
    "America",
    "Antarctica",
    "Arctic",
    "Asia",
    "Atlantic",
    "Australia",
    "Europe",
    "Indian",
    "Pacific",
    "Etc",
    "US",
)


def corpus_time_zones(refs):
    """Every IANA-looking zone id the feature files in scope actually name.

    Deriving the list from the CORPUS rather than hardcoding it means the
    check cannot drift from the fixtures it is meant to protect - and it
    cannot be padded with zones nothing tests (an earlier version of this
    probe hardcoded 'Africa/Eswatini', which is not an IANA zone at all and
    produced a false anomaly).
    """
    pat = re.compile(r"\b(?:" + "|".join(IANA_AREAS) + r")/[A-Za-z_+-]+")
    zones = set()
    for ref in refs:
        f = BEHAVIOUR / ref
        if f.is_file():
            zones |= set(pat.findall(f.read_text()))
    return sorted(zones)


def harness_environment(venv, refs):
    """Facts about the interpreter environment the suite runs in, checked
    against the corpus rather than assumed.

    The IANA time-zone database is the one that actually bit here. This host
    ships a SLIM /usr/share/zoneinfo without the `backward` compatibility
    aliases, so `zoneinfo.ZoneInfo("Asia/Calcutta")` raised
    ZoneInfoNotFoundError and driver/concept.feature's "Driver processes
    datetime-tz values in different user time-zones identically" failed on
    the fixture, not on the driver or the server. (Executed and recorded:
    the Rust lane passes the same scenario because chrono-tz compiles the
    full IANA database, aliases included.) Supplying the full database via
    the `tzdata` distribution restores the fixture; it does not weaken the
    test, and every zone the corpus names is probed here so a reader sees
    which ones resolved rather than taking it on trust.
    """
    py = venv / "bin" / "python"
    probe = (
        "import json,sys,zoneinfo\n"
        "zones=" + repr(corpus_time_zones(refs)) + "\n"
        "res={}\n"
        "for z in zones:\n"
        "    try:\n"
        "        zoneinfo.ZoneInfo(z); res[z]=True\n"
        "    except Exception as e:\n"
        "        res[z]=f'{type(e).__name__}: {e}'\n"
        "try:\n"
        "    import tzdata; v=getattr(tzdata,'IANA_VERSION',None)\n"
        "except Exception as e:\n"
        "    v=f'absent ({type(e).__name__})'\n"
        "print(json.dumps({'python':sys.version,'tzpath':list(zoneinfo.TZPATH),"
        "'zones_from_corpus':res,'tzdata_package':v}))\n"
    )
    r = subprocess.run([str(py), "-c", probe], capture_output=True, text=True)
    try:
        info = json.loads(r.stdout)
    except json.JSONDecodeError:
        return {"problems": [f"time-zone probe failed: {r.stderr[-300:]}"], "raw": r.stdout}
    info["problems"] = [
        f"time zone {z}, named by the behaviour corpus, is not resolvable in this interpreter: {v}"
        for z, v in info["zones_from_corpus"].items()
        if v is not True
    ]
    return info


# ----------------------------------------------------------------- behave IO


def materialise(suite_id, meta, run_dir):
    """Rebuild the Bazel `prepare_py_behave_directory` output for one suite."""
    d = run_dir / "features" / suite_id.replace("/", "__")
    if d.exists():
        shutil.rmtree(d)
    (d / "steps").mkdir(parents=True)
    env_src = BHROOT / "background" / "core" / "environment.py"
    shutil.copy(env_src, d / "environment.py")
    feature_src = BEHAVIOUR / meta["feature_ref"]
    shutil.copy(feature_src, d / feature_src.name)
    copied = []
    for rel in meta["step_files"]:
        s = REPO / rel
        shutil.copy(s, d / "steps" / s.name)
        copied.append({"source": rel, "sha256": common.sha256_file(s)})
    return d, {
        "features_dir": str(d),
        "environment": {"source": common.rel(env_src), "sha256": common.sha256_file(env_src)},
        "feature": {
            "source": common.rel(feature_src),
            "sha256": common.sha256_file(feature_src),
            "copy_sha256": common.sha256_file(d / feature_src.name),
        },
        "steps": copied,
    }


def parse_behave_json(path):
    """-> ordered scenario records from behave's own structured output."""
    data = json.loads(pathlib.Path(path).read_text())
    out = []
    for feat in data:
        for el in feat.get("elements") or []:
            if el.get("type") != "scenario":
                continue
            steps = el.get("steps") or []
            counts = {
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "undefined": 0,
                "untested": 0,
                "other": 0,
            }
            for st in steps:
                s = ((st.get("result") or {}).get("status")) or "untested"
                counts[s if s in counts else "other"] += 1
            name = el.get("name") or ""
            base = re.sub(r"\s+--\s+@\d+\.\d+\s*.*$", "", name)
            out.append(
                {
                    "feature": feat.get("name"),
                    "keyword": el.get("keyword"),
                    "raw_name": name,
                    "display_name": base,
                    "location": el.get("location"),
                    "status": (el.get("status") or "untested").upper(),
                    "steps_total": len(steps),
                    "steps_passed": counts["passed"],
                    "steps_failed": counts["failed"],
                    "steps_skipped": counts["skipped"] + counts["untested"],
                    "steps_undefined": counts["undefined"],
                }
            )
    return out


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--lane", default="fork-classic", choices=sorted(typedb_server.LANES))
    ap.add_argument("--backend", default=None)
    ap.add_argument("--out", type=pathlib.Path, required=False)
    ap.add_argument("--run-dir", type=pathlib.Path, required=True)
    ap.add_argument("--venv", type=pathlib.Path, required=True)
    ap.add_argument("--suite", action="append", default=None)
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--list-suites", action="store_true")
    args = ap.parse_args()

    suites = scan_python_behaviour()
    if args.list_suites:
        print(json.dumps(suites, indent=1))
        return 0
    if args.out is None:
        ap.error("--out is required")

    backend = (
        args.backend
        or {"U0": "rocksdb", "U1": "rocksdb", "U2": "slatedb"}[typedb_server.LANES[args.lane][1]]
    )
    out_dir = args.out if args.out.is_absolute() else REPO / args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    run_dir = args.run_dir
    run_dir.mkdir(parents=True, exist_ok=True)
    venv = args.venv

    anomalies = []
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

    prov = wheel_provenance(venv)
    prov["harness_environment"] = harness_environment(
        venv, [m["feature_ref"] for m in suites.values()]
    )
    for problem in prov["harness_environment"]["problems"]:
        anomalies.append(f"harness environment: {problem}")
    if prov["differing_from_locked_source"]:
        anomalies.append(
            f"the installed wheel's python modules differ from the locked "
            f"TDRIVER tree in {len(prov['differing_from_locked_source'])} "
            f"file(s): {prov['differing_from_locked_source'][:5]}"
        )
    if prov["only_in_locked_source"]:
        anomalies.append(
            f"the wheel is MISSING locked driver modules: {prov['only_in_locked_source'][:5]}"
        )
    if prov["metadata"].get("Version") != DRIVER_VERSION:
        anomalies.append(
            f"installed driver version "
            f"{prov['metadata'].get('Version')!r} != locked "
            f"driver VERSION {DRIVER_VERSION!r}"
        )
    extra = [
        f["file"]
        for f in prov["only_in_wheel_nonempty"]
        if f["file"] not in ("native_driver_wrapper.py",)
    ]
    if extra:
        anomalies.append(
            f"the wheel carries non-empty python modules the locked tree does not: {extra[:5]}"
        )

    selected = args.suite or [s for s in suites if not suites[s]["cluster_only"]]
    env = dict(os.environ)
    # Bazel's py_test puts the WORKSPACE ROOT on sys.path (so
    # `python.tests.behaviour.util.functor_encoder` resolves) and the
    # py_library import roots too (so `tests.behaviour.context` resolves).
    # Both upstream spellings appear in the step modules, so both roots go on
    # PYTHONPATH here; using only one of them makes step modules fail to
    # import at RUNTIME, mid-scenario, which reads as a product failure and
    # is not one. (Executed: with only PYROOT, driver/query.feature scenario
    # "Row queries can request the query structure to be included in
    # response" failed with ModuleNotFoundError: No module named 'python'.)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(DRIVER), str(PYROOT)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
    )
    behave = venv / "bin" / "behave"

    suite_rows, leaf_rows, server_records = [], [], []
    for suite_id in list(selected) + sorted(s for s in suites if suites[s]["cluster_only"]):
        meta = suites[suite_id]
        sid_flat = suite_id.replace("/", "__")
        ref = meta["feature_ref"]
        row = {
            "suite_id": suite_id,
            "feature_ref": ref,
            "build_file": meta["build_file"],
            "bazel_rule": meta["bazel_rule"],
            "feature_path": common.rel(BEHAVIOUR / ref),
            "feature_sha256": common.sha256_file(BEHAVIOUR / ref),
        }
        if meta["cluster_only"] or suite_id in SUITE_PRECONDITIONS:
            row["status"] = "NOT_EXECUTED_PRECONDITION_UNMET"
            row["precondition"] = SUITE_PRECONDITIONS.get(
                suite_id, "declared upstream only for the cluster lane"
            )
            expected = gherkin_leaves.enumerate_leaves(BEHAVIOUR / ref, ref)
            row["leaves_enumerated"] = len(expected)
            suite_rows.append(row)
            leaf_rows.extend(
                {
                    "leaf_case_id": e["leaf_case_id"],
                    "suite_id": suite_id,
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

        srv_dir = run_dir / sid_flat
        srv_dir.mkdir(parents=True, exist_ok=True)
        server = typedb_server.TypeDBServer(args.lane, srv_dir)
        server.start()
        fdir, layout = materialise(suite_id, meta, run_dir)
        row["harness_layout"] = layout
        if layout["feature"]["sha256"] != layout["feature"]["copy_sha256"]:
            anomalies.append(
                f"{suite_id}: the copied feature file does not match the locked corpus"
            )
        log_path = out_dir / f"{sid_flat}.log"
        json_path = out_dir / f"{sid_flat}.behave.json"
        argv = [
            str(behave),
            str(fdir),
            "--no-capture",
            "-D",
            f"port={server.grpc_port}",
            "-f",
            "json",
            "-o",
            str(json_path),
            "-f",
            "plain",
        ]
        t0 = time.time()
        timed_out = False
        with open(log_path, "wb") as fh:
            try:
                p = subprocess.run(
                    argv,
                    stdout=fh,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    env=env,
                    timeout=args.timeout,
                    cwd=str(run_dir),
                )
                rc = p.returncode
            except subprocess.TimeoutExpired:
                rc, timed_out = None, True
        row.update(
            {
                "argv": argv,
                "exit_code": rc,
                "timed_out": timed_out,
                "duration_seconds": round(time.time() - t0, 2),
                "raw_log": common.rel(log_path),
                "log_sha256": common.sha256_file(log_path),
                "structured_log": common.rel(json_path) if json_path.is_file() else None,
                "structured_log_sha256": (
                    common.sha256_file(json_path) if json_path.is_file() else None
                ),
                "server_alive_after_suite": server.alive(),
            }
        )
        if not server.alive():
            anomalies.append(f"{suite_id}: the TypeDB server died during the suite")
        rec = server.evidence()
        rec["suite_id"] = suite_id
        w = rec.get("backend_witness") or {}
        if w.get("marker_text"):
            marker = out_dir / f"backend-spec-{sid_flat}.marker"
            marker.write_text(w["marker_text"])
            w["archived_marker"] = common.rel(marker)
        if w.get("problem"):
            anomalies.append(f"{suite_id}: {w['problem']}")
        server.stop()
        rec["exit_code"] = server.returncode()
        shutil.copy(server.log_path, out_dir / f"server-{sid_flat}.log")
        rec["log"] = common.rel(out_dir / f"server-{sid_flat}.log")
        rec["log_sha256"] = common.sha256_file(out_dir / f"server-{sid_flat}.log")
        server_records.append(rec)

        if not json_path.is_file():
            row["status"] = "NO_STRUCTURED_OUTPUT"
            anomalies.append(
                f"{suite_id}: behave produced no JSON output - nothing can be joined at leaf level"
            )
            suite_rows.append(row)
            continue
        observed = parse_behave_json(json_path)
        expected = gherkin_leaves.enumerate_leaves(BEHAVIOUR / ref, ref)
        mine = sorted(e["leaf_case_id"] for e in expected)
        planned = sorted(k for k in plan["leaves"] if k.startswith(f"cucumber:{ref}::"))
        row["leaves_enumerated"] = len(expected)
        row["leaves_in_plan"] = len(planned)
        row["observed_scenarios"] = len(observed)
        row["status"] = "EXECUTED" if observed else "NO_SCENARIOS"
        if not observed:
            anomalies.append(f"{suite_id}: behave ran ZERO scenarios")
        if planned and mine != planned:
            anomalies.append(
                f"{suite_id}: independent enumeration of {ref} disagrees with the plan's leaf ids"
            )
        for lid in planned:
            ph = plan["leaves"][lid].get("source_hash")
            if ph and ph != row["feature_sha256"]:
                anomalies.append(f"{suite_id}: {ref} does not match the plan's pinned source hash")
                break
        obs_names = [o["display_name"] for o in observed]
        exp_names = [e["display_name"] for e in expected]
        if obs_names != exp_names:
            first = next(
                (i for i, (a, b) in enumerate(zip(exp_names, obs_names)) if a != b),
                min(len(exp_names), len(obs_names)),
            )
            anomalies.append(
                f"{suite_id}: observed scenario sequence != the sequence "
                f"enumerated from {ref} (expected {len(exp_names)}, observed "
                f"{len(obs_names)}; first divergence at {first}: "
                f"{exp_names[first : first + 1]} vs {obs_names[first : first + 1]})"
            )
        if rc not in (0, None):
            anomalies.append(f"{suite_id}: behave exited {rc}")
        for i, e in enumerate(expected):
            o = observed[i] if i < len(observed) else None
            lr = {
                "leaf_case_id": e["leaf_case_id"],
                "suite_id": suite_id,
                "feature_ref": ref,
                "display_name": e["display_name"],
                "feature_line": e["line"],
                "kind": e["kind"],
                "in_plan": e["leaf_case_id"] in plan["leaves"],
            }
            if o is None or o["display_name"] != e["display_name"]:
                lr.update(
                    {
                        "status": "NOT_RUN",
                        "reason": "no behave element at this position with this name",
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
                        "behave_location": o["location"],
                        "behave_raw_name": o["raw_name"],
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
    covered = [leaf for leaf in in_plan if leaf["status"] in ("PASSED", "FAILED", "SKIPPED")]
    passed = [leaf for leaf in in_plan if leaf["status"] == "PASSED"]
    counts = {}
    for leaf in leaf_rows:
        counts[leaf["status"]] = counts.get(leaf["status"], 0) + 1

    results = {
        "schema": "typedb-r2-driver-lane-v1",
        "harness": "python-behave-json",
        "statement": (
            "LEAF-LEVEL execution evidence for one official-driver plan row, "
            "produced by the OFFICIAL published typedb-driver wheel whose "
            "pure-Python modules are proven byte-identical to the locked "
            "TDRIVER tree, driving the upstream behave harness rebuilt from "
            "the upstream BUILD declarations."
        ),
        "row_id": f"driver:python:{backend}",
        "driver": "python",
        "backend": backend,
        "lane": args.lane,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "plan": {
            "path": common.rel(common.PLAN),
            "plan_root_declared": plan.get("plan_root"),
            "plan_root_recomputed": common.plan_root_of_body(plan),
            "sha256": common.sha256_file(common.PLAN),
        },
        "driver_artifact": prov,
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
        f"{len(passed)} passed, {len(anomalies)} anomaly(ies) -> "
        f"{'GREEN' if green else 'RED'}",
        file=sys.stderr,
    )
    return 0 if green else 1


if __name__ == "__main__":
    sys.exit(main())
