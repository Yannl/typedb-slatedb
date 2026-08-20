#!/usr/bin/env python3
"""INDEPENDENT read-only verifier for an official-driver lane evidence bundle.

Deliberately imports NOTHING from tools/drivers/. The duplication below is
the control: the producer derived the leaf rows, and this verifier re-derives
them from the archived BYTES with its own Gherkin enumerator, its own cucumber
output parser and its own root computation, so a defect - or a forgery - in
the producer cannot vouch for itself. What the two share is the documented
ALGORITHM (leaf id = `cucumber:<ref>::<scenario>[#ex<N>][@<k>]`; scenario
outcome = the cucumber writer's per-step marks; bundle root = sha256 over
sorted `rel\\0sha\\n` pairs of every consumed file), never the code.

Checks, all fail-closed:

  1. structure   - driver-results.json parses and carries the expected schema;
                   no duplicate leaf_case_id; no two suites naming one log.
  2. log binding - every suite's raw log exists inside the bundle and hashes
                   to the suite row's log_sha256; the same for every server
                   log. Unbound bytes are not evidence.
  3. reparse     - every log is re-parsed HERE, and the re-derived
                   per-scenario outcome sequence must equal the recorded leaf
                   rows exactly: same ids, same order, same status, same step
                   counts. A fabricated leaf row has no scenario block behind
                   it and dies here.
  4. corpus      - every feature file is re-enumerated HERE and must yield the
                   recorded leaf ids and display names; its sha256 must equal
                   the suite row's AND the qualification plan's pinned
                   source_hash. A corpus edited after the run is a mismatch.
  5. completeness- every plan leaf in the bundle's scope must have a leaf row;
                   a suite with zero scenarios and no [Summary] is refused
                   unless the bundle declares its exact precondition.
  6. server      - each recorded server carries a binary sha256, an argv, a
                   readiness probe series ending in a successful probe, and a
                   log that hash-binds. "The suite passed but nothing was
                   listening" cannot survive this.
  7. provenance  - sources/typedb-driver and sources/typedb-behaviour must be
                   clean and match the source-lock revision AND tree NOW; the
                   plan's self-declared root must recompute from its own body
                   and equal the root the bundle pinned.
  8. roots       - the bundle root recomputes and must equal the sidecar
                   manifest root, the verdict's bundle_root, and any
                   `COMPLETE <hex>` marker.
  9. verdict     - the GREEN/RED verdict is re-derived here from the
                   re-parsed leaf outcomes and compared with the recorded one.

Exit code: 0 only when there are zero anomalies (and, under --qualification,
only when the re-derived verdict is GREEN and a root-bound COMPLETE exists).

Usage:
  python3 tools/evidence/verify_drivers.py docs/evidence/G1/drivers/<bundle>
  python3 tools/evidence/verify_drivers.py BUNDLE --qualification
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys

DEFAULT_REPO = pathlib.Path(__file__).resolve().parents[2]
SCHEMA = "typedb-r2-driver-lane-v1"
# duplicated on purpose: the verifier must not import the
# producer's idea of which backend a profile requires
EXPECTED_BACKEND_KIND = {"U0": "classic", "U1": "classic",
                         "U2": "slatedb-r2"}


# ----------------------------------------------------------- own primitives

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def canon_sha256(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def bundle_rel(path, repo, bundle_dir):
    p = pathlib.Path(path).resolve()
    try:
        return p.relative_to(pathlib.Path(repo).resolve()).as_posix()
    except ValueError:
        pass
    try:
        return "<out>/" + p.relative_to(pathlib.Path(bundle_dir).resolve()).as_posix()
    except ValueError:
        return str(p)


def recompute_root(bundle_dir, files, repo):
    pairs = {}
    for f in files:
        f = pathlib.Path(f)
        if f.is_file():
            pairs[bundle_rel(f, repo, bundle_dir)] = sha256_file(f)
    h = hashlib.sha256()
    for r in sorted(pairs):
        h.update(r.encode() + b"\0" + pairs[r].encode() + b"\n")
    return h.hexdigest(), pairs


# ------------------------------------------- own Gherkin leaf re-enumeration

def reenumerate(feature_path, ref):
    """Independent re-derivation of (leaf_case_id, display_name) in run order."""
    lines = pathlib.Path(feature_path).read_text().splitlines()
    if any(re.match(r"^\s*Rule:", ln) for ln in lines):
        raise ValueError(f"{ref}: Rule: blocks are not supported by the "
                         f"upstream SingletonParser")
    out, seen = [], {}
    i, n = 0, len(lines)
    while i < n:
        s = lines[i].strip()
        m = re.match(r"^(Scenario Outline|Scenario Template|Scenario|Example):\s*(.*)$", s)
        if not m:
            i += 1
            continue
        keyword, name = m.group(1), m.group(2).strip()
        outline = keyword in ("Scenario Outline", "Scenario Template")
        rows, header, in_ex = [], None, False
        j = i + 1
        while j < n:
            t = lines[j].strip()
            if not t or t.startswith("#"):
                j += 1
                continue
            if re.match(r"^(Scenario|Scenario Outline|Scenario Template|Example|Feature|Rule|Background)\b", t):
                break
            if re.match(r"^(Examples|Scenarios):", t):
                in_ex, header = True, None
                j += 1
                continue
            if t.startswith("|") and in_ex:
                cells = [c.strip() for c in t.split("|")[1:-1]]
                if header is None:
                    header = cells
                else:
                    rows.append(dict(zip(header, cells)))
                j += 1
                continue
            if t.startswith("@"):
                j += 1
                continue
            in_ex, header = False, None
            j += 1

        def add(base, display):
            k = seen.get(base, 0) + 1
            seen[base] = k
            out.append({"leaf_case_id": base if k == 1 else f"{base}@{k}",
                        "display_name": display})

        if outline:
            for idx, row in enumerate(rows, start=1):
                disp = re.sub(r"<([^<>]+)>",
                              lambda mm: row.get(mm.group(1), mm.group(0)), name)
                add(f"cucumber:{ref}::{name}#ex{idx}", disp)
        else:
            add(f"cucumber:{ref}::{name}", name)
        i = j
    return out


# ------------------------------------------- own cucumber output re-parsing

def reparse_log(text):
    """-> (primary scenario records, summary dict or None, libtest dict or None)."""
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
    lines = text.splitlines()
    cut = next((i for i, ln in enumerate(lines)
                if ln.strip() == "[Summary]"), None)
    body = lines[:cut] if cut is not None else lines

    scen, cur = [], None
    for idx, ln in enumerate(body):
        mf = re.match(r"^Feature: (.*?) :: (.*)$", ln)
        if mf:
            if cur:
                scen.append(cur)
            cur = {"name": None, "p": 0, "f": 0, "s": 0, "hook": False,
                   "line": idx + 1}
            continue
        if cur is None:
            continue
        ms = re.match(r"^ {2}(?:Scenario Outline|Scenario Template|Scenario|Example): (.*)$", ln)
        if ms:
            cur["name"] = ms.group(1)
            continue
        if re.match(r"^\s*✘\s+Scenario's (before|after) hook failed", ln):
            cur["hook"] = True
            continue
        mst = re.match(r"^ {3}(✔>|✔|✘>|✘|\?>|\?)\s", ln)
        if mst:
            k = mst.group(1)[0]
            cur["p" if k == "✔" else "f" if k == "✘" else "s"] += 1
    if cur:
        scen.append(cur)

    for s in scen:
        s["status"] = ("FAILED" if (s["f"] or s["hook"]) else
                       "SKIPPED" if s["s"] else
                       "PASSED" if s["p"] else "EMPTY")

    summary = None
    if cut is not None:
        summary = {"parsing_errors": 0, "hook_errors": 0}
        for ln in lines[cut + 1:]:
            t = ln.strip()
            m = re.match(r"^(\d+) (features?|scenarios?|steps?|rules?)"
                         r"(?: \(([^)]*)\))?", t)
            if m:
                key = m.group(2).rstrip("s") + "s"
                st = {"total": int(m.group(1))}
                for num, what in re.findall(r"(\d+) (passed|skipped|failed)",
                                            m.group(3) or ""):
                    st[what] = int(num)
                summary[key] = st
            for num, what in re.findall(r"(\d+) (parsing errors?|hook errors?)", t):
                summary["parsing_errors" if what.startswith("parsing")
                        else "hook_errors"] += int(num)
    libtest = None
    for ln in lines:
        m = re.match(r"^test result: (\w+)\. (\d+) passed; (\d+) failed;", ln)
        if m:
            libtest = {"outcome": m.group(1), "passed": int(m.group(2)),
                       "failed": int(m.group(3))}
    return scen, summary, libtest


def reparse_behave(path):
    """Independent re-derivation of per-scenario outcomes from behave's own
    structured output. Duplicated on purpose: the producer's reading of this
    file must not be the only reading of it."""
    doc = json.loads(pathlib.Path(path).read_text())
    out = []
    for feat in doc:
        for el in feat.get("elements") or []:
            if el.get("type") != "scenario":
                continue
            steps = el.get("steps") or []
            p = f = sk = 0
            for st in steps:
                stat = ((st.get("result") or {}).get("status")) or "untested"
                if stat == "passed":
                    p += 1
                elif stat in ("failed", "undefined"):
                    f += 1
                else:
                    sk += 1
            name = re.sub(r"\s+--\s+@\d+\.\d+\s*.*$", "", el.get("name") or "")
            out.append({"name": name, "p": p, "f": f, "s": sk,
                        "status": (el.get("status") or "untested").upper(),
                        "line": el.get("location")})
    return out


def reparse_cucumberjs(path):
    """Independent re-derivation from cucumber-js's `message` NDJSON stream.
    Only first attempts are counted, so a retry cannot inflate the census."""
    pickles, cases, started, steps = {}, {}, [], {}
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
        elif "testStepFinished" in m:
            steps.setdefault(m["testStepFinished"]["testCaseStartedId"],
                             []).append(
                (m["testStepFinished"]["testStepResult"] or {}).get("status"))
    out = []
    for st in started:
        if st.get("attempt", 0) != 0:
            continue
        pk = pickles.get((cases.get(st.get("testCaseId")) or {}).get("pickleId")) or {}
        sts = steps.get(st["id"], [])
        bad = [x for x in sts if x in ("FAILED", "UNDEFINED", "AMBIGUOUS")]
        status = ("FAILED" if bad else
                  "SKIPPED" if sts and all(x in ("SKIPPED", "PENDING")
                                           for x in sts) else
                  "PASSED" if sts else "EMPTY")
        out.append({"name": pk.get("name"), "status": status,
                    "p": sum(1 for x in sts if x == "PASSED"),
                    "f": len(bad),
                    "s": sum(1 for x in sts if x in ("SKIPPED", "PENDING")),
                    "line": pk.get("uri"),
                    "undefined": any(x in ("UNDEFINED", "AMBIGUOUS")
                                     for x in sts)})
    return out


def console_scenario_tally(text, harness):
    """The scenario tally the harness printed to its CONSOLE log.

    The console log and the machine-readable stream are two artefacts written
    by the SAME process. Requiring them to agree is what stops a fabricated
    structured stream (or a suite that never started but whose structured
    stream was written by hand) from passing: the forger has to lie
    consistently in two formats, and the console format carries the
    harness's own independently computed totals.

    Returns {'passed':n,'failed':n,'skipped':n} or None when the log carries
    no summary at all - which is itself reported by the caller.
    """
    if harness == "python-behave-json":
        m = re.search(r"^(\d+) scenarios? passed, (\d+) failed, (\d+) skipped",
                      text, re.M)
        if not m:
            return None
        return {"passed": int(m.group(1)), "failed": int(m.group(2)),
                "skipped": int(m.group(3))}
    if harness == "typescript-cucumberjs-messages":
        m = re.search(r"^(\d+) scenarios? \(([^)]*)\)", text, re.M)
        if not m:
            return None
        out = {"passed": 0, "failed": 0, "skipped": 0, "undefined": 0,
               "ambiguous": 0, "pending": 0}
        for n, what in re.findall(r"(\d+) (passed|failed|skipped|undefined|"
                                  r"ambiguous|pending)", m.group(2)):
            out[what] = int(n)
        return {"passed": out["passed"],
                "failed": out["failed"] + out["undefined"] + out["ambiguous"],
                "skipped": out["skipped"] + out["pending"]}
    return None


# ---------------------------------------------------------------- verifying

def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, check=False)


def verify(bundle_dir, repo, qualification=False):
    bundle_dir = pathlib.Path(bundle_dir).resolve()
    repo = pathlib.Path(repo).resolve()
    A = []          # anomalies
    W = []          # warnings

    rf = bundle_dir / "driver-results.json"
    if not rf.is_file():
        return {"anomalies": [f"{bundle_dir}: no driver-results.json"],
                "warnings": [], "verified": False, "qualification_pass": False}
    try:
        data = json.loads(rf.read_text())
    except json.JSONDecodeError as e:
        return {"anomalies": [f"driver-results.json does not parse: {e}"],
                "warnings": [], "verified": False, "qualification_pass": False}

    if data.get("schema") != SCHEMA:
        A.append(f"schema is {data.get('schema')!r}, expected {SCHEMA!r}")

    suites = data.get("suites") or []
    leaves = data.get("leaves") or []

    # ---- 1 structure
    ids = [l["leaf_case_id"] for l in leaves]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        A.append(f"duplicate leaf_case_id in the results: {dupes[:5]}")
    logs = [s.get("raw_log") for s in suites if s.get("raw_log")]
    if len(set(logs)) != len(logs):
        A.append("two suite rows name the same raw log file")

    # ---- 2 log binding (+ server logs)
    def bind(path, expect_sha, what):
        # A bundle must verify WHEREVER it is checked out, so the recorded
        # repo-relative path is treated as a claim, not as the locator: the
        # log is resolved by basename inside the bundle directory first, and
        # the resolved file must then live inside the bundle. That is what
        # makes an archive relocatable and a log outside the bundle a refusal.
        if not path:
            A.append(f"{what}: no log path recorded")
            return None
        name = pathlib.Path(path).name
        cand = bundle_dir / name
        p = cand if cand.is_file() else (
            (repo / path) if not pathlib.Path(path).is_absolute()
            else pathlib.Path(path))
        try:
            p.resolve().relative_to(bundle_dir)
        except ValueError:
            A.append(f"{what}: log {path} lives outside the bundle directory")
        if not p.is_file():
            A.append(f"{what}: log {path} does not exist")
            return None
        got = sha256_file(p)
        if expect_sha and got != expect_sha:
            A.append(f"{what}: log {path} hashes to {got} but the row records "
                     f"{expect_sha} - the bytes changed after the run")
        elif not expect_sha:
            A.append(f"{what}: row records no log_sha256; unbound bytes are not "
                     f"evidence")
        return p

    # ---- 3/4/5 reparse + re-enumerate + completeness
    plan_path = repo / (data.get("plan", {}).get("path")
                        or "docs/evidence/G1/qualification-plan-v2.json")
    plan = None
    if plan_path.is_file():
        plan = json.loads(plan_path.read_text())
        recomputed = canon_sha256({k: v for k, v in plan.items()
                                   if k != "plan_root"})
        if recomputed != plan.get("plan_root"):
            A.append(f"plan {plan_path.name}: self-declared plan_root "
                     f"{plan.get('plan_root')} does not recompute from its own "
                     f"body ({recomputed}) - forged plan")
        pinned = data.get("plan", {}).get("plan_root_declared")
        if pinned and pinned != plan.get("plan_root"):
            A.append(f"bundle pinned plan_root {pinned} but the plan now "
                     f"declares {plan.get('plan_root')}")
    else:
        A.append(f"qualification plan not found at {plan_path}")

    harness = data.get("harness", "rust-cucumber-basic")
    if harness not in ("rust-cucumber-basic", "python-behave-json",
                       "typescript-cucumberjs-messages"):
        A.append(f"unknown harness {harness!r}: this verifier re-derives only "
                 f"the harnesses it implements, and refuses what it cannot "
                 f"re-derive")

    if harness == "python-behave-json":
        # The Python lane runs the OFFICIAL published wheel because the SWIG
        # wrapper is a Bazel output. That is only acceptable if the wheel is
        # proven to be the locked driver, so the provenance section is checked
        # here rather than trusted: no differing module, no missing module,
        # the version must equal the locked VERSION file, and the comparison
        # must have covered EVERY module in the locked tree (a comparison that
        # silently skipped files would otherwise read as agreement).
        prov = data.get("driver_artifact") or {}
        if not prov:
            A.append("python lane records no driver artifact provenance")
        else:
            if prov.get("differing_from_locked_source"):
                A.append(f"wheel differs from the locked driver tree in "
                         f"{len(prov['differing_from_locked_source'])} module(s)")
            if prov.get("only_in_locked_source"):
                A.append(f"wheel is missing locked driver modules: "
                         f"{prov['only_in_locked_source'][:5]}")
            vfile = (repo / "sources" / "typedb-driver" / "VERSION")
            locked_version = vfile.read_text().strip() if vfile.is_file() else None
            if (prov.get("metadata") or {}).get("Version") != locked_version:
                A.append(f"installed driver version "
                         f"{(prov.get('metadata') or {}).get('Version')!r} != "
                         f"locked VERSION {locked_version!r}")
            locked_modules = len(list(
                (repo / "sources" / "typedb-driver" / "python" / "typedb")
                .rglob("*.py")))
            if prov.get("identical_to_locked_source") != locked_modules:
                A.append(f"the wheel/source comparison covered "
                         f"{prov.get('identical_to_locked_source')} module(s) "
                         f"but the locked tree has {locked_modules} - the "
                         f"comparison was not exhaustive")
            for f in prov.get("only_in_wheel_nonempty") or []:
                if f.get("file") != "native_driver_wrapper.py":
                    A.append(f"wheel carries non-empty module "
                             f"{f.get('file')!r} absent from the locked tree")

    leaves_by_suite = {}
    for l in leaves:
        leaves_by_suite.setdefault(l.get("suite_id"), []).append(l)

    rederived_status = {}
    for s in suites:
        sid = s.get("suite_id")
        ref = s.get("feature_ref")
        status = s.get("status")
        if status == "NOT_BUILT":
            A.append(f"{sid}: suite was never built")
            continue
        if status == "NOT_EXECUTED_PRECONDITION_UNMET":
            # A blocked suite is legitimate ONLY if it names its exact external
            # precondition. It may have produced a log (a suite that started
            # and self-skipped) or none at all (a suite that was never
            # launched); either way it must carry no scenario blocks.
            if not s.get("precondition"):
                A.append(f"{sid}: declared not-executed but records no "
                         f"precondition; a blocked row must name its exact "
                         f"external precondition")
            if s.get("raw_log"):
                p = bind(s.get("raw_log"), s.get("log_sha256"), f"suite {sid}")
                if p is not None:
                    scen, _sm, _lt = reparse_log(p.read_text(errors="replace"))
                    if scen:
                        A.append(f"{sid}: declared not-executed but its log "
                                 f"carries {len(scen)} scenario block(s)")
            continue
        p = bind(s.get("raw_log"), s.get("log_sha256"), f"suite {sid}")
        if p is None:
            continue
        text = p.read_text(errors="replace")
        if not text.strip():
            A.append(f"{sid}: raw log is empty - an empty log is never evidence")
        if harness in ("python-behave-json", "typescript-cucumberjs-messages"):
            jp = bind(s.get("structured_log"), s.get("structured_log_sha256"),
                      f"suite {sid} structured log")
            if jp is None:
                A.append(f"{sid}: no structured output to re-derive from")
                continue
            scen = (reparse_behave(jp) if harness == "python-behave-json"
                    else reparse_cucumberjs(jp))
            summary, libtest = None, None
            console = console_scenario_tally(text, harness)
            if console is None:
                A.append(f"{sid}: the console log carries no scenario summary - "
                         f"the structured stream is then the only account of "
                         f"the run and nothing corroborates it")
            else:
                tally = {"passed": 0, "failed": 0, "skipped": 0}
                for sc in scen:
                    tally[{"PASSED": "passed", "FAILED": "failed",
                           "SKIPPED": "skipped",
                           "EMPTY": "failed"}[sc["status"]]] += 1
                if tally != console:
                    A.append(f"{sid}: the console log's own scenario tally "
                             f"{console} disagrees with the structured stream "
                             f"re-derived here {tally} - the two artefacts the "
                             f"run produced do not describe the same run")
            if harness == "typescript-cucumberjs-messages":
                und = sum(1 for x in scen if x.get("undefined"))
                if und:
                    A.append(f"{sid}: {und} scenario(s) contain undefined or "
                             f"ambiguous steps in the re-parsed message stream")
        else:
            scen, summary, libtest = reparse_log(text)

        if not scen:
            A.append(f"{sid}: re-parse finds ZERO cucumber scenarios in the log "
                     f"- a suite that ran nothing proves nothing")
        if summary is None and harness == "rust-cucumber-basic":
            A.append(f"{sid}: re-parse finds no [Summary] - truncated run")
        elif summary is not None:
            for key in ("features", "scenarios"):
                tot = (summary.get(key) or {}).get("total")
                if tot != len(scen):
                    A.append(f"{sid}: [Summary] declares {tot} {key} but the "
                             f"log carries {len(scen)} scenario block(s)")
            tally = {"passed": 0, "failed": 0, "skipped": 0}
            for sc in scen:
                tally[{"PASSED": "passed", "FAILED": "failed",
                       "SKIPPED": "skipped", "EMPTY": "failed"}[sc["status"]]] += 1
            decl = summary.get("scenarios") or {}
            for k in ("passed", "failed", "skipped"):
                if decl.get(k, 0) != tally[k]:
                    A.append(f"{sid}: re-derived {tally[k]} {k} but [Summary] "
                             f"declares {decl.get(k, 0)}")
            if summary.get("parsing_errors") or summary.get("hook_errors"):
                A.append(f"{sid}: cucumber reported parsing/hook errors")
        if (libtest is None and harness == "rust-cucumber-basic"
                and not s.get("timed_out")):
            A.append(f"{sid}: no libtest result line - the process never "
                     f"finished its test case")
        elif libtest is not None and (libtest["outcome"] == "ok") != (
                s.get("exit_code") == 0):
            A.append(f"{sid}: libtest says {libtest['outcome']!r} but the row "
                     f"records exit_code {s.get('exit_code')}")

        # corpus re-enumeration
        feature = repo / "sources" / "typedb-behaviour" / (ref or "")
        if not feature.is_file():
            A.append(f"{sid}: feature file {ref} not found")
            continue
        fsha = sha256_file(feature)
        if s.get("feature_sha256") != fsha:
            A.append(f"{sid}: {ref} hashes to {fsha} but the row records "
                     f"{s.get('feature_sha256')}")
        if plan:
            for lid in [k for k in plan["leaves"]
                        if k.startswith(f"cucumber:{ref}::")]:
                ph = plan["leaves"][lid].get("source_hash")
                if ph and ph != fsha:
                    A.append(f"{sid}: {ref} does not match the source_hash the "
                             f"plan pinned ({ph})")
                    break
        expected = reenumerate(feature, ref)
        recorded = leaves_by_suite.get(sid, [])
        if [e["leaf_case_id"] for e in expected] != [r["leaf_case_id"] for r in recorded]:
            A.append(f"{sid}: recorded leaf ids do not equal an independent "
                     f"re-enumeration of {ref} "
                     f"({len(recorded)} recorded vs {len(expected)} enumerated)")
        # positional join of executed leaves onto re-parsed scenario blocks
        run_rows = [r for r in recorded
                    if r.get("status") in ("PASSED", "FAILED", "SKIPPED", "EMPTY")]
        # SKIPPED_IGNORED_TAG rows were filtered out by the driver's own tag
        # expression before cucumber ever saw them; they are recorded, never
        # counted as executed, and must NOT be expected in the log.
        if len(run_rows) != len(scen):
            A.append(f"{sid}: {len(run_rows)} leaf row(s) claim an executed "
                     f"outcome but the log carries {len(scen)} scenario "
                     f"block(s) - fabricated or lost rows")
        exp_by_id = {e["leaf_case_id"]: e["display_name"] for e in expected}
        for r, sc in zip(run_rows, scen):
            if sc["name"] != r.get("display_name"):
                A.append(f"{sid}: leaf {r['leaf_case_id']} records display name "
                         f"{r.get('display_name')!r} but the log's block at "
                         f"line {sc['line']} names {sc['name']!r}")
            if exp_by_id.get(r["leaf_case_id"]) != r.get("display_name"):
                A.append(f"{sid}: leaf {r['leaf_case_id']} display name does not "
                         f"match the re-enumerated corpus")
            if sc["status"] != r.get("status"):
                A.append(f"{sid}: leaf {r['leaf_case_id']} records status "
                         f"{r.get('status')} but the log re-parses to "
                         f"{sc['status']}")
            for key, got in (("steps_passed", sc["p"]), ("steps_failed", sc["f"]),
                             ("steps_skipped", sc["s"])):
                if r.get(key) is not None and r[key] != got:
                    A.append(f"{sid}: leaf {r['leaf_case_id']} records {key}="
                             f"{r[key]} but the log re-parses to {got}")
            rederived_status[r["leaf_case_id"]] = sc["status"]

    # ---- 5 completeness against the plan
    if plan:
        scope = set()
        for s in suites:
            ref = s.get("feature_ref")
            scope |= {k for k in plan["leaves"]
                      if k.startswith(f"cucumber:{ref}::")}
        produced = {l["leaf_case_id"] for l in leaves}
        missing = sorted(scope - produced)
        if missing:
            A.append(f"{len(missing)} plan leaf/leaves in scope have no leaf row "
                     f"({missing[:3]})")
        for l in leaves:
            if l.get("in_plan") and l["leaf_case_id"] not in plan["leaves"]:
                A.append(f"leaf {l['leaf_case_id']} claims in_plan but the plan "
                         f"has no such leaf - fabricated plan membership")
            if not l.get("in_plan") and l["leaf_case_id"] in plan["leaves"]:
                A.append(f"leaf {l['leaf_case_id']} is in the plan but the row "
                         f"says in_plan=false")

    # ---- 6 servers
    servers = data.get("servers") or []
    if not servers:
        A.append("no server record at all - a driver suite with no server "
                 "behind it did not test a product")
    covered_suites = {s.get("suite_id") for s in servers if s.get("suite_id")}
    executed = {s["suite_id"] for s in suites if s.get("status") == "EXECUTED"}
    if covered_suites and not executed <= covered_suites:
        A.append(f"executed suites with no server record: "
                 f"{sorted(executed - covered_suites)}")
    for srv in servers:
        tag = f"server[{srv.get('suite_id') or srv.get('lane')}]"
        if not srv.get("binary_sha256"):
            A.append(f"{tag}: no binary sha256 recorded")
        if not srv.get("argv"):
            A.append(f"{tag}: no argv recorded")
        probes = srv.get("ready_probes") or []
        if not probes:
            A.append(f"{tag}: no readiness probes recorded - readiness was "
                     f"assumed, not observed")
        else:
            last = probes[-1]
            if not (last.get("health_status") == 204
                    and last.get("version_status") == 200
                    and last.get("grpc_accepts")):
                A.append(f"{tag}: the last readiness probe is not a success "
                         f"({json.dumps(last)[:200]}) - the suite ran against a "
                         f"server that was never proven up")
        if srv.get("version_endpoint") in (None, {}):
            A.append(f"{tag}: no /v1/version document recorded")
        bind(srv.get("log"), srv.get("log_sha256"), tag)
        ident = srv.get("checkout") or {}
        if ident.get("dirty") is None:
            A.append(f"{tag}: server checkout dirt is UNKNOWN - never read as "
                     f"clean")
        # the storage backend the server actually BUILT, re-read from the
        # archived on-disk marker bytes. A `slatedb` plan row backed only by
        # `TYPEDB_STORAGE_PROFILE=U2` in the environment would be
        # indistinguishable from a run in which the profile was ignored.
        expect = EXPECTED_BACKEND_KIND.get(srv.get("storage_profile_env"))
        w = srv.get("backend_witness") or {}
        if expect is None:
            A.append(f"{tag}: storage profile "
                     f"{srv.get('storage_profile_env')!r} has no known backend "
                     f"expectation")
        elif not w:
            A.append(f"{tag}: no backend witness - the backend the server built "
                     f"was never observed, only requested")
        else:
            if w.get("problem"):
                A.append(f"{tag}: {w['problem']}")
            am = w.get("archived_marker")
            if not am:
                A.append(f"{tag}: the backend-spec marker was not archived into "
                         f"the bundle; an unarchived witness is not evidence")
            else:
                mp = bundle_dir / pathlib.Path(am).name
                if not mp.is_file():
                    A.append(f"{tag}: archived backend-spec marker {am} is "
                             f"missing from the bundle")
                else:
                    raw = mp.read_bytes()
                    if hashlib.sha256(raw).hexdigest() != w.get("marker_sha256"):
                        A.append(f"{tag}: archived backend-spec marker does not "
                                 f"hash to the recorded marker_sha256")
                    kind = None
                    for line in raw.decode(errors="replace").splitlines():
                        parts = line.split(None, 1)
                        if len(parts) == 2 and parts[0] == "kind":
                            kind = parts[1].strip()
                    if kind != expect:
                        A.append(f"{tag}: archived backend-spec marker says "
                                 f"kind={kind!r} but profile "
                                 f"{srv.get('storage_profile_env')} requires "
                                 f"{expect!r}")

    # ---- 7 provenance of the locked sources
    lock_path = repo / "source-lock" / "source-lock.json"
    lock = json.loads(lock_path.read_text()) if lock_path.is_file() else {"nodes": []}
    nodes = {n["id"]: n for n in lock.get("nodes", [])}
    for node_id, sub, key in (("TDRIVER", "sources/typedb-driver", "resolved_revision"),
                              ("BH", "sources/typedb-behaviour", "revision")):
        n = nodes.get(node_id)
        path = repo / sub
        if n is None:
            A.append(f"source-lock has no node {node_id}")
            continue
        rev = git(path, "rev-parse", "HEAD").stdout.strip()
        tree = git(path, "rev-parse", "HEAD^{tree}").stdout.strip()
        st = git(path, "status", "--porcelain").stdout.strip()
        if rev != n.get(key):
            A.append(f"{sub}: HEAD {rev} != locked {n.get(key)}")
        if tree != n.get("tree"):
            A.append(f"{sub}: tree {tree} != locked {n.get('tree')}")
        if st:
            A.append(f"{sub}: checkout is DIRTY ({len(st.splitlines())} path(s)) "
                     f"- executed bytes are not the locked bytes")

    # ---- 8 roots
    def resolve_consumed(rel):
        cand = bundle_dir / pathlib.Path(rel).name
        return cand if cand.is_file() else (repo / rel)

    consumed = [rf]
    if plan_path.is_file():
        consumed.append(plan_path)
    consumed += [resolve_consumed(s["raw_log"]) for s in suites if s.get("raw_log")]
    consumed += [resolve_consumed(s["structured_log"]) for s in suites
                 if s.get("structured_log")]
    consumed += [resolve_consumed(s["log"]) for s in servers if s.get("log")]
    consumed += [resolve_consumed((s.get("backend_witness") or {})["archived_marker"])
                 for s in servers
                 if (s.get("backend_witness") or {}).get("archived_marker")]
    # build artefacts some harnesses archive alongside the results
    for extra in ("npm-tree.json", "tsc.log"):
        if (bundle_dir / extra).is_file():
            consumed.append(bundle_dir / extra)
    root, _pairs = recompute_root(bundle_dir, consumed, repo)
    manifest = bundle_dir / "bundle-manifest.json"
    if manifest.is_file():
        mroot = json.loads(manifest.read_text()).get("bundle_root")
        if mroot != root:
            A.append(f"recomputed bundle root {root} != sidecar manifest root "
                     f"{mroot} - a consumed file changed after sealing")
    else:
        W.append("no bundle-manifest.json sidecar")

    vpath = bundle_dir / "verdict.json"
    recorded_verdict = None
    if vpath.is_file():
        recorded_verdict = json.loads(vpath.read_text())
        if recorded_verdict.get("policy_verdict") not in ("GREEN", "RED"):
            A.append(f"verdict policy_verdict is "
                     f"{recorded_verdict.get('policy_verdict')!r}, not in "
                     f"{{GREEN,RED}} - forged or foreign verdict")
        if recorded_verdict.get("bundle_root") != root:
            A.append(f"verdict records bundle_root "
                     f"{recorded_verdict.get('bundle_root')} but the bundle "
                     f"recomputes to {root}")
    else:
        W.append("no verdict.json in the bundle")

    marker = bundle_dir / "COMPLETE"
    sealed = False
    if marker.is_file():
        m = re.match(r"^COMPLETE ([0-9a-f]{64})\s*$",
                     (marker.read_text().splitlines() or [""])[0])
        if not m:
            A.append("COMPLETE marker carries no bundle root")
        elif m.group(1) != root:
            A.append(f"COMPLETE binds root {m.group(1)} but the bundle "
                     f"recomputes to {root} - modified after sealing")
        else:
            sealed = True
    else:
        W.append("no COMPLETE marker - this bundle was never sealed green")

    # ---- 9 independently re-derived verdict
    executed_rows = [l for l in leaves if l.get("in_plan")
                     and l.get("status") in ("PASSED", "FAILED", "SKIPPED", "EMPTY")]
    passed_rows = [l for l in executed_rows
                   if rederived_status.get(l["leaf_case_id"]) == "PASSED"]
    rederived_green = (not A and bool(executed_rows)
                       and len(passed_rows) == len(executed_rows))
    if recorded_verdict is not None:
        rec_green = recorded_verdict.get("policy_verdict") == "GREEN"
        if rec_green and not rederived_green:
            A.append("recorded verdict is GREEN but this verifier re-derives "
                     "RED from the archived bytes")

    for c in (data.get("caveats") or []):
        if not c.get("detail"):
            A.append(f"caveat {c.get('id')!r} carries no detail; a caveat "
                     f"without an explanation is a hidden gap")
        W.append(f"declared caveat: {c.get('id')} - {(c.get('detail') or '')[:200]}")

    out = {
        "bundle": str(bundle_dir),
        "declared_caveats": [c.get("id") for c in (data.get("caveats") or [])],
        "row_id": data.get("row_id"),
        "recomputed_bundle_root": root,
        "sealed_complete": sealed,
        "leaf_rows": len(leaves),
        "leaf_rows_in_plan": sum(1 for l in leaves if l.get("in_plan")),
        "rederived_executed_leaves": len(executed_rows),
        "rederived_passed_leaves": len(passed_rows),
        "rederived_verdict": "GREEN" if rederived_green else "RED",
        "recorded_verdict": (recorded_verdict or {}).get("policy_verdict"),
        "anomalies": A,
        "warnings": W,
        "verified": not A,
        "qualification_pass": bool(not A and rederived_green and sealed),
    }
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("bundle", type=pathlib.Path)
    ap.add_argument("--repo", type=pathlib.Path, default=DEFAULT_REPO)
    ap.add_argument("--qualification", "--strict", dest="qualification",
                    action="store_true")
    args = ap.parse_args()
    rep = verify(args.bundle, args.repo, args.qualification)
    print(json.dumps(rep, indent=1))
    bad = bool(rep["anomalies"]) or (args.qualification
                                     and not rep["qualification_pass"])
    print(f"VERIFY {rep.get('row_id')}: {len(rep['anomalies'])} anomaly(ies), "
          f"re-derived {rep.get('rederived_verdict')}, "
          f"{'sealed' if rep.get('sealed_complete') else 'UNSEALED'}",
          file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
