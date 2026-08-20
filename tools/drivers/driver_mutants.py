#!/usr/bin/env python3
"""Negative controls for the official-driver evidence lane.

A runner that can only ever print GREEN is worthless. This harness takes a
REAL driver-lane bundle, mutates it the way a forged or broken run would look,
and requires tools/evidence/verify_drivers.py to REFUSE each one. A mutant
that survives is a hole in the evidence chain and fails this tool.

Two sophistication levels are exercised deliberately:

  NAIVE        - the file is edited and nothing else. Killed by the hash
                 bindings and the bundle root alone.
  RESEALED     - the forger also rewrites every log_sha256, recomputes the
                 bundle root, and rewrites bundle-manifest.json, verdict.json
                 and the COMPLETE marker, exactly as the producer would. These
                 are the mutants that matter: they can only be killed by
                 RE-DERIVING the leaf outcomes from the archived bytes.

Mutants:
  empty_result_file      driver-results.json emptied
  empty_log              one suite's raw log truncated to zero bytes
  truncated_run          one suite's log cut before its cucumber [Summary]
  suite_never_started    one suite's log replaced by the libtest preamble only
  fabricated_leaf_row    a PASSED leaf row invented for a scenario that has no
                         block in any log
  dropped_leaf_rows      one suite's leaf rows deleted from the results
  flipped_leaf_status    one PASSED leaf row rewritten to FAILED
  forged_step_counts     one leaf row's step counts inflated
  forged_plan_membership an out-of-plan leaf row marked in_plan
  forged_feature_hash    the recorded corpus hash no longer matches the corpus
  server_never_booted    the server record's readiness probes stripped
  server_probe_failed    the last readiness probe rewritten to a failure
  forged_verdict_enum    policy_verdict set to a value outside {GREEN,RED}
  unsealed_edit          results edited, COMPLETE left binding the old root

Usage:
  python3 tools/drivers/driver_mutants.py --bundle docs/evidence/G1/drivers/<b>
  python3 tools/drivers/driver_mutants.py --bundle B --only truncated_run
"""
import argparse
import copy
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import common  # noqa: E402

REPO = common.REPO
VERIFIER = REPO / "tools" / "evidence" / "verify_drivers.py"


# --------------------------------------------------------------- mutant kit

def load(bundle):
    return json.loads((bundle / "driver-results.json").read_text())


def save(bundle, data):
    (bundle / "driver-results.json").write_text(json.dumps(data, indent=1) + "\n")


def log_path(bundle, rel):
    """Map a repo-relative raw_log recorded in the results onto THIS copy of
    the bundle (mutants live in a temp dir)."""
    return bundle / pathlib.Path(rel).name


def reseal(bundle, data):
    """What a competent forger would do: re-hash every log the results name,
    recompute the bundle root over the same consumed set, and rewrite the
    manifest, the verdict and the COMPLETE marker so every binding is
    internally consistent again."""
    for s in data.get("suites", []):
        if s.get("raw_log"):
            p = log_path(bundle, s["raw_log"])
            if p.is_file():
                s["log_sha256"] = common.sha256_file(p)
                s["log_bytes"] = p.stat().st_size
    for srv in data.get("servers", []):
        if srv.get("log"):
            p = log_path(bundle, srv["log"])
            if p.is_file():
                srv["log_sha256"] = common.sha256_file(p)
    save(bundle, data)
    consumed = [bundle / "driver-results.json", common.PLAN]
    consumed += [log_path(bundle, s["raw_log"])
                 for s in data.get("suites", []) if s.get("raw_log")]
    consumed += [log_path(bundle, s["log"])
                 for s in data.get("servers", []) if s.get("log")]
    root, pairs = common.compute_bundle_root(bundle, consumed)
    (bundle / "bundle-manifest.json").write_text(json.dumps(
        {"schema": "driver-lane-bundle-manifest-v1", "bundle_root": root,
         "files": dict(sorted(pairs.items()))}, indent=1) + "\n")
    v = json.loads((bundle / "verdict.json").read_text())
    v["bundle_root"] = root
    v["green"] = True
    v["policy_verdict"] = "GREEN"
    v["anomaly_count"] = 0
    v["anomalies"] = []
    (bundle / "verdict.json").write_text(json.dumps(v, indent=1) + "\n")
    (bundle / "COMPLETE").write_text(f"COMPLETE {root}\n")
    return root


def _first_executed_suite(data):
    for s in data.get("suites", []):
        if s.get("status") == "EXECUTED" and s.get("raw_log"):
            return s
    raise RuntimeError("bundle has no executed suite to mutate")


# ------------------------------------------------------------------ mutants

def m_empty_result_file(bundle, data):
    (bundle / "driver-results.json").write_text("")
    return "NAIVE"


def m_empty_log(bundle, data):
    s = _first_executed_suite(data)
    log_path(bundle, s["raw_log"]).write_text("")
    return "NAIVE"


def m_truncated_run(bundle, data):
    s = _first_executed_suite(data)
    p = log_path(bundle, s["raw_log"])
    lines = p.read_text().splitlines()
    cut = next(i for i, ln in enumerate(lines) if ln.strip() == "[Summary]")
    p.write_text("\n".join(lines[:cut - 20]) + "\n")
    reseal(bundle, data)
    return "RESEALED"


def m_suite_never_started(bundle, data):
    s = _first_executed_suite(data)
    log_path(bundle, s["raw_log"]).write_text("\nrunning 1 test\n")
    reseal(bundle, data)
    return "RESEALED"


def m_fabricated_leaf_row(bundle, data):
    s = _first_executed_suite(data)
    tmpl = next(l for l in data["leaves"] if l["suite_id"] == s["suite_id"])
    fake = copy.deepcopy(tmpl)
    fake["leaf_case_id"] = tmpl["leaf_case_id"] + "#FABRICATED"
    fake["display_name"] = "a scenario that never ran"
    fake["status"] = "PASSED"
    fake["in_plan"] = True
    data["leaves"].append(fake)
    data["counts"]["leaf_rows"] += 1
    reseal(bundle, data)
    return "RESEALED"


def m_dropped_leaf_rows(bundle, data):
    s = _first_executed_suite(data)
    data["leaves"] = [l for l in data["leaves"] if l["suite_id"] != s["suite_id"]]
    reseal(bundle, data)
    return "RESEALED"


def m_flipped_leaf_status(bundle, data):
    l = next(l for l in data["leaves"] if l.get("status") == "PASSED")
    l["status"] = "FAILED"
    reseal(bundle, data)
    return "RESEALED"


def m_forged_step_counts(bundle, data):
    l = next(l for l in data["leaves"] if l.get("steps_passed"))
    l["steps_passed"] = l["steps_passed"] + 7
    reseal(bundle, data)
    return "RESEALED"


def m_forged_plan_membership(bundle, data):
    l = next((l for l in data["leaves"] if not l.get("in_plan")), None)
    if l is None:
        raise RuntimeError("bundle has no out-of-plan leaf to promote")
    l["in_plan"] = True
    reseal(bundle, data)
    return "RESEALED"


def m_forged_feature_hash(bundle, data):
    s = _first_executed_suite(data)
    s["feature_sha256"] = "0" * 64
    reseal(bundle, data)
    return "RESEALED"


def m_server_never_booted(bundle, data):
    if not data.get("servers"):
        raise RuntimeError("bundle records no server")
    data["servers"][0]["ready_probes"] = []
    data["servers"][0]["ready_after_seconds"] = None
    reseal(bundle, data)
    return "RESEALED"


def m_server_probe_failed(bundle, data):
    if not data.get("servers"):
        raise RuntimeError("bundle records no server")
    probes = data["servers"][0].get("ready_probes") or [{}]
    probes[-1] = {"t": 1.0, "error": "ConnectionRefusedError: [Errno 111]"}
    data["servers"][0]["ready_probes"] = probes
    reseal(bundle, data)
    return "RESEALED"


def m_forged_verdict_enum(bundle, data):
    v = json.loads((bundle / "verdict.json").read_text())
    v["policy_verdict"] = "TOTAL_QUALITY_PASS"
    (bundle / "verdict.json").write_text(json.dumps(v, indent=1) + "\n")
    return "NAIVE"


def m_unsealed_edit(bundle, data):
    data["counts"]["plan_leaves_passed"] = 999999
    save(bundle, data)          # deliberately NOT resealed
    return "NAIVE"


MUTANTS = {
    "empty_result_file": m_empty_result_file,
    "empty_log": m_empty_log,
    "truncated_run": m_truncated_run,
    "suite_never_started": m_suite_never_started,
    "fabricated_leaf_row": m_fabricated_leaf_row,
    "dropped_leaf_rows": m_dropped_leaf_rows,
    "flipped_leaf_status": m_flipped_leaf_status,
    "forged_step_counts": m_forged_step_counts,
    "forged_plan_membership": m_forged_plan_membership,
    "forged_feature_hash": m_forged_feature_hash,
    "server_never_booted": m_server_never_booted,
    "server_probe_failed": m_server_probe_failed,
    "forged_verdict_enum": m_forged_verdict_enum,
    "unsealed_edit": m_unsealed_edit,
}


def shadow_repo(td, src_bundle):
    """A throwaway repo layout that mirrors the real one closely enough that a
    mutated COPY of the bundle verifies under exactly the production rules.

    `sources/` and `source-lock/` are symlinked (they are read-only inputs the
    verifier only reads and runs git against); the qualification plan and the
    bundle itself are real copies at their real repo-relative paths, so the
    bundle root - which is computed over repo-relative names - comes out
    identical to production. Testing a mutant against a bundle whose every
    path had shifted would only ever prove that the paths shifted.
    """
    root = pathlib.Path(td) / "repo"
    (root / "docs" / "evidence" / "G1" / "drivers").mkdir(parents=True)
    for link in ("sources", "source-lock"):
        (root / link).symlink_to(REPO / link)
    shutil.copy(common.PLAN, root / "docs" / "evidence" / "G1" / common.PLAN.name)
    work = root / "docs" / "evidence" / "G1" / "drivers" / src_bundle.name
    shutil.copytree(src_bundle, work)
    return root, work


def run_verifier(bundle, repo=REPO):
    p = subprocess.run([sys.executable, str(VERIFIER), str(bundle),
                        "--repo", str(repo), "--qualification"],
                       capture_output=True, text=True)
    try:
        rep = json.loads(p.stdout)
    except json.JSONDecodeError:
        rep = {"anomalies": ["verifier produced no JSON"],
               "stderr": p.stderr[-500:]}
    return p.returncode, rep


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", type=pathlib.Path, required=True)
    ap.add_argument("--only", action="append", default=None)
    ap.add_argument("--out", type=pathlib.Path, default=None)
    args = ap.parse_args()

    src = args.bundle if args.bundle.is_absolute() else REPO / args.bundle
    rc0, base = run_verifier(src)
    results = {"schema": "driver-lane-mutants-v1",
               "bundle": common.rel(src),
               "baseline": {"exit_code": rc0,
                            "anomalies": base.get("anomalies"),
                            "rederived_verdict": base.get("rederived_verdict"),
                            "qualification_pass": base.get("qualification_pass")},
               "mutants": []}
    if rc0 != 0:
        print(json.dumps(results, indent=1))
        print("BASELINE BUNDLE DOES NOT VERIFY - mutants are meaningless "
              "against a bundle that is already refused", file=sys.stderr)
        return 2

    killed = survived = errored = 0
    for name in (args.only or sorted(MUTANTS)):
        fn = MUTANTS[name]
        with tempfile.TemporaryDirectory(prefix=f"mutant-{name}-") as td:
            shadow, work = shadow_repo(td, src)
            data = load(work)
            try:
                level = fn(work, data)
            except Exception as e:
                results["mutants"].append(
                    {"mutant": name, "outcome": "ERROR",
                     "error": f"{type(e).__name__}: {e}"})
                errored += 1
                continue
            rc, rep = run_verifier(work, repo=shadow)
            dead = rc != 0 and bool(rep.get("anomalies"))
            killed += dead
            survived += not dead
            results["mutants"].append({
                "mutant": name,
                "sophistication": level,
                "verifier_exit_code": rc,
                "outcome": "KILLED" if dead else "SURVIVED",
                "first_anomalies": (rep.get("anomalies") or [])[:3],
                "anomaly_count": len(rep.get("anomalies") or []),
                "rederived_verdict": rep.get("rederived_verdict"),
                "qualification_pass": rep.get("qualification_pass"),
            })
    results["summary"] = {"total": killed + survived + errored,
                          "killed": killed, "survived": survived,
                          "errored": errored}
    print(json.dumps(results, indent=1))
    if args.out:
        out = args.out if args.out.is_absolute() else REPO / args.out
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(results, indent=1) + "\n")
    print(f"MUTANTS: {killed} killed, {survived} survived, {errored} errored",
          file=sys.stderr)
    return 0 if (survived == 0 and errored == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
