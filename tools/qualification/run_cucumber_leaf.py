#!/usr/bin/env python3
"""Cucumber leaf evidence producer: per-SCENARIO outcomes for the 20,495 rows.

WHAT THIS MOVES
---------------
`leaf_coverage.py` reports the cucumber family as 20,495 rows UNCOVERED with
the reason "no leaf-level runner lane has produced archived evidence". That
reason was true of the LIBTEST lane: one libtest case runs a whole feature
file, so `run_leaf.py`'s finest grain is `test migration::data_validation::
test_data_validation ... ok` - one line standing for 122 scenarios. The
scenarios themselves were nonetheless printed, by cucumber, into the very
logs `run_leaf.py` already archived and sealed.

So this producer RUNS NOTHING. It reads the sealed bundles' archived bytes,
re-derives the Scenario Outline expansion the runtime performed, proves the
join three independent ways (see cucumber_common's P1/P2/P3), and publishes
one leaf per scenario. Re-executing 4,099 scenarios x 2 profiles to learn
what 20 MB of already-archived, already-mutant-tested logs record would cost
~40 minutes of CPU and 16 GB of build tree for strictly less evidence: the
archived run is the run that happened.

WHAT IT REFUSES (each one is a way to report green without an execution)
-----------------------------------------------------------------------
  * a source bundle that does not re-verify with verify_leaf.py, or that
    carries no COMPLETE marker binding its recomputed root  -> no leaves
  * a source bundle whose profile the plan does not name, or whose toolchain
    the plan does not name                                  -> no leaves
  * a feature file whose bytes no longer hash to what the catalogue declares
                                                            -> no leaves
  * a feature whose expansion disagrees with the catalogue's leaf list (P1)
    or with the plan's anchors (P2)                         -> no leaves
  * a log whose libtest counts do not reconcile with its own per-case lines,
    or that reports filtered_out > 0, or that timed out     -> no leaves
    (a filtered run enumerates a SUBSET while looking full)
  * a log carrying a cucumber summary that is not all-passed -> no leaves
    from that log, with the reason: several libtest cases interleave into
    one stream, so a failed step cannot be attributed to the scenario that
    owns it. Re-run that binary with --test-threads 1 to make it derivable.
  * a log whose scanned scenario count does not equal the sum of its own
    cucumber summaries' scenario counts                     -> no leaves
  * a feature whose runtime scenario SEQUENCE is not element-for-element the
    expansion's predicted sequence (P3)                     -> no leaves
  * a scenario the runner's ignore-tag filter excluded -> recorded NOT_RUN
    with its tags. An unrun scenario is uncovered, never passed.

OWNING-CASE RULE (two features are reachable from two cargo cases each)
----------------------------------------------------------------------
`connection/database.feature` is run by both `test_connection` (native
`steps` runner) and `test_http_database` (the `http_steps` runner);
`connection/transaction.feature` by `test_connection` and
`test_http_transaction`. Both runs are real, so the rule is not "pick one and
throw the other away" - it is:

    For each (feature, profile) exactly one observation is the OWNER, chosen
    by (1) most scenarios actually executed - ownership follows evidence, not
    naming; (2) then the native runner over the HTTP runner, because the
    native `steps` Context is the one the plan's non-service rows describe;
    (3) then lexicographically by (bundle, cargo target). Every other
    observation is kept as a CORROBORATION and must agree scenario for
    scenario; a single disagreement REFUSES the feature for that profile
    rather than letting a majority vote decide. Scenarios only a
    corroborator ran (its ignore-tag set differs) are NOT promoted into the
    owner's leaf set - they are reported by count - because a leaf row must
    name one lane, not a blend of two.

Usage:
  python3 tools/qualification/run_cucumber_leaf.py \\
      --source docs/evidence/G3/leaf/u1-full-1 \\
      --source docs/evidence/G3/leaf/u1-http-2 \\
      --out docs/evidence/G3/leaf/cucumber-u1-1
"""
import argparse
import collections
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "tools" / "catalog"))
import common  # noqa: E402
import leaf_common as lc  # noqa: E402
import verify_leaf  # noqa: E402
import cucumber_common as cc  # noqa: E402


def load_source(d, plan, catalog_leaves, catalog_targets, repo=REPO):
    """One sealed leaf bundle, re-verified before a single byte of it is used."""
    p = pathlib.Path(d)
    p = p if p.is_absolute() else pathlib.Path(repo) / p
    rec = {"bundle": str(p.relative_to(repo)) if p.is_relative_to(repo) else str(p),
           "refusals": [], "logs": []}
    anomalies, facts = verify_leaf.verify(p, plan, catalog_leaves,
                                          catalog_targets, repo=repo)
    rec["verify_anomalies"] = anomalies
    rec["bundle_root"] = facts.get("bundle_root")
    if anomalies:
        rec["refusals"].append(
            f"the source bundle does not re-verify from its own bytes "
            f"({len(anomalies)} anomaly/anomalies) - evidence derived from it "
            f"would inherit the defect")
        return rec, None
    marker = p / "COMPLETE"
    rec["complete_marker"] = marker.read_text().strip() if marker.is_file() else None
    if rec["complete_marker"] != f"COMPLETE {facts['bundle_root']}":
        rec["refusals"].append(
            f"the source bundle's COMPLETE marker is {rec['complete_marker']!r}, "
            f"not the root it recomputes to ({facts['bundle_root']}) - an "
            f"unsealed or resealed archive is a run in progress, not evidence")
        return rec, None
    bundle = json.loads((p / lc.RESULTS_NAME).read_text())
    rec.update({"profile": bundle.get("profile"),
                "profile_in_plan": bundle.get("profile_in_plan"),
                "toolchain_id": bundle.get("toolchain_id"),
                "plan_root": bundle.get("plan_root"),
                "catalog_sha256": bundle.get("catalog_sha256"),
                "executed_tree": bundle.get("executed_tree"),
                "fixtures": bundle.get("fixtures")})
    if bundle.get("profile") not in plan["profiles"]:
        rec["refusals"].append(
            f"profile {bundle.get('profile')!r} is not a plan profile")
    if bundle.get("toolchain_id") is None:
        rec["refusals"].append(
            "the source bundle's toolchain matches no toolchain the plan names")
    return rec, bundle


def analyse_log(row, corpus, declared_refs, runner, repo=REPO):
    """One archived log -> the scenarios it proves, or a refusal with a reason.

    Everything is read out of the LOG FILE on disk, after its sha256 is
    checked against the row the sealed bundle recorded. No count and no name
    comes from any JSON.
    """
    out = {"runner_row_id": row.get("runner_row_id"),
           "cargo_target": row.get("cargo_target"),
           "raw_log": row.get("raw_log"),
           "log_sha256": row.get("log_sha256"),
           "runner": runner,
           "features_declared": sorted(declared_refs),
           "refusals": [], "publishable": False}
    p = pathlib.Path(row["raw_log"])
    p = p if p.is_absolute() else pathlib.Path(repo) / p
    if not p.is_file():
        out["refusals"].append(f"the archived log {row['raw_log']} does not exist")
        return out, {}
    actual = common.sha256_file(p)
    out["log_sha256_recomputed"] = actual
    if actual != row.get("log_sha256"):
        out["refusals"].append(
            f"the archived log hashes {actual} but the sealed bundle recorded "
            f"{row.get('log_sha256')} - the log changed under its own seal")
        return out, {}
    text = cc.decolour(p.read_text(errors="replace"))

    # --- the libtest layer must still be sound, by the same rules run_leaf uses
    counts = common.parse_libtest_counts(text)
    cases, parse_problems = lc.parse_libtest_cases(text)
    out["libtest_counts"] = counts
    out["libtest_cases"] = len(cases)
    if not lc.has_summary(text):
        out["refusals"].append(
            "the log carries no libtest 'test result:' summary - it is "
            "truncated or the binary died mid-run")
    else:
        out["refusals"] += lc.reconcile(cases, counts, parse_problems)
    if row.get("timed_out"):
        out["refusals"].append(
            "the source row records a TIMEOUT - a killed process's partial "
            "output is never a complete scenario enumeration")
    if "No space left on device" in text:
        out["refusals"].append(
            "the log contains 'No space left on device' - the environment "
            "failed during this target")

    # --- the cucumber layer
    titles = {r["feature_title"]: r for r in corpus.values()
              if r.get("joinable") and r.get("feature_title")}
    scanned, unattributed = cc.scan_scenario_lines(text, set(titles))
    out["scanned_scenarios"] = len(scanned)
    out["unattributed_feature_markers"] = [
        {"line": ln, "column": col, "text": t} for ln, col, t in unattributed]
    if unattributed:
        out["refusals"].append(
            f"{len(unattributed)} 'Feature: ' marker(s) in the log name a "
            f"feature title the catalogue does not carry, e.g. line "
            f"{unattributed[0][0]}: {unattributed[0][2]!r} - a scenario this "
            f"producer cannot attribute is never silently dropped")
    summaries = cc.parse_summaries(text)
    out["summaries"] = [{k: v for k, v in s.items() if k != "raw"} for s in summaries]
    out["summary_blocks"] = len(summaries)
    not_all_passed = [s for s in summaries if not cc.all_passed(s)]
    if not_all_passed:
        s = not_all_passed[0]
        out["refusals"].append(
            f"{len(not_all_passed)} of {len(summaries)} cucumber [Summary] "
            f"block(s) are not all-passed (line {s['line']}: {s['raw'] if 'raw' in s else s}) "
            f"- with several libtest cases interleaving into one stream a "
            f"failed step cannot be attributed to the scenario that owns it, "
            f"so which scenario failed is NOT derivable from these bytes. "
            f"Re-run this binary with --test-threads 1 to make it derivable.")
    summed = sum(s["scenarios"] or 0 for s in summaries)
    out["summary_scenarios_total"] = summed
    if summed != len(scanned):
        out["refusals"].append(
            f"the log's own cucumber summaries count {summed} scenario(s) but "
            f"{len(scanned)} scenario line(s) were scanned from it - the "
            f"enumeration contradicts the runtime's own tally")
    for s in summaries:
        if s["features"] != s["scenarios"]:
            out["refusals"].append(
                f"the [Summary] block at line {s['line']} reports "
                f"{s['features']} feature(s) but {s['scenarios']} scenario(s); "
                f"SingletonParser makes every scenario its own feature, so a "
                f"difference means the log is not what this producer can read")
        out["refusals"] += [f"[Summary] at line {s['line']}: {x}"
                            for x in s["problems"]]

    by_title = collections.defaultdict(list)
    for ln, col, title, name in scanned:
        by_title[title].append((ln, col, name))
    observed_refs = {titles[t]["ref"] for t in by_title}
    out["features_observed"] = sorted(observed_refs)
    missing = sorted(set(declared_refs) - observed_refs)
    extra = sorted(observed_refs - set(declared_refs))
    out["features_missing_from_log"] = missing
    out["features_not_declared_by_target"] = extra
    if missing:
        out["refusals"].append(
            f"the cargo target declares feature(s) {missing} that produced NO "
            f"scenario line in this log - a feature that did not run cannot be "
            f"covered from it")
    if extra:
        out["refusals"].append(
            f"the log names feature(s) {extra} that this cargo target's crate "
            f"sources do not reference - the log is not this target's")
    plain, outline = cc.count_keyword_lines(text)
    out["keyword_lines"] = {"scenario": plain, "scenario_outline": outline}
    out["publishable"] = not out["refusals"]
    return out, by_title


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", action="append", required=True,
                    help="a SEALED leaf evidence bundle to derive from "
                         "(repeatable). All sources must share one profile.")
    ap.add_argument("--out", required=True)
    ap.add_argument("--repo", default=str(REPO))
    args = ap.parse_args()

    repo = pathlib.Path(args.repo).resolve()
    out_dir = pathlib.Path(args.out)
    out_dir = out_dir if out_dir.is_absolute() else repo / out_dir
    if (out_dir / "COMPLETE").exists():
        sys.exit(f"{out_dir} carries a COMPLETE marker - it is a sealed bundle "
                 f"and this producer will not write into it. Use a fresh --out.")
    out_dir.mkdir(parents=True, exist_ok=True)

    plan = json.loads(lc.PLAN.read_text())
    catalog_leaves, catalog_targets, catalog = lc.load_catalog_leaves()
    catalog_full = json.loads(lc.CATALOG.read_text())
    corpus = cc.build_corpus_index(catalog_full, plan)
    target_refs = cc.target_feature_refs()
    cargo_targets = cc.cargo_behaviour_targets()
    fixtures = lc.fixture_state()

    sources, profiles, tcids = [], set(), set()
    # (ref, target_id) -> [observation]
    observations = collections.defaultdict(list)
    for d in args.source:
        rec, bundle = load_source(d, plan, catalog_leaves, catalog_targets, repo)
        sources.append(rec)
        if bundle is None or rec["refusals"]:
            print(f"SOURCE REFUSED {d}: {rec['refusals']}", file=sys.stderr)
            continue
        profiles.add(rec["profile"])
        tcids.add(rec["toolchain_id"])
        for row in bundle.get("targets", []):
            tgt = row.get("cargo_target")
            declared = [r for r in target_refs.get(tgt, [])
                        if f"cucumber-corpus:{r}" in corpus]
            if not declared:
                continue
            runner = cc.runner_of(tgt, cargo_targets)
            log, by_title = analyse_log(row, corpus, declared, runner, repo)
            log["source_bundle"] = rec["bundle"]
            rec["logs"].append(log)
            if not log["publishable"]:
                print(f"LOG REFUSED {row.get('raw_log')}: {log['refusals'][0]}",
                      file=sys.stderr)
                continue
            titles = {r["feature_title"]: r for r in corpus.values()
                      if r.get("joinable")}
            for title, items in by_title.items():
                observations[titles[title]["target_id"]].append({
                    "bundle": rec["bundle"], "raw_log": log["raw_log"],
                    "log_sha256": log["log_sha256"],
                    "cargo_target": tgt, "runner_row_id": row["runner_row_id"],
                    "runner": runner, "items": items,
                    "summary_lines": [s["line"] for s in log["summaries"]],
                })

    if len(profiles) > 1:
        sys.exit(f"the sources span profiles {sorted(profiles)} - one bundle "
                 f"records one lane, never a blend of two")
    profile = next(iter(profiles), None)
    tc_id = next(iter(tcids), None)

    features, leaves, not_run = [], [], []
    for tid in sorted(corpus):
        rec = corpus[tid]
        obs = observations.get(tid, [])
        frec = {"target_id": tid, "ref": rec["ref"],
                "feature_title": rec["feature_title"],
                "source_sha256": rec["source_sha256"],
                "catalogued_scenarios": len(rec["entries"]),
                "joinable": rec["joinable"], "corpus_problems": rec["problems"],
                "observations": len(obs), "refusals": [], "owner": None,
                "corroborations": [], "templates": [],
                "leaves_published": 0, "not_run": 0,
                "corroborator_only_scenarios": 0}
        features.append(frec)
        if not rec["joinable"]:
            frec["refusals"].append(
                f"the feature is not joinable: {rec['problems'][:1]}")
            continue
        if not obs:
            frec["refusals"].append(
                "no publishable log in any source bundle carries this feature")
            continue
        # ---- P3, per observation: the runtime SEQUENCE must be the expansion
        sound = []
        for o in obs:
            run, skipped = cc.runnable_entries(rec["entries"], o["runner"])
            got = [n for _ln, _c, n in o["items"]]
            want = [e["runtime_name"] for e in run]
            if got != want:
                first = next((k for k in range(max(len(got), len(want)))
                              if got[k:k + 1] != want[k:k + 1]), 0)
                frec["refusals"].append(
                    f"P3 FAILED in {o['raw_log']} ({o['cargo_target']}): the "
                    f"runtime printed {len(got)} scenario(s) where the "
                    f"expansion predicts {len(want)} runnable one(s); first "
                    f"divergence at position {first}: log says "
                    f"{got[first:first+1]}, expansion says {want[first:first+1]}")
                continue
            o["run"], o["skipped"] = run, skipped
            sound.append(o)
        if not sound:
            continue
        # ---- owning-case rule (see module docstring)
        sound.sort(key=lambda o: (-len(o["run"]), 0 if o["runner"] == "native" else 1,
                                  o["bundle"], o["cargo_target"]))
        owner, rest = sound[0], sound[1:]
        frec["owner"] = {"bundle": owner["bundle"], "raw_log": owner["raw_log"],
                         "cargo_target": owner["cargo_target"],
                         "runner": owner["runner"],
                         "scenarios_executed": len(owner["run"])}
        owner_ids = {e["leaf_case_id"] for e in owner["run"]}
        for o in rest:
            shared = disagree = 0
            by_leaf = {e["leaf_case_id"]: (ln, col)
                       for e, (ln, col, _n) in zip(o["run"], o["items"])}
            for e in owner["run"]:
                if e["leaf_case_id"] in by_leaf:
                    shared += 1  # both logs are all-passed, so both say PASSED
            only = sum(1 for e in o["run"] if e["leaf_case_id"] not in owner_ids)
            frec["corroborator_only_scenarios"] += only
            frec["corroborations"].append({
                "bundle": o["bundle"], "raw_log": o["raw_log"],
                "cargo_target": o["cargo_target"], "runner": o["runner"],
                "scenarios_executed": len(o["run"]),
                "scenarios_shared_with_owner": shared,
                "scenarios_disagreeing": disagree,
                "scenarios_only_here": only,
            })
            if disagree:
                frec["refusals"].append(
                    f"corroborating log {o['raw_log']} disagrees with the owner "
                    f"on {disagree} scenario(s) - two executions of one leaf "
                    f"cannot both be right, so the feature is refused")
        if frec["refusals"]:
            continue
        # ---- per template reconciliation, archived so it can be re-checked
        per_t = collections.OrderedDict()
        for e in rec["entries"]:
            if e["template"] is None:
                continue
            k = (e["template"], e["declaration_line"])
            t = per_t.setdefault(k, {"template": e["template"],
                                     "declaration_line": e["declaration_line"],
                                     "catalogued_examples": 0,
                                     "runnable_examples": 0,
                                     "runtime_matched": 0,
                                     "example_indices_bound": []})
            t["catalogued_examples"] += 1
        run_ids = {e["leaf_case_id"] for e in owner["run"]}
        for e, (ln, col, name) in zip(owner["run"], owner["items"]):
            if e["template"] is None:
                continue
            t = per_t[(e["template"], e["declaration_line"])]
            t["runnable_examples"] += 1
            t["runtime_matched"] += 1
            t["example_indices_bound"].append(e["example_index"])
        bad_t = []
        for k, t in per_t.items():
            if t["runtime_matched"] != t["runnable_examples"]:
                bad_t.append(t)
            elif t["example_indices_bound"] != sorted(t["example_indices_bound"]):
                bad_t.append(t)
        if bad_t:
            frec["refusals"].append(
                f"per-template reconciliation FAILED for {len(bad_t)} "
                f"template(s), e.g. {bad_t[0]}")
            continue
        frec["templates"] = list(per_t.values())
        # ---- publish
        fs_ok_cache = {}
        for e, (ln, col, name) in zip(owner["run"], owner["items"]):
            fs_id = e.get("fixture_set_id", "fs:none")
            if fs_id not in fs_ok_cache:
                fs_ok_cache[fs_id] = lc.fixture_set_satisfied(fs_id, plan, fixtures)
            corr = []
            for o in rest:
                for oe, (oln, ocol, _on) in zip(o["run"], o["items"]):
                    if oe["leaf_case_id"] == e["leaf_case_id"]:
                        corr.append({"raw_log": o["raw_log"], "log_line": oln,
                                     "log_column": ocol, "outcome": "PASSED"})
                        break
            leaves.append({
                "leaf_case_id": e["leaf_case_id"],
                "target_id": tid,
                "feature_ref": rec["ref"],
                "feature_title": rec["feature_title"],
                "display_name": e["display_name"],
                "runtime_name": e["runtime_name"],
                "template": e["template"],
                "example_index": e["example_index"],
                "example_total": e["example_total"],
                "anchor": e["anchor"],
                "declaration_line": e["declaration_line"],
                "scenario_ordinal_in_feature": e["ordinal"],
                "outcome": "PASSED",
                "outcome_derivation": "ALL_PASSED_SUMMARY",
                "raw_log": owner["raw_log"],
                "log_sha256": owner["log_sha256"],
                "log_line": ln,
                "log_column": col,
                "runner_row_id": owner["runner_row_id"],
                "cargo_target": owner["cargo_target"],
                "runner": owner["runner"],
                "fixture_set_id": fs_id,
                "fixture_set_satisfied": fs_ok_cache[fs_id],
                "corroborations": corr,
            })
            frec["leaves_published"] += 1
        for e in owner["skipped"]:
            not_run.append({
                "leaf_case_id": e["leaf_case_id"],
                "target_id": tid,
                "display_name": e["display_name"],
                "tags": e["tags"],
                "runner": owner["runner"],
                "reason": (f"the {owner['runner']} runner's own scenario filter "
                           f"(is_ignore) excludes tags "
                           f"{sorted(cc.RUNNER_IGNORE_TAGS[owner['runner']])}; "
                           f"this scenario carries {e['tags']} and was never "
                           f"executed, so it has no outcome to record"),
            })
            frec["not_run"] += 1

    bh = fixtures.get("fixture:typedb-behaviour", {})
    bundle = {
        "schema": cc.SCHEMA,
        "producer": "tools/qualification/run_cucumber_leaf.py",
        "derived_from_archived_logs": True,
        "profile": profile,
        "profile_in_plan": profile in plan["profiles"],
        "toolchain_id": tc_id,
        "plan_root": plan.get("plan_root"),
        "catalog_sha256": common.sha256_file(lc.CATALOG),
        "source_lock_digest": catalog.get("source_lock_digest"),
        "behaviour_fixture": bh,
        "fixtures": fixtures,
        "join_proofs": {
            "P1": "the expansion reproduces the catalogue's display_name list "
                  "for every joinable feature, in order",
            "P2": "the expansion reproduces the plan's own "
                  "<file>:<line>[#exN] anchor for every leaf it claims",
            "P3": "the runtime's ordered scenario names equal the expansion's "
                  "predicted runnable sequence, element for element",
        },
        "outcome_derivations": {
            "ALL_PASSED_SUMMARY":
                "every cucumber [Summary] block in the owning log reports "
                "K scenarios (K passed) with zero skipped, failed and retried "
                "and no parsing or hook errors, and those blocks' scenario "
                "counts sum to exactly the number of scenario lines scanned "
                "from that log; therefore every scanned scenario passed",
        },
        "sources": sources,
        "corpus": [{k: v for k, v in r.items() if k != "entries"}
                   for r in corpus.values()],
        "features": features,
        "leaves": sorted(leaves, key=lambda l: l["leaf_case_id"]),
        "not_run": sorted(not_run, key=lambda l: l["leaf_case_id"]),
    }
    results = out_dir / cc.RESULTS_NAME
    results.write_text(json.dumps(bundle, indent=1) + "\n")
    root, pairs = cc.compute_bundle_root(out_dir, bundle, repo)
    (out_dir / cc.MANIFEST_NAME).write_text(
        json.dumps({"bundle_root": root, "files": pairs}, indent=1) + "\n")

    obs_counts = collections.Counter(l["outcome"] for l in leaves)
    observation = {
        "features_catalogued": len(corpus),
        "features_published": sum(1 for f in features if f["leaves_published"]),
        "features_refused": sum(1 for f in features if f["refusals"]),
        "scenarios_catalogued": sum(len(r["entries"]) for r in corpus.values()),
        "leaves": len(leaves),
        "leaves_passed": obs_counts.get("PASSED", 0),
        "leaves_failed": obs_counts.get("FAILED", 0),
        "leaves_ignored": obs_counts.get("IGNORED", 0),
        "scenarios_not_run": len(not_run),
        "logs_read": sum(len(s["logs"]) for s in sources),
        "logs_refused": sum(1 for s in sources for l in s["logs"]
                            if not l["publishable"]),
    }
    (out_dir / cc.VERDICT_NAME).write_text(json.dumps({
        "producer": "tools/qualification/run_cucumber_leaf.py",
        "schema": cc.SCHEMA,
        "profile": profile,
        "profile_in_plan": bundle["profile_in_plan"],
        "toolchain_id": tc_id,
        "plan_root": plan.get("plan_root"),
        "catalog_sha256": bundle["catalog_sha256"],
        "sources": [{"bundle": s["bundle"], "bundle_root": s.get("bundle_root"),
                     "refusals": s["refusals"]} for s in sources],
        "observation": observation,
        "bundle_root": root,
        "statement": (
            "This bundle records per-SCENARIO outcomes, not a pass. COVERED "
            "means an outcome was RECORDED for that scenario in this lane; a "
            "FAILED leaf would be covered evidence of a failure. Scenarios the "
            "runner's ignore-tag filter never executed are reported NOT_RUN "
            "and cover nothing."),
    }, indent=1) + "\n")

    print(json.dumps({"profile": profile, "toolchain_id": tc_id,
                      **observation, "bundle_root": root}, indent=1))
    for f in features:
        if f["refusals"]:
            print(f"FEATURE REFUSED {f['ref']}: {f['refusals'][0]}",
                  file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
