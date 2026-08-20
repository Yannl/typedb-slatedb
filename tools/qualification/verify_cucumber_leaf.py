#!/usr/bin/env python3
"""Fail-closed verification of a cucumber leaf bundle, from the BYTES.

The defect this exists to kill is a verifier that reads the producer's JSON
back to itself. So nothing in `cucumber-leaf-results.json` is believed on its
own: the corpus is re-expanded from the feature files, the plan's anchors are
re-checked, every archived log is re-hashed and re-scanned, every scenario
line is read back at the line and column its leaf row names, the owning-case
rule is re-run, and the per-template reconciliation is recomputed. The results
file is only ever the CLAIM being tested.

What is re-derived here, in order:

  * policy identity - plan root, catalogue digest, profile, toolchain id;
  * source bundles - each one re-verified with verify_leaf.py's own rules and
    required to carry a COMPLETE marker binding the root it recomputes to;
  * the corpus - every catalogued feature re-parsed and re-expanded, P1 (the
    expansion reproduces the catalogue's leaf list) and P2 (it reproduces the
    plan's anchors) re-decided here, not read;
  * every log the bundle names - re-hashed against the SEALED bundle's own
    recorded sha256, re-scanned for scenario lines (with the same torn-write
    tolerance), its cucumber summaries re-parsed, and its publishable claim
    re-decided from those bytes;
  * P3 per feature - the runtime's ordered scenario names must equal the
    expansion's predicted runnable sequence, element for element;
  * the owning-case rule - recomputed from the sound observations and required
    to select exactly the owner the bundle recorded;
  * every leaf - its id must be the catalogue's id for that display name under
    that target; its anchor the plan's; its runtime name the expansion's; and
    line `log_line`, column `log_column` of its named log must literally read
    `Feature: <title> :: <runtime_name>`, at the ORDINAL POSITION among that
    feature's scenario lines that its example index implies. An off-by-one in
    the example index moves the expected line, so it cannot survive;
  * completeness - a published feature must publish one leaf per executed
    scenario, no more and no fewer, and every scenario the runner's tag filter
    excluded must appear in `not_run` and NOWHERE in `leaves`;
  * the seal - bundle root recomputed over the results file and every log it
    consumed, matched against the sidecar manifest, the verdict and COMPLETE.

Usage:
  python3 tools/qualification/verify_cucumber_leaf.py DIR [DIR ...]
  python3 tools/qualification/verify_cucumber_leaf.py DIR --seal
"""

import argparse
import collections
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "tools" / "catalog"))
import common  # noqa: E402
import leaf_common as lc  # noqa: E402
import verify_leaf  # noqa: E402
import cucumber_common as cc  # noqa: E402


def verify(out_dir, plan=None, catalog=None, repo=REPO, corpus=None):
    """(anomalies, facts). Any anomaly refuses the bundle."""
    out_dir = pathlib.Path(out_dir).resolve()
    repo = pathlib.Path(repo).resolve()
    A = []
    results = out_dir / cc.RESULTS_NAME
    if not results.is_file():
        return [f"{out_dir}: no {cc.RESULTS_NAME} - there is no bundle here"], {}
    bundle = json.loads(results.read_text())
    if bundle.get("schema") != cc.SCHEMA:
        A.append(f"schema is {bundle.get('schema')!r}, expected {cc.SCHEMA!r}")

    plan = plan or json.loads(lc.PLAN.read_text())
    catalog = catalog or json.loads(lc.CATALOG.read_text())
    catalog_leaves, catalog_targets, _c = lc.load_catalog_leaves()

    # ---- policy / denominator identity ---------------------------------
    if bundle.get("plan_root") != plan.get("plan_root"):
        A.append(
            f"bundle pins plan_root {bundle.get('plan_root')} but the plan "
            f"now roots at {plan.get('plan_root')} - the denominator moved "
            f"under this evidence"
        )
    cat_sha = common.sha256_file(lc.CATALOG)
    if bundle.get("catalog_sha256") != cat_sha:
        A.append(
            f"bundle pins catalog_sha256 {bundle.get('catalog_sha256')} but "
            f"the catalogue now hashes {cat_sha}"
        )
    prof = bundle.get("profile")
    if bundle.get("profile_in_plan") != (prof in plan["profiles"]):
        A.append(
            f"bundle claims profile_in_plan={bundle.get('profile_in_plan')} "
            f"for profile {prof!r}; the plan's profiles are "
            f"{sorted(plan['profiles'])}"
        )

    # ---- the behaviour corpus is the plan's declared one ----------------
    declared_fx = {f["fixture_id"]: f for f in (plan.get("fixtures") or [])}
    bh_plan = declared_fx.get("fixture:typedb-behaviour") or {}
    bh = bundle.get("behaviour_fixture") or {}
    want = (bh_plan.get("source") or "").rsplit(" @ ", 1)[-1].strip()
    if want and bh.get("checkout_revision") != want:
        A.append(
            f"the behaviour corpus was at revision "
            f"{bh.get('checkout_revision')} but the plan declares {want}"
        )
    if bh.get("checkout_dirty"):
        A.append(
            "the behaviour corpus checkout was DIRTY - the feature bytes "
            "the scenarios were expanded from are then not the declared ones"
        )

    # ---- source bundles, re-verified ------------------------------------
    source_by_name, tcids = {}, set()
    for s in bundle.get("sources", []):
        p = repo / s["bundle"]
        anomalies, facts = verify_leaf.verify(p, plan, catalog_leaves, catalog_targets, repo=repo)
        claimed_clean = not s.get("refusals")
        if anomalies and claimed_clean:
            A.append(
                f"source bundle {s['bundle']} is presented as usable but "
                f"does not re-verify ({len(anomalies)} anomaly/anomalies, "
                f"first: {anomalies[0]})"
            )
            continue
        if anomalies:
            continue
        marker = p / "COMPLETE"
        head = marker.read_text().strip() if marker.is_file() else None
        if head != f"COMPLETE {facts['bundle_root']}":
            if claimed_clean:
                A.append(
                    f"source bundle {s['bundle']} carries COMPLETE {head!r} "
                    f"but recomputes to {facts['bundle_root']}"
                )
            continue
        sb = json.loads((p / lc.RESULTS_NAME).read_text())
        source_by_name[s["bundle"]] = sb
        if s.get("profile") != sb.get("profile"):
            A.append(
                f"source bundle {s['bundle']} records profile "
                f"{sb.get('profile')!r}, the row says {s.get('profile')!r}"
            )
        if sb.get("profile") != prof and claimed_clean:
            A.append(
                f"source bundle {s['bundle']} is profile "
                f"{sb.get('profile')!r} but this bundle is filed under "
                f"{prof!r} - one bundle records one lane"
            )
        tcids.add(sb.get("toolchain_id"))
    if tcids and bundle.get("toolchain_id") not in tcids:
        A.append(
            f"bundle records toolchain_id {bundle.get('toolchain_id')!r} "
            f"but its sources record {sorted(map(str, tcids))}"
        )

    # ---- the corpus, re-expanded (P1 and P2 decided HERE) ---------------
    corpus = corpus if corpus is not None else cc.build_corpus_index(catalog, plan)
    claimed_corpus = {r["target_id"]: r for r in (bundle.get("corpus") or [])}
    for tid, rec in corpus.items():
        cl = claimed_corpus.get(tid)
        if cl is None:
            A.append(
                f"the bundle omits catalogued feature {tid} from its corpus "
                f"record - a feature that is silently absent is a hole"
            )
            continue
        if cl.get("joinable") != rec["joinable"]:
            A.append(
                f"{rec['ref']}: bundle claims joinable={cl.get('joinable')} "
                f"but re-expansion decides {rec['joinable']} "
                f"({rec['problems'][:1]})"
            )
        if cl.get("source_sha256") != rec["source_sha256"]:
            A.append(
                f"{rec['ref']}: bundle records source_sha256 "
                f"{cl.get('source_sha256')} but the file now hashes "
                f"{rec['source_sha256']}"
            )
        if cl.get("feature_title") != rec["feature_title"]:
            A.append(
                f"{rec['ref']}: bundle records feature title "
                f"{cl.get('feature_title')!r}, the file declares "
                f"{rec['feature_title']!r}"
            )
    titles = {
        r["feature_title"]: r for r in corpus.values() if r["joinable"] and r["feature_title"]
    }
    if len(titles) != sum(1 for r in corpus.values() if r["joinable"]):
        dupes = [
            t
            for t, n in collections.Counter(
                r["feature_title"] for r in corpus.values() if r["joinable"]
            ).items()
            if n > 1
        ]
        A.append(
            f"catalogued feature titles are not unique ({dupes}) - the "
            f"runtime prints only the title, so two features sharing one "
            f"would make every scenario of both unattributable"
        )

    # ---- every log, re-hashed, re-scanned, re-decided --------------------
    scan_cache, log_rows = {}, {}
    for s in bundle.get("sources", []):
        sb = source_by_name.get(s["bundle"])
        rows = {r["raw_log"]: r for r in (sb or {}).get("targets", [])}
        for lg in s.get("logs", []):
            raw = lg["raw_log"]
            log_rows[raw] = lg
            src_row = rows.get(raw)
            if sb is not None and src_row is None:
                A.append(
                    f"{raw}: the bundle reads a log the sealed source "
                    f"bundle {s['bundle']} does not name"
                )
                continue
            p = repo / raw
            if not p.is_file():
                if lg.get("publishable"):
                    A.append(f"{raw}: named as publishable but does not exist")
                continue
            actual = common.sha256_file(p)
            if actual != lg.get("log_sha256"):
                A.append(f"{raw}: hashes {actual} but the row records {lg.get('log_sha256')}")
                continue
            if src_row is not None and actual != src_row.get("log_sha256"):
                A.append(
                    f"{raw}: hashes {actual} but the SEALED source bundle "
                    f"recorded {src_row.get('log_sha256')}"
                )
                continue
            try:
                inside = p.resolve().is_relative_to(repo / s["bundle"])
            except OSError:
                inside = False
            if not inside:
                A.append(
                    f"{raw}: lives outside its source bundle "
                    f"{s['bundle']} - a log this bundle's seal does not "
                    f"cover through that bundle"
                )
                continue
            text = cc.decolour(p.read_text(errors="replace"))
            scanned, unattributed = cc.scan_scenario_lines(text, set(titles))
            summaries = cc.parse_summaries(text)
            counts = common.parse_libtest_counts(text)
            cases, probs = lc.parse_libtest_cases(text)
            bad = list(probs)
            if not lc.has_summary(text):
                bad.append("no libtest 'test result:' summary")
            else:
                bad += lc.reconcile(cases, counts, probs)
            if unattributed:
                bad.append(f"{len(unattributed)} unattributable 'Feature: ' marker(s)")
            not_ok = [x for x in summaries if not cc.all_passed(x)]
            if not_ok:
                bad.append(f"{len(not_ok)} cucumber summary block(s) are not all-passed")
            summed = sum(x["scenarios"] or 0 for x in summaries)
            if summed != len(scanned):
                bad.append(f"summaries count {summed} scenario(s), {len(scanned)} scanned")
            for x in summaries:
                if x["features"] != x["scenarios"]:
                    bad.append(
                        f"[Summary] at line {x['line']}: "
                        f"{x['features']} features vs {x['scenarios']} "
                        f"scenarios"
                    )
            if lg.get("publishable") and bad:
                A.append(f"{raw}: marked publishable but re-derivation refuses it: {bad[0]}")
            if not lg.get("publishable") and not bad:
                A.append(
                    f"{raw}: marked NOT publishable while re-derivation "
                    f"finds nothing wrong - a silently withheld log hides "
                    f"evidence as effectively as a forged one"
                )
            if lg.get("scanned_scenarios") != len(scanned):
                A.append(
                    f"{raw}: row claims {lg.get('scanned_scenarios')} "
                    f"scanned scenario(s), the bytes yield {len(scanned)}"
                )
            if lg.get("summary_blocks") != len(summaries):
                A.append(
                    f"{raw}: row claims {lg.get('summary_blocks')} summary "
                    f"block(s), the bytes carry {len(summaries)}"
                )
            plain, outline = cc.count_keyword_lines(text)
            if (lg.get("keyword_lines") or {}) != {"scenario": plain, "scenario_outline": outline}:
                A.append(
                    f"{raw}: row claims keyword line counts "
                    f"{lg.get('keyword_lines')}, the bytes yield "
                    f"{{'scenario': {plain}, 'scenario_outline': {outline}}}"
                )
            tgt = lg.get("cargo_target")
            runner = cc.runner_of(tgt)
            if runner != lg.get("runner"):
                A.append(
                    f"{raw}: row calls the runner {lg.get('runner')!r} but "
                    f"Cargo.toml places {tgt} under a {runner!r} crate"
                )
            per_title = collections.defaultdict(list)
            for ln, col, t, n in scanned:
                per_title[t].append((ln, col, n))
            scan_cache[raw] = {
                "per_title": per_title,
                "all_passed": not not_ok,
                "scenarios": len(scanned),
                "text_lines": None,
            }
            scan_cache[raw]["lines"] = text.splitlines()

    # ---- P3, ownership and per-template reconciliation, recomputed -------
    exp_owner, exp_run = {}, {}
    obs_by_target = collections.defaultdict(list)
    for s in bundle.get("sources", []):
        for lg in s.get("logs", []):
            if not lg.get("publishable") or lg["raw_log"] not in scan_cache:
                continue
            sc = scan_cache[lg["raw_log"]]
            for title, items in sc["per_title"].items():
                rec = titles.get(title)
                if rec is None:
                    continue
                obs_by_target[rec["target_id"]].append(
                    {
                        "bundle": s["bundle"],
                        "raw_log": lg["raw_log"],
                        "cargo_target": lg["cargo_target"],
                        "runner": lg["runner"],
                        "items": items,
                    }
                )
    claimed_features = {f["target_id"]: f for f in (bundle.get("features") or [])}
    for tid, obs in obs_by_target.items():
        rec = corpus[tid]
        sound = []
        for o in obs:
            run, skipped = cc.runnable_entries(rec["entries"], o["runner"])
            if [n for _l, _c, n in o["items"]] != [e["runtime_name"] for e in run]:
                continue
            o["run"], o["skipped"] = run, skipped
            sound.append(o)
        if not sound:
            continue
        sound.sort(
            key=lambda o: (
                -len(o["run"]),
                0 if o["runner"] == "native" else 1,
                o["bundle"],
                o["cargo_target"],
            )
        )
        exp_owner[tid] = sound[0]
        exp_run[tid] = sound[0]["run"]
        cf = claimed_features.get(tid) or {}
        own = cf.get("owner") or {}
        if own.get("raw_log") != sound[0]["raw_log"]:
            A.append(
                f"{rec['ref']}: the bundle names {own.get('raw_log')!r} as "
                f"the owning log, but the owning-case rule recomputes to "
                f"{sound[0]['raw_log']!r}"
            )
        # per-template reconciliation, recomputed from the expansion
        per_t = collections.OrderedDict()
        for e in rec["entries"]:
            if e["template"] is None:
                continue
            k = (e["template"], e["declaration_line"])
            per_t.setdefault(k, {"catalogued": 0, "runnable": 0})["catalogued"] += 1
        for e in sound[0]["run"]:
            if e["template"] is not None:
                per_t[(e["template"], e["declaration_line"])]["runnable"] += 1
        claimed_t = {(t["template"], t["declaration_line"]): t for t in (cf.get("templates") or [])}
        for k, v in per_t.items():
            ct = claimed_t.get(k)
            if ct is None:
                A.append(
                    f"{rec['ref']}: the bundle records no per-template "
                    f"reconciliation for outline {k[0]!r} at line {k[1]}"
                )
                continue
            if (
                ct.get("catalogued_examples") != v["catalogued"]
                or ct.get("runtime_matched") != v["runnable"]
                or ct.get("runnable_examples") != v["runnable"]
            ):
                A.append(
                    f"{rec['ref']}: template {k[0]!r} at line {k[1]} - the "
                    f"bundle claims catalogued={ct.get('catalogued_examples')} "
                    f"runnable={ct.get('runnable_examples')} "
                    f"matched={ct.get('runtime_matched')}, the expansion and "
                    f"the log give catalogued={v['catalogued']} "
                    f"runnable={v['runnable']} matched={v['runnable']}"
                )
            idx = ct.get("example_indices_bound") or []
            if idx != sorted(idx):
                A.append(
                    f"{rec['ref']}: template {k[0]!r} binds example indices "
                    f"out of order ({idx[:6]}) - the i-th runtime scenario "
                    f"must be example i"
                )

    # ---- every leaf, read back out of its log ---------------------------
    leaves = bundle.get("leaves") or []
    seen, per_target = set(), collections.Counter()
    cat_by_target = collections.defaultdict(dict)
    for leaf in catalog["leaf_cases"]:
        if leaf["kind"] == "CUCUMBER":
            cat_by_target[leaf["target_id"]][leaf["leaf_case_id"]] = leaf
    entry_by_id = {}
    for rec in corpus.values():
        for e in rec["entries"]:
            if "leaf_case_id" in e:
                entry_by_id[e["leaf_case_id"]] = (rec, e)
    ordinal_seen = collections.defaultdict(list)
    for lf in leaves:
        lid = lf.get("leaf_case_id")
        if lid in seen:
            A.append(f"duplicate leaf row {lid}")
            continue
        seen.add(lid)
        tid = lf.get("target_id")
        per_target[tid] += 1
        pair = entry_by_id.get(lid)
        if pair is None:
            A.append(
                f"{lid}: no catalogued cucumber scenario re-expands to this "
                f"leaf id - a leaf bound to nothing is refused"
            )
            continue
        rec, e = pair
        if rec["target_id"] != tid:
            A.append(
                f"{lid}: bound to target {tid!r} but the catalogue places "
                f"it under {rec['target_id']!r}"
            )
        if cat_by_target.get(tid, {}).get(lid, {}).get("display_name") != lf.get("display_name"):
            A.append(
                f"{lid}: row says display_name {lf.get('display_name')!r}, "
                f"the catalogue says "
                f"{cat_by_target.get(tid, {}).get(lid, {}).get('display_name')!r}"
            )
        if lf.get("runtime_name") != e["runtime_name"]:
            A.append(
                f"{lid}: row says the runtime printed "
                f"{lf.get('runtime_name')!r}, the expansion of example "
                f"{e['example_index']} yields {e['runtime_name']!r}"
            )
        if (
            lf.get("anchor") != e["anchor"]
            or (plan.get("leaves") or {}).get(lid, {}).get("anchor") != e["anchor"]
        ):
            A.append(
                f"{lid}: anchor {lf.get('anchor')!r} does not agree with the "
                f"expansion ({e['anchor']!r}) and the plan "
                f"({(plan.get('leaves') or {}).get(lid, {}).get('anchor')!r})"
            )
        if (
            lf.get("example_index") != e["example_index"]
            or lf.get("example_total") != e["example_total"]
        ):
            A.append(
                f"{lid}: row says example {lf.get('example_index')}/"
                f"{lf.get('example_total')}, the expansion says "
                f"{e['example_index']}/{e['example_total']}"
            )
        fs_id = (plan.get("leaves") or {}).get(lid, {}).get("fixture_set_id")
        if lf.get("fixture_set_id") != fs_id:
            A.append(
                f"{lid}: row files the leaf under fixture set "
                f"{lf.get('fixture_set_id')!r}, the plan says {fs_id!r}"
            )
        raw = lf.get("raw_log")
        sc = scan_cache.get(raw)
        if sc is None:
            A.append(f"{lid}: names log {raw} which this bundle does not read or which was refused")
            continue
        if lf.get("outcome") != "PASSED" or not sc["all_passed"]:
            A.append(
                f"{lid}: claims outcome {lf.get('outcome')!r} from log {raw}, "
                f"whose cucumber summaries are "
                f"{'all-passed' if sc['all_passed'] else 'NOT all-passed'} - "
                f"ALL_PASSED_SUMMARY is the only derivation this schema "
                f"admits and it only ever yields PASSED"
            )
            continue
        lines = sc["lines"]
        n, col = lf.get("log_line"), lf.get("log_column")
        if (
            not isinstance(n, int)
            or not (1 <= n <= len(lines))
            or not isinstance(col, int)
            or col < 1
        ):
            A.append(
                f"{lid}: log_line/log_column {n!r}/{col!r} are outside its log ({len(lines)} lines)"
            )
            continue
        want = f"{cc.FEATURE_MARK}{rec['feature_title']}{cc.TITLE_SEP}{e['runtime_name']}"
        got = lines[n - 1][col - 1 :]
        if got != want:
            # Show the bytes AROUND the first divergence, not the first 160
            # characters: these scenario names run to 200+ characters and are
            # identical for most of their length, so a head-truncated message
            # would print two strings that look the same and prove nothing.
            k = next(
                (i for i in range(max(len(got), len(want))) if got[i : i + 1] != want[i : i + 1]), 0
            )
            A.append(
                f"{lid}: line {n} column {col} of {raw} diverges from the "
                f"expected scenario line at character {k}: the log reads "
                f"...{got[max(0, k - 20) : k + 40]!r}, the row claims "
                f"...{want[max(0, k - 20) : k + 40]!r} - the row points at "
                f"bytes that do not say what it claims"
            )
            continue
        items = sc["per_title"].get(rec["feature_title"], [])
        pos = [i for i, (ln, c, _n) in enumerate(items) if ln == n and c == col]
        if len(pos) != 1:
            A.append(
                f"{lid}: line {n}/{col} of {raw} is not exactly one of that "
                f"feature's scanned scenario lines ({len(pos)} match(es))"
            )
            continue
        ordinal_seen[(tid, raw)].append((pos[0], lid))
        run = exp_run.get(tid)
        if run is not None and raw == (exp_owner[tid]["raw_log"]):
            if pos[0] >= len(run) or run[pos[0]]["leaf_case_id"] != lid:
                A.append(
                    f"{lid}: is the {pos[0] + 1}th scenario line of "
                    f"{rec['ref']} in {raw}, but the expansion puts "
                    f"{run[pos[0]]['leaf_case_id'] if pos[0] < len(run) else None} "
                    f"at that position - the ordinal binding is wrong"
                )

    # ---- completeness: one leaf per executed scenario, no more, no fewer -
    for tid, owner in exp_owner.items():
        rec = corpus[tid]
        want = len(owner["run"])
        if per_target.get(tid, 0) != want:
            A.append(
                f"{rec['ref']}: publishes {per_target.get(tid, 0)} leaf/leaves "
                f"but the owning log {owner['raw_log']} executed {want} "
                f"scenario(s)"
            )
        got_ids = {lid for _p, lid in ordinal_seen.get((tid, owner["raw_log"]), [])}
        missing = [e["leaf_case_id"] for e in owner["run"] if e["leaf_case_id"] not in got_ids]
        if missing:
            A.append(
                f"{rec['ref']}: {len(missing)} executed scenario(s) have no "
                f"leaf row, e.g. {missing[:3]} - a silently dropped outcome"
            )
    claimed_not_run = {x["leaf_case_id"]: x for x in (bundle.get("not_run") or [])}
    for tid, owner in exp_owner.items():
        rec = corpus[tid]
        for e in owner["skipped"]:
            if e["leaf_case_id"] in seen:
                A.append(
                    f"{e['leaf_case_id']}: the {owner['runner']} runner's "
                    f"tag filter excluded it, yet the bundle publishes an "
                    f"outcome for it"
                )
            if e["leaf_case_id"] not in claimed_not_run:
                A.append(
                    f"{e['leaf_case_id']}: excluded by the runner's tag "
                    f"filter but absent from not_run - a scenario that "
                    f"never ran must be reported, not omitted"
                )
    for lid in claimed_not_run:
        if lid in seen:
            A.append(f"{lid}: appears in both leaves and not_run")

    # ---- the headline reconciliation, recomputed ------------------------
    want_jr = cc.join_reconciliation(corpus, bundle.get("features") or [], leaves)
    got_jr = bundle.get("join_reconciliation") or {}
    for k, v in want_jr.items():
        if got_jr.get(k) != v:
            A.append(
                f"join_reconciliation.{k} is {got_jr.get(k)!r} in the "
                f"bundle but recomputes to {v!r}"
            )

    # ---- the seal -------------------------------------------------------
    if "bundle_root" in bundle:
        A.append(
            "the results file carries a bundle_root field; the root is "
            "computed OVER this file and must live outside it"
        )
    root, pairs = cc.compute_bundle_root(out_dir, bundle, repo)
    vf = out_dir / cc.VERDICT_NAME
    if vf.is_file():
        v = json.loads(vf.read_text())
        if v.get("bundle_root") != root:
            A.append(
                f"{cc.VERDICT_NAME} binds root {v.get('bundle_root')} but "
                f"the bundle recomputes to {root}"
            )
        obs = v.get("observation") or {}
        if obs.get("leaves") != len(leaves):
            A.append(
                f"{cc.VERDICT_NAME} records {obs.get('leaves')} leaf/leaves "
                f"but the results file carries {len(leaves)}"
            )
        if obs.get("scenarios_not_run") != len(claimed_not_run):
            A.append(
                f"{cc.VERDICT_NAME} records "
                f"{obs.get('scenarios_not_run')} not-run scenario(s) but "
                f"the results file carries {len(claimed_not_run)}"
            )
    else:
        A.append(f"no {cc.VERDICT_NAME} - the bundle states no observation")
    mf = out_dir / cc.MANIFEST_NAME
    if mf.is_file():
        m = json.loads(mf.read_text())
        if m.get("bundle_root") != root:
            A.append(f"sidecar manifest root {m.get('bundle_root')} != recomputed {root}")
        for rel, sha in (m.get("files") or {}).items():
            if pairs.get(rel) != sha:
                A.append(f"sidecar manifest binds {rel}={sha} but it now hashes {pairs.get(rel)}")
        for rel in pairs:
            if rel not in (m.get("files") or {}):
                A.append(f"the bundle consumes {rel} which the sidecar manifest does not bind")
    else:
        A.append(f"no {cc.MANIFEST_NAME} sidecar - the bundle binds nothing")
    marker = out_dir / "COMPLETE"
    if marker.is_file():
        head = (marker.read_text().strip().splitlines() or [""])[0]
        m = re.match(r"^COMPLETE ([0-9a-f]{64})$", head)
        if not m:
            A.append(f"COMPLETE marker does not bind a bundle root: {head!r}")
        elif m.group(1) != root:
            A.append(
                f"COMPLETE binds root {m.group(1)} but the bundle "
                f"recomputes to {root} - the archive was modified after it "
                f"was sealed"
            )

    outcomes = collections.Counter(leaf.get("outcome") for leaf in leaves)
    facts = {
        "bundle": str(out_dir.relative_to(repo)) if out_dir.is_relative_to(repo) else str(out_dir),
        "profile": prof,
        "toolchain_id": bundle.get("toolchain_id"),
        "features_published": sum(
            1 for f in (bundle.get("features") or []) if f.get("leaves_published")
        ),
        "leaves": len(leaves),
        "leaves_passed": outcomes.get("PASSED", 0),
        "leaves_failed": outcomes.get("FAILED", 0),
        "scenarios_not_run": len(claimed_not_run),
        "bundle_root": root,
    }
    return A, facts


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("dirs", nargs="+")
    ap.add_argument(
        "--seal",
        action="store_true",
        help="write a COMPLETE marker binding the bundle root, but "
        "ONLY if the bundle verifies with zero anomalies",
    )
    ap.add_argument("--repo", default=str(REPO))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    plan = json.loads(lc.PLAN.read_text())
    catalog = json.loads(lc.CATALOG.read_text())
    corpus = cc.build_corpus_index(catalog, plan)
    rc = 0
    for d in args.dirs:
        A, facts = verify(d, plan, catalog, repo=args.repo, corpus=corpus)
        if not args.quiet:
            print(json.dumps({**facts, "anomalies": len(A)}, indent=1))
        for a in A:
            print(f"ANOMALY {d}: {a}", file=sys.stderr)
        if A:
            rc = 1
            continue
        if args.seal:
            (pathlib.Path(d) / "COMPLETE").write_text(f"COMPLETE {facts['bundle_root']}\n")
            print(f"SEALED {d} COMPLETE {facts['bundle_root']}", file=sys.stderr)
    print(f"CUCUMBER LEAF BUNDLE VERIFY: {'CLEAN' if rc == 0 else 'REFUSED'}", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
