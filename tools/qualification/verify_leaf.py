#!/usr/bin/env python3
"""Fail-closed verification of a leaf evidence bundle, from the BYTES.

The defect class this exists to kill is the one the E-P0-06/07/10 audit
already caught once at target granularity: a verifier that trusts the JSON a
producer wrote about the run instead of the run's own archived output. At
leaf granularity there is strictly more to forge - a case list, a per-case
outcome, a target id a leaf is bound to - so every one of those is
re-derived here and nothing in the results file is believed on its own:

  * the bundle root is recomputed over every consumed file and must equal
    the root the results file carries, the root the sidecar manifest
    carries, and the root a `COMPLETE <hex>` marker binds;
  * every target's log must exist, live INSIDE the bundle directory, and
    hash to the sha256 its row recorded;
  * every log must REPARSE (tools/catalog/common.parse_libtest_counts) to
    exactly the counts its row claims, and its per-case lines must
    RECONCILE with those counts - the same rule the producer applied, applied
    again by a different process over the archived bytes;
  * every leaf must be READ BACK out of its named log at its named line, and
    that line must name exactly that case with exactly that outcome;
  * every leaf's id must be exactly `<catalog_target_id>::<case_name>`, must
    exist in the catalogue under THAT target, and its runner row id must be
    the one `common.runner_row_id` derives for THAT target - a leaf bound to
    another target's id is refused, never repaired;
  * a target the bundle marks publishable must publish one leaf per parsed
    case that the catalogue declares - no more, no fewer;
  * a target that the catalogue says is case-bearing and that published zero
    leaves may not be marked publishable (the vacuous-evidence rule);
  * a bundle claiming a PRISTINE tree while recording a nonempty staged
    delta is refused, as is any tree_state of DIRTY or UNKNOWN;
  * the plan root, the catalogue digest and the toolchain identity recorded
    in the bundle must still match the plan, the catalogue and the plan's
    declared toolchain - a bundle whose denominator moved under it is not
    silently reinterpreted.

Usage:
  python3 tools/qualification/verify_leaf.py DIR [DIR ...]
  python3 tools/qualification/verify_leaf.py DIR --seal   # write COMPLETE
                                                          # iff it verifies
"""

import argparse
import hashlib
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


EMPTY_DELTA_SHA = hashlib.sha256(b"").hexdigest()


def verify(
    out_dir, plan=None, catalog_leaves=None, catalog_targets=None, repo=REPO, corroborate_tree=False
):
    """Returns (anomalies, facts). Any anomaly means the bundle is refused."""
    out_dir = pathlib.Path(out_dir).resolve()
    repo = pathlib.Path(repo).resolve()
    A = []
    results = out_dir / lc.RESULTS_NAME
    if not results.is_file():
        return [f"{out_dir}: no {lc.RESULTS_NAME} - there is no bundle here"], {}
    bundle = json.loads(results.read_text())
    if bundle.get("schema") != lc.SCHEMA:
        A.append(f"schema is {bundle.get('schema')!r}, expected {lc.SCHEMA!r}")

    plan = plan or json.loads(lc.PLAN.read_text())
    if catalog_leaves is None:
        catalog_leaves, catalog_targets, _cat = lc.load_catalog_leaves()
    rid_map = lc.rid_to_catalog_target(catalog_targets)

    # ---- policy / denominator identity -------------------------------
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
    tc_id = lc.toolchain_id(bundle.get("toolchain") or {}, plan)
    if bundle.get("toolchain_id") != tc_id:
        A.append(
            f"bundle records toolchain_id {bundle.get('toolchain_id')!r} but "
            f"its own measured toolchain re-derives to {tc_id!r}"
        )

    # ---- fixture identity: the plan's own declared bytes ---------------
    # A plan row names a FIXTURE SET, so "covered" must mean "run against the
    # fixtures the plan declares", not "run against something by that name".
    fx = bundle.get("fixtures") or {}
    declared_fx = {f["fixture_id"]: f for f in (plan.get("fixtures") or [])}
    script = declared_fx.get("fixture:assembly-script.tql")
    if script and fx.get("fixture:assembly-script.tql", {}).get("present"):
        got = fx["fixture:assembly-script.tql"].get("sha256")
        if got != script.get("sha256"):
            A.append(
                f"fixture:assembly-script.tql hashed {got} at run time but "
                f"the plan declares {script.get('sha256')}"
            )
    bh = declared_fx.get("fixture:typedb-behaviour")
    if bh and fx.get("fixture:typedb-behaviour", {}).get("present"):
        want = (bh.get("source") or "").rsplit(" @ ", 1)[-1].strip()
        got = fx["fixture:typedb-behaviour"].get("checkout_revision")
        if want and got != want:
            A.append(
                f"fixture:typedb-behaviour was at revision {got} at run "
                f"time but the plan declares {want}"
            )
        if fx["fixture:typedb-behaviour"].get("checkout_dirty"):
            A.append(
                "fixture:typedb-behaviour checkout was DIRTY at run time - "
                "the feature corpus under test is then not the declared one"
            )

    # ---- tree cleanliness, three-state and internally consistent -------
    tree = bundle.get("executed_tree") or {}
    state = tree.get("tree_state")
    if state not in ("PRISTINE", "FORK_STAGED_EXACT"):
        A.append(
            f"executed tree_state is {state!r} - only PRISTINE or "
            f"FORK_STAGED_EXACT (dirty w.r.t. the pin, but byte-identical "
            f"to fork/typedb with no stale staged files) is publishable"
        )
    if state == "PRISTINE" and (tree.get("dirty") or tree.get("staged_delta_files")):
        A.append(
            f"bundle claims a PRISTINE tree while recording "
            f"dirty={tree.get('dirty')} and "
            f"{tree.get('staged_delta_files')} staged delta file(s) - a "
            f"dirty tree presented as clean"
        )
    if state == "FORK_STAGED_EXACT" and not tree.get("dirty"):
        A.append(
            "bundle claims FORK_STAGED_EXACT with dirty=false - staging the "
            "fork always diverges from the locked revision"
        )
    if state == "FORK_STAGED_EXACT":
        stray = [
            u for u in (tree.get("unstaged_fork_patches") or []) if u not in lc.NON_CARGO_INPUTS
        ]
        if stray:
            A.append(
                f"bundle claims FORK_STAGED_EXACT while recording "
                f"{len(stray)} UNSTAGED fork patch(es) that DO affect the "
                f"cargo build ({stray[:3]}) - the checkout is then neither "
                f"upstream nor the fork"
            )
        if tree.get("unstaged_fork_patches_affecting_cargo"):
            A.append(
                f"bundle claims FORK_STAGED_EXACT while itself recording "
                f"cargo-affecting unstaged patches "
                f"{tree['unstaged_fork_patches_affecting_cargo'][:3]}"
            )
        for e in tree.get("non_cargo_input_paths") or []:
            if e.get("path") not in lc.NON_CARGO_INPUTS:
                A.append(
                    f"bundle excludes {e.get('path')!r} from its executed "
                    f"tree identity as a NON_CARGO_INPUT, but that path is "
                    f"not in the declared, reasoned NON_CARGO_INPUTS list - "
                    f"an exclusion a bundle invents for itself is refused"
                )
        if tree.get("unexplained_paths"):
            A.append(
                f"bundle claims FORK_STAGED_EXACT while recording "
                f"{len(tree['unexplained_paths'])} path(s) that are "
                f"neither the pinned upstream nor byte-identical to "
                f"fork/typedb: {tree['unexplained_paths'][:3]}"
            )
        classes = {c.get("class") for c in (tree.get("diverging_paths") or [])}
        if not classes <= {"FORK_PATCH", "RUNTIME_OUTPUT", "NON_CARGO_INPUT"}:
            A.append(
                f"bundle claims FORK_STAGED_EXACT but classifies diverging "
                f"paths as {sorted(classes)}"
            )
    if state == "PRISTINE":
        # the staged-delta digest of an EMPTY delta is the sha256 of nothing.
        # A bundle claiming a pristine tree must carry exactly that digest, so
        # relabelling a dirty run as clean means fabricating the digest too.
        if tree.get("staged_delta_sha256") != EMPTY_DELTA_SHA:
            A.append(
                f"bundle claims a PRISTINE tree but its staged-delta digest "
                f"is {tree.get('staged_delta_sha256')}, not the digest of an "
                f"empty delta ({EMPTY_DELTA_SHA}) - a dirty tree presented "
                f"as clean"
            )
        if tree.get("diverging_paths"):
            A.append(
                f"bundle claims a PRISTINE tree while listing "
                f"{len(tree['diverging_paths'])} diverging path(s)"
            )
    if corroborate_tree:
        # An external corroboration, used when re-verifying on the machine that
        # produced the bundle: the bundle's tree record is the ONE fact no
        # internal binding can pin, because the producer wrote it. If the
        # checkout is still at the same revision, its CURRENT staging state
        # must at least be reconcilable with what the bundle claims.
        cur = lc.executed_tree_identity()
        if cur["checkout_revision"] == tree.get("checkout_revision"):
            if state == "PRISTINE" and cur["tree_state"] != "PRISTINE":
                A.append(
                    f"bundle claims a PRISTINE tree, but the checkout it "
                    f"names is currently {cur['tree_state']} at the same "
                    f"revision ({cur['stage_check']}) - corroboration refuses "
                    f"the claim"
                )
    if not bundle.get("tree_stable_across_run", False):
        A.append(
            "the executed tree changed between the start and the end of the "
            "run - rows produced against two different trees cannot be filed "
            "under one identity"
        )

    # ---- bundle root over every consumed byte ---------------------------
    # The root is recomputed over the results file and every log it names, and
    # must equal the root the sidecar manifest, the verdict and the COMPLETE
    # marker each bind. The results file itself never carries the root (it is
    # hashed BY it), so a self-referential seal cannot exist here.
    if "bundle_root" in bundle:
        A.append(
            "the results file carries a bundle_root field; the root is "
            "computed OVER this file and must live outside it, or it can "
            "never be recomputed"
        )
    root, pairs = lc.compute_bundle_root(out_dir, bundle, repo)
    vf = out_dir / "leaf-verdict.json"
    if vf.is_file():
        v = json.loads(vf.read_text())
        if v.get("bundle_root") != root:
            A.append(
                f"leaf-verdict.json binds root {v.get('bundle_root')} but "
                f"the bundle recomputes to {root}"
            )
        obs = v.get("observation") or {}
        if obs.get("leaves") != len(bundle.get("leaves") or []):
            A.append(
                f"leaf-verdict.json records {obs.get('leaves')} leaf/leaves "
                f"but the results file carries "
                f"{len(bundle.get('leaves') or [])}"
            )
    else:
        A.append("no leaf-verdict.json - the bundle states no observation")
    mf = out_dir / "bundle-manifest.json"
    if mf.is_file():
        m = json.loads(mf.read_text())
        if m.get("bundle_root") != root:
            A.append(f"sidecar manifest root {m.get('bundle_root')} != recomputed {root}")
        for rel, sha in (m.get("files") or {}).items():
            if pairs.get(rel) != sha:
                A.append(f"sidecar manifest binds {rel}={sha} but it now hashes {pairs.get(rel)}")
    else:
        A.append("no bundle-manifest.json sidecar - the bundle binds nothing")
    marker = out_dir / "COMPLETE"
    if marker.is_file():
        head = (marker.read_text().strip().splitlines() or [""])[0]
        m = re.match(r"^COMPLETE ([0-9a-f]{64})$", head)
        if not m:
            A.append(f"COMPLETE marker does not bind a bundle root: {head!r}")
        elif m.group(1) != root:
            A.append(
                f"COMPLETE binds root {m.group(1)} but the bundle recomputes "
                f"to {root} - the archive was modified after it was sealed"
            )

    # ---- per target: bytes, counts, reconciliation ----------------------
    rows = bundle.get("targets") or []
    seen_rid, seen_log = {}, {}
    target_by_rid = {}
    for r in rows:
        rid = r.get("runner_row_id", "<none>")
        # the broken pre-fix id space plan_coverage.py reports as UNJOINABLE.
        # It arose from parsing a cargo package-id fragment instead of the
        # package NAME; a bundle carrying it cannot be joined without guessing
        # and is refused here rather than being guessed at downstream.
        if rid.startswith("0.0.0:"):
            A.append(
                f"target row id {rid!r} is in the broken pre-fix "
                f"'0.0.0:<target>' id space - unjoinable without guessing"
            )
        if rid in seen_rid:
            A.append(
                f"duplicate target row {rid} - a row that appears twice "
                f"inflates the corpus without running anything"
            )
            continue
        seen_rid[rid] = r
        target_by_rid[rid] = r
        raw = r.get("raw_log")
        if not raw:
            A.append(
                f"{rid}: records no raw log - counts without a log are an assertion, not evidence"
            )
            continue
        log = pathlib.Path(raw)
        log = log if log.is_absolute() else repo / log
        if not log.is_file():
            A.append(f"{rid}: names raw log {raw} which does not exist")
            continue
        try:
            inside = log.resolve().is_relative_to(out_dir)
        except OSError:
            inside = False
        if not inside:
            A.append(f"{rid}: names raw log {raw} OUTSIDE the bundle dir {out_dir}")
            continue
        key = log.resolve()
        if key in seen_log:
            A.append(
                f"{rid} and {seen_log[key]} both name log {raw} - one "
                f"execution cannot vouch for two rows"
            )
            continue
        seen_log[key] = rid
        actual = common.sha256_file(log)
        if actual != r.get("log_sha256"):
            A.append(
                f"{rid}: log {raw} hashes {actual} but the row recorded "
                f"{r.get('log_sha256')} - the log was rewritten after the "
                f"row was"
            )
            continue
        text = log.read_text(errors="replace")
        counts = common.parse_libtest_counts(text)
        for k, v in counts.items():
            if v != (r.get("counts") or {}).get(k, 0):
                A.append(
                    f"{rid}: row claims {k}={(r.get('counts') or {}).get(k)} "
                    f"but its log reparses to {k}={v}"
                )
        cases, parse_problems = lc.parse_libtest_cases(text)
        if len(cases) != r.get("parsed_cases"):
            A.append(
                f"{rid}: row claims {r.get('parsed_cases')} parsed case(s) "
                f"but the log yields {len(cases)}"
            )
        if r.get("publishable"):
            if not lc.has_summary(text):
                A.append(
                    f"{rid}: marked publishable but its log carries no "
                    f"libtest summary line (truncated log)"
                )
            for p in lc.reconcile(cases, counts, parse_problems):
                A.append(f"{rid}: marked publishable but {p}")
            if r.get("timed_out"):
                A.append(f"{rid}: marked publishable but the row records a TIMEOUT")
            ctid = r.get("catalog_target_id")
            declared = catalog_leaves.get(ctid, {})
            if declared and not cases:
                A.append(
                    f"{rid}: marked publishable with ZERO parsed cases while "
                    f"the catalogue records {len(declared)} leaf case(s) - "
                    f"vacuous evidence claiming coverage"
                )
            if ctid is not None and rid_map.get(rid) != ctid:
                A.append(
                    f"{rid}: bound to catalogue target {ctid!r} but the shared "
                    f"join (common.runner_row_id) maps it to "
                    f"{rid_map.get(rid)!r}"
                )

    # ---- per leaf: read the outcome back out of the log ------------------
    leaves = bundle.get("leaves") or []
    seen_leaf = set()
    per_target = {}
    log_cache = {}
    for lf in leaves:
        lid = lf.get("leaf_case_id")
        if lid in seen_leaf:
            A.append(f"duplicate leaf row {lid}")
            continue
        seen_leaf.add(lid)
        rid, ctid, name = (
            lf.get("runner_row_id"),
            lf.get("catalog_target_id"),
            lf.get("case_name"),
        )
        per_target[rid] = per_target.get(rid, 0) + 1
        if rid not in target_by_rid:
            A.append(
                f"{lid}: bound to target row {rid!r} which this bundle does "
                f"not contain - a leaf from a target that never ran"
            )
            continue
        if lid != f"{ctid}::{name}":
            A.append(f"{lid}: id is not <catalog_target_id>::<case_name> ({ctid!r}, {name!r})")
        declared = catalog_leaves.get(ctid, {})
        if name not in declared:
            A.append(
                f"{lid}: the catalogue declares no leaf {name!r} under target "
                f"{ctid!r} - a leaf bound to the wrong target_id is refused, "
                f"never repaired"
            )
        elif declared[name]["leaf_case_id"] != lid:
            A.append(
                f"{lid}: catalogue leaf id for {name!r} under {ctid!r} is "
                f"{declared[name]['leaf_case_id']}"
            )
        if rid_map.get(rid) != ctid:
            A.append(
                f"{lid}: runner row id {rid!r} joins to catalogue target "
                f"{rid_map.get(rid)!r}, not {ctid!r}"
            )
        tr = target_by_rid.get(rid) or {}
        if lf.get("log_sha256") != tr.get("log_sha256"):
            A.append(
                f"{lid}: binds log sha {lf.get('log_sha256')} but its target "
                f"row binds {tr.get('log_sha256')}"
            )
        raw = lf.get("raw_log")
        if raw not in log_cache:
            p = pathlib.Path(raw)
            p = p if p.is_absolute() else repo / p
            log_cache[raw] = p.read_text(errors="replace").splitlines() if p.is_file() else None
        lines = log_cache[raw]
        if lines is None:
            A.append(f"{lid}: its log {raw} does not exist")
            continue
        n = lf.get("log_line")
        c = lf.get("outcome_line", n)
        if (
            not isinstance(n, int)
            or not (1 <= n <= len(lines))
            or not isinstance(c, int)
            or not (1 <= c <= len(lines))
            or c < n
        ):
            A.append(
                f"{lid}: log_line/outcome_line {n!r}/{c!r} are outside its "
                f"log ({len(lines)} lines) or out of order"
            )
            continue
        # Read the claim back out of the bytes: the naming line and the
        # outcome line are re-parsed as the producer's parser would, over
        # exactly that slice of the log, so neither half is taken on trust.
        parsed, probs = lc.parse_libtest_cases("\n".join(lines[n - 1 : c]) + "\n")
        if probs or len(parsed) != 1:
            A.append(
                f"{lid}: lines {n}..{c} of {raw} do not read back as exactly "
                f"one libtest case ({len(parsed)} case(s), {len(probs)} parse "
                f"problem(s)); line {n} is {lines[n - 1]!r}"
            )
            continue
        got_name, got_outcome, got_open, got_close = parsed[0]
        if (
            got_name != name
            or got_outcome != lf.get("outcome")
            or got_open != 1
            or got_close != (c - n + 1)
        ):
            A.append(
                f"{lid}: the row claims ({name!r}, {lf.get('outcome')!r}) at "
                f"lines {n}..{c} but {raw} says ({got_name!r}, "
                f"{got_outcome!r}) - an edited outcome over an untouched log"
            )

    # ---- publishable targets must publish every catalogued case they ran --
    for rid, r in target_by_rid.items():
        if not r.get("publishable"):
            if per_target.get(rid):
                A.append(f"{rid}: refused target published {per_target[rid]} leaf/leaves anyway")
            continue
        ctid = r.get("catalog_target_id")
        declared = catalog_leaves.get(ctid, {})
        expect = r.get("parsed_cases", 0) - len(r.get("extra_cases") or [])
        if per_target.get(rid, 0) != expect:
            A.append(
                f"{rid}: publishes {per_target.get(rid, 0)} leaf/leaves but "
                f"ran {r.get('parsed_cases')} case(s) of which "
                f"{len(r.get('extra_cases') or [])} are not catalogued - "
                f"expected {expect}"
            )
        if declared and per_target.get(rid, 0) == 0:
            A.append(
                f"{rid}: publishable and catalogued case-bearing "
                f"({len(declared)} leaf case(s)) yet publishes no leaf"
            )

    facts = {
        "bundle": str(out_dir.relative_to(repo)) if out_dir.is_relative_to(repo) else str(out_dir),
        "profile": prof,
        "profile_in_plan": bundle.get("profile_in_plan"),
        "toolchain_id": bundle.get("toolchain_id"),
        "tree_state": state,
        "targets": len(rows),
        "targets_publishable": sum(1 for r in rows if r.get("publishable")),
        "targets_refused": sum(1 for r in rows if r.get("refusals")),
        "leaves": len(leaves),
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
    ap.add_argument(
        "--repo",
        default=str(REPO),
        help="root a repo-relative raw_log resolves against; "
        "only the negative-control harness passes this, so "
        "it can run THIS verifier against a mutated COPY "
        "without touching the real archive",
    )
    ap.add_argument(
        "--corroborate-tree",
        action="store_true",
        help="additionally check the bundle's tree claim against the "
        "checkout on THIS machine (only meaningful where the "
        "bundle was produced): the producer writes the tree "
        "record, so no binding inside the bundle can pin it",
    )
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    plan = json.loads(lc.PLAN.read_text())
    cl, ct, _ = lc.load_catalog_leaves()
    rc = 0
    for d in args.dirs:
        A, facts = verify(d, plan, cl, ct, repo=args.repo, corroborate_tree=args.corroborate_tree)
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
    print(f"LEAF BUNDLE VERIFY: {'CLEAN' if rc == 0 else 'REFUSED'}", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
