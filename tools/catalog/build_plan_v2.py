#!/usr/bin/env python3
"""E-02: the immutable leaf/profile/fixture qualification plan (v2).

The catalogue records 303 targets, 4,740 unique leaves and 23,132 required
(leaf, profile) pairs; the execution evidence that exists proves only ~106
AGGREGATE cargo target rows. Nothing joined each leaf to a planned execution
until now. This tool freezes the DENOMINATOR as a first-class artifact:

  docs/evidence/G1/qualification-plan-v2.json

  - one plan row per applicable (leaf, profile, fixture-set, toolchain),
    derived 1:1 from the catalogue's required_pairs (the profile matrix is
    the catalogue's, not re-invented here);
  - the canonical TargetId / LeafCaseId are THE CATALOGUE'S IDS, shared by
    plan, runner, logs and comparator - no second id space. For Cucumber
    leaves the plan additionally binds every leaf to a physical anchor
    `<feature-file>:<line>[#ex<N>]` parsed from the pinned behaviour
    checkout, so a scenario(-outline example) is identified by
    file/line/example-index and name collisions are impossible: a name that
    resolves to zero or to two declarations in its feature file stops the
    build here, fail-closed;
  - the catalogue's approved exclusions (declared zero-case targets etc.)
    are carried through as explicit exclusion rows with their reasons - a
    zero-case executable target is non-pass WITHOUT one of these rows;
  - E-05: official-driver namespace rows (rust/python/typescript x
    rocksdb/slatedb backends) are recorded with status NOT_IMPLEMENTED and
    required_by v17-A17.5, so the denominator INCLUDES the driver suites and
    any coverage report must show them uncovered - absence is recorded, not
    hidden. NOTE: that NOT_IMPLEMENTED is the plan's SEED value and stays
    that way by design, because the plan body feeds plan_root and archived
    verdicts pin that root (see the paragraph below). Whether a driver row
    has since been EXECUTED is a RESULT-side fact and lives in
    docs/evidence/G1/drivers/driver-row-status.json, written by
    tools/drivers/row_status.py only for rows whose evidence bundle
    tools/evidence/verify_drivers.py accepts, and re-checked independently
    by tools/catalog/plan_coverage.py. Do not "fix" the seed here: changing
    it re-roots the plan and turns every bundle that pinned the old root
    red for a reason that has nothing to do with its bytes;
  - a content-addressed `plan_root` (sha256 over the canonical JSON of the
    whole body) makes the plan pin-able: verdicts record it (policy_roots)
    and a silent plan edit becomes a root mismatch, never a reinterpretation.

The plan is a DENOMINATOR, never a pass: emitting it proves nothing ran.
tools/catalog/plan_coverage.py joins execution evidence onto these rows and
must report the plan NOT satisfied until every row is covered or excluded.

Source-lock freshness (R4-EVID-01a, closed by the round-5 R5-EVID-01
regeneration): the plan's generated_from.source_lock_digest is faithfully
copied from the catalogue, and `--check` always compares it against the
CURRENT source-lock/source-lock.json. `--check --require-current-lock`
turns staleness into a hard failure; plain `--check` reports it
informationally. CI runs the flagged form as a BLOCKING step: a source-lock
change without catalogue+plan regeneration turns CI red.

Usage:
  python3 tools/catalog/build_plan_v2.py            # (re)build + write + print root
  python3 tools/catalog/build_plan_v2.py --check    # committed plan vs catalogue; drift = nonzero
  python3 tools/catalog/build_plan_v2.py --check --require-current-lock
"""

import argparse
import hashlib
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import common  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[2]
CATALOG = REPO / "docs" / "evidence" / "G1" / "upstream-test-catalog.json"
BH = REPO / "sources" / "typedb-behaviour"
PLAN = REPO / "docs" / "evidence" / "G1" / "qualification-plan-v2.json"

DRIVERS = ("rust", "python", "typescript")
BACKENDS = ("rocksdb", "slatedb")

errors = []


def error(msg):
    errors.append(msg)


# ------------------------------------------------- cucumber physical anchors


def scan_feature_declarations(text):
    """(name -> [(line_no, kind, example_rows)]) for one feature file.

    The same strict line machine completeness.py recounts with, extended to
    capture NAMES and LINE NUMBERS. Independent of generate_catalog's parser
    on purpose - agreement is the check.
    """
    decls = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        m = re.match(r"Scenario Outline:\s*(.*)$", line)
        if m:
            name = m.group(1).strip()
            rows = 0
            j = i + 1
            in_examples = False
            header_seen = False
            while j < len(lines):
                l2 = lines[j].strip()
                if re.match(r"(Scenario\b|Scenario Outline:|Rule:|Feature:)", l2):
                    break
                if l2.startswith("Examples"):
                    in_examples, header_seen = True, False
                elif in_examples and l2.startswith("|"):
                    if header_seen:
                        rows += 1
                    else:
                        header_seen = True
                elif in_examples and l2 and not l2.startswith("#"):
                    in_examples = False
                j += 1
            decls.setdefault(name, []).append((i + 1, "outline", rows))
            i = j
            continue
        m = re.match(r"Scenario:\s*(.*)$", line)
        if m:
            decls.setdefault(m.group(1).strip(), []).append((i + 1, "scenario", 0))
        i += 1
    return decls


def _resolve_declaration(decls, name, ex_index, ordinal):
    """The declaration a catalogue leaf id addresses, mirroring the
    generator's `@k` occurrence-ordinal semantics EXACTLY (generate_catalog
    keys occurrences on the full id base, so the k-th occurrence of
    `name#exN` is the k-th OUTLINE declaration of `name` with >= N example
    rows, and the k-th occurrence of a bare `name` is the k-th plain
    Scenario declaration of it). Returns (line, kind, ex_rows) or None."""
    candidates = decls.get(name, [])
    if ex_index is None:
        candidates = [d for d in candidates if d[1] == "scenario"]
    else:
        candidates = [d for d in candidates if d[1] == "outline" and d[2] >= ex_index]
    if len(candidates) < ordinal:
        return None
    return candidates[ordinal - 1]


def cucumber_anchors(catalog):
    """leaf_case_id -> 'file:line[#exN]' for every CUCUMBER leaf, fail-closed.

    Collisions are impossible by construction: every leaf id resolves to
    exactly one (file, line, example-index) triple, two leaves never share a
    triple, and every declared scenario / example row is claimed by exactly
    one leaf (symmetric exact-set). Any residue stops the build.
    """
    per_file = {}
    anchors = {}
    used = {}  # (ref, line, ex_index) -> leaf_case_id
    for lc in catalog["leaf_cases"]:
        if lc["kind"] != "CUCUMBER":
            continue
        ref = lc["target_id"].split("cucumber-corpus:", 1)[1]
        if ref not in per_file:
            f = BH / ref
            if not f.is_file():
                error(
                    f"plan: feature file {ref} referenced by the catalogue is "
                    f"absent from the pinned behaviour checkout"
                )
                per_file[ref] = {}
            else:
                per_file[ref] = scan_feature_declarations(f.read_text())
        prefix = f"cucumber:{ref}::"
        if not lc["leaf_case_id"].startswith(prefix):
            error(
                f"plan: leaf {lc['leaf_case_id']!r} does not carry the canonical "
                f"'cucumber:<file>::<name>' shape for its target {ref}"
            )
            continue
        raw = lc["leaf_case_id"][len(prefix) :]

        def parse(raw):
            ordinal = 1
            m = re.match(r"^(.*)@(\d+)$", raw)
            if m:
                ordinal = int(m.group(2))
                raw = m.group(1)
            ex_index = None
            m = re.match(r"^(.*)#ex(\d+)$", raw)
            if m:
                raw, ex_index = m.group(1), int(m.group(2))
            return raw, ex_index, ordinal

        name, ex_index, ordinal = parse(raw)
        decl = _resolve_declaration(per_file[ref], name, ex_index, ordinal)
        if decl is None and ordinal > 1:
            # a genuine scenario name could itself end in '@<digits>';
            # retry treating the suffix as part of the name, occurrence 1
            m = re.match(r"^(.*)#ex(\d+)$", raw)
            name, ex_index, ordinal = (m.group(1), int(m.group(2)), 1) if m else (raw, None, 1)
            decl = _resolve_declaration(per_file[ref], name, ex_index, 1)
        if decl is None:
            error(
                f"plan: {ref} has no declaration matching leaf "
                f"{lc['leaf_case_id']!r} (name {name!r}, example {ex_index}, "
                f"occurrence {ordinal}) - the leaf is unanchorable"
            )
            continue
        line_no, kind, ex_rows = decl
        key = (ref, line_no, ex_index)
        if key in used:
            error(
                f"plan: leaves {used[key]!r} and {lc['leaf_case_id']!r} both "
                f"anchor to {ref}:{line_no}"
                + (f"#ex{ex_index}" if ex_index else "")
                + " - two leaves cannot share one physical case"
            )
            continue
        used[key] = lc["leaf_case_id"]
        anchors[lc["leaf_case_id"]] = (
            f"{ref}:{line_no}#ex{ex_index}" if ex_index else f"{ref}:{line_no}"
        )
    # symmetric exact-set: every declared scenario and every declared example
    # row must be claimed by exactly one leaf (missing = lost case)
    for ref, decls in sorted(per_file.items()):
        for name, dlist in sorted(decls.items()):
            for line_no, kind, ex_rows in dlist:
                if kind == "scenario":
                    if (ref, line_no, None) not in used:
                        error(
                            f"plan: {ref}:{line_no} Scenario {name!r} is claimed "
                            f"by no catalogue leaf - a physical case is missing "
                            f"from the denominator"
                        )
                else:
                    for n in range(1, ex_rows + 1):
                        if (ref, line_no, n) not in used:
                            error(
                                f"plan: {ref}:{line_no} outline {name!r} example "
                                f"row {n}/{ex_rows} is claimed by no catalogue "
                                f"leaf - a physical case is missing from the "
                                f"denominator"
                            )
    return anchors


# ----------------------------------------------------------------- the plan


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def plan_root_of(body):
    return hashlib.sha256(canonical(body).encode()).hexdigest()


def build_body(catalog, catalog_sha):
    anchors = cucumber_anchors(catalog)

    toolchain_id = (
        "rust-" + catalog["rust_toolchain"]["rustc"].split()[1] + ":" + catalog["target_triple"]
    )
    toolchains = {
        toolchain_id: {**catalog["rust_toolchain"], "target_triple": catalog["target_triple"]}
    }

    targets = {t["target_id"]: t for t in catalog["targets"]}
    fixture_sets = {}

    def fixture_set_id(target):
        ids = tuple(sorted(target.get("fixture_ids") or []))
        fsid = (
            "fs:none"
            if not ids
            else "fs:" + hashlib.sha256("|".join(ids).encode()).hexdigest()[:12]
        )
        fixture_sets.setdefault(fsid, list(ids))
        return fsid

    leaves = {}
    for lc in catalog["leaf_cases"]:
        t = targets.get(lc["target_id"])
        if t is None:
            error(
                f"plan: leaf {lc['leaf_case_id']!r} references unknown target {lc['target_id']!r}"
            )
            continue
        entry = {
            "target_id": lc["target_id"],
            "kind": lc["kind"],
            "source_hash": lc["source_hash"],
            "fixture_set_id": fixture_set_id(t),
        }
        if lc["kind"] == "CUCUMBER":
            a = anchors.get(lc["leaf_case_id"])
            if a is None:
                continue  # already reported by cucumber_anchors, fail-closed
            entry["anchor"] = a
        leaves[lc["leaf_case_id"]] = entry

    rows = []
    for rp in catalog["required_pairs"]:
        leaf = leaves.get(rp["leaf_case_id"])
        if leaf is None:
            error(
                f"plan: required pair references leaf {rp['leaf_case_id']!r} "
                f"which produced no plan leaf"
            )
            continue
        rows.append([rp["leaf_case_id"], rp["profile_id"], leaf["fixture_set_id"], toolchain_id])
    rows.sort()
    if len({tuple(r) for r in rows}) != len(rows):
        error("plan: duplicate (leaf, profile, fixture-set, toolchain) row")

    # SEED status only - see the module docstring. The result side is
    # docs/evidence/G1/drivers/driver-row-status.json; editing the value
    # below changes the plan body and therefore plan_root.
    driver_rows = [
        {
            "row_id": f"driver:{d}:{b}",
            "driver": d,
            "backend": b,
            "status": "NOT_IMPLEMENTED",
            "required_by": "v17-A17.5",
            "reason": "official driver suite harness is not built; this row exists "
            "so the denominator includes it and every coverage report "
            "must show it uncovered - absence is recorded, never hidden",
        }
        for d in DRIVERS
        for b in BACKENDS
    ]

    body = {
        "schema": "typedb-r2-qualification-plan-v2",
        "statement": (
            "This plan is the DENOMINATOR of qualification, never a pass: it "
            "enumerates every (leaf, profile, fixture-set, toolchain) that must "
            "either produce an execution event or carry an approved exclusion "
            "row. Emitting or committing this file proves nothing ran. The "
            "plan is immutable per plan_root: verdicts pin plan_root and any "
            "silent edit is a root mismatch."
        ),
        "generated_from": {
            "catalog": "docs/evidence/G1/upstream-test-catalog.json",
            "catalog_sha256": catalog_sha,
            "source_lock_digest": catalog["source_lock_digest"],
            "behaviour_checkout": "sources/typedb-behaviour",
        },
        "toolchains": toolchains,
        "profiles": {
            p["profile_id"]: {k: v for k, v in p.items() if k != "profile_id"}
            for p in catalog["profiles"]
        },
        "fixture_sets": dict(sorted(fixture_sets.items())),
        "fixtures": sorted(catalog["fixtures"], key=lambda f: f["fixture_id"]),
        "leaves": dict(sorted(leaves.items())),
        "row_columns": ["leaf_case_id", "profile_id", "fixture_set_id", "toolchain_id"],
        "rows": rows,
        "driver_rows": driver_rows,
        "exclusions": sorted(catalog["exclusions"], key=lambda e: e["subject_id"]),
        "counts": {
            "targets": len(catalog["targets"]),
            "leaves": len(leaves),
            "rows": len(rows),
            "driver_rows": len(driver_rows),
            "exclusions": len(catalog["exclusions"]),
            "profiles": len(catalog["profiles"]),
        },
    }
    return body


def write_plan(body, path):
    doc = dict(body)
    doc["plan_root"] = plan_root_of(body)
    # rows one-per-line: reviewable diffs without exploding every element
    rows = doc.pop("rows")
    head = json.dumps(doc, sort_keys=True, indent=1, ensure_ascii=False)
    rows_text = ",\n  ".join(json.dumps(r, ensure_ascii=False) for r in rows)
    text = head[:-2] + ',\n "rows": [\n  ' + rows_text + "\n ]\n}\n"
    # the spliced text must parse back to exactly body+root, or nothing is written
    parsed = json.loads(text)
    root = parsed.pop("plan_root")
    if parsed != body or root != doc["plan_root"]:
        sys.exit("plan: serialization round-trip failed - refusing to write")
    path.write_text(text)
    return doc["plan_root"]


SOURCE_LOCK = REPO / "source-lock" / "source-lock.json"


def check(catalog, catalog_sha, require_current_lock=False):
    """Committed plan vs the catalogue: any drift is nonzero. With
    require_current_lock, a plan/catalogue whose source_lock_digest is not
    the sha256 of the CURRENT source-lock.json also fails (R4-EVID-01a)."""
    if not PLAN.exists():
        print(f"CHECK FAIL: {PLAN} does not exist", file=sys.stderr)
        return 1
    committed = json.loads(PLAN.read_text())
    committed_root = committed.pop("plan_root", None)
    recomputed_committed_root = plan_root_of(committed)
    problems = []
    # R4-EVID-01a: the plan copies the catalogue's lock digest; compare it
    # to the CURRENT lock file, always report, fail only when required to
    current_lock = common.sha256_file(SOURCE_LOCK) if SOURCE_LOCK.is_file() else None
    pinned_lock = (committed.get("generated_from") or {}).get("source_lock_digest")
    if pinned_lock != current_lock:
        msg = (
            f"plan pins source_lock_digest {pinned_lock} (copied from the "
            f"catalogue) but the current "
            f"{SOURCE_LOCK.relative_to(REPO)} hashes {current_lock} - the "
            f"source binding is STALE (R5-EVID-01: regenerate catalogue + "
            f"plan against the current lock)"
        )
        if require_current_lock:
            problems.append(msg)
        else:
            print(f"STALE-LOCK: {msg}", file=sys.stderr)
    if committed_root != recomputed_committed_root:
        problems.append(
            f"committed plan_root {committed_root} != root of the committed "
            f"body {recomputed_committed_root} - the plan was hand-edited"
        )
    body = build_body(catalog, catalog_sha)
    problems.extend(errors)
    if not errors and canonical(body) != canonical(committed):
        fresh_root = plan_root_of(body)
        problems.append(
            f"plan drift: rebuilding from the current catalogue yields root "
            f"{fresh_root}, the committed plan body hashes "
            f"{recomputed_committed_root}"
        )
        for key in body:
            if canonical(body.get(key)) != canonical(committed.get(key)):
                problems.append(f"plan drift in section {key!r}")
    for p in problems:
        print(f"CHECK FAIL: {p}", file=sys.stderr)
    if not problems:
        print(
            f"plan check OK: {committed_root} "
            f"({committed['counts']['rows']} rows, "
            f"{committed['counts']['driver_rows']} driver rows, "
            f"{committed['counts']['exclusions']} exclusion rows)"
        )
    return 1 if problems else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--catalog", type=pathlib.Path, default=CATALOG)
    ap.add_argument("--out", type=pathlib.Path, default=PLAN)
    ap.add_argument(
        "--check",
        action="store_true",
        help="revalidate the committed plan against the catalogue; drift is a nonzero exit",
    )
    ap.add_argument(
        "--require-current-lock",
        action="store_true",
        help="with --check: FAIL if the plan's pinned "
        "source_lock_digest is not the sha256 of the current "
        "source-lock/source-lock.json (R5-EVID-01: CI runs "
        "this as a BLOCKING step; regenerate whenever the "
        "source lock changes)",
    )
    args = ap.parse_args()
    catalog = json.loads(args.catalog.read_text())
    catalog_sha = common.sha256_file(args.catalog)

    if args.check:
        return check(catalog, catalog_sha, require_current_lock=args.require_current_lock)

    body = build_body(catalog, catalog_sha)
    for e in errors:
        print(f"ERROR: {e}", file=sys.stderr)
    if errors:
        return 1
    root = write_plan(body, args.out)
    rel = args.out.relative_to(REPO) if args.out.is_relative_to(REPO) else args.out
    counts = body["counts"]
    print(
        json.dumps(
            {"plan": str(rel), "plan_root": root, **(counts if isinstance(counts, dict) else {})},
            indent=1,
        )
    )
    print(
        "NOTE: this plan is a denominator, not a result - nothing is proven "
        "executed by its existence.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
