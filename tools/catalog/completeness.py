#!/usr/bin/env python3
"""F10 remainder: denominator-completeness checks over the test catalogue.

Four independent verifications, each fail-closed (any anomaly is a nonzero
exit naming the exact site - silent omission is the defect class this tool
exists to kill):

  1. BUILD declaration parsing - a balanced-paren declaration scanner over
     every upstream BUILD file. Any call to a *_test rule whose `name`
     cannot be extracted as a STRING LITERAL is a hard error (the previous
     regex reconnaissance silently missed reformatted declarations - the
     exact fail-open defect the donor's Starlark parser avoids). Every
     extracted rust_test name must reconcile against a cargo-catalogued
     target or an explicit allowlist entry with a reason.

  2. Cucumber leaf recount - an INDEPENDENT stricter parser over every
     feature file the catalogue references; per-file leaf counts must equal
     the catalogue's exactly (two disagreeing parsers = a parser bug or a
     stale catalogue; both stop the line).

  3. Failpoint x execution-context recount - re-derive the fail_points!
     registry and the ALL-loop contexts from source; the product must equal
     the catalogue's FAILPOINT leaves.

  4. Flake/exclusion ledger - docs/evidence/flake-ledger.json is the ONLY
     place a failing or ignored case may be tolerated. Every result row
     with failures/ignores must be covered by a ledger entry with matching
     counts, a reason, and an unexpired expiry; every ledger entry must
     still be live (stale entries are errors too - an exclusion that no
     longer fires is a debt that must be retired, not carried).

Usage:
  python3 tools/catalog/completeness.py --results docs/evidence/G3/u2s3-full-2
  python3 tools/catalog/completeness.py --self-test   # embedded negative controls
"""

import argparse
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import common  # noqa: E402
import verdict as verdict_policy  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[2]
TB = REPO / "sources" / "typedb"
BH = REPO / "sources" / "typedb-behaviour"
CATALOG = REPO / "docs" / "evidence" / "G1" / "upstream-test-catalog.json"
LEDGER = verdict_policy.LEDGER

# Bazel rust_test names that intentionally have no cargo-lane equivalent.
# Every entry needs a reason; an empty reason is treated as absent.
BUILD_ALLOWLIST = {
    # (build_file, name) -> reason
}

errors = []
dead_outlines = []


def error(msg):
    errors.append(msg)


# ---------------------------------------------------------------- BUILD scan


def scan_build_declarations(text, build_file):
    """All top-level `callee(...)` declarations, by balanced-paren walk.

    Returns [(callee, args_text, offset)]. No regex over the whole call:
    the walk cannot be defeated by newlines, nesting, or argument order.
    Strings are skipped quote-aware so parens inside them cannot unbalance
    the walk; # comments are skipped to end of line.
    """
    calls = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "#":
            i = text.find("\n", i)
            i = n if i == -1 else i
            continue
        if ch in "\"'":
            j = i + 1
            while j < n and text[j] != ch:
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            continue
        m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", text[i:])
        if m:
            callee = m.group(0)
            j = i + len(m.group(0))
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] == "(":
                depth, k = 0, j
                while k < n:
                    c = text[k]
                    if c == "#":
                        k = text.find("\n", k)
                        k = n if k == -1 else k
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
                    error(f"{build_file}: unbalanced parentheses in {callee}(... at offset {i}")
                    return calls
                calls.append((callee, text[j + 1 : k], i))
                i = k + 1
                continue
            i = j if j > i else i + 1
            continue
        i += 1
    return calls


def extract_name_literal(args_text):
    """The `name` attribute as a string literal, or None if not literal."""
    m = re.search(r"\bname\s*=\s*(\"[^\"]*\"|'[^']*')", args_text)
    if m:
        return m.group(1)[1:-1]
    return None


def check_build_declarations(catalog):
    cargo_targets = {t["cargo_target"] for t in catalog["targets"] if t.get("cargo_target")}
    # upstream convention: rust_test(name = "test_crate_X", crate = ":X")
    # is crate X's unit-test target; the cargo catalogue carries it as the
    # unit target named X
    unit_targets = {
        t["cargo_target"]
        for t in catalog["targets"]
        if t.get("cargo_target")
        and t["target_id"].startswith("cargo:")
        and ":unit:" in t["target_id"]
    }
    found = []
    for build in sorted(TB.rglob("BUILD")):
        parts = build.parts
        if "target" in parts or "bazel-typedb" in parts:
            continue
        rel = str(build.relative_to(TB))
        for callee, args, offset in scan_build_declarations(build.read_text(), rel):
            if not callee.endswith("_test"):
                continue
            name = extract_name_literal(args)
            if name is None:
                # fail closed: a test declaration whose name cannot be read
                # as a literal is INVISIBLE to the denominator
                error(
                    f"{rel}: {callee}( at offset {offset} has no literal name= - "
                    f"unparseable test declarations make the denominator silently incomplete"
                )
                continue
            found.append({"build_file": rel, "rule": callee, "name": name})
            crate_unit = (
                name.startswith("test_crate_") and name[len("test_crate_") :] in unit_targets
            )
            # a test_crate_* rule tests the library declared in ITS OWN
            # BUILD directory; when the Bazel library label differs from the
            # cargo package name (admin/client's ":client" is cargo package
            # "typedb-admin"), the sibling Cargo.toml's package identifies
            # the unit target that covers it - directory identity, not an
            # allowlist guess
            if name.startswith("test_crate_") and not crate_unit:
                sibling = build.parent / "Cargo.toml"
                if sibling.exists():
                    pkg = re.search(r"^\s*name\s*=\s*\"([^\"]+)\"", sibling.read_text(), re.M)
                    if pkg and pkg.group(1).replace("-", "_") in unit_targets:
                        crate_unit = True
            if (
                callee == "rust_test"
                and name not in cargo_targets
                and not crate_unit
                and not BUILD_ALLOWLIST.get((rel, name))
            ):
                error(
                    f"{rel}: rust_test '{name}' has no cargo-catalogued target and no allowlist entry"
                )
    return found


# ------------------------------------------------------------ cucumber leaves


def cucumber_leaves_strict(text, ref):
    """Leaf count of one feature file, by strict line state machine.

    Independent of generate_catalog's parser on purpose: agreement between
    two implementations is the check. A Scenario Outline whose Examples
    rows are all commented out expands to ZERO leaves (cucumber semantics);
    it is recorded in the dead-outline report so upstream dead scenarios
    stay visible, and the catalogue must agree (it must NOT count phantom
    leaves for them).
    """
    leaves = 0
    i = 0
    lines = text.splitlines()
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("Scenario Outline:"):
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
            if rows == 0:
                dead_outlines.append(f"{ref}:{i + 1}")
            leaves += rows
            i = j
            continue
        if line.startswith("Scenario:"):
            leaves += 1
        i += 1
    return leaves


def check_cucumber(catalog):
    per_feature_catalog = {}
    for lc in catalog["leaf_cases"]:
        if lc["kind"] != "CUCUMBER":
            continue
        ref = lc["target_id"].split("cucumber-corpus:", 1)[1]
        per_feature_catalog[ref] = per_feature_catalog.get(ref, 0) + 1
    checked = 0
    for ref, expected in sorted(per_feature_catalog.items()):
        f = BH / ref
        if not f.exists():
            error(
                f"cucumber: {ref} referenced by the catalogue but absent from the pinned checkout"
            )
            continue
        actual = cucumber_leaves_strict(f.read_text(), ref)
        if actual != expected:
            error(f"cucumber: {ref} leaf count {actual} (strict recount) != {expected} (catalogue)")
        checked += 1
    return checked, sum(per_feature_catalog.values())


# ------------------------------------------------------ failpoint x context


def check_failpoints(catalog):
    lib = (TB / "common" / "fail_point" / "lib.rs").read_text()
    m = re.search(r"fail_points!\s*\{(.*?)\}", lib, re.S)
    if not m:
        error("failpoints: fail_points! registry not found in common/fail_point/lib.rs")
        return 0, 0
    members = [
        x.strip().rstrip(",")
        for x in m.group(1).splitlines()
        if x.strip().rstrip(",") and re.fullmatch(r"[A-Z0-9_]+", x.strip().rstrip(","))
    ]
    fp_test = (TB / "tests" / "assembly" / "fail_points.rs").read_text()
    contexts = len(re.findall(r"for fail_point in fail_point::ALL", fp_test))
    expected = sum(1 for lc in catalog["leaf_cases"] if lc["kind"] == "FAILPOINT")
    actual = len(members) * contexts
    if actual != expected:
        error(
            f"failpoints: registry x contexts = {len(members)}x{contexts} = {actual} "
            f"!= {expected} catalogued FAILPOINT leaves"
        )
    if contexts == 0:
        error("failpoints: no fail_point::ALL execution contexts found - registry unexercised")
    return actual, expected


# ------------------------------------------------------------- flake ledger


def required_targets_from_catalog(catalog):
    """The shared denominator join - see common.required_executable_targets
    (one implementation; run_u0 consumes the same one)."""
    return common.required_executable_targets(catalog)


def check_ledger(results_dir, catalog=None, ledger_path=None):
    """Fail-closed policy over an executed run.

    Three mutants the previous version accepted, each closed here:
      - a results file containing ONLY the ledgered rows (the denominator was
        never compared against the catalogue, so a corpus of two rows passed);
      - a row with an unknown `rc=127` crash and zero parsed failures (only
        `failed`/`ignored`/`timed_out` were inspected, never the exit code);
      - a case-bearing target reporting zero cases (a binary that silently
        ran nothing looked identical to one with no tests).

    E-P0-06/07/10: the rows themselves are no longer trusted either. The
    shared bundle layer (verdict_policy.verify_bundle) reopens every raw log,
    checks its hash binding (row hash or sidecar manifest), REPARSES its
    libtest counts against the row, verifies ledger fingerprints against the
    log's actual failing case names, and recomputes the bundle root against
    the sidecar manifest and any root the COMPLETE marker binds.
    """
    ledger, problems = verdict_policy.load_ledger(ledger_path or LEDGER)
    for p in problems:
        error(p)
    data = json.loads((results_dir / "u0-results.json").read_text())
    results = data["results"]
    required = case_bearing = None
    if catalog is not None:
        required, case_bearing, excluded = required_targets_from_catalog(catalog)
        for a in verdict_policy.denominator_anomalies(results, required, excluded):
            error(a)
    for a in verdict_policy.classify_rows(results, ledger, expected_case_bearing=case_bearing):
        error(a)
    bundle_anoms, warnings, bundle_root = verdict_policy.verify_bundle(
        results_dir,
        results,
        ledger,
        file_profile=data.get("profile"),
        ledger_path=ledger_path or LEDGER,
    )
    for a in bundle_anoms:
        error(a)
    for w in warnings:
        print(f"WARNING: {w}", file=sys.stderr)
    return len(results), len(ledger), bundle_root


# ---------------------------------------------------------------- self-test


def self_test():
    """Embedded negative controls: each parser must REJECT its mutant."""
    failures = []

    def expect_errors(label, fn, minimum=1):
        del errors[:]
        fn()
        if len(errors) < minimum:
            failures.append(
                f"self-test '{label}' expected >= {minimum} error(s), got {len(errors)}"
            )
        del errors[:]

    # 1. non-literal name: must be a hard error, never a silent skip
    def non_literal():
        calls = scan_build_declarations(
            'NAME = "x"\nrust_test(\n  name = NAME,\n  srcs = ["a.rs"],\n)\n', "B"
        )
        for callee, args, offset in calls:
            if callee.endswith("_test") and extract_name_literal(args) is None:
                error("B: unparseable")

    expect_errors("non-literal rust_test name", non_literal)

    # 2. the balanced walk still finds a declaration a line-anchored regex misses
    reformatted = 'rust_test(srcs = ["a.rs"], name = "tucked_at_the_end")\n'
    calls = scan_build_declarations(reformatted, "B")
    names = [extract_name_literal(a) for c, a, o in calls if c == "rust_test"]
    if names != ["tucked_at_the_end"]:
        failures.append(f"self-test: reformatted declaration not fully parsed: {names}")
    legacy_regex = re.findall(r'rust_test\s*\(\s*\n\s*name\s*=\s*"([^"]+)"', reformatted)
    if legacy_regex:
        failures.append(
            "self-test: the legacy regex unexpectedly caught the reformatted declaration"
        )

    # 3. parens inside strings must not unbalance the walk
    tricky = 'rust_test(\n  name = "with_paren",\n  args = ["--filter=(a|b)"],\n)\n'
    calls = scan_build_declarations(tricky, "B")
    if [extract_name_literal(a) for c, a, o in calls if c == "rust_test"] != ["with_paren"]:
        failures.append("self-test: string-embedded parens broke the declaration walk")

    # 4. dead outline: zero leaves, visibly reported, never a phantom 1
    del dead_outlines[:]
    dead_count = cucumber_leaves_strict("Feature: f\n  Scenario Outline: o\n    Given x\n", "F")
    if dead_count != 0 or dead_outlines != ["F:2"]:
        failures.append(
            f"self-test: dead outline expected 0 leaves + report, got {dead_count} {dead_outlines}"
        )
    del dead_outlines[:]
    two_blocks = (
        "Feature: f\n  Scenario Outline: o\n    Given <a>\n"
        "    Examples:\n      | a |\n      | 1 |\n      | 2 |\n"
        "    Examples:\n      | a |\n      | 3 |\n"
        "  Scenario: plain\n    Given y\n"
    )
    del errors[:]
    count = cucumber_leaves_strict(two_blocks, "F")
    if count != 4 or errors:
        failures.append(
            f"self-test: two-Examples expansion expected 4 leaves, got {count} ({errors})"
        )
    del errors[:]

    # 5. results-policy mutants - each one was ACCEPTED before this change
    import tempfile

    def with_results(rows, cat=None, ledger=None):
        """A results dir plus an EMPTY ledger by default: these controls test
        the results policy, not the committed project ledger (whose entries
        would otherwise fire as stale against every synthetic run). Each row
        gets a real raw log whose libtest summary matches its counts, hashed
        into the row - the bundle layer now verifies bytes, so a synthetic
        run must carry real bytes for the CLEAN control to mean anything."""
        tmpdir = pathlib.Path(tempfile.mkdtemp())
        for r in rows:
            log = tmpdir / (r["target_id"].replace(":", "__") + ".log")
            log.write_text(
                f"\nrunning {r['passed'] + r['failed'] + r['ignored']} tests\n"
                f"test result: ok. {r['passed']} passed; {r['failed']} failed; "
                f"{r['ignored']} ignored; 0 measured; 0 filtered out; "
                f"finished in 0.00s\n"
            )
            r["raw_log"] = str(log)
            r["log_sha256"] = common.sha256_file(log)
        (tmpdir / "u0-results.json").write_text(json.dumps({"results": rows}))
        lp = tmpdir / "ledger.json"
        lp.write_text(json.dumps({"entries": ledger or []}))
        return lambda: check_ledger(tmpdir, cat, lp)

    # rc is None for a target that TIMED OUT: it never exited, so it has no
    # exit code, and 0 would read as success.
    def row(tid, p=1, f=0, i=0, rc: int | None = 0, to=False):
        return {
            "target_id": tid,
            "passed": p,
            "failed": f,
            "ignored": i,
            "exit_code": rc,
            "timed_out": to,
        }

    mini_catalog = {
        "targets": [
            {
                "target_id": "cargo:x:unit:t",
                "origin": "CARGO",
                "cargo_package": "x",
                "cargo_target": "t",
            },
            {
                "target_id": "cargo:y:unit:u",
                "origin": "CARGO",
                "cargo_package": "y",
                "cargo_target": "u",
            },
        ],
        "leaf_cases": [{"target_id": "cargo:x:unit:t"}, {"target_id": "cargo:y:unit:u"}],
        "exclusions": [],
    }
    expect_errors("unledgered failure", with_results([row("x:t", f=1, rc=101)]))
    expect_errors(
        "results truncated to the ledgered rows only", with_results([row("x:t")], mini_catalog)
    )
    expect_errors(
        "unknown rc=127 crash row with zero parsed failures",
        with_results([row("x:t", rc=127), row("y:u")], mini_catalog),
    )
    expect_errors(
        "case-bearing target that ran zero cases",
        with_results([row("x:t", p=0), row("y:u")], mini_catalog),
    )
    expect_errors(
        "timeout row", with_results([row("x:t", to=True, rc=None), row("y:u")], mini_catalog)
    )
    expect_errors(
        "row for a target the catalogue does not declare",
        with_results([row("x:t"), row("y:u"), row("ghost:g")], mini_catalog),
    )
    # and the clean case must be accepted, or the checks above prove nothing
    clean = with_results([row("x:t"), row("y:u")], mini_catalog)
    del errors[:]
    clean()
    if errors:
        failures.append(f"self-test: a clean run was rejected: {errors}")
    del errors[:]

    for f in failures:
        print(f"SELF-TEST FAIL: {f}", file=sys.stderr)
    print(
        f"self-test: {'FAIL' if failures else 'PASS'} "
        f"(10 negative-control groups + clean-run control)",
        file=sys.stderr,
    )
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results",
        type=pathlib.Path,
        help="evidence dir containing u0-results.json for the ledger check",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(self_test())

    catalog = json.loads(CATALOG.read_text())
    build_found = check_build_declarations(catalog)
    cucumber_files, cucumber_leaves = check_cucumber(catalog)
    fp_actual, fp_expected = check_failpoints(catalog)
    report = {
        "build_declarations": len(build_found),
        "build_rules": sorted({b["rule"] for b in build_found}),
        "cucumber_features_checked": cucumber_files,
        "cucumber_leaves": cucumber_leaves,
        "dead_outlines": dead_outlines,
        "failpoint_leaves": fp_actual,
    }
    if args.results:
        results_count, ledger_count, bundle_root = check_ledger(args.results, catalog)
        report["results_targets"] = results_count
        report["ledger_entries"] = ledger_count
        report["bundle_root"] = bundle_root
        required, case_bearing, excluded = required_targets_from_catalog(catalog)
        report["required_executable_targets"] = len(required)
        report["case_bearing_targets"] = len(case_bearing)
        report["declared_zero_case_targets"] = len(excluded)
        # E-P0-04 scope honesty: the execution-reconciliation denominator
        # above is ONLY the cargo-target projection of the catalogue. Saying
        # anything broader would be exactly the false-coverage claim this
        # tool exists to prevent.
        report["denominator_scope"] = "cargo-targets-only"

    print(json.dumps(report, indent=2))
    if args.results:
        print(
            "SCOPE: execution reconciliation above covers the CARGO-target "
            "projection of the catalogue ONLY; CUCUMBER/STATIC/FAILPOINT/SCRIPT "
            "leaves are recounted against the catalogue (checks 1-3) but are "
            "NOT execution-reconciled by this tool."
        )
    for e in errors:
        print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
