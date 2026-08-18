#!/usr/bin/env python3
"""Validate the generated catalogue against the NORMATIVE contract schema.

`contract/typedb-r2-v14-upstream-test-catalog.schema.json` has been in the
repository since v14 and nothing ever checked the catalogue against it. That
is how a catalogue acquires 27 duplicated leaf ids, 44 leaves pointing at a
target that does not exist, and a profile matrix that silently disagrees with
the conformance plan: the schema is the contract's shape, and an unchecked
contract is prose.

Two layers, both fail-closed:

  1. SCHEMA - a self-contained validator for the JSON Schema subset the
     contract actually uses (type, enum, const, required, properties,
     additionalProperties, items, $ref/$defs, minItems, minLength, pattern,
     format:date). No third-party dependency, because the bootstrap must
     stay a rootless `python3 file.py`.

  2. SEMANTICS - the invariants a shape cannot express: leaf ids unique,
     every leaf's target present, every required pair's leaf present, every
     required pair's profile declared, every exclusion subject resolvable,
     no unexpired-exclusion/leaf contradiction.

Usage:
  python3 tools/catalog/validate_catalog.py                # the committed catalogue
  python3 tools/catalog/validate_catalog.py --catalog X.json
  python3 tools/catalog/validate_catalog.py --self-test    # negative controls
"""
import argparse
import datetime
import copy
import json
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
SCHEMA = REPO / "contract" / "typedb-r2-v14-upstream-test-catalog.schema.json"
CATALOG = REPO / "docs" / "evidence" / "G1" / "upstream-test-catalog.json"

TYPES = {
    "object": dict, "array": list, "string": str, "boolean": bool,
    "number": (int, float), "integer": int, "null": type(None),
}


def type_ok(value, spec):
    names = spec if isinstance(spec, list) else [spec]
    for n in names:
        t = TYPES.get(n)
        if t is None:
            continue
        if n in ("number", "integer") and isinstance(value, bool):
            continue
        if isinstance(value, t):
            return True
    return False


def validate(node, schema, root, path, errors):
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            errors.append(f"{path}: unsupported $ref {ref}")
            return
        validate(node, root["$defs"][ref[len("#/$defs/"):]], root, path, errors)
        return
    if "const" in schema and node != schema["const"]:
        errors.append(f"{path}: {node!r} != const {schema['const']!r}")
    if "enum" in schema and node not in schema["enum"]:
        errors.append(f"{path}: {node!r} not in enum {schema['enum']}")
    if "type" in schema and not type_ok(node, schema["type"]):
        errors.append(f"{path}: {type(node).__name__} is not {schema['type']}")
        return
    if isinstance(node, str):
        if "minLength" in schema and len(node) < schema["minLength"]:
            errors.append(f"{path}: shorter than minLength {schema['minLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], node):
            errors.append(f"{path}: {node!r} does not match {schema['pattern']}")
        if schema.get("format") == "date":
            try:
                datetime.date.fromisoformat(node)
            except ValueError:
                errors.append(f"{path}: {node!r} is not an ISO date")
    if isinstance(node, list):
        if "minItems" in schema and len(node) < schema["minItems"]:
            errors.append(f"{path}: {len(node)} items < minItems {schema['minItems']}")
        item = schema.get("items")
        if item:
            for i, v in enumerate(node):
                validate(v, item, root, f"{path}[{i}]", errors)
    if isinstance(node, dict):
        props = schema.get("properties", {})
        for r in schema.get("required", []):
            if r not in node:
                errors.append(f"{path}: missing required property {r!r}")
        if schema.get("additionalProperties") is False:
            for k in node:
                if k not in props:
                    errors.append(f"{path}: additional property {k!r} is not allowed")
        for k, v in node.items():
            if k in props:
                validate(v, props[k], root, f"{path}.{k}", errors)


def semantic_checks(cat):
    errors = []
    target_ids = {t["target_id"] for t in cat["targets"]}
    if len(target_ids) != len(cat["targets"]):
        errors.append("targets: duplicate target_id")
    leaf_ids = set()
    for lc in cat["leaf_cases"]:
        if lc["leaf_case_id"] in leaf_ids:
            errors.append(f"leaf_cases: duplicate leaf_case_id {lc['leaf_case_id']!r}")
        leaf_ids.add(lc["leaf_case_id"])
        if lc["target_id"] not in target_ids:
            errors.append(
                f"leaf_cases: {lc['leaf_case_id']!r} references unknown target "
                f"{lc['target_id']!r}")
    profile_ids = {p["profile_id"] for p in cat["profiles"]}
    pair_profiles = set()
    for rp in cat["required_pairs"]:
        if rp["leaf_case_id"] not in leaf_ids:
            errors.append(
                f"required_pairs: unknown leaf_case_id {rp['leaf_case_id']!r}")
        if rp["profile_id"] not in profile_ids:
            errors.append(f"required_pairs: unknown profile {rp['profile_id']!r}")
        pair_profiles.add(rp["profile_id"])
    if len(cat["required_pairs"]) != len({(r["leaf_case_id"], r["profile_id"])
                                          for r in cat["required_pairs"]}):
        errors.append("required_pairs: duplicate (leaf, profile) pair")
    leaves_per_target = {}
    for lc in cat["leaf_cases"]:
        leaves_per_target[lc["target_id"]] = leaves_per_target.get(lc["target_id"], 0) + 1
    declared_zero = set()
    for ex in cat["exclusions"]:
        sid = ex["subject_id"]
        if sid in target_ids:
            declared_zero.add(sid)
            if leaves_per_target.get(sid, 0):
                errors.append(
                    f"exclusions: {sid} is declared zero-case but carries "
                    f"{leaves_per_target[sid]} leaves")
        elif not sid.startswith(("bazel:", "policy:")):
            errors.append(f"exclusions: subject {sid!r} resolves to nothing")
        try:
            if datetime.date.fromisoformat(ex["expiry"]) < datetime.date.today():
                errors.append(f"exclusions: {sid} expired ({ex['expiry']})")
        except ValueError:
            errors.append(f"exclusions: {sid} has a malformed expiry")
    for tid in sorted(target_ids):
        if not leaves_per_target.get(tid, 0) and tid not in declared_zero:
            errors.append(
                f"targets: {tid} has zero leaf cases and no declared exclusion - "
                f"an undeclared empty target is indistinguishable from a lost suite")
    return errors, sorted(pair_profiles)


def self_test():
    """Negative controls: each mutant of a valid catalogue must be REJECTED."""
    schema = json.loads(SCHEMA.read_text())
    base = {
        "schema_version": 1,
        "source_lock_digest": "a" * 64,
        "rust_toolchain": {"rustc": "r", "cargo": "c"},
        "target_triple": "x86_64-unknown-linux-gnu",
        "bazel_query_oracle": None,
        "profiles": [{"profile_id": p, "kv_backend": "k", "durability": "d",
                      "object_store": "o", "controller": "c"}
                     for p in ("U0", "U1", "U2", "U3", "U4")],
        "targets": [{"target_id": "cargo:p:unit:t", "origin": "CARGO",
                     "upstream_label": None, "cargo_package": "p", "cargo_target": "t",
                     "source_files": [{"path": "a.rs", "sha256": "b" * 64}],
                     "case_discovery": "LIBTEST_LIST", "platform_predicate": "any",
                     "timeout_seconds": 60, "serial_group": None,
                     "port_status": "BYTE_IDENTICAL"}],
        "leaf_cases": [{"leaf_case_id": "cargo:p:unit:t::x", "target_id": "cargo:p:unit:t",
                        "kind": "LIBTEST", "source_hash": "b" * 64,
                        "declared_ignored": False}],
        "required_pairs": [{"leaf_case_id": "cargo:p:unit:t::x", "profile_id": "U0"}],
        "fixtures": [],
        "exclusions": [],
    }
    failures = []

    def check(label, mutate, expect_schema=False):
        cat = copy.deepcopy(base)
        mutate(cat)
        errs = []
        validate(cat, schema, schema, "$", errs)
        sem, _ = semantic_checks(cat)
        if not (errs if expect_schema else errs + sem):
            failures.append(f"self-test '{label}' was accepted but must be rejected")

    # the baseline must actually pass (a self-test whose fixture is itself
    # invalid proves nothing about the mutants)
    errs = []
    validate(base, schema, schema, "$", errs)
    sem, profs = semantic_checks(base)
    if errs or sem:
        failures.append(f"self-test: valid baseline rejected: {errs + sem}")

    check("duplicate leaf id", lambda c: c["leaf_cases"].append(dict(c["leaf_cases"][0])))
    check("leaf pointing at a missing target",
          lambda c: c["leaf_cases"][0].__setitem__("target_id", "cargo:ghost:unit:ghost"))
    check("required pair naming an unknown leaf",
          lambda c: c["required_pairs"].append(
              {"leaf_case_id": "nope", "profile_id": "U0"}))
    check("target with zero leaves and no declaration",
          lambda c: c["targets"].append(dict(c["targets"][0], target_id="cargo:p:unit:empty")))
    check("profile outside the contract enum",
          lambda c: c["profiles"].append(dict(c["profiles"][0], profile_id="U2S3")),
          expect_schema=True)
    check("undeclared extra property on a target",
          lambda c: c["targets"][0].__setitem__("leaf_count", 0), expect_schema=True)
    check("non-hex source digest",
          lambda c: c["leaf_cases"][0].__setitem__("source_hash", "zz"), expect_schema=True)

    for f in failures:
        print(f"SELF-TEST FAIL: {f}", file=sys.stderr)
    print(f"validate_catalog self-test: {'FAIL' if failures else 'PASS'} "
          f"(7 negative controls + baseline)", file=sys.stderr)
    return 1 if failures else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--catalog", type=pathlib.Path, default=CATALOG)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()

    schema = json.loads(SCHEMA.read_text())
    cat = json.loads(args.catalog.read_text())
    errors = []
    validate(cat, schema, schema, "$", errors)
    sem, pair_profiles = semantic_checks(cat)
    errors += sem
    print(json.dumps({
        "catalog": str(args.catalog.relative_to(REPO)),
        "targets": len(cat["targets"]),
        "leaf_cases": len(cat["leaf_cases"]),
        "unique_leaf_cases": len({l["leaf_case_id"] for l in cat["leaf_cases"]}),
        "required_pairs": len(cat["required_pairs"]),
        "required_pair_profiles": pair_profiles,
        "exclusions": len(cat["exclusions"]),
        "errors": len(errors),
    }, indent=1))
    for e in errors[:200]:
        print(f"ERROR: {e}", file=sys.stderr)
    if len(errors) > 200:
        print(f"... and {len(errors) - 200} more", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
