"""Shared facts for the catalogue toolchain (one definition each).

Everything here computes RELEASE-DENOMINATOR inputs or identities that more
than one producer consumes. Duplicating any of it forked the truth once
already: the denominator join lived in both run_u0 and completeness, so a
repair to one silently diverged the other.
"""

import hashlib
import os
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[2]
TB = REPO / "sources" / "typedb"
CATALOG = REPO / "docs" / "evidence" / "G1" / "upstream-test-catalog.json"
TOOLCHAIN = "+1.93.0"

# hermetic, deterministic cargo environment for catalogue/corpus builds
CARGO_ENV = {
    **os.environ,
    "CARGO_INCREMENTAL": "0",
    "CARGO_PROFILE_DEV_DEBUG": "false",
    "CARGO_PROFILE_TEST_DEBUG": "false",
}


def sha256_file(path):
    """Chunked file digest (the evidence identity primitive)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def package_name_from_id(package_id):
    """Package name from a cargo package-id spec (`url[#[name@]version]`).

    Cargo omits the `name@` part of the fragment when the name equals the
    final path segment of the url, so `...typedb/concept#0.0.0` means package
    `concept` while `...storage/tests#test_utils_storage@0.0.0` means package
    `test_utils_storage`. Parsing the fragment alone collapses most workspace
    crates onto the bare version string.
    """
    url, _, frag = package_id.partition("#")
    if "@" in frag:
        return frag.split("@")[0]
    return url.rstrip("/").rsplit("/", 1)[-1]


def is_non_libtest_harness_error(head):
    """True when output shows a `harness = false` binary rejecting libtest
    flags. Harness DETECTION, not failure classification: both the catalogue
    generator and the corpus runner must agree on what a harness is."""
    return ("Unrecognized option" in head or "unexpected argument" in head
            or "error: Found argument" in head)


def required_executable_targets(catalog):
    """The executable denominator, joined to the runner's row ids.

    The catalogue's target ids (`cargo:<pkg>:<kind>:<target>`) and the
    runner's row ids (`<pkg>:<target>`) live in different id spaces, which is
    why NONE of the 106 result ids could be found in the catalogue and the
    denominator was never actually checked. The cargo package/target pair the
    catalogue already records is the join.

    Two different things wear the "zero leaves" label and must not be
    confused: a [[bench]] target is COMPILED by the cargo test lane and never
    executed as a test, so it produces no row and is exempt; a crate with no
    #[test] functions DOES run and reports zero cases - it stays required, it
    is simply not case-bearing.

    Returns (required_row_ids, case_bearing_row_ids, excluded_row_id_reasons).
    """
    declared = {e["subject_id"]: e.get("reason") for e in catalog.get("exclusions", []) if e.get("subject_id")}
    leaves = {}
    for lc in catalog["leaf_cases"]:
        leaves[lc["target_id"]] = leaves.get(lc["target_id"], 0) + 1
    required, case_bearing, excluded = set(), set(), {}
    for t in catalog["targets"]:
        if t.get("origin") != "CARGO":
            continue
        pkg, tgt = t.get("cargo_package"), t.get("cargo_target")
        if not pkg or not tgt:
            continue
        rid = f"{pkg}:{tgt}"
        if t["target_id"].split(":")[2:3] == ["bench"]:
            excluded[rid] = declared.get(
                t["target_id"], "cargo target kind == bench: compiled, never executed as a test")
            continue
        required.add(rid)
        if leaves.get(t["target_id"], 0) > 0:
            case_bearing.add(rid)
    return required, case_bearing, excluded
