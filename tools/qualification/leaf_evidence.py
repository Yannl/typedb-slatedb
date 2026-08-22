#!/usr/bin/env python3
"""Load sealed leaf bundles into a coverage index — the one implementation.

This function used to live in `leaf_coverage.py`, which imports
`plan_coverage.py` for the coverage rules, while `plan_coverage.py` imported
`leaf_coverage.py` back for exactly this function. That is a cycle, and the
deferred import that made it work at runtime only hid it: both modules are
still each other's dependency, and which of the two is half-initialised when
something imports them in a new order is not a property anyone was choosing.

Extracted here so the dependency runs one way — plan_coverage and
leaf_coverage both read this module, and neither reads the other for it.
"""

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))

import leaf_common as lc  # noqa: E402
import verify_leaf  # noqa: E402


def load_leaf_evidence(dirs, plan, catalog_leaves, catalog_targets, repo=REPO):
    """(leaf_index, notes). leaf_index maps (profile, leaf_case_id) -> ref.

    Every bundle is RE-VERIFIED from its bytes before a single row of it is
    counted. This is the whole difference between evidence and assertion.
    """
    index, notes = {}, []
    for d in dirs:
        p = pathlib.Path(d)
        p = p if p.is_absolute() else pathlib.Path(repo) / p
        anomalies, facts = verify_leaf.verify(p, plan, catalog_leaves, catalog_targets, repo=repo)
        note = {**facts, "bundle": str(d), "anomalies": anomalies, "counted": False}
        if anomalies:
            note["reason"] = (
                f"{len(anomalies)} verification anomaly/anomalies - "
                f"a bundle that does not re-derive from its own "
                f"bytes contributes NOTHING"
            )
            notes.append(note)
            continue
        bundle = json.loads((p / lc.RESULTS_NAME).read_text())
        profile = bundle["profile"]
        if profile not in plan["profiles"]:
            note["reason"] = (
                f"profile {profile!r} is not a plan profile; this "
                f"bundle's leaves are other-lane evidence and cover "
                f"no plan row"
            )
            notes.append(note)
            continue
        tc_id = bundle.get("toolchain_id")
        if tc_id is None:
            note["reason"] = (
                "the measured toolchain matches no toolchain the "
                "plan names; a run on an unnamed compiler is not "
                "filed under the plan's lane"
            )
            notes.append(note)
            continue
        if not (p / "COMPLETE").is_file():
            note["reason"] = (
                "no COMPLETE marker - the bundle was never sealed; "
                "an unsealed bundle is a run in progress, not "
                "archived evidence"
            )
            notes.append(note)
            continue
        n = 0
        for leaf in bundle["leaves"]:
            if not leaf.get("fixture_set_satisfied"):
                continue
            key = (profile, leaf["leaf_case_id"])
            ref = {
                "bundle": str(d),
                "profile": profile,
                "outcome": leaf["outcome"],
                "fixture_set_id": leaf["fixture_set_id"],
                "toolchain_id": tc_id,
                "raw_log": leaf["raw_log"],
                "log_line": leaf["log_line"],
                "log_sha256": leaf["log_sha256"],
            }
            index.setdefault(key, []).append(ref)
            n += 1
        note.update({"counted": True, "leaves_indexed": n, "tree_state": facts["tree_state"]})
        notes.append(note)
    return index, notes
