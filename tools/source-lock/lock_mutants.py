#!/usr/bin/env python3
"""Behavioral negative controls for the source-lock linter (E-P0-02).

The audit forged four lock mutations and the linter of record passed all of
them with RC 0, because it validated only selected node kinds. These
controls re-apply every one of those forgeries (plus three more of the same
class) to a TEMP COPY of source-lock.json and run the real linter CLI as a
subprocess against it. A control "holds" only if the linter exits non-zero
AND its output names the mutated node — a silent or generic failure would
be as unreviewable as a false green.

Nothing here touches the real files: lock mutants use the linter's
--lock-file override; the consumer-Cargo.lock mutant builds a shadow repo
root out of symlinks (real bytes everywhere except the one mutated
Cargo.lock copy) and uses --repo-root. If any mutant survives, this script
exits non-zero: a surviving mutant means the linter is false-green again
and MUST NOT be trusted until the gap is closed.

Run: python3 tools/source-lock/lock_mutants.py
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
LINTER = REPO / "tools" / "source-lock" / "lint_source_lock.py"
LOCK = REPO / "source-lock" / "source-lock.json"
CONSUMER_LOCK = "fork/typedb/Cargo.lock"


def node(doc: dict, nid: str) -> dict:
    for n in doc["nodes"]:
        if n["id"] == nid:
            return n
    raise KeyError(f"lock has no node {nid} - the controls no longer match the lock")


# ---------------------------------------------------------------------------
# mutations: each takes the parsed lock and returns the id the linter must
# name. Mutants 1-4 are the audit's E-P0-02 forgeries, verbatim.
# ---------------------------------------------------------------------------


def mutant_object_store_version(doc):
    """E-P0-02 mutant 1: cargo_dependency version forged."""
    node(doc, "OBJECT_STORE")["version"] = "99.0.0"
    return "OBJECT_STORE"


def mutant_wrangler_integrity(doc):
    """E-P0-02 mutant 2: npm integrity forged (charset-valid, SRI-invalid)."""
    node(doc, "WRANGLER")["integrity"] = "sha512-FORGED"
    return "WRANGLER"


def mutant_git_tree_zeros(doc):
    """E-P0-02 mutant 3: git tree forged to forty zeros (well-formed hex, so
    only the checkout comparison can catch it)."""
    node(doc, "TB")["tree"] = "0" * 40
    return "TB"


def mutant_tdriver_tree_dropped(doc):
    """E-P0-02 mutant 4: git_tag node kept with no tree field at all."""
    del node(doc, "TDRIVER")["tree"]
    return "TDRIVER"


def mutant_registry_checksum_forged(doc):
    """registry crate checksum forged (well-formed 64-hex, wrong bytes) —
    must fail against the consumer Cargo.locks, not just shape checks."""
    node(doc, "SL")["checksum_sha256"] = "f" * 64
    return "SL"


def mutant_artifact_sha_malformed(doc):
    """artifact sha256 malformed (not 64-hex) — shape check must fire even
    before the on-disk digest comparison gets a chance to."""
    node(doc, "TCONSOLE")["sha256"] = "deadbeef"
    return "TCONSOLE"


LOCK_MUTANTS = [
    mutant_object_store_version,
    mutant_wrangler_integrity,
    mutant_git_tree_zeros,
    mutant_tdriver_tree_dropped,
    mutant_registry_checksum_forged,
    mutant_artifact_sha_malformed,
]


def build_shadow_root(tmp: pathlib.Path) -> pathlib.Path:
    """A repo root that IS this repo (symlinks) except for one real-copy
    fork/typedb/Cargo.lock the consumer-lock mutant can edit. Symlinks keep
    the control cheap and honest: every unmutated byte the linter reads is
    the real byte."""
    root = tmp / "repo"
    root.mkdir()
    for child in sorted(REPO.iterdir()):
        if child.name != "fork":
            os.symlink(child, root / child.name)
    (root / "fork").mkdir()
    for child in sorted((REPO / "fork").iterdir()):
        if child.name != "typedb":
            os.symlink(child, root / "fork" / child.name)
    (root / "fork" / "typedb").mkdir()
    for child in sorted((REPO / "fork" / "typedb").iterdir()):
        if child.name != "Cargo.lock":
            os.symlink(child, root / "fork" / "typedb" / child.name)
    shutil.copy2(REPO / CONSUMER_LOCK, root / CONSUMER_LOCK)
    return root


def run_linter(lock_file: pathlib.Path, repo_root: pathlib.Path):
    r = subprocess.run(
        [sys.executable, str(LINTER), "--lock-file", str(lock_file), "--repo-root", str(repo_root)],
        capture_output=True,
        text=True,
    )
    return r.returncode, (r.stdout + r.stderr)


def judge(label: str, must_name: str, rc: int, output: str) -> bool:
    if rc == 0:
        print(f"  SURVIVED  {label}: linter returned 0 on a forged lock")
        return False
    if must_name not in output:
        print(
            f"  SURVIVED  {label}: linter failed (rc={rc}) but never "
            f"named node {must_name}; a failure nobody can act on"
        )
        return False
    line = next(
        (
            out_line.strip()
            for out_line in output.splitlines()
            if must_name in out_line and out_line.strip().startswith("-")
        ),
        "",
    )
    print(f"  held      {label} (rc={rc}) {line}")
    return True


def main() -> int:
    held = total = 0
    with tempfile.TemporaryDirectory(prefix="lock-mutants-") as tmpdir:
        tmp = pathlib.Path(tmpdir)

        for mutate in LOCK_MUTANTS:
            total += 1
            doc = json.loads(LOCK.read_text())
            must_name = mutate(doc)
            mutated = tmp / f"mutant-{total}-{mutate.__name__}.json"
            mutated.write_text(json.dumps(doc, indent=2) + "\n")
            rc, out = run_linter(mutated, REPO)
            if judge(mutate.__name__, must_name, rc, out):
                held += 1

        # consumer-lock mutant: the LOCK is untouched and true; the consumer
        # Cargo.lock in a shadow root drifts (object_store version bumped).
        # The lock-vs-consumer agreement must fail from either side.
        total += 1
        root = build_shadow_root(tmp)
        clock = root / CONSUMER_LOCK
        text = clock.read_text()
        needle = 'name = "object_store"\nversion = "0.14.1"'
        if needle not in text:
            print(
                "  SURVIVED  mutant_consumer_lock_bumped: could not apply "
                "(object_store 0.14.1 not found in Cargo.lock - update the control)"
            )
        else:
            clock.write_text(text.replace(needle, 'name = "object_store"\nversion = "0.99.0"', 1))
            rc, out = run_linter(LOCK, root)
            if judge("mutant_consumer_lock_bumped", "OBJECT_STORE", rc, out):
                held += 1

    print(f"source-lock mutants: {held}/{total} controls held")
    return 0 if held == total else 1


if __name__ == "__main__":
    sys.exit(main())
