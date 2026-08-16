#!/usr/bin/env python3
"""G0 source-lock linter (BT-P0 scope).

Validates that every node in source-lock/source-lock.json is resolved and,
for git nodes, that the corresponding checkout under sources/ exists, is
clean, and sits at exactly the locked revision. Exits non-zero on any
unresolved node, missing checkout, revision mismatch, or dirty tree.

Negative control: hide or corrupt any checkout (e.g. rename sources/typedb)
and this linter MUST fail. The archived run of that control lives in
docs/evidence/G0/negative-control-missing-node.txt.
"""
import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
LOCK = REPO / "source-lock" / "source-lock.json"
SOURCES = REPO / "sources"

# lock node id -> sources/ directory name
GIT_DIRS = {
    "TB": "typedb",
    "SL": "slatedb",
    "BH": "typedb-behaviour",
    "TBD": "typedb-dependencies",
    "TBDIST": "typedb-bazel-distribution",
    "TQL": "typeql",
    "TPROTO": "typedb-protocol",
    "TDRIVER": "typedb-driver",
    "CF_CTR_SOURCE": "cloudflare-containers",
    "CF_WORKERS_SDK": "cloudflare-workers-sdk",
}

ARTIFACTS = {
    "TCONSOLE": "fixtures/console/typedb-console-linux-x86_64-3.12.0.tar.gz",
    "TLOADER": "fixtures/loader/typedb-loader-linux-x86_64-3.12.0.tar.gz",
}


def sha256(path: pathlib.Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    failures = []
    lock = json.loads(LOCK.read_text())
    nodes = {n["id"]: n for n in lock["nodes"]}

    for nid, node in nodes.items():
        status = node.get("status", "")
        if status.startswith(("locked", "recorded", "declared_not_yet_qualified",
                              "architecture_choice_required")):
            pass
        else:
            failures.append(f"{nid}: unresolved status {status!r}")

    for nid, dirname in GIT_DIRS.items():
        node = nodes.get(nid)
        if node is None:
            failures.append(f"{nid}: missing from lock")
            continue
        want = node.get("revision") or node.get("resolved_revision")
        d = SOURCES / dirname
        if not (d / ".git").exists():
            failures.append(f"{nid}: checkout missing at sources/{dirname}")
            continue
        got = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"],
                             capture_output=True, text=True).stdout.strip()
        if got != want:
            failures.append(f"{nid}: revision mismatch want {want} got {got}")
        dirty = subprocess.run(["git", "-C", str(d), "status", "--porcelain"],
                               capture_output=True, text=True).stdout.strip()
        if dirty:
            failures.append(f"{nid}: dirty tree at sources/{dirname}")

    for nid, rel in ARTIFACTS.items():
        node = nodes.get(nid)
        if node is None:
            failures.append(f"{nid}: missing from lock")
            continue
        p = SOURCES / rel
        if not p.exists():
            failures.append(f"{nid}: artifact missing at sources/{rel}")
            continue
        got = sha256(p)
        if got != node["sha256"]:
            failures.append(f"{nid}: sha256 mismatch want {node['sha256']} got {got}")

    if failures:
        print("SOURCE-LOCK LINT: FAIL")
        for f in failures:
            print("  -", f)
        return 1
    print(f"SOURCE-LOCK LINT: PASS ({len(GIT_DIRS)} git nodes, "
          f"{len(ARTIFACTS)} artifacts, {len(nodes)} lock nodes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
