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

# lock node id -> Cargo.lock files (relative to repo root) that must pin the
# crates — every workspace that consumes the crate is checked
REGISTRY_NODES = {
    "SL": ["tools/Cargo.lock", "fork/typedb/Cargo.lock"],
}


def cargo_lock_packages(path: pathlib.Path) -> dict:
    """name -> (version, checksum) for registry packages in a Cargo.lock."""
    pkgs = {}
    def quoted(line: str):
        parts = line.split('"')
        return parts[1] if len(parts) >= 2 else None

    name = version = source = checksum = None
    in_package = False
    for line in path.read_text().splitlines() + ["[[package]]"]:
        if line.strip() == "[[package]]":
            if in_package and name and source and "registry+" in source:
                pkgs[name] = (version, checksum)
            name = version = source = checksum = None
            in_package = True
        elif in_package and line.startswith("name = "):
            name = quoted(line)
        elif in_package and line.startswith("version = "):
            version = quoted(line)
        elif in_package and line.startswith("source = "):
            source = quoted(line)
        elif in_package and line.startswith("checksum = "):
            checksum = quoted(line)
    return pkgs


def check_registry_node(nid: str, node: dict, lock_rel: str, failures: list) -> None:
    lock_path = REPO / lock_rel
    if not lock_path.exists():
        failures.append(f"{nid}: consumer lockfile missing at {lock_rel}")
        return
    pkgs = cargo_lock_packages(lock_path)
    want = {node["crate"]: (node["version"].lstrip("="), node["checksum_sha256"])}
    for cname, cinfo in node.get("companion_crates", {}).items():
        want[cname] = (cinfo["version"].lstrip("="), cinfo["checksum_sha256"])
    for cname, (wver, wsum) in want.items():
        got = pkgs.get(cname)
        if got is None:
            failures.append(f"{nid}: crate {cname} not pinned in {lock_rel}")
        elif got != (wver, wsum):
            failures.append(
                f"{nid}: crate {cname} mismatch want {(wver, wsum)} got {got}")


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

    for nid, lock_rels in REGISTRY_NODES.items():
        node = nodes.get(nid)
        if node is None:
            failures.append(f"{nid}: missing from lock")
            continue
        if node.get("kind") != "registry":
            failures.append(f"{nid}: expected kind 'registry', got {node.get('kind')!r}")
            continue
        for lock_rel in lock_rels:
            check_registry_node(nid, node, lock_rel, failures)

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
