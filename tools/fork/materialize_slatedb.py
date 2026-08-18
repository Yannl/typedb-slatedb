#!/usr/bin/env python3
"""Deterministically reconstruct the SlateDB fork from the pinned crate.

The fork is stored as a PATCH SERIES, not a vendored tree. The upstream
bytes are already pinned by digest in source-lock/source-lock.json (node
`SL`), so committing a second copy of 5.4 MB of upstream source would add
weight without adding identity - and would make "what did we actually
change?" a diff against something nobody reads. What is committed is:

    fork/slatedb/patches/*.patch     the change, reviewable on its own
    fork/slatedb/UPSTREAM-PROVENANCE the exact crate + digest it applies to

and this script reproduces the tree from those two, verifying at every
step:

  1. the crate is fetched (or reused) and its sha256 must equal the digest
     in the source lock - a mismatching download is discarded, never kept;
  2. patches apply in filename order with `patch -p1` and no fuzz, so a
     patch that no longer applies is a hard failure rather than a silent
     partial application;
  3. the post-patch tree digest is recomputed and compared against the
     digest recorded in the provenance file, so an edited patch or an
     edited working tree is caught even when both individually "apply".

    python3 tools/fork/materialize_slatedb.py            # reconstruct
    python3 tools/fork/materialize_slatedb.py --check    # verify only
    python3 tools/fork/materialize_slatedb.py --record   # stamp the digest

The reconstructed tree lands in sources/slatedb-fork/ (git-ignored, like
every other materialised source).
"""
import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

REPO = pathlib.Path(__file__).resolve().parents[2]
LOCK = REPO / "source-lock" / "source-lock.json"
FORK = REPO / "fork" / "slatedb"
PATCHES = FORK / "patches"
PROVENANCE = FORK / "UPSTREAM-PROVENANCE"
DEST = REPO / "sources" / "slatedb-fork"
CACHE = REPO / "sources" / "fixtures" / "crates"


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_digest(root: pathlib.Path) -> str:
    """Digest over (relative path, content) for every file, sorted.

    Path-inclusive so a renamed file changes the digest, content-inclusive
    so an edited file does too.
    """
    h = hashlib.sha256()
    for f in sorted(root.rglob("*")):
        if not f.is_file():
            continue
        rel = f.relative_to(root).as_posix()
        h.update(rel.encode() + b"\0" + sha256_file(f).encode() + b"\0")
    return h.hexdigest()


def locked_crate() -> tuple:
    lock = json.loads(LOCK.read_text())
    node = next(n for n in lock["nodes"] if n["id"] == "SL")
    version = node["version"].lstrip("=")
    return node["crate"], version, node["checksum_sha256"]


def fetch(crate: str, version: str, digest: str) -> pathlib.Path:
    CACHE.mkdir(parents=True, exist_ok=True)
    target = CACHE / f"{crate}-{version}.crate"
    if target.exists() and sha256_file(target) == digest:
        return target
    url = f"https://static.crates.io/crates/{crate}/{crate}-{version}.crate"
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        with urllib.request.urlopen(url, timeout=120) as response:
            shutil.copyfileobj(response, tmp)
        staged = pathlib.Path(tmp.name)
    observed = sha256_file(staged)
    if observed != digest:
        staged.unlink()
        sys.exit(f"{crate} {version}: sha256 {observed} != locked {digest}; download discarded")
    shutil.move(str(staged), target)
    return target


def extract(crate_file: pathlib.Path, into: pathlib.Path) -> pathlib.Path:
    if into.exists():
        shutil.rmtree(into)
    into.mkdir(parents=True)
    with tarfile.open(crate_file) as tar:
        # crates are a single top-level <name>-<version>/ directory
        for member in tar.getmembers():
            if member.name.startswith("/") or ".." in pathlib.PurePosixPath(member.name).parts:
                sys.exit(f"refusing unsafe archive member {member.name!r}")
        tar.extractall(into)
    roots = [p for p in into.iterdir() if p.is_dir()]
    if len(roots) != 1:
        sys.exit(f"expected exactly one directory in the crate archive, found {roots}")
    return roots[0]


def apply_patches(tree: pathlib.Path) -> list:
    applied = []
    for patch in sorted(PATCHES.glob("*.patch")):
        result = subprocess.run(
            ["patch", "-p1", "--forward", "--fuzz=0", "-i", str(patch)],
            cwd=tree, capture_output=True, text=True)
        if result.returncode != 0:
            sys.exit(f"{patch.name} did not apply cleanly:\n{result.stdout}{result.stderr}")
        applied.append(patch.name)
    return applied


def read_provenance() -> dict:
    if not PROVENANCE.exists():
        return {}
    return json.loads(PROVENANCE.read_text())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true",
                       help="reconstruct into a temporary directory and verify only")
    group.add_argument("--record", action="store_true",
                       help="reconstruct and stamp the resulting digest into UPSTREAM-PROVENANCE")
    args = ap.parse_args()

    crate, version, digest = locked_crate()
    crate_file = fetch(crate, version, digest)

    staging = pathlib.Path(tempfile.mkdtemp(prefix="slatedb-fork-"))
    try:
        tree = extract(crate_file, staging)
        applied = apply_patches(tree)
        observed = tree_digest(tree)
        provenance = read_provenance()
        expected = provenance.get("patched_tree_sha256")

        if args.record:
            PROVENANCE.write_text(json.dumps({
                "document": "SlateDB fork provenance (ADR-0012 external epochs)",
                "upstream_crate": crate,
                "upstream_version": version,
                "upstream_crate_sha256": digest,
                "patches": applied,
                "patched_tree_sha256": observed,
                "note": "reconstruct with tools/fork/materialize_slatedb.py; "
                        "the patch series is the fork, the crate is the base",
            }, indent=2) + "\n")
            print(f"recorded patched_tree_sha256={observed}")
            return 0

        if expected and expected != observed:
            print(f"FORK DIGEST MISMATCH\n  expected {expected}\n  observed {observed}",
                  file=sys.stderr)
            return 1
        if not expected:
            print("UPSTREAM-PROVENANCE records no patched_tree_sha256 "
                  "(run --record once to stamp it)", file=sys.stderr)
            return 1

        if args.check:
            print(f"SLATEDB FORK: OK ({len(applied)} patch(es), tree {observed[:12]}…)")
            return 0

        if DEST.exists():
            shutil.rmtree(DEST)
        DEST.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(tree), str(DEST))
        print(f"materialised {DEST.relative_to(REPO)} "
              f"({crate} {version} + {len(applied)} patch(es), tree {observed[:12]}…)")
        return 0
    finally:
        shutil.rmtree(staging, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
