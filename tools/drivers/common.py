#!/usr/bin/env python3
"""Shared primitives for the official-driver qualification lane."""

import hashlib
import json
import pathlib
import subprocess

REPO = pathlib.Path(__file__).resolve().parents[2]
SOURCES = REPO / "sources"
PLAN = REPO / "docs" / "evidence" / "G1" / "qualification-plan-v2.json"
LEDGER = REPO / "docs" / "evidence" / "flake-ledger.json"
SOURCE_LOCK = REPO / "source-lock" / "source-lock.json"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
    )


def checkout_identity(path):
    """Revision + tree + dirt of a git checkout under sources/.

    `dirty` is True, False, or None when it could not be established. None
    must NEVER be read as clean by a caller.
    """
    path = pathlib.Path(path)
    rev = git(path, "rev-parse", "HEAD")
    tree = git(path, "rev-parse", "HEAD^{tree}")
    st = git(path, "status", "--porcelain")
    if rev.returncode or tree.returncode or st.returncode:
        return {
            "path": rel(path),
            "revision": None,
            "tree": None,
            "dirty": None,
            "error": (rev.stderr or tree.stderr or st.stderr).strip(),
        }
    changed = [ln for ln in st.stdout.splitlines() if ln.strip()]
    out = {
        "path": rel(path),
        "revision": rev.stdout.strip(),
        "tree": tree.stdout.strip(),
        "dirty": bool(changed),
        "dirty_path_count": len(changed),
    }
    if changed:
        out["dirty_paths"] = sorted(ln[3:] for ln in changed)[:200]
        out["dirty_delta_sha256"] = sha256_bytes(git(path, "diff", "HEAD").stdout.encode())
    return out


def source_lock_node(node_id):
    doc = json.loads(SOURCE_LOCK.read_text())
    for n in doc["nodes"]:
        if n.get("id") == node_id:
            return n
    return None


def rel(p):
    p = pathlib.Path(p).resolve()
    try:
        return p.relative_to(REPO).as_posix()
    except ValueError:
        return str(p)


def bundle_rel(path, bundle_dir, repo=None):
    """Same identity rule the u0 evidence chain uses (tools/catalog/verdict.py
    _bundle_rel): repo-relative when possible, `<out>/`-relative otherwise."""
    p = pathlib.Path(path).resolve()
    try:
        return p.relative_to(pathlib.Path(repo or REPO).resolve()).as_posix()
    except ValueError:
        pass
    try:
        return "<out>/" + p.relative_to(pathlib.Path(bundle_dir).resolve()).as_posix()
    except ValueError:
        return str(p)


def compute_bundle_root(bundle_dir, files, repo=None):
    """sha256 over sorted `rel\\0sha\\n` pairs - the SAME documented algorithm
    tools/catalog/verdict.py:compute_bundle_root uses for the u0/u2s3 lane, so
    one root definition covers the whole evidence chain. Files that do not
    exist are simply absent from the pairs; their absence is already an
    anomaly elsewhere and the root is then never bound green."""
    pairs = {}
    for f in files:
        f = pathlib.Path(f)
        if f.is_file():
            pairs[bundle_rel(f, bundle_dir, repo)] = sha256_file(f)
    h = hashlib.sha256()
    for r in sorted(pairs):
        h.update(r.encode() + b"\0" + pairs[r].encode() + b"\n")
    return h.hexdigest(), pairs


def canonical_json_sha256(obj):
    return sha256_bytes(
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    )


def plan_root_of_body(doc):
    body = {k: v for k, v in doc.items() if k != "plan_root"}
    return canonical_json_sha256(body)
