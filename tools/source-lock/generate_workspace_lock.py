#!/usr/bin/env python3
"""Generate (or verify) source-lock/workspace-lock.json — the release
binding the brief's §0.2.1 asks for on top of the source lock: it ties the
federated workspaces together by digest so that "the same release" is a
checkable claim, not a branch name.

Bound facts:
  - repo commit the binding was generated at;
  - each workspace's manifest + lockfile sha256;
  - the SlateDB consumption surface per consumer (version pin + features,
    parsed from the manifests — the consume-only contract, ADR-0001);
  - toolchain identities (parity rustc, pinned rustfmt nightly, node);
  - pinned artifact digests (console/loader fixtures, assembly archive);
  - the sha256 of source-lock.json itself (so the two locks co-rotate).

Deliberately NOT bound here: the containing repo commit. A committed file
cannot truthfully name the commit that contains it — the hash of the
commit depends on the file's content, so any recorded value is either the
PREVIOUS commit or a lie, and the checker had to ignore it (round-3 audit
E-07 caught exactly that: a claimed repo_commit excluded from
comparison). The commit<->lock binding therefore lives OUTSIDE the tree:
a post-checkout/release attestation records (actual HEAD commit, sha256
of this file, release-input Merkle root) at verification time, when both
are observable facts rather than self-references.

Modes:
  generate (default) — write the file;
  --check           — regenerate in memory and diff against the committed
                      file; non-zero on drift (generated_at is not
                      recorded at all). Wired into lint_source_lock.py.
"""

import argparse
import hashlib
import json
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
OUT = REPO / "source-lock" / "workspace-lock.json"

# one definition each: the fork-file iterator comes from stage.py (a private
# copy here silently diverged the lock's digest from what staging does the
# moment either side changed), and the rustfmt pin from run_static (which
# executes it)
sys.path.insert(0, str(REPO / "tools" / "fork"))
sys.path.insert(0, str(REPO / "tools" / "catalog"))
import stage  # noqa: E402
from run_static import RUSTFMT_TOOLCHAIN  # noqa: E402

WORKSPACES = {
    "fork/typedb": {"manifest": "fork/typedb/Cargo.toml", "lockfile": "fork/typedb/Cargo.lock"},
    "tools": {"manifest": "tools/Cargo.toml", "lockfile": "tools/Cargo.lock"},
    "control-plane": {
        "manifest": "control-plane/package.json",
        "lockfile": "control-plane/package-lock.json",
    },
}

# Pinned *inputs* only. The assembly archive
# (sources/assembly-artifacts/typedb-all-linux-x86_64.tar.gz) was bound here
# until it was shown to be a build product, not an input: it repackages
# locally built debug binaries, which are not bit-reproducible, so binding it
# made the lint unsatisfiable in any environment that had rebuilt the fork —
# including every fresh checkout, where it is simply absent. The archive's
# identity still travels with the evidence that depends on it: each corpus run
# records `assembly_archive_sha256` of the archive it actually ran against
# (tools/catalog/run_u0.py), and the packaging step is deterministic given the
# binaries (tools/catalog/package_assembly.py).
ARTIFACTS = [
    "sources/fixtures/console/typedb-console-linux-x86_64-3.12.0.tar.gz",
    "sources/fixtures/loader/typedb-loader-linux-x86_64-3.12.0.tar.gz",
]

TOOLCHAINS = {
    "rust_parity": "1.93.0",
    "rustfmt_pinned_nightly": RUSTFMT_TOOLCHAIN,
    # the qualification lane is recorded by its evidence run, not asserted here
}


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fork_staging() -> dict:
    """Deterministic identity of the fork patch set (§20.2).

    `sources/typedb` under test is the locked upstream revision with
    `fork/typedb` staged over it, which makes it permanently "dirty" to a
    lint that only knows revisions. That left the fork's own content
    unpinned: any edit to a staged file produced a differently-behaving tree
    with an identical lock. Binding the fork file set by digest makes the
    executed tree's identity exactly `locked revision + this digest`.
    """
    fork_root = REPO / "fork" / "typedb"
    files = [(str(rel), sha256(fork_root / rel)) for rel in stage.fork_files()]
    h = hashlib.sha256()
    for rel, digest in files:
        h.update(f"{rel}\0{digest}\0".encode())
    return {
        "fork_root": "fork/typedb",
        "staged_file_count": len(files),
        "staged_tree_sha256": h.hexdigest(),
        "note": "sources/typedb under test == locked TB revision + this patch set",
    }


def slatedb_consumption() -> dict:
    """Version + feature surface of every slatedb consumer, from manifests."""
    out = {}
    fork = (REPO / "fork/typedb/Cargo.toml").read_text()
    m = re.search(
        r"\[workspace\.dependencies\.slatedb\]\s*\n\s*features\s*=\s*(\[[^\]]*\])\s*\n\s*version\s*=\s*\"([^\"]+)\"\s*\n\s*default-features\s*=\s*(\w+)",
        fork,
    )
    if m:
        out["fork/typedb"] = {
            "version": m.group(2),
            "features": json.loads(m.group(1).replace("'", '"')),
            "default_features": m.group(3) == "true",
        }
    spike = (REPO / "tools/storage-diff-spike/Cargo.toml").read_text()
    m = re.search(
        r'slatedb\s*=\s*\{\s*version\s*=\s*"([^"]+)"\s*,\s*default-features\s*=\s*(\w+)', spike
    )
    if m:
        out["tools/storage-diff-spike"] = {
            "version": m.group(1),
            "features": [],
            "default_features": m.group(2) == "true",
        }
    return out


def build() -> dict:
    doc = {
        "document": "workspace release binding (brief v16 §0.2.1; generated, never hand-edited)",
        "generated_by": "tools/source-lock/generate_workspace_lock.py",
        # no repo_commit: a committed file cannot bind its own containing
        # commit — that binding lives in a post-checkout attestation (see
        # the module docstring)
        "commit_binding": "external: post-checkout attestation of (HEAD, sha256 of this file)",
        "source_lock_sha256": sha256(REPO / "source-lock" / "source-lock.json"),
        "workspaces": {},
        "fork_staging": fork_staging(),
        "slatedb_consumption": slatedb_consumption(),
        "toolchains": TOOLCHAINS,
        "artifacts": {},
    }
    for name, paths in WORKSPACES.items():
        doc["workspaces"][name] = {
            "manifest": paths["manifest"],
            "manifest_sha256": sha256(REPO / paths["manifest"]),
            "lockfile": paths["lockfile"],
            "lockfile_sha256": sha256(REPO / paths["lockfile"]),
        }
    for rel in ARTIFACTS:
        p = REPO / rel
        doc["artifacts"][rel] = sha256(p) if p.exists() else "MISSING"
    return doc


def main() -> int:
    # argparse, deliberately: with bare sys.argv sniffing a mistyped
    # `--chek` silently fell through to GENERATE mode and overwrote the
    # committed lock - a verify that becomes a write on a typo
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate in memory and diff against the committed file",
    )
    args = parser.parse_args()
    doc = build()
    if args.check:
        if not OUT.exists():
            print("workspace-lock: MISSING (run the generator)")
            return 1
        committed = json.loads(OUT.read_text())
        a = doc
        b = committed
        if a != b:
            for key in sorted(set(a) | set(b)):
                if a.get(key) != b.get(key):
                    print(
                        f"workspace-lock DRIFT in '{key}':\n  now:       {a.get(key)}\n  committed: {b.get(key)}"
                    )
            return 1
        print("workspace-lock: OK")
        return 0
    OUT.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
