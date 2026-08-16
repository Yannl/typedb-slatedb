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

Modes:
  generate (default) — write the file;
  --check           — regenerate in memory and diff against the committed
                      file, ignoring volatile fields (repo_commit,
                      generated_at is not recorded at all); non-zero on
                      drift. Wired into lint_source_lock.py.
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
OUT = REPO / "source-lock" / "workspace-lock.json"

WORKSPACES = {
    "fork/typedb": {"manifest": "fork/typedb/Cargo.toml", "lockfile": "fork/typedb/Cargo.lock"},
    "tools": {"manifest": "tools/Cargo.toml", "lockfile": "tools/Cargo.lock"},
    "control-plane": {"manifest": "control-plane/package.json", "lockfile": "control-plane/package-lock.json"},
}

ARTIFACTS = [
    "sources/fixtures/console/typedb-console-linux-x86_64-3.12.0.tar.gz",
    "sources/fixtures/loader/typedb-loader-linux-x86_64-3.12.0.tar.gz",
    "sources/assembly-artifacts/typedb-all-linux-x86_64.tar.gz",
]

TOOLCHAINS = {
    "rust_parity": "1.93.0",
    "rustfmt_pinned_nightly": "nightly-2026-04-15",
    # the qualification lane is recorded by its evidence run, not asserted here
}


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


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
    m = re.search(r'slatedb\s*=\s*\{\s*version\s*=\s*"([^"]+)"\s*,\s*default-features\s*=\s*(\w+)', spike)
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
        "repo_commit": subprocess.run(
            ["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip(),
        "source_lock_sha256": sha256(REPO / "source-lock" / "source-lock.json"),
        "workspaces": {},
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


VOLATILE = {"repo_commit"}


def main() -> int:
    doc = build()
    if "--check" in sys.argv:
        if not OUT.exists():
            print("workspace-lock: MISSING (run the generator)")
            return 1
        committed = json.loads(OUT.read_text())
        a = {k: v for k, v in doc.items() if k not in VOLATILE}
        b = {k: v for k, v in committed.items() if k not in VOLATILE}
        if a != b:
            for key in sorted(set(a) | set(b)):
                if a.get(key) != b.get(key):
                    print(f"workspace-lock DRIFT in '{key}':\n  now:       {a.get(key)}\n  committed: {b.get(key)}")
            return 1
        print("workspace-lock: OK")
        return 0
    OUT.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
