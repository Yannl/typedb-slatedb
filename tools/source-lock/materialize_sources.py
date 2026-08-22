#!/usr/bin/env python3
"""Materialise sources/ from the source lock.

`sources/` is deliberately not committed (it is large, and it is fully
determined by source-lock/source-lock.json). Every fresh environment —
a new container, a new contributor's machine — therefore starts with no
checkouts at all, and `lint_source_lock.py` fails until they exist.
This script is the inverse of that lint: it reconstitutes exactly what
the lint demands, from the same lock, so that

    python3 tools/source-lock/materialize_sources.py
    python3 tools/source-lock/lint_source_lock.py     # LINT: PASS

is the whole bootstrap.

Properties:
  - the revision/tag never comes from this file, only from the lock
    (drift between lock and checkout is what the lock exists to prevent);
  - every git node is verified after checkout: HEAD == locked revision,
    HEAD^{tree} == locked tree (when the lock records one), clean tree;
  - every artifact is verified by sha256 against the lock before it is
    accepted, and a mismatching download is discarded, never kept;
  - idempotent: a node already at the locked revision is left alone
    (`--force` re-fetches).

What it deliberately does NOT do: build anything. The assembly archive
(sources/assembly-artifacts/) is a build product of the parity toolchain
— see docs/development.md.
"""

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from lint_source_lock import ARTIFACTS, GIT_DIRS, LOCK, SOURCES  # noqa: E402


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, text=True, **kw)


def out(cmd) -> str:
    return subprocess.run(cmd, check=True, text=True, capture_output=True).stdout.strip()


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def locked_revision(node: dict) -> str:
    rev = node.get("revision") or node.get("resolved_revision")
    if not rev:
        raise SystemExit(f"{node['id']}: lock has no revision to materialise")
    return rev


def fetch_git(_nid: str, node: dict, dest: pathlib.Path, force: bool) -> str:
    """Clone/fetch a git node to its locked revision. Returns a status word."""
    rev = locked_revision(node)
    repo = node["repository"]

    if (dest / ".git").exists() and not force:
        head = out(["git", "-C", str(dest), "rev-parse", "HEAD"])
        if head == rev:
            return "already at lock"

    if not (dest / ".git").exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        # blob-filtered: the corpus needs the worktree, not the whole history.
        run(["git", "clone", "--filter=blob:none", "--no-checkout", repo, str(dest)])

    # Named refs first (cheap, always allowed); a bare-SHA fetch is the
    # fallback for revisions that no branch tip reaches any more.
    try:
        run(
            ["git", "-C", str(dest), "fetch", "--force", "--tags", "origin"],
            stdout=subprocess.DEVNULL,
        )
        run(
            ["git", "-C", str(dest), "cat-file", "-e", f"{rev}^{{commit}}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        run(["git", "-C", str(dest), "fetch", "--force", "origin", rev])

    run(
        ["git", "-C", str(dest), "checkout", "--detach", "--force", rev],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    run(
        ["git", "-C", str(dest), "submodule", "update", "--init", "--recursive"],
        stdout=subprocess.DEVNULL,
    )
    run(
        ["git", "-C", str(dest), "clean", "-fdx", "-e", "target", "-e", "node_modules"],
        stdout=subprocess.DEVNULL,
    )
    return "materialised"


def verify_git(nid: str, node: dict, dest: pathlib.Path) -> list:
    problems = []
    rev = locked_revision(node)
    head = out(["git", "-C", str(dest), "rev-parse", "HEAD"])
    if head != rev:
        problems.append(f"{nid}: HEAD {head} != locked {rev}")
    tree = node.get("tree")
    if tree and len(tree) == 40:  # some nodes record prose, not a tree hash
        got = out(["git", "-C", str(dest), "rev-parse", "HEAD^{tree}"])
        if got != tree:
            problems.append(f"{nid}: tree {got} != locked {tree}")
    dirty = out(["git", "-C", str(dest), "status", "--porcelain"])
    if dirty:
        problems.append(f"{nid}: dirty tree at {dest}")
    return problems


def fetch_artifact(nid: str, node: dict, rel: str, force: bool) -> str:
    dest = SOURCES / rel
    want = node["sha256"]
    # A file already on disk is only ever replaced by a verified download:
    # a wrong-looking local copy is not evidence that the lock is right, so
    # nothing is deleted until the replacement bytes have matched the lock.
    if dest.exists() and not force and sha256(dest) == want:
        return "already at lock"
    url = node.get("url")
    if not url:
        raise SystemExit(f"{nid}: lock records no url for {rel}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=dest.parent, delete=False) as tmp:
        tmp_path = pathlib.Path(tmp.name)
    try:
        # curl, not urllib: it picks up the environment's proxy and CA
        # configuration, which sandboxed/corporate networks depend on.
        run(
            [
                "curl",
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--retry",
                "5",
                "--retry-all-errors",
                url,
                "--output",
                str(tmp_path),
            ]
        )
        got = sha256(tmp_path)
        if got != want:
            raise SystemExit(f"{nid}: sha256 mismatch for {url}\n  want {want}\n  got  {got}")
        os.replace(tmp_path, dest)
    finally:
        tmp_path.unlink(missing_ok=True)
    return "downloaded"


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--force", action="store_true", help="re-fetch even when the node is already at the lock"
    )
    ap.add_argument(
        "--only",
        action="append",
        default=None,
        metavar="NODE_ID",
        help="materialise only these lock nodes (repeatable)",
    )
    ap.add_argument(
        "--lock",
        default=str(LOCK),
        metavar="PATH",
        help="read a different lock file (used by the negative "
        "control: a corrupted digest must abort the fetch)",
    )
    args = ap.parse_args()

    nodes = {n["id"]: n for n in json.loads(pathlib.Path(args.lock).read_text())["nodes"]}
    selected = set(args.only) if args.only else None
    if selected:
        # a typo'd node id must not become a silent no-op success
        known = set(GIT_DIRS) | set(ARTIFACTS)
        unknown = selected - known
        if unknown:
            raise SystemExit(
                f"unknown node id(s): {', '.join(sorted(unknown))} "
                f"(materialisable: {', '.join(sorted(known))})"
            )
    problems = []
    done_git = done_art = 0

    for nid, dirname in GIT_DIRS.items():
        if selected and nid not in selected:
            continue
        node = nodes.get(nid)
        if node is None:
            problems.append(f"{nid}: missing from lock")
            continue
        dest = SOURCES / dirname
        try:
            status = fetch_git(nid, node, dest, args.force)
        except subprocess.CalledProcessError as exc:
            # A revision the remote does not have is a lock problem, and it
            # is reported as one — not as a stack trace.
            problems.append(f"{nid}: fetch failed ({' '.join(exc.cmd)})")
            print(f"  {nid:<16} sources/{dirname:<28} FETCH FAILED")
            continue
        done_git += 1
        node_problems = verify_git(nid, node, dest)
        problems += node_problems
        print(
            f"  {nid:<16} sources/{dirname:<28} {status}"
            f"{' — ' + '; '.join(node_problems) if node_problems else ''}"
        )

    for nid, rel in ARTIFACTS.items():
        if selected and nid not in selected:
            continue
        node = nodes.get(nid)
        if node is None:
            problems.append(f"{nid}: missing from lock")
            continue
        try:
            status = fetch_artifact(nid, node, rel, args.force)
        except subprocess.CalledProcessError:
            # same contract as the git loop: a fetch failure is a reported
            # problem, and the remaining nodes still get their chance
            problems.append(f"{nid}: download failed ({node.get('url')})")
            print(f"  {nid:<16} sources/{rel:<28} FETCH FAILED")
            continue
        done_art += 1
        print(f"  {nid:<16} sources/{rel:<28} {status}")

    if problems:
        print("MATERIALISE: FAIL")
        for p in problems:
            print("  -", p)
        return 1
    print(
        f"MATERIALISE: OK ({done_git} git node(s), {done_art} artifact(s)"
        f"{' — selection via --only' if selected else ''})"
    )
    print("next: python3 tools/source-lock/lint_source_lock.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
