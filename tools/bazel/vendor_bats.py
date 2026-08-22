#!/usr/bin/env python3
"""Rebuild the bats archives Bazel needs, from the locked git tags (SI-G0-1).

WHY THIS EXISTS
---------------
`aspect_bazel_lib` REGISTERS `bats_toolchains`, and Bazel must load every
registered toolchain before it can resolve toolchains for ANY configured
target. So a fetch this project never otherwise needs — four archives from
github.com/bats-core — gated the entire ANALYSIS phase, and with it Mode-Q.
The ledger recorded that as SI-G0-1 and G0 has been OPEN_RED behind it since
round 6.

The block is narrower than it looked. This environment's egress denies
`https://github.com/<o>/<r>/archive/<tag>.tar.gz` with 403 (reproduced with
curl on github.com and codeload.github.com alike), but it SERVES anonymous git
reads of the same public repositories. And GitHub's release tarball is not a
bespoke artefact: it is `git archive` of the tag, gzipped. Measured
2026-08-22, all four reproduce BYTE-FOR-BYTE:

    git archive --format=tar --prefix=<repo>-<version>/ <tag> | gzip -n -6

  bats-core    v1.10.0  a1a9f7875aa4b6a9480ca384d5865f1ccf1b0b1faead6b47aa47d79709a5c5fd
  bats-support v0.3.0   7815237aafeb42ddcc1b8c698fc5808026d33317d8701d5ec2396e9634e2918f
  bats-assert  v2.1.0   98ca3b685f8b8993e48ec057565e6e2abcc541034ed5b0e81f191505682037fd
  bats-file    v0.4.0   9b69043241f3af1c2d251f89b4fcafa5df3f05e97b89db18d7c9bdf5731bb27a

Those are the digests `aspect_bazel_lib` itself pins, so Bazel verifies this
work independently: a wrong byte anywhere and `--distdir` is ignored, the
fetch is attempted, and the 403 comes back. The reconstruction cannot forge a
pass.

`gzip -n -6` is load-bearing on both flags. `-n` omits the filename and mtime
from the gzip header (with them, the digest depends on when you ran it); `-6`
is gzip's default level and the one GitHub uses — `-9` produces a valid,
identical-on-extraction archive with a DIFFERENT digest (measured:
1461ab68…), which Bazel would reject.

WHAT IT REFUSES
---------------
Everything, on any mismatch. A checkout at the wrong revision, a tree that
does not match the lock, or an archive whose digest is not the pinned one all
stop the tool with a nonzero exit and no file written. A half-populated
distdir is worse than an empty one: Bazel would fall through to the network
for whatever is missing and fail with the original 403, which reads as "the
vendoring did nothing" rather than "the vendoring is wrong".

usage:
  python3 tools/bazel/vendor_bats.py                     # -> sources/bazel-distdir
  python3 tools/bazel/vendor_bats.py --out DIR --check   # verify only, write nothing
"""

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
SOURCES = REPO / "sources"
LOCK = REPO / "source-lock" / "source-lock.json"
DEFAULT_OUT = SOURCES / "bazel-distdir"

sys.path.insert(0, str(REPO / "tools" / "source-lock"))

from lint_source_lock import GIT_DIRS  # noqa: E402

# The lock node ids this tool vendors. Read from the lock rather than restated:
# the repository, tag, revision, tree and expected archive digest all live
# there, and `lint_source_lock.py` already validates their shape.
NODE_IDS = ("BATS_CORE", "BATS_SUPPORT", "BATS_ASSERT", "BATS_FILE")

# GitHub's own tarball settings. Not a preference — see the module docstring.
GZIP_LEVEL = "-6"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(checkout: pathlib.Path, *args: str) -> str:
    r = subprocess.run(
        ["git", "-C", str(checkout), *args], capture_output=True, text=True, check=False
    )
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} in {checkout} failed: {r.stderr.strip()[:400]}")
    return r.stdout.strip()


def rebuild_archive(checkout: pathlib.Path, tag: str, prefix: str) -> bytes:
    """GitHub's `/archive/<tag>.tar.gz` for this checkout, byte for byte.

    `core.autocrlf=false` is set explicitly: a machine that had it on would
    rewrite line endings into the tar and change every digest.
    """
    tar = subprocess.run(
        [
            "git",
            "-C",
            str(checkout),
            "-c",
            "core.autocrlf=false",
            "archive",
            "--format=tar",
            f"--prefix={prefix}/",
            tag,
        ],
        capture_output=True,
        check=False,
    )
    if tar.returncode != 0:
        raise RuntimeError(f"git archive {tag} failed: {tar.stderr.decode(errors='replace')[:400]}")
    gz = subprocess.run(
        ["gzip", "-n", GZIP_LEVEL], input=tar.stdout, capture_output=True, check=False
    )
    if gz.returncode != 0:
        raise RuntimeError(f"gzip failed: {gz.stderr.decode(errors='replace')[:400]}")
    return gz.stdout


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--out", type=pathlib.Path, default=DEFAULT_OUT)
    ap.add_argument(
        "--check",
        action="store_true",
        help="rebuild and verify every archive, write nothing",
    )
    args = ap.parse_args()

    lock = json.loads(LOCK.read_text())
    nodes = {n["id"]: n for n in lock["nodes"]}
    failures: list[str] = []
    built: list[tuple[pathlib.Path, bytes, str]] = []

    for nid in NODE_IDS:
        node = nodes.get(nid)
        if node is None:
            failures.append(f"{nid}: absent from {LOCK.relative_to(REPO)}")
            continue
        checkout = SOURCES / GIT_DIRS[nid]
        if not (checkout / ".git").is_dir():
            failures.append(
                f"{nid}: no checkout at {checkout.relative_to(REPO)} — run "
                f"`python3 tools/source-lock/materialize_sources.py {nid}` first"
            )
            continue

        # The checkout must BE the locked revision. Rebuilding a tag from a
        # tree that drifted would produce a wrong archive with a right name.
        try:
            rev = git(checkout, "rev-parse", f"{node['tag']}^{{commit}}")
            tree = git(checkout, "rev-parse", f"{node['tag']}^{{tree}}")
        except RuntimeError as e:
            failures.append(f"{nid}: {e}")
            continue
        if rev != node["resolved_revision"]:
            failures.append(
                f"{nid}: tag {node['tag']} is {rev}, lock says {node['resolved_revision']}"
            )
            continue
        if tree != node["tree"]:
            failures.append(f"{nid}: tree {tree} != locked {node['tree']}")
            continue

        try:
            blob = rebuild_archive(checkout, node["tag"], node["archive_prefix"])
        except RuntimeError as e:
            failures.append(f"{nid}: {e}")
            continue
        got = sha256_bytes(blob)
        want = node["archive_sha256"]
        if got != want:
            failures.append(
                f"{nid}: rebuilt archive is {got}, the pinned digest is {want}. Bazel verifies "
                f"this digest itself, so a distdir entry that does not match is not a shortcut — "
                f"it is a file Bazel will ignore before failing on the original fetch."
            )
            continue
        # Bazel matches a distdir entry by the BASENAME of the download URL,
        # not by the archive's internal prefix: `v1.10.0.tar.gz`, not
        # `bats-core-1.10.0.tar.gz`.
        built.append((args.out / node["archive_url"].rsplit("/", 1)[-1], blob, got))
        print(f"  ok  {nid:13} {node['tag']:8} {got}")

    if failures:
        for f in failures:
            print(f"REFUSED: {f}", file=sys.stderr)
        print(
            f"\nvendor_bats: {len(failures)} of {len(NODE_IDS)} archive(s) could not be rebuilt; "
            f"nothing written. A partial distdir makes Bazel fall through to the network for the "
            f"rest and fail on the 403 this exists to avoid.",
            file=sys.stderr,
        )
        return 1

    if args.check:
        print(f"vendor_bats: all {len(built)} archives reproduce their pinned digests (--check)")
        return 0

    args.out.mkdir(parents=True, exist_ok=True)
    for path, blob, _digest in built:
        path.write_bytes(blob)
    print(f"vendor_bats: wrote {len(built)} archive(s) into {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
