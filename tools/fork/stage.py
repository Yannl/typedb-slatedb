#!/usr/bin/env python3
"""Stage fork/typedb into sources/typedb (and restore it afterwards).

Upstream test execution happens in `sources/typedb` — a pinned, pristine
checkout — because the warm build cache and the Bazel-equivalent runfile
layout live there. Fork-owned patches are authored in `fork/typedb`.
Moving between the two was a hand-run copy documented in prose
(docs/development.md §"The staging model"); this script is that step,
executed the same way every time, so that "did I stage everything?" and
"is the checkout pristine again?" are commands rather than recollection.

    python3 tools/fork/stage.py            # fork -> sources (only real diffs)
    python3 tools/fork/stage.py --check    # STAGED / PRISTINE / MIXED, no writes
    python3 tools/fork/stage.py --restore  # sources back to the locked revision

`--restore` leaves build outputs alone (git clean without -x), so the warm
`sources/typedb/target` cache survives the round trip; the source-lock lint
passes again immediately after it.

Fork-only metadata (the port ledger, the provenance stamp) is never staged:
it documents the fork, it is not part of the buildable tree.
"""
import argparse
import filecmp
import pathlib
import shutil
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
FORK = REPO / "fork" / "typedb"
DEST = REPO / "sources" / "typedb"

# Fork-side files that describe the fork rather than build with it.
FORK_ONLY = {"PORT-LEDGER.md", "UPSTREAM-PROVENANCE"}
SKIP_DIRS = {".git", "target", "node_modules"}


def fork_files():
    for p in sorted(FORK.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(FORK)
        if rel.parts[0] in SKIP_DIRS or str(rel) in FORK_ONLY:
            continue
        yield rel


def differing():
    """(new, changed, stale) relative paths.

    new/changed: fork files absent from / different in sources.
    stale: files a previous staging added to sources (untracked relative to
    the locked revision) that the fork no longer carries — e.g. a fork patch
    deleted a module it had introduced. Leaving them makes the tree under
    test neither upstream nor the fork, so staging removes them and --check
    reports them.
    """
    new, changed = [], []
    fork_set = set()
    for rel in fork_files():
        fork_set.add(str(rel))
        dst = DEST / rel
        if not dst.exists():
            new.append(rel)
        elif not filecmp.cmp(FORK / rel, dst, shallow=False):
            changed.append(rel)
    r = subprocess.run(
        ["git", "-C", str(DEST), "ls-files", "--others", "--exclude-standard"],
        capture_output=True, text=True, check=True)
    stale = [pathlib.Path(p) for p in r.stdout.splitlines()
             if p and p not in fork_set]
    return new, changed, stale


def dirty_paths() -> list:
    r = subprocess.run(["git", "-C", str(DEST), "status", "--porcelain"],
                       capture_output=True, text=True, check=True)
    return [line[3:] for line in r.stdout.splitlines()]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true", help="report state, write nothing")
    g.add_argument("--restore", action="store_true",
                   help="revert sources/typedb to the locked revision")
    args = ap.parse_args()

    if not (DEST / ".git").exists():
        print(f"sources/typedb missing — run "
              f"python3 tools/source-lock/materialize_sources.py first")
        return 1

    if args.restore:
        subprocess.run(["git", "-C", str(DEST), "checkout", "--", "."], check=True)
        subprocess.run(["git", "-C", str(DEST), "clean", "-fd"], check=True,
                       stdout=subprocess.DEVNULL)
        left = dirty_paths()
        if left:
            print("RESTORE: INCOMPLETE — still dirty:")
            for p in left:
                print("  -", p)
            return 1
        print("RESTORE: sources/typedb pristine at the locked revision")
        return 0

    new, changed, stale = differing()
    if args.check:
        dirty = dirty_paths()
        if not new and not changed and not stale:
            print(f"STAGED: sources/typedb carries every fork patch "
                  f"({len(dirty)} paths differ from the locked revision)")
            return 0
        if not dirty:
            print(f"PRISTINE: sources/typedb is at the locked revision "
                  f"({len(new) + len(changed)} fork patches not staged)")
            return 0
        print(f"MIXED: {len(new) + len(changed)} fork patches unstaged, "
              f"{len(stale)} stale staged files, "
              f"{len(dirty)} paths diverge from the locked revision")
        for rel in new + changed:
            print("  - unstaged:", rel)
        for rel in stale:
            print("  - stale (in sources, not in fork):", rel)
        return 1

    for rel in new + changed:
        dst = DEST / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(FORK / rel, dst)
        print(f"  {'+' if rel in new else 'M'} {rel}")
    for rel in stale:
        (DEST / rel).unlink()
        print(f"  - {rel} (removed: no longer in fork)")
    print(f"STAGE: {len(new)} new, {len(changed)} changed, "
          f"{len(stale)} stale removed "
          f"(sources/typedb is now the fork tree; "
          f"run --restore before the source-lock lint)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
