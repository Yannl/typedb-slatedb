#!/usr/bin/env python3
"""Reclaim stale cargo artifacts. Cargo never garbage-collects; this does.

Every time a crate's inputs change, cargo emits a NEW hash-suffixed artifact
and leaves the previous one on disk forever. Across a working session that
accumulates fast, and in this repository it is the difference between
fitting in the disk allowance and not:

  measured on sources/typedb/target/debug/deps
    136 test/bin executables on disk for 100 distinct targets
    10.4 GB of executables, of which the 36 duplicates are the waste
    the 12 behaviour binaries are ~245 MB EACH (each statically links the
    whole server plus rocksdb plus slatedb), so a single stale copy of one
    costs more than most crates' entire build

Only the NEWEST artifact per (target-name, extension) is kept. Removing an
older one is safe: cargo addresses artifacts by fingerprint hash, so a file
it still wants is by definition the newest for its inputs. Worst case it
relinks — time, never correctness.

This deliberately does NOT touch `.rlib`/`.rmeta` by default: intermediate
libraries are shared across many downstream targets and are cheap to keep
(3.4 GB across 979 files, so ~3.5 MB each), while executables are the
concentration. `--include-libs` opts in when the squeeze is severe.

usage:
  python3 tools/dev/cargo_gc.py --dry-run                 # report only
  python3 tools/dev/cargo_gc.py                           # reclaim
  python3 tools/dev/cargo_gc.py --target-dir DIR ...      # extra trees
"""

import argparse
import collections
import pathlib
import re
import sys

# a cargo artifact hash is exactly 16 lowercase hex characters
HASH = re.compile(r"-[0-9a-f]{16}$")
DEFAULT_TARGET_DIRS = [
    "sources/typedb/target",
    "sources/slatedb-fork/target",
    # the overlay workspace the quality controller builds: since round 7 this
    # is the LARGEST tree on the machine (11 GB with the test binaries linked),
    # so leaving it out defeated the point of the tool
    "fork/typedb/target",
    "tools/target",
    "target",
]
REPO = pathlib.Path(__file__).resolve().parents[2]


def stem_and_hash(name: str):
    """Split `foo-0123456789abcdef.rlib` into ('foo', '.rlib'), else None."""
    path = pathlib.PurePosixPath(name)
    suffix = "".join(path.suffixes) if path.suffixes else ""
    base = name[: len(name) - len(suffix)] if suffix else name
    if not HASH.search(base):
        return None
    return HASH.sub("", base), suffix


def scan(deps: pathlib.Path, include_libs: bool):
    """Group artifacts by (stem, suffix); newest first within each group."""
    groups = collections.defaultdict(list)
    for entry in deps.iterdir():
        if not entry.is_file():
            continue
        parsed = stem_and_hash(entry.name)
        if parsed is None:
            continue
        stem, suffix = parsed
        if suffix in (".d",):
            continue
        if not include_libs and suffix in (".rlib", ".rmeta", ".so", ".a"):
            continue
        stat = entry.stat()
        groups[(stem, suffix)].append((stat.st_mtime, stat.st_size, entry))
    for key in groups:
        groups[key].sort(reverse=True)
    return groups


def human(n: int) -> str:
    return f"{n / 1073741824:.2f} GB" if n >= 1073741824 else f"{n / 1048576:.1f} MB"


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument(
        "--target-dir",
        action="append",
        default=None,
        help="cargo target dir (repeatable); defaults to this repository's known build trees",
    )
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument(
        "--include-libs",
        action="store_true",
        help="also collect stale .rlib/.rmeta/.so — more reclaim, more relinking on the next build",
    )
    args = ap.parse_args()

    dirs = [pathlib.Path(d) for d in (args.target_dir or DEFAULT_TARGET_DIRS)]
    total_freed = total_kept = 0
    removed = 0

    for target_dir in dirs:
        root = target_dir if target_dir.is_absolute() else REPO / target_dir
        if not root.is_dir():
            print(f"skip   {target_dir}  (absent)")
            continue
        for deps in sorted(root.glob("*/deps")):
            groups = scan(deps, args.include_libs)
            freed = kept = 0
            stale = 0
            for _key, entries in sorted(groups.items()):
                kept += entries[0][1]
                for _mtime, size, path in entries[1:]:
                    freed += size
                    stale += 1
                    if not args.dry_run:
                        path.unlink(missing_ok=True)
            if stale:
                verb = "would free" if args.dry_run else "freed"
                print(
                    f"{deps.relative_to(REPO)}: {stale} stale artifact(s), "
                    f"{verb} {human(freed)} (kept {human(kept)})"
                )
            total_freed += freed
            total_kept += kept
            removed += stale

    verb = "WOULD RECLAIM" if args.dry_run else "RECLAIMED"
    print(
        f"\n{verb}: {human(total_freed)} across {removed} stale artifact(s); "
        f"{human(total_kept)} of current artifacts kept"
    )
    if args.dry_run:
        print("re-run without --dry-run to reclaim")
    return 0


if __name__ == "__main__":
    sys.exit(main())
