#!/usr/bin/env python3
"""Stage the runtime fixtures a TypeDB cargo workspace needs before its tests.

The corpus does not run from source alone. Two fixtures have to exist next to
whichever workspace is under test, and when they do not the affected targets do
not error usefully — they report success-shaped emptiness:

  behaviour features   `0 features / 0 scenarios / 1 parsing error` in ~2s,
                       because the Cucumber files are read through a
                       Bazel-equivalent runfiles symlink that cargo does not
                       create. 49 targets on the fork workspace.
  assembly archive     `tests/assembly/assembly.rs` extracts the packaged
                       server from its own working directory. 3 targets.

`run_leaf.py` already stages both, per target, which is why the sealed lane
bundles are green while a bare `cargo nextest run` over the same tree is not.
This script exists so the quality controller stages them THE SAME WAY, from the
same definitions in `run_u0`, instead of growing a second copy that drifts.

The archive is REBUILT here, never reused: it must contain the binaries of the
tree under test, and packaging whatever happens to be lying around is how an
assembly test certifies the wrong server (see the round-7 handoff on the shared
archive path). Rebuilding is safe only because this runs immediately after the
controller has built that same tree — which is why it takes the workspace root
explicitly rather than guessing one.

usage:
  stage_test_fixtures.py --workspace-root fork/typedb
"""

import argparse
import pathlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))

sys.path.insert(0, str(REPO / "tools" / "dev"))

import netns_exec  # noqa: E402
import run_u0  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--workspace-root",
        required=True,
        help="the cargo workspace the tests will run from, repo-relative or absolute",
    )
    args = ap.parse_args()
    root = pathlib.Path(args.workspace_root)
    if not root.is_absolute():
        root = REPO / root
    root = root.resolve()
    if not (root / "Cargo.toml").is_file():
        sys.exit(f"{root} is not a cargo workspace (no Cargo.toml)")

    if not run_u0.ensure_behaviour_fixture(root):
        sys.exit(
            f"behaviour fixture unusable for {root}: sources/typedb-behaviour is "
            f"absent or serves no features. Run "
            f"`python3 tools/source-lock/materialize_sources.py` first — running the "
            f"behaviour targets without it archives false reds."
        )
    print(
        f"behaviour fixture: staged for {root.relative_to(REPO) if root.is_relative_to(REPO) else root}"
    )

    # Per-process assembly working directories from any previous run: cleared
    # now rather than left to accumulate under target/.
    iso_root = root / "target" / netns_exec.NETNS_ISO_DIR
    if iso_root.exists():
        shutil.rmtree(iso_root)

    archive = run_u0.assembly_archive_for(root)
    rc = subprocess.run(
        [
            sys.executable,
            str(HERE / "package_assembly.py"),
            "--workspace-root",
            str(root),
        ],
        cwd=REPO,
    ).returncode
    if rc != 0:
        sys.exit(
            f"assembly archive: could not package one from {root}.\n"
            f"  The 3 assembly-family targets bind their verdict to the packaged\n"
            f"  server, so running them against an absent or stale archive would\n"
            f"  archive a result about the wrong binary."
        )
    if not archive.is_file():
        sys.exit(f"assembly archive: package_assembly.py reported success but {archive} is absent")
    print(f"assembly fixture: packaged from {root} into {archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
