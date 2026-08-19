#!/usr/bin/env python3
"""Attest that the strict external-epoch fence is SHIPPED, not test-only.

R5-STOR-04 (round-5 audit): "the TypeDB storage crate defines
`external_epoch_required` as an optional feature ... a test-only feature is
not a fence." The fence is only real if the ORDINARY product build resolves
the SlateDB fork with `external_epoch_required` on — i.e. the fail-closed
refusal of an epoch-less writer open is compiled into what actually ships,
with no flag anyone has to remember.

This script is that provenance check, executable:

    python3 tools/fork/check_strict_epoch.py            # PASS (exit 0) / FAIL (exit 1)

It runs `cargo +1.93.0 tree -p storage -e features --locked` in the staged
workspace (sources/typedb — run tools/fork/stage.py first) with NO feature
flags, exactly as an ordinary build resolves, and

  * FAILS (exit 1) unless the resolved feature set of the `slatedb`
    dependency includes `external_epoch_required`;
  * FAILS if `slatedb` does not resolve at all, or if `cargo tree` errors
    (e.g. --locked drift) — absence of evidence is failure, never a pass;
  * prints the resolved slatedb version + source and its full feature list
    either way, so the attestation is a recorded fact, not a bare exit code.

Mutant (executed for the audit trail): remove
`features = ["external_epoch_required"]` from [dependencies.slatedb] in the
staged storage/Cargo.toml and rerun — this script must FAIL. `--workspace-dir`
exists so that mutant can run against a scratch copy without touching the
real staged tree.

Not wired into CI here (the workflow owner does that); this file only
guarantees the check exists, fails closed, and is one command.
"""
import argparse
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
WORKSPACE = REPO / "sources" / "typedb"
TOOLCHAIN = "+1.93.0"  # same pin as tools/catalog/*
FEATURE = "external_epoch_required"

# `cargo tree -e features` renders each resolved feature as its own node:
#   ├── slatedb feature "external_epoch_required"
#   │   └── slatedb v0.15.0 (/…/sources/slatedb-fork) (*)
# Match the crate `slatedb` exactly — slatedb-common / slatedb-txn-obj
# features are not the fence.
FEATURE_NODE = re.compile(r'\bslatedb feature "([^"]+)"')
VERSION_NODE = re.compile(r"\bslatedb (v\S+)(?: \(([^)]*)\))?")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace-dir", type=pathlib.Path, default=WORKSPACE,
                    help="cargo workspace to interrogate (default: sources/typedb; "
                         "override only for mutant runs against a scratch copy)")
    args = ap.parse_args()

    if not (args.workspace_dir / "Cargo.toml").exists():
        print(f"FAIL: no Cargo.toml under {args.workspace_dir} "
              f"(materialise + stage first)", file=sys.stderr)
        return 1

    cmd = ["cargo", TOOLCHAIN, "tree", "-p", "storage", "-e", "features", "--locked"]
    r = subprocess.run(cmd, cwd=args.workspace_dir, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"FAIL: {' '.join(cmd)} exited {r.returncode}:\n{r.stderr}",
              file=sys.stderr)
        return 1

    features = sorted({m.group(1) for m in FEATURE_NODE.finditer(r.stdout)})
    resolved = sorted({(m.group(1), m.group(2) or "registry")
                       for m in VERSION_NODE.finditer(r.stdout)})

    if not resolved:
        print("FAIL: `slatedb` does not resolve in storage's dependency tree",
              file=sys.stderr)
        return 1

    for version, source in resolved:
        print(f"slatedb {version} ({source})")
    print(f"resolved slatedb features: {', '.join(features) if features else '(none)'}")

    if FEATURE not in features:
        print(f"FAIL: `{FEATURE}` is ABSENT from the ordinary build's resolved "
              f"slatedb feature set — the strict epoch fence is not shipped "
              f"(R5-STOR-04)", file=sys.stderr)
        return 1

    print(f"PASS: `{FEATURE}` is resolved into the ordinary `storage` build")
    return 0


if __name__ == "__main__":
    sys.exit(main())
