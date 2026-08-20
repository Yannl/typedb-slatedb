#!/usr/bin/env python3
"""Produce the Mode-Q bundle by actually running `bazel cquery` (SI-G0-1, G0).

`validate_modeq.py` has existed for three rounds with nothing to validate:
Mode-Q has been ABSENT, and G0 has been OPEN_RED because of it. This is the
producer. It is deliberately thin — every rule about what a valid bundle is
lives in the validator, and this tool's job is to run the real command and
record its real bytes, not to describe them.

Why it does not run in the agent sandbox, measured rather than assumed:
`aspect_bazel_lib` registers `bats_toolchains`, fetched from
github.com/bats-core, and the egress policy there denies that fetch with
403. A REGISTERED toolchain must load before Bazel can resolve toolchains
for any configured target, so even a single-target cquery aborts in the
analysis phase. `bazel query` (loading only) works fine there, which is why
tools/bazel/bazel_parity.py can answer the structural question locally while
this cannot answer the semantic one.

The correct behaviour when it cannot run is to produce NOTHING. An absent
bundle directory makes the validator print `MODEQ: ABSENT` and exit 0,
keeping G0 honestly open; a half-written directory would make it print
`MODEQ: INVALID` and break the gate. So this tool writes the bundle only
after a successful cquery, into a temporary directory it renames into place.

usage:
  python3 tools/modeq/produce_modeq.py --out docs/evidence/G0/mode-q
"""

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
TB = REPO / "sources" / "typedb"
SOURCE_LOCK = REPO / "source-lock" / "source-lock.json"
WORKSPACE_LOCK = REPO / "source-lock" / "workspace-lock.json"
CATALOG = REPO / "docs" / "evidence" / "G1" / "upstream-test-catalog.json"

# Every test target in the product workspace, as the build system itself
# sees them. `//bazel-typedb` is excluded because this project materialises
# symlinks there that upstream does not have; they would report phantom
# packages that are an artefact of our checkout, not of TypeDB.
ENUMERATION_QUERY = "kind('.*_test rule', //...) - //bazel-typedb/..."

# Enumeration runs in the LOADING phase and cquery then runs on the explicit
# label set. That is not a convenience: `cquery kind(..., //...)` has to
# CONFIGURE the whole universe before it can filter by kind, and //... contains
# `//:deploy-mac-installer-pkg`, an upstream mac-only alias whose select() has
# no default - so it fails analysis on Linux no matter what the network allows.
# Narrowing the universe to `//... - //:*` would dodge it but silently drop 5
# real root-package test targets (228 -> 223), which is exactly the kind of
# quiet denominator shrink this project refuses. Enumerating first keeps all
# 228 and configures only test targets.


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pinned_tb() -> tuple[str, str]:
    lock = json.loads(SOURCE_LOCK.read_text())
    tb = next(n for n in lock["nodes"] if n.get("id") == "TB")
    return tb["revision"], tb["tree"]


def catalog_by_label() -> dict[str, str]:
    """Map a Bazel label to its catalogue target id.

    The catalogue records the label it was generated from; the crosswalk is
    that mapping and nothing more. A label the catalogue does not know is
    left out here and the validator will reject the bundle for omitting an
    enumerated target — which is the correct outcome: it means the
    catalogue and the build graph have diverged and a human must look.
    """
    cat = json.loads(CATALOG.read_text())
    out: dict[str, str] = {}
    for t in cat["targets"]:
        for key in ("bazel_label", "label", "target_label"):
            if isinstance(t.get(key), str) and t[key].startswith("//"):
                out[t[key]] = t["target_id"]
                break
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--bazel", default=shutil.which("bazel") or "bazel")
    ap.add_argument(
        "--query",
        default=ENUMERATION_QUERY,
        help="loading-phase enumeration query; cquery then runs on "
        "the explicit label set it returns",
    )
    ap.add_argument(
        "--toolchain", default=None, help="recorded toolchain identity; defaults to .bazelversion"
    )
    args = ap.parse_args()

    bazel = pathlib.Path(args.bazel)
    if not bazel.is_file():
        print(f"REFUSED: bazel not found at {bazel}", file=sys.stderr)
        return 2
    version_proc = subprocess.run([str(bazel), "--version"], cwd=TB, capture_output=True, text=True)
    version = (version_proc.stdout + version_proc.stderr).strip().splitlines()
    if version_proc.returncode != 0 or not version:
        print(
            f"REFUSED: `bazel --version` failed: "
            f"{(version_proc.stdout + version_proc.stderr)[:400]}",
            file=sys.stderr,
        )
        return 2

    enum_argv = [str(bazel), "query", args.query, "--output=label"]
    enum = subprocess.run(enum_argv, cwd=TB, capture_output=True, text=True)
    if enum.returncode != 0:
        print(
            f"REFUSED: enumeration `bazel query` failed (exit {enum.returncode}); "
            "nothing written, Mode-Q stays ABSENT.",
            file=sys.stderr,
        )
        print(enum.stderr[-3000:], file=sys.stderr)
        return 1
    enumerated = sorted({ln.strip() for ln in enum.stdout.splitlines() if ln.strip()})
    if not enumerated:
        print("REFUSED: enumeration returned no test targets", file=sys.stderr)
        return 1

    # one positional expression, as the approved argv grammar requires
    expr = "set(" + " ".join(enumerated) + ")"
    argv = [str(bazel), "cquery", expr, "--output=label"]
    proc = subprocess.run(argv, cwd=TB, capture_output=True, text=True)
    if proc.returncode != 0:
        # The honest outcome: write nothing, explain, and leave Mode-Q ABSENT
        # so the gate stays open rather than being broken by a junk directory.
        print(
            "REFUSED: `bazel cquery` did not succeed, so there is no Mode-Q "
            f"observation to record (exit {proc.returncode}). Nothing was "
            "written; Mode-Q stays ABSENT and G0 stays open.",
            file=sys.stderr,
        )
        print(proc.stderr[-3000:], file=sys.stderr)
        return 1

    labels = [ln.split(" (")[0].strip() for ln in proc.stdout.splitlines() if ln.strip()]
    labels = sorted(set(labels))
    if not labels:
        print(
            "REFUSED: cquery returned no targets — an empty snapshot enumerates nothing",
            file=sys.stderr,
        )
        return 1

    by_label = catalog_by_label()
    crosswalk = [
        {"bazel_target": lb, "catalog_target_id": by_label[lb]} for lb in labels if lb in by_label
    ]
    unknown = [lb for lb in labels if lb not in by_label]
    if unknown:
        print(
            f"REFUSED: {len(unknown)} enumerated target(s) have no catalogue "
            f"entry, e.g. {unknown[:5]}. The build graph and the catalogue "
            "have diverged; a bundle that silently dropped them would shrink "
            "the denominator.",
            file=sys.stderr,
        )
        return 1

    rev, tree = pinned_tb()
    with tempfile.TemporaryDirectory(prefix="modeq-") as tmp:
        stage = pathlib.Path(tmp) / "mode-q"
        stage.mkdir()
        (stage / "cquery-stdout.txt").write_text(proc.stdout, encoding="utf-8")
        (stage / "cquery-stderr.txt").write_text(proc.stderr, encoding="utf-8")
        (stage / "crosswalk.json").write_text(
            json.dumps(crosswalk, indent=2) + "\n", encoding="utf-8"
        )

        manifest = {
            "schema": "modeq-bundle/v1",
            "bazel": {
                "binary_sha256": sha256_file(bazel),
                "version": version[0],
            },
            "invocation": {
                "argv": argv,
                "env": {k: os.environ.get(k, "") for k in ("PATH", "HOME", "USE_BAZEL_VERSION")},
                "toolchain": args.toolchain or (TB / ".bazelversion").read_text().strip(),
                "source_commit": rev,
                "source_tree": tree,
                "workspace_lock_sha256": sha256_file(WORKSPACE_LOCK),
            },
            "cquery": {
                "stdout_file": "cquery-stdout.txt",
                "stderr_file": "cquery-stderr.txt",
                "stdout_sha256": sha256_file(stage / "cquery-stdout.txt"),
                "stderr_sha256": sha256_file(stage / "cquery-stderr.txt"),
                "exit_code": proc.returncode,
            },
            "targets": labels,
            "enumeration": {
                "argv": enum_argv,
                "query": args.query,
                "count": len(enumerated),
                "note": "loading-phase enumeration; cquery configured exactly "
                "these labels, never the whole //... universe",
            },
            "crosswalk_file": "crosswalk.json",
        }
        lines = [f"{p.name}\n{sha256_file(p)}\n" for p in sorted(stage.iterdir()) if p.is_file()]
        manifest["root"] = hashlib.sha256("".join(sorted(lines)).encode()).hexdigest()
        (stage / "modeq.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        out = args.out
        if out.exists():
            shutil.rmtree(out)
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(stage, out)

    print(f"MODEQ PRODUCED: {len(labels)} targets, root {manifest['root']}")
    print(f"bundle: {args.out}")
    print(
        "now run tools/modeq/validate_modeq.py — this producer deliberately "
        "does not judge its own output."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
