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
import xml.etree.ElementTree as ET

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "bazel"))

import bazel_parity  # noqa: E402

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


def _tree_path(label: str) -> str | None:
    """`//server:service/x_test.rs` -> `server/service/x_test.rs`."""
    if not label.startswith("//") or ":" not in label:
        return None
    pkg, name = label[2:].split(":", 1)
    return f"{pkg}/{name}" if pkg else name


def build_crosswalk(bazel: pathlib.Path, labels: list[str], flags: list[str]):
    """Map every enumerated Bazel test label to its catalogue target id.

    Three kinds of target, three ways in — all of them anchored on the
    CATALOGUE, which is the denominator this crosswalk has to land in:

      static / shell rules   the catalogue records the label itself, spelled
                             `//.:x` for the root package where Bazel prints
                             `//:x` (bazel_parity.norm is the one place that
                             difference is written down).
      rust_test with srcs    the source file IS the join. The catalogue's
                             CARGO targets carry `source_files[].path`, so a
                             test's src resolves to exactly one of them.
      rust_test with crate   a lib unit test: the crate label names the
                             package, and the catalogue's `unit` target for
                             that package is its counterpart.

    Refuses rather than guesses. An unmapped label, or two labels landing on
    one catalogue id, stops the producer — the validator enforces the same
    bijection, and a bundle that papered over either would be rejected there
    anyway, but later and with less to say about why.
    """
    cat = json.loads(CATALOG.read_text())
    by_label: dict[str, str] = {}
    by_src: dict[str, str] = {}
    unit_by_package: dict[str, str] = {}
    for t in cat["targets"]:
        tid = t["target_id"]
        lbl = t.get("upstream_label")
        if isinstance(lbl, str) and lbl.startswith("//"):
            by_label[bazel_parity.norm(lbl)] = tid
        for sf in t.get("source_files") or []:
            path = sf.get("path")
            if path:
                by_src.setdefault(path, tid)
        if t.get("origin") == "CARGO" and tid.split(":")[2] == "unit":
            # keyed by the crate root's DIRECTORY, which is what a Bazel
            # `crate = "//admin/client:client"` names. The cargo package is
            # `typedb-admin` there and the Bazel crate is `client`: joining on
            # either name would miss it, joining on the directory cannot.
            for sf in t.get("source_files") or []:
                path = sf.get("path")
                if path:
                    unit_by_package[str(pathlib.PurePosixPath(path).parent)] = tid
                    break

    xml_proc = subprocess.run(
        [str(bazel), "query", "set(" + " ".join(labels) + ")", "--output=xml", *flags],
        cwd=TB,
        capture_output=True,
        text=True,
    )
    if xml_proc.returncode != 0:
        raise RuntimeError(f"`bazel query --output=xml` failed: {xml_proc.stderr[-2000:]}")
    root = ET.fromstring(xml_proc.stdout)

    crosswalk: list[dict[str, str]] = []
    unmapped: list[str] = []
    for rule in root.findall("rule"):
        label = rule.get("name")
        if label is None or label not in set(labels):
            continue
        tid = by_label.get(label)
        if tid is None:
            srcs = [
                c.get("value")
                for lst in rule.findall("list")
                if lst.get("name") == "srcs"
                for c in lst
            ]
            for src in srcs:
                path = _tree_path(src) if src else None
                if path and path in by_src:
                    tid = by_src[path]
                    break
        if tid is None:
            crate = next(
                (e.get("value") for e in rule.findall("label") if e.get("name") == "crate"), None
            )
            if crate and crate.startswith("//"):
                tid = unit_by_package.get(crate[2:].split(":", 1)[0] or ".")
        if tid is None:
            unmapped.append(label)
            continue
        crosswalk.append({"bazel_target": label, "catalog_target_id": tid})
    return crosswalk, unmapped


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
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
    ap.add_argument(
        "--distdir",
        type=pathlib.Path,
        default=REPO / "sources" / "bazel-distdir",
        help="Bazel --distdir holding the vendored bats archives (SI-G0-1). Bazel still verifies "
        "every digest itself, so this cannot substitute a wrong archive; build it with "
        "tools/bazel/vendor_bats.py.",
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

    # `--distdir` on BOTH invocations. The enumeration is loading-phase and
    # does not need it; passing it anyway keeps the two commands one
    # configuration, so a bundle can never be half-produced under two.
    bazel_flags = []
    if args.distdir is not None and args.distdir.is_dir():
        bazel_flags.append(f"--distdir={args.distdir}")

    enum_argv = [str(bazel), "query", args.query, "--output=label", *bazel_flags]
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
    # Two enumerated rules are build-release plumbing, not semantic tests of
    # the product, and bazel_parity.py already carries them as REVIEWED
    # non-denominator targets with reasons. Imported, not restated: a second
    # copy of an exclusion list is how an exclusion outlives its reason. They
    # are dropped from the cquery set AND recorded in the bundle, so the
    # bundle's own targets, its cquery stdout and its crosswalk are one set.
    declared_non_denominator = {
        lb: why
        for lb, why in bazel_parity.KNOWN_BAZEL_ONLY_NON_RUST_TEST.items()
        if lb in enumerated
    }
    enumerated = [lb for lb in enumerated if lb not in declared_non_denominator]
    if not enumerated:
        print("REFUSED: enumeration returned no test targets", file=sys.stderr)
        return 1

    # one positional expression, as the approved argv grammar requires
    expr = "set(" + " ".join(enumerated) + ")"
    argv = [str(bazel), "cquery", expr, "--output=label", *bazel_flags]
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

    try:
        crosswalk, unknown = build_crosswalk(bazel, labels, bazel_flags)
    except RuntimeError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 1
    if unknown:
        print(
            f"REFUSED: {len(unknown)} enumerated target(s) have no catalogue "
            f"entry, e.g. {unknown[:5]}. The build graph and the catalogue "
            "have diverged; a bundle that silently dropped them would shrink "
            "the denominator.",
            file=sys.stderr,
        )
        return 1
    by_cid: dict[str, list[str]] = {}
    for row in crosswalk:
        by_cid.setdefault(row["catalog_target_id"], []).append(row["bazel_target"])
    collisions = {k: v for k, v in by_cid.items() if len(v) > 1}
    if collisions:
        print(
            f"REFUSED: the crosswalk is not a bijection — {len(collisions)} catalogue id(s) "
            f"receive more than one Bazel label, e.g. "
            f"{sorted(collisions.items())[:2]}. The validator enforces the same rule.",
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
                "declared_non_denominator": declared_non_denominator,
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
