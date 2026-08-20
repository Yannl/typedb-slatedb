#!/usr/bin/env python3
"""R6-TRUTH-01 - the SEMANTIC dependency-source linter.

The round-6 audit found the repository telling two incompatible SlateDB
stories: `sources/typedb/Cargo.toml` carries a workspace-global
`[patch.crates-io] slatedb = { path = "../../sources/slatedb-fork" }`, while
README/architecture/development/operations and two ADR index rows still said
SlateDB is consumed unmodified from crates.io with deliberately no fork.

A grep over prose cannot catch that class of defect, and neither can a grep
over manifests: the storage crate's dependency table literally says
`source = "registry+https://github.com/rust-lang/crates.io-index"`. Only the
RESOLVED graph knows the patch exists. So this linter starts from
`cargo metadata`'s resolve nodes - the same ground truth `cargo tree` prints -
derives where each named dependency actually comes from, and then:

  1. FAILS when the resolved source contradicts the claim registered in
     tools/ci/dependency-source-claims.json (assert-side: the code moved and
     nobody re-ratified the decision);
  2. FAILS when a registered document still carries prose that the resolved
     graph has made false (prose-side: the code is right and the docs lie);
  3. FAILS when a document that must now state the true posture does not
     (prose-side, positive: silence is how a superseded claim survives).

Rules 2 and 3 only ACTIVATE when rule 1 holds, so this is not a grep list: if
the patch were removed tomorrow, rule 1 turns red instead of rules 2/3
silently inverting into nonsense.

Modes
-----
    check_dependency_sources.py                 # the real graph, the real docs
    check_dependency_sources.py --metadata WS=FILE
                                                # decide over captured
                                                # `cargo metadata` output
    check_dependency_sources.py --self-test     # behavioral mutants

Exit codes: 0 PASS, 1 contradiction found, 2 usage/IO/toolchain error.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CLAIMS_PATH = REPO_ROOT / "tools" / "ci" / "dependency-source-claims.json"
SCHEMA = "typedb-r2/dependency-source-claims@1"
CARGO_TOOLCHAIN = "+1.93.0"


class LinterError(Exception):
    """The linter cannot establish ground truth, so it must not report PASS."""


# ---------------------------------------------------------------------------
# ground truth: the resolved cargo graph
# ---------------------------------------------------------------------------


def cargo_metadata(manifest: Path) -> dict:
    cargo = shutil.which("cargo")
    if cargo is None:
        raise LinterError("cargo is not on PATH; cannot resolve the dependency graph")
    if not manifest.exists():
        raise LinterError(
            f"{manifest} is absent. This workspace is MATERIALISED, not committed - run the "
            f"workspace's `materialize` commands from tools/ci/dependency-source-claims.json first. "
            f"An absent tree is not evidence of a clean graph."
        )
    cmd = [cargo, CARGO_TOOLCHAIN, "metadata", "--manifest-path", str(manifest), "--format-version", "1", "--locked", "--offline"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise LinterError(f"`{' '.join(cmd)}` failed (exit {proc.returncode}):\n{proc.stderr.strip()[:4000]}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise LinterError(f"cargo metadata produced unparseable JSON: {exc}")


def resolved_facts(metadata: dict, package: str) -> list[dict]:
    """Every resolved node for `package`, with its ACTUAL source and features.

    `source: null` plus a manifest_path is how cargo represents a path
    dependency - which is precisely what `[patch.crates-io]` produces.
    """
    by_id = {p["id"]: p for p in metadata.get("packages", [])}
    resolve = metadata.get("resolve")
    if not isinstance(resolve, dict) or not isinstance(resolve.get("nodes"), list):
        raise LinterError(
            "cargo metadata carries no `resolve` graph (was it run with --no-deps?). "
            "Without the resolve graph there is no ground truth and PASS would be a guess."
        )
    facts = []
    for node in resolve["nodes"]:
        pkg = by_id.get(node["id"])
        if pkg is None or pkg.get("name") != package:
            continue
        source = pkg.get("source")
        if source is None:
            kind, detail = "path", str(Path(pkg["manifest_path"]).parent)
        elif source.startswith("registry+"):
            kind, detail = "registry", source[len("registry+") :]
        elif source.startswith("git+"):
            kind, detail = "git", source[len("git+") :]
        else:
            kind, detail = "unknown", source
        facts.append(
            {
                "id": node["id"],
                "version": pkg.get("version"),
                "kind": kind,
                "detail": detail,
                "features": sorted(node.get("features", [])),
            }
        )
    return facts


def assert_holds(claim: dict, facts: list[dict]) -> list[str]:
    """Return the reasons the claim's assertion does NOT hold ([] == it holds)."""
    spec = claim["assert"]
    if not facts:
        return [f"package {claim['package']!r} does not appear in the resolved graph at all"]
    if len(facts) > 1:
        return [
            f"package {claim['package']!r} resolves to {len(facts)} distinct nodes "
            f"({', '.join(f['id'] for f in facts)}); a source claim cannot be settled against an ambiguous graph"
        ]
    fact = facts[0]
    bad: list[str] = []
    if "version" in spec and fact["version"] != spec["version"]:
        bad.append(f"version is {fact['version']}, claim says {spec['version']}")
    if "resolved_source_kind" in spec and fact["kind"] != spec["resolved_source_kind"]:
        bad.append(f"resolved source kind is {fact['kind']!r} ({fact['detail']}), claim says {spec['resolved_source_kind']!r}")
    if "resolved_path_suffix" in spec:
        suffix = spec["resolved_path_suffix"]
        if fact["kind"] != "path" or not fact["detail"].replace("\\", "/").endswith(suffix):
            bad.append(f"resolved path is {fact['detail']!r}, claim expects it to end with {suffix!r}")
    if "resolved_registry" in spec and fact["detail"] != spec["resolved_registry"]:
        bad.append(f"resolved registry is {fact['detail']!r}, claim says {spec['resolved_registry']!r}")
    for feat in spec.get("enabled_features_include", []):
        if feat not in fact["features"]:
            bad.append(f"feature {feat!r} is NOT enabled in the resolved graph (enabled: {fact['features']})")
    return bad


# ---------------------------------------------------------------------------
# prose, gated on ground truth
# ---------------------------------------------------------------------------


def check_prose(claim: dict, root: Path) -> list[str]:
    prose = claim.get("prose") or {}
    failures: list[str] = []

    for rule in prose.get("forbidden_when_assert_holds", []):
        rx = re.compile(rule["pattern"])
        for rel in claim.get("documents", []):
            path = root / rel
            if not path.exists():
                failures.append(f"{claim['id']}: registered document {rel} does not exist")
                continue
            text = path.read_text(encoding="utf-8")
            for m in rx.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                failures.append(
                    f"{claim['id']}: {rel}:{line} still claims a dependency source the resolved graph "
                    f"contradicts - matched /{rule['pattern']}/ ({rule['reason']})"
                )

    for rule in prose.get("required_when_assert_holds", []):
        rel = rule["file"]
        path = root / rel
        if not path.exists():
            failures.append(f"{claim['id']}: required document {rel} does not exist")
            continue
        if not re.search(rule["pattern"], path.read_text(encoding="utf-8")):
            failures.append(
                f"{claim['id']}: {rel} does not state the posture the resolved graph proves - "
                f"expected /{rule['pattern']}/ ({rule['reason']})"
            )
    return failures


# ---------------------------------------------------------------------------
# self-test: behavioral mutants over real cargo metadata documents
# ---------------------------------------------------------------------------


def _fixture_metadata(*, source: str | None, manifest: str, features: list[str]) -> dict:
    ident = "path+file:///x#slatedb@0.15.0" if source is None else f"{source}#slatedb@0.15.0"
    return {
        "packages": [{"id": ident, "name": "slatedb", "version": "0.15.0", "source": source, "manifest_path": manifest}],
        "resolve": {"nodes": [{"id": ident, "features": features, "deps": []}], "root": None},
    }


def self_test(root: Path) -> int:
    claims = load_claims(CLAIMS_PATH)
    real = next(c for c in claims["claims"] if c["id"] == "DS-01")
    failures = 0

    forked = _fixture_metadata(
        source=None,
        manifest="/repo/sources/slatedb-fork/Cargo.toml",
        features=["aws", "external_epoch_required", "wal_disable"],
    )
    registry_src = "registry+https://github.com/rust-lang/crates.io-index"

    graph_cases = [
        ("CONTROL: the fork-resolved graph satisfies DS-01", forked, True),
        (
            "MUTANT graph-reverts-to-crates.io (the [patch.crates-io] line is deleted)",
            _fixture_metadata(source=registry_src, manifest="/root/.cargo/registry/.../Cargo.toml", features=["aws", "external_epoch_required", "wal_disable"]),
            False,
        ),
        (
            "MUTANT shipped-fence-feature-silently-dropped",
            _fixture_metadata(source=None, manifest="/repo/sources/slatedb-fork/Cargo.toml", features=["aws", "wal_disable"]),
            False,
        ),
        (
            "MUTANT fork-path-swapped-for-a-different-tree",
            _fixture_metadata(source=None, manifest="/repo/sources/slatedb-someone-elses/Cargo.toml", features=["aws", "external_epoch_required", "wal_disable"]),
            False,
        ),
        (
            "MUTANT version-drifts-under-the-same-path",
            {
                "packages": [{"id": "path+file:///x#slatedb@0.16.0", "name": "slatedb", "version": "0.16.0", "source": None, "manifest_path": "/repo/sources/slatedb-fork/Cargo.toml"}],
                "resolve": {"nodes": [{"id": "path+file:///x#slatedb@0.16.0", "features": ["aws", "external_epoch_required", "wal_disable"], "deps": []}]},
            },
            False,
        ),
        (
            "MUTANT metadata-without-a-resolve-graph must not read as PASS",
            {"packages": [], "resolve": None},
            None,
        ),
    ]
    for name, meta, expect_holds in graph_cases:
        try:
            bad = assert_holds(real, resolved_facts(meta, real["package"]))
            err = None
        except LinterError as exc:
            bad, err = [], str(exc)
        if expect_holds is None:
            ok = err is not None
            detail = f"expected a LinterError, got {bad}"
        elif expect_holds:
            ok = err is None and not bad
            detail = f"expected the assertion to hold, got {bad or err}"
        else:
            ok = err is None and bool(bad)
            detail = f"expected the assertion to be contradicted, got PASS ({err or ''})"
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")
        if not ok:
            print(f"       {detail}")
            failures += 1

    # prose mutants, executed over real copies of the real documents
    with tempfile.TemporaryDirectory() as tmp:
        sandbox = Path(tmp)
        for rel in real["documents"] + [r["file"] for r in real["prose"]["required_when_assert_holds"]]:
            src = root / rel
            dst = sandbox / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.exists():
                dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

        prose_cases: list[tuple[str, str, str, bool]] = [
            ("CONTROL: the ratified documents pass the prose gate", "", "", True),
            (
                "MUTANT a document re-asserts the crates.io story",
                "README.md",
                "\n\nSlateDB is consumed **unmodified from crates.io** (`=0.15.0`, checksum-locked).\n",
                False,
            ),
            (
                "MUTANT development.md re-asserts 'SlateDB is never edited'",
                "docs/development.md",
                "\n\n3. SlateDB is never edited (ADR-0001).\n",
                False,
            ),
            (
                "MUTANT operations.md re-asserts the pending-ADR posture",
                "docs/operations.md",
                "\n\n`sources/typedb` consumes\ncrates.io until ADR-0012 is decided and G2 passes.\n",
                False,
            ),
            (
                "MUTANT the ADR index restores the no-fork row",
                "docs/architecture/ADR/README.md",
                "\n| ADR-0001 | SlateDB is a pinned crates.io dependency — no fork; SL-P* patch obligations relocated to owned layers | accepted |\n",
                False,
            ),
        ]
        originals = {rel: (sandbox / rel).read_text(encoding="utf-8") for rel in {c[1] for c in prose_cases if c[1]}}
        for name, rel, injected, expect_pass in prose_cases:
            if rel:
                (sandbox / rel).write_text(originals[rel] + injected, encoding="utf-8")
            found = check_prose(real, sandbox)
            if rel:
                (sandbox / rel).write_text(originals[rel], encoding="utf-8")
            ok = (not found) if expect_pass else bool(found)
            print(f"  {'ok  ' if ok else 'FAIL'} {name}")
            if not ok:
                print(f"       expected {'PASS' if expect_pass else 'FAIL'}, got {found}")
                failures += 1

        # A required statement that is DELETED must also be caught: silence is
        # how a superseded claim survives a review.
        rel = real["prose"]["required_when_assert_holds"][0]["file"]
        original = (sandbox / rel).read_text(encoding="utf-8")
        (sandbox / rel).write_text(original.replace("sources/slatedb-fork", "the storage engine"), encoding="utf-8")
        found = check_prose(real, sandbox)
        ok = any("does not state the posture" in f for f in found)
        print(f"  {'ok  ' if ok else 'FAIL'} MUTANT the required fork statement is quietly deleted from {rel}")
        if not ok:
            print(f"       expected a missing-required-statement failure, got {found}")
            failures += 1
        (sandbox / rel).write_text(original, encoding="utf-8")

    print()
    if failures:
        print(f"dependency-source linter self-test: {failures} case(s) FAILED")
        return 1
    print("dependency-source linter self-test: every mutant was caught and every control passed")
    return 0


# ---------------------------------------------------------------------------


def load_claims(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise LinterError(f"claims file missing: {path}")
    except json.JSONDecodeError as exc:
        raise LinterError(f"claims file is not valid JSON: {exc}")
    if doc.get("schema") != SCHEMA:
        raise LinterError(f"claims schema must be {SCHEMA!r}, got {doc.get('schema')!r}")
    if not doc.get("claims"):
        raise LinterError("claims file registers no claims - an empty gate is not a gate")
    return doc


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--claims", default=str(CLAIMS_PATH))
    ap.add_argument("--root", default=str(REPO_ROOT))
    ap.add_argument("--metadata", action="append", default=[], metavar="WS=FILE",
                    help="use a captured `cargo metadata` document for workspace WS instead of running cargo")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    if args.self_test:
        try:
            return self_test(root)
        except LinterError as exc:
            print(f"LINTER ERROR: {exc}", file=sys.stderr)
            return 2

    captured: dict[str, Path] = {}
    for spec in args.metadata:
        if "=" not in spec:
            print(f"--metadata expects WS=FILE, got {spec!r}", file=sys.stderr)
            return 2
        ws, _, file = spec.partition("=")
        captured[ws] = Path(file)

    try:
        claims_doc = load_claims(Path(args.claims))
    except LinterError as exc:
        print(f"LINTER ERROR: {exc}", file=sys.stderr)
        return 2

    failures: list[str] = []
    meta_cache: dict[str, dict] = {}
    for claim in claims_doc["claims"]:
        ws_id = claim["workspace"]
        ws = claims_doc["workspaces"][ws_id]
        try:
            if ws_id not in meta_cache:
                if ws_id in captured:
                    meta_cache[ws_id] = json.loads(captured[ws_id].read_text(encoding="utf-8"))
                else:
                    meta_cache[ws_id] = cargo_metadata(root / ws["manifest"])
            facts = resolved_facts(meta_cache[ws_id], claim["package"])
        except LinterError as exc:
            if claim.get("optional"):
                print(f"{claim['id']}: SKIPPED (optional) - {exc}")
                continue
            failures.append(f"{claim['id']}: {exc}")
            continue

        bad = assert_holds(claim, facts)
        fact_line = facts[0] if facts else None
        if fact_line:
            print(f"{claim['id']}: {ws_id}/{claim['package']} resolves as {fact_line['kind']} -> {fact_line['detail']} "
                  f"(v{fact_line['version']}, features {fact_line['features']})")
        if bad:
            for b in bad:
                failures.append(
                    f"{claim['id']} [{claim['title']}]: the RESOLVED graph contradicts the ratified claim: {b}. "
                    f"Either the dependency change is wrong, or the decision must be re-ratified in "
                    f"{', '.join(claim.get('ratified_by', ['the ADRs'])) or 'the ADRs'} and in this claims file."
                )
            continue  # prose rules are gated on the assertion holding
        failures.extend(check_prose(claim, root))

    print()
    if failures:
        print(f"DEPENDENCY-SOURCE TRUTH: FAIL ({len(failures)} contradiction(s))")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("DEPENDENCY-SOURCE TRUTH: PASS (every documented dependency source matches the resolved cargo graph)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
