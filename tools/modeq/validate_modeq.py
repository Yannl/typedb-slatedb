#!/usr/bin/env python3
"""Semantic Mode-Q bundle validator (round-3 audit finding E-01).

The previous CI check passed on ANY file in docs/evidence/G0/mode-q — the
audit dropped a junk file in and G0 looked evidenced. This validator
replaces that check with a schema + integrity + crosswalk verification of
the Mode-Q bundle the v17 addendum actually requires:

  docs/evidence/G0/mode-q/
    modeq.json          the bundle manifest (schema modeq-bundle/v1):
      bazel:            {binary_sha256 (64-hex), version (non-empty)}
      invocation:       {argv, env, toolchain,
                         source_commit (must EQUAL the TB revision pinned
                         in source-lock/source-lock.json), source_tree
                         (must equal the pinned tree), workspace_lock_sha256
                         (must EQUAL the sha256 of the CURRENT
                         source-lock/workspace-lock.json - a well-shaped
                         but wrong or forged hash fails; strict equality is
                         safe because no committed bundle exists today and
                         absence keeps G0 open anyway)}
                        R4-MODEQ-01: argv must match the approved command
                        grammar - argv[0]'s basename must be an approved
                        Bazel executable (bazel/bazelisk; 'echo' fails),
                        followed by optional startup options (-...), the
                        literal 'cquery', exactly one query expression, and
                        optional --flags. A list merely CONTAINING the
                        string 'cquery' is not an invocation.
      cquery:           {stdout_file, stderr_file, stdout_sha256,
                         stderr_sha256, exit_code} — the raw byte files
                         must exist, hash-match, and exit_code MUST be 0.
                         R4-MODEQ-01: stdout is PARSED with the real cquery
                         line grammar - every non-empty line must be a
                         Bazel label, optionally followed by a
                         configuration hash "(hex)" or "(null)"; arbitrary
                         junk ("THIS IS NOT BAZEL OUTPUT") fails.
      targets:          non-empty, unique Bazel labels
      crosswalk_file:   file of [{bazel_target, catalog_target_id}]:
                         every bundle target appears EXACTLY once, no
                         unknown bazel targets, and every catalog id
                         exists in the canonical catalogue.
                         R4-MODEQ-01: the mapping must be a BIJECTION -
                         each catalogue id maps to at most one Bazel label
                         unless a versioned n:1 allowlist entry with a
                         reason exists below (N_TO_ONE_ALLOWLIST, default
                         empty); two labels onto one id is rejected.
      root:             sha256 over the sorted "relpath\\nsha256\\n" lines
                         of every OTHER file in the bundle directory
    <raw files>         every file must be accounted for (manifest,
                         stdout, stderr, crosswalk) — an unaccounted junk
                         file fails the bundle. R4-MODEQ-01: every
                         referenced filename must be a SAFE BASENAME inside
                         the bundle dir - path separators, '..', and
                         absolute paths are rejected before any resolution.

Exit codes:
  0  directory absent            -> prints "MODEQ: ABSENT"  (the ledger
                                    consistency check keeps G0 open)
  0  bundle present and VALID    -> prints "MODEQ: VALID"
  1  anything else               -> prints "MODEQ: INVALID" + reasons

With --ledger <gates.json> the two-directional consistency is enforced in
the same process: VALID requires the ledger to have closed G0, ABSENT
requires it to hold G0 open — either mismatch (and any INVALID) exits 1.
Only validator success may ever set G0 CLOSED; NOT_REACHABLE or a
narrative proof is not green.
"""

import argparse
import hashlib
import json
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_DIR = REPO / "docs" / "evidence" / "G0" / "mode-q"
SOURCE_LOCK = REPO / "source-lock" / "source-lock.json"
CATALOG = REPO / "docs" / "evidence" / "G1" / "upstream-test-catalog.json"

WORKSPACE_LOCK = REPO / "source-lock" / "workspace-lock.json"

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

# R4-MODEQ-01: the only executables that may claim to have produced a
# cquery snapshot (basename of argv[0])
APPROVED_BAZEL_BASENAMES = {"bazel", "bazelisk"}

# R4-MODEQ-01: one cquery result line — a Bazel label, optionally followed
# by a configuration checksum "(hex)" or "(null)" (bazel cquery's default
# --output=label form). Anything else on stdout is not cquery output.
CQUERY_LINE = re.compile(r"^(@[\w.-]*)?//[\w./-]*(:[\w./+=,@~-]+)?( \(([0-9a-f]+|null)\))?$")

# R4-MODEQ-01: a referenced file must be a safe basename inside the bundle
SAFE_BASENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# R4-MODEQ-01: versioned n:1 crosswalk allowlist. The bijection policy is
# the default: each catalogue id maps to at most one Bazel label. An entry
# here — {"catalog_target_id": {"labels": [...], "reason": "..."}} — is the
# ONLY way more than one label may land on one id, and each entry must name
# its reason. Deliberately empty (v1): no approved n:1 mapping exists.
N_TO_ONE_ALLOWLIST_VERSION = 1
N_TO_ONE_ALLOWLIST: dict = {}


def safe_bundle_file(
    bundle_dir: pathlib.Path, name: str, field: str, errors: list[str]
) -> pathlib.Path | None:
    """Resolve a manifest-referenced filename strictly as a basename under
    the bundle dir; reject path separators, '..' and absolute paths BEFORE
    touching the filesystem."""
    if (
        "/" in name
        or "\\" in name
        or name in (".", "..")
        or pathlib.PurePosixPath(name).is_absolute()
        or pathlib.PureWindowsPath(name).is_absolute()
        or not SAFE_BASENAME.match(name)
    ):
        errors.append(
            f"{field} {name!r} is not a safe basename — referenced "
            "files must live directly inside the bundle directory"
        )
        return None
    return bundle_dir / name


def check_argv_grammar(argv: list[str], errors: list[str]) -> None:
    """The approved command grammar (R4-MODEQ-01):
    <bazel|bazelisk> [startup options...] cquery <expr> [--flags...]
    Merely containing the string 'cquery' somewhere is NOT an invocation
    (the audit's counterexample: ['echo', 'cquery'])."""
    base = pathlib.PurePosixPath(argv[0]).name
    if base not in APPROVED_BAZEL_BASENAMES:
        errors.append(
            f"invocation.argv[0] {argv[0]!r} is not an approved Bazel "
            f"executable ({', '.join(sorted(APPROVED_BAZEL_BASENAMES))}) — "
            "whatever ran, it was not Bazel"
        )
        return
    rest = argv[1:]
    i = 0
    while i < len(rest) and rest[i].startswith("-"):
        i += 1  # bazel startup options
    if i >= len(rest) or rest[i] != "cquery":
        errors.append(
            "invocation.argv does not match the approved grammar "
            "'bazel [startup opts] cquery <expr> [--flags]' — the command "
            "after the startup options must be cquery"
        )
        return
    tail = rest[i + 1 :]
    positional = [a for a in tail if not a.startswith("-")]
    flags = [a for a in tail if a.startswith("-")]
    if len(positional) != 1 or not positional[0].strip():
        errors.append(
            f"invocation.argv must carry exactly one cquery expression, got {positional!r}"
        )
    if any(not f.startswith("--") for f in flags):
        errors.append(
            f"invocation.argv carries malformed cquery flags: "
            f"{[f for f in flags if not f.startswith('--')]!r}"
        )


def check_cquery_stdout(path: pathlib.Path, errors: list[str]) -> None:
    """Parse the raw stdout with the real cquery line grammar: every
    non-empty line must be a Bazel label (optionally '(confighash)' or
    '(null)'). Junk bytes are not a query snapshot."""
    try:
        text = path.read_text(errors="replace")
    except OSError as error:
        errors.append(f"cquery stdout is unreadable: {error}")
        return
    bad = [
        line for line in text.splitlines() if line.strip() and not CQUERY_LINE.match(line.strip())
    ]
    if bad:
        errors.append(
            f"cquery stdout contains {len(bad)} line(s) that are not Bazel "
            f"cquery output (first: {bad[0][:80]!r}) — junk bytes are not a "
            "query snapshot"
        )


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pinned_source(errors: list[str]) -> tuple[str | None, str | None]:
    """The TB revision+tree the source lock pins; Mode-Q must match it."""
    try:
        lock = json.loads(SOURCE_LOCK.read_text())
        tb = next(n for n in lock["nodes"] if n.get("id") == "TB")
        return str(tb["revision"]), str(tb.get("tree") or "")
    except Exception as error:
        errors.append(f"cannot read the pinned TB source from {SOURCE_LOCK}: {error}")
        return None, None


def catalog_target_ids(errors: list[str]) -> set[str] | None:
    try:
        cat = json.loads(CATALOG.read_text())
        return {t["target_id"] for t in cat["targets"]}
    except Exception as error:
        errors.append(f"cannot read the canonical catalogue {CATALOG}: {error}")
        return None


def validate_bundle(bundle_dir: pathlib.Path) -> list[str]:
    """Return the list of validation failures (empty == VALID)."""
    errors: list[str] = []
    manifest_path = bundle_dir / "modeq.json"
    if not manifest_path.is_file():
        return [f"{manifest_path.name} is missing — a Mode-Q bundle without its manifest is junk"]
    try:
        doc = json.loads(manifest_path.read_text())
    except Exception as error:
        return [f"modeq.json is not valid JSON: {error}"]
    if not isinstance(doc, dict):
        return ["modeq.json is not a JSON object"]
    if doc.get("schema") != "modeq-bundle/v1":
        errors.append(f"schema must be 'modeq-bundle/v1', got {doc.get('schema')!r}")

    # --- bazel identity ---
    bazel = doc.get("bazel")
    if not isinstance(bazel, dict):
        errors.append("missing 'bazel' object")
    else:
        if not (
            isinstance(bazel.get("binary_sha256"), str) and HEX64.match(bazel["binary_sha256"])
        ):
            errors.append(
                "bazel.binary_sha256 must be a 64-hex sha256 of the exact Bazel/Bazelisk binary"
            )
        if not (isinstance(bazel.get("version"), str) and bazel["version"].strip()):
            errors.append("bazel.version missing")

    # --- invocation identity, bound to the pinned source ---
    inv = doc.get("invocation")
    if not isinstance(inv, dict):
        errors.append("missing 'invocation' object")
    else:
        argv = inv.get("argv")
        if not (isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv)):
            errors.append("invocation.argv must be a non-empty string list")
        else:
            check_argv_grammar(argv, errors)
        if not isinstance(inv.get("env"), dict):
            errors.append("invocation.env must be an object")
        if not (isinstance(inv.get("toolchain"), str) and inv["toolchain"].strip()):
            errors.append("invocation.toolchain missing")
        pinned_rev, pinned_tree = pinned_source(errors)
        commit = inv.get("source_commit")
        if not (isinstance(commit, str) and HEX40.match(commit)):
            errors.append("invocation.source_commit must be a full 40-hex commit")
        elif pinned_rev is not None and commit != pinned_rev:
            errors.append(
                f"invocation.source_commit {commit} is not the pinned TB revision {pinned_rev} — "
                "evidence over the wrong source proves nothing about this release"
            )
        tree = inv.get("source_tree")
        if not (isinstance(tree, str) and HEX40.match(tree)):
            errors.append("invocation.source_tree must be a full 40-hex tree")
        elif pinned_tree and tree != pinned_tree:
            errors.append(f"invocation.source_tree {tree} is not the pinned TB tree {pinned_tree}")
        wl = inv.get("workspace_lock_sha256")
        if not (isinstance(wl, str) and HEX64.match(wl)):
            errors.append("invocation.workspace_lock_sha256 must be a 64-hex sha256")
        elif not WORKSPACE_LOCK.is_file():
            errors.append(f"cannot verify workspace_lock_sha256: {WORKSPACE_LOCK} does not exist")
        elif wl != sha256_file(WORKSPACE_LOCK):
            errors.append(
                f"invocation.workspace_lock_sha256 {wl} is not the sha256 of the CURRENT "
                f"{WORKSPACE_LOCK.relative_to(REPO)} ({sha256_file(WORKSPACE_LOCK)}) — "
                "a well-shaped hash that matches nothing pins nothing (R4-MODEQ-01)"
            )

    # --- raw cquery bytes ---
    accounted = {"modeq.json"}
    cq = doc.get("cquery")
    if not isinstance(cq, dict):
        errors.append("missing 'cquery' object")
    else:
        for role in ("stdout", "stderr"):
            fname = cq.get(f"{role}_file")
            digest = cq.get(f"{role}_sha256")
            if not (isinstance(fname, str) and fname):
                errors.append(f"cquery.{role}_file missing")
                continue
            fpath = safe_bundle_file(bundle_dir, fname, f"cquery.{role}_file", errors)
            if fpath is None:
                continue
            accounted.add(fname)
            if not fpath.is_file():
                errors.append(f"cquery.{role}_file {fname} does not exist in the bundle")
                continue
            if not (isinstance(digest, str) and HEX64.match(digest)):
                errors.append(f"cquery.{role}_sha256 must be a 64-hex sha256")
            elif sha256_file(fpath) != digest:
                errors.append(
                    f"cquery.{role}_file {fname} does not hash to its recorded sha256 — "
                    "truncated or altered raw output"
                )
        if cq.get("exit_code") != 0:
            errors.append(
                f"cquery.exit_code is {cq.get('exit_code')!r} — a nonzero cquery is not evidence of anything"
            )
        stdout_file = cq.get("stdout_file")
        if (
            isinstance(stdout_file, str)
            and SAFE_BASENAME.match(stdout_file)
            and (bundle_dir / stdout_file).is_file()
        ):
            if (bundle_dir / stdout_file).stat().st_size == 0:
                errors.append("cquery stdout is empty — an empty snapshot enumerates nothing")
            else:
                check_cquery_stdout(bundle_dir / stdout_file, errors)

    # --- target set ---
    targets = doc.get("targets")
    target_set: set[str] = set()
    if not (isinstance(targets, list) and targets and all(isinstance(t, str) for t in targets)):
        errors.append("targets must be a non-empty string list of Bazel labels")
    else:
        if len(set(targets)) != len(targets):
            dupes = sorted({t for t in targets if targets.count(t) > 1})
            errors.append(f"duplicate targets: {', '.join(dupes)}")
        bad = [t for t in targets if not (t.startswith("//") or t.startswith("@"))]
        if bad:
            errors.append(f"non-label targets: {', '.join(bad[:5])}")
        target_set = set(targets)

    # --- crosswalk to the canonical catalogue ---
    xw_name = doc.get("crosswalk_file")
    if not (isinstance(xw_name, str) and xw_name):
        errors.append("crosswalk_file missing")
    elif (xw_path := safe_bundle_file(bundle_dir, xw_name, "crosswalk_file", errors)) is not None:
        accounted.add(xw_name)
        if not xw_path.is_file():
            errors.append(f"crosswalk_file {xw_name} does not exist in the bundle")
        else:
            try:
                xw = json.loads(xw_path.read_text())
            except Exception as error:
                xw = None
                errors.append(f"crosswalk is not valid JSON: {error}")
            if xw is not None:
                if not isinstance(xw, list):
                    errors.append("crosswalk must be a list of {bazel_target, catalog_target_id}")
                else:
                    cat_ids = catalog_target_ids(errors)
                    seen: list[str] = []
                    by_catalog_id: dict[str, list[str]] = {}
                    for i, row in enumerate(xw):
                        if not (
                            isinstance(row, dict)
                            and isinstance(row.get("bazel_target"), str)
                            and isinstance(row.get("catalog_target_id"), str)
                        ):
                            errors.append(
                                f"crosswalk row {i} is not {{bazel_target, catalog_target_id}}"
                            )
                            continue
                        seen.append(row["bazel_target"])
                        by_catalog_id.setdefault(row["catalog_target_id"], []).append(
                            row["bazel_target"]
                        )
                        if target_set and row["bazel_target"] not in target_set:
                            errors.append(
                                f"crosswalk names unknown bazel target {row['bazel_target']}"
                            )
                        if cat_ids is not None and row["catalog_target_id"] not in cat_ids:
                            errors.append(
                                f"crosswalk names unknown catalogue id {row['catalog_target_id']}"
                            )
                    if len(set(seen)) != len(seen):
                        dupes = sorted({t for t in seen if seen.count(t) > 1})
                        errors.append(
                            f"crosswalk maps a bazel target more than once: {', '.join(dupes)}"
                        )
                    # R4-MODEQ-01: BIJECTION policy — each catalogue id may
                    # receive at most one Bazel label unless a versioned
                    # allowlist entry with a reason approves the n:1 mapping
                    for cid, labels in sorted(by_catalog_id.items()):
                        if len(labels) <= 1:
                            continue
                        allowed = N_TO_ONE_ALLOWLIST.get(cid)
                        if (
                            allowed
                            and sorted(labels) == sorted(allowed.get("labels", []))
                            and allowed.get("reason")
                        ):
                            continue
                        errors.append(
                            f"crosswalk maps {len(labels)} bazel labels "
                            f"({', '.join(sorted(labels)[:3])}) onto one catalogue id "
                            f"{cid} — the mapping must be a bijection; an n:1 mapping "
                            f"requires a versioned allowlist entry with a reason "
                            f"(allowlist v{N_TO_ONE_ALLOWLIST_VERSION} has none)"
                        )
                    missing = sorted(target_set - set(seen))
                    if missing:
                        errors.append(
                            f"targets omitted from the crosswalk: {', '.join(missing[:5])} — "
                            "every enumerated target must land in the catalogue"
                        )

    # --- unaccounted files: junk fails the bundle ---
    actual = {p.name for p in bundle_dir.iterdir() if p.is_file()}
    junk = sorted(actual - accounted)
    if junk:
        errors.append(
            f"unaccounted file(s) in the bundle: {', '.join(junk)} — junk is not evidence"
        )
    for sub in bundle_dir.iterdir():
        if sub.is_dir():
            errors.append(f"unexpected subdirectory {sub.name}/ in the bundle")

    # --- content-addressed root over every raw file ---
    root = doc.get("root")
    if not (isinstance(root, str) and HEX64.match(root)):
        errors.append("root must be a 64-hex sha256")
    else:
        lines = []
        for name in sorted(actual - {"modeq.json"}):
            lines.append(f"{name}\n{sha256_file(bundle_dir / name)}\n")
        recomputed = hashlib.sha256("".join(lines).encode()).hexdigest()
        if recomputed != root:
            errors.append(
                f"content-addressed root does not recompute (recorded {root}, actual {recomputed})"
            )

    return errors


def g0_state(ledger_path: pathlib.Path) -> str:
    ledger = json.loads(ledger_path.read_text())
    return str(next(g for g in ledger["gates"] if g["id"] == "G0")["state"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dir",
        type=pathlib.Path,
        default=DEFAULT_DIR,
        help="Mode-Q bundle directory (default docs/evidence/G0/mode-q)",
    )
    parser.add_argument(
        "--ledger",
        type=pathlib.Path,
        default=None,
        help="also enforce two-directional consistency with this gates.json",
    )
    args = parser.parse_args()

    if not args.dir.is_dir():
        status = "ABSENT"
        errors: list[str] = []
    else:
        errors = validate_bundle(args.dir)
        status = "VALID" if not errors else "INVALID"

    print(f"MODEQ: {status}")
    for e in errors:
        print(f"  - {e}")

    if status == "INVALID":
        return 1

    if args.ledger is not None:
        try:
            state = g0_state(args.ledger)
        except Exception as error:
            print(f"MODEQ: ledger unreadable: {error}")
            return 1
        g0_open = state in ("OPEN_RED", "OPEN")
        if status == "VALID" and g0_open:
            print(
                f"MODEQ: bundle is VALID but the ledger still holds G0 {state} — reconcile the ledger"
            )
            return 1
        if status == "ABSENT" and not g0_open:
            print(f"MODEQ: ledger closes G0 ({state}) without Mode-Q evidence — refused")
            return 1
        print(f"MODEQ: consistent with ledger (G0={state})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
