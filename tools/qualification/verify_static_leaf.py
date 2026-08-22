#!/usr/bin/env python3
"""Re-derive a STATIC_CHECK leaf bundle from its own bytes and the pinned tree.

WHAT INDEPENDENCE MEANS HERE
----------------------------
`verify_leaf.py` does not re-run the tests; it re-parses their output. This
verifier goes further, because a static check is cheap enough to REDO:

  file set     re-resolved from the rule in the pinned BUILD file, through
               `run_static.py`'s own selection. Shared deliberately — a second
               copy of Bazel's glob semantics is a copy that drifts, and the
               producer cannot benefit from sharing it: it cannot name a file
               the rule does not resolve, or omit one it does.

  file bytes   every FILE digest in the log is recomputed against
               sources/typedb. This is the binding that makes the verdict mean
               something: "PASS over these files at these digests" is
               checkable, "PASS, 4 files" is not.

  the verdict  RE-DERIVED, not read. The tab and header predicates are
               reimplemented in this file on purpose (`_has_tab`,
               `_header_mismatch`) — that duplication IS the independence, and
               it is the only duplication here. rustfmt is simply re-run under
               the toolchain the log names.

So a producer that reports PASS on a file with a tab in it, or that quietly
drops a failing file from its list, is caught by this verifier and not by
politeness.

REFUSALS
--------
Everything is an anomaly, and a bundle with any anomaly contributes nothing to
coverage. There is no "warning" tier: this is the plane that decides whether
141 plan rows carry an outcome.

usage:
  python3 tools/qualification/verify_static_leaf.py docs/evidence/G3/leaf/static-u0-1
"""

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "tools" / "catalog"))

import leaf_common as lc  # noqa: E402
import run_static  # noqa: E402

TB = REPO / "sources" / "typedb"
RESULTS_NAME = "static-leaf-results.json"
SCHEMA = "typedb-r2-static-leaf-evidence-v1"

LINE_RE = re.compile(r"^(STATIC-CHECK|RULE|TOOLCHAIN|FILE|FAILURE|RESULT) +(.*)$")
RESULT_RE = re.compile(r"^(PASS|FAIL|ERROR) files=(\d+) failures=(\d+)$")
FILE_RE = re.compile(r"^([0-9a-f]{64}) (.+)$")

# checkstyle's `multiLines = [1, 2]`: header lines 1 and 2 may repeat.
MULTILINES = {1, 2}


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _has_tab(path: pathlib.Path) -> bool:
    """FileTabCharacter, reimplemented. The duplication is the point."""
    return b"\t" in path.read_bytes()


def _header_mismatch(path: pathlib.Path, regexes) -> bool:
    """RegexpHeader with multiLines {1,2}, reimplemented. Ditto."""
    lines = path.read_text(errors="replace").splitlines()
    at = 0
    for index, regex in enumerate(regexes, start=1):
        if index in MULTILINES:
            while at < len(lines) and regex.search(lines[at]):
                at += 1
            continue
        if at >= len(lines) or not regex.search(lines[at]):
            return True
        at += 1
    return False


def parse_log(text: str, anomalies: list[str], where: str):
    """The log's grammar, strictly. An unrecognised line is an anomaly."""
    rec: dict[str, str | None] = {"target_id": None, "rule": None, "toolchain": None}
    files: list[tuple[str, str]] = []
    failures: list[str] = []
    result = None
    result_line = None
    for n, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        m = LINE_RE.match(raw)
        if not m:
            anomalies.append(f"{where}: line {n} is not static-check log grammar: {raw[:80]!r}")
            continue
        key, rest = m.group(1), m.group(2).strip()
        if key == "STATIC-CHECK":
            rec["target_id"] = rest
        elif key == "RULE":
            rec["rule"] = rest
        elif key == "TOOLCHAIN":
            rec["toolchain"] = rest
        elif key == "FILE":
            fm = FILE_RE.match(rest)
            if not fm:
                anomalies.append(f"{where}: line {n} is not `FILE <sha256> <path>`")
            else:
                files.append((fm.group(1), fm.group(2)))
        elif key == "FAILURE":
            failures.append(rest)
        else:
            rm = RESULT_RE.match(rest)
            if not rm:
                anomalies.append(f"{where}: line {n} is not `RESULT <verdict> files=N failures=M`")
            else:
                result, result_line = rm, n
    return rec, files, failures, result, result_line


def rederive(
    target_id: str,
    rule: str,
    files: list[str],
    anomalies: list[str],
    where: str,
    tb: pathlib.Path = TB,
) -> str:
    """PASS or FAIL, computed here from the pinned tree — never read."""
    if rule == "rustfmt":
        if not files:
            return "FAIL"
        # R8-P2-01: the SAME resolver as the producer (one definition of "which
        # rustfmt"), while the verdict below is still re-derived independently.
        # Sharing the resolver is not sharing the answer: the verifier runs the
        # binary itself and compares its own exit status.
        argv, _identity = run_static.resolve_rustfmt()
        proc = subprocess.run(
            argv
            + [
                "--check",
                "--config-path",
                str(tb / "rustfmt.toml"),
                *[str(tb / f) for f in files],
            ],
            capture_output=True,
            text=True,
            cwd=tb,
        )
        return "PASS" if proc.returncode == 0 else "FAIL"

    _, build_rel, rule_name = target_id.split(":", 2)
    package_dir = (tb / build_rel).parent
    block = run_static.parse_rule_block((tb / build_rel).read_text(), "checkstyle_test", rule_name)
    if not block:
        anomalies.append(f"{where}: {rule_name} is not in {build_rel} at the pinned revision")
        return "ERROR"
    attrs = run_static.eval_rule_attrs(block, package_dir)
    regexes = run_static.load_header_regexes(attrs.get("license_type", "mpl-header"))
    for rel in files:
        path = tb / rel
        if _has_tab(path) or _header_mismatch(path, regexes):
            return "FAIL"
    return "PASS"


def verify(bundle_dir, repo=REPO):
    """(anomalies, facts) for one static leaf bundle."""
    repo = pathlib.Path(repo)
    # Derived from `repo`, not the module constant: the negative-control
    # harness verifies a bundle against a SHADOW tree, which is the only way
    # to exercise "the producer claimed PASS on a file that fails the check".
    tb = repo / "sources" / "typedb"
    bundle = pathlib.Path(bundle_dir)
    bundle = bundle if bundle.is_absolute() else repo / bundle
    A: list[str] = []
    facts: dict[str, object] = {"bundle": str(bundle)}

    results_path = bundle / RESULTS_NAME
    if not results_path.is_file():
        return [f"{bundle}: no {RESULTS_NAME} — not a static leaf bundle"], facts
    body = json.loads(results_path.read_text())
    facts["profile"] = body.get("profile")
    facts["toolchain_id"] = body.get("toolchain_id")
    if body.get("schema") != SCHEMA:
        A.append(f"schema is {body.get('schema')!r}, not {SCHEMA!r}")

    # ---- the tree this bundle DESCRIBES vs the tree it is being read against.
    #
    # The static checks run over `sources/typedb`, which is either the pristine
    # upstream checkout or the fork staged into it. A bundle produced against
    # the staged tree, re-read against the pristine one, reports every file as
    # "has changed since the check read it" — 141 anomalies that look like a
    # forged bundle and are nothing of the kind, and which a coverage run then
    # turns into "no evidence exists", silently removing 141 rows from a
    # published number. That happened, and it is why this check is FIRST and
    # says what to do.
    #
    # It is not a way to pass with the wrong tree: the anomaly still refuses the
    # bundle. It names the remedy instead of the symptom.
    declared_state = ((body.get("executed_tree") or {}).get("tree_state")) or "UNKNOWN"
    if repo == REPO:
        sys.path.insert(0, str(REPO / "tools" / "qualification"))
        from leaf_common import stage_state  # noqa: E402

        actual_state, actual_line = stage_state()
        staged_now = actual_state == "STAGED"
        staged_then = declared_state.startswith("FORK_STAGED")
        facts["tree_state_declared"] = declared_state
        facts["tree_state_now"] = actual_state
        if staged_then != staged_now:
            A.append(
                f"this bundle was produced against a {declared_state} tree and is being verified "
                f"against a {actual_state} one ({actual_line}). Every file-content check below "
                f"would fail for that reason alone, which is not a statement about the bundle. "
                + (
                    "Run `python3 tools/fork/stage.py` first."
                    if staged_then
                    else "Run `python3 tools/fork/stage.py --restore` first."
                )
            )
            return A, facts

    # ---- seal: the manifest must account for every file, and the root must
    # recompute from the bytes on disk
    man_path = bundle / "bundle-manifest.json"
    if not man_path.is_file():
        A.append("no bundle-manifest.json — an unsealed directory is a run in progress")
    else:
        man = json.loads(man_path.read_text())
        named = set(man.get("files") or {})
        present = {
            str(p.relative_to(repo))
            for p in bundle.iterdir()
            if p.is_file() and p.name != "COMPLETE"
        }
        present.discard(str(man_path.relative_to(repo)))
        if named != present:
            missing = sorted(named - present)
            extra = sorted(present - named)
            A.append(f"manifest/bundle mismatch: missing {missing[:3]}, unaccounted {extra[:3]}")
        for rel, digest in sorted((man.get("files") or {}).items()):
            path = repo / rel
            if not path.is_file():
                A.append(f"manifest names {rel}, which is absent")
            elif sha256_file(path) != digest:
                A.append(f"{rel} does not hash to the digest the manifest records")
        root = hashlib.sha256(
            "".join(f"{k}\n{v}\n" for k, v in sorted((man.get("files") or {}).items())).encode()
        ).hexdigest()
        facts["bundle_root"] = root
        if root != man.get("bundle_root"):
            A.append("bundle_root does not recompute from the manifest's own file list")
        marker = bundle / "COMPLETE"
        if not marker.is_file():
            A.append("no COMPLETE marker — the bundle was never sealed")
        elif marker.read_text().strip() != f"COMPLETE {root}":
            A.append("the COMPLETE marker does not bind the recomputed root")

    # ---- plan and catalogue agreement
    plan = json.loads(lc.PLAN.read_text())
    catalog = json.loads(lc.CATALOG.read_text())
    if body.get("profile") not in plan["profiles"]:
        A.append(f"profile {body.get('profile')!r} is not a plan profile")
    if body.get("toolchain_id") is None:
        A.append("toolchain_id is null — a run on a compiler the plan does not name")
    if body.get("plan_root") != plan.get("plan_root"):
        A.append("plan_root does not match the current plan")
    cat_leaves: dict[str, set[str]] = {}
    for leaf in catalog["leaf_cases"]:
        if leaf["kind"] == "STATIC_CHECK":
            cat_leaves.setdefault(leaf["target_id"], set()).add(leaf["leaf_case_id"])

    # ---- per target: re-derive everything
    published = [t for t in body.get("targets") or [] if t.get("publishable")]
    facts["targets"] = len(body.get("targets") or [])
    facts["published_targets"] = len(published)
    leaves_by_target: dict[str, list[dict]] = {}
    for leaf in body.get("leaves") or []:
        leaves_by_target.setdefault(leaf["catalog_target_id"], []).append(leaf)

    for row in published:
        tid = row["runner_row_id"]
        where = f"{tid}"
        log_rel = row.get("raw_log")
        log_path = repo / log_rel if log_rel else None
        if log_path is None or not log_path.is_file():
            A.append(f"{where}: archived log {log_rel} is absent")
            continue
        if sha256_file(log_path) != row.get("log_sha256"):
            A.append(f"{where}: the log does not hash to the digest the row records")
            continue
        text = log_path.read_text()
        rec, files, failures, result, result_line = parse_log(text, A, where)
        if rec["target_id"] != tid:
            A.append(f"{where}: the log names target {rec['target_id']!r}")
            continue
        if result is None:
            A.append(f"{where}: the log carries no RESULT line — it is truncated")
            continue

        # every recorded input must BE the pinned tree's byte
        recorded = [rel for _d, rel in files]
        for digest, rel in files:
            path = tb / rel
            if not path.is_file():
                A.append(f"{where}: the log records {rel}, which is not in the pinned tree")
            elif sha256_file(path) != digest:
                A.append(f"{where}: {rel} has changed since the check read it")

        # the file SET must be what the rule resolves to
        if rec["rule"] == "rustfmt":
            _, build_rel, _ = tid.split(":", 2)
            resolved = sorted(
                p.resolve().relative_to(tb.resolve()).as_posix()
                for p in run_static.package_rs_files((tb / build_rel).parent)
            )
        else:
            files_field = run_static.run_checkstyle(tid).get("files")
            resolved = sorted(files_field if isinstance(files_field, list) else [])
        if sorted(recorded) != resolved:
            A.append(
                f"{where}: the log's file set is not what the rule resolves "
                f"({len(recorded)} recorded, {len(resolved)} resolved)"
            )
            continue

        verdict = rederive(tid, rec["rule"] or "", recorded, A, where, tb=tb)
        if result.group(1) != verdict:
            A.append(f"{where}: the log says {result.group(1)}, re-derivation says {verdict}")
        if int(result.group(2)) != len(recorded):
            A.append(f"{where}: RESULT files={result.group(2)} but the log lists {len(recorded)}")
        if int(result.group(3)) != len(failures):
            A.append(
                f"{where}: RESULT failures={result.group(3)} but the log lists {len(failures)}"
            )
        if (verdict == "PASS") != (not failures):
            A.append(f"{where}: the verdict and the FAILURE lines disagree")

        # leaves
        expected = cat_leaves.get(tid, set())
        got = {leaf["leaf_case_id"] for leaf in leaves_by_target.get(tid, [])}
        if got != expected:
            A.append(f"{where}: published leaves {sorted(got)} != catalogue {sorted(expected)}")
        for leaf in leaves_by_target.get(tid, []):
            want = "PASSED" if verdict == "PASS" else "FAILED"
            if leaf.get("outcome") != want:
                A.append(
                    f"{where}: leaf outcome {leaf.get('outcome')} but re-derivation says {want}"
                )
            if leaf.get("log_line") != result_line:
                A.append(f"{where}: leaf log_line does not point at the RESULT line")

    # a leaf whose target was refused must not be published
    refused = {t["runner_row_id"] for t in body.get("targets") or [] if not t.get("publishable")}
    for tid in refused & set(leaves_by_target):
        A.append(f"{tid}: refused target published {len(leaves_by_target[tid])} leaf/leaves")

    facts["leaves"] = len(body.get("leaves") or [])
    return A, facts


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("bundle", nargs="+")
    ap.add_argument(
        "--repo",
        default=str(REPO),
        help="root a repo-relative raw_log and the pinned tree resolve "
        "against; only the negative-control harness passes this",
    )
    args = ap.parse_args()
    bad = 0
    for b in args.bundle:
        anomalies, facts = verify(b, repo=args.repo)
        print(json.dumps({"bundle": b, "facts": facts, "anomalies": anomalies}, indent=1))
        print(
            f"STATIC LEAF VERIFY {b}: {len(anomalies)} anomaly(ies), "
            f"{facts.get('published_targets')} published target(s), {facts.get('leaves')} leaves",
            file=sys.stderr,
        )
        bad += 1 if anomalies else 0
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
