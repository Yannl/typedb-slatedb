#!/usr/bin/env python3
"""Run the catalogue's 141 STATIC_CHECK cases in the cargo lane (BT-P2/SI-G0-4).

Faithful reimplementation of the two Bazel static rules at the pin:

- checkstyle_test (typedb_dependencies//tool/checkstyle): Checker-level modules
  only for non-Java sources - FileTabCharacter (no tab on any line) and
  RegexpHeader against checkstyle-file-<license_type>.txt with
  multiLines = [1, 2] (header lines 1 and 2 may repeat zero or more times).
  TreeWalker modules apply only to .java files; the tree has none.
- rustfmt_test (rules_rust): rustfmt --check over the referenced targets'
  sources with the workspace rustfmt.toml, using the pinned nightly toolchain.
  The file set of a package's rustfmt_test targets is the package's .rs files
  (Bazel globs stop at package boundaries).
"""

import argparse, json, pathlib, re, subprocess, sys, fnmatch

REPO = pathlib.Path(__file__).resolve().parents[2]
TYPEDB = REPO / "sources" / "typedb"
DEPS = REPO / "sources" / "typedb-dependencies"
CATALOG = REPO / "docs" / "evidence" / "G1" / "upstream-test-catalog.json"
RUSTFMT_TOOLCHAIN = "nightly-2026-04-15"

HEADER_FILES = {
    "mpl-header": DEPS / "tool/checkstyle/config/checkstyle-file-mpl-header.txt",
    "mpl-fulltext": DEPS / "tool/checkstyle/config/checkstyle-file-mpl-fulltext.txt",
    "apache-header": DEPS / "tool/checkstyle/config/checkstyle-file-apache-header.txt",
    "apache-fulltext": DEPS / "tool/checkstyle/config/checkstyle-file-apache-fulltext.txt",
    "commercial-header": DEPS / "tool/checkstyle/config/checkstyle-file-commercial-header.txt",
    "commercial-fulltext": DEPS / "tool/checkstyle/config/checkstyle-file-commercial-fulltext.txt",
}
MULTILINES = {1, 2}  # from templates/checkstyle.xml: <property name="multiLines" value="1, 2"/>


def is_package_boundary(directory: pathlib.Path) -> bool:
    return (directory / "BUILD").exists() or (directory / "BUILD.bazel").exists()


def bazel_glob(package_dir: pathlib.Path, patterns, exclude=()):
    """Bazel glob: relative patterns, files only, stops at subpackage boundaries."""
    results = set()
    for pattern in patterns:
        for path in package_dir.glob(pattern):
            if not path.is_file():
                continue
            rel = path.relative_to(package_dir)
            # prune paths that cross a subpackage boundary
            crossed = False
            probe = package_dir
            for part in rel.parts[:-1]:
                probe = probe / part
                if is_package_boundary(probe):
                    crossed = True
                    break
            if crossed:
                continue
            results.add(str(rel))
    for pattern in exclude:
        results = {r for r in results if not fnmatch.fnmatch(r, pattern) and r != pattern}
    return sorted(results)


def parse_rule_block(build_text: str, rule: str, name: str) -> str:
    # simpler: find each rule invocation by balancing parens
    for m in re.finditer(rule + r"\(", build_text):
        depth, i = 1, m.end()
        while depth and i < len(build_text):
            if build_text[i] == "(":
                depth += 1
            elif build_text[i] == ")":
                depth -= 1
            i += 1
        block = build_text[m.start():i]
        if re.search(r'name\s*=\s*"' + re.escape(name) + r'"', block):
            return block
    return ""


def eval_rule_attrs(block: str, package_dir: pathlib.Path):
    """Evaluate the rule call in a tiny Starlark-ish namespace to get its attrs."""
    inner = block[block.index("(") + 1 : block.rindex(")")]
    attrs = {}

    # Bazel applies exclude within the glob call itself
    def glob(patterns, exclude=(), **_kwargs):
        return bazel_glob(package_dir, patterns, exclude=exclude)

    namespace = {"glob": glob, "True": True, "False": False}

    def record(**kwargs):
        attrs.update(kwargs)

    try:
        eval(f"record({inner})", {"__builtins__": {}}, {**namespace, "record": record})
    except Exception as exc:  # unparseable attr (e.g. select()) -> record for report
        attrs["__parse_error__"] = f"{type(exc).__name__}: {exc}"
    return attrs


def load_header_regexes(license_type: str):
    lines = HEADER_FILES[license_type].read_text().splitlines()
    return [re.compile(l) for l in lines]


def check_regexp_header(path: pathlib.Path, header_regexes) -> str | None:
    try:
        file_lines = path.read_text(errors="replace").splitlines()
    except OSError as exc:
        return f"unreadable: {exc}"
    fi = 0
    for hi, regex in enumerate(header_regexes, start=1):
        if hi in MULTILINES:
            while fi < len(file_lines) and regex.search(file_lines[fi]):
                fi += 1
            continue
        if fi >= len(file_lines) or not regex.search(file_lines[fi]):
            got = file_lines[fi] if fi < len(file_lines) else "<eof>"
            return f"header line {hi} mismatch at file line {fi + 1}: {got[:80]!r}"
        fi += 1
    return None


def check_tabs(path: pathlib.Path) -> str | None:
    try:
        content = path.read_bytes()
    except OSError as exc:
        return f"unreadable: {exc}"
    if b"\t" in content:
        line = content.split(b"\t")[0].count(b"\n") + 1
        return f"tab character (first at line {line})"
    return None


def run_checkstyle(target_id: str):
    # target_id: static:<pkg-path>/BUILD:<rule-name> ; pkg-path may be empty for root
    _, build_rel, rule_name = target_id.split(":", 2)
    package_dir = (TYPEDB / build_rel).parent
    build_text = (TYPEDB / build_rel).read_text()
    block = parse_rule_block(build_text, "checkstyle_test", rule_name)
    if not block:
        return {"target_id": target_id, "status": "ERROR", "detail": "rule not found in BUILD"}
    attrs = eval_rule_attrs(block, package_dir)
    if "__parse_error__" in attrs:
        return {"target_id": target_id, "status": "ERROR", "detail": attrs["__parse_error__"]}
    include = attrs.get("include", [])
    if isinstance(include, str):
        include = [include]
    # attrs may combine glob(...) results (already lists) with literal lists
    files = sorted(set(include if all(isinstance(i, str) for i in include) else sum(include, [])))
    exclude = attrs.get("exclude", [])
    if exclude:
        excluded = set(exclude)
        files = [f for f in files if f not in excluded and not any(fnmatch.fnmatch(f, p) for p in exclude)]
    header_regexes = load_header_regexes(attrs.get("license_type", "mpl-header"))
    failures = []
    checked = 0
    for rel in files:
        if pathlib.Path(rel).parts and pathlib.Path(rel).parts[0] in NON_SOURCE_DIRS:
            continue
        path = package_dir / rel
        if not path.is_file():
            continue
        checked += 1
        tab_issue = check_tabs(path)
        # FileTabCharacter applies to all checked files
        if tab_issue:
            failures.append(f"{rel}: {tab_issue}")
        header_issue = check_regexp_header(path, header_regexes)
        if header_issue:
            failures.append(f"{rel}: {header_issue}")
    return {
        "target_id": target_id,
        "status": "PASS" if not failures else "FAIL",
        "files_checked": checked,
        "failures": failures[:20],
    }


NON_SOURCE_DIRS = {"target", "bazel-bin", "bazel-out", "bazel-testlogs", "bazel-typedb", ".git"}


def package_rs_files(package_dir: pathlib.Path):
    files = []
    for path in package_dir.rglob("*.rs"):
        rel = path.relative_to(package_dir)
        if rel.parts and rel.parts[0] in NON_SOURCE_DIRS:
            continue
        probe = package_dir
        crossed = False
        for part in rel.parts[:-1]:
            probe = probe / part
            if is_package_boundary(probe):
                crossed = True
                break
        if not crossed:
            files.append(path)
    return sorted(files)


def run_rustfmt_batch(targets):
    """Run rustfmt --check once per package; map verdicts to targets."""
    results = []
    for target_id in targets:
        _, build_rel, rule_name = target_id.split(":", 2)
        package_dir = (TYPEDB / build_rel).parent
        files = package_rs_files(package_dir)
        if not files:
            results.append({"target_id": target_id, "status": "PASS", "files_checked": 0, "failures": []})
            continue
        cmd = [
            str(pathlib.Path.home() / ".cargo/bin/rustfmt"),
            f"+{RUSTFMT_TOOLCHAIN}",
            "--check",
            "--config-path",
            str(TYPEDB / "rustfmt.toml"),
        ] + [str(f) for f in files]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=TYPEDB)
        if proc.returncode == 0:
            results.append({"target_id": target_id, "status": "PASS", "files_checked": len(files), "failures": []})
        else:
            bad = sorted({l.split(" at line")[0].replace("Diff in ", "") for l in proc.stdout.splitlines() if l.startswith("Diff in ")})
            detail = bad or [proc.stderr.strip()[:200]]
            results.append({
                "target_id": target_id,
                "status": "FAIL",
                "files_checked": len(files),
                "failures": [str(pathlib.Path(b).relative_to(TYPEDB)) if b.startswith(str(TYPEDB)) else b for b in detail][:20],
            })
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    catalog = json.loads(CATALOG.read_text())
    static_targets = sorted({l["target_id"] for l in catalog["leaf_cases"] if l["kind"] == "STATIC_CHECK"})
    checkstyle_targets = [t for t in static_targets if t.rsplit(":", 1)[-1].startswith("checkstyle")]
    rustfmt_targets = [t for t in static_targets if t.rsplit(":", 1)[-1].startswith("rustfmt")]
    other = [t for t in static_targets if t not in checkstyle_targets and t not in rustfmt_targets]

    results = []
    for t in checkstyle_targets:
        results.append(run_checkstyle(t))
        sys.stdout.write(f"{results[-1]['status']:5} {t}\n")
    results.extend(run_rustfmt_batch(rustfmt_targets))
    for r in results[len(checkstyle_targets):]:
        sys.stdout.write(f"{r['status']:5} {r['target_id']}\n")
    for t in other:
        results.append({"target_id": t, "status": "ERROR", "detail": "unrecognized static rule"})

    summary = {
        "total": len(results),
        "pass": sum(1 for r in results if r["status"] == "PASS"),
        "fail": sum(1 for r in results if r["status"] == "FAIL"),
        "error": sum(1 for r in results if r["status"] == "ERROR"),
        "rustfmt_toolchain": RUSTFMT_TOOLCHAIN,
        "results": results,
    }
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps({k: summary[k] for k in ("total", "pass", "fail", "error")}))

    # ---- terminal verdict (Q-29) -------------------------------------
    # This producer used to write FAIL and ERROR rows and still exit zero: a
    # deliberately-broken rustfmt run archived 78 pass / 63 fail with rc=0,
    # so any CI step invoking it recorded a green static lane over a red one.
    # There is no ledger for static checks - a formatting/checkstyle rule
    # either passes or the lane is red.
    anomalies = [f"{r['target_id']}: {r['status']}"
                 + (f" ({', '.join(r.get('failures', [])[:3])})" if r.get("failures") else "")
                 + (f" ({r['detail']})" if r.get("detail") else "")
                 for r in results if r["status"] != "PASS"]
    if not results:
        anomalies.append("static: the catalogue selected ZERO static targets - "
                         "an empty static lane is never a pass")
    for a in anomalies:
        print(f"ANOMALY: {a}", file=sys.stderr)
    print(f"VERDICT: {'GREEN' if not anomalies else 'RED'} "
          f"({len(anomalies)} anomaly/anomalies)", file=sys.stderr)
    return 1 if anomalies else 0


if __name__ == "__main__":
    sys.exit(main())
