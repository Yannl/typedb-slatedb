#!/usr/bin/env python3
"""Compare TypeDB's real Bazel target graph against this repo's catalogue and
cargo target set — the "is cargo a parallel reality?" check.

Only the Bazel LOADING phase is used (`bazel query`), because in the sealed
build environment the ANALYSIS phase cannot run at all: aspect_bazel_lib
registers `bats_toolchains`, fetched from
https://github.com/bats-core/bats-core/archive/v1.10.0.tar.gz, which the agent
egress policy denies with 403. A registered toolchain must be loaded to
resolve toolchains for ANY configured target, so `bazel cquery`, `bazel build`
and `bazel test` all abort before doing any work. `bazel query` needs no
toolchains and enumerates the graph completely.

Usage:
  tools/bazel/bazel_parity.py --bazel /path/to/bazel [--out docs/evidence/G0/bazel-parity]
"""
import argparse, collections, json, os, pathlib, re, subprocess, sys

REPO = pathlib.Path(__file__).resolve().parents[2]
TB = REPO / "sources" / "typedb"
CATALOG = REPO / "docs" / "evidence" / "G1" / "upstream-test-catalog.json"
# untracked symlink shim (bazel-typedb/external/typedb_behaviour* ->
# sources/typedb-behaviour) that lets cargo find the .feature corpus at the
# path Bazel runfiles would use. It is ours, not upstream: exclude it.
SHIM = "//bazel-typedb/"
TESTFN = re.compile(r"#\[(?:tokio::)?test[^\]]*\]\s*(?:async\s+)?fn\s+(\w+)", re.S)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def bazel_query(bazel, expr, out_fmt=None):
    cmd = [bazel, "--output_user_root=" + os.environ.get("BAZEL_ROOT", "/home/user/.bazel-out"),
           "query", expr, "--disk_cache="]
    if out_fmt:
        cmd.append("--output=" + out_fmt)
    r = run(cmd, cwd=TB)
    if r.returncode != 0:
        sys.exit(f"bazel query failed ({r.returncode}):\n{r.stderr[-2000:]}")
    return r.stdout


def norm(label):
    """Bazel prints the root package as //:x; the catalogue spells it //.:x."""
    return "//:" + label[4:] if label.startswith("//.:") else label


# Divergences between the Bazel test graph and the cargo test graph that are
# KNOWN, reviewed and recorded. The gate fails on anything not in this list,
# so a NEW divergence cannot appear silently — the same discipline the fork's
# EXCLUSIONS list carries. Removing an entry here is how it gets fixed.
KNOWN_CATALOGUE_ONLY = {
    "//tool/test:simulate-crash":
        "catalogue entry with no referent: //tool/test:all contains only "
        "//tool/test:checkstyle at the pinned revision. Real catalogue defect, "
        "recorded rather than deleted, because deleting a plan row silently is "
        "how a denominator shrinks.",
}
KNOWN_BAZEL_ONLY_NON_RUST_TEST = {
    "//:Release_validate_deps_gen":
        "release dependency-manifest generator; not a semantic test of the "
        "product and not in the qualification denominator.",
    "//:release-validate-deps":
        "release dependency-manifest check; same rationale.",
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bazel", default="/home/user/.bazel-bin/bazel")
    ap.add_argument("--out", type=pathlib.Path,
                    default=REPO / "docs/evidence/G0/bazel-parity")
    args = ap.parse_args()

    # --- 1. the real Bazel test-target graph -------------------------------
    kinds = {}
    for line in bazel_query(args.bazel, 'kind(".*_test rule", //...)', "label_kind").splitlines():
        if line.strip():
            kind, _rule, label = line.split(None, 2)
            kinds[label.strip()] = kind
    upstream = {l: k for l, k in kinds.items() if not l.startswith(SHIM)}

    # --- 2. catalogue labels vs that graph ---------------------------------
    cat = json.loads(CATALOG.read_text())
    cl = {norm(t["upstream_label"]): t for t in cat["targets"]
          if t["upstream_label"] and t["upstream_label"].startswith("//")}
    cat_only = sorted(set(cl) - set(upstream))
    bazel_only = sorted(set(upstream) - set(cl))

    # --- 3. bazel rust_test -> cargo target, matched by SOURCE PATH --------
    import xml.etree.ElementTree as ET
    root = ET.fromstring(bazel_query(args.bazel, f"kind(rust_test, //... - {SHIM}...)", "xml"))
    meta = json.loads(run(["cargo", "metadata", "--no-deps", "--format-version", "1",
                           "--offline"], cwd=TB).stdout)
    all_cargo, by_src, by_dir = [], {}, collections.defaultdict(list)
    for p in meta["packages"]:
        d = os.path.dirname(os.path.realpath(p["manifest_path"]))
        for t in p["targets"]:
            rec = {"pkg": p["name"], "target": t["name"], "kinds": t["kind"],
                   "src": t["src_path"], "test": t.get("test")}
            all_cargo.append(rec)
            # a src_path can back two cargo targets (a helper lib crate and the
            # tests/*.rs target cargo auto-discovers for it); keep the first for
            # lookup but never let the dict stand in for the full target list
            by_src.setdefault(os.path.realpath(t["src_path"]), rec)
            by_dir[d].append(rec)

    crosswalk = []
    for rule in root.findall("rule"):
        label = rule.get("name")
        attrs = {e.get("name"): ([c.get("value") for c in e] if e.tag == "list"
                                 else (e.get("value") or e.get("label")))
                 for e in rule}
        row = {"bazel_target": label, "cargo": None, "note": ""}
        if attrs.get("srcs"):                      # integration test
            pkg = label[2:].split(":")[0]
            hits = [by_src[p] for p in
                    (os.path.realpath(str(TB / pkg / s.split(":", 1)[1])) for s in attrs["srcs"])
                    if p in by_src]
            if hits:
                row["cargo"] = f'{hits[0]["pkg"]}:{"/".join(hits[0]["kinds"])}:{hits[0]["target"]}'
            else:
                row["note"] = "no cargo target with a matching src_path"
        elif attrs.get("crate"):                   # lib unit tests
            d = os.path.realpath(str(TB / attrs["crate"][2:].split(":")[0]))
            libs = [c for c in by_dir.get(d, []) if "lib" in c["kinds"]]
            if libs:
                row["cargo"] = f'{libs[0]["pkg"]}:lib:{libs[0]["target"]}'
            else:
                row["note"] = f"no cargo package at {d}"
        crosswalk.append(row)

    matched = [r for r in crosswalk if r["cargo"]]
    cargo_only = sorted({f'{c["pkg"]}:{"/".join(c["kinds"])}:{c["target"]}'
                         for c in all_cargo
                         if c["test"] and set(c["kinds"]) & {"lib", "test"}}
                        - {r["cargo"] for r in matched})

    # --- 4. catalogue CARGO entries vs live cargo metadata -----------------
    cat_cargo = {(t["cargo_package"], t["cargo_target"])
                 for t in cat["targets"] if t["origin"] == "CARGO"}
    live_cargo = {(c["pkg"], c["target"]) for c in all_cargo
                  if set(c["kinds"]) & {"lib", "test", "bench", "bin"}}

    # --- 5. did the fork DROP any upstream test? ---------------------------
    changed = [f for f in run(["git", "-C", str(TB), "diff", "--name-only", "HEAD"]).stdout.split()
               if f.endswith(".rs")]
    untracked = [f for f in run(["git", "-C", str(TB), "ls-files", "--others",
                                 "--exclude-standard"]).stdout.split() if f.endswith(".rs")]
    dropped, added = {}, 0
    for f in changed:
        pinned = set(TESTFN.findall(run(["git", "-C", str(TB), "show", f"HEAD:{f}"]).stdout))
        work = set(TESTFN.findall((TB / f).read_text()))
        added += len(work - pinned)
        if pinned - work:
            dropped[f] = sorted(pinned - work)
    for f in untracked:
        added += len(set(TESTFN.findall((TB / f).read_text())))

    report = {
        "bazel_test_targets_upstream": len(upstream),
        "by_kind": dict(collections.Counter(upstream.values())),
        "catalogue_only_labels": cat_only,
        "bazel_only_labels_non_rust_test": [l for l in bazel_only if upstream[l] != "rust_test"],
        "bazel_only_rust_test_count": sum(1 for l in bazel_only if upstream[l] == "rust_test"),
        "rust_test_total": len(crosswalk),
        "rust_test_matched_to_cargo": len(matched),
        "rust_test_unmatched": [r["bazel_target"] for r in crosswalk if not r["cargo"]],
        "crosswalk_is_bijective": len({r["cargo"] for r in matched}) == len(matched),
        "cargo_only_targets": cargo_only,
        "catalogue_cargo_equals_live_cargo": cat_cargo == live_cargo,
        "upstream_tests_dropped_by_fork": dropped,
        "tests_added_by_fork": added,
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "parity-recomputed.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))

    # --- the gate ---------------------------------------------------------
    # Reporting these numbers is not the same as enforcing them. Until this
    # existed the tool always exited 0, so a regression in test-graph fidelity
    # would have printed and been ignored — the exact "a number that looks
    # like evidence but enforces nothing" failure this audit round is about.
    failures = []
    if report["rust_test_unmatched"]:
        failures.append(
            f"{len(report['rust_test_unmatched'])} Bazel rust_test target(s) have no "
            f"cargo counterpart: {report['rust_test_unmatched'][:5]}. Something the "
            "upstream build tests is not reachable from cargo, so the cargo runs "
            "are no longer a superset.")
    if not report["crosswalk_is_bijective"]:
        failures.append("the Bazel->cargo crosswalk is not bijective: two Bazel "
                        "targets map onto one cargo target, so per-target outcomes "
                        "cannot be attributed.")
    if not report["catalogue_cargo_equals_live_cargo"]:
        failures.append("the catalogue's cargo target set no longer equals the live "
                        "`cargo metadata` set: the denominator has drifted from the "
                        "workspace.")
    if report["upstream_tests_dropped_by_fork"]:
        failures.append(
            f"the fork DROPPED upstream #[test] functions: "
            f"{list(report['upstream_tests_dropped_by_fork'])[:5]}. Removing an "
            "upstream test is how a fork quietly stops being comparable.")
    new_cat_only = [l for l in report["catalogue_only_labels"]
                    if l not in KNOWN_CATALOGUE_ONLY]
    if new_cat_only:
        failures.append(f"new catalogue label(s) with no Bazel referent: {new_cat_only}")
    new_bazel_only = [l for l in report["bazel_only_labels_non_rust_test"]
                      if l not in KNOWN_BAZEL_ONLY_NON_RUST_TEST]
    if new_bazel_only:
        failures.append(f"new Bazel test target(s) absent from the catalogue: "
                        f"{new_bazel_only}")

    for label, reason in sorted(KNOWN_CATALOGUE_ONLY.items()):
        print(f"recorded divergence  {label}\n    {reason}")
    for label, reason in sorted(KNOWN_BAZEL_ONLY_NON_RUST_TEST.items()):
        print(f"recorded divergence  {label}\n    {reason}")

    if failures:
        print("BAZEL PARITY GATE: FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"BAZEL PARITY GATE: PASS — {report['rust_test_total']} Bazel rust_test "
          f"targets all map 1:1 onto cargo targets; the catalogue's cargo set equals "
          f"the live workspace; 0 upstream tests dropped by the fork. STRUCTURAL "
          f"equivalence only: no test was EXECUTED under Bazel, so identical "
          f"outcomes remain unproven.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
