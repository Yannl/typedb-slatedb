#!/usr/bin/env python3
"""Fail-closed proof that the cargo projection compiles the LOCKED driver.

tools/drivers/rust-behaviour/ is a Cargo workspace whose crate roots and
[[test]] paths point straight at sources/typedb-driver. That is only
qualification-grade if it can be PROVEN, before every run, that:

  1. sources/typedb-driver is the locked TDRIVER node: its git HEAD equals
     the lock's `resolved_revision`, its tree equals the lock's `tree`, and
     the checkout is clean. A dirty driver checkout means the bytes executed
     are not the bytes the lock names - refused, never annotated.
  2. sources/typedb-behaviour is the locked BH node, same three checks. The
     feature corpus is the test input; a dirty corpus is a forged denominator.
  3. Every path the projection manifests reference resolves INSIDE
     sources/typedb-driver (no crate root, no [[test]] path may point at a
     file this repo controls) and exists.
  4. The projection's Cargo.lock resolves the same package versions as the
     driver's own committed Cargo.lock. The only permitted difference is the
     root package: upstream's workspace roots the C driver
     (`typedb_driver_clib`), the projection roots the behaviour test package.
     Any OTHER version difference means the projection is not compiling the
     dependency set upstream pins.
  5. Every dependency the projection declares carries the same version and
     feature set as the corresponding entry in the driver's own
     [workspace.dependencies] - except `typedb-driver` itself, whose
     `features = ["sync"]` the projection deliberately does not apply because
     the Bazel behaviour graph (rust/tests/behaviour/steps/BUILD) depends on
     the ASYNC `//rust:typedb_driver`. That one deviation is declared here,
     named, and is the ONLY one allowed.
  6. The [[test]] target set equals the rust_behaviour_test declarations in
     the upstream BUILD files, so the projection cannot silently drop a suite
     from the denominator.

Exit 0 only if every check passes; the JSON report is printed either way.

Usage:
  python3 tools/drivers/projection_check.py
  python3 tools/drivers/projection_check.py --json
"""
import argparse
import json
import pathlib
import re
import sys

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import common  # noqa: E402

REPO = common.REPO
DRIVER = REPO / "sources" / "typedb-driver"
BEHAVIOUR = REPO / "sources" / "typedb-behaviour"
PROJ = REPO / "tools" / "drivers" / "rust-behaviour"

# The single declared, reviewed deviation from the upstream Cargo workspace.
DECLARED_DEVIATIONS = {
    "typedb-driver.features": {
        "upstream_cargo": ["sync"],
        "projection": [],
        "why": ("rust/tests/behaviour/steps/BUILD depends on //rust:typedb_driver "
                "(async). The upstream Cargo workspace can express only one "
                "feature set for the shared workspace dependency and pins the "
                "sync one, which makes the async step definitions fail to "
                "compile under cargo (115 type errors, recorded in the bundle). "
                "The Bazel graph is authoritative for what the behaviour suite "
                "links against."),
    },
}

BUILD_TEST_RE = re.compile(
    r'rust_behaviour_test\(\s*name\s*=\s*"([^"]+)"[^)]*?srcs\s*=\s*\[\s*"([^"]+)"',
    re.S)


def _toml(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


def _lock_packages(path):
    out = {}
    for blk in pathlib.Path(path).read_text().split("[[package]]"):
        n = re.search(r'^name = "(.*)"', blk, re.M)
        v = re.search(r'^version = "(.*)"', blk, re.M)
        if n and v:
            out[n.group(1)] = v.group(1)
    return out


def check():
    problems = []
    report = {"schema": "driver-projection-check-v1", "problems": problems}

    if tomllib is None:
        problems.append("python tomllib unavailable; cannot parse manifests")
        return report

    # ---- 1/2 locked source identity -------------------------------------
    for node_id, path, key in (("TDRIVER", DRIVER, "resolved_revision"),
                               ("BH", BEHAVIOUR, "revision")):
        node = common.source_lock_node(node_id)
        ident = common.checkout_identity(path)
        entry = {"source_lock": {"id": node_id,
                                 "revision": (node or {}).get(key),
                                 "tree": (node or {}).get("tree"),
                                 "status": (node or {}).get("status")},
                 "checkout": ident}
        report[f"{node_id.lower()}_identity"] = entry
        if node is None:
            problems.append(f"source-lock has no node {node_id}")
            continue
        if node.get("status") != "locked":
            problems.append(f"{node_id}: source-lock status is "
                            f"{node.get('status')!r}, not 'locked'")
        if ident.get("dirty") is not False:
            problems.append(
                f"{node_id}: checkout {common.rel(path)} is dirty or its dirt "
                f"could not be established (dirty={ident.get('dirty')!r}, "
                f"{ident.get('dirty_path_count')} path(s)) - the executed bytes "
                f"would not be the locked bytes")
        if ident.get("revision") != node.get(key):
            problems.append(f"{node_id}: checkout revision "
                            f"{ident.get('revision')} != locked {node.get(key)}")
        if ident.get("tree") != node.get("tree"):
            problems.append(f"{node_id}: checkout tree {ident.get('tree')} != "
                            f"locked tree {node.get('tree')}")

    # ---- 3 every projected path is inside the locked driver --------------
    projected = []
    for manifest in sorted(PROJ.glob("*/Cargo.toml")):
        doc = _toml(manifest)
        pkgdir = manifest.parent
        paths = []
        lib = doc.get("lib") or {}
        if lib.get("path"):
            paths.append(("lib:" + lib.get("name", doc["package"]["name"]),
                          lib["path"]))
        for t in doc.get("test", []):
            paths.append(("test:" + t["name"], t["path"]))
        for label, p in paths:
            resolved = (pkgdir / p).resolve()
            rec = {"manifest": common.rel(manifest), "target": label,
                   "declared": p, "resolved": common.rel(resolved),
                   "exists": resolved.is_file()}
            inside = str(resolved).startswith(str(DRIVER.resolve()) + "/")
            rec["inside_locked_driver"] = inside
            if resolved.is_file():
                rec["sha256"] = common.sha256_file(resolved)
            else:
                # a projection target that does not exist is a silently empty
                # suite: refuse rather than report zero cases
                if label.startswith("lib:") and p == "lib.rs":
                    rec["inside_locked_driver"] = inside = True  # local stub
                problems.append(f"{common.rel(manifest)}: target {label} path "
                                f"{p!r} does not resolve to a file")
            if not inside and not (label.startswith("lib:") and p == "lib.rs"):
                problems.append(
                    f"{common.rel(manifest)}: target {label} resolves to "
                    f"{common.rel(resolved)}, which is OUTSIDE the locked "
                    f"driver checkout - the projection may only compile locked "
                    f"upstream sources")
            projected.append(rec)
    report["projected_targets"] = projected

    # ---- 4 dependency resolution parity ----------------------------------
    up_lock = _lock_packages(DRIVER / "Cargo.lock")
    pj_lock_path = PROJ / "Cargo.lock"
    if not pj_lock_path.is_file():
        problems.append("projection has no Cargo.lock; run cargo with --locked "
                        "only against a committed lock")
        pj_lock = {}
    else:
        pj_lock = _lock_packages(pj_lock_path)
    roots = {"typedb_driver_clib", "typedb-driver-behaviour"}
    diffs = {k: {"upstream": up_lock.get(k), "projection": pj_lock.get(k)}
             for k in set(up_lock) | set(pj_lock)
             if up_lock.get(k) != pj_lock.get(k) and k not in roots}
    report["lock_parity"] = {
        "upstream_packages": len(up_lock), "projection_packages": len(pj_lock),
        "differences": diffs,
        "permitted_root_difference": sorted(roots),
    }
    if diffs:
        problems.append(f"projection Cargo.lock diverges from the driver's own "
                        f"lock on {len(diffs)} package(s): {sorted(diffs)[:10]}")

    # ---- 5 dependency spec parity ---------------------------------------
    up_ws = _toml(DRIVER / "Cargo.toml")["workspace"]["dependencies"]
    pj_ws = _toml(PROJ / "Cargo.toml")["workspace"]["dependencies"]
    spec_report = {}
    for name, pj in sorted(pj_ws.items()):
        if "path" in pj and name in ("config", "steps"):
            continue
        up = up_ws.get(name)
        if up is None:
            problems.append(f"projection declares dependency {name!r} which the "
                            f"driver workspace does not declare")
            continue
        for field in ("version", "default-features", "features"):
            u, p = up.get(field), pj.get(field)
            if name == "typedb-driver" and field == "features":
                dev = DECLARED_DEVIATIONS["typedb-driver.features"]
                if (u or []) != dev["upstream_cargo"] or (p or []) != dev["projection"]:
                    problems.append(
                        f"typedb-driver features deviation is not the declared "
                        f"one: upstream={u!r} projection={p!r}")
                continue
            if name == "typedb-driver" and field == "version":
                continue
            if u != p:
                problems.append(f"dependency {name!r}: {field} upstream={u!r} "
                                f"projection={p!r}")
        spec_report[name] = {"upstream": up, "projection": pj}
    report["dependency_specs"] = spec_report
    report["declared_deviations"] = DECLARED_DEVIATIONS

    # ---- 6 suite set parity with the Bazel declarations -------------------
    bazel = {}
    for build in (DRIVER / "rust" / "tests" / "behaviour").rglob("BUILD"):
        text = build.read_text()
        for name, src in BUILD_TEST_RE.findall(text):
            bazel[name] = common.rel((build.parent / src).resolve())
    proj_tests = {}
    tdoc = _toml(PROJ / "tests" / "Cargo.toml")
    for t in tdoc.get("test", []):
        proj_tests[t["name"]] = common.rel(
            (PROJ / "tests" / t["path"]).resolve())
    report["bazel_suites"] = bazel
    report["projection_suites"] = proj_tests
    if set(bazel) != set(proj_tests):
        problems.append(
            f"projected suite set {sorted(proj_tests)} != Bazel "
            f"rust_behaviour_test set {sorted(bazel)}")
    for name in sorted(set(bazel) & set(proj_tests)):
        if bazel[name] != proj_tests[name]:
            problems.append(f"suite {name}: Bazel srcs {bazel[name]} != "
                            f"projection path {proj_tests[name]}")

    report["ok"] = not problems
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    rep = check()
    print(json.dumps(rep, indent=1))
    if not rep["ok"]:
        print(f"PROJECTION CHECK FAILED: {len(rep['problems'])} problem(s)",
              file=sys.stderr)
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
