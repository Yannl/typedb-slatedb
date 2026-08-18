#!/usr/bin/env python3
"""BT-P1: upstream test catalogue generator (v14 schema).

Emits docs/evidence/G1/upstream-test-catalog.json conforming to
typedb-r2-v14-upstream-test-catalog.schema.json, generated from:

  - `cargo +<toolchain> metadata --locked` over the pinned TypeDB workspace
    (CARGO-origin targets: test/bench targets of every workspace member);
  - libtest `--list` output of every compiled test executable
    (LIBTEST leaf cases, including #[ignore] cases via a second listing);
  - the pinned typedb-behaviour checkout (CUCUMBER leaf cases: each
    Scenario, and each Scenario Outline example row, of every feature file
    referenced by the behaviour test sources);
  - the fail_point::ALL registry (FAILPOINT leaf cases: each member in
    each of the two loop contexts of tests/assembly/fail_points.rs);
  - BUILD files (BAZEL_DIRECT reconnaissance: rust_test / checkstyle /
    fmt targets, recorded for the parity audit; Mode Q snapshot pending).

No count in this file is hand-asserted; rerunning the generator against the
pinned checkout must reproduce the output byte-for-byte (ordering is sorted).
"""
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

ENV = {**os.environ, "CARGO_INCREMENTAL": "0",
       "CARGO_PROFILE_DEV_DEBUG": "false",
       "CARGO_PROFILE_TEST_DEBUG": "false"}

REPO = pathlib.Path(__file__).resolve().parents[2]
TB = REPO / "sources" / "typedb"
BH = REPO / "sources" / "typedb-behaviour"
TOOLCHAIN = "+1.93.0"
OUT = REPO / "docs" / "evidence" / "G1" / "upstream-test-catalog.json"

SERIAL_GROUPS = {
    # tests that bind ports / global failpoints / process data dirs
    "test_assembly": "assembly-server",
    "test_fail_points": "assembly-server",
    "test_behaviour_connection": "server-port",
    "test_behaviour_concept": "server-port",
    "test_behaviour_query": "server-port",
    "test_http_behaviour": "http-port",
    "test_http_driver_behaviour": "http-port",
}

DEFAULT_TIMEOUT = 1800


def package_name_from_id(package_id: str) -> str:
    """Package name from a cargo package-id spec (`url[#[name@]version]`).

    Cargo omits the `name@` part of the fragment when the name equals the
    final path segment of the url, so `...typedb/concept#0.0.0` means package
    `concept` while `...storage/tests#test_utils_storage@0.0.0` means package
    `test_utils_storage`. Parsing the fragment alone collapses most workspace
    crates onto the bare version string.
    """
    url, _, frag = package_id.partition("#")
    if "@" in frag:
        return frag.split("@")[0]
    return url.rstrip("/").rsplit("/", 1)[-1]


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(p: pathlib.Path) -> str:
    return sha256_bytes(p.read_bytes())


def cargo_metadata():
    out = subprocess.check_output(
        ["cargo", TOOLCHAIN, "metadata", "--locked", "--format-version", "1",
         "--no-deps"],
        cwd=TB, text=True, env=ENV)
    return json.loads(out)


def rel(p: str) -> str:
    return str(pathlib.Path(p).resolve().relative_to(TB.resolve()))


def collect_cargo_targets(meta):
    targets = []
    for pkg in meta["packages"]:
        for t in pkg["targets"]:
            kinds = t["kind"]
            if "test" in kinds:
                kind = "test"
            elif "bench" in kinds:
                kind = "bench"
            elif "lib" in kinds or "bin" in kinds or "proc-macro" in kinds:
                # unit tests live inside lib/bin targets; they are test-capable
                kind = "unit"
            else:
                continue
            src = pathlib.Path(t["src_path"])
            targets.append({
                "package": pkg["name"],
                "target_name": t["name"],
                "kind": kind,
                "crate_kinds": kinds,
                "src": rel(str(src)),
                "src_sha256": sha256_file(src),
            })
    return targets


def libtest_cases():
    """Discover per-executable libtest cases from compiled binaries."""
    out = subprocess.check_output(
        ["cargo", TOOLCHAIN, "test", "--workspace", "--locked", "--no-run",
         "--message-format", "json"],
        cwd=TB, text=True, stderr=subprocess.DEVNULL, env=ENV)
    cases = {}
    execs = {}
    for line in out.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") == "compiler-artifact" and msg.get("executable"):
            tgt = msg["target"]
            pkg_name = package_name_from_id(msg["package_id"])
            execs[(pkg_name, tgt["name"])] = (msg["executable"], tgt)
    for (pkg, tname), (exe, tgt) in sorted(execs.items()):
        listing = subprocess.run(
            [exe, "--list", "--format", "terse"],
            capture_output=True, text=True, cwd=TB)
        ignored = subprocess.run(
            [exe, "--list", "--format", "terse", "--ignored"],
            capture_output=True, text=True, cwd=TB)
        # completeness contract: an executable that cannot even be listed must
        # fail the generation loudly, never contribute zero cases silently.
        # (harness=false binaries reject libtest flags with a nonzero exit and
        # a usage error on the flag - that is expected and handled downstream;
        # any other failure mode, e.g. loader errors/exit 127, is fatal.)
        for run in (listing, ignored):
            if run.returncode != 0:
                combined = (run.stdout + run.stderr)
                if not ("Unrecognized option" in combined
                        or "unexpected argument" in combined
                        or "error: Found argument" in combined):
                    raise RuntimeError(
                        f"--list failed for {pkg}:{tname} ({exe}) rc={run.returncode}: "
                        f"{combined[:400]}")
        names = []
        for line in listing.stdout.splitlines():
            if line.endswith(": test"):
                names.append(line[:-len(": test")])
        ignored_names = set()
        for line in ignored.stdout.splitlines():
            if line.endswith(": test"):
                ignored_names.add(line[:-len(": test")])
        entry = cases.setdefault((pkg, tname), [])
        for n in names:
            entry.append({"name": n, "ignored": n in ignored_names})
        for n in sorted(ignored_names - set(names)):
            entry.append({"name": n, "ignored": True})
    return cases


def cucumber_cases():
    """Each Scenario and each Scenario Outline example row is a leaf case."""
    refs = set()
    for rs in TB.rglob("*.rs"):
        if "target" in rs.parts or "bazel-typedb" in rs.parts:
            continue
        try:
            text = rs.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for m in re.finditer(r'typedb_behaviour\+/([^"]+\.feature)', text):
            refs.add(m.group(1))
    out = {}
    for ref in sorted(refs):
        f = BH / ref
        text = f.read_text()
        src_hash = sha256_file(f)
        scenarios = []
        lines = text.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith("Scenario Outline:"):
                name = line.split(":", 1)[1].strip()
                rows = 0
                j = i + 1
                in_examples = False
                header_seen = False
                while j < len(lines):
                    l2 = lines[j].strip()
                    if re.match(r"(Scenario|Feature|Rule)\b", l2):
                        break
                    if l2.startswith("Examples"):
                        in_examples = True
                        header_seen = False
                    elif in_examples and l2.startswith("|"):
                        if not header_seen:
                            header_seen = True
                        else:
                            rows += 1
                    elif in_examples and l2 and not l2.startswith("#"):
                        in_examples = False
                    j += 1
                # an outline whose Examples rows are all commented out
                # expands to ZERO runs (cucumber semantics) - counting it as
                # one would put a phantom leaf in the denominator that no
                # runner ever executes (completeness.py cross-checks this)
                scenarios.append({"name": name, "outline_examples": rows})
                i = j
                continue
            if line.startswith("Scenario:"):
                scenarios.append({"name": line.split(":", 1)[1].strip(),
                                  "outline_examples": None})
            i += 1
        out[ref] = {"sha256": src_hash, "scenarios": scenarios}
    return out


def failpoint_cases():
    lib = (TB / "common" / "fail_point" / "lib.rs").read_text()
    m = re.search(r"fail_points!\s*\{(.*?)\}", lib, re.S)
    members = []
    for x in m.group(1).splitlines():
        x = x.strip().rstrip(",")
        if x and re.fullmatch(r"[A-Z0-9_]+", x):
            members.append(x)
    fp_test = (TB / "tests" / "assembly" / "fail_points.rs").read_text()
    loops = [mm.start() for mm in re.finditer(r"for fail_point in fail_point::ALL", fp_test)]
    fn_names = []
    for pos in loops:
        fns = re.findall(r"fn\s+([a-z0-9_]+)\s*\(", fp_test[:pos])
        fn_names.append(fns[-1] if fns else f"loop_at_{pos}")
    return members, fn_names, sha256_bytes(fp_test.encode())


def build_targets_recon():
    """Static BUILD-file reconnaissance (Mode-S style; Mode Q snapshot pending)."""
    recon = []
    for build in TB.rglob("BUILD"):
        if "target" in build.parts or "bazel-typedb" in build.parts:
            continue
        text = build.read_text()
        for m in re.finditer(
                r'(rust_test|rust_integration_test|sh_test|checkstyle_test|'
                r'rustfmt_test|typedb_rust_test)\s*\(\s*\n\s*name\s*=\s*"([^"]+)"',
                text):
            recon.append({
                "build_file": rel(str(build)),
                "rule": m.group(1),
                "name": m.group(2),
            })
    return sorted(recon, key=lambda r: (r["build_file"], r["name"]))


def main():
    source_lock_digest = sha256_file(REPO / "source-lock" / "source-lock.json")
    meta = cargo_metadata()
    cargo_targets = collect_cargo_targets(meta)
    print(f"cargo targets: {len(cargo_targets)} total, "
          f"{sum(1 for t in cargo_targets if t['kind'] == 'test')} [[test]], "
          f"{sum(1 for t in cargo_targets if t['kind'] == 'bench')} [[bench]]",
          file=sys.stderr)

    lib_cases = libtest_cases()
    cucumber = cucumber_cases()
    fp_members, fp_contexts, fp_test_hash = failpoint_cases()
    recon = build_targets_recon()

    profiles = [
        {"profile_id": "U0", "kv_backend": "rocksdb-pristine", "durability": "file-wal",
         "object_store": "none", "controller": "upstream-local", "features": [], "cfg": []},
        {"profile_id": "U1", "kv_backend": "rocksdb-adapter", "durability": "file-wal",
         "object_store": "none", "controller": "fork-local", "features": [], "cfg": []},
        {"profile_id": "U2", "kv_backend": "slatedb-localfs", "durability": "file-wal",
         "object_store": "localfs", "controller": "local", "features": [], "cfg": []},
        {"profile_id": "U3", "kv_backend": "slatedb-localfs", "durability": "remote-wal",
         "object_store": "localfs", "controller": "deterministic-model", "features": [], "cfg": []},
        {"profile_id": "U4", "kv_backend": "slatedb-r2", "durability": "remote-wal",
         "object_store": "r2", "controller": "real-do", "features": [], "cfg": []},
    ]

    targets, leaf_cases, required_pairs, fixtures, exclusions = [], [], [], [], []

    fixtures.append({
        "fixture_id": "fixture:typedb-behaviour",
        "kind": "DIRECTORY",
        "source": "https://github.com/typedb/typedb-behaviour @ ac5d5733a484cea1d8809a2968029a818fdae24f",
        "sha256": sha256_bytes(b"git-tree:8d4f0b44550648cfe53fe703e039d48696b227dd"),
        "licence": "MPL-2.0",
        "destination": "bazel-typedb/external/typedb_behaviour+",
    })
    fixtures.append({
        "fixture_id": "fixture:typedb-console-linux-x86_64-3.12.0",
        "kind": "ARCHIVE",
        "source": "https://repo.typedb.com/public/public-release/raw/names/typedb-console-linux-x86_64/versions/3.12.0/typedb-console-linux-x86_64-3.12.0.tar.gz",
        "sha256": "058145121f478f2f8ad10991cd17e64e12957b93e0836ac180fe9d095a4c4e40",
        "licence": "MPL-2.0",
        "destination": "assembly-archive/console",
    })
    fixtures.append({
        "fixture_id": "fixture:typedb-loader-linux-x86_64-3.12.0",
        "kind": "ARCHIVE",
        "source": "https://repo.typedb.com/public/public-release/raw/names/typedb-loader-linux-x86_64/versions/3.12.0/typedb-loader-linux-x86_64-3.12.0.tar.gz",
        "sha256": "c46fba13d835701e43778a2ea1e2dbf0e031d206c55c6c8fec28e03c274d37f9",
        "licence": "MPL-2.0",
        "destination": "assembly-archive/loader",
    })
    script = TB / "tests" / "assembly" / "script.tql"
    fixtures.append({
        "fixture_id": "fixture:assembly-script.tql",
        "kind": "FILE",
        "source": "tests/assembly/script.tql @ TB pin",
        "sha256": sha256_file(script),
        "licence": "MPL-2.0",
        "destination": "tests/assembly/script.tql",
    })

    for t in sorted(cargo_targets, key=lambda x: (x["package"], x["target_name"], x["kind"])):
        if t["kind"] == "unit":
            tid = f"cargo:{t['package']}:unit:{t['target_name']}"
        else:
            tid = f"cargo:{t['package']}:{t['kind']}:{t['target_name']}"
        is_behaviour = t["target_name"].startswith(("test_behaviour", "test_http"))
        is_assembly = t["target_name"] in ("test_assembly", "test_fail_points")
        case_discovery = ("CUCUMBER_SCENARIOS" if is_behaviour
                          else "FAILPOINT_REGISTRY" if t["target_name"] == "test_fail_points"
                          else "LIBTEST_LIST")
        env = {}
        fixture_ids = []
        if is_assembly:
            env["TYPEDB_ASSEMBLY_ARCHIVE"] = "<staged by runner: cargo-built typedb-all-linux-x86_64 archive>"
            fixture_ids = ["fixture:typedb-console-linux-x86_64-3.12.0",
                           "fixture:typedb-loader-linux-x86_64-3.12.0",
                           "fixture:assembly-script.tql"]
        if is_behaviour:
            fixture_ids = ["fixture:typedb-behaviour"]
        targets.append({
            "target_id": tid,
            "origin": "CARGO",
            "upstream_label": None,
            "cargo_package": t["package"],
            "cargo_target": t["target_name"],
            "source_files": [{"path": t["src"], "sha256": t["src_sha256"]}],
            "case_discovery": case_discovery,
            "platform_predicate": "linux-x86_64",
            "features": [],
            "cfg": [],
            "env": env,
            "fixture_ids": fixture_ids,
            "working_directory": None,
            "timeout_seconds": DEFAULT_TIMEOUT,
            "serial_group": SERIAL_GROUPS.get(t["target_name"]),
            "port_status": "BYTE_IDENTICAL",
        })

    kind_by_target = {(t["package"], t["target_name"]): (t["kind"], t["src_sha256"])
                      for t in cargo_targets}
    for (pkg, tname), cs in sorted(lib_cases.items()):
        kind, src_hash = kind_by_target.get((pkg, tname), ("test", "0" * 64))
        tid = (f"cargo:{pkg}:unit:{tname}" if kind == "unit"
               else f"cargo:{pkg}:{kind}:{tname}")
        for c in sorted(cs, key=lambda x: x["name"]):
            leaf_cases.append({
                "leaf_case_id": f"{tid}::{c['name']}",
                "target_id": tid,
                "kind": "LIBTEST",
                "display_name": c["name"],
                "source_hash": src_hash,
                "declared_ignored": c["ignored"],
                "resource_group": SERIAL_GROUPS.get(tname),
            })

    for ref, data in sorted(cucumber.items()):
        targets.append({
            "target_id": f"cucumber-corpus:{ref}",
            "origin": "BAZEL_MACRO",
            "upstream_label": f"@typedb_behaviour//{ref}",
            "cargo_package": None,
            "cargo_target": None,
            "source_files": [{"path": f"<BH>/{ref}", "sha256": data["sha256"]}],
            "case_discovery": "CUCUMBER_SCENARIOS",
            "platform_predicate": "any",
            "features": [],
            "cfg": [],
            "env": {},
            "fixture_ids": ["fixture:typedb-behaviour"],
            "working_directory": None,
            "timeout_seconds": DEFAULT_TIMEOUT,
            "serial_group": "server-port",
            "port_status": "BYTE_IDENTICAL",
        })
        # Scenario names repeat inside a feature file (upstream writes the
        # same name for genuinely different scenarios). Keying leaves on the
        # name alone silently collapsed 29 rows onto 27 ids, so the catalogue
        # claimed 4,740 leaves while offering only 4,711 addressable ones -
        # a denominator that cannot be joined case-by-case. An occurrence
        # ordinal disambiguates without inventing a name: the FIRST
        # occurrence keeps the bare id (stable against the previous
        # catalogue), later ones carry `@2`, `@3`, ... in file order.
        seen_names = {}

        def uniq(base):
            k = seen_names.get(base, 0) + 1
            seen_names[base] = k
            return base if k == 1 else f"{base}@{k}"

        for s in data["scenarios"]:
            n = s["outline_examples"]
            if n == 0:
                # dead outline (all Examples rows commented out upstream):
                # zero leaves, deliberately absent from the denominator
                continue
            if n is None:
                leaf_cases.append({
                    "leaf_case_id": uniq(f"cucumber:{ref}::{s['name']}"),
                    "target_id": f"cucumber-corpus:{ref}",
                    "kind": "CUCUMBER",
                    "display_name": s["name"],
                    "source_hash": data["sha256"],
                    "declared_ignored": False,
                    "resource_group": "server-port",
                })
            else:
                for i in range(n):
                    leaf_cases.append({
                        "leaf_case_id": uniq(f"cucumber:{ref}::{s['name']}#ex{i+1}"),
                        "target_id": f"cucumber-corpus:{ref}",
                        "kind": "CUCUMBER",
                        "display_name": f"{s['name']} [example {i+1}/{n}]",
                        "source_hash": data["sha256"],
                        "declared_ignored": False,
                        "resource_group": "server-port",
                    })

    # The failpoint leaves used to name `cargo:typedb:test:test_fail_points`,
    # a target that does not exist in this catalogue's own target table (the
    # cargo package is `typedb_server_bin`), leaving 44 leaves dangling off a
    # phantom parent. Resolve the id from the cargo target table and fail
    # closed if the target is not there.
    fp_target = next(
        (f"cargo:{t['package']}:{t['kind']}:{t['target_name']}"
         for t in cargo_targets if t["target_name"] == "test_fail_points"), None)
    if fp_target is None:
        raise RuntimeError("failpoint leaves have no cargo target named test_fail_points")
    for ctx in fp_contexts:
        for member in fp_members:
            leaf_cases.append({
                "leaf_case_id": f"{fp_target}::{ctx}::{member}",
                "target_id": fp_target,
                "kind": "FAILPOINT",
                "display_name": f"{ctx}[{member}]",
                "source_hash": fp_test_hash,
                "declared_ignored": False,
                "resource_group": "assembly-server",
            })

    crash_sh = TB / "tool" / "test" / "simulate-crash.sh"
    targets.append({
        "target_id": "shell:tool/test/simulate-crash.sh",
        "origin": "SHELL",
        "upstream_label": "//tool/test:simulate-crash",
        "cargo_package": None,
        "cargo_target": None,
        "source_files": [{"path": "tool/test/simulate-crash.sh",
                          "sha256": sha256_file(crash_sh)}],
        "case_discovery": "SCRIPT",
        "platform_predicate": "linux-x86_64+docker",
        "features": [],
        "cfg": [],
        "env": {},
        "fixture_ids": [],
        "working_directory": None,
        "timeout_seconds": 3600,
        "serial_group": "crash-orchestration",
        "port_status": "SEMANTIC_PORT",
    })
    leaf_cases.append({
        "leaf_case_id": "shell:tool/test/simulate-crash.sh::crash-restart-loop",
        "target_id": "shell:tool/test/simulate-crash.sh",
        "kind": "SCRIPT",
        "display_name": "docker kill/restart crash-recovery loop (xtask port pending)",
        "source_hash": sha256_file(crash_sh),
        "declared_ignored": False,
        "resource_group": "crash-orchestration",
    })

    for r in recon:
        if r["rule"] in ("checkstyle_test", "rustfmt_test"):
            tid = f"static:{r['build_file']}:{r['name']}"
            targets.append({
                "target_id": tid,
                "origin": "STATIC_CHECK",
                "upstream_label": f"//{pathlib.Path(r['build_file']).parent}:{r['name']}",
                "cargo_package": None,
                "cargo_target": None,
                "source_files": [{"path": r["build_file"],
                                  "sha256": sha256_file(TB / r["build_file"])}],
                "case_discovery": "STATIC_CHECK",
                "platform_predicate": "any",
                "features": [], "cfg": [], "env": {}, "fixture_ids": [],
                "working_directory": None,
                "timeout_seconds": 600,
                "serial_group": None,
                "port_status": "SEMANTIC_PORT",
            })
            leaf_cases.append({
                "leaf_case_id": f"{tid}::check",
                "target_id": tid,
                "kind": "STATIC_CHECK",
                "display_name": f"{r['rule']} {r['name']}",
                "source_hash": sha256_file(TB / r["build_file"]),
                "declared_ignored": False,
                "resource_group": None,
            })

    # ---- referential integrity, uniqueness, and denominator ------------
    # Every one of these was silently violated by the previous catalogue and
    # nothing in the toolchain noticed. They are hard errors here: a
    # catalogue that cannot be joined to a run is not a denominator.
    target_ids = {t["target_id"] for t in targets}
    seen_leaf = {}
    for lc in leaf_cases:
        if lc["leaf_case_id"] in seen_leaf:
            raise RuntimeError(
                f"duplicate leaf_case_id {lc['leaf_case_id']!r} - leaf ids must be unique")
        seen_leaf[lc["leaf_case_id"]] = lc
        if lc["target_id"] not in target_ids:
            raise RuntimeError(
                f"leaf {lc['leaf_case_id']!r} references unknown target {lc['target_id']!r}")

    # ---- required (leaf, profile) pairs --------------------------------
    # The conformance plan requires EVERY required pair executed across the
    # U0..U4 profile matrix; the previous catalogue emitted U0 only, so the
    # contractual denominator was understated by a factor of five and no
    # profile beyond the baseline could ever be shown incomplete. Static and
    # script leaves are backend-independent and stay U0-only.
    BACKEND_INDEPENDENT = {"STATIC_CHECK", "SCRIPT"}
    for lc in leaf_cases:
        if lc["kind"] in BACKEND_INDEPENDENT:
            required_pairs.append({"leaf_case_id": lc["leaf_case_id"],
                                   "profile_id": "U0",
                                   "reason": "backend-independent check"})
            continue
        for prof in ("U0", "U1", "U2", "U3", "U4"):
            required_pairs.append({
                "leaf_case_id": lc["leaf_case_id"],
                "profile_id": prof,
                "reason": "conformance plan: every required (leaf, profile) pair executed"})

    # ---- declared zero-case targets ------------------------------------
    # A target with no leaves is legitimate (a crate with no #[test], a
    # [[bench]] that the cargo test lane compiles but never runs). What is
    # NOT legitimate is leaving that invisible: an intentional zero and a
    # silently-lost suite look identical. Each one is declared here, so the
    # completeness checker can require that the declaration matches reality.
    leaves_per_target = {}
    for lc in leaf_cases:
        leaves_per_target[lc["target_id"]] = leaves_per_target.get(lc["target_id"], 0) + 1
    for t in sorted(targets, key=lambda x: x["target_id"]):
        if leaves_per_target.get(t["target_id"], 0):
            continue
        is_bench = t["target_id"].split(":")[2:3] == ["bench"]
        exclusions.append({
            "subject_id": t["target_id"],
            "predicate": ("cargo target kind == bench" if is_bench
                          else "libtest enumeration returns zero cases"),
            "reason": ("[[bench]] targets are compiled by the cargo test lane but "
                       "carry no libtest cases and are never executed as tests; "
                       "benchmark measurement is a separate, non-conformance lane"
                       if is_bench else
                       "the crate declares no #[test] functions at this pin; the "
                       "zero is enumerated from the compiled binary, not assumed"),
            "owner": "conformance-catalogue",
            "expiry": "2027-12-31",
            "replacement_test_id": None,
        })

    exclusions.append({
        "subject_id": "bazel:mac-signing-and-installer-targets",
        "predicate": "platform == linux-x86_64 (targets are macOS-only, tagged manual at pin)",
        "reason": "macOS signing/installer targets are platform-inapplicable on Linux; declared visible per brief §1.1",
        "owner": "build-evidence",
        "expiry": "2027-12-31",
        "replacement_test_id": None,
    })

    catalog = {
        "schema_version": 1,
        "source_lock_digest": source_lock_digest,
        "rust_toolchain": {"rustc": "rustc 1.93.0 (254b59607 2026-01-19)",
                           "cargo": "cargo 1.93.0 (083ac5135 2025-12-15)"},
        "target_triple": "x86_64-unknown-linux-gnu",
        "bazel_query_oracle": None,
        "profiles": profiles,
        "targets": targets,
        "leaf_cases": leaf_cases,
        "required_pairs": required_pairs,
        "fixtures": fixtures,
        "exclusions": exclusions,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(catalog, indent=1, sort_keys=True) + "\n")
    summary = {
        "targets": len(targets),
        "explicit_cargo_test_targets": sum(1 for t in cargo_targets if t["kind"] == "test"),
        "explicit_cargo_bench_targets": sum(1 for t in cargo_targets if t["kind"] == "bench"),
        "unit_test_capable_targets": sum(1 for t in cargo_targets if t["kind"] == "unit"),
        "libtest_cases": sum(1 for l in leaf_cases if l["kind"] == "LIBTEST"),
        "cucumber_cases": sum(1 for l in leaf_cases if l["kind"] == "CUCUMBER"),
        "failpoint_cases": sum(1 for l in leaf_cases if l["kind"] == "FAILPOINT"),
        "script_cases": sum(1 for l in leaf_cases if l["kind"] == "SCRIPT"),
        "static_checks": sum(1 for l in leaf_cases if l["kind"] == "STATIC_CHECK"),
        "leaf_cases_total": len(leaf_cases),
        "declared_ignored": sum(1 for l in leaf_cases if l["declared_ignored"]),
        "fixtures": len(fixtures),
        "build_recon_targets": len(recon),
    }
    (OUT.parent / "catalog-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
