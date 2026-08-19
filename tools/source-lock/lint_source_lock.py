#!/usr/bin/env python3
"""G0 source-lock linter (BT-P0 scope).

Validates that EVERY node in source-lock/source-lock.json is resolved,
schema-valid for its declared kind, and consistent with the materialized
world: git checkouts under sources/ (revision AND tree), consumer
Cargo.locks for registry/cargo nodes, control-plane/package-lock.json for
npm nodes, and on-disk digests for artifacts.

The invariant: a value in the lock is either checked against the thing it
claims to pin, or checked for well-formedness where the pinned thing is not
present in this environment. No node kind is exempt — audit finding E-P0-02
showed that validating only a selected subset (the SlateDB registry node)
let forged versions, forged npm integrities, forged git trees, and missing
tree fields all pass with RC 0. A node whose kind this linter does not
recognize is a FAILURE, not a skip: fail closed on unknown.

Negative controls: tools/source-lock/lock_mutants.py applies the E-P0-02
forgeries (and more) to a temp copy of the lock and requires this linter to
reject every one. Hide or corrupt any checkout (e.g. rename sources/typedb)
and this linter MUST also fail; the archived run of that control lives in
docs/evidence/G0/negative-control-missing-node.txt.

CLI: --lock-file and --repo-root exist so the negative controls can run the
real linter against mutated temp copies without touching the real files.
The staged-fork and workspace-lock subprocess checks always run against
this repo (their scripts are bound to it); everything else resolves against
--repo-root.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
LOCK = REPO / "source-lock" / "source-lock.json"
# the materialization root: every GIT_DIRS checkout and ARTIFACTS file lands
# under here (main() re-resolves it from an optional --root, but this is the
# default and the one materialize_sources.py imports and writes into).
SOURCES = REPO / "sources"

# lock node id -> sources/ directory name
GIT_DIRS = {
    "TB": "typedb",
    "BH": "typedb-behaviour",
    "TBD": "typedb-dependencies",
    "TBDIST": "typedb-bazel-distribution",
    "TQL": "typeql",
    "TPROTO": "typedb-protocol",
    "TDRIVER": "typedb-driver",
    "CF_CTR_SOURCE": "cloudflare-containers",
    "CF_WORKERS_SDK": "cloudflare-workers-sdk",
}

ARTIFACTS = {
    "TCONSOLE": "fixtures/console/typedb-console-linux-x86_64-3.12.0.tar.gz",
    "TLOADER": "fixtures/loader/typedb-loader-linux-x86_64-3.12.0.tar.gz",
}

# lock node id -> Cargo.lock files (relative to repo root) that must pin the
# crates — every workspace that consumes the crate is checked. A listed
# consumer that does not contain the crate is a failure: the lock claimed a
# consumption relationship that does not exist.
# round-3 S-02: fork/typedb no longer consumes the REGISTRY slatedb - it
# consumes the PATCHED fork via [patch.crates-io] (see the SL node's
# `patched_consumers`, validated separately below). tools/Cargo.lock still
# resolves the registry crate, so SL keeps its registry checksum there.
REGISTRY_NODES = {
    "SL": ["tools/Cargo.lock"],
}

# cargo_dependency nodes (crates pinned transitively, e.g. via SlateDB) and
# the consumer Cargo.locks whose resolution they must match. E-P0-02 mutant
# 1 (OBJECT_STORE 0.14.0 -> 99.0.0) survived because nothing compared this
# node to the locks that actually resolve the crate.
CARGO_DEP_NODES = {
    "OBJECT_STORE": ["tools/Cargo.lock", "fork/typedb/Cargo.lock"],
}

# the single npm lockfile in this repo; npm nodes are cross-checked against
# it wherever the package appears there
NPM_LOCKFILE = "control-plane/package-lock.json"

# R3 A-01 (Alchemy adoption): pins resolved by the stack/ workspace, not
# control-plane. Each lock node here must agree EXACTLY (version AND
# integrity) with stack/package-lock.json, and its direct dependency spec in
# stack/package.json - when it is a direct dependency - must be the exact
# version, never a range: version identity is release identity for the
# fast-moving alchemy beta. A missing lockfile or missing resolution is a
# failure, not a skip: these nodes exist to pin what stack/ actually runs
# (WORKERD_ALCHEMY is the EFFECTIVE workerd `alchemy dev` executes, which
# is deliberately a different line than the WRANGLER-resolved WORKERD node).
STACK_NPM_LOCKFILE = "stack/package-lock.json"
STACK_PACKAGE_JSON = "stack/package.json"
STACK_LOCK_PINS = {
    "ALCHEMY": "alchemy",
    "WORKERD_ALCHEMY": "workerd",
}

# artifacts materialized into an uncommitted cache under sources/ (which is
# gitignored) instead of committed fixtures: verified against the locked
# sha256 whenever the file is present. Absence is NOT a failure - they are
# fetched on demand by their consumers (stack/minio.mjs,
# tools/s3-cert-corpus/run-corpus.sh), which re-verify the digest on every
# use and refuse mismatches.
CACHED_ARTIFACTS = {
    "MINIO": "minio/minio-RELEASE.2025-09-07T16-13-09Z",
    "RUSTFS": "rustfs/rustfs-1.0.0-rc.2",
}

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
# npm SRI for sha512: exactly 86 base64 chars + '==' padding (64 raw bytes).
# Length is enforced, not just charset: "sha512-FORGED" is all base64
# characters and sailed through a charset-only check (E-P0-02 mutant 2).
NPM_INTEGRITY = re.compile(r"^sha512-[A-Za-z0-9+/]{86}==$")
# version strings: digits-led dotted release, optional leading '=' pin,
# optional -pre/+build suffix (covers 0.15.0, 1.20260811.1, 5.x-alpha)
VERSION = re.compile(r"^=?\d+(\.\d+)*([.+-][0-9A-Za-z.]+)*$")


def cargo_lock_packages(path: pathlib.Path) -> dict:
    """name -> (version, checksum) for registry packages in a Cargo.lock."""
    pkgs = {}
    def quoted(line: str):
        parts = line.split('"')
        return parts[1] if len(parts) >= 2 else None

    name = version = source = checksum = None
    in_package = False
    for line in path.read_text().splitlines() + ["[[package]]"]:
        if line.strip() == "[[package]]":
            if in_package and name and source and "registry+" in source:
                pkgs[name] = (version, checksum)
            name = version = source = checksum = None
            in_package = True
        elif in_package and line.startswith("name = "):
            name = quoted(line)
        elif in_package and line.startswith("version = "):
            version = quoted(line)
        elif in_package and line.startswith("source = "):
            source = quoted(line)
        elif in_package and line.startswith("checksum = "):
            checksum = quoted(line)
    return pkgs


def check_patched_consumers(nid: str, node: dict, repo_root: pathlib.Path, failures: list) -> None:
    """round-3 S-02: a consumer that consumes the crate through a
    [patch.crates-io] path override (not the registry) is verified as a
    PATCH, not a checksum: the manifest must carry the patch line pointing at
    the recorded fork path, and the consumer Cargo.lock must resolve the
    crate WITHOUT a registry source (proving the patch actually took). The
    fork's byte identity is bound by tools/fork/materialize_slatedb.py
    --check (a separate gate step), not re-hashed here."""
    crate = node.get("crate")
    for pc in node.get("patched_consumers", []):
        manifest_rel = pc.get("manifest")
        lock_rel = pc.get("consumer_lock")
        patch_path = pc.get("patch_path")
        manifest = repo_root / manifest_rel if manifest_rel else None
        if manifest is None or not manifest.exists():
            failures.append(f"{nid}: patched consumer manifest missing at {manifest_rel}")
            continue
        text = manifest.read_text()
        # the [patch.crates-io] override for this crate must point at the
        # recorded fork path (a different path is a different, unlocked fork)
        if "[patch.crates-io]" not in text or crate not in text or (patch_path and patch_path not in text):
            failures.append(f"{nid}: {manifest_rel} lacks the [patch.crates-io] {crate} = path override "
                            f"pointing at {patch_path!r}")
        # the consumer lock must NOT resolve the crate from the registry
        # (if it does, the patch did not take and we are silently on crates.io)
        lock_path = repo_root / lock_rel if lock_rel else None
        if lock_path is None or not lock_path.exists():
            failures.append(f"{nid}: patched consumer lock missing at {lock_rel}")
            continue
        if crate in cargo_lock_packages(lock_path):
            failures.append(f"{nid}: {lock_rel} still resolves {crate} from the REGISTRY - "
                            f"the [patch.crates-io] override did not take (S-02 regression)")


def check_crates_in_lock(nid: str, want: dict, lock_rel: str,
                         repo_root: pathlib.Path, failures: list) -> None:
    """Every crate in `want` (name -> (version, checksum)) must be pinned in
    the consumer lockfile with exactly that version and checksum."""
    lock_path = repo_root / lock_rel
    if not lock_path.exists():
        failures.append(f"{nid}: consumer lockfile missing at {lock_rel}")
        return
    pkgs = cargo_lock_packages(lock_path)
    for cname, (wver, wsum) in want.items():
        got = pkgs.get(cname)
        if got is None:
            failures.append(f"{nid}: crate {cname} not pinned in {lock_rel}")
        elif got != (wver, wsum):
            failures.append(
                f"{nid}: crate {cname} mismatch in {lock_rel} "
                f"want {(wver, wsum)} got {got}")


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# per-kind schema validation — every node passes through exactly one of
# these; a kind with no validator is a failure (fail closed on unknown)
# ---------------------------------------------------------------------------

def validate_git(nid: str, node: dict, repo_root: pathlib.Path, failures: list):
    """git / git_tag: commit and tree must both be locked as 40-hex ids.

    A commit hash alone is not enough once anything downstream is allowed to
    talk about "the tree": E-P0-02 mutants 3 and 4 forged a tree to forty
    zeros and dropped a tree field entirely, and both passed. Presence and
    shape are checked here for every git node; agreement with the actual
    checkout is checked in the sources/ loop where a checkout exists.
    """
    rev = node.get("revision") or node.get("resolved_revision")
    if not (isinstance(rev, str) and HEX40.match(rev)):
        failures.append(f"{nid}: git revision not a 40-hex commit id: {rev!r}")
    tree = node.get("tree")
    if not (isinstance(tree, str) and HEX40.match(tree)):
        failures.append(f"{nid}: git tree missing or not a 40-hex tree id: {tree!r}")
    repo_url = node.get("repository")
    if not (isinstance(repo_url, str) and repo_url.startswith("https://")):
        failures.append(f"{nid}: git repository URL missing or not https: {repo_url!r}")
    if node.get("kind") == "git_tag" and not node.get("tag"):
        failures.append(f"{nid}: git_tag node without a tag")


def validate_registry(nid: str, node: dict, repo_root: pathlib.Path, failures: list):
    """crates.io registry node: pinned version + sha256 for the crate and
    every companion crate, each cross-checked against every listed consumer
    Cargo.lock (the consumer check happens in the REGISTRY_NODES loop)."""
    crates = {node.get("crate"): node}
    crates.update(node.get("companion_crates", {}))
    for cname, cinfo in crates.items():
        if not cname:
            failures.append(f"{nid}: registry node without a crate name")
            continue
        ver = cinfo.get("version")
        if not (isinstance(ver, str) and VERSION.match(ver)):
            failures.append(f"{nid}: crate {cname} malformed version {ver!r}")
        cs = cinfo.get("checksum_sha256")
        if not (isinstance(cs, str) and HEX64.match(cs)):
            failures.append(
                f"{nid}: crate {cname} checksum_sha256 missing or not 64-hex: {cs!r}")


def validate_cargo_dependency(nid: str, node: dict, repo_root: pathlib.Path,
                              failures: list):
    """Transitively-pinned crate: same shape rules as a registry node; the
    consumer Cargo.lock agreement is checked in the CARGO_DEP_NODES loop."""
    if not node.get("name"):
        failures.append(f"{nid}: cargo_dependency without a crate name")
    ver = node.get("version")
    if not (isinstance(ver, str) and VERSION.match(ver)):
        failures.append(f"{nid}: malformed version {ver!r}")
    cs = node.get("checksum_sha256")
    if not (isinstance(cs, str) and HEX64.match(cs)):
        failures.append(f"{nid}: checksum_sha256 missing or not 64-hex: {cs!r}")


def validate_npm(nid: str, node: dict, repo_root: pathlib.Path, failures: list):
    """npm node: SRI-shaped sha512 integrity, registry tarball URL, and
    agreement with control-plane/package-lock.json where the package appears
    there (per policy npm_requires_tarball_integrity_and_source_mapping)."""
    name = node.get("name")
    if not name:
        failures.append(f"{nid}: npm node without a package name")
        return
    ver = node.get("version")
    if not (isinstance(ver, str) and VERSION.match(ver)):
        failures.append(f"{nid}: malformed version {ver!r}")
    integrity = node.get("integrity")
    if not (isinstance(integrity, str) and NPM_INTEGRITY.match(integrity)):
        failures.append(
            f"{nid}: integrity missing or not sha512-<86 base64 chars>==: "
            f"{integrity!r}")
    tarball = node.get("tarball")
    if not (isinstance(tarball, str) and tarball.startswith("https://registry.npmjs.org/")):
        failures.append(f"{nid}: tarball missing or not registry.npmjs.org: {tarball!r}")
    # cross-check the consumer lockfile: absence there is not a failure (some
    # npm nodes pin provenance for tools installed outside the workspace),
    # but where npm resolved the package, the two locks must agree exactly
    pkg_lock = repo_root / NPM_LOCKFILE
    if not pkg_lock.exists():
        failures.append(f"{nid}: npm consumer lockfile missing at {NPM_LOCKFILE}")
        return
    packages = json.loads(pkg_lock.read_text()).get("packages", {})
    entry = packages.get(f"node_modules/{name}")
    if entry is not None:
        if entry.get("version") != ver:
            failures.append(
                f"{nid}: version mismatch vs {NPM_LOCKFILE} "
                f"want {ver!r} got {entry.get('version')!r}")
        if entry.get("integrity") != integrity:
            failures.append(
                f"{nid}: integrity mismatch vs {NPM_LOCKFILE} "
                f"want {integrity!r} got {entry.get('integrity')!r}")


def validate_artifact(nid: str, node: dict, repo_root: pathlib.Path, failures: list):
    """artifact node: policy artifacts_require_url_sha256_license, plus a
    well-formed digest (the on-disk digest check is the ARTIFACTS loop)."""
    cs = node.get("sha256")
    if not (isinstance(cs, str) and HEX64.match(cs)):
        failures.append(f"{nid}: artifact sha256 missing or not 64-hex: {cs!r}")
    url = node.get("url")
    if not (isinstance(url, str) and url.startswith("https://")):
        failures.append(f"{nid}: artifact url missing or not https: {url!r}")
    if not node.get("license"):
        failures.append(f"{nid}: artifact without a license")
    ver = node.get("version")
    if not (isinstance(ver, str) and VERSION.match(ver)):
        failures.append(f"{nid}: malformed version {ver!r}")


def validate_oci_image(nid: str, node: dict, repo_root: pathlib.Path, failures: list):
    """oci_image node: policy oci_requires_digest. One documented exception:
    a node whose status records an open architecture decision
    (architecture_choice_required) has nothing to pin yet — anything else
    with a null or malformed digest is a floating reference."""
    if str(node.get("status", "")).startswith("architecture_choice_required"):
        return
    ref = node.get("reference")
    if not (isinstance(ref, str) and ref):
        failures.append(f"{nid}: oci_image without a reference: {ref!r}")
    digest = node.get("digest")
    if not (isinstance(digest, str) and OCI_DIGEST.match(digest)):
        failures.append(
            f"{nid}: oci digest missing or not sha256:<64-hex>: {digest!r}")


def validate_toolchain(nid: str, node: dict, repo_root: pathlib.Path, failures: list):
    """toolchain node: a named tool with a well-formed version string."""
    if not node.get("name"):
        failures.append(f"{nid}: toolchain without a name")
    ver = node.get("version")
    if not (isinstance(ver, str) and VERSION.match(ver)):
        failures.append(f"{nid}: malformed toolchain version {ver!r}")


def validate_toolchain_set(nid: str, node: dict, repo_root: pathlib.Path,
                           failures: list):
    """toolchain_set node: a non-empty member map, every member recorded as a
    non-empty identity string (path or version banner)."""
    members = node.get("members")
    if not isinstance(members, dict) or not members:
        failures.append(f"{nid}: toolchain_set without members")
        return
    for mname, mval in members.items():
        if not (isinstance(mval, str) and mval.strip()):
            failures.append(f"{nid}: toolchain_set member {mname!r} has no identity")


KIND_VALIDATORS = {
    "git": validate_git,
    "git_tag": validate_git,
    "registry": validate_registry,
    "cargo_dependency": validate_cargo_dependency,
    "npm": validate_npm,
    "artifact": validate_artifact,
    "oci_image": validate_oci_image,
    "toolchain": validate_toolchain,
    "toolchain_set": validate_toolchain_set,
}


def check_staged_fork(workspace_lock_stale):
    """The staged tree must be exactly `locked revision + the locked fork`.

    Returns [] when sources/typedb carries the complete fork patch set and
    that patch set matches the digest in workspace-lock.json; otherwise the
    exact reason. Nothing here tolerates a partially staged or hand-edited
    tree: those are the states in which a run's evidence names bytes nobody
    can reconstruct.
    """
    out = []
    stage = subprocess.run(
        [sys.executable, str(REPO / "tools" / "fork" / "stage.py"), "--check"],
        capture_output=True, text=True)
    state = stage.stdout.strip().splitlines()[0] if stage.stdout.strip() else "UNKNOWN"
    if not state.startswith("STAGED:"):
        out.append(f"TB: sources/typedb is dirty but not cleanly staged - {state}")
        return out
    ws_path = REPO / "source-lock" / "workspace-lock.json"
    if not ws_path.exists():
        out.append("TB: workspace-lock.json missing - the staged fork has no locked identity")
        return out
    locked = json.loads(ws_path.read_text()).get("fork_staging")
    if not locked:
        out.append("TB: workspace-lock.json records no fork_staging digest - "
                   "regenerate it (tools/source-lock/generate_workspace_lock.py)")
        return out
    # the digest comparison itself is main()'s single generate_workspace_lock
    # --check run (previously re-run here: a second full-tree rehash per lint)
    if workspace_lock_stale:
        out.append("TB: staged fork digest does not match workspace-lock.json "
                   "(see generate_workspace_lock.py --check)")
    return out


def main() -> int:
    # overrides exist for the negative controls (lock_mutants.py): they run
    # this real linter against mutated temp copies, never the real files
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock-file", type=pathlib.Path, default=LOCK,
                        help="source-lock.json to lint (default: the committed one)")
    parser.add_argument("--repo-root", type=pathlib.Path, default=REPO,
                        help="root for resolving sources/ and consumer lockfiles")
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()
    sources = repo_root / "sources"

    failures = []
    lock = json.loads(args.lock_file.read_text())
    nodes = {n["id"]: n for n in lock["nodes"]}

    # ONE workspace-lock verification per lint (it rehashes the whole fork
    # tree); both the TB staged-fork check and the workspace binding check
    # below consume this result. Always runs against THIS repo: the script
    # is bound to it, and the mutant lane mutates node data, not the binding.
    ws_check = subprocess.run(
        [sys.executable, str(REPO / "tools" / "source-lock" / "generate_workspace_lock.py"), "--check"],
        capture_output=True, text=True)

    for nid, node in nodes.items():
        status = node.get("status", "")
        if status.startswith(("locked", "recorded", "declared_not_yet_qualified",
                              "architecture_choice_required")):
            pass
        else:
            failures.append(f"{nid}: unresolved status {status!r}")

    # every node gets exactly one per-kind schema validation; an unknown or
    # missing kind is a failure, never a skip (E-P0-02: skipped kinds are
    # where the forgeries lived)
    for nid, node in nodes.items():
        kind = node.get("kind")
        validator = KIND_VALIDATORS.get(kind)
        if validator is None:
            failures.append(
                f"{nid}: unknown or missing kind {kind!r} - no validator; "
                f"fail closed (add one to KIND_VALIDATORS or fix the node)")
        else:
            validator(nid, node, repo_root, failures)

    for nid, dirname in GIT_DIRS.items():
        node = nodes.get(nid)
        if node is None:
            failures.append(f"{nid}: missing from lock")
            continue
        want = node.get("revision") or node.get("resolved_revision")
        d = sources / dirname
        if not (d / ".git").exists():
            failures.append(f"{nid}: checkout missing at sources/{dirname}")
            continue
        got = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"],
                             capture_output=True, text=True).stdout.strip()
        if got != want:
            failures.append(f"{nid}: revision mismatch want {want} got {got}")
        # the locked tree must be the commit's real tree. rev-parse reads the
        # commit object, so this holds even while the fork is staged (a dirty
        # working tree does not change HEAD^{tree}); a forged tree in the
        # lock (E-P0-02 mutant 3) fails here against every present checkout.
        want_tree = node.get("tree")
        got_tree = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD^{tree}"],
                                  capture_output=True, text=True).stdout.strip()
        if want_tree != got_tree:
            failures.append(
                f"{nid}: tree mismatch want {want_tree} got {got_tree} "
                f"(sources/{dirname})")
        dirty = subprocess.run(["git", "-C", str(d), "status", "--porcelain"],
                               capture_output=True, text=True).stdout.strip()
        if dirty:
            if nid == "TB":
                # sources/typedb is legitimately dirty while the fork is
                # staged over the locked revision (tools/fork/stage.py). A
                # blanket "dirty tree" failure made the ONLY runnable state
                # of the test lane permanently red, which trains readers to
                # ignore the lint. Accept exactly one dirty state - fully
                # staged, with the fork patch set matching the digest bound
                # in workspace-lock.json - and fail everything else.
                failures.extend(check_staged_fork(ws_check.returncode != 0))
            else:
                failures.append(f"{nid}: dirty tree at sources/{dirname}")

    for nid, lock_rels in REGISTRY_NODES.items():
        node = nodes.get(nid)
        if node is None:
            failures.append(f"{nid}: missing from lock")
            continue
        if node.get("kind") != "registry":
            failures.append(f"{nid}: expected kind 'registry', got {node.get('kind')!r}")
            continue
        want = {node["crate"]: (node["version"].lstrip("="),
                                node.get("checksum_sha256"))}
        for cname, cinfo in node.get("companion_crates", {}).items():
            want[cname] = (cinfo["version"].lstrip("="), cinfo.get("checksum_sha256"))
        for lock_rel in lock_rels:
            check_crates_in_lock(nid, want, lock_rel, repo_root, failures)
        # round-3 S-02: also verify any patched (fork) consumers of this node
        check_patched_consumers(nid, node, repo_root, failures)

    for nid, lock_rels in CARGO_DEP_NODES.items():
        node = nodes.get(nid)
        if node is None:
            failures.append(f"{nid}: missing from lock")
            continue
        if node.get("kind") != "cargo_dependency":
            failures.append(
                f"{nid}: expected kind 'cargo_dependency', got {node.get('kind')!r}")
            continue
        want = {node["name"]: (node["version"].lstrip("="),
                               node.get("checksum_sha256"))}
        for lock_rel in lock_rels:
            check_crates_in_lock(nid, want, lock_rel, repo_root, failures)

    if ws_check.returncode != 0:
        failures.append(f"workspace-lock: {ws_check.stdout.strip() or ws_check.stderr.strip()}")

    # stack/ workspace pins (R3 A-01): exact agreement with the stack
    # lockfile, SRI-shaped integrity, and exact (rangeless) direct specs
    stack_lock_path = repo_root / STACK_NPM_LOCKFILE
    stack_pkg_path = repo_root / STACK_PACKAGE_JSON
    for nid, pkg in STACK_LOCK_PINS.items():
        node = nodes.get(nid)
        if node is None:
            failures.append(f"{nid}: missing from lock")
            continue
        integrity = node.get("integrity")
        if not (isinstance(integrity, str) and NPM_INTEGRITY.match(integrity)):
            failures.append(
                f"{nid}: integrity missing or not sha512-<86 base64 chars>==: {integrity!r}")
        if not stack_lock_path.exists():
            failures.append(f"{nid}: consumer lockfile missing at {STACK_NPM_LOCKFILE}")
            continue
        packages = json.loads(stack_lock_path.read_text()).get("packages", {})
        entry = packages.get(f"node_modules/{pkg}")
        if entry is None:
            failures.append(f"{nid}: {pkg} not resolved in {STACK_NPM_LOCKFILE}")
            continue
        if entry.get("version") != node.get("version"):
            failures.append(
                f"{nid}: version mismatch vs {STACK_NPM_LOCKFILE} "
                f"want {node.get('version')!r} got {entry.get('version')!r}")
        if entry.get("integrity") != integrity:
            failures.append(
                f"{nid}: integrity mismatch vs {STACK_NPM_LOCKFILE} "
                f"want {integrity!r} got {entry.get('integrity')!r}")
        if stack_pkg_path.exists():
            spec = (json.loads(stack_pkg_path.read_text())
                    .get("dependencies", {}).get(pkg))
            if spec is not None and spec != node.get("version"):
                failures.append(
                    f"{nid}: {STACK_PACKAGE_JSON} pins {pkg} as {spec!r} - "
                    f"must be the exact locked version {node.get('version')!r}, never a range")
        else:
            failures.append(f"{nid}: {STACK_PACKAGE_JSON} missing")

    # cached (uncommitted) artifacts: digest-verified whenever materialized
    for nid, rel in CACHED_ARTIFACTS.items():
        node = nodes.get(nid)
        if node is None:
            failures.append(f"{nid}: missing from lock")
            continue
        if node.get("kind") != "artifact":
            failures.append(f"{nid}: expected kind 'artifact', got {node.get('kind')!r}")
            continue
        p = sources / rel
        if p.exists():
            got = sha256(p)
            if got != node.get("sha256"):
                failures.append(
                    f"{nid}: cached artifact sha256 mismatch at sources/{rel} "
                    f"want {node.get('sha256')} got {got}")

    for nid, rel in ARTIFACTS.items():
        node = nodes.get(nid)
        if node is None:
            failures.append(f"{nid}: missing from lock")
            continue
        p = sources / rel
        if not p.exists():
            failures.append(f"{nid}: artifact missing at sources/{rel}")
            continue
        got = sha256(p)
        if got != node["sha256"]:
            failures.append(f"{nid}: sha256 mismatch want {node['sha256']} got {got}")

    if failures:
        print("SOURCE-LOCK LINT: FAIL")
        for f in failures:
            print("  -", f)
        return 1
    print(f"SOURCE-LOCK LINT: PASS ({len(GIT_DIRS)} git nodes, "
          f"{len(ARTIFACTS)} artifacts, {len(nodes)} lock nodes, "
          f"all kinds schema-validated)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
