#!/usr/bin/env python3
"""Seal the corpus evidence bundle (R5-LOCAL-03, hardened for R6-EVID-01).

Round-5 sealed a bundle that was internally self-consistent but not
SOURCE-AUTHENTIC: it recorded a bare `git_head`, a COUNT of dirty paths, and
the CALLER'S CLAIM about the provider binary digest. A modified tracked
corpus source could therefore hide behind an unchanged `git_head`, and a
lying `--server-sha256` was never contradicted.

v2 binds the run to its executable inputs:

  * clean-tree gate. Any dirt (tracked or untracked, `-uall`) is REFUSED
    before execution and before sealing. `--allow-dirty` is an explicit
    opt-out that STAMPS the bundle `qualification: false` and names every
    dirty path; verify-bundle.py then refuses it unless the reader
    consciously passes --allow-non-qualification.
  * corpus content root. An exact digest over every executable input of the
    corpus (Cargo manifest, lockfile, src/**, run scripts, the sealer and
    the verifier themselves) — recomputed independently by the verifier, so
    a byte-level change to the harness invalidates the bundle even at an
    unchanged commit.
  * provider identity. The binary digest is RECOMPUTED here from the bytes
    at --server-bin and matched against the source-lock node for the
    provider; the caller's --server-sha256 is recorded as a CLAIM and the
    seal is refused when it disagrees. source-lock.json and
    workspace-lock.json bytes are copied into the bundle and sealed.
  * executed machinery. Absolute path + sha256 + version of every helper
    actually invoked (provider binary, cas_racer, cargo, rustc, python3,
    git), the effective CARGO_TARGET_DIR resolved by `cargo metadata` /
    `--message-format=json` (never a hardcoded target path), the command
    argv log, and an environment ALLOWLIST with secrets redacted and any
    unaccounted-for influential variable reported.
  * structured per-phase results. Cargo test logs are parsed into per-test
    records and the multi-process CAS rounds into per-round counters, so
    the verdict is data, not a grep over prose.
  * attestation. `attestation.stable_root` is a digest over only the
    deterministic identity of the run (content root, provider, locks,
    config, toolchain, structured phase verdicts) — excluding timestamps,
    pids, ports, temp paths and build-path-dependent digests — so a fresh
    clean checkout can reproduce it. root.txt remains the rollup over every
    sealed artifact including bundle.json.

FORMAT CONTRACT (the only thing verify-bundle.py shares with this file; it
re-derives every value with its own code):

  CORPUS SOURCE SET — files under <repo>/tools/s3-cert-corpus that are
    Cargo.toml, Cargo.lock, any *.py or *.sh directly in that directory, or
    any file under src/ recursively; excluding target/, evidence/ and
    __pycache__/. Paths are POSIX, relative to the repo root.
  CORPUS SOURCE ROOT — sha256 over, for each path in bytewise-sorted order,
    b"<relpath>\n<sha256hex>\n".
  ARTIFACT ROOT (root.txt) — sha256 over, for each name in bytewise-sorted
    order of the sealed artifacts plus "bundle.json", b"<name>\n<sha256hex>\n".
  STABLE ROOT — sha256 of json.dumps(payload, sort_keys=True,
    separators=(",", ":")) over the deterministic payload built by
    stable_payload() below.

Stdlib only.
"""

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

SCHEMA = "s3-cert-corpus-bundle/v2"

# provider name -> source-lock node id. A corpus verdict may only ever cite a
# source-locked artifact, so an unknown provider has no identity to bind.
PROVIDER_LOCK_NODE = {"minio": "MINIO", "rustfs": "RUSTFS"}

REQUIRED_PHASES = ("semantics", "mp-cas", "crash-restart", "post-restart")

# Environment allowlist: variables that may influence the build or the run.
# Values are captured verbatim except where the name looks secret-bearing.
ENV_ALLOWLIST = (
    "CARGO",
    "CARGO_BUILD_TARGET",
    "CARGO_HOME",
    "CARGO_HTTP_CAINFO",
    "CARGO_HTTP_PROXY",
    "CARGO_INCREMENTAL",
    "CARGO_NET_GIT_FETCH_WITH_CLI",
    "CARGO_NET_OFFLINE",
    "CARGO_TARGET_DIR",
    "CARGO_TERM_COLOR",
    "LANG",
    "LC_ALL",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "PATH",
    "RUSTC",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
    "RUSTUP_DIST_SERVER",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "RUSTUP_UPDATE_ROOT",
    "RUST_BACKTRACE",
    "RUST_LOG",
    "RUST_MIN_STACK",
    "RUST_TEST_THREADS",
    "SOURCE_DATE_EPOCH",
    "TZ",
    # the per-run S3 credentials are allowlisted so they are ACCOUNTED FOR,
    # and redacted by ENV_SECRET_RE so their values never enter the bundle.
    "S3_CERT_ACCESS_KEY",
    "S3_CERT_ALLOW_DIRTY",
    "S3_CERT_BUCKET",
    "S3_CERT_CAS_ROUNDS",
    "S3_CERT_CAS_WRITERS",
    "S3_CERT_ENDPOINT",
    "S3_CERT_EVIDENCE_DIR",
    "S3_CERT_MP_PROCS",
    "S3_CERT_MP_ROUNDS",
    "S3_CERT_PHASE",
    "S3_CERT_PORT",
    "S3_CERT_PROVIDER",
    "S3_CERT_SECRET_KEY",
    "S3_CERT_SERVER_BIN",
    "S3_CERT_UPDATE_ROUNDS",
)
# Any variable matching this prefix set influences the run; if one is present
# and NOT in the allowlist the bundle records it and the verifier refuses.
ENV_INFLUENTIAL_RE = re.compile(r"^(S3_CERT_|CARGO|RUST|LD_)")
ENV_SECRET_RE = re.compile(r"(KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)", re.I)

CORPUS_REL = "tools/s3-cert-corpus"


# --------------------------------------------------------------------------
# digests and the corpus content root
# --------------------------------------------------------------------------


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def corpus_source_files(repo: pathlib.Path) -> dict:
    """The CORPUS SOURCE SET -> {posix relpath from repo root: sha256}."""
    base = repo / CORPUS_REL
    skip = {"target", "evidence", "__pycache__"}
    out = {}

    def add(p: pathlib.Path):
        out[p.relative_to(repo).as_posix()] = sha256_file(p)

    for name in ("Cargo.toml", "Cargo.lock"):
        p = base / name
        if p.is_file():
            add(p)
    for p in sorted(base.iterdir()):
        if p.is_file() and p.suffix in (".py", ".sh"):
            add(p)
    src = base / "src"
    if src.is_dir():
        for p in sorted(src.rglob("*")):
            if p.is_file() and not any(part in skip for part in p.relative_to(base).parts):
                add(p)
    return dict(sorted(out.items()))


def rollup(pairs) -> str:
    h = hashlib.sha256()
    for name, digest in pairs:
        h.update(f"{name}\n{digest}\n".encode())
    return h.hexdigest()


# --------------------------------------------------------------------------
# structured parsing of cargo test output (no grep-only verdicts)
# --------------------------------------------------------------------------

RE_TEST = re.compile(r"^test ([^\s]+) \.\.\. (ok|FAILED|ignored)$")
RE_RESULT = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out"
)


def parse_cargo_test_log(text: str) -> dict:
    """Structured view of a cargo-test log: per-test outcomes + suite totals."""
    tests, results = [], []
    for line in text.splitlines():
        line = line.rstrip()
        m = RE_TEST.match(line)
        if m:
            tests.append({"name": m.group(1), "outcome": m.group(2)})
            continue
        m = RE_RESULT.match(line)
        if m:
            results.append(
                {
                    "verdict": m.group(1),
                    "passed": int(m.group(2)),
                    "failed": int(m.group(3)),
                    "ignored": int(m.group(4)),
                    "measured": int(m.group(5)),
                    "filtered_out": int(m.group(6)),
                }
            )
    return {
        "tests": sorted(tests, key=lambda t: t["name"]),
        "suite_results": results,
        "passed": sum(r["passed"] for r in results),
        "failed": sum(r["failed"] for r in results),
    }


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def run(argv, **kw) -> str:
    return subprocess.run(argv, capture_output=True, text=True, **kw).stdout.strip()


def git(repo: pathlib.Path, *argv: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), *argv], capture_output=True, text=True)
    if r.returncode != 0:
        die(f"git {' '.join(argv)} failed in {repo}: {r.stderr.strip()}")
    return r.stdout.strip()


def dirty_paths(repo: pathlib.Path) -> list:
    """Every tracked modification AND every untracked non-ignored path."""
    out = git(repo, "status", "--porcelain", "--untracked-files=all")
    return [line.rstrip() for line in out.splitlines() if line.strip()]


def die(msg: str, code: int = 2):
    print(f"seal-bundle: REFUSED — {msg}", file=sys.stderr)
    sys.exit(code)


def lock_node(lock_doc: dict, node_id: str) -> dict:
    for n in lock_doc.get("nodes", []):
        if n.get("id") == node_id:
            return n
    die(f"source-lock has no node {node_id!r} — the provider has no locked identity")


def tool_record(path_or_name: str, version: str = None, required=True) -> dict:
    resolved = shutil.which(path_or_name) or path_or_name
    p = pathlib.Path(resolved)
    rec = {"name": pathlib.Path(path_or_name).name, "path": str(p), "required": required}
    if p.is_file():
        rec["sha256"] = sha256_file(p)
    elif required:
        die(f"executable {path_or_name} not found at {p} — cannot bind what actually ran")
    else:
        rec["sha256"] = None
    rec["version"] = version
    return rec


def capture_environment() -> dict:
    allow, unlisted = {}, []
    for k, v in sorted(os.environ.items()):
        if k in ENV_ALLOWLIST:
            allow[k] = "<redacted>" if ENV_SECRET_RE.search(k) else v
        elif ENV_INFLUENTIAL_RE.match(k):
            unlisted.append(k)
    return {
        "allowlist": allow,
        "unlisted_influential": sorted(unlisted),
        "redaction_rule": ENV_SECRET_RE.pattern,
    }


# --------------------------------------------------------------------------
# stable root: the deterministic identity of the run
# --------------------------------------------------------------------------


def stable_payload(bundle: dict) -> dict:
    """Deterministic subset — reproducible from a fresh clean checkout.

    Excludes wall-clock times, pids, ports, temp paths, log digests, and the
    debug-build artifact digests (rustc embeds absolute paths, so a cas_racer
    built in another checkout has a different sha256 by construction).
    """
    prov = bundle["provider"]
    return {
        "schema": bundle["schema"],
        "corpus_source_root": bundle["corpus_source"]["root"],
        "corpus_source_files": bundle["corpus_source"]["files"],
        "provider": {
            "name": prov["name"],
            "source_lock_node": prov["source_lock_node"],
            "binary_sha256": prov["binary_sha256_recomputed"],
            "url": prov["url"],
            "version": prov["version"],
        },
        "locks": bundle["locks"],
        "corpus": bundle["corpus"],
        # only the reproducible part of the toolchain: cargo_target_dir is a
        # per-checkout path and must not enter the stable identity.
        "toolchain": {k: bundle["toolchain"].get(k) for k in ("rustc", "cargo", "object_store")},
        "phases": [
            {
                "name": p["name"],
                "verdict": p["verdict"],
                "exit_code": p["exit_code"],
                "summary": p["summary"],
            }
            for p in bundle["phases"]
        ],
    }


def stable_root(bundle: dict) -> str:
    blob = json.dumps(stable_payload(bundle), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


# --------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("evidence_dir", nargs="?")
    ap.add_argument(
        "--preflight",
        action="store_true",
        help="only run the clean-tree gate (used before execution) and exit",
    )
    ap.add_argument("--provider")
    ap.add_argument("--server-bin")
    ap.add_argument(
        "--server-sha256", help="CALLER CLAIM; recorded and cross-checked, never trusted"
    )
    ap.add_argument("--endpoint")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--semantics-expected", type=int)
    ap.add_argument("--mp-rounds", type=int)
    ap.add_argument("--mp-procs", type=int)
    ap.add_argument("--racer", help="cas_racer path resolved from cargo, not hardcoded")
    ap.add_argument("--cargo-target-dir", help="effective target directory reported by cargo")
    ap.add_argument(
        "--allow-dirty",
        action="store_true",
        help="opt out of the clean-tree gate; STAMPS the bundle non-qualification",
    )
    args = ap.parse_args()

    repo = pathlib.Path(args.repo).resolve()

    # ---- clean-tree gate (runs before execution via --preflight, and again
    # ---- here before sealing) -------------------------------------------
    dirt = dirty_paths(repo)
    if dirt and not args.allow_dirty:
        print(
            "seal-bundle: REFUSED — working tree is dirty; evidence must be produced from a "
            "clean checkout.",
            file=sys.stderr,
        )
        for d in dirt[:50]:
            print(f"  {d}", file=sys.stderr)
        if len(dirt) > 50:
            print(f"  … and {len(dirt) - 50} more", file=sys.stderr)
        print(
            "seal-bundle: re-run from a clean tree, or set S3_CERT_ALLOW_DIRTY=1 to produce a "
            "bundle explicitly STAMPED qualification=false.",
            file=sys.stderr,
        )
        return 3
    if args.preflight:
        if dirt:
            print(
                f"seal-bundle: preflight — dirty tree ACCEPTED under --allow-dirty "
                f"({len(dirt)} paths); the bundle will be stamped qualification=false"
            )
        else:
            print("seal-bundle: preflight — clean tree")
        return 0

    for req in (
        "evidence_dir",
        "provider",
        "server_bin",
        "server_sha256",
        "endpoint",
        "semantics_expected",
        "mp_rounds",
        "mp_procs",
        "racer",
    ):
        if getattr(args, req) in (None, ""):
            die(f"--{req.replace('_', '-')} is required to seal")

    evidence = pathlib.Path(args.evidence_dir).resolve()

    # ---- locks: copy the bytes in, so the bundle carries its own truth ---
    src_lock_path = repo / "source-lock" / "source-lock.json"
    ws_lock_path = repo / "source-lock" / "workspace-lock.json"
    for p in (src_lock_path, ws_lock_path):
        if not p.is_file():
            die(f"{p} absent — cannot bind provider identity")
    shutil.copyfile(src_lock_path, evidence / "source-lock.json")
    shutil.copyfile(ws_lock_path, evidence / "workspace-lock.json")
    locks = {
        "source_lock_path": str(src_lock_path.relative_to(repo)),
        "source_lock_sha256": sha256_file(src_lock_path),
        "source_lock_copy": "source-lock.json",
        "workspace_lock_path": str(ws_lock_path.relative_to(repo)),
        "workspace_lock_sha256": sha256_file(ws_lock_path),
        "workspace_lock_copy": "workspace-lock.json",
    }
    lock_doc = json.loads(src_lock_path.read_text())
    ws_doc = json.loads(ws_lock_path.read_text())
    if ws_doc.get("source_lock_sha256") != locks["source_lock_sha256"]:
        die(
            "workspace-lock.json does not bind the current source-lock.json bytes "
            f"(binds {ws_doc.get('source_lock_sha256')}, actual {locks['source_lock_sha256']})"
        )

    # ---- provider identity: RECOMPUTED, matched to the locked node -------
    node_id = PROVIDER_LOCK_NODE.get(args.provider)
    if node_id is None:
        die(f"provider {args.provider!r} has no source-lock node mapping")
    node = lock_node(lock_doc, node_id)
    server_bin = pathlib.Path(args.server_bin)
    if not server_bin.is_file():
        die(f"provider binary absent at {server_bin}")
    recomputed = sha256_file(server_bin)
    if recomputed != node.get("sha256"):
        die(
            f"provider binary digest {recomputed} != source-lock {node_id} sha256 "
            f"{node.get('sha256')} — a verdict may only cite the pinned artifact"
        )
    if args.server_sha256 != recomputed:
        die(
            f"caller claimed --server-sha256 {args.server_sha256} but the bytes at "
            f"{server_bin} hash to {recomputed}"
        )
    provider = {
        "name": args.provider,
        "source_lock_node": node_id,
        "binary_path": str(server_bin),
        "binary_sha256_recomputed": recomputed,
        "binary_sha256_claimed": args.server_sha256,
        "source_lock_sha256": node.get("sha256"),
        "url": node.get("url"),
        "version": node.get("version"),
        "endpoint": args.endpoint,
        "digest_binding": "recomputed-from-bytes-and-matched-to-source-lock",
    }

    # ---- source identity + clean-tree proof ------------------------------
    porcelain = git(repo, "status", "--porcelain", "--untracked-files=all")
    source = {
        "repo_root": str(repo),
        "git_head": git(repo, "rev-parse", "HEAD"),
        "git_tree": git(repo, "rev-parse", "HEAD^{tree}"),
        "git_branch": git(repo, "rev-parse", "--abbrev-ref", "HEAD"),
        "clean": not dirt,
        "dirty_paths": dirt,
        "status_porcelain_sha256": hashlib.sha256(porcelain.encode()).hexdigest(),
        "clean_tree_proof": "git status --porcelain --untracked-files=all",
    }

    # ---- corpus content root --------------------------------------------
    files = corpus_source_files(repo)
    corpus_source = {
        "set": (
            f"{CORPUS_REL}: Cargo.toml, Cargo.lock, ./*.py, ./*.sh, src/** "
            "(excluding target/, evidence/, __pycache__/)"
        ),
        "files": files,
        "root": rollup(files.items()),
    }

    # ---- executed machinery ---------------------------------------------
    racer = pathlib.Path(args.racer)
    if not racer.is_file():
        die(f"cas_racer absent at {racer} — the decisive CAS evidence has no executable identity")
    # each toolchain version is resolved EXACTLY ONCE and reused: under load a
    # rustup proxy call is expensive, and two calls could in principle disagree.
    rustc_version = run(["rustc", "+1.93.0", "--version"])
    cargo_version = run(["cargo", "+1.93.0", "--version"])
    executables = [
        {
            "name": "provider",
            "path": str(server_bin),
            "sha256": recomputed,
            "required": True,
            "version": node.get("version"),
        },
        {
            "name": "cas_racer",
            "path": str(racer),
            "sha256": sha256_file(racer),
            "required": True,
            "version": None,
        },
        tool_record("cargo", cargo_version),
        tool_record("rustc", rustc_version),
        tool_record(sys.executable, sys.version.split()[0]),
        tool_record("git", None),
    ]

    # ---- toolchain -------------------------------------------------------
    lock_text = (repo / CORPUS_REL / "Cargo.lock").read_text()
    lines = lock_text.splitlines()
    object_store_version = None
    for i, line in enumerate(lines):
        if line == 'name = "object_store"':
            object_store_version = lines[i + 1].split('"')[1]
    toolchain = {
        "rustc": rustc_version,
        "cargo": cargo_version,
        "object_store": object_store_version,
        "cargo_target_dir": args.cargo_target_dir,
        "target_dir_resolution": "cargo metadata / --message-format=json (never hardcoded)",
    }
    host = {
        "uname": run(["uname", "-srmo"]),
        "platform": sys.platform,
        "python": sys.version.split()[0],
    }

    # ---- structured phases ----------------------------------------------
    phases = []
    mp_json_path = evidence / "phase1b.json"
    mp_structured = json.loads(mp_json_path.read_text()) if mp_json_path.is_file() else None
    for line in (evidence / "phases.tsv").read_text().splitlines():
        name, exit_code, log_file, detail = line.split("\t", 3)
        log_path = evidence / log_file
        rec = {
            "name": name,
            "exit_code": int(exit_code),
            "verdict": "PASS" if exit_code == "0" else "FAIL",
            "log": log_file,
            "log_sha256": sha256_file(log_path) if log_path.exists() else None,
            "detail": detail,
        }
        if name in ("semantics", "post-restart") and log_path.exists():
            parsed = parse_cargo_test_log(log_path.read_text(errors="replace"))
            rec["results"] = parsed
            rec["summary"] = {
                "kind": "cargo-test",
                "tests": [t["name"] for t in parsed["tests"]],
                "passed": parsed["passed"],
                "failed": parsed["failed"],
            }
        elif name == "mp-cas":
            if mp_structured is None:
                die("phase1b.json absent — mp-cas has no structured result")
            rounds = mp_structured["rounds"]
            rec["results"] = mp_structured
            rec["summary"] = {
                "kind": "mp-cas",
                "rounds": len(rounds),
                "procs": mp_structured["procs"],
                "winners_total": sum(r["winners"] for r in rounds),
                "losers_total": sum(r["losers"] for r in rounds),
                "overwrites_total": sum(r["overwrites"] for r in rounds),
                "errors_total": sum(r["errors"] for r in rounds),
            }
        elif name == "crash-restart":
            rec["summary"] = {
                "kind": "crash-restart",
                "signal": "SIGKILL",
                "restarted_same_data_dir": True,
            }
        else:
            rec["summary"] = {"kind": "other"}
        phases.append(rec)

    got_phases = tuple(p["name"] for p in phases)
    if got_phases != REQUIRED_PHASES:
        die(
            f"phase list {got_phases} != required {REQUIRED_PHASES} — a truncated corpus "
            "cannot be sealed"
        )

    commands = []
    cmd_path = evidence / "commands.jsonl"
    if cmd_path.is_file():
        commands = [json.loads(line) for line in cmd_path.read_text().splitlines() if line.strip()]

    bundle = {
        "schema": SCHEMA,
        "sealed_at": datetime.now(timezone.utc).isoformat(),
        "qualification": not dirt,
        "qualification_disqualifiers": (
            []
            if not dirt
            else [f"dirty-tree: {len(dirt)} path(s) not committed at seal time (--allow-dirty)"]
        ),
        "provider": provider,
        "source": source,
        "corpus_source": corpus_source,
        "locks": locks,
        "toolchain": toolchain,
        "host": host,
        "environment": capture_environment(),
        "executables": executables,
        "commands": commands,
        "corpus": {
            "semantics_expected": args.semantics_expected,
            "mp_rounds": args.mp_rounds,
            "mp_procs": args.mp_procs,
            "required_phases": list(REQUIRED_PHASES),
        },
        "phases": phases,
        "artifacts": {},
    }
    bundle["attestation"] = {
        "attested_by": "tools/s3-cert-corpus/run-corpus.sh via seal-bundle.py",
        "runner_host": run(["hostname"]) or "unknown",
        "statement": (
            "the phases below were executed by this runner against the provider "
            "binary named above, from the corpus source whose content root is "
            "recorded here"
        ),
        "stable_root": stable_root(bundle),
        "stable_root_excludes": [
            "sealed_at",
            "pids",
            "ports",
            "temp paths",
            "log digests",
            "build-path-dependent artifact digests",
            "git identity",
        ],
    }

    for path in sorted(evidence.iterdir()):
        if path.name in ("bundle.json", "root.txt") or not path.is_file():
            continue
        bundle["artifacts"][path.name] = sha256_file(path)

    (evidence / "bundle.json").write_text(json.dumps(bundle, indent=1, sort_keys=False) + "\n")

    names = sorted([*bundle["artifacts"].keys(), "bundle.json"])
    root = rollup((n, sha256_file(evidence / n)) for n in names)
    (evidence / "root.txt").write_text(root + "\n")

    stamp = "QUALIFICATION" if bundle["qualification"] else "NON-QUALIFICATION (dirty tree)"
    print(f"seal-bundle: sealed {len(names)} artifacts [{stamp}]")
    print(f"seal-bundle:   corpus source root {corpus_source['root']}")
    print(f"seal-bundle:   stable root        {bundle['attestation']['stable_root']}")
    print(f"seal-bundle:   artifact root      {root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
