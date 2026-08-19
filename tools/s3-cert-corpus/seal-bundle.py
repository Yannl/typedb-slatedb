#!/usr/bin/env python3
"""Seal the corpus evidence bundle (R5-LOCAL-03). Stdlib only.

Writes bundle.json (identity + config + per-phase records + per-artifact
digests) into the evidence dir, then root.txt = sha256 over the sorted
(name, sha256) list INCLUDING bundle.json. verify-bundle.py re-derives
everything with no shared code beyond the format.
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
from datetime import datetime, timezone


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("evidence_dir")
    ap.add_argument("--provider", required=True)
    ap.add_argument("--server-bin", required=True)
    ap.add_argument("--server-sha256", required=True)
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--semantics-expected", type=int, required=True)
    ap.add_argument("--mp-rounds", type=int, required=True)
    ap.add_argument("--mp-procs", type=int, required=True)
    args = ap.parse_args()

    evidence = pathlib.Path(args.evidence_dir)
    repo = pathlib.Path(args.repo)

    phases = []
    tsv = evidence / "phases.tsv"
    for line in tsv.read_text().splitlines():
        name, exit_code, log_file, detail = line.split("\t", 3)
        log_path = evidence / log_file
        phases.append({
            "name": name,
            "exit_code": int(exit_code),
            "verdict": "PASS" if exit_code == "0" else "FAIL",
            "log": log_file,
            "log_sha256": sha256_file(log_path) if log_path.exists() else None,
            "detail": detail,
        })

    def git(*argv: str) -> str:
        return subprocess.run(["git", "-C", str(repo), *argv], capture_output=True, text=True, check=True).stdout.strip()

    rustc = subprocess.run(["rustc", "+1.93.0", "--version"], capture_output=True, text=True).stdout.strip()
    lock = (pathlib.Path(__file__).parent / "Cargo.lock").read_text()
    object_store_version = None
    lines = lock.splitlines()
    for i, line in enumerate(lines):
        if line == 'name = "object_store"':
            object_store_version = lines[i + 1].split('"')[1]

    bundle = {
        "schema": "s3-cert-corpus-bundle/v1",
        "sealed_at": datetime.now(timezone.utc).isoformat(),
        "provider": {
            "name": args.provider,
            "binary_path": args.server_bin,
            "binary_sha256": args.server_sha256,
            "endpoint": args.endpoint,
        },
        "source": {
            "git_head": git("rev-parse", "HEAD"),
            "dirty_paths": len([l for l in git("status", "--porcelain").splitlines() if l.strip()]),
            "source_lock_sha256": sha256_file(repo / "source-lock" / "source-lock.json"),
        },
        "toolchain": {"rustc": rustc, "object_store": object_store_version},
        "corpus": {
            "semantics_expected": args.semantics_expected,
            "mp_rounds": args.mp_rounds,
            "mp_procs": args.mp_procs,
        },
        "phases": phases,
        "artifacts": {},
    }

    for path in sorted(evidence.iterdir()):
        if path.name in ("bundle.json", "root.txt") or not path.is_file():
            continue
        bundle["artifacts"][path.name] = sha256_file(path)

    (evidence / "bundle.json").write_text(json.dumps(bundle, indent=1) + "\n")

    rollup = hashlib.sha256()
    names = sorted([*bundle["artifacts"].keys(), "bundle.json"])
    for name in names:
        rollup.update(f"{name}\n{sha256_file(evidence / name)}\n".encode())
    (evidence / "root.txt").write_text(rollup.hexdigest() + "\n")
    print(f"seal-bundle: sealed {len(names)} artifacts, root {rollup.hexdigest()[:16]}…")
    return 0


if __name__ == "__main__":
    sys.exit(main())
