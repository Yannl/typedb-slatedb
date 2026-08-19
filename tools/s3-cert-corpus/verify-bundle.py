#!/usr/bin/env python3
"""Independent verifier for a sealed corpus evidence bundle (R5-LOCAL-03).

Shares no code with seal-bundle.py beyond the documented format. Checks:
  - root.txt equals the recomputed rollup over sorted (name, sha256)
    including bundle.json;
  - every artifact digest in bundle.json matches the file bytes;
  - every phase has verdict PASS and exit_code 0;
  - the mandatory phases are all present (semantics, mp-cas,
    crash-restart, post-restart);
  - the semantics log actually contains the expected executed-test count
    (a bundle whose log says fewer tests cannot verify);
  - the provider binary digest field is a 64-hex value.
Exit nonzero on any failure.
"""
import hashlib
import json
import pathlib
import re
import sys


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    evidence = pathlib.Path(sys.argv[1])
    failures = []

    bundle = json.loads((evidence / "bundle.json").read_text())
    if bundle.get("schema") != "s3-cert-corpus-bundle/v1":
        failures.append(f"unknown schema {bundle.get('schema')!r}")

    for name, want in bundle.get("artifacts", {}).items():
        path = evidence / name
        if not path.exists():
            failures.append(f"artifact {name} missing")
            continue
        got = sha256_file(path)
        if got != want:
            failures.append(f"artifact {name} digest mismatch: want {want} got {got}")

    rollup = hashlib.sha256()
    names = sorted([*bundle.get("artifacts", {}).keys(), "bundle.json"])
    for name in names:
        rollup.update(f"{name}\n{sha256_file(evidence / name)}\n".encode())
    recorded_root = (evidence / "root.txt").read_text().strip()
    if recorded_root != rollup.hexdigest():
        failures.append(f"root mismatch: recorded {recorded_root} recomputed {rollup.hexdigest()}")

    phases = {p["name"]: p for p in bundle.get("phases", [])}
    for required in ("semantics", "mp-cas", "crash-restart", "post-restart"):
        p = phases.get(required)
        if p is None:
            failures.append(f"mandatory phase {required} absent")
        elif p.get("verdict") != "PASS" or p.get("exit_code") != 0:
            failures.append(f"phase {required} is not PASS/0: {p}")

    expected = bundle.get("corpus", {}).get("semantics_expected")
    log = evidence / "phase1.log"
    if not isinstance(expected, int):
        failures.append("corpus.semantics_expected absent")
    elif log.exists():
        if not re.search(rf"test result: ok\. {expected} passed", log.read_text(errors="replace")):
            failures.append(f"phase1.log does not show {expected} executed tests passing")
    else:
        failures.append("phase1.log absent")

    sha = bundle.get("provider", {}).get("binary_sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", sha):
        failures.append(f"provider binary_sha256 not 64-hex: {sha!r}")

    if failures:
        print("BUNDLE VERIFY: FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"BUNDLE VERIFY: PASS ({len(names)} artifacts, root {recorded_root[:16]}…)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
