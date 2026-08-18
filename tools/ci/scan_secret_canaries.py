#!/usr/bin/env python3
"""Secret canary scanner over evidence trees (round-3 audit finding P-01).

Scans one or more directory trees (probe evidence bundles, self-test
output, logs) for:

  - configured CANARY markers (the mock provider mints credentials whose
    values embed "CANARY"; any hit means the evidence redaction pipeline
    regressed);
  - common credential value shapes:
      AWS-style access key ids   (AKIA|ASIA|AGPA|AROA|AIPA|ANPA + 16)
      bearer tokens              (Bearer <long-token>)
      JWTs                       (eyJ….…​.… three base64url segments)
      PEM private-key headers    (-----BEGIN … PRIVATE KEY-----)
      SigV4 authorization values (AWS4-HMAC-SHA256 Credential=…)

Fail-closed:
  - any hit                          -> exit 1, every hit printed path:line
  - a named directory that does not  -> exit 2 (a scanner pointed at
    exist or contains no files          nothing must never look green)
  - unreadable file                  -> exit 2

Usage:
  python3 tools/ci/scan_secret_canaries.py <dir> [<dir>...]
          [--canary EXTRA_MARKER]... [--max-bytes N]
"""
import argparse
import pathlib
import re
import sys

DEFAULT_CANARIES = ["CANARY"]

SHAPES: list[tuple[str, re.Pattern[bytes]]] = [
    ("aws-key-id", re.compile(rb"\b(?:AKIA|ASIA|AGPA|AROA|AIPA|ANPA)[0-9A-Z]{16}\b")),
    ("bearer-token", re.compile(rb"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("jwt", re.compile(rb"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b")),
    ("pem-private-key", re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("sigv4-authorization", re.compile(rb"\bAWS4-HMAC-SHA256\s+Credential=")),
    ("aws-secret-assignment", re.compile(rb"(?i)aws_secret_access_key\s*[=:]\s*\S+")),
]


def scan_file(path: pathlib.Path, canaries: list[re.Pattern[bytes]], max_bytes: int) -> list[str]:
    hits: list[str] = []
    data = path.read_bytes()[:max_bytes]
    patterns = [("canary", p) for p in canaries] + SHAPES
    for lineno, line in enumerate(data.split(b"\n"), start=1):
        for tag, pat in patterns:
            m = pat.search(line)
            if m:
                # Print WHERE, never the full secret: a scanner must not
                # itself copy the credential into CI logs.
                snippet = m.group(0)[:12].decode("utf-8", "replace")
                hits.append(f"{path}:{lineno}: [{tag}] starts with {snippet!r}…")
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dirs", nargs="+", type=pathlib.Path)
    parser.add_argument("--canary", action="append", default=[],
                        help="extra canary marker (literal, case-sensitive)")
    parser.add_argument("--max-bytes", type=int, default=32 * 1024 * 1024,
                        help="per-file scan cap (default 32 MiB)")
    args = parser.parse_args()

    canaries = [re.compile(re.escape(c.encode())) for c in DEFAULT_CANARIES + args.canary]

    all_hits: list[str] = []
    scanned = 0
    for d in args.dirs:
        if not d.is_dir():
            print(f"SECRET-SCAN: FAIL-CLOSED — directory does not exist: {d}")
            return 2
        files = [p for p in sorted(d.rglob("*")) if p.is_file()]
        if not files:
            print(f"SECRET-SCAN: FAIL-CLOSED — directory contains no files to scan: {d}")
            return 2
        for f in files:
            try:
                all_hits.extend(scan_file(f, canaries, args.max_bytes))
            except OSError as error:
                print(f"SECRET-SCAN: FAIL-CLOSED — unreadable file {f}: {error}")
                return 2
            scanned += 1

    if all_hits:
        print(f"SECRET-SCAN: FAIL — {len(all_hits)} credential-shaped hit(s) across {scanned} file(s):")
        for h in all_hits:
            print(f"  {h}")
        return 1
    print(f"SECRET-SCAN: PASS — {scanned} file(s) scanned, zero canaries / credential shapes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
