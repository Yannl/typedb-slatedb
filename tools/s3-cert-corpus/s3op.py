#!/usr/bin/env python3
"""Minimal SigV4 S3 operations for the certification runner (stdlib only).

Usage:
  AWS_ACCESS_KEY_ID=.. AWS_SECRET_ACCESS_KEY=.. \
    python3 s3op.py <endpoint> list-buckets
    python3 s3op.py <endpoint> create-bucket <name>

Readiness policy (round-4 R4-LOCAL-01): the runner treats ONLY a
successful AUTHENTICATED S3 operation as ready — never a /health
endpoint, which RustFS has been observed to answer before storage quorum.
"""
import datetime
import hashlib
import hmac
import os
import sys
import urllib.request
import urllib.error


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sigv4_request(endpoint: str, method: str, path: str, body: bytes = b"") -> int:
    access = os.environ["AWS_ACCESS_KEY_ID"]
    secret = os.environ["AWS_SECRET_ACCESS_KEY"]
    host = endpoint.split("://", 1)[1]
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()
    headers = {
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    signed = ";".join(sorted(headers))
    canonical = "\n".join([
        method, path, "",
        *(f"{k}:{headers[k]}" for k in sorted(headers)), "",
        signed, payload_hash,
    ])
    scope = f"{date}/auto/s3/aws4_request"
    to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        hashlib.sha256(canonical.encode()).hexdigest(),
    ])
    k = _sign(_sign(_sign(_sign(("AWS4" + secret).encode(), date), "auto"), "s3"), "aws4_request")
    signature = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access}/{scope}, "
        f"SignedHeaders={signed}, Signature={signature}"
    )
    req = urllib.request.Request(endpoint + path, data=body or None, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            return res.status
    except urllib.error.HTTPError as e:
        return e.code


def main() -> int:
    endpoint, op = sys.argv[1], sys.argv[2]
    if op == "list-buckets":
        status = sigv4_request(endpoint, "GET", "/")
        return 0 if status == 200 else 1
    if op == "create-bucket":
        status = sigv4_request(endpoint, "PUT", f"/{sys.argv[3]}")
        # 200 created; 409 already-owned is fine for an idempotent runner
        return 0 if status in (200, 409) else 1
    print(f"unknown op {op}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
