#!/usr/bin/env python3
"""Report-only GC for orphaned keyspace materialisations (V16 F3, inv. 105).

The storage runtime NEVER deletes remote objects (inv. 84 — its store
handle structurally lacks delete authority). Every superseded or retired
materialisation therefore remains in the bucket as orphan bytes (inv. 83).
This tool is the SEPARATED maintenance principal that accounts for them:

    python3 tools/maintenance/s3_gc.py               # report (the only mode that exists)
    python3 tools/maintenance/s3_gc.py --delete m... # REFUSED before G13 (Q-25): no delete
                                                     # implementation exists in this file

Report mode lists, per keyspace prefix, every materialisation with object
count, bytes, and last-modified — and NEVER issues a delete. Delete mode
refuses to run unless BOTH of the following hold, keeping the authority
separation auditable pre-G13:

  - the operator names explicit materialisation ids (no --all exists; the
    operator states exactly what dies, the tool never infers "orphaned"
    into "deletable");
  - TYPEDB_S3_MAINT_ACCESS_KEY_ID / TYPEDB_S3_MAINT_SECRET_ACCESS_KEY are
    set — a credential DISTINCT from the runtime's TYPEDB_S3_ACCESS_KEY_ID,
    so the runtime principal's key material can never reach a delete call
    even through this tool.

S3 access goes through curl --aws-sigv4 (the same mechanism the local-dev
docs use for bucket administration), so the tool works against MinIO and
R2 alike without extra Python dependencies.
"""

import argparse
import os
import subprocess
import sys
import urllib.parse
import xml.etree.ElementTree as ET

NS = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}


def env(name, default=None):
    value = os.environ.get(name, default)
    if value is None:
        sys.exit(f"{name} must be set")
    return value


def s3_request(endpoint, bucket, region, key_id, secret, method, path="", query=None):
    url = f"{endpoint}/{bucket}"
    if path:
        url += "/" + urllib.parse.quote(path)
    if query:
        url += "?" + urllib.parse.urlencode(query)
    result = subprocess.run(
        [
            "curl", "-sS", "--fail-with-body", "-X", method, url,
            "--user", f"{key_id}:{secret}",
            "--aws-sigv4", f"aws:amz:{region}:s3",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.exit(f"S3 {method} {url} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def list_all(endpoint, bucket, region, key_id, secret, prefix):
    """Every (key, size, last_modified) under prefix, across pages."""
    token = None
    while True:
        query = {"list-type": "2", "prefix": prefix, "max-keys": "1000"}
        if token:
            query["continuation-token"] = token
        body = s3_request(endpoint, bucket, region, key_id, secret, "GET", query=query)
        root = ET.fromstring(body)
        for contents in root.findall("s3:Contents", NS):
            yield (
                contents.findtext("s3:Key", namespaces=NS),
                int(contents.findtext("s3:Size", default="0", namespaces=NS)),
                contents.findtext("s3:LastModified", namespaces=NS),
            )
        token = root.findtext("s3:NextContinuationToken", namespaces=NS)
        if not token:
            return


def materialization_of(key, root_prefix):
    """Split `<root>/<keyspace>/<fv>/<materialisation>/…` or None."""
    if not key.startswith(root_prefix + "/"):
        return None
    parts = key[len(root_prefix) + 1 :].split("/")
    if len(parts) < 4 or not parts[2].startswith("m"):
        return None
    keyspace, format_version, materialization = parts[0], parts[1], parts[2]
    return keyspace, format_version, materialization


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--delete",
        nargs="+",
        metavar="MATERIALIZATION_ID",
        help="delete every object of the NAMED materialisation ids; requires the maintenance credential",
    )
    args = parser.parse_args()

    if args.delete:
        # ------------------------------------------------------------------
        # Q-25 (P0 pre-G13): physical deletion is NOT AVAILABLE in this
        # release line, and the refusal is unconditional.
        #
        # A separated maintenance credential is a NECESSARY precondition for
        # deletion, never a sufficient one. Before an object of an
        # authoritative namespace may be destroyed the contract requires all
        # of: proved unreachability from every live catalogue/manifest root,
        # a pin against a concurrent restore, retention/legal clearance, a
        # recorded approval, an IAM principal whose credential ancestry
        # cannot reach the runtime, and a proven restore path. G13 is the
        # gate that builds those; until it exists, a tool that deletes
        # whenever a credential check happens to pass is a shipped path to
        # erasing authoritative state (inv. 84).
        #
        # The delete IMPLEMENTATION is gone, not merely guarded: there is no
        # DELETE request anywhere in this file, so no flag, environment
        # variable or code path can make one effective. The flag itself is
        # retained so that reaching for it produces this explanation rather
        # than sending an operator looking for another tool.
        sys.exit(
            "REFUSED: physical deletion is unavailable before G13.\n"
            "  missing gate record: docs/evidence/G13/delete-authority-gate.json\n"
            "  required and absent: reachability closure over every live catalogue/manifest\n"
            "    root; restore pin; retention/legal clearance; recorded approval; separated\n"
            "    IAM principal with no runtime credential ancestry; proven restore path.\n"
            "  this tool contains no delete implementation at all - the G13 work adds one\n"
            "    behind that gate, it is not being suppressed by a flag here.\n"
            "  available today: report mode (no arguments) - inventory only."
        )


    endpoint = env("TYPEDB_S3_ENDPOINT")
    bucket = env("TYPEDB_S3_BUCKET")
    region = os.environ.get("TYPEDB_S3_REGION", "auto")
    root_prefix = os.environ.get("TYPEDB_S3_PREFIX", "typedb")

    # report mode: the runtime read credential suffices; no delete is ever issued
    key_id = env("TYPEDB_S3_ACCESS_KEY_ID")
    secret = env("TYPEDB_S3_SECRET_ACCESS_KEY")
    per_materialization = {}
    for key, size, mtime in list_all(endpoint, bucket, region, key_id, secret, root_prefix + "/"):
        split = materialization_of(key, root_prefix)
        if not split:
            continue
        entry = per_materialization.setdefault(split, {"objects": 0, "bytes": 0, "last_modified": ""})
        entry["objects"] += 1
        entry["bytes"] += size
        entry["last_modified"] = max(entry["last_modified"], mtime or "")

    if not per_materialization:
        print(f"no materialisations under {root_prefix}/")
        return
    print(f"{'keyspace':<40} {'materialisation':<64} {'objects':>8} {'bytes':>14} last-modified")
    for (keyspace, format_version, materialization), entry in sorted(per_materialization.items()):
        print(
            f"{keyspace[:40]:<40} {format_version + '/' + materialization:<64} "
            f"{entry['objects']:>8} {entry['bytes']:>14} {entry['last_modified']}"
        )
    print(
        f"\n{len(per_materialization)} materialisations. This report is the ONLY default action; "
        "deletion requires --delete with explicit ids and the separated maintenance credential."
    )


if __name__ == "__main__":
    main()
