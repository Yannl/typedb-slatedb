#!/usr/bin/env bash
# Materialize the federated fork workspaces (fork/typedb, fork/slatedb) as
# byte-identical imports of the pinned upstream trees (brief §21.1 / H.3).
# The trees are reproducible from the source lock, so they are not stored in
# this repository until fork-owned patches (TB-P*/SL-P*) diverge from upstream;
# at that point the patched trees (or patch series) become committed content.
# Provenance: fork/*/UPSTREAM-PROVENANCE, verified against source-lock.json.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$ROOT/fork/typedb" "$ROOT/fork/slatedb"
git -C "$ROOT/sources/typedb" archive 2256711abd532742dae8e822a9ad5cce63e69b1a | tar -x -C "$ROOT/fork/typedb"
git -C "$ROOT/sources/slatedb" archive f88be86d17ac53260d3684edbc8f82811d945b5c | tar -x -C "$ROOT/fork/slatedb"
# Apply fork patch series in stable order once they exist.
for series in "$ROOT"/fork/patches/typedb/*.patch; do
  [ -e "$series" ] || break
  patch -d "$ROOT/fork/typedb" -p1 < "$series"
done
for series in "$ROOT"/fork/patches/slatedb/*.patch; do
  [ -e "$series" ] || break
  patch -d "$ROOT/fork/slatedb" -p1 < "$series"
done
echo "fork workspaces materialized"
