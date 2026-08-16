#!/usr/bin/env bash
# Materialize the federated fork workspace (fork/typedb) as a byte-identical
# import of the pinned upstream tree (brief §21.1 / H.3).
# The tree is reproducible from the source lock, so it is not stored in
# this repository until fork-owned patches (TB-P*) diverge from upstream;
# at that point the patched tree (or patch series) becomes committed content.
# Provenance: fork/typedb/UPSTREAM-PROVENANCE, verified against source-lock.json.
#
# SlateDB is consume-only (ADR-0001): a crates.io dependency pinned by exact
# version + checksum in tools/Cargo.lock and source-lock.json node SL.
# There is no fork/slatedb workspace to materialize.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# The revision comes from the lock, never from this script: drift between the
# lock and the materialized tree is exactly what the lock exists to prevent.
TB_REV="$(python3 -c "
import json
nodes = json.load(open('$ROOT/source-lock/source-lock.json'))['nodes']
print(next(n['revision'] for n in nodes if n['id'] == 'TB'))
")"
mkdir -p "$ROOT/fork/typedb"
git -C "$ROOT/sources/typedb" archive "$TB_REV" | tar -x -C "$ROOT/fork/typedb"
# Apply fork patch series in stable order once they exist.
for series in "$ROOT"/fork/patches/typedb/*.patch; do
  [ -e "$series" ] || break
  patch -d "$ROOT/fork/typedb" -p1 < "$series"
done
echo "fork workspace materialized"
