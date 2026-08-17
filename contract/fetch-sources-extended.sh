#!/usr/bin/env bash
# Extended source graph (addendum A17.5 + owner directive "clone every mentioned repo,
# plus the Cloudflare OSS implementations and the Cloudflare docs, verify at source").
#
# This script is ADDITIVE to fetch-pinned-sources-v16.sh; run that one first.
# Every node here is recorded with a full immutable commit in sources/resolved-sources-extended.json.
set -euo pipefail

ROOT="${1:-sources}"
mkdir -p "$ROOT"
ROOT="$(cd "$ROOT" && pwd)"

# Pinned checkout at an exact revision (full history, blobless).
fetch_pinned() {
  local name="$1" orgrepo="$2" rev="$3"
  local dst="$ROOT/$name" repo="https://github.com/${orgrepo}.git"
  if [[ ! -d "$dst/.git" ]]; then
    git clone --filter=blob:none --no-checkout "$repo" "$dst"
  fi
  git -C "$dst" fetch --force --tags origin "$rev"
  git -C "$dst" checkout --detach "$rev"
  git -C "$dst" fsck --connectivity-only
}

# Tag -> full commit, recorded.
fetch_tag() {
  local name="$1" orgrepo="$2" tag="$3"
  local dst="$ROOT/$name" repo="https://github.com/${orgrepo}.git"
  if [[ ! -d "$dst/.git" ]]; then
    git clone --filter=blob:none --no-checkout "$repo" "$dst"
  fi
  git -C "$dst" fetch --force --tags origin "refs/tags/${tag}:refs/tags/${tag}"
  local rev; rev="$(git -C "$dst" rev-list -n1 "$tag")"
  git -C "$dst" checkout --detach "$rev"
  git -C "$dst" fsck --connectivity-only
  printf '%s %s\n' "$tag" "$rev" > "$dst/.resolved-tag"
}

# Reference corpora we read but do not ship: single-commit snapshot, commit still recorded.
fetch_snapshot() {
  local name="$1" orgrepo="$2" ref="${3:-HEAD}"
  local dst="$ROOT/$name" repo="https://github.com/${orgrepo}.git"
  if [[ -d "$dst/.git" ]]; then
    git -C "$dst" fetch --depth 1 origin "$ref"
    git -C "$dst" checkout --detach FETCH_HEAD
  else
    git clone --depth 1 "$repo" "$dst"
  fi
  printf '%s\n' "$(git -C "$dst" rev-parse HEAD)" > "$dst/.snapshot-revision"
}

# --- A17.5: the official polyglot driver monorepo, at the release matching the server pin.
# fork/typedb VERSION at commit 2256711a is 3.12.3 -> driver tag 3.12.3.
fetch_tag typedb-driver typedb/typedb-driver 3.12.3

# --- Cloudflare open-source implementations (ground truth for platform semantics).
# workerd: the Workers runtime itself - R2 bindings, Durable Object storage/alarms, containers.
fetch_snapshot cloudflare-workerd cloudflare/workerd
# Official documentation source (markdown), so platform claims cite bytes we hold.
fetch_snapshot cloudflare-docs cloudflare/cloudflare-docs
# Cloudflare API / R2 OpenAPI schemas.
fetch_snapshot cloudflare-api-schemas cloudflare/api-schemas

python3 - "$ROOT" <<'PY'
import json, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
records = []
for child in sorted(root.iterdir()):
    if not child.is_dir() or not (child / ".git").exists():
        continue
    g = lambda *a: subprocess.check_output(["git", "-C", str(child), *a], text=True).strip()
    rec = {
        "name": child.name,
        "revision": g("rev-parse", "HEAD"),
        "tree": g("rev-parse", "HEAD^{tree}"),
        "shallow": (child / ".git" / "shallow").exists(),
    }
    if (child / ".resolved-tag").exists():
        rec["tag"] = (child / ".resolved-tag").read_text().split()[0]
    # Untracked marker files this fetcher writes are not source drift.
    dirty = [l for l in g("status", "--porcelain").splitlines()
             if l.split()[-1] not in (".resolved-tag", ".snapshot-revision", ".source-revision")]
    rec["dirty"] = bool(dirty)
    records.append(rec)
(root / "resolved-sources-extended.json").write_text(
    json.dumps(records, indent=2, sort_keys=True) + "\n")
print(json.dumps(records, indent=2, sort_keys=True))
PY
