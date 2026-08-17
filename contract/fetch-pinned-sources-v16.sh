#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-sources-v16}"
mkdir -p "$ROOT"
ROOT="$(cd "$ROOT" && pwd)"

fetch_git() {
  local name="$1" repo="$2" rev="$3"
  local dst="$ROOT/$name"
  if [[ -d "$dst/.git" ]]; then
    git -C "$dst" remote set-url origin "$repo"
    git -C "$dst" fetch --force --tags origin "$rev"
  else
    git clone --filter=blob:none --no-checkout "$repo" "$dst"
    git -C "$dst" fetch --force --tags origin "$rev"
  fi
  git -C "$dst" checkout --detach "$rev"
  git -C "$dst" submodule update --init --recursive
  git -C "$dst" fsck --connectivity-only
  test -z "$(git -C "$dst" status --porcelain)"
}

fetch_codeload_commit() {
  local name="$1" orgrepo="$2" rev="$3"
  local archive="$ROOT/${name}-${rev}.tar.gz"
  local dst="$ROOT/$name"
  curl --fail --location --retry 5 --retry-all-errors \
    "https://codeload.github.com/${orgrepo}/tar.gz/${rev}" \
    --output "$archive"
  rm -rf "$dst"
  mkdir -p "$dst"
  tar -xzf "$archive" --strip-components=1 -C "$dst"
  printf '%s\n' "$rev" > "$dst/.source-revision"
  sha256sum "$archive" > "$archive.sha256"
}

fetch_with_fallback() {
  local name="$1" orgrepo="$2" rev="$3"
  local repo="https://github.com/${orgrepo}.git"
  if ! fetch_git "$name" "$repo" "$rev"; then
    echo "git fetch failed for $name; using codeload archive" >&2
    fetch_codeload_commit "$name" "$orgrepo" "$rev"
  fi
}

fetch_tag_and_resolve() {
  local name="$1" orgrepo="$2" tag="$3"
  local repo="https://github.com/${orgrepo}.git"
  local dst="$ROOT/$name"
  if [[ ! -d "$dst/.git" ]]; then
    git clone --filter=blob:none --no-checkout "$repo" "$dst"
  fi
  git -C "$dst" fetch --force --tags origin "refs/tags/${tag}:refs/tags/${tag}"
  local rev
  rev="$(git -C "$dst" rev-list -n1 "$tag")"
  git -C "$dst" checkout --detach "$rev"
  git -C "$dst" fsck --connectivity-only
  printf '%s %s\n' "$tag" "$rev" > "$dst/.resolved-tag"
}

fetch_with_fallback typedb typedb/typedb 2256711abd532742dae8e822a9ad5cce63e69b1a
fetch_with_fallback slatedb slatedb/slatedb f88be86d17ac53260d3684edbc8f82811d945b5c
fetch_with_fallback typedb-behaviour typedb/typedb-behaviour ac5d5733a484cea1d8809a2968029a818fdae24f
fetch_with_fallback typedb-dependencies typedb/dependencies a5c51254088f343fb8b6a9668eaf99b35503dad4
fetch_with_fallback typedb-bazel-distribution typedb/bazel-distribution ab5bfc90274e2d34569d5bc22558314b551cdecd
fetch_tag_and_resolve typeql typedb/typeql 3.12.2
fetch_tag_and_resolve typedb-protocol typedb/typedb-protocol 3.12.0

# Candidate Cloudflare sources. Resolve package-to-source identity separately from
# pnpm-lock/npm tarball integrity; do not assume main equals the package release.
fetch_git cloudflare-containers https://github.com/cloudflare/containers.git main
fetch_git cloudflare-workers-sdk https://github.com/cloudflare/workers-sdk.git c576a82 || true

cat > "$ROOT/UNRESOLVED.md" <<'EOF'
# G0 items that this script intentionally does not guess

- Full source commit corresponding to @cloudflare/containers 0.3.7.
- Full workers-sdk commit for short release id c576a82.
- npm tarball integrity for Wrangler, Containers, Vitest pool, Miniflare, workerd.
- Exact TypeDB Console 3.12.0 Linux x86-64 URL, SHA-256 and licence.
- Whether Loader 3.12.0 is applicable to the selected upstream corpus.
- OCI digest for typedb/ubuntu:3.1.0-amd64 and the chosen production base.
- Native compiler/linker/CMake/protoc/pkg-config/libc/TLS-root digests.
- Cloudflare documentation byte hashes and real-account probe evidence.
EOF

python3 - "$ROOT" <<'PY'
import hashlib, json, os, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
records = []
for child in sorted(root.iterdir()):
    if not child.is_dir():
        continue
    if (child / ".git").exists():
        rev = subprocess.check_output(["git","-C",str(child),"rev-parse","HEAD"], text=True).strip()
        tree = subprocess.check_output(["git","-C",str(child),"rev-parse","HEAD^{tree}"], text=True).strip()
        dirty = bool(subprocess.check_output(["git","-C",str(child),"status","--porcelain"], text=True).strip())
        records.append({"name":child.name,"kind":"git","revision":rev,"tree":tree,"dirty":dirty})
    elif (child / ".source-revision").exists():
        records.append({"name":child.name,"kind":"archive","revision":(child/".source-revision").read_text().strip()})
(root / "resolved-sources.json").write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
PY

echo "Sources written to $ROOT"
