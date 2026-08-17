# G0 evidence — storage note

The push channel for this repository is the GitHub MCP API (direct
`git push` returns an org-policy 403 in this environment), which cannot
carry multi-megabyte raw artifacts. Therefore:

- `cloudflare-docs/SHA256SUMS` pins the exact retrieved bytes of every
  Cloudflare contract page (13 pages, retrieved 2026-08-16). The raw HTML
  bytes are archived in the session workspace at
  `docs/evidence/G0/cloudflare-docs/*.html` and are re-verifiable by
  re-retrieval + hash comparison against SHA256SUMS.
- `parity-build.json` carries the full-log SHA-256
  (`u0-parity-build.log`, retained raw in the session workspace).
- The unpacked contract package is not duplicated in git: it is bit-exact
  reproducible from `typedb-r2-implementation-package.zip` (committed at
  repo root; per-file SHA-256 in the zip's PACKAGE-MANIFEST.json).

Deviation recorded as stop-item SI-G0-5 in stop-items.json: raw bytes are
session-archived rather than repo-committed until a bulk push channel is
available.
