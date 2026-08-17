# TypeDB on Cloudflare (SlateDB + R2) — implementation package

Self-contained handoff for the implementation agent. Product goal: run TypeDB (soft fork) with a pluggable storage backend — `classic` (RocksDB + file WAL, identical to upstream, used in local dev) or `slatedb-r2` (SlateDB keyspaces on Cloudflare R2, external WAL, per-database Durable Object controller) — behind rigorously unchanged public APIs, conforming to the entire upstream TypeDB test suite, deployed on Cloudflare Containers with zero-RPO durability.

Start with `AGENTS.md`, then `typedb-r2-v17-final-addendum.md` §A17.7 for the full reading order.

| File | Role |
|---|---|
| AGENTS.md | Agent operating instructions + environment bootstrap |
| typedb-r2-implementation-brief-v16.md | Normative architecture contract (invariants, protocols, gates) |
| typedb-r2-v17-final-addendum.md | Final decisions + product requirements (pluggability, driver compat); wins on conflict |
| typedb-r2-v16-implementation-playbook.md | Phase order J.0→ with stable patch IDs |
| typedb-r2-v16-source-lock-candidate.json | Complete pinned source/package/toolchain graph |
| fetch-pinned-sources-v16.sh | Source fetcher (git + codeload fallback) |
| typedb-r2-v14-upstream-test-catalog.schema.json | Machine schema for the upstream test denominator |
| typedb-r2-v14-cargo-test-conformance-plan.md | Cargo-only test-conformance plan (U0–U4 profiles) |
| typedb-r2-v16-cloudflare-contract-lock.json | Locked platform contract claims + dependent gates |
| typedb-r2-v16-platform-probes.md | Real-account Cloudflare probe plan |
| typedb-r2-v16-cloudflare-source-matrix.md | Cloudflare package↔source mapping obligations |
| typedb-r2-v16-review-actions.json | 50 tracked actions with gates and owners |
| PROMPT-implementation-agent.md | The kickoff prompt (copy-paste) |

Design lineage: 16 adversarially-reviewed revisions between two LLM agents, one with full pinned-source access (TypeDB `2256711a`, SlateDB `f88be86d`, typedb-behaviour `ac5d5733`, plus the Cloudflare/HydraDB reference graph). All source-anchored facts in the contract were verified by direct code read; prose test counts are reconnaissance floors until the generated catalogue exists.
