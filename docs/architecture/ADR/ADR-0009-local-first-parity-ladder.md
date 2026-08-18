# ADR-0009 — Local-first development on a fidelity ladder; Cloudflare is the last step, not an environment

**Status:** accepted (operative; details in [local-dev-parity-plan.md](../../local-dev-parity-plan.md))

> **Round-3 correction (2026-08-18).** L1 runs the production Worker/DO
> RUNTIME (workerd) under a LOCAL TOPOLOGY — it is not "the production
> topology." Edge routing, service bindings, DO scheduling/eviction/alarms,
> Containers, and real R2 service behavior differ and are enumerated as
> platform residuals in the round-3 response
> ([reviews/deep-audit-2026-08-18-round3-response.md](../../reviews/deep-audit-2026-08-18-round3-response.md)).
> The canonical local topology is now the Alchemy + native-MinIO parity
> stack (`stack/`, ADR/A-01); the tables below describe the ladder's
> intent, not a claim that any local rung reproduces a Cloudflare fact.

## Context

The production target is Cloudflare (Workers, Durable Objects, R2,
Containers). Developing *against* a cloud account is slow, unreproducible,
credential-gated, and makes platform noise indistinguishable from logic
bugs. The decisive fact making local-first viable at high fidelity:
`workerd` — pinned in the source lock via workers-sdk — **is the
production Workers/DO engine itself**, not an emulator. Only R2's service
internals and platform operational behavior cannot be reproduced locally.

## Decision

A four-rung fidelity ladder, with a hard rule about what each rung may be
used for:

| Rung | What runs | What it proves |
|---|---|---|
| L0 | native TypeDB process (U1/U2 profile) | storage semantics, the full upstream corpus |
| L1 | Worker + `DatabaseControllerDO` on real workerd + local R2 binding | the protocol against the production DO engine |
| L2 | full container topology under `wrangler dev` (Docker) | container lifecycle wiring |
| L3 | real Cloudflare staging | **platform facts only**: G2 measurements, real R2 conditional-write behavior, cost/latency envelopes |

Nothing deploys until L0→L1→L2 are green. L3 is never used to debug
logic. Local R2 (miniflare's simulator) is treated as API-faithful but
**not evidence-grade** — anything the conformance plan calls a platform
fact must be re-verified at L3.

## Consequences

- The entire system — storage engine, corpus parity, controller
  invariants, protocol E2E — was built and proven with zero cloud
  credentials; the single remaining program blocker (SI-G0-3) gates only
  the platform-fact rung.
- Deterministic reference lanes (pure Rust models, in-process spike, node
  SQLite lane) sit *below* L1 and must stay trace-equivalent to the
  production TS core, so logic bugs are caught at the cheapest rung that
  can express them.
- The cost is a documented caveat class: local conditional-write, 5xx,
  and throttling behavior are re-implementations, and claims that depend
  on them are explicitly marked pending-L3 rather than silently assumed.
