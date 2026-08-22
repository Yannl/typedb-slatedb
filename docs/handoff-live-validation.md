# Live-validation handoff — Cloudflare probe run (HARD STOP in force)

## ⛔ 0. EXECUTABLE HARD STOP — read before touching any credential

**A live Cloudflare run is NOT READY and MUST NOT be attempted from this
document alone.** The machine truth is `docs/ledger/gates.json` — its
canonical `current` section, rendered into the generated block in
[operations.md](operations.md). This document deliberately states NO gate
state of its own: a second copy of current truth in prose is exactly what
goes stale (R8-P0-02). Before ANY step below, run the two
commands that enforce the stop and believe their exit codes, not this
prose:

```sh
cd control-plane
npm run probes:preflight        # exit 3 = RED = STOP. No credential goes near the runner.
npm run probes:selftest         # 26 controls; anything nonzero = STOP.
```

The current blockers (ledger `G2.blockers`) are structural, not
paperwork: there is no owner-SIGNED approval envelope, and the
production issuer/registry seam (R4-SEC-01) precedes any
product-labelled run. Two former blockers are now closed in-repo:
the nine `/do/*`, `/ctr/*`, `/worker/*` probes have a deployable
harness implementation (`control-plane/probes/harness-worker.ts` +
`wrangler.probe-harness.toml`, source-digest-bound into the bundle;
R4-CF-02), and every assertion is classified provider-fact vs
product-conformance by the obligation manifest with the three
product obligations honestly OPEN (`probes/obligations.ts`;
R4-CF-04) — the VERDICT's `product_conformance` sub-verdict stays
OPEN until they are discharged, so a run cannot overclaim.

What IS true after round-4: the runner's formerly destructive refusal
path is repaired and mutant-proved — a RED preflight makes **zero**
external calls (cleanup included), cleanup restores the captured
bucket-lock baseline instead of erasing the ruleset, the owner envelope
is an enforced request/byte/time budget, and evidence redaction is a
serialization invariant with a seal-time secret scanner
(`docs/reviews/deep-audit-2026-08-19-round4-response.md`).

Historical note: the pre-round-4 version of this document described a
four-variable setup against a bucket named `typedb-probe-staging`, the
deprecated `probes:r2` entry point, and a copy-and-deploy Wrangler flow.
Following it with real credentials would have produced a RED preflight
followed by a destructive lock-policy reset (R4-DOC-01/R4-CF-00). Every
such instruction is superseded by this file; the deprecated
`probes:r2` wrapper only forwards to the current runner.

## 1. What an eventual disposable probe run requires (informational)

Nothing here may be executed until the ledger's G2 blockers are cleared
and `probes:preflight` is GREEN. The runner reads EXACTLY these inputs
(`control-plane/probes/preflight.ts`, `provider.ts`) and refuses
anything less:

| Input | Rule enforced by preflight (fail-closed) |
|---|---|
| `R2_PROBE_OWNERSHIP_NONCE` | ≥8 chars of `[a-z0-9]`; the run must own its target by name |
| `R2_PROBE_BUCKET` | must match `typedb-probe-<nonce>[-suffix]`; forbidden fragments (`prod`, `live`, `main`, `backup`, `primary`, `customer`, `data`) are refused; the bucket must be FRESH — the first real act is a LIST that must return empty |
| `R2_ACCOUNT_ID` / `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY` | scoped Object Read & Write on the probe bucket only; never an admin key |
| `CF_ACCOUNT_ID` / `CF_API_TOKEN` | ADMIN principal (lock config, credential minting) |
| `CF_RUNTIME_API_TOKEN` | a genuinely SEPARATE, less-privileged runtime principal; equality with the admin token is refused |
| `CF_PROBE_HARNESS_URL` / `CF_PROBE_HARNESS_TOKEN` / `CF_PROBE_HARNESS_ALLOWED_HOSTS` | https-only, own token (never the account token), exact hostname allowlist — and the harness itself must be deployed from THIS repository's canonical graph (R4-CF-02: not yet possible) |
| `docs/probe-run-envelope.json` | owner-SIGNED approval artifact (`probe-run-envelope/v2`, R5-CF-01): Ed25519 signature verified against the out-of-band `PROBE_ENVELOPE_PUBLIC_KEY`; BOUND to the exact release commit, probes source root, account, bucket, ownership nonce and ONE run id; time-boxed (`valid_from`/`valid_until`, ≤7 days) and one-time (consumed-run journal). Limits (`max_total_requests`, `max_total_bytes_written`, `max_run_seconds`, `max_probe_seconds`, `max_request_seconds`, `max_cost_usd_cents`, `credential_ttl_seconds`=900 exactly) are never guessed and are enforced at dispatch time by the metered provider. The owner signs with `probes/sign-envelope.ts` (`--keygen`, then `--sign` from the exact tree being authorized); an unsigned file grants nothing |
| `PROBE_ENVELOPE_PUBLIC_KEY` | the owner's Ed25519 verification key (SPKI PEM), delivered with the deployment and never stored inside the envelope file |

Run entry point (the ONLY one): `npm run probes:platform`
(`control-plane/probes/run-platform-probes.ts`). Evidence lands in a
sealed `PlatformRunBundle v2` under `docs/evidence/G1-platform/runs/`;
a bundle without `COMPLETE` is an aborted run, and a run whose cleanup
failed exits nonzero regardless of probe verdicts.

## 2. Deployment posture (informational)

- The canonical IaC is the typed graph in `stack/graph.data.mjs`.
  `stack/alchemy.run.ts` is mechanically LOCAL-ONLY (execution-mode
  assertion; it cannot be deployed). A deployable production stack is a
  future generated program from the same graph — it intentionally does
  not exist yet.
- `control-plane/wrangler.toml` is the MANAGED fail-closed default
  (managed key profile, closed surface, production bucket, no
  workers.dev). Local development uses the explicit
  `wrangler.local-dev.toml`. There is no copy-and-edit staging flow:
  when a staging deploy becomes legitimate it will be generated from the
  graph and checked by `stack check-wrangler`, never hand-copied.
- Custody rules: credentials live in env vars only for the duration of a
  run; the evidence pipeline redacts at serialization and refuses to
  seal on any detected secret byte; rotate/revoke both tokens when the
  session ends. Nothing is committed.

## 3. Orientation for a fresh session

- **State machine**: `docs/ledger/gates.json` (canonical `current` section)
  → rendered into [operations.md](operations.md). Read the gate states
  THERE; they are not restated here.
- **Round-4 program**: `docs/reviews/deep-audit-2026-08-19-round4-response.md`
  (per-finding accounting, actions R4-A..R4-F).
- **Local stack**: `node stack/cli.mjs dev` (loopback MinIO + Alchemy
  workerd; zero cloud risk by construction).
- **Probe harness self-test** (no credentials): `npm run probes:selftest`.
