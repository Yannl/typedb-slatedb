# Live-validation handoff — Cloudflare probe run (HARD STOP in force)

## ⛔ 0. EXECUTABLE HARD STOP — read before touching any credential

**A live Cloudflare run is NOT READY and MUST NOT be attempted from this
document alone.** The machine truth is `docs/ledger/gates.json`
(`adopted_audit_round4`, gate `G2: NOT_READY_TO_EXECUTE`) rendered into
[operations.md](operations.md). Before ANY step below, run the two
commands that enforce the stop and believe their exit codes, not this
prose:

```sh
cd control-plane
npm run probes:preflight        # exit 3 = RED = STOP. No credential goes near the runner.
npm run probes:selftest         # 22 controls; anything nonzero = STOP.
```

The current blockers (ledger `G2.blockers`) are structural, not
paperwork: nine of the fourteen probes require `/do/*`, `/ctr/*`,
`/worker/*` harness endpoints that have **no deployable implementation in
this repository** (R4-CF-02); several real-mode assertions do not yet
encode the normative product contract (R4-CF-04); there is no
owner-approved numeric envelope; and the production issuer/registry seam
(R4-SEC-01) precedes any product-labelled run.

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
| `docs/probe-run-envelope.json` | owner-approved numeric limits (`max_total_requests`, `max_total_bytes_written`, `max_run_seconds`, `max_probe_seconds`, `max_request_seconds`, `max_cost_usd_cents`) with `approved_by`/`approved_at`; never guessed; `max_run_seconds` must cover the fixed credential ttl (900 s); enforced at dispatch time by the metered provider |

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

- **State machine**: `docs/ledger/gates.json` → rendered
  [operations.md](operations.md). G0 OPEN_RED, G1 OPEN, G2
  NOT_READY_TO_EXECUTE.
- **Round-4 program**: `docs/reviews/deep-audit-2026-08-19-round4-response.md`
  (per-finding accounting, actions R4-A..R4-F).
- **Local stack**: `node stack/cli.mjs dev` (loopback MinIO + Alchemy
  workerd; zero cloud risk by construction).
- **Probe harness self-test** (no credentials): `npm run probes:selftest`.
