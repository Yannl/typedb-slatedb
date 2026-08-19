# Round-4 deep-audit response (2026-08-19) — per-finding accounting

**Directive:** TypeDB on SlateDB/R2 round-4 deep audit and pre-Cloudflare
total-quality directive, 2026-08-19 (audited commit `e1f88a0`).
**Decision adopted:** NO-GO for a product-labelled Cloudflare live
qualification; continue local implementation. G0/G1/G2 remain open.

This document is being filled in per-finding as the round-4 program lands;
the machine source of truth is `docs/ledger/gates.json`
(`adopted_audit_round4`, actions `R4-A`..`R4-F`). A finding listed here as
CLOSED carries an executed mutant; anything else is honestly IN_PROGRESS
or OPEN with its blocker named.

## Destructive-stop safety (R4-CF-00, R4-CF-01, R4-CF-03) — CLOSED (action R4-A)

The audit dynamically reproduced the worst defect in the repository: a
real-mode probe run with a RED preflight still issued
`PUT .../lock {"rules":[]}` against the refused bucket from its
unconditional cleanup. Repaired structurally:

- a RED preflight constructs a zero-authority `RefusedProvider`; probes
  AND cleanup can make no call, attempts are counted and any nonzero
  count fails the run;
- cleanup never writes `rules:[]`: the exact lock-policy baseline is
  captured before any probe, P-R2-03 is read-modify-write, and cleanup
  conservatively restores the snapshot (operator changes are a CONFLICT
  that refuses to write);
- the real-mode empty-bucket LIST executes before the first write;
- the owner envelope is an enforced budget (reserve-before-dispatch,
  absolute run deadline, clamped request deadlines, cleanup reserve),
  write intents are journaled before dispatch, probe timeouts close the
  provider, and the verdict is computed after cleanup;
- redaction is a serialization invariant (deep redaction at the single
  write choke point) plus a seal-time secret scanner that refuses
  COMPLETE on any hit.

Proof: `control-plane/probes/runner-safety.test.ts` (14 executed mutants,
including the audit's exact counterexample with global fetch intercepted:
rc=3, zero escaped requests), self-test control 7b; 22/22 controls green.

## Posture truth (R4-STACK-01/02/08/10, R4-DOC-01) — action R4-B

- `toGraph` variants now declare `securityPosture`; `cloudflare-real`
  emits the managed vars and structurally cannot carry a forbidden dev
  var. `local-parity` is the managed-posture local lane; `local-native`
  is explicitly developer-convenience (non-parity).
- `graph-diff` validates every graph's posture INDEPENDENTLY before
  comparing (two graphs sharing unsafe values now both fail), compares
  bindings by stable name, and scopes field variation to the named
  binding (bucketName → PAYLOADS only, declaredAhead → CONTAINER only).
- `wrangler.toml` is now the MANAGED fail-closed default (managed keys,
  no dev surface var, production bucket, `workers_dev`/`preview_urls`
  false); local development uses the explicit
  `wrangler.local-dev.toml` (vitest/wrangler-dev lanes updated). The
  migration history is an append-only ledger checked in both files.
- `alchemy.run.ts` carries an execution-mode assertion: it throws before
  declaring any resource unless invoked through `stack/cli.mjs dev`
  (ack variable), refuses deploy-shaped invocations even with the ack,
  and refuses live credential variables outright.
- OD-008 (confidentiality profile, OPEN) and OD-009 (RustFS strategic
  target / MinIO loopback transition baseline) are recorded owner
  decisions; no gate rests on an undecided default.

## Remaining round-4 findings

Tracked in `docs/ledger/gates.json` actions R4-C (storage), R4-D
(evidence/Mode-Q/CI), R4-E (security seam), R4-F (local stack); each
lands with executed mutants and updates this document.
