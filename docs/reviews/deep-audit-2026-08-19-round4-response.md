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

## Storage (R4-STOR-00..11) — CLOSED (action R4-C)

- STOR-04/07 (`5aff4ff`): multipart mutation policy enforced at use time;
  a checkpoint cut refuses to activate without its manifest root.
- STOR-08/10/11 (`0da6d0b`): recency-aware checkpoint retention,
  newest→oldest fallback, and remote startup never consumes a fixture.
- STOR-00/01/02 (`ca1e5cd`): one immutable `BackendContext` per open
  (mid-process env change = typed refusal, proven by a barrier mutant);
  `backend-identity v2` persists the FULL identity — kind, durability
  backend, object-store profile, policies, protocol versions and the
  non-secret S3 binding — sealed by a SHA-256 digest, with per-field
  typed mismatches and a one-time sanctioned v1→v2 upgrade; checkpoints
  embed the identity and a cross-identity restore is a HARD typed
  refusal, never fallback material; the marker write is no-follow,
  create_new + fsync + hard-link publication, and cannot delete foreign
  content. Proof: storage lib 138, test_recovery 11, database suites
  green (independently re-run).

## Evidence/Mode-Q/CI (R4-EVID-01/01a/03a, R4-MODEQ-01) — CLOSED (action R4-D, `868f617`)

Verifier adjudication split (observation_integrity / policy_adjudicated /
qualification_pass), source-lock freshness binding, CI v2 enforcement,
and Mode-Q Bazel cquery semantic validation.

## Security seam (R4-SEC-03..06) — CLOSED for the audited findings (action R4-E)

- SEC-04/05/06 (`56fda81`): the capability method registry is CLOSED with
  exact per-action methods and REQUIRED restrictions; WAL_READ binds
  session+generation and is revalidated live (`assertActiveReader`);
  checkpoint activation takes the material
  `checkpoint-restore-evidence/v2` manifest validated field-by-field.
- SEC-03 (`b53fd35`): the Rust L1 client threads the exact generation
  through every mint as a JSON number — no default, no zero fallback —
  holds a bound actor for reads, and its contract mock now VALIDATES
  issuance like the worker does (refusal matrix executed; live workerd
  24/24 including the issuance-refusal checks).
- OPEN remainder (tracked as R4-PR1 / R4-SEC-01): production tenant
  registry, private issuer/provisioner, managed-surface local E2E,
  keyring/kid rotation.

## Probe harness truth (R4-CF-04, R4-CF-02) — CLOSED (`6301fec`)

- The obligation manifest (`probe-obligations/v1`) classifies all 100
  assertions of the 14 probes into provider-fact vs product-conformance;
  three product obligations are honestly OPEN and the VERDICT's
  `product_conformance` sub-verdict cannot be PASS while they are.
- The harness the probes call is now a deployable Worker+DO artifact
  (`probes/harness-worker.ts`, `wrangler.probe-harness.toml`) whose
  source digest is bound into the bundle. Self-test: 24/24 controls.

## Local realism (R4-STACK/LOCAL, PR2, PR3) — action R4-F

- Stack hardening (`e37f9e8`): semantic readiness, PID identity, atomic
  manifests, transitive no-cloud guard, hardened downloader, secret
  hygiene.
- PR2 EXECUTED (`a3411c8`, `8809f89`): the provider-neutral S3
  certification corpus (9 semantic tests via `object_store =0.14.1` —
  conditional-create single winner, If-Match fencing, multipart,
  pagination, byte-exact readback — plus a REAL kill -9 crash/restart
  persistence barrier) passes on BOTH the locked MinIO baseline and the
  now-PINNED RustFS 1.0.0-rc.2 (source-lock node RUSTFS; the runner
  hard-refuses a digest mismatch). OD-009 progress recorded; the default
  provider has NOT flipped (timeout/ambiguity lane, SlateDB suite and
  TypeDB corpus on RustFS remain outstanding).
- PR3 (partial, `f685d0e` + `stack/native-fidelity.mjs`): deterministic
  TCP fault proxy (schedule-replayable, self-tested) and the
  native-fidelity lane: the EXACT `typedb_server_bin` fork build runs
  over SlateDB-on-S3 through the proxy, driven via the official HTTP
  surface. Six phases pass on both providers: workload, nonzero-S3-path
  witness, kill -9 recovery, parallel isolation, injected-reset
  survival, and a U1-profile mutant proving the S3 witness detects a
  silent local fallback. OPEN: U3 remote-WAL product integration,
  driver-level suites in the lane, L2 container parity.
