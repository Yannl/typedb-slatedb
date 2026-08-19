# Round-5 deep-audit response (2026-08-19) — per-finding accounting

**Directive:** Round 5 deep audit and implementation directive, 2026-08-19
(audited commit `29fd003`). **Decision adopted:** continue the local
implementation pass; NO-GO for live qualification stands until the §13
checklist is green; the branch merges to `main` at the end of this pass
(R5-REL-00) with every gate rerun against the exact merged commit.

A finding listed CLOSED carries an executed mutant; anything else is
honestly IN_PROGRESS or OPEN with its blocker named. Machine source of
truth: `docs/ledger/gates.json`.

## Release truth (R5-REL-00/01, R5-EVID-01/02, R5-QUAL-01) — action R5-A

- R5-REL-00 (merge to main) is the LAST step of this pass, after the
  full sweep on the final tree; the exact merged commit is recorded here
  when it exists.
- R5-REL-01/EVID-01/QUAL-01 (ledger drift + semantic reconciliation,
  catalogue/plan regeneration against the current lock with the
  `|| echo` escapes removed, the storage `--all-targets` bench red fixed,
  workflow hardening): implemented by the truth-plane workstream —
  recorded in its own commit with its verification.
- R5-EVID-02 stays honestly RED by design: Mode Q absent, plan coverage
  0/23k, driver rows NOT_IMPLEMENTED. No coverage is faked; the typed
  runner/evidence program is post-merge work and the gates stay open.

## Storage (R5-STOR-01..12) — CLOSED for the audited findings

- **STOR-01** (`46164cd`): `BackendContext` owns the complete effective
  S3 configuration (endpoint, region, bucket, prefix, cache budget,
  secrets as opaque redacted handles) resolved at ONE admission point;
  the `static OnceLock<S3Config>` and every env read below admission are
  deleted, with a source-level guard test that fails if they reappear.
  Identity digests move for every behavior-affecting input; a second
  differing config in-process is a typed refusal; post-admission env
  changes are proven inert.
- **STOR-05** (`46164cd`): multipart completion is provider-atomic
  create-only — staging attempt key → readback verify → atomic
  create-mode promote (create-only single-PUT fallback documented where
  conditional copy is unsupported); two INDEPENDENT completers with
  different bytes yield one winner and no changed-byte overwrite;
  timeout-after-promote replay converges.
- **STOR-08** (`46164cd`): journal retires terminal rows to a bounded
  receipt window; hard attempt/byte budgets reserved before provider
  state; exceeding is a typed admission refusal, never growth.
- **STOR-10** (`46164cd` + `3e6ed64`): silent legacy rebind is dead on
  both sides — v1 markers and identity-less cuts are typed refusals on
  ordinary open/recovery; explicit imports require the acknowledged full
  identity and write sealed provenance.
- **STOR-06** (`3e6ed64`): restore materialises into scratch, re-verifies
  bytes, opens every keyspace, replays the fixed WAL head, and only then
  atomically activates (rename swap + parent fsync + rollback); the
  kill-point matrix (before/during/after activation, unopenable cut) is
  executed and every pre-activation failure leaves the predecessor
  byte-identical AND active.
- **STOR-09** (`3e6ed64`): `CHECKPOINT-COMPLETE v2` — streaming SHA-256
  per file and root over length-prefix-framed raw path bytes; lossy-path
  collisions impossible; duplicate keys and trailing garbage refuse;
  v1/64-bit manifests refuse as unverifiable.
- **STOR-11** (`3e6ed64`): attempt ordering and retention are keyed by
  the sealed checkpoint sequence, never wall clock; clock-rollback and
  reverse-completion mutants keep the logically newer cut; renamed
  attempt directories are unselectable.
- **STOR-12** (`3e6ed64`): the reachable `todo!()` in
  `open_snapshot_write_at` is a typed error.
- **STOR-04** — CLOSED (`5cbe3dd`), and worth reading twice. The fence
  now SHIPS (unconditional on the storage crate's slatedb dependency,
  attested by `cargo tree`). Shipping it makes "run the whole upstream
  suite feature-on" a real question with an unflattering answer, so it
  is answered exactly: feature-OFF full suite 1988/0 (no regression);
  feature-ON `db::builder` 12/0 (the audit's measured set, was 7/5);
  feature-ON full suite 1566/420 — those 420 are upstream tests opening
  databases through the epoch-less builder, which the fence refuses BY
  DESIGN. A first draft of this work claimed 1940/0; that claim was not
  reproducible and is retracted in the patch ledger. The invariant now
  enforced (`tools/fork/check_strict_epoch_suite.py`) is not "all green"
  but "every failure is the fence doing its job", asserted per failing
  test by cause — which is how 3 GENUINE regressions were found hiding
  among the expected refusals (patch 0005).
- **STOR-02/03** — CLOSED (`e63a337`): `classic|slatedb-r2` is a product
  option resolved from server configuration, and a conformance profile
  can never silently decide it (typed refusal naming both sides); the
  local epoch source documents precisely what it is not, and the lanes
  that would claim cross-host fencing refuse at admission.
- **STOR-07** stays a documented U2S3-lane containment (fresh
  materialisation per open is the experimental lane's design; the
  production lifecycle needs the controller pointer — tracked with
  STOR-03).

## Security architecture (R5-SEC-01..10) — the audited P0 core is closed

- **SEC-03** (`9d60e53`): capability + provision tokens are Ed25519
  schema v3; the managed runtime holds ONLY public verification keys
  (proven: stealing every managed env var yields no minting ability;
  a wrong-key self-signed forgery refuses; unknown alg/kid/version
  refuse; two-slot rotation with explicit retirement is tested). Minting
  lives only in the issuer module; the dev keys are committed insecure
  constants refused under managed. The journal MAC deliberately stays
  symmetric (writer = verifier = same DO) — documented.
- **SEC-01** (`9d60e53`): the managed graph boots from exactly its
  declared inputs — one requirement source consumed verbatim by the
  runtime resolver AND the pre-deployment graph checker; construction
  test builds the env from the graph programmatically; drop-each-input
  mutants fail before deployment; the managed E2E boots the real
  `wrangler.toml` with per-run ephemeral keypairs.
- **SEC-08** (`9d60e53`): `docs/security-topology.md` — the exact
  principal/binding/key map, with the explicit statement that TypeDB
  end-user auth is NOT service auth; every claim cites its enforcing
  file.
- **SEC-04** — CLOSED (`48bf2c3`): capability uses are a durable
  operation/effect protocol. Each claim records its authoritative
  effect; a recovery reducer settles AMBIGUOUS from that effect
  (present → the exact original success, absent → re-execute,
  contradicted → QUARANTINED terminally); the retry path settles instead
  of answering 409 forever; and restart/alarm sweeps converge even if
  the client never retries. 10 mutants executed.
- **SEC-02** — CLOSED (`197547c`): the exact Rust client operates the
  managed surface as a pure bearer of issuer-granted v3 tokens, with a
  new managed lane that boots the real `wrangler.toml` plus the private
  issuer sidecar and proves the dev-route 404 matrix from Rust before
  any bootstrap (44 checks managed, 35 local-dev). Residual recorded:
  drain/revoke, checkpoint open/activate and the ambiguous-operation
  query are not yet in the client.
- **SEC-06/07/09** — CLOSED (`7de23b8`): ContainerDO binds only through
  the registry provisioning transaction (race/squat/wrong-principal/
  stale-incarnation mutants); observation bytes are bounded per field,
  per request on ACTUAL bytes, and in aggregate; the graph marks the
  container execution facet declared-ahead/advisory, enforced by a stack
  honesty test. No actual Container process exists — stated openly.
- **SEC-05** — CLOSED (`00fc024`): the token check, the actor-liveness
  revalidation and the catalogue read happen in ONE synchronous
  transaction that also records a single-use, short-TTL lease over the
  exact object keys; fence/revoke/expire/incarnation-bump delete that
  actor's leases in their own transactions; redemption re-checks
  existence, expiry, single-use, exact key set and live authority AT
  REDEMPTION TIME. The in-DO-read alternative was rejected on the record
  (it would route payload bytes through the byte-blind controller,
  serialize reads behind control mutations, and contradict PERF-01).
  Executed: pause-after-authorization → fence → resume is refused on all
  seven read routes, a pinned iterator cannot be paged after a fence, and
  replayed/doubled/widened leases refuse.
- **SEC-10 / OD-008** (confidentiality profile): remains an OPEN owner
  decision on purpose; no profile is silently inferred.

## Cloudflare probe readiness (R5-CF-01) — CLOSED (`f8fa481`)

The approval envelope is a SIGNED, run-bound, one-time authorization
artifact: Ed25519 over the canonical body, verified against the
out-of-band `PROBE_ENVELOPE_PUBLIC_KEY`; bound to release commit, probes
source root, account, bucket, ownership nonce and ONE run id; validity
≤7 days; the run id is consumed at authority acquisition. 16 executed
mutants (unsigned/foreign/tampered/copied/expired/replayed/wrong-TTL/
absent-key) + self-test control 7c; owner tooling `sign-envelope.ts`
refuses to sign for a tree that differs from the draft's binding.

## Local parity (R5-LOCAL-01/02/03) — 01/03 CLOSED (`0d111e9`)

- **LOCAL-01**: the CAS gate can no longer accidentally serialize —
  barrier-released rounds (100×16 writers, independent clients, 1 MiB
  pairwise-distinct bodies), current-ETag update races with post-race
  ABA refusal, and a MULTI-PROCESS lane (8 OS processes per round,
  start-file barrier, winner self-verifies byte-exact stored bytes).
  Executed green on BOTH pinned providers (MinIO baseline, RustFS
  1.0.0-rc.2); OD-009 records it; the default has NOT flipped (fault
  lane, SlateDB suite and TypeDB corpus on RustFS outstanding).
- **LOCAL-03**: every corpus run seals a structured evidence bundle
  (provider binary digest, per-phase logs+digests, crash receipt, root
  seal) verified by an independent verifier.
- **LOCAL-02** (one executable ladder to the full managed stack):
  partially closed by the managed E2E + native-fidelity lanes; the
  combined single-command topology remains tracked work.

## Performance/robustness (R5-PERF-01/02) — CLOSED (`00fc024`)

The JSON cap binds ACTUAL bytes (stream-capped, strict UTF-8, depth
bounded); payload writes are digest-declared streaming (stage → verify →
create-only promote); reads gain a negotiated streaming variant while the
DEFAULT response stays byte-identical base64 JSON, asserted including key
order. Three limits are recorded in code rather than glossed: R2 refuses
unknown-length streams (so the mandatory content-length becomes a
FixedLengthStream length and the platform enforces the declaration both
ways); a streamed read's digest verdict can only gate the last byte, so a
corrupted object aborts the response body rather than refusing up front —
which is why the default remains verify-then-serve; and the scan page
still buffers within its authority-cut 8 MiB budget, because streaming an
array-of-records would be a different protocol, not a different encoding.

## Final sweep on the merge candidate

Executed on the exact tree being merged, nothing skipped:

| Lane | Result |
|---|---|
| fork Rust (storage, recovery, mvcc, snapshot, isolation, durability, database) | **345 passed, 0 failed** |
| tools Rust (remote-wal-spike incl. both live lanes, protocol models) | **70 passed, 0 failed** |
| control-plane node core | **124 passed, 0 failed** |
| control-plane workerd | **69 passed, 0 failed** (10 files) |
| L1 local-dev E2E / managed-surface E2E | **ALL PASS** / **ALL PASS** |
| probe harness self-test | **25/25 controls** |
| stack | **68 passed, 0 failed**; wrangler consistency PASS |
| ledger lint / mutants | PASS / **16 executed, 16 killed** |
| catalogue + plan (`--require-current-lock`) | PASS / PASS (23,132 rows) |
| evidence-v2 / Mode-Q mutants | **15/15** / **11/11 killed** |
| source-lock lint / mutants | PASS / **7/7** |
| strict-epoch attestation + suite gate | PASS / PASS (420/420 failures accounted for as fence refusals) |
| SlateDB fork reconstruction | OK (5 patches, deterministic) |

What remains RED is red on purpose and unchanged: G0 OPEN_RED (Mode Q
absent), G1 OPEN, G2 NOT_READY_TO_EXECUTE, plan coverage 0/23,138,
official driver rows NOT_IMPLEMENTED, OD-008 confidentiality profile
undecided. R5-LOCAL-02 (the single-command ladder) and the R5-CI-01
release pipeline (tested-equals-shipped, SBOM/provenance) are the named
carry-forward items.

## CI/packaging (R5-CI-01) — workflow hardening lands with R5-A; the
package-once/test-the-digest release pipeline, SBOM/provenance and the
driver suites remain post-merge program work, honestly open.
