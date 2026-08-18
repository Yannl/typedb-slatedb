# Handoff: state after the total-quality closure session

**Written at:** end of the session that executed "fix all remaining issues.
total quality." on top of the consolidated-directive work, branch
`claude/typedb-slatedb-r2-continue-ss62cz`. Start a new session FROM this
branch or from `main` once it is merged.

## One-paragraph state

Every directive item that is closable in this environment is now closed
with an executed mutant, and every item that is not closable here is
recorded in the response document's **"Blocked here, and why"** section
with its external dependency named. Closed since the last handoff: the
§12.4 lifecycle (activation is the only fence; takeover-at-open is gone),
credentialed issuance + fail-closed key profiles (Q-02/Q-24), mandatory
budgets and exact wire guards (Q-12/Q-10), the storage containment batch
(Q-27 copy immutability, Q-13/Q-23 bounded retries + bounded loud bridge
under OD-006, Q-22 structural cursor drop order, Q-16 relabel), the Q-17
remainder (plan assertions + a 500k-row latency-ratio control, which
caught and killed a real O(history) double-`MAX` head lookup), the J.3
pure resolver model, and the ADR-0012 **Candidate B** spike — both
candidates are now measured and the comparison is recorded in the ADR.
The corpus archive at `docs/evidence/G3/u2s3-full-3/` is a HISTORICAL
observation over a superseded staged tree (see the ledger's U2S3 entry for
the raw numbers); it is not current-tree conformance. **The release
decision is still NO-GO.** The authoritative gate state is
`docs/ledger/gates.json` (rendered in docs/operations.md) — the 2026-08-18
deep audit reopened G0 (Mode-Q), reclassified U2/U2S3 as historical
non-qualifying, and marked U3.0 red (Rust client / Worker protocol drift).

## Read these first (15 minutes)

1. `docs/reviews/consolidated-directive-response.md` — every finding with
   a status, a commit, and — for the OPEN ones — the named blocker.
   The "Blocked here, and why" section is the honest boundary of this
   environment.
2. `docs/contradictions.json` — four contradictions, safe side taken.
3. `docs/owner-decisions.json` — six values deliberately not invented
   (OD-006 is new: bridge deadline + retry bound).
4. `docs/operations.md` — the gate table and the truth-plane checks.
5. `docs/architecture/ADR/ADR-0012-...md` — the two-candidate comparison,
   now with both sides measured.

## Run this first, always

```sh
python3 tools/dev/doctor.py
```

A previous session's only environment failure was a cold build dying ten
minutes in on a missing `protoc`. Doctor reports that in one second.

## Top follow-ups, in order

1. **Q-06 remainder: the Mode-Q Bazel oracle (SI-G0-1).** BLOCKED here (no
   Bazel toolchain). Until it exists the catalogue is self-derived and G1
   cannot be green even with U3/U4 covered. The regeneration recipe for
   everything else after a source-lock bump:

   ```sh
   git -C sources/typedb worktree add ../typedb-pristine <locked-revision>   # if absent
   CARGO_TARGET_DIR=sources/pristine-target PROTOC=$(command -v protoc) \
       cargo +1.93.0 test --manifest-path sources/typedb-pristine/Cargo.toml \
       --workspace --locked --no-run
   CARGO_TARGET_DIR=sources/pristine-target \
       python3 tools/catalog/generate_catalog.py --tree sources/typedb-pristine
   python3 tools/catalog/validate_catalog.py
   python3 tools/catalog/run_u0.py --verdict-only --out docs/evidence/G3/u2s3-full-3
   python3 tools/catalog/completeness.py --results docs/evidence/G3/u2s3-full-3
   ```

2. **U3/U4 coverage.** The required matrix emits U0..U4 pairs; U3/U4 have
   zero rows. This is the largest UNBLOCKED remaining work: the U3
   controller build-out (command ledger inv. 85–98, R2 RecoveryAnchor
   publication, durable barriers past the outbox frontier) has no external
   dependency — it is post-G2 only where the playbook says so, and the
   response document's F7/F8 rows itemise it.

3. **Q-08 probe harness: BUILT (2026-08-18).** All 14 normative IDs exist
   with fail-closed aggregation, sealed evidence bundles and an 18-control
   self-test (`control-plane/probes/`, CI-enforced). Their *execution*
   remains credential-blocked (SI-G0-3); the ledger's G2 entry also needs
   the owner-approved envelope before any live run.

4. **Q-19 / Q-12 streaming remainder.** Streaming/backpressure framing for
   payload and scan surfaces instead of accumulated base64; whole-object
   serial remote helpers.

5. **G2** stays blocked on SI-G0-3; the lifecycle's external attestation
   root and the provider-side IAM/no-delete proof land with the same
   credentials.

## What is blocked here (do not burn a session rediscovering this)

Mode-Q Bazel oracle (SI-G0-1) · G2 + probe execution (SI-G0-3) · real
IAM/provider no-delete + multipart conditional-write proof · driver
gates/classic matrix (external repos) · the §12.4 external attestation
root. Full reasons: response document, "Blocked here, and why".

## Environment notes (save yourself an hour)

- `python3 tools/dev/doctor.py` first. Then
  `python3 tools/source-lock/materialize_sources.py`, then
  `python3 tools/fork/stage.py`.
- `protoc` is required and NOT in the base image; install before building.
- Never `pkill rustc` mid-build: cargo orphans into `do_wait` holding
  `target/debug/.cargo-lock` and every later build deadlocks silently.
  Kill the cargos, then `rm target/debug/.cargo-lock`.
- Never `pkill -f "<pattern>"` where the pattern appears in your own
  command line — it matches your own shell. Prefer `pkill -x`.
- Two concurrent cargo builds in one target directory serialise on that
  lock. Use a separate `CARGO_TARGET_DIR` for the pristine catalogue build
  (and for `spikes/publication-firewall`, which is workspace-external).
- Disk: `sources/typedb/target` is ~9 GB warm; a pristine build needs its
  own ~9 GB. The firewall spike adds ~2 GB in its own target dir.
- MinIO: install per `docs/operations.md`, export `TYPEDB_S3_*` before any
  U2S3 test. If storage-lib tests fail with `Connection refused
  127.0.0.1:9000`, MinIO died — restart it and re-run before believing
  anything (it happened here; the failures were environmental).
- SlateDB writes with `flush_interval: None` + WAL off MUST use
  `await_durable: false` (`WriteOptions`) — a durable-awaiting `put`
  blocks forever. `#[tokio::test]` needs the multi-thread flavor for any
  test that opens a SlateDB.
- Control plane: `cd control-plane && npx tsc --noEmit`; the seven suites
  via `node --test --experimental-strip-types src/controller/core/*.test.ts`
  (70 tests); `npx vitest run`; E2E via `npx wrangler dev --port 8787` +
  `node scripts/local-stack-e2e.mjs` (84 checks; wipe `.wrangler/state`
  only while no workerd holds it — check port 8787 is free first).
- The query-plans latency test seeds 500k rows and takes ~5 s; that is
  expected, not a hang.

## Suggested opening message for the new session

> Continue the TypeDB-on-SlateDB/R2 work. Read
> docs/reviews/consolidated-directive-response.md first — everything
> closable is closed; the "Blocked here, and why" section is the map.
> Then take follow-up 2: U3/U4 coverage via the U3 controller build-out
> (command ledger inv. 85–98, RecoveryAnchor publication), which is the
> largest remaining unblocked work.
