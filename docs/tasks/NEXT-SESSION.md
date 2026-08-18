# Handoff: state after the consolidated-directive session

**Written at:** end of the session that worked the consolidated convergence
and total-quality directive (the independent SWE review) on top of `main`
@ `7fd118f`. Start a new session FROM this branch or from `main` once it is
merged.

## One-paragraph state

The corpus re-run landed: `docs/evidence/G3/u2s3-full-3/` is 106 executables,
105 green, 1 ledgered red, 0 timeouts, 462/2/1 cases, with a **GREEN verdict
over a closed denominator** and an oracle comparison reporting **0
unexplained** divergences.

The truth plane is repaired and now fails closed: both corpus producers
return terminal verdicts, the comparator is symmetric and exact, the
catalogue is joinable to results and checked against the normative v14
contract schema, the source locks pass with the fork patch set bound by
digest, and a root CI workflow runs all of it. The executable defects the
audit itself demonstrated are closed with executed mutants: the capability
gate that accepted an unrestricted token, the controller database that could
not migrate, the dedupe that answered a fresh operation id and recorded
nothing, the caller-supplied replay digest, the caller-owned iteration cut,
the append path whose cost grew with history, the shipping raw `--delete`,
the ignored cache-wipe error, the rename that left a copy behind, and the
post-WAL commit boundary that returned an ordinary error while a durable
obligation stood. F4/F5 is built: ADR-0012 Candidate A is a five-file patch
series over the digest-pinned SlateDB crate with a passing qualifying matrix
and a killed observe-and-bind mutant. **The release decision is still
NO-GO**, and G1 is explicitly not green — but what keeps it red is now U3/U4
coverage and the absent Mode-Q Bazel oracle, not a denominator nobody could
join. See `docs/operations.md`.

## Read these first (15 minutes)

1. `docs/reviews/consolidated-directive-response.md` — every directive
   finding with a status, a commit, and what is actually missing where it
   is not closed. Read this before anything else.
2. `docs/contradictions.json` — four open contract-vs-implementation
   contradictions, each with the safe side taken.
3. `docs/owner-decisions.json` — five values that were deliberately not
   invented.
4. `docs/operations.md` — the gate table (honest), and the truth-plane
   checks to run **before** trusting any run.
5. `fork/slatedb/PATCH-LEDGER.md` — what the SlateDB fork is and, more
   importantly, what it is not.

## Run this first, always

```sh
python3 tools/dev/doctor.py
```

This session's only environment failure was a cold Rust build dying ten
minutes in on a missing `protoc`. Doctor reports that in one second. It also
checks `cmake`, `pkg-config`, both Rust toolchains, the pinned rustfmt
nightly, the source lock and `control-plane/node_modules`.

## Top follow-ups, in order

1. **Q-06 remainder: the Mode-Q Bazel oracle (SI-G0-1).** The catalogue is
   now regenerated from a pristine worktree, validates with 0 errors, and its
   denominator closes against the U2S3 corpus (106 required == 106 rows). The
   one piece the catalogue still lacks is the Bazel cquery oracle v17 selects
   as Mode Q; `bazel_query_oracle` is `null` and no Bazel has ever run here.
   Until it exists the catalogue is self-derived, and G1 cannot be green even
   with U3/U4 covered.

   Regenerating after any source-lock bump:

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

   `--verdict-only` re-derives an archived run's verdict against a repaired
   denominator without re-running the two-hour corpus. Delete
   `sources/pristine-target` afterwards; it is ~6 GB.

2. **Q-03 / §12.4: the controller lifecycle protocol.** Registration is
   still takeover-at-open — any fresh session id takes over. This is the
   largest remaining control-plane hole and it gates Q-02 (capability
   issuance is still open on the L1 facade, which is fine for L1 and not
   fine for anything deployable). It needs `reserveSession` /
   `attestContainer` / `activateSession` with holder nonces, controller-time
   leases and an external recovery root — none of it exists.

3. **Q-01 remainder: the J.5 shared resolver.** The containment guard is in
   and proven, but it decides nothing: `ValidationBasisV1`,
   `TransactionResolutionV1`, idempotent per-keyspace apply markers and the
   failpoint schedule matrix (§9.5) are unbuilt. Pre-G2 this is correctly
   scoped as containment; do not let "guard exists" become "boundary
   repaired" in status prose.

4. **ADR-0012 Candidate B.** Candidate A is built and measured. The
   directive requires a two-candidate spike: a provider-enforced publication
   firewall over stock SlateDB with a fresh credential domain. Until B
   exists there is no comparison and therefore no decision, and the
   production lane must stay on crates.io.

5. **G2 and everything behind it** stays blocked on SI-G0-3 (Cloudflare
   staging credentials). Before requesting them, finish the probe harness
   (Q-08) — the directive is explicit that the harness comes first.

## What is deliberately still OPEN

Marked so in the response document, with the missing part named: Q-02
(issuance authentication), Q-03 (lifecycle), Q-04 (IAM/provider no-delete
proof), Q-07 (per-database backend + driver gates), Q-08 (probes),
Q-13/Q-23 (SlateDB lower-layer retry bounds and a bridge deadline), Q-16
(checkpoint closure), Q-19 (streaming remote helpers), Q-22 (Rocks cursor
`transmute`), Q-24 (key management), Q-28 (journal is not yet an externally
anchored command ledger), and the Mode-Q Bazel oracle.

## Environment notes (save yourself an hour)

- `python3 tools/dev/doctor.py` first. Then
  `python3 tools/source-lock/materialize_sources.py`, then
  `python3 tools/fork/stage.py`.
- `protoc` is required and is NOT in the base image here; install it before
  building (`doctor.py` names the fix).
- Never `pkill rustc` mid-build: cargo orphans into `do_wait` holding
  `target/debug/.cargo-lock` and every later build deadlocks silently. Kill
  the cargos, then `rm target/debug/.cargo-lock`.
- Never `pkill -f "<pattern>"` where the pattern also appears in your own
  command line — it matches your own shell. (Learned the hard way here.)
- Two concurrent cargo builds in one target directory serialise on that
  lock. Use a separate `CARGO_TARGET_DIR` for the pristine catalogue build.
- Disk: `sources/typedb/target` is ~9 GB warm; the corpus runner's `--reap`
  frees binaries as it goes. A second (pristine) build needs its own ~9 GB.
- MinIO: install per `docs/operations.md` and export the `TYPEDB_S3_*`
  variables before any U2S3 test. Two storage lib tests hang, not fail, if
  it is down.
- Control plane: `cd control-plane && npx tsc --noEmit`;
  `node --test --experimental-strip-types src/controller/core/*.test.ts`;
  `npx vitest run`; E2E via `npx wrangler dev --port 8787` +
  `node scripts/local-stack-e2e.mjs` (wipe `.wrangler/state` first — old DO
  SQLite rows predate the current migrations and fail closed, which is the
  intended behaviour).
- Do not run the workerd lanes while a corpus run is executing unless you
  have checked the headroom: the corpus has timing-sensitive targets that
  take hours to re-measure.

## Suggested opening message for the new session

> Continue the TypeDB-on-SlateDB/R2 work. Read
> docs/reviews/consolidated-directive-response.md first (the corpus, the
> catalogue and the denominator are done; the response document says what is
> not). Then take follow-up 2: Q-03/§12.4, the controller lifecycle protocol
> — registration is still takeover-at-open, and it gates Q-02.
