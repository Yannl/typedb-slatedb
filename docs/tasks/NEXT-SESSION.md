# Handoff: state at merge to main, and what a fresh session does next

**Written at:** end of the V16-convergence + donor-response session
(branch `claude/review-continue-previous-zv4wmi`, tip `f8c1bae` + this doc,
merged to `main`). Start a new session FROM `main`.

## One-paragraph state

Every P0 the V16 convergence audit accepted is closed with code, executed
negative controls, and executed mutant runs; the independent donor's
adversarial audit (branch `claude/typedb-donor-verification-sfxfbz`) filed
4 P0s — all four are closed (two were already covered by this session's
work, two got dedicated fixes). All lanes are green: storage lib 15/15 on
U2S3 (incl. the A6 memo control, mutant-verified), control-plane core
23/23 / journal 7/7 / state 5/5 / workerd 8/8 / L1 E2E 59/59. The full
single-commit corpus evidence exists at `docs/evidence/G3/u2s3-full-2/`
(105/106, 0 unexplained) but predates this session's storage changes — a
re-run is the top follow-up.

## Read these first (10 minutes)

1. `docs/reviews/v16-convergence-audit.md` — the finding-by-finding truth
   table (statuses predate this session's closures; see the commit map
   below for what moved).
2. `docs/reviews/donor-a-branch-response.md` — all 14 donor findings with
   dispositions and SHAs.
3. `docs/design/slatedb-external-epochs.md` — the staged F4/F5 fork design
   (file/symbol level).
4. `docs/operations.md` — gate table + how to run everything.

## Commit map (this session, oldest first)

| SHA | What |
|---|---|
| `e20cff5` | u2s3-full-2 corpus evidence (single-commit, 105/106, 0 unexplained) |
| `997da46` | F7r: exact u64 (BE-blob SQL, bigint core, decimal-string wire) + 2^53 mutant |
| `ed13a9a` | F8: authenticated journal (canonical encoding, chain, MAC) + tamper matrix |
| `fe853aa` | F9r: capability tokens on every route; content-addressed keys; refusal matrix |
| `d47378e` | F7r/F6r: command ledger, CheckpointCut, anchored journal verification |
| `3c00b9e` | F3: immutable materialisation namespaces, NoDeleteStore; F4/F5 posture guard + fork design |
| `b76ad35` | F10r: completeness tooling (fail-closed BUILD parse, leaf recounts, flake ledger) |
| `c71b8e1` | Donor A3: session-bound WAL_FINALIZE capabilities |
| `f8c1bae` | Donor A6: key-count memo actually written; schema lock off the remote scan |

## Top follow-ups, in order

1. **Re-run the single-commit corpus on the merged tree.** The
   `u2s3-full-2` evidence is from `c75a1af`; F3 changed `open_s3` and the
   estimate path since. Run:
   `python3 tools/fork/stage.py && cd sources/typedb && cargo +1.93.0 test --workspace --no-run`
   then `python3 tools/catalog/package_assembly.py` and
   `python3 tools/catalog/run_u0.py --reap --timeout 7200 --out docs/evidence/G3/u2s3-full-3`
   (U2S3 env vars in `docs/operations.md`; MinIO must be up), then
   `python3 tools/catalog/compare_u2s3.py u2s3-full-3`. Expect the same
   105/106 with the storage:storage delta growing by the new controls
   (memo, posture, materialisation, F3 count = +5 lib tests vs u2s3-full-2).
2. **Regenerate the catalogue + green completeness.** `generate_catalog.py`
   was fixed (dead outlines no longer count phantom leaves) but
   `docs/evidence/G1/upstream-test-catalog.json` is not yet regenerated, so
   `python3 tools/catalog/completeness.py --results docs/evidence/G3/u2s3-full-2`
   still reports the 4-leaf cucumber mismatch. Regenerate (needs the cargo
   build warm: `python3 tools/catalog/generate_catalog.py`), re-run
   completeness, commit both.
3. **Update the audit statuses.** `v16-convergence-audit.md` still shows
   F3/F8/F9/F10 with pre-session statuses; fold in the commit map above
   (F3 storage-side closed, F8 closed except R2 RecoveryAnchor publication,
   F9 closed except streaming, F10 closed except Mode-Q Bazel oracle).
4. **Donor P1 remainders** (`donor-a-branch-response.md` has the full
   dispositions): A5 guard `generation` at the wire boundary; A10 give
   `get_prev` a transient-vs-fatal retry channel instead of panic-on-any;
   A9/A11 are U3.2 integration items.
5. **The remaining OPEN-P0s are the big builds**: F4/F5 external-epoch
   SlateDB fork (design staged at file/symbol level), F6r controller-owned
   global CheckpointCut integration with TypeDB (U3.2), F8r immutable R2
   RecoveryAnchor publication. G2/L3 remain blocked on credentials
   (SI-G0-3).

## Environment notes (save yourself an hour)

- Build/test in `sources/typedb` (materialize via
  `python3 tools/source-lock/materialize_sources.py`, then
  `python3 tools/fork/stage.py`). `stage.py` now bumps mtimes — do NOT
  revert that; cargo fingerprints by mtime and stale mutant binaries
  survive restores otherwise.
- Never `pkill rustc` mid-build: cargo orphans into `do_wait` holding
  `target/debug/.cargo-lock`, and every later build deadlocks silently at
  0% CPU. If it happens: kill the cargos, `rm target/debug/.cargo-lock`.
- MinIO: binary + data in the session scratchpad previously; a fresh
  session should install its own (`docs/operations.md`) and export the
  TYPEDB_S3_* env vars before any U2S3 test. Two lib tests hang (not
  fail) if MinIO is down.
- Disk: the session allowance dies at ~38G used; `sources/typedb/target`
  is ~15G after a full corpus build. Delete target/ before a fresh corpus
  run if a previous build generation exists.
- Control-plane: `cd control-plane && npx tsc --noEmit`, node suites via
  `node --test --experimental-strip-types src/controller/core/*.test.ts`,
  `npx vitest run`, E2E via `npx wrangler dev --port 8787` +
  `node scripts/local-stack-e2e.mjs` (wipe `.wrangler/state` first — old
  DO SQLite rows predate the blob-sequence schema and fail closed).

## Suggested opening message for the new session

> Continue the TypeDB-on-SlateDB/R2 work from main (see
> docs/tasks/NEXT-SESSION.md). Start with follow-ups 1–3: re-run the
> single-commit corpus on the merged tree into u2s3-full-3 with the oracle
> comparison, regenerate the test catalogue and get completeness.py green
> against it, and update the V16 audit statuses to reflect the commit map.
> Then continue with the donor P1 remainders (A5 generation guard, A10
> get_prev retry channel) and the staged OPEN-P0 builds per the audit.
