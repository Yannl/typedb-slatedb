# Operations guide

Gates, evidence, deployment, and runbooks. The contract behind all of this
is the v16 brief; this page is the operational digest.

## Gate status

| Gate | Meaning | Status |
|---|---|---|
| G0 | Source graph materialised, identities resolved, offline build proven | **green** (evidence: `docs/evidence/G0/`) |
| G1 | Complete upstream test catalogue + pristine U0 baseline | **green** (`docs/evidence/G1/`) |
| — | Safe boundaries (TB-P1..P3, BT-P3), pure models, local protocol spikes | **green** (`docs/evidence/G3/`, models in `tools/protocol-models`) |
| TB-P7 / U2 | SlateDB keyspace engine, corpus parity vs oracle | **green** — full corpus: 106 executables, 104 green, 0 timeouts; the 2 red are documented upstream defects (`u2-vs-oracle-comparison.json`) |
| Local total-quality lanes | soak repeatability, compiler-delta, memory safety | **green** — soak run 2: all 106 targets, red = todo-stubs only (fail-points passed twice); 1.97.1 qualification byte-identical; ASan clean on both engines (`qualification-1.97.1.json`, `asan-storage.json`, `u2-soak-2/`) |
| G2 | Real-platform measurements (latency/cost/amplification kill gate) | **blocked** on SI-G0-3 |
| U3/U4, broad TypeDB semantic phases | remote WAL lanes and beyond | gated on G2 |

### Open blockers

- **SI-G0-3 — Cloudflare staging credentials.** See
  [handoff-live-validation.md](handoff-live-validation.md) for the exact
  minimal-scope token setup and the live execution plan. The only unresolved stop
  item. Without a staging account there is no L3 lane, no G2 measurement,
  and no platform-fact validation (real R2 conditional-write behavior,
  throttling, cost envelopes). Everything local is done and green.
- **L2 (container topology)** needs a Docker daemon — available on dev
  machines, absent in the CI sandbox. `npm run stack:local` +
  `wrangler dev` container support is the entry point.

## Evidence conventions

Every gate claim is backed by a machine-readable artifact under
`docs/evidence/<gate>/`:

- catalogue and baselines: `upstream-test-catalog.json`, `u0-results*/`
- per-run corpus results: one JSON row per executable (exit code,
  pass/fail/ignored counts, duration, log path, binary sha256)
- differential/model evidence: e.g. `slatedb-differential-registry.json`
  (the crates.io 0.15.0 semantics re-validation)
- negative controls are part of evidence: checkers must be shown to fail
  when the protected invariant is deliberately broken.

Historical evidence is never rewritten; superseding runs get new files and
the superseded ones remain as the record of what was true at the time.

## Deployment ladder

Local-first is normative (see
[local-dev-parity-plan.md](local-dev-parity-plan.md)): nothing deploys to
Cloudflare until L0→L1→L2 are green, and L3 exists for platform facts and
G2 measurements — not for debugging logic.

1. **L1 (running today)**: `cd control-plane && npx wrangler dev --local`
   boots the production Worker + DO code on real workerd with a local R2
   binding. `node scripts/local-stack-e2e.mjs` must print ALL PASS.
2. **L2**: production container image next to workerd via `wrangler dev`
   containers (Docker required).
3. **L3**: real staging account. First actions when credentials arrive:
   run `control-plane/probes/` (R2 conditional-put semantics, DO
   behavior), then the G2 measurement matrix (p50/p95/p99 append + sync,
   DO transaction throughput, outbox lag, cost amplification).

## Runbooks

### Re-run the full corpus on a profile

```sh
cd sources/typedb && cargo +1.93.0 test --workspace --no-run
python3 tools/catalog/package_assembly.py        # refresh assembly archive
TYPEDB_STORAGE_PROFILE=U2 python3 tools/catalog/run_u0.py --reap \
    --out docs/evidence/G3/u2-full
```

Compare against the oracle baseline (`docs/evidence/G3/u1-full/`): the
pass/fail profile must be identical (including the two upstream `todo!()`
stubs in `test_recovery`). Any new failure is a stop-the-line defect in the
adapter or a genuine semantic gap; nothing is skipped or quarantined to get
green.

### Bump the SlateDB version

1. Edit the pin in `fork/typedb/Cargo.toml` + `tools/storage-diff-spike`
   (workspace dep `slatedb = "=X.Y.Z"`).
2. `cargo update -p slatedb` in both workspaces; record new checksums in
   `source-lock/source-lock.json` node `SL` (companions included).
3. Re-run: the storage-diff differential, full `storage` crate on U2, then
   the full corpus. `python3 tools/source-lock/lint_source_lock.py` must
   pass.
4. Ledger nothing — consume-only means a version bump is a lock change,
   not a patch.

### Bump the TypeDB pin

Atomic across the source graph (brief §1): update every lock node together,
re-materialise `fork/typedb` (`tools/fork/materialize.sh` — it reads the
revision from the lock), replay the TB-P* patch series, regenerate the
catalogue, re-baseline U0/U1, then re-run U2.

### Storage recovery semantics (what to expect in production)

- Keyspace stores (RocksDB and SlateDB alike) are **disposable**: without a
  checkpoint, reopen deletes the storage dir and replays the TypeDB WAL
  from the start; with a checkpoint, the checkpoint is restored and the WAL
  replayed from its watermark.
- A SlateDB checkpoint is a flushed, quiescent copy of the keyspace object
  store (compactor/GC are disabled by design). Restore is a recursive file
  sync — the same code path as RocksDB checkpoints.
- The WAL ahead of a checkpoint must never be truncated: recovery panics
  (fail-closed) if the checkpoint is ahead of the durability log.

### Disk hygiene (CI sandbox)

Build caches dominate: `sources/typedb/target` (~15 GB warm),
`tools/target` (~4 GB). Both are safely deletable (cold rebuild ≈ 30–45
min). Evidence and locks are small; never delete `sources/fixtures` or
`sources/assembly-artifacts` (pinned artifacts).
