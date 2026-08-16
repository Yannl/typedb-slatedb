# End-Product Breakdown Structure (EPBS)

*Arcadia perspective 5 — what the end product is made of: the
configuration items under change control, how each is identified, and how
the product is reconstructed from them.*

## CI-1 Source configuration items (the lock graph)

Normative identity lives in `source-lock/source-lock.json`; the linter
(`tools/source-lock/lint_source_lock.py`) verifies reality against it
mechanically.

| CI | Kind | Identity |
|---|---|---|
| `TB` TypeDB | git checkout | commit `2256711ab…` + tree hash; clean-tree enforced at rest |
| `SL` SlateDB | **crates.io registry** | `slatedb =0.15.0` + sha256 checksums (incl. companions `slatedb-common`, `slatedb-txn-obj`), verified in *every* consumer lockfile (fork + tools) — consume-only per ADR-0001 |
| `BH` typedb-behaviour | git checkout | pinned commit (Cucumber corpus) |
| `TBD`/`TBDIST`/`TQL`/`TPROTO`/`TDRIVER` | git checkouts | the proof-critical TypeDB dependency graph, pinned atomically with `TB` |
| `CF_WORKERS_SDK`, `CF_CTR_SOURCE` | git checkouts | workerd/wrangler & containers sources backing the L1+ rungs |
| `TCONSOLE`, `TLOADER` | binary artifacts | sha256-pinned release archives |
| Toolchains | rust `1.93.0` (parity), rustfmt `nightly-2026-04-15`, node/npm via lockfile | recorded in lock/docs; parity lane never mixes objects with the qualification lane |

## CI-2 Buildable workspaces (federated, ADR-0010)

| CI | Contents | Own lockfile |
|---|---|---|
| `fork/typedb` | the shipped database node (TB-P* patches over the pin) | `fork/typedb/Cargo.lock` |
| `tools/` | proof machinery (catalog, models, spikes, lock lint) | `tools/Cargo.lock` |
| `control-plane/` | Worker + DO + core + suites + E2E | `package-lock.json` |

Change control: every manifest and lockfile is fork-owned; upstream test
files are immutable; every non-test patch has a `PORT-LEDGER.md` entry
with a behavior-preservation argument.

## CI-3 Built artifacts

| CI | Produced by | Identity |
|---|---|---|
| `typedb_server_bin` (+ admin, console/loader repack) | cargo, parity toolchain | offline `--frozen` build proven (G0); sha256 recorded |
| `typedb-all-linux-x86_64.tar.gz` assembly archive | `tools/catalog/package_assembly.py` | sha256 printed at build; installed to `sources/assembly-artifacts/` (the corpus runner's link point) |
| Control-plane bundle | wrangler | pinned compatibility date + lockfile |

## CI-4 Evidence configuration items

Evidence is append-only (superseding runs add files; history is never
rewritten):

| CI | What it certifies |
|---|---|
| `docs/evidence/G0/` | source-graph resolution, vendor manifests, offline build, negative controls |
| `docs/evidence/G1/` | machine catalogue + pristine U0 baseline |
| `docs/evidence/G3/u1-full/`, `u2-full/`, `u2-vs-oracle-comparison.json` | oracle baseline; U2 sweep; structural-equality claim |
| `finding-*.md` | corrected expectations for proven upstream defects (fail-points port race; deleted-storage-dir benchmark) with their deterministic brackets |
| `slatedb-differential*.json` | engine-semantics ground truth at each SlateDB identity |
| `static-checks*.json` | 141 static conformance checks |

## CI-5 Decision and description items

The ADR set (`../ADR/`), the Arcadia perspective set (this folder), the
operational docs (`../../development.md`, `../../operations.md`,
`../../user-guide.md`, `../../local-dev-parity-plan.md`), and the received
contract (`typedb-r2-implementation-package/`, read-only).

## Reconstruction procedure (product from CIs)

1. Verify CI-1: `python3 tools/source-lock/lint_source_lock.py` → PASS.
2. Materialise the fork from the lock + patches
   (`tools/fork/materialize.sh`; revision read from the lock, never
   hardcoded).
3. Build CI-3 offline from content-verified inputs (cargo `--frozen`;
   registry crates by checksum).
4. Re-establish the claim: run the corpus per profile (runbook in
   `../../operations.md`), compare structurally, expect exactly the
   corrected-expectation set and nothing else red.
