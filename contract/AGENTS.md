# AGENTS.md — operating instructions for the implementation agent

You are the source-owning implementation agent for the TypeDB-on-SlateDB/R2 programme. This repository contains the complete, self-contained design contract. You have no access to the design conversation; everything you need is here. Read `typedb-r2-v17-final-addendum.md` §A17.7 for the document order, then follow the phase playbook.

## 1. Ground rules (non-negotiable)

- The architecture contract is `typedb-r2-implementation-brief-v16.md` + `typedb-r2-v17-final-addendum.md` (addendum wins on conflict). Do not re-litigate settled decisions; record genuine source contradictions as evidence and update document+schema+tests together.
- Trust code over prose. Every source-dependent claim must be (re)verified against the pinned checkouts. Every claim you produce carries commit+path+line anchors.
- No gate goes green from a narrative. Only archived, machine-readable evidence (raw commands, raw results, digests) counts.
- No false greens: zero unknown targets/cases/fixtures; skips/ignores/retries are counted, never converted to PASS; negative controls must fail when infrastructure is deliberately broken.
- Bazel is never executed in CI or dev. Mode Q only (one isolated cquery snapshot per source pin, archived as inert evidence).
- Public server APIs (typedb-protocol gRPC + HTTP) never change, in any patch. Driver suites (TypeScript mandatory, Rust+Python minimal) are release gates on both backends (addendum A17.5).
- The `classic` (RocksDB+file-WAL) backend is a shipping mode forever, selected by config; `slatedb-r2` is the remote mode. Identical observable behaviour, proven by U0/U1 equality (A17.4).
- Pre-G13: nothing may delete an authoritative object — by capability construction, not convention.

## 2. Environment bootstrap

Prereqs: Linux x86_64, git, curl, docker (for crash-orchestration ports only), and `proto` (moonrepo's toolchain manager).

```bash
# 1. Fetch every pinned source (extend the script per A17.5: add typedb/typedb-driver at the
#    release matching the TypeDB pin, then re-run; record the resolved commit in the lock).
./fetch-pinned-sources-v16.sh sources/

# 2. Pin toolchains (create .prototools at repo root):
#    moon, rust (channel per source-lock: upstream pins 1.93.0 — run the dual-lane policy of v16 P0-18),
#    node + pnpm (driver TS suites + control plane), python (driver suite), protoc, cmake.
proto install

# 3. Federated workspaces (A17.2): fork/ (upstream-shaped, 41 members), slatedb/, tooling/.
#    Vendor Rust deps per workspace; commit lockfiles; release builds are --frozen --offline.

# 4. Verify reproducibility: two clean path-remapped builds of the server produce identical digests.
```

Key upstream facts you will need immediately (all verified at the pins; re-verify yourself):
- Root `Cargo.toml` is generated ("Do not modify") and Bazel-downstream via `tool/rust/sync.sh` → fork-owned manifests are your first structural change (patch TB-P0 family).
- Target-level census floor: 59 `[[test]]` + 8 bench targets across 13 manifests; leaf cases expand via libtest, doctests, Cucumber scenarios (external corpus `typedb/typedb-behaviour @ ac5d5733…`), `fail_point::ALL` registry members (macro in `common/fail_point`, iterated twice in `tests/assembly/fail_points.rs`), scripts, and static checks.
- Assembly tests need the platform archive env + `script.tql` + a pinned Console fixture; crash orchestration is a docker kill/restart loop to port as a Rust xtask.

## 3. Execution order

Follow `typedb-r2-v16-implementation-playbook.md` phases J.0→ exactly, with stable patch IDs (TB-P*, SL-P*, BT-P*, CF-P*). Currently authorized: **G0–G2 only** (source graph + document integrity; corpus catalogue + pristine U0 baseline; safe boundaries; pure models + Cloudflare real-account probes + remote-append spike). Each later phase unlocks only when the previous phase's Done criteria are archived.

Per-phase evidence lands in `docs/evidence/<phase>/` as: raw command transcripts, machine-readable results (catalogue JSON, runner manifests), digests, and a short human summary that cites — never replaces — the raw artifacts.

## 4. When something contradicts the contract

Stop the affected phase; write a contradiction record (claim, anchor, observed behaviour, minimal correction); update the brief text, schemas, models, and tests in one reviewed change; then resume. Never convert a contradiction into a silent exclusion or a "known issue" comment.
