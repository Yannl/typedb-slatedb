# typedb-slatedb

TypeDB on Cloudflare: a conformance-gated port of [TypeDB](https://github.com/typedb/typedb)'s
storage layer from RocksDB + local WAL to [SlateDB](https://github.com/slatedb/slatedb)
over object storage (Cloudflare R2), with a Durable-Object control plane for
write authority, fencing, and the remote WAL protocol.

The governing principle: **the pinned upstream TypeDB test corpus is the
oracle.** Every storage backend swap must run the same upstream tests and
produce the same results, with every deviation ledgered and evidenced.

## Documentation

| Doc | Audience | Contents |
|---|---|---|
| [docs/architecture.md](docs/architecture.md) | everyone | Architecture entry point: map of the Arcadia perspective set and the ADR index, with reading paths |
| [docs/development.md](docs/development.md) | contributors | Repo layout, building, running every test lane, patch discipline |
| [docs/operations.md](docs/operations.md) | operators | Gates and evidence, deployment ladder, runbooks, open blockers |
| [docs/user-guide.md](docs/user-guide.md) | TypeDB users | What changes (nothing at the query surface), storage profiles, limitations |
| [docs/architecture/ADR/](docs/architecture/ADR/README.md) | everyone | Architecture Decision Records (ADR-0001…0013; ADR-0001 consume-only is SUPERSEDED by ADR-0012, the shipped SlateDB soft fork) |
| [docs/architecture/arcadia/](docs/architecture/arcadia/operational-analysis.md) | everyone | Arcadia/MBSE perspective set (OA, SA, LA, PA, EPBS) |
| [docs/local-dev-parity-plan.md](docs/local-dev-parity-plan.md) | contributors | The L0–L3 local-to-production fidelity ladder |
| [fork/typedb/PORT-LEDGER.md](fork/typedb/PORT-LEDGER.md) | reviewers | Every fork-side patch with its behavior-preservation argument |
| [docs/spec-delivery-comparison.md](docs/spec-delivery-comparison.md) | everyone | Final reconciliation: inception contract vs delivered work packages |
| [docs/inception/](docs/inception/ARCHIVE-NOTE.md) | everyone | The archived ideation/research-phase contract (brief v16 + sidecars) |
| [docs/handoff-live-validation.md](docs/handoff-live-validation.md) | next session | Cloudflare minimal-token setup + empty-context pickup guide for the live test |

## Layout

```
fork/typedb/         soft-fork of TypeDB at the locked pin (TB-P* patches, ledgered)
fork/slatedb/        soft-fork of SlateDB: patch series + provenance (ADR-0012, ledgered)
sources/             pinned source graph (git checkouts + artifacts; lint-verified)
source-lock/         the normative source lock (source-lock.json)
tools/               Rust workspace: corpus catalog/runner, protocol models, spikes
control-plane/       TypeScript workspace: Worker + DatabaseControllerDO + tests
docs/                architecture/dev/ops/user docs, ADRs, gate evidence
docs/inception/       the received v16 contract & research corpus (archived; see its ARCHIVE-NOTE.md)
```

## Storage profiles

| Profile | Keyspaces | Durability | Status |
|---|---|---|---|
| `U0`/`U1` | RocksDB | TypeDB file WAL | oracle; default |
| `U2` | SlateDB (LocalFS object store) | TypeDB file WAL | live — `TYPEDB_STORAGE_PROFILE=U2` |
| `U3` | SlateDB | remote WAL (simulated) | gated on G2 |
| `U4` | SlateDB (R2) | remote WAL (production) | gated on G2 + staging credentials |

SlateDB is consumed as an **in-repo soft fork** of the digest-pinned
crates.io crate `=0.15.0`. `sources/typedb/Cargo.toml` carries a
workspace-global `[patch.crates-io] slatedb = { path =
"../../sources/slatedb-fork" }`, so **every** crate in the product workspace —
`U2`, `U2S3`, `U3`, `U4`, and the RocksDB lanes that merely link `storage` —
resolves SlateDB to `sources/slatedb-fork`, never to the registry artifact.
The fork's identity is the five-patch series in
[`fork/slatedb/patches/`](fork/slatedb/patches) over the checksum-locked
crate, reconstructed byte-for-byte by
`python3 tools/fork/materialize_slatedb.py` and verified against a recorded
post-patch tree digest. Its central patch makes writer/compactor epochs
**externally issued**; the `external_epoch_required` feature is enabled
unconditionally by `fork/typedb/storage/Cargo.toml`, so the fail-closed fence
is shipped default behaviour, not an opt-in.

Why this changed: ADR-0001 originally chose consume-only, and that stance was
**superseded** by ADR-0012 (fork) — first for the production lane, then, when
the patch was made workspace-global, for every lane. ADR-0001 and ADR-0012
both now record the shipped posture; `tools/ci/check_dependency_sources.py`
fails CI if this paragraph and the resolved `cargo metadata` graph ever
disagree again. The one workspace that still resolves the *registry* crate is
`tools/` (no patch table): `tools/storage-diff-spike` measures unmodified
0.15.0 on purpose, which is what makes it an oracle for the fork.
