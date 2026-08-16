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
| [docs/architecture.md](docs/architecture.md) | everyone | System design: planes, storage profiles, engine seam, remote WAL protocol, control plane |
| [docs/development.md](docs/development.md) | contributors | Repo layout, building, running every test lane, patch discipline |
| [docs/operations.md](docs/operations.md) | operators | Gates and evidence, deployment ladder, runbooks, open blockers |
| [docs/user-guide.md](docs/user-guide.md) | TypeDB users | What changes (nothing at the query surface), storage profiles, limitations |
| [docs/ADR-0001-slatedb-consume-only.md](docs/ADR-0001-slatedb-consume-only.md) | everyone | Decision: SlateDB is a pinned crates.io dependency, never a fork |
| [docs/local-dev-parity-plan.md](docs/local-dev-parity-plan.md) | contributors | The L0–L3 local-to-production fidelity ladder |
| [fork/typedb/PORT-LEDGER.md](fork/typedb/PORT-LEDGER.md) | reviewers | Every fork-side patch with its behavior-preservation argument |

## Layout

```
fork/typedb/         soft-fork of TypeDB at the locked pin (TB-P* patches, ledgered)
sources/             pinned source graph (git checkouts + artifacts; lint-verified)
source-lock/         the normative source lock (source-lock.json)
tools/               Rust workspace: corpus catalog/runner, protocol models, spikes
control-plane/       TypeScript workspace: Worker + DatabaseControllerDO + tests
docs/                architecture/dev/ops/user docs, ADRs, gate evidence
typedb-r2-implementation-package/  the v16 implementation contract (brief + playbook)
```

## Storage profiles

| Profile | Keyspaces | Durability | Status |
|---|---|---|---|
| `U0`/`U1` | RocksDB | TypeDB file WAL | oracle; default |
| `U2` | SlateDB (LocalFS object store) | TypeDB file WAL | live — `TYPEDB_STORAGE_PROFILE=U2` |
| `U3` | SlateDB | remote WAL (simulated) | gated on G2 |
| `U4` | SlateDB (R2) | remote WAL (production) | gated on G2 + staging credentials |

SlateDB is consumed **unmodified from crates.io** (`=0.15.0`, checksum-locked)
— see ADR-0001 for why there is deliberately no fork.
