# User guide

For application developers using TypeDB built from this repository.

## The short version

**Nothing changes at the query surface.** TypeQL, the drivers, the gRPC and
HTTP protocols, transaction semantics, error codes — all identical to
upstream TypeDB at the pinned version (3.12.x line, commit `2256711ab`).
That is not a promise but a measured property: the complete upstream test
corpus (unit, integration, behaviour/Cucumber, assembly) runs against every
storage backend this repo ships, and a backend may only ship when its
results are identical to the RocksDB oracle. For `U2` (SlateDB) the full
sweep is archived: 106 test executables, 450 cases passed, zero timeouts,
with the only failures being two independently documented upstream test
defects that fail for reasons unrelated to the storage engine
(`docs/evidence/G3/u2-vs-oracle-comparison.json`).

What does change is **where your data physically lives**, selected by one
environment variable at server start.

## Choosing a storage profile

```sh
# default: upstream-equivalent RocksDB + file WAL
typedb server

# SlateDB keyspaces over a local object store (same durability guarantees)
TYPEDB_STORAGE_PROFILE=U2 typedb server
```

| Profile | Keyspace engine | What it's for |
|---|---|---|
| unset / `U1` | RocksDB | production default today; the conformance oracle |
| `U2` | SlateDB over local filesystem | the object-store engine, locally; the stepping stone to R2 |
| `U3`, `U4` | SlateDB + remote WAL / Cloudflare R2 | not yet available — fail closed with a typed error |

Rules:

- **Pick one profile per database directory and stay on it.** The on-disk
  keyspace formats differ (RocksDB SSTs vs SlateDB object files). The
  server resolves the profile once at startup and refuses unknown values
  rather than guessing.
- To migrate a database between profiles, use export/import (or restore
  from the WAL: keyspace stores are rebuildable — see below). There is no
  in-place format conversion.

## Durability model (both profiles)

Your committed data's durability comes from **TypeDB's write-ahead log**,
not from the keyspace engine:

- A successful commit means the WAL has the transaction. Keyspace stores
  are disposable caches of applied state — if one is lost or corrupted, the
  server rebuilds it from the WAL (or from the latest checkpoint + WAL
  tail) on next start.
- Checkpoints (created by the server, e.g. for backup) capture a
  point-in-time copy of every keyspace plus the watermark needed to replay
  the rest of the WAL. This works identically on both engines.

## Operational differences you may notice on `U2`

- The storage directory contains SlateDB object-store files (`manifest/`,
  `compacted/`, ...) instead of RocksDB files.
- Background compaction is disabled in this lane; disk usage grows with
  write volume until checkpoint/rebuild. This is a deliberate
  correctness-first posture for the local object-store lane.
- Size/key-count statistics are computed differently (directory size and
  exact scans instead of RocksDB estimates); planner behavior is
  unaffected.

## Limitations (current state)

- One active writer process per database (upstream TypeDB's model; the
  distributed lanes make this an enforced, fenced lease rather than an
  assumption).
- `U3`/`U4` (remote WAL, Cloudflare R2) are implemented at the protocol
  level and fully tested locally, but gated behind real-platform
  measurements (gate G2) before they are exposed.
- Windows is untested for `U2` in this repo; the conformance evidence is
  Linux x86_64.

## Where to go next

- Building and testing: [development.md](development.md)
- How it all works: [architecture.md](architecture.md)
- Gate status and blockers: [operations.md](operations.md)
