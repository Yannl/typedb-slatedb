# System Analysis (SA)

*Arcadia perspective 2 — what the system must do for its users: the system
as a black box, its boundary, external interfaces, functions, functional
chains, and modes. How it does it belongs to the logical architecture.*

## System mission

Provide TypeDB — semantically identical to the pinned upstream commit —
with keyspace storage on an object store and durability on a
write-ahead-log service, deployable from a single developer machine up to
Cloudflare's platform.

## System boundary and external interfaces

**Inside**: the TypeDB server (query, concept, MVCC, durability client),
the pluggable keyspace storage backend, the database controller service
(sessions, fencing, WAL finalisation, outbox), the payload data path, and
the conformance/verification machinery that substantiates the equivalence
claim.

**Outside (interfaces)**:

| External | Interface | Contract |
|---|---|---|
| Application drivers | gRPC + HTTP (TypeQL) | byte-level protocol of upstream TypeDB 3.12.x at pin `2256711ab` |
| Operator | server CLI/config + one env selector | `TYPEDB_STORAGE_PROFILE` chooses the storage mode; unknown values refused |
| Object store | filesystem (local) / R2 (production) | ordered KV objects; conditional create honored; no unlink-while-open semantics assumed |
| Durability substrate | file WAL (local modes) / remote WAL protocol (distributed modes) | append, sync barrier, bounded iteration, exact replay |
| Upstream corpus | test executables of the pinned commit | executed unmodified; results compared structurally |

## System functions

- **SF1 Serve TypeQL** transactions (read/write/schema) with upstream
  semantics (needs N1).
- **SF2 Persist commits** as authoritative WAL intent history; report
  commit only after durable append (N2).
- **SF3 Materialise state** in keyspace storage rebuildable from SF2's
  history; hide partial application behind a visibility watermark (N2).
- **SF4 Checkpoint and restore** materialised state with roll-forward
  from the watermark (N2, operator recovery).
- **SF5 Enforce single-writer authority**: register, revalidate, and
  fence sessions; refuse every action — including result reporting — to a
  fenced actor (N3).
- **SF6 Transport payloads** out-of-band with create-or-identical
  immutability and digest verification before finalisation (N2, N3).
- **SF7 Publish an ordered event stream** (outbox) of finalised records
  with at-least-once delivery and idempotent acknowledgement.
- **SF8 Prove equivalence**: enumerate the complete upstream corpus,
  execute it per storage mode, and compare structurally against the
  oracle mode (N1).
- **SF9 Measure platform facts** (latency/cost/behavior envelopes)
  before enabling a platform-dependent mode (N4; gate G2).

## Functional chains

- **Commit chain**: driver request → transaction execution → commit
  validation → WAL append (SF2) → keyspace batch apply (SF3) → visibility
  watermark advance → driver acknowledgement.
- **Recovery chain**: open database → checkpoint present? restore (SF4)
  : start empty → replay WAL from watermark/start (SF2→SF3) → serve.
- **Remote finalisation chain** (distributed modes): payload upload (SF6)
  → digest verification → session revalidation (SF5) → exact-once
  finalisation → allocation (LSN/type-sequence/control-seq) → outbox
  publication (SF7) → receipt.
- **Assurance chain**: catalogue discovery → per-mode corpus execution →
  structural comparison → corrected-expectation ledger for proven
  upstream defects (SF8).

## System modes (storage profiles)

| Mode | Meaning | Status |
|---|---|---|
| `U0`/`U1` | oracle: RocksDB keyspaces + file WAL | reference; default |
| `U2` | object-store keyspaces (SlateDB, local FS) + file WAL | live; corpus-equal to oracle |
| `U3` | object-store keyspaces + remote WAL (simulated) | designed; gated on G2 |
| `U4` | production: R2 keyspaces + remote WAL | gated on G2 + credentials |

Mode selection is per process and immutable at runtime; modes never mix
on one storage directory.

## Non-functional requirements

- **Equivalence**: full-corpus structural equality with the oracle mode
  per release (SF8); denominator machine-derived, zero unknowns.
- **Fail-closed**: unknown configuration, unavailable modes, ambiguous
  writes, and fenced actors are typed errors, never fallbacks.
- **Recovery-completeness**: any keyspace state loss ≤ everything since
  last durable WAL record is tolerated and repaired by replay.
- **Measured platform envelopes** before U3/U4: p50/p95/p99 append and
  sync, DO throughput, outbox lag, cost amplification (the G2 kill gate —
  failure triggers protocol redesign, not shipping).
