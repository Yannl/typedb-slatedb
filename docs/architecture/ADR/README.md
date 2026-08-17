# Architecture Decision Records

Nygard-style records of the decisions that shaped this system. Each ADR
states its context, the decision, and the consequences we accepted.
Perspective documents (../arcadia/) describe the resulting architecture;
ADRs explain *why it is that way and what else was on the table*.

| ADR | Decision | Status |
|---|---|---|
| [ADR-0001](ADR-0001-slatedb-consume-only.md) | SlateDB is a pinned crates.io dependency — no fork; SL-P* patch obligations relocated to owned layers | accepted |
| [ADR-0002](ADR-0002-engine-seam-at-keyspace-layer.md) | Storage-engine seam at the keyspace layer as an enum; profile selected once per process | accepted |
| [ADR-0003](ADR-0003-typedb-wal-sole-durability-authority.md) | TypeDB's WAL is the sole durability authority; engine WALs disabled; keyspace stores disposable | accepted |
| [ADR-0004](ADR-0004-sync-bridge-storage-runtime.md) | One process-wide storage runtime; spawn + std-channel sync bridge | accepted |
| [ADR-0005](ADR-0005-u2-slatedb-configuration-and-checkpoints.md) | U2 posture: no compactor/GC, unbounded L0, manifest-pinned checkpoints | accepted |
| [ADR-0006](ADR-0006-fencing-precedes-replay.md) | Finalisation fences before replaying; all lanes trace-equivalent (brief inv. 38) | accepted |
| [ADR-0007](ADR-0007-payload-immutability-conditional-create.md) | Payload objects are create-or-identical via conditional create | accepted |
| [ADR-0008](ADR-0008-upstream-corpus-as-oracle.md) | Upstream corpus is the conformance oracle; upstream defects get corrected expectations, never edits | accepted |
| [ADR-0009](ADR-0009-local-first-parity-ladder.md) | Local-first on the L0–L3 fidelity ladder; Cloudflare is the last step | accepted |
| [ADR-0010](ADR-0010-cargo-only-federated-workspaces.md) | Cargo-only builds, federated workspaces, machine-verified source lock | accepted |
| [ADR-0011](ADR-0011-actor-scoped-fencing-takeover-at-register.md) | Fencing is actor-scoped; registering is takeover-at-open (fences every other actor) | accepted |
| [ADR-0012](ADR-0012-slatedb-soft-fork-external-epochs.md) | Production lane consumes a SlateDB soft fork carrying exact external epochs (supersedes ADR-0001 there; local lanes stay crates.io) | accepted-as-plan |
| [ADR-0013](ADR-0013-shared-store-vs-per-keyspace.md) | Shared SlateDB store + coalesced writes evaluated against per-keyspace; not adopted pending G2 evidence | evaluated |

Numbering is chronological by decision, not by importance. A decision is
reversed only by a new ADR that names the one it supersedes.
