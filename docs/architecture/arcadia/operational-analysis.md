# Operational Analysis (OA)

*Arcadia perspective 1 — what the users of the system need to accomplish,
independent of any system design. No component of this project appears
here; only the world it serves.*

## Operational context

Organisations build applications on TypeDB, a strongly-typed database
queried through TypeQL. Today, operating TypeDB means owning stateful
infrastructure: machines with disks, backup regimes, failover, capacity
planning. A class of adopters wants the database *as a service on
serverless infrastructure they already use* (Cloudflare), where storage is
an object store priced per use and compute is ephemeral.

## Operational actors

| Actor | Who they are | What they care about |
|---|---|---|
| **Application developer** | builds products on TypeQL/drivers | queries behave exactly as documented upstream; local dev is cheap and identical in semantics to production |
| **Platform operator** | runs the database service | durability, recovery, cost, capacity; no bespoke storage fleet; auditable claims, not vendor promises |
| **Data owner / compliance** | accountable for the data | committed data survives failures; history is reconstructible; nothing is silently lost or altered |
| **Upstream TypeDB project** | owns the database's semantics and test corpus | derived works stay faithful; divergences are explicit |
| **Cloud platform (Cloudflare)** | provides R2 / Durable Objects / Workers / Containers | consumed within its real limits, quotas, and consistency contracts |

## Operational capabilities

1. **Run typed database workloads without storage infrastructure** —
   the operator provisions no disks and administers no storage engine;
   the object store is the only durable substrate paid for.
2. **Trust equivalence, not hope for it** — anyone can verify that the
   service's query behavior equals upstream TypeDB's, from evidence, at
   any time.
3. **Survive failure cheaply** — a crashed or discarded compute instance
   loses nothing; recovery is a replay, not a restore-from-tape exercise.
4. **Develop everything locally** — a developer without cloud
   credentials can reproduce, test, and debug the full behavior of the
   service on one machine.

## Operational activities and processes

- **Develop**: write TypeQL, run against a local database, ship — with
  the guarantee that the production backend changes nothing observable.
- **Operate**: create/delete databases; take and restore backups;
  upgrade versions; watch cost and latency envelopes.
- **Recover**: after any compute loss, bring the database back from the
  durable log; after operator error, restore a checkpoint and roll
  forward.
- **Assure**: on every change, re-establish the equivalence claim from
  the upstream corpus; on every platform assumption, obtain a measured
  platform fact.

## Operational needs driving everything downstream

- **N1 Semantic fidelity**: observable behavior must equal the pinned
  upstream TypeDB — measured, not asserted (→ the conformance oracle).
- **N2 Durability with disposable compute**: a single durable
  authoritative history; everything else rebuildable (→ WAL authority).
- **N3 Single-writer integrity under failover**: two instances must
  never both act as the writer, however messy the handover (→ fencing).
- **N4 Cost/latency visibility**: object-store economics must be
  measured before commitment (→ the G2 gate).
- **N5 Locality of development**: full-fidelity local operation
  (→ the parity ladder).
