# ADR-0011 — Fencing is actor-scoped, and registering fences every other actor

**Status:** accepted (U3.0; enforced across TS core, Rust spike client lane, pure model)

## Context

The first cut of the production TS `ControllerCore` treated
register/fence as bookkeeping over independent `(database, generation,
session)` rows: registering inserted a row, fencing flipped one row's
flag, and *nothing fenced the predecessor when a new actor registered*.
Both Rust reference lanes had takeover built in from the start — their
`open_session` advances a monotone counter that implicitly revokes every
earlier session — so the three lanes diverged on the exact schedule the
fencing machinery exists for: **a database is re-opened elsewhere while
the old process still holds a connection** (crash-restart with a zombie,
split-brain during migration). On the TS lane the zombie kept appending;
on the Rust lanes it was fenced. This is the same class of silent
cross-lane divergence ADR-0006 records, on the neighbouring invariant
(inv. 17/26–28: exactly one live writer per database).

Fixing takeover forces a second decision: what is the *unit* of fencing?
Per `(generation, session)` pairs, a session that spans a generation
rollover (one process, `generation` incremented after a rebuild) would
fence *itself* on re-register — or, fenced explicitly in one generation,
would remain writable in the other while being refused re-registration:
a half-revoked actor.

## Decision

The **actor** — the startup session id — is the authority unit for a
database, not the `(generation, session)` pair:

- **Register fences every other actor of the database.** Registration is
  takeover-at-open: after `register(db, g, S)`, every session row of the
  database whose `startup_session_id ≠ S` is fenced, across all
  generations. The same actor re-registering (a generation rollover) does
  not fence itself.
- **A fenced actor can never re-take authority.** If any row of actor `S`
  is fenced, its re-register is a no-op that leaves it fenced — the
  models' session counter only moves forward, so a superseded actor stays
  superseded. Recovering a crashed process re-opens with a *new* startup
  session id.
- **Explicit fencing revokes the actor everywhere.** `fence(db, S)`
  fences all of `S`'s rows; the wire shape still accepts a `generation`
  field for compatibility but it does not scope the revocation.

All three lanes pin the schedule: register(new) → old actor's finalize
is the typed `SESSION_FENCED`; the new actor appends; the durable
records of the fenced actor survive untouched (ADR-0006's rule —
fencing revokes reporting and future appends, never durability).

## Consequences

- The zombie-writer schedule is closed on the production lane, and any
  future re-divergence fails suites in three lanes, not zero.
- `Database::open` on the remote-WAL client (U3.4) gets its intended
  semantics for free: opening *is* taking over; no separate
  fence-the-predecessor call exists to forget.
- One live actor per **database** (not per generation) is the invariant;
  a deliberate multi-writer design across generations would need a new
  ADR superseding this one.
- Operators fencing a runaway process revoke it wholly; there is no
  partially-fenced state to reason about.
