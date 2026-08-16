# ADR-0006 — Finalisation checks fencing before replay; every lane must produce the same trace

**Status:** accepted (brief inv. 38; enforced across TS core, Rust spike, pure model)

## Context

The remote WAL finalisation procedure answers a retried request for an
operation that was already durably finalised by replaying the original
receipt (exact-once by operation identity, inv. 34–35). Separately, a
session can be **fenced** (stale-actor revocation, inv. 26–28). The two
rules collide on one schedule: *a fenced session retries the identical
finalize whose response it lost before the fence*.

Two defensible orders exist:

- **Replay-first**: the record is immutable history; reporting it to the
  old holder is harmless information.
- **Fence-first**: after fencing, the controller must give the old holder
  *nothing* — simpler authority reasoning, and the reply channel itself is
  part of what fencing revokes.

The brief decides it: inv. 38 — "Fencing after finalisation cannot revoke
the durability truth of the record; **it can prevent the old holder from
applying or reporting it**." The production TS core was initially written
replay-first; both Rust reference lanes (deterministic spike controller,
pure WAL model) were fence-first — a silent trace divergence between the
lanes whose equivalence the conformance method depends on.

## Decision

Fence-first, everywhere: session revalidation precedes the operation-id
replay lookup in the TS `ControllerCore`, the Rust spike, and the pure
model, and the schedule is pinned by tests in all three lanes (the model
test names the invariant; the TS test asserts the durable record survives
the fence untouched — durability is never revoked, only reporting).

By the same "typed outcome or nothing" principle, the client-side
protocol wrappers treat any non-`200 {ok:true}` response to
register/fence as a typed protocol error — a caller must never believe a
fence exists that was never installed.

## Consequences

- A fenced holder can no longer learn its own committed LSNs; recovery
  after failover belongs to the *new* session via read paths, which is the
  intended design (the old actor must treat everything as fenced).
- Trace equivalence across lanes is restored and regression-pinned; any
  future re-ordering fails three suites, not zero.
- The rule generalises: every controller response to a fenced session is
  the typed `SESSION_FENCED`, with no informational side channel.
