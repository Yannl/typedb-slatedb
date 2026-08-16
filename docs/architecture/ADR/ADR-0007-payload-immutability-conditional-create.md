# ADR-0007 — Payload objects are create-or-identical, enforced by conditional create

**Status:** accepted (implemented in the payload facade; production enforcement via object-store conditions)

## Context

WAL payload bytes travel a data path separate from finalisation: a client
uploads the payload object, then finalises the record binding the
payload's digest. The controller digest-verifies before finalisation, so a
payload object that changes *after* verification breaks the chain of
custody: a later exact read would fetch bytes that no longer match the
receipt.

The facade's original implementation enforced "create-or-identical" with
get-then-put: read the existing object, compare digests, else write. That
is a TOCTOU window — two concurrent PUTs of different bytes to the same
key can both observe absence and both write; last-writer-wins silently
replaces bytes another client may already have receipt-verified.

## Decision

The create is a **conditional put** (`If-None-Match: *`) — the object
store itself arbitrates exactly one winner. On precondition failure the
facade fetches the (now guaranteed-existing) object and compares digests:
identical → idempotent success (`deduplicated`); different →
`409 PAYLOAD_IMMUTABILITY_VIOLATION` carrying the stored digest. A bounded
retry covers the theoretical delete/create race; exhaustion is a typed
`503`, never a blind write.

The same contract binds every lane: locally the R2 binding's `onlyIf`
honors the precondition (regression-tested with genuinely concurrent
racing PUTs under workerd); in production the enforcement is R2
conditional writes and credential policy — with the caveat, recorded in
the parity plan, that the local simulator's conditional-write behavior is
API-faithful but not evidence-grade, so the platform fact is re-verified
at L3.

## Consequences

- Two racing different-bytes uploads can never both succeed; the loser
  gets a receipt naming the winner's digest, which is exactly the
  information a client needs to detect a payload-key collision.
- Identical-bytes races are harmless and idempotent (at most one create).
- The facade holds no lock and serialises nothing; the object store's
  atomicity is the only synchronisation point, which is the property that
  survives the move to R2 unchanged.
