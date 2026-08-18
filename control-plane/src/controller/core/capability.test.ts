/*
 * Q-26 negative controls for the capability gate.
 *
 * The consolidation audit executed one direct control against the previous
 * implementation: a correctly-MACed `PUT_PAYLOAD` token carrying NO key, NO
 * digest and NO maxBytes, checked against a different key, a different
 * digest and a 999,999,999-byte length. It was accepted (`{ok:true}`).
 * Every restriction was verified as `if (payload.X !== undefined)`, so
 * omitting a restriction did not narrow the capability - it removed the
 * check. The controls below are that exact scenario plus its neighbours.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { checkCapability, mintCapability, MAX_CAPABILITY_BYTES, type CapabilityPayload } from "./capability.ts";

const KEY = new Uint8Array(32).fill(7);
const NOW = 1_000_000;

function token(overrides: Partial<CapabilityPayload> = {}): string {
  return mintCapability(KEY, {
    principal: "p", databaseId: "db1", method: "PUT_PAYLOAD",
    incarnation: 1, nonce: "n-1", expiresAtMs: NOW + 60_000, ...overrides,
  } as CapabilityPayload);
}

const request = {
  method: "PUT_PAYLOAD", databaseId: "db1", currentIncarnation: 1, nowMs: NOW,
  key: "p/db1/aa", bodyDigest: "aa", bodyLength: 10,
};

test("Q-26: a PUT_PAYLOAD token that omits its restrictions is refused, not widened", () => {
  // the audit's exact accepted mutant
  const unrestricted = token();
  const verdict = checkCapability(KEY, unrestricted, {
    ...request, key: "p/db1/SOMETHING_ELSE", bodyDigest: "different", bodyLength: 999_999_999,
  });
  assert.deepEqual(verdict, { ok: false, error: "CAPABILITY_RESTRICTION_MISSING" });

  // each restriction is individually mandatory
  for (const omit of ["key", "digest", "maxBytes"] as const) {
    const partial: Record<string, unknown> = { key: "p/db1/aa", digest: "aa", maxBytes: 1024 };
    delete partial[omit];
    assert.deepEqual(
      checkCapability(KEY, token(partial as Partial<CapabilityPayload>), request),
      { ok: false, error: "CAPABILITY_RESTRICTION_MISSING" },
      `omitting ${omit} must refuse`,
    );
  }
});

test("Q-26: a fully restricted token is accepted, and each restriction still binds", () => {
  const good = token({ key: "p/db1/aa", digest: "aa", maxBytes: 1024 });
  const ok = checkCapability(KEY, good, request);
  assert.ok(ok.ok, "a correctly restricted token must still work");

  assert.deepEqual(
    checkCapability(KEY, token({ key: "p/db1/bb", digest: "aa", maxBytes: 1024 }), request),
    { ok: false, error: "CAPABILITY_KEY_MISMATCH" },
  );
  assert.deepEqual(
    checkCapability(KEY, token({ key: "p/db1/aa", digest: "bb", maxBytes: 1024 }), request),
    { ok: false, error: "CAPABILITY_DIGEST_MISMATCH" },
  );
  assert.deepEqual(
    checkCapability(KEY, token({ key: "p/db1/aa", digest: "aa", maxBytes: 4 }), request),
    { ok: false, error: "CAPABILITY_BUDGET_EXCEEDED" },
  );
});

test("Q-26: a byte budget above the data-path ceiling is refused at verification", () => {
  const oversized = token({ key: "p/db1/aa", digest: "aa", maxBytes: 999_999_999 });
  assert.deepEqual(
    checkCapability(KEY, oversized, { ...request, bodyLength: 900_000_000 }),
    { ok: false, error: "CAPABILITY_BUDGET_ABOVE_CEILING" },
  );
  // exactly at the ceiling is fine; one byte over is not
  assert.ok(checkCapability(KEY, token({ key: "p/db1/aa", digest: "aa", maxBytes: MAX_CAPABILITY_BYTES }),
    request).ok);
  assert.deepEqual(
    checkCapability(KEY, token({ key: "p/db1/aa", digest: "aa", maxBytes: MAX_CAPABILITY_BYTES + 1 }), request),
    { ok: false, error: "CAPABILITY_BUDGET_ABOVE_CEILING" },
  );
});

test("Q-26: a request that needs a restriction cannot be satisfied by a token that declines to bind one", () => {
  // WAL_READ has no method-mandatory restrictions, but if the ROUTE checks a
  // key/digest/length then the token must bind the matching one
  const readToken = mintCapability(KEY, {
    principal: "p", databaseId: "db1", method: "WAL_READ",
    incarnation: 1, nonce: "n-2", expiresAtMs: NOW + 60_000,
  } as CapabilityPayload);
  assert.deepEqual(
    checkCapability(KEY, readToken, { ...request, method: "WAL_READ" }),
    { ok: false, error: "CAPABILITY_RESTRICTION_MISSING" },
  );
  // with no per-request restriction demanded, the same token is fine
  assert.ok(checkCapability(KEY, readToken, {
    method: "WAL_READ", databaseId: "db1", currentIncarnation: 1, nowMs: NOW,
  }).ok);
});

test("Q-26: WAL_FINALIZE stays session-bound (donor A3) and the binding is mandatory", () => {
  const unbound = mintCapability(KEY, {
    principal: "p", databaseId: "db1", method: "WAL_FINALIZE",
    incarnation: 1, nonce: "n-3", expiresAtMs: NOW + 60_000,
  } as CapabilityPayload);
  const expect = { method: "WAL_FINALIZE", databaseId: "db1", currentIncarnation: 1, nowMs: NOW };
  // no session demanded by the route: still refused, because the METHOD
  // requires the binding - otherwise a route that forgot to pass `session`
  // would silently accept an unbound finalize token
  assert.deepEqual(checkCapability(KEY, unbound, expect),
    { ok: false, error: "CAPABILITY_RESTRICTION_MISSING" });
  const bound = mintCapability(KEY, {
    principal: "p", databaseId: "db1", method: "WAL_FINALIZE", session: "sess-1",
    incarnation: 1, nonce: "n-4", expiresAtMs: NOW + 60_000,
  } as CapabilityPayload);
  assert.ok(checkCapability(KEY, bound, { ...expect, session: "sess-1" }).ok);
  assert.deepEqual(checkCapability(KEY, bound, { ...expect, session: "sess-OTHER" }),
    { ok: false, error: "CAPABILITY_SESSION_MISMATCH" });
});
