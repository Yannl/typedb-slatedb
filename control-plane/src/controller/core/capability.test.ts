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

/** The v2 binding fields every token carries (R4 PR1): version, key id,
 *  environment, tenant. */
const V2 = { v: 2, kid: "cap:local", env: "local", tenantId: "t1" } as const;

function token(overrides: Partial<CapabilityPayload> = {}): string {
  return mintCapability(KEY, {
    ...V2, principal: "p", databaseId: "db1", method: "PUT_PAYLOAD",
    incarnation: 1, nonce: "n-1", expiresAtMs: NOW + 60_000, ...overrides,
  } as CapabilityPayload);
}

const request = {
  method: "PUT_PAYLOAD", databaseId: "db1", env: "local", currentIncarnation: 1, nowMs: NOW,
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

test("Q-26/R4-SEC-05: WAL_READ binds session AND generation, both mandatory", () => {
  // R4-SEC-05: runtime reads are actor-bound - a session/generation-unbound
  // read token is refused by the METHOD's required restrictions, so a
  // fenced actor cannot mint-and-hold an unbound reader.
  const unboundRead = mintCapability(KEY, {
    ...V2, principal: "p", databaseId: "db1", method: "WAL_READ",
    incarnation: 1, nonce: "n-2", expiresAtMs: NOW + 60_000,
  } as CapabilityPayload);
  assert.deepEqual(
    checkCapability(KEY, unboundRead, {
      method: "WAL_READ", databaseId: "db1", env: "local", currentIncarnation: 1, nowMs: NOW,
    }),
    { ok: false, error: "CAPABILITY_RESTRICTION_MISSING" },
  );
  // fully actor-bound: fine (use-time liveness is the DO's assertActiveReader)
  const boundRead = mintCapability(KEY, {
    ...V2, principal: "p", databaseId: "db1", method: "WAL_READ", session: "sess-1", generation: "7",
    incarnation: 1, nonce: "n-2b", expiresAtMs: NOW + 60_000,
  } as CapabilityPayload);
  assert.ok(checkCapability(KEY, boundRead, {
    method: "WAL_READ", databaseId: "db1", env: "local", currentIncarnation: 1, nowMs: NOW,
  }).ok);
  // and if the ROUTE additionally checks a key/digest/length, the token
  // must bind the matching one (the original Q-26 property, retained)
  assert.deepEqual(
    checkCapability(KEY, boundRead, { ...request, method: "WAL_READ" }),
    { ok: false, error: "CAPABILITY_RESTRICTION_MISSING" },
  );
});

test("R4-SEC-04: the capability method space is a CLOSED registry", () => {
  // an unknown method must refuse at VERIFICATION even when the route
  // (buggily) expects it - `?? []` must never launder it into a
  // restriction-free bearer token
  const rogue = mintCapability(KEY, {
    ...V2, principal: "p", databaseId: "db1", method: "TOTALLY_NEW_ADMIN",
    incarnation: 1, nonce: "n-x", expiresAtMs: NOW + 60_000,
  } as CapabilityPayload);
  assert.deepEqual(
    checkCapability(KEY, rogue, {
      method: "TOTALLY_NEW_ADMIN", databaseId: "db1", env: "local", currentIncarnation: 1, nowMs: NOW,
    }),
    { ok: false, error: "CAPABILITY_METHOD_UNKNOWN" },
  );
});

test("Q-26/C-05: WAL_FINALIZE binds session AND generation, both mandatory", () => {
  const unbound = mintCapability(KEY, {
    ...V2, principal: "p", databaseId: "db1", method: "WAL_FINALIZE",
    incarnation: 1, nonce: "n-3", expiresAtMs: NOW + 60_000,
  } as CapabilityPayload);
  const expect = { method: "WAL_FINALIZE", databaseId: "db1", env: "local", currentIncarnation: 1, nowMs: NOW };
  // no session/generation demanded by the route: still refused, because the
  // METHOD requires both bindings - a route that forgot to pass one would
  // otherwise silently accept an under-bound finalize token
  assert.deepEqual(checkCapability(KEY, unbound, expect),
    { ok: false, error: "CAPABILITY_RESTRICTION_MISSING" });
  const bound = mintCapability(KEY, {
    ...V2, principal: "p", databaseId: "db1", method: "WAL_FINALIZE", session: "sess-1", generation: "3",
    incarnation: 1, nonce: "n-4", expiresAtMs: NOW + 60_000,
  } as CapabilityPayload);
  assert.ok(checkCapability(KEY, bound, { ...expect, session: "sess-1", generation: "3" }).ok);
  assert.deepEqual(checkCapability(KEY, bound, { ...expect, session: "sess-OTHER", generation: "3" }),
    { ok: false, error: "CAPABILITY_SESSION_MISMATCH" });
  // C-05: a token minted for generation 3 cannot finalize generation 4
  assert.deepEqual(checkCapability(KEY, bound, { ...expect, session: "sess-1", generation: "4" }),
    { ok: false, error: "CAPABILITY_GENERATION_MISMATCH" });
});

test("R4 PR1: token schema is versioned - a v1-shaped or future-versioned token is refused", () => {
  // the retired v1 shape (no v/kid/env/tenantId): version refusal, never a
  // field-by-field guess
  const v1Shaped = mintCapability(KEY, {
    principal: "p", databaseId: "db1", method: "WAL_READ", session: "s", generation: "1",
    incarnation: 1, nonce: "n-v1", expiresAtMs: NOW + 60_000,
  } as unknown as CapabilityPayload);
  assert.deepEqual(
    checkCapability(KEY, v1Shaped, { method: "WAL_READ", databaseId: "db1", env: "local", nowMs: NOW }),
    { ok: false, error: "CAPABILITY_VERSION_UNKNOWN" });
  // a future version the verifier does not understand
  const v3 = token({ v: 3 } as unknown as Partial<CapabilityPayload>);
  assert.deepEqual(checkCapability(KEY, v3, request), { ok: false, error: "CAPABILITY_VERSION_UNKNOWN" });
});

test("R4 PR1: an unknown token field is refused, not ignored", () => {
  // a correctly-MACed token smuggling an extra field: old verifiers must
  // refuse it rather than silently drop a possibly authority-bearing field
  const extra = token({ superpowers: "all" } as unknown as Partial<CapabilityPayload>);
  assert.deepEqual(checkCapability(KEY, extra, request), { ok: false, error: "CAPABILITY_FIELD_UNKNOWN" });
});

test("R4 PR1: environment and tenant are part of the authority", () => {
  // a token for another environment is refused even under the same key
  const otherEnv = token({ env: "prod-eu" } as unknown as Partial<CapabilityPayload>);
  assert.deepEqual(
    checkCapability(KEY, otherEnv, { ...request, key: undefined, bodyDigest: undefined, bodyLength: undefined }),
    { ok: false, error: "CAPABILITY_ENV_MISMATCH" });
  // when the verifier expects a tenant (the DO passes its provisioned
  // binding), a token for another tenant is refused
  const good = token({ key: "p/db1/aa", digest: "aa", maxBytes: 1024 });
  assert.ok(checkCapability(KEY, good, { ...request, tenantId: "t1" }).ok);
  assert.deepEqual(
    checkCapability(KEY, good, { ...request, tenantId: "t-OTHER" }),
    { ok: false, error: "CAPABILITY_TENANT_MISMATCH" });
});

test("R4 PR1: the kid must name the exact scope of the presented method", () => {
  // an ordinary method claiming the PROVISION scope kid (or any other kid)
  // is refused - a token cannot claim one scope while validating under
  // another
  const wrongKid = token({ kid: "prov:local", key: "p/db1/aa", digest: "aa", maxBytes: 1024 });
  assert.deepEqual(checkCapability(KEY, wrongKid, request), { ok: false, error: "CAPABILITY_KID_MISMATCH" });
});
