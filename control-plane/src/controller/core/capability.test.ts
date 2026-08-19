/*
 * Q-26 / R5-SEC-03 negative controls for the capability gate (schema v3,
 * Ed25519).
 *
 * The consolidation audit executed one direct control against the round-2
 * implementation: a correctly-authenticated `PUT_PAYLOAD` token carrying NO
 * key, NO digest and NO maxBytes, checked against a different key, a
 * different digest and a 999,999,999-byte length. It was accepted
 * (`{ok:true}`). Every restriction was verified as
 * `if (payload.X !== undefined)`, so omitting a restriction did not narrow
 * the capability - it removed the check. The controls below are that exact
 * scenario plus its neighbours, ported to the v3 signature scheme, plus the
 * round-5 asymmetric-specific refusals: unknown alg, unknown kid, retired
 * kid (rotation), and self-signed forgeries under a wrong key.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  verifyCapabilityToken, MAX_CAPABILITY_BYTES,
  type CapabilityPayload, type VerificationKeyring,
} from "./capability.ts";
import { mintCapabilityToken } from "./issuer.ts";
import { generateEd25519KeyPair } from "./ed25519.ts";

const NOW = 1_000_000;

// one issuer keypair for the whole suite (generation is the slow part)
const ISSUER = await generateEd25519KeyPair();
const ATTACKER = await generateEd25519KeyPair();

const KEYRING: VerificationKeyring = {
  scope: "cap", environment: "local",
  keys: [{ kid: "cap:local", publicKey: ISSUER.publicKey, retired: false }],
};

/** The v3 binding fields every token carries: version, algorithm, key id,
 *  environment, tenant. */
const V3 = { v: 3, alg: "Ed25519", kid: "cap:local", env: "local", tenantId: "t1" } as const;

function token(overrides: Partial<CapabilityPayload> = {}, signWith = ISSUER.privateKeyPkcs8): Promise<string> {
  return mintCapabilityToken(signWith, {
    ...V3, principal: "p", databaseId: "db1", method: "PUT_PAYLOAD",
    key: "p/db1/aa", digest: "aa", maxBytes: 1024,
    incarnation: 1, nonce: "n-1", expiresAtMs: NOW + 60_000, ...overrides,
  } as CapabilityPayload);
}

/** Sign an arbitrary (possibly deliberately malformed) payload, bypassing
 *  the issuer's own refusals - the adversarial mint the mutants need. */
async function rawToken(payload: Record<string, unknown>, signWith = ISSUER.privateKeyPkcs8): Promise<string> {
  const { canonicalJson, hex, utf8 } = await import("./journal-crypto.ts");
  const { ed25519Sign } = await import("./ed25519.ts");
  const { base64urlEncode } = await import("./capability.ts");
  const body = utf8(canonicalJson(payload));
  return `${base64urlEncode(body)}.${hex(await ed25519Sign(signWith, body))}`;
}

const request = {
  method: "PUT_PAYLOAD", databaseId: "db1", env: "local", currentIncarnation: 1, nowMs: NOW,
  key: "p/db1/aa", bodyDigest: "aa", bodyLength: 10,
};

test("Q-26: a PUT_PAYLOAD token that omits its restrictions is refused, not widened", async () => {
  // the audit's exact accepted mutant (issuer refusals bypassed via rawToken)
  const unrestricted = await rawToken({
    ...V3, principal: "p", databaseId: "db1", method: "PUT_PAYLOAD",
    incarnation: 1, nonce: "n-1", expiresAtMs: NOW + 60_000,
  });
  const verdict = await verifyCapabilityToken(KEYRING, unrestricted, {
    ...request, key: "p/db1/SOMETHING_ELSE", bodyDigest: "different", bodyLength: 999_999_999,
  });
  assert.deepEqual(verdict, { ok: false, error: "CAPABILITY_RESTRICTION_MISSING" });

  // each restriction is individually mandatory
  for (const omit of ["key", "digest", "maxBytes"] as const) {
    const partial: Record<string, unknown> = {
      ...V3, principal: "p", databaseId: "db1", method: "PUT_PAYLOAD",
      key: "p/db1/aa", digest: "aa", maxBytes: 1024,
      incarnation: 1, nonce: "n-1", expiresAtMs: NOW + 60_000,
    };
    delete partial[omit];
    assert.deepEqual(
      await verifyCapabilityToken(KEYRING, await rawToken(partial), request),
      { ok: false, error: "CAPABILITY_RESTRICTION_MISSING" },
      `omitting ${omit} must refuse`,
    );
  }
});

test("Q-26: a fully restricted token is accepted, and each restriction still binds", async () => {
  const ok = await verifyCapabilityToken(KEYRING, await token(), request);
  assert.ok(ok.ok, "a correctly restricted token must still work");

  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, await token({ key: "p/db1/bb" }), request),
    { ok: false, error: "CAPABILITY_KEY_MISMATCH" },
  );
  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, await token({ digest: "bb" }), request),
    { ok: false, error: "CAPABILITY_DIGEST_MISMATCH" },
  );
  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, await token({ maxBytes: 4 }), request),
    { ok: false, error: "CAPABILITY_BUDGET_EXCEEDED" },
  );
});

test("Q-26: a byte budget above the data-path ceiling is refused at verification", async () => {
  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, await token({ maxBytes: 999_999_999 }),
      { ...request, bodyLength: 900_000_000 }),
    { ok: false, error: "CAPABILITY_BUDGET_ABOVE_CEILING" },
  );
  // exactly at the ceiling is fine; one byte over is not
  assert.ok((await verifyCapabilityToken(KEYRING, await token({ maxBytes: MAX_CAPABILITY_BYTES }), request)).ok);
  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, await token({ maxBytes: MAX_CAPABILITY_BYTES + 1 }), request),
    { ok: false, error: "CAPABILITY_BUDGET_ABOVE_CEILING" },
  );
});

test("MUTANT R5-SEC-03: verifier-only material cannot mint - a self-signed forgery under a wrong key refuses", async () => {
  // The strongest thing a compromised verifier holds is the PUBLIC keyring.
  // There is no API to mint from it (capability.ts exports verification
  // only; minting requires a PRIVATE pkcs8 key, issuer.ts) - so the best an
  // attacker can do is generate its OWN keypair and self-sign a token that
  // CLAIMS the real kid. The signature cannot validate under the real
  // public key: typed refusal, before any authority field is trusted.
  const forged = await token({}, ATTACKER.privateKeyPkcs8);
  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, forged, request),
    { ok: false, error: "CAPABILITY_SIGNATURE_INVALID" });
  // and the public key itself is NOT a signing key: minting "with the
  // verifier's material" is a WebCrypto import failure, not a token
  await assert.rejects(
    () => token({}, ISSUER.publicKey),
    /.*/, "a raw public key must not import as pkcs8 signing material");
});

test("MUTANT R5-SEC-03: a tampered signature or tampered body refuses", async () => {
  const good = await token();
  const flipped = good.slice(0, -1) + (good.endsWith("0") ? "1" : "0");
  assert.deepEqual(await verifyCapabilityToken(KEYRING, flipped, request),
    { ok: false, error: "CAPABILITY_SIGNATURE_INVALID" });
  // splice a modified body onto the original signature
  const [, sig] = good.split(".");
  const other = await token({ maxBytes: 2048 });
  const [otherBody] = other.split(".");
  assert.deepEqual(await verifyCapabilityToken(KEYRING, `${otherBody}.${sig}`, request),
    { ok: false, error: "CAPABILITY_SIGNATURE_INVALID" });
});

test("MUTANT R5-SEC-03: unknown alg / unknown version / unknown kid / unknown field all refuse", async () => {
  const base = {
    ...V3, principal: "p", databaseId: "db1", method: "PUT_PAYLOAD",
    key: "p/db1/aa", digest: "aa", maxBytes: 1024,
    incarnation: 1, nonce: "n-1", expiresAtMs: NOW + 60_000,
  };
  // retired v2 (HMAC) shape: version refusal, never a downgrade
  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, await rawToken({ ...base, v: 2 }), request),
    { ok: false, error: "CAPABILITY_VERSION_UNKNOWN" });
  // v1 shape (no version at all)
  const { v: _v, alg: _alg, kid: _kid, env: _env, tenantId: _t, ...v1Shape } = base;
  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, await rawToken(v1Shape), request),
    { ok: false, error: "CAPABILITY_VERSION_UNKNOWN" });
  // an alg the verifier does not understand fails closed
  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, await rawToken({ ...base, alg: "HS256" }), request),
    { ok: false, error: "CAPABILITY_ALG_UNKNOWN" });
  // a kid of the right scope/env but not in the keyring (attacker-invented
  // rotation slot) is a typed unknown-kid refusal
  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, await rawToken({ ...base, kid: "cap:local/9" }), request),
    { ok: false, error: "CAPABILITY_KID_UNKNOWN" });
  // an unknown field is refused, not ignored
  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, await rawToken({ ...base, superpowers: "all" }), request),
    { ok: false, error: "CAPABILITY_FIELD_UNKNOWN" });
});

test("MUTANT R5-SEC-03 rotation: previous key verifies during overlap, refuses after retirement", async () => {
  const oldPair = await generateEd25519KeyPair();
  const newPair = await generateEd25519KeyPair();
  const mint = (kid: string, pair: { privateKeyPkcs8: Uint8Array }) => mintCapabilityToken(pair.privateKeyPkcs8, {
    ...V3, kid, principal: "p", databaseId: "db1", method: "PUT_PAYLOAD",
    key: "p/db1/aa", digest: "aa", maxBytes: 1024,
    incarnation: 1, nonce: "n-r", expiresAtMs: NOW + 60_000,
  } as CapabilityPayload);
  const oldToken = await mint("cap:local/1", oldPair);
  const newToken = await mint("cap:local/2", newPair);
  // overlap window: both kids live
  const overlap: VerificationKeyring = {
    scope: "cap", environment: "local",
    keys: [
      { kid: "cap:local/2", publicKey: newPair.publicKey, retired: false },
      { kid: "cap:local/1", publicKey: oldPair.publicKey, retired: false },
    ],
  };
  assert.ok((await verifyCapabilityToken(overlap, newToken, request)).ok);
  assert.ok((await verifyCapabilityToken(overlap, oldToken, request)).ok);
  // retirement: the old kid stays RECOGNIZED but refuses with the typed
  // retirement error - not forgeable back to life by re-presenting tokens
  const retired: VerificationKeyring = {
    scope: "cap", environment: "local",
    keys: [
      { kid: "cap:local/2", publicKey: newPair.publicKey, retired: false },
      { kid: "cap:local/1", publicKey: oldPair.publicKey, retired: true },
    ],
  };
  assert.ok((await verifyCapabilityToken(retired, newToken, request)).ok);
  assert.deepEqual(await verifyCapabilityToken(retired, oldToken, request),
    { ok: false, error: "CAPABILITY_KID_RETIRED" });
  // full removal: unknown kid
  const removed: VerificationKeyring = {
    scope: "cap", environment: "local",
    keys: [{ kid: "cap:local/2", publicKey: newPair.publicKey, retired: false }],
  };
  assert.deepEqual(await verifyCapabilityToken(removed, oldToken, request),
    { ok: false, error: "CAPABILITY_KID_UNKNOWN" });
});

test("Q-26/R4-SEC-05: WAL_READ binds session AND generation, both mandatory", async () => {
  // R4-SEC-05: runtime reads are actor-bound - a session/generation-unbound
  // read token is refused by the METHOD's required restrictions, so a
  // fenced actor cannot mint-and-hold an unbound reader.
  const unboundRead = await rawToken({
    ...V3, principal: "p", databaseId: "db1", method: "WAL_READ",
    incarnation: 1, nonce: "n-2", expiresAtMs: NOW + 60_000,
  });
  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, unboundRead, {
      method: "WAL_READ", databaseId: "db1", env: "local", currentIncarnation: 1, nowMs: NOW,
    }),
    { ok: false, error: "CAPABILITY_RESTRICTION_MISSING" },
  );
  // fully actor-bound: fine (use-time liveness is the DO's assertActiveReader)
  const boundRead = await rawToken({
    ...V3, principal: "p", databaseId: "db1", method: "WAL_READ", session: "sess-1", generation: "7",
    incarnation: 1, nonce: "n-2b", expiresAtMs: NOW + 60_000,
  });
  assert.ok((await verifyCapabilityToken(KEYRING, boundRead, {
    method: "WAL_READ", databaseId: "db1", env: "local", currentIncarnation: 1, nowMs: NOW,
  })).ok);
  // and if the ROUTE additionally checks a key/digest/length, the token
  // must bind the matching one (the original Q-26 property, retained)
  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, boundRead, { ...request, method: "WAL_READ" }),
    { ok: false, error: "CAPABILITY_RESTRICTION_MISSING" },
  );
});

test("R4-SEC-04: the capability method space is a CLOSED registry", async () => {
  // an unknown method must refuse at VERIFICATION even when the route
  // (buggily) expects it - `?? []` must never launder it into a
  // restriction-free bearer token
  const rogue = await rawToken({
    ...V3, principal: "p", databaseId: "db1", method: "TOTALLY_NEW_ADMIN",
    incarnation: 1, nonce: "n-x", expiresAtMs: NOW + 60_000,
  });
  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, rogue, {
      method: "TOTALLY_NEW_ADMIN", databaseId: "db1", env: "local", currentIncarnation: 1, nowMs: NOW,
    }),
    { ok: false, error: "CAPABILITY_METHOD_UNKNOWN" },
  );
});

test("Q-26/C-05: WAL_FINALIZE binds session AND generation, both mandatory", async () => {
  const unbound = await rawToken({
    ...V3, principal: "p", databaseId: "db1", method: "WAL_FINALIZE",
    incarnation: 1, nonce: "n-3", expiresAtMs: NOW + 60_000,
  });
  const expect = { method: "WAL_FINALIZE", databaseId: "db1", env: "local", currentIncarnation: 1, nowMs: NOW };
  // no session/generation demanded by the route: still refused, because the
  // METHOD requires both bindings - a route that forgot to pass one would
  // otherwise silently accept an under-bound finalize token
  assert.deepEqual(await verifyCapabilityToken(KEYRING, unbound, expect),
    { ok: false, error: "CAPABILITY_RESTRICTION_MISSING" });
  const bound = await rawToken({
    ...V3, principal: "p", databaseId: "db1", method: "WAL_FINALIZE", session: "sess-1", generation: "3",
    incarnation: 1, nonce: "n-4", expiresAtMs: NOW + 60_000,
  });
  assert.ok((await verifyCapabilityToken(KEYRING, bound, { ...expect, session: "sess-1", generation: "3" })).ok);
  assert.deepEqual(await verifyCapabilityToken(KEYRING, bound, { ...expect, session: "sess-OTHER", generation: "3" }),
    { ok: false, error: "CAPABILITY_SESSION_MISMATCH" });
  // C-05: a token minted for generation 3 cannot finalize generation 4
  assert.deepEqual(await verifyCapabilityToken(KEYRING, bound, { ...expect, session: "sess-1", generation: "4" }),
    { ok: false, error: "CAPABILITY_GENERATION_MISMATCH" });
});

test("R4 PR1/R5-SEC-03: environment, tenant and kid scope are part of the authority", async () => {
  // MUTANT (cross-environment): a token for another environment is refused
  // even when self-consistently signed under the real key - the kid cannot
  // name a foreign environment's scope
  const otherEnv = await rawToken({
    ...V3, env: "prod-eu", kid: "cap:prod-eu",
    principal: "p", databaseId: "db1", method: "PUT_PAYLOAD",
    key: "p/db1/aa", digest: "aa", maxBytes: 1024,
    incarnation: 1, nonce: "n-e", expiresAtMs: NOW + 60_000,
  });
  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, otherEnv, request),
    { ok: false, error: "CAPABILITY_KID_MISMATCH" });
  // env field alone disagreeing (kid still local) is its own refusal
  const envOnly = await rawToken({
    ...V3, env: "prod-eu",
    principal: "p", databaseId: "db1", method: "PUT_PAYLOAD",
    key: "p/db1/aa", digest: "aa", maxBytes: 1024,
    incarnation: 1, nonce: "n-e2", expiresAtMs: NOW + 60_000,
  });
  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, envOnly, request),
    { ok: false, error: "CAPABILITY_ENV_MISMATCH" });
  // MUTANT (cross-tenant): when the verifier expects a tenant (the DO
  // passes its provisioned binding), a token for another tenant is refused
  const good = await token();
  assert.ok((await verifyCapabilityToken(KEYRING, good, { ...request, tenantId: "t1" })).ok);
  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, good, { ...request, tenantId: "t-OTHER" }),
    { ok: false, error: "CAPABILITY_TENANT_MISMATCH" });
  // MUTANT (cross-database): the audience check refuses another database
  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, good, {
      ...request, databaseId: "db-OTHER", key: undefined, bodyDigest: undefined, bodyLength: undefined,
    }),
    { ok: false, error: "CAPABILITY_AUDIENCE_MISMATCH" });
  // an ordinary method claiming the PROVISION scope kid is refused - a
  // token cannot claim one scope while validating under another
  const wrongKid = await rawToken({
    ...V3, kid: "prov:local",
    principal: "p", databaseId: "db1", method: "PUT_PAYLOAD",
    key: "p/db1/aa", digest: "aa", maxBytes: 1024,
    incarnation: 1, nonce: "n-k", expiresAtMs: NOW + 60_000,
  });
  assert.deepEqual(await verifyCapabilityToken(KEYRING, wrongKid, request),
    { ok: false, error: "CAPABILITY_KID_MISMATCH" });
});

test("expiry and incarnation still bound the authority (v3 carries the v2 semantics forward)", async () => {
  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, await token({ expiresAtMs: NOW - 1 }), request),
    { ok: false, error: "CAPABILITY_EXPIRED" });
  assert.deepEqual(
    await verifyCapabilityToken(KEYRING, await token({ incarnation: 99 }), request),
    { ok: false, error: "CAPABILITY_STALE_INCARNATION" });
});
