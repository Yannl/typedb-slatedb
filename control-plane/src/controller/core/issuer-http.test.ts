/*
 * R5-SEC-03/02-seam: the reusable issuer module (scripts/issuer.mjs) and
 * its minimal loopback HTTP issuance mode.
 *
 * Properties under proof:
 *   - tokens minted in-process AND over HTTP verify under the issuer's
 *     published PUBLIC keyrings (the exact vars a managed runtime boots
 *     from), and under nothing else;
 *   - the HTTP mode is 127.0.0.1-only and bearer-authenticated: no bearer,
 *     wrong bearer, junk bodies and unknown routes are typed refusals;
 *   - the issuance spec is validated (unknown method refuses; PUT_PAYLOAD
 *     derives the content-addressed key server-side).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
// the issuer module is the SCRIPTS-side seam; the test imports it exactly
// as the e2e drivers (and later the Rust client's local runner) do
// @ts-ignore: plain .mjs script module
import { createIssuer, startIssuerServer } from "../../../scripts/issuer.mjs";
import { verifyCapabilityToken, type VerificationKeyring } from "../../shared/capability.ts";
import { verifyProvisionToken } from "../../shared/registry.ts";
import { parseVerificationKeyring } from "../../shared/key-config.ts";

const ENV_NAME = "managed-e2e";
const BEARER = "test-bearer-token-0123456789abcdef";

interface Issuer {
  environment: string;
  capabilityKid: string;
  provisionKid: string;
  runtimeVars(): Record<string, string>;
  mintCapability(spec: Record<string, unknown>): Promise<{ token: string; key?: string; expiresAtMs: number }>;
  mintProvision(binding: Record<string, string>, opts?: Record<string, unknown>): Promise<string>;
}

const issuer = (await createIssuer({ environment: ENV_NAME })) as Issuer;

/** The runtime side of this run: keyrings parsed from the EXACT vars the
 *  issuer publishes — the same parse the managed worker performs. */
function runtimeKeyrings(): { cap: VerificationKeyring; prov: VerificationKeyring } {
  const vars = issuer.runtimeVars();
  return {
    cap: parseVerificationKeyring("CONTROLLER_CAPABILITY_PUBLIC_KEYS", "cap", ENV_NAME,
      vars.CONTROLLER_CAPABILITY_PUBLIC_KEYS),
    prov: parseVerificationKeyring("CONTROLLER_PROVISION_PUBLIC_KEYS", "prov", ENV_NAME,
      vars.CONTROLLER_PROVISION_PUBLIC_KEYS),
  };
}

test("issuer: in-process minted tokens verify under the published public keyrings", async () => {
  const { cap, prov } = runtimeKeyrings();
  const issued = await issuer.mintCapability({
    databaseId: "db1", method: "WAL_READ", session: "s-1", generation: 1,
  });
  const verdict = await verifyCapabilityToken(cap, issued.token, {
    method: "WAL_READ", databaseId: "db1", env: ENV_NAME, nowMs: Date.now(),
  });
  assert.ok(verdict.ok, JSON.stringify(verdict));
  assert.equal(verdict.ok && verdict.payload.kid, issuer.capabilityKid);
  const provisionToken = await issuer.mintProvision({
    environment: ENV_NAME, tenantId: "tenant-a", databaseId: "db1",
  });
  const binding = { environment: ENV_NAME, tenantId: "tenant-a", databaseId: "db1" };
  assert.ok((await verifyProvisionToken(prov, provisionToken, { binding, nowMs: Date.now() })).ok);
  // scope separation holds at the issuer too: the provision token does not
  // verify under the capability keyring
  assert.equal(
    (await verifyCapabilityToken(cap, provisionToken, {
      method: "PROVISION", databaseId: "db1", env: ENV_NAME, nowMs: Date.now(),
    })).ok, false);
});

test("issuer: PUT_PAYLOAD derives the content-addressed key; unknown methods refuse", async () => {
  const digest = "ab".repeat(32);
  const issued = await issuer.mintCapability({
    databaseId: "db1", method: "PUT_PAYLOAD", digest, maxBytes: 16,
  });
  assert.equal(issued.key, `p/db1/${digest}`);
  await assert.rejects(() => issuer.mintCapability({ databaseId: "db1", method: "TOTALLY_NEW" }),
    /ISSUE_SPEC_INVALID/);
});

test("issuer HTTP: loopback-only + bearer required by construction", async () => {
  await assert.rejects(() => startIssuerServer(issuer, { host: "0.0.0.0", bearerToken: BEARER }),
    /ISSUER_LOOPBACK_ONLY/);
  await assert.rejects(() => startIssuerServer(issuer, { bearerToken: "short" }),
    /ISSUER_BEARER_REQUIRED/);
});

test("issuer HTTP: POST /issue and /provision-token round-trip; refusal matrix holds", async () => {
  const server = await startIssuerServer(issuer, { bearerToken: BEARER }) as
    { url: string; close(): Promise<void> };
  try {
    const call = async (path: string, body: unknown, headers: Record<string, string> = {}) => {
      const response = await fetch(`${server.url}${path}`, {
        method: "POST", body: JSON.stringify(body),
        headers: { "content-type": "application/json", ...headers },
      });
      return { status: response.status, body: await response.json() as Record<string, unknown> };
    };
    const auth = { authorization: `Bearer ${BEARER}` };

    // no bearer / wrong bearer: typed 401, no token
    const anonymous = await call("/issue", { spec: { databaseId: "db1", method: "WAL_READ", session: "s", generation: 1 } });
    assert.equal(anonymous.status, 401);
    assert.equal(anonymous.body.error, "ISSUER_UNAUTHORIZED");
    const wrong = await call("/issue", { spec: { databaseId: "db1", method: "WAL_READ", session: "s", generation: 1 } },
      { authorization: "Bearer not-the-right-token-at-all" });
    assert.equal(wrong.status, 401);

    // authorized issuance: the token verifies under the runtime keyring
    const issued = await call("/issue",
      { spec: { databaseId: "db1", method: "WAL_READ", session: "s-http", generation: 2 } }, auth);
    assert.equal(issued.status, 200);
    const { cap, prov } = runtimeKeyrings();
    const verdict = await verifyCapabilityToken(cap, String(issued.body.token), {
      method: "WAL_READ", databaseId: "db1", env: ENV_NAME, nowMs: Date.now(),
      session: "s-http", generation: "2",
    });
    assert.ok(verdict.ok, JSON.stringify(verdict));

    // provision token over HTTP
    const provisioned = await call("/provision-token",
      { binding: { tenantId: "tenant-a", databaseId: "db-http" } }, auth);
    assert.equal(provisioned.status, 200);
    const binding = { environment: ENV_NAME, tenantId: "tenant-a", databaseId: "db-http" };
    assert.ok((await verifyProvisionToken(prov, String(provisioned.body.token),
      { binding, nowMs: Date.now() })).ok);

    // refusals: junk body, invalid spec, invalid binding, unknown route
    const junk = await fetch(`${server.url}/issue`, {
      method: "POST", body: "{not json", headers: { ...auth, "content-type": "application/json" } });
    assert.equal(junk.status, 400);
    const badSpec = await call("/issue", { spec: { databaseId: "db1", method: "NOPE" } }, auth);
    assert.equal(badSpec.status, 400);
    assert.equal(badSpec.body.error, "ISSUE_SPEC_INVALID");
    const badBinding = await call("/provision-token", { binding: { tenantId: "BAD/ID", databaseId: "db1" } }, auth);
    assert.equal(badBinding.status, 400);
    assert.equal(badBinding.body.error, "INVALID_BINDING");
    const unknownRoute = await call("/mint-anything", {}, auth);
    assert.equal(unknownRoute.status, 404);
  } finally {
    await server.close();
  }
});
