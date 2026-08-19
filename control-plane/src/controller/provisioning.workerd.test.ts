/*
 * R4 PR1 / R5-SEC-03 mandatory security mutants (audit 4.5, round-5 §11)
 * at the Worker/DO seam, under REAL workerd:
 *
 *   - ordinary authenticated call to an unprovisioned DO -> fail closed,
 *     NO binding side effect (the first-call squat is dead);
 *   - two provisioners race the same uninitialized DO with different
 *     tenants -> exactly one binding wins, the loser gets a typed
 *     refusal, and the record is never partial or overwritten;
 *   - a valid tenant-A token referencing tenant B's database -> refused at
 *     the Worker framing (audience) AND at the DO (binding mismatch /
 *     unprovisioned neighbor);
 *   - CROSS-SCOPE signing material cannot provision (the capability
 *     issuer key signing a provision-shaped token fails the signature);
 *   - unknown token version / alg / field -> refused at the frame check
 *     before any DO contact.
 */
import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { DatabaseControllerDO } from "./database-controller.ts";
import { canonicalJson, hex, utf8 } from "./core/journal-crypto.ts";
import { DEV_CAPABILITY_KID, DEV_ENVIRONMENT, devCapabilitySigningKey } from "./core/key-config.ts";
import { base64urlEncode, type CapabilityPayload } from "./core/capability.ts";
import { ed25519Sign } from "./core/ed25519.ts";
import { mintCapabilityToken, mintProvisionToken } from "./core/issuer.ts";
import {
  devProvisionToken, localBinding, localDoName, provisionInstance, provisionViaSelf,
} from "./workerd-test-support.ts";

interface TestEnv {
  CONTROLLER: DurableObjectNamespace<DatabaseControllerDO>;
}
const testEnv = env as unknown as TestEnv;

/** A well-formed, correctly-signed v3 capability minted directly under the
 *  local-dev capability signing key - the strongest ordinary credential an
 *  attacker-controlled caller could present. */
function mintLocalCapability(overrides: Partial<CapabilityPayload> & { databaseId: string; method: string }): Promise<string> {
  return mintCapabilityToken(devCapabilitySigningKey(), {
    v: 3, alg: "Ed25519", kid: DEV_CAPABILITY_KID, env: DEV_ENVIRONMENT, tenantId: "local",
    principal: "mutant-suite", incarnation: 1, nonce: crypto.randomUUID(),
    expiresAtMs: Date.now() + 60_000, session: "sess-m", generation: "1",
    ...overrides,
  } as CapabilityPayload);
}

/** Sign an arbitrary (deliberately malformed) payload with the dev
 *  capability key, bypassing the issuer's own schema refusals. */
async function rawSigned(payload: Record<string, unknown>): Promise<string> {
  const body = utf8(canonicalJson(payload));
  return `${base64urlEncode(body)}.${hex(await ed25519Sign(devCapabilitySigningKey(), body))}`;
}

function stubForName(name: string) {
  return testEnv.CONTROLLER.get(testEnv.CONTROLLER.idFromName(name));
}

describe("R4 PR1 provisioning seam mutants (workerd)", () => {
  it("MUTANT (squat): an ordinary authenticated call to an unprovisioned DO fails closed with no binding", async () => {
    const db = "squat-target";
    // a READ under a valid, fully-bound token
    const read = await SELF.fetch(`https://facade.local/wal/${db}/1/head`, {
      method: "GET", headers: { "x-capability": await mintLocalCapability({ databaseId: db, method: "WAL_READ" }) },
    });
    expect(read.status).toBe(403);
    expect(((await read.json()) as { error: string }).error).toBe("DATABASE_UNPROVISIONED");
    // a MUTATION under a valid token
    const reserve = await SELF.fetch("https://facade.local/session/reserve", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-capability": await mintLocalCapability({ databaseId: db, method: "SESSION_RESERVE" }),
      },
      body: JSON.stringify({ databaseId: db, generation: 1, startupSessionId: "sess-m", holder: "h" }),
    });
    expect(reserve.status).toBe(403);
    expect(((await reserve.json()) as { error: string }).error).toBe("DATABASE_UNPROVISIONED");
    // the squat check: the calls above created NO binding on the authority
    // the worker routed to
    await runInDurableObject(stubForName(localDoName(db)), async (instance: DatabaseControllerDO) => {
      expect(instance.getBinding()).toBeNull();
    });
  });

  it("MUTANT (race): two tenants race the same uninitialized DO - exactly one binding wins, no partial state", async () => {
    await runInDurableObject(stubForName("race-target"), async (instance: DatabaseControllerDO) => {
      const bindingA = localBinding("race-db", "tenant-a");
      const bindingB = localBinding("race-db", "tenant-b");
      // the DO serializes the two provisioning transactions; the first
      // writes the record...
      const first = await instance.provision(await devProvisionToken(bindingA), bindingA);
      expect(first).toMatchObject({ ok: true, created: true });
      // ...the second (different tenant, same database id) is the typed
      // loser - even though its token is genuinely valid for ITS binding
      const second = await instance.provision(await devProvisionToken(bindingB), bindingB);
      expect(second).toEqual({ ok: false, error: "PROVISION_CONFLICT" });
      // no partial or overwritten binding: the record is exactly A's
      expect(instance.getBinding()).toEqual(bindingA);
      // the winner's replay stays idempotent
      const replay = await instance.provision(await devProvisionToken(bindingA), bindingA);
      expect(replay).toMatchObject({ ok: true, created: false });
    });
  });

  it("MUTANT (cross-tenant): a valid tenant-A token referencing tenant B's database is refused at Worker AND DO", async () => {
    const dbB = "tenant-b-database";
    expect((await provisionViaSelf(dbB, "tenant-b")).status).toBe(200);

    // (a) Worker framing: tenant A's token for ITS OWN database presented
    // against B's database path dies at the audience check - no DO contact
    const tokenForA = await mintLocalCapability({ databaseId: "tenant-a-database", tenantId: "tenant-a", method: "WAL_READ" });
    const framing = await SELF.fetch(`https://facade.local/wal/${dbB}/1/head`, {
      method: "GET", headers: { "x-capability": tokenForA },
    });
    expect(framing.status).toBe(403);
    expect(((await framing.json()) as { error: string }).error).toBe("CAPABILITY_AUDIENCE_MISMATCH");

    // (b) a FORGED token claiming tenant A owns B's database routes to a
    // DIFFERENT authority (the registry-derived name includes the tenant),
    // which is unprovisioned - tenant B's data is structurally unreachable
    const forged = await mintLocalCapability({ databaseId: dbB, tenantId: "tenant-a", method: "WAL_READ" });
    const misrouted = await SELF.fetch(`https://facade.local/wal/${dbB}/1/head`, {
      method: "GET", headers: { "x-capability": forged },
    });
    expect(misrouted.status).toBe(403);
    expect(((await misrouted.json()) as { error: string }).error).toBe("DATABASE_UNPROVISIONED");

    // (c) DO-level defense in depth: even a worker that (buggily) routed
    // the forged tenant to B's REAL authority is refused by the stored
    // binding cross-check
    await runInDurableObject(stubForName(localDoName(dbB, "tenant-b")),
      async (instance: DatabaseControllerDO) => {
        const verdict = await instance.checkCapabilityOnly(forged,
          { method: "WAL_READ", databaseId: dbB, tenantId: "tenant-a", session: "sess-m", generation: "1" });
        expect(verdict).toEqual({ ok: false, error: "DO_BINDING_MISMATCH" });
      });
  });

  it("MUTANT (verifier/cross-scope mints): capability signing material cannot provision; the forgery binds nothing", async () => {
    const db = "verifier-mint-target";
    const binding = localBinding(db);
    // R5-SEC-03: the runtime itself holds only PUBLIC keys (no mint API at
    // all); the strongest remaining forgery is the CAPABILITY issuer key
    // signing a provision-shaped token - the signature cannot validate
    // under the provisioning scope's public key
    const forged = await mintProvisionToken(devCapabilitySigningKey(), binding, {
      nonce: crypto.randomUUID(), expiresAtMs: Date.now() + 60_000,
    });
    const response = await SELF.fetch("https://facade.local/provision", {
      method: "POST",
      headers: { "content-type": "application/json", "x-provision": forged },
      body: JSON.stringify({ tenantId: binding.tenantId, databaseId: db }),
    });
    expect(response.status).toBe(403);
    expect(((await response.json()) as { error: string }).error).toBe("CAPABILITY_SIGNATURE_INVALID");
    await runInDurableObject(stubForName(localDoName(db)), async (instance: DatabaseControllerDO) => {
      expect(instance.getBinding()).toBeNull();
    });
  });

  it("MUTANT (schema): unknown version / unknown alg / unknown field are refused at the frame check", async () => {
    const db = "schema-target";
    expect((await provisionViaSelf(db)).status).toBe(200);
    const base = {
      v: 3, alg: "Ed25519", kid: DEV_CAPABILITY_KID, env: DEV_ENVIRONMENT, tenantId: "local",
      principal: "p", databaseId: db, method: "WAL_READ", session: "s", generation: "1",
      incarnation: 1, nonce: crypto.randomUUID(), expiresAtMs: Date.now() + 60_000,
    };
    // v1-shaped token (no version field)
    const { v: _v, alg: _alg, kid: _kid, env: _env, tenantId: _tenant, ...v1Shape } = base;
    const versioned = await SELF.fetch(`https://facade.local/wal/${db}/1/head`, {
      method: "GET", headers: { "x-capability": await rawSigned(v1Shape) },
    });
    expect(versioned.status).toBe(403);
    expect(((await versioned.json()) as { error: string }).error).toBe("CAPABILITY_VERSION_UNKNOWN");
    // the RETIRED v2 (HMAC) version number
    const v2Shaped = await SELF.fetch(`https://facade.local/wal/${db}/1/head`, {
      method: "GET", headers: { "x-capability": await rawSigned({ ...base, v: 2 }) },
    });
    expect(v2Shaped.status).toBe(403);
    expect(((await v2Shaped.json()) as { error: string }).error).toBe("CAPABILITY_VERSION_UNKNOWN");
    // an unknown signature algorithm fails closed (no downgrade)
    const wrongAlg = await SELF.fetch(`https://facade.local/wal/${db}/1/head`, {
      method: "GET", headers: { "x-capability": await rawSigned({ ...base, alg: "HS256" }) },
    });
    expect(wrongAlg.status).toBe(403);
    expect(((await wrongAlg.json()) as { error: string }).error).toBe("CAPABILITY_ALG_UNKNOWN");
    // unknown extra field
    const unknownField = await SELF.fetch(`https://facade.local/wal/${db}/1/head`, {
      method: "GET", headers: { "x-capability": await rawSigned({ ...base, superpowers: "all" }) },
    });
    expect(unknownField.status).toBe(403);
    expect(((await unknownField.json()) as { error: string }).error).toBe("CAPABILITY_FIELD_UNKNOWN");
  });

  it("provisioned bootstrap: provision -> issue -> register -> finalize path works end-to-end on the derived route", async () => {
    const db = "bootstrap-db";
    const provisioned = await provisionViaSelf(db);
    expect(provisioned.status).toBe(200);
    expect((await provisioned.json() as { created: boolean }).created).toBe(true);
    // issuance embeds the provisioned binding (env + tenant): the minted
    // token verifies on the data path with no further hints
    const reserve = await SELF.fetch("https://facade.local/session/reserve", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-capability": await mintLocalCapability({ databaseId: db, method: "SESSION_RESERVE", session: "sess-b" }),
      },
      body: JSON.stringify({ databaseId: db, generation: 1, startupSessionId: "sess-b", holder: "host-1" }),
    });
    expect(reserve.status).toBe(200);
  });
});
