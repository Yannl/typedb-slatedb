/*
 * Payload facade contract under REAL workerd, at the F9 capability
 * boundary: object keys are issuer-derived and content-addressed
 * (`p/<db>/<sha256hex>`), writes bind key+digest+budget, and puts are
 * create-or-identical with a CONDITIONAL create (If-None-Match: *) as
 * defense in depth beneath the capability check. Regression for the review
 * finding that a get-then-put window let two concurrent puts of different
 * bytes both succeed - under content-addressed keys that race is
 * structurally impossible through the boundary, and this suite pins BOTH
 * layers: the capability refusal and the surviving identical-bytes races.
 */
import { SELF, env } from "cloudflare:test";
import { DEV_ISSUER_SECRET } from "./core/key-config.ts";
import { describe, expect, it } from "vitest";

interface TestEnv {
  PAYLOADS: R2Bucket;
}
const testEnv = env as unknown as TestEnv;

const DB = "payload-test-db";

async function sha256hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function issueCap(spec: Record<string, unknown>): Promise<{ token: string; key?: string }> {
  const response = await SELF.fetch("https://facade.local/capability", {
    method: "POST",
    // Q-02: issuance is credentialed in every posture; this is the L1 dev
    // credential from wrangler.toml's local-dev profile (core/key-config.ts)
    headers: { "content-type": "application/json", "x-issuer-authorization": DEV_ISSUER_SECRET },
    body: JSON.stringify({ principal: "workerd-test", databaseId: DB, ...spec }),
  });
  return (await response.json()) as { token: string; key?: string };
}

/** Capability-bound PUT of `body`; key defaults to the issuer-derived one. */
async function putPayload(body: string, overrideKey?: string): Promise<Response> {
  const digest = await sha256hex(body);
  const cap = await issueCap({ method: "PUT_PAYLOAD", digest, maxBytes: body.length });
  return SELF.fetch(`https://facade.local/payload/${overrideKey ?? cap.key}`, {
    method: "PUT",
    body,
    headers: { "x-capability": cap.token },
  });
}

describe("payload facade on workerd (capability boundary)", () => {
  it("keys are issuer-derived: a caller-selected key is refused before R2", async () => {
    const response = await putPayload("caller-keyed bytes", `${DB}/g1/custom-key`);
    // the malformed (non-content-addressed) key dies at the key-scheme
    // check; a well-formed but different key dies at the binding
    expect(response.status).toBe(400);
    const wellFormed = await putPayload("caller-keyed bytes", `p/${DB}/${"0".repeat(64)}`);
    expect(wellFormed.status).toBe(403);
    expect(((await wellFormed.json()) as { error: string }).error).toBe("CAPABILITY_KEY_MISMATCH");
  });

  it("different bytes cannot collide on one key: the digest binding refuses (immutability at the boundary)", async () => {
    const first = await putPayload("bytes-A");
    expect(first.status).toBe(200);
    const keyOfA = ((await first.json()) as { key: string }).key;
    // adversarial: a valid capability for bytes-B used against A's key
    const digestB = await sha256hex("bytes-B");
    const capB = await issueCap({ method: "PUT_PAYLOAD", digest: digestB, maxBytes: 7 });
    const attack = await SELF.fetch(`https://facade.local/payload/${keyOfA}`, {
      method: "PUT", body: "bytes-B", headers: { "x-capability": capB.token },
    });
    expect(attack.status).toBe(403);
    expect(((await attack.json()) as { error: string }).error).toBe("CAPABILITY_KEY_MISMATCH");
    // A's bytes survive untouched
    const stored = await testEnv.PAYLOADS.get(keyOfA);
    expect(await stored?.text()).toBe("bytes-A");
  });

  it("concurrent puts of IDENTICAL bytes: both succeed, at most one creates (conditional-put defense in depth)", async () => {
    const [a, b] = await Promise.all([putPayload("same-bytes"), putPayload("same-bytes")]);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    const bodies = (await Promise.all([a.json(), b.json()])) as { key: string; deduplicated?: boolean }[];
    expect(bodies.filter((x) => x.deduplicated).length).toBeGreaterThanOrEqual(1);
    const stored = await testEnv.PAYLOADS.get(bodies[0].key);
    expect(await stored?.text()).toBe("same-bytes");
  });

  it("sequential create-then-identical is deduplicated", async () => {
    const created = await putPayload("v1-bytes");
    expect(created.status).toBe(200);
    const dedup = await putPayload("v1-bytes");
    expect(dedup.status).toBe(200);
    expect(((await dedup.json()) as { deduplicated?: boolean }).deduplicated).toBe(true);
  });

  it("C-03: a junk capability is refused by the worker FRAME check, before any DO/R2 work", async () => {
    // a forged, non-token string on a data route to a database that was
    // never provisioned. The outer worker verifies the token's framing/MAC
    // with its OWN key before contacting the DO, so a junk token cannot
    // instantiate, migrate or bind a Durable Object (audit C-03). The
    // refusal is the frame-level typed error.
    const forged = await SELF.fetch("https://facade.local/wal/never-provisioned-db/1/head", {
      method: "GET", headers: { "x-capability": "not-a-real-token" },
    });
    expect(forged.status).toBe(400); // CAPABILITY_MALFORMED at the frame check
    expect(((await forged.json()) as { error: string }).error).toBe("CAPABILITY_MALFORMED");
    // a well-formed but wrong-MAC token is a 403, still at the frame check
    const wrongMac = "eyJhIjoxfQ.".padEnd(75, "0"); // base64url body + 64 hex zeros
    const forgedMac = await SELF.fetch("https://facade.local/wal/never-provisioned-db/1/head", {
      method: "GET", headers: { "x-capability": wrongMac },
    });
    expect([400, 403]).toContain(forgedMac.status);
  });
});
