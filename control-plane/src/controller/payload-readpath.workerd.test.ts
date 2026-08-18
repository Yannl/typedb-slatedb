/*
 * C-06 read-path integrity under REAL workerd, at the F9 capability boundary.
 * The exact-read route re-verifies every payload against its catalogued digest
 * with a STREAMING DigestStream and a hard per-object byte ceiling enforced
 * before the body is read. These two refusals cannot be reached through the
 * honest write path (the 8 MiB write cap + content-addressed immutability), so
 * they are proven by cataloguing a record and then tampering the R2 object
 * directly — exactly the "corrupt/oversized object behind a valid manifest"
 * the read path exists to catch. Mutants:
 *   - an over-cap catalogued object on the read path → typed 413 refusal;
 *   - a corrupted object (same length, different bytes) → digest mismatch 500.
 */
import { SELF, env } from "cloudflare:test";
import { DEV_ISSUER_SECRET } from "./core/key-config.ts";
import { describe, expect, it } from "vitest";

interface TestEnv {
  PAYLOADS: R2Bucket;
}
const testEnv = env as unknown as TestEnv;

const MAX_PAYLOAD_OBJECT_BYTES = 8 * 1024 * 1024;

async function sha256hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function issue(spec: Record<string, unknown>): Promise<{ token: string; key?: string }> {
  const response = await SELF.fetch("https://facade.local/capability", {
    method: "POST",
    headers: { "content-type": "application/json", "x-issuer-authorization": DEV_ISSUER_SECRET },
    body: JSON.stringify({ principal: "readpath-test", ...spec }),
  });
  return (await response.json()) as { token: string; key?: string };
}

async function postJson(path: string, token: string, body: unknown): Promise<Response> {
  return SELF.fetch(`https://facade.local${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-capability": token },
    body: JSON.stringify(body),
  });
}

/** Catalogue one WAL record end-to-end (register → budget → put → finalize),
 *  returning the content-addressed key it was catalogued under. */
async function catalogueRecord(db: string, session: string, gen: number, bytes: Uint8Array): Promise<string> {
  const adminCap = async () =>
    (await issue({ databaseId: db, method: "SESSION_ADMIN", session })).token;

  const reg = await postJson("/session/register", await adminCap(),
    { databaseId: db, generation: gen, startupSessionId: session });
  expect(reg.status).toBe(200);
  const budget = await postJson("/budgets", await adminCap(),
    { databaseId: db, maxUnpublishedOutbox: 10_000, maxPayloadLength: 1_000_000, maxTailRecords: 1_000_000 });
  expect(budget.status).toBe(200);

  const digest = await sha256hex(bytes);
  const putCap = await issue({ databaseId: db, method: "PUT_PAYLOAD", digest, maxBytes: bytes.byteLength });
  const put = await SELF.fetch(`https://facade.local/payload/${putCap.key}`, {
    method: "PUT", body: bytes, headers: { "x-capability": putCap.token },
  });
  expect(put.status).toBe(200);

  const finalizeCap = await issue({ databaseId: db, method: "WAL_FINALIZE", session, generation: gen });
  const finalize = await postJson("/wal/finalize", finalizeCap.token, {
    databaseId: db, generation: gen, startupSessionId: session,
    operationId: "op-readpath", sequencingKind: "SEQUENCED", recordType: 2, logicalKey: null,
    payloadKey: putCap.key, payloadDigest: digest, payloadLength: bytes.byteLength,
  });
  const finalizeBody = (await finalize.json()) as { ok: boolean; appendLsn?: string };
  expect(finalizeBody.ok).toBe(true);
  return putCap.key as string;
}

async function readExact(db: string, gen: number, lsn: number): Promise<Response> {
  const readCap = await issue({ databaseId: db, method: "WAL_READ" });
  return SELF.fetch(`https://facade.local/wal/${db}/${gen}/${lsn}`, {
    method: "GET", headers: { "x-capability": readCap.token },
  });
}

describe("C-06 read-path streaming integrity (workerd)", () => {
  it("valid catalogued record streams back its exact bytes (base64 wire shape preserved)", async () => {
    const db = "readpath-ok";
    const bytes = new TextEncoder().encode("commit-record-readpath");
    await catalogueRecord(db, "sess-ok", 1, bytes);
    const read = await readExact(db, 1, 0);
    expect(read.status).toBe(200);
    const body = (await read.json()) as { ok: boolean; payloadBase64: string };
    expect(body.ok).toBe(true);
    const decoded = Uint8Array.from(atob(body.payloadBase64), (c) => c.charCodeAt(0));
    expect(decoded).toEqual(bytes);
  });

  it("MUTANT: an over-cap catalogued object is refused on the read path (typed 413, not materialised)", async () => {
    const db = "readpath-overcap";
    const bytes = new TextEncoder().encode("small-catalogued-payload");
    const key = await catalogueRecord(db, "sess-oc", 1, bytes);
    // tamper: replace the R2 object with one exceeding the per-object ceiling.
    // Direct put bypasses the route's write cap + immutability (the exact
    // condition — an oversized object behind a valid manifest — the size
    // precheck exists to refuse before reading the body).
    const oversized = new Uint8Array(MAX_PAYLOAD_OBJECT_BYTES + 1);
    await testEnv.PAYLOADS.put(key, oversized);
    const read = await readExact(db, 1, 0);
    expect(read.status).toBe(413);
    const body = (await read.json()) as { error: string; cap: number };
    expect(body.error).toBe("PAYLOAD_EXCEEDS_OBJECT_CAP");
    expect(body.cap).toBe(MAX_PAYLOAD_OBJECT_BYTES);
  });

  it("MUTANT: a corrupted object (same length, different bytes) is caught by the streaming digest (500)", async () => {
    const db = "readpath-corrupt";
    const bytes = new TextEncoder().encode("authentic-payload-bytes");
    const key = await catalogueRecord(db, "sess-cr", 1, bytes);
    // tamper: same byte length so the length check passes, different content so
    // only the recomputed digest catches it — proves the digest is verified,
    // not trusted from the catalogue.
    const corrupted = new Uint8Array(bytes.byteLength).fill(0x41);
    expect(corrupted.byteLength).toBe(bytes.byteLength);
    await testEnv.PAYLOADS.put(key, corrupted);
    const read = await readExact(db, 1, 0);
    expect(read.status).toBe(500);
    const body = (await read.json()) as { error: string };
    expect(body.error).toBe("PAYLOAD_INTEGRITY_VIOLATION");
  });
});
