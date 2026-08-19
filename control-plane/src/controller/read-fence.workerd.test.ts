/*
 * R5-SEC-05 mutants at the WORKER/DO seam, under real workerd.
 *
 * The audit's exact acceptance for the read-fence TOCTOU is:
 *
 *   "Pause after authorization, activate/fence the replacement, then resume
 *    the old read. It must fail or return only a cut explicitly pinned by
 *    the old transaction's valid lease; it may never silently serve as a
 *    current read. Test existing streams, cached Edge routes, and direct
 *    endpoint bypass."
 *
 * The pause is executed literally: the DO's `authorizedRead` is called (the
 * single authoritative hop that verifies the token, revalidates the actor
 * and reads the catalogue), the replacement is then activated through the
 * ordinary fencing route, and only afterwards is the lease redeemed — which
 * is exactly where the worker sits while the R2 bytes are in flight.
 *
 * "Direct endpoint bypass" is covered too: a superseded actor holding an
 * unexpired, perfectly valid WAL_READ token is refused on every read route
 * (there is no second endpoint that answers without the authority hop).
 */
import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { DatabaseControllerDO } from "./database-controller.ts";
import { DEV_ISSUER_SECRET } from "./core/key-config.ts";
import { localDoName, provisionViaSelf } from "./workerd-test-support.ts";

interface TestEnv {
  CONTROLLER: DurableObjectNamespace<DatabaseControllerDO>;
  PAYLOADS: R2Bucket;
}
const testEnv = env as unknown as TestEnv;

async function sha256hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function issue(spec: Record<string, unknown>): Promise<{ token: string; key?: string }> {
  const response = await SELF.fetch("https://facade.local/capability", {
    method: "POST",
    headers: { "content-type": "application/json", "x-issuer-authorization": DEV_ISSUER_SECRET },
    body: JSON.stringify({ principal: "read-fence-suite", ...spec }),
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

/** Provision, register the actor, budget it, upload a payload and catalogue
 *  one WAL record — the ordinary end-to-end write path. */
async function catalogueOne(db: string, session: string, gen: number, bytes: Uint8Array): Promise<string> {
  expect((await provisionViaSelf(db)).status).toBe(200);
  expect((await postJson("/session/register",
    (await issue({ databaseId: db, method: "SESSION_REGISTER", session, generation: gen })).token,
    { databaseId: db, generation: gen, startupSessionId: session })).status).toBe(200);
  expect((await postJson("/budgets",
    (await issue({ databaseId: db, method: "BUDGETS_SET", session })).token,
    { databaseId: db, maxUnpublishedOutbox: 10_000, maxPayloadLength: 1_000_000, maxTailRecords: 1_000_000 })).status)
    .toBe(200);
  const digest = await sha256hex(bytes);
  const put = await issue({ databaseId: db, method: "PUT_PAYLOAD", digest, maxBytes: bytes.byteLength });
  expect((await SELF.fetch(`https://facade.local/payload/${put.key}`, {
    method: "PUT", body: bytes, headers: { "x-capability": put.token },
  })).status).toBe(200);
  const finalize = await postJson("/wal/finalize",
    (await issue({ databaseId: db, method: "WAL_FINALIZE", session, generation: gen })).token, {
      databaseId: db, generation: gen, startupSessionId: session,
      operationId: "op-fence-1", sequencingKind: "SEQUENCED", recordType: 2, logicalKey: null,
      payloadKey: put.key, payloadDigest: digest, payloadLength: bytes.byteLength,
    });
  expect(((await finalize.json()) as { ok: boolean }).ok).toBe(true);
  return put.key as string;
}

async function readToken(db: string, session: string, gen: number): Promise<string> {
  return (await issue({ databaseId: db, method: "WAL_READ", session, generation: gen })).token;
}

describe("R5-SEC-05 read-fence TOCTOU (workerd)", () => {
  it("MUTANT (in-flight single read): pause after authorization, fence, resume -> typed refusal, never served", async () => {
    const db = "fence-inflight";
    const session = "sess-old";
    const gen = 1;
    const key = await catalogueOne(db, session, gen, new TextEncoder().encode("in-flight-bytes"));
    const token = await readToken(db, session, gen);

    const stub = testEnv.CONTROLLER.get(testEnv.CONTROLLER.idFromName(localDoName(db)));
    const lease = await runInDurableObject(stub, async (instance: DatabaseControllerDO) => {
      // ---- the ONE authoritative hop the worker makes before fetching bytes
      const authorized = await instance.authorizedRead(token, { method: "WAL_READ", databaseId: db, tenantId: "local" },
        { kind: "EXACT", generation: gen, appendLsn: 0n });
      expect(authorized.ok).toBe(true);
      return (authorized as { lease: { leaseId: string } }).lease;
    });

    // ---- PAUSE. The worker is now awaiting R2. The replacement activates.
    const fence = await postJson("/session/fence",
      (await issue({ databaseId: db, method: "SESSION_FENCE", session })).token,
      { databaseId: db, generation: gen, startupSessionId: session });
    expect(fence.status).toBe(200);

    // ---- RESUME. The bytes are in hand; redemption is the authoritative cut.
    const redeemed = await runInDurableObject(stub, async (instance: DatabaseControllerDO) =>
      instance.redeemReadLease(lease.leaseId, [key]));
    expect(redeemed.ok).toBe(false);
    expect((redeemed as { error: string }).error).toBe("READ_LEASE_UNKNOWN");
  });

  it("MUTANT (open scan/iterator): a pinned snapshot cannot be served or paged after the fence", async () => {
    const db = "fence-iterator";
    const session = "sess-iter";
    const gen = 1;
    const key = await catalogueOne(db, session, gen, new TextEncoder().encode("iterated-bytes"));

    // open the iterator through the real route (the pinned, server-owned cut)
    const iterator = await SELF.fetch(`https://facade.local/wal/${db}/${gen}/iterator`, {
      method: "POST", headers: { "x-capability": await readToken(db, session, gen) },
    });
    expect(iterator.status).toBe(200);
    const snapshotId = ((await iterator.json()) as { snapshotId: string }).snapshotId;

    const token = await readToken(db, session, gen);
    const stub = testEnv.CONTROLLER.get(testEnv.CONTROLLER.idFromName(localDoName(db)));
    const lease = await runInDurableObject(stub, async (instance: DatabaseControllerDO) => {
      const page = await instance.authorizedRead(token, { method: "WAL_READ", databaseId: db, tenantId: "local" }, {
        kind: "SCAN", generation: gen, snapshotId, fromTypeSequence: 0n, fromLsn: 0n,
        recordType: null, limit: 100, maxBytes: 8 * 1024 * 1024,
      });
      expect(page.ok).toBe(true);
      expect((page as { records: unknown[] }).records.length).toBe(1);
      return (page as { lease: { leaseId: string } }).lease;
    });

    const fence = await postJson("/session/fence",
      (await issue({ databaseId: db, method: "SESSION_FENCE", session })).token,
      { databaseId: db, generation: gen, startupSessionId: session });
    expect(fence.status).toBe(200);

    // the page already authorized cannot be served ...
    const redeemed = await runInDurableObject(stub, async (instance: DatabaseControllerDO) =>
      instance.redeemReadLease(lease.leaseId, [key]));
    expect(redeemed.ok).toBe(false);

    // ... and the NEXT page of the SAME pinned snapshot is refused at the route
    const nextPage = await SELF.fetch(
      `https://facade.local/wal/${db}/${gen}/scan?fromTs=0&snapshotId=${encodeURIComponent(snapshotId)}`,
      { headers: { "x-capability": await readToken(db, session, gen) } });
    expect(nextPage.status).toBe(409);
    expect(((await nextPage.json()) as { error: string }).error).toBe("SESSION_NOT_ACTIVE");
  });

  it("MUTANT (lease replayed after expiry): a redemption past the TTL is refused", async () => {
    const db = "fence-expiry";
    const session = "sess-exp";
    const gen = 1;
    const key = await catalogueOne(db, session, gen, new TextEncoder().encode("expiring-bytes"));
    const token = await readToken(db, session, gen);
    const stub = testEnv.CONTROLLER.get(testEnv.CONTROLLER.idFromName(localDoName(db)));

    const outcome = await runInDurableObject(stub, async (instance: DatabaseControllerDO) => {
      const authorized = await instance.authorizedRead(token,
        { method: "WAL_READ", databaseId: db, tenantId: "local" },
        { kind: "EXACT", generation: gen, appendLsn: 0n });
      expect(authorized.ok).toBe(true);
      const lease = (authorized as { lease: { leaseId: string; expiresAtMs: number } }).lease;
      // force the lease past its TTL without waiting: the row's own deadline
      // is the authority (controller time, not a timer), so expiring it in
      // place is the exact state a slow byte hop produces.
      const sql = (instance as unknown as { sql: SqlStorage }).sql;
      sql.exec(`UPDATE read_leases SET expires_at = 0 WHERE lease_id = ?`, lease.leaseId);
      return instance.redeemReadLease(lease.leaseId, [key]);
    });
    expect(outcome.ok).toBe(false);
    expect((outcome as { error: string }).error).toBe("READ_LEASE_EXPIRED");
  });

  it("MUTANT (direct endpoint bypass): a fenced actor's valid token reads nothing on ANY route", async () => {
    const db = "fence-bypass";
    const session = "sess-bypass";
    const gen = 1;
    await catalogueOne(db, session, gen, new TextEncoder().encode("bypass-bytes"));
    // a token minted BEFORE the fence, still unexpired, still signature-valid
    const token = await readToken(db, session, gen);
    const fence = await postJson("/session/fence",
      (await issue({ databaseId: db, method: "SESSION_FENCE", session })).token,
      { databaseId: db, generation: gen, startupSessionId: session });
    expect(fence.status).toBe(200);

    const routes = [
      `/wal/${db}/${gen}/0`,
      `/wal/${db}/${gen}/head`,
      `/wal/${db}/${gen}/audit`,
      `/wal/${db}/${gen}/last?recordType=2`,
      `/wal/${db}/${gen}/operation/op-fence-1`,
      `/checkpoint/${db}/${gen}/active`,
    ];
    for (const route of routes) {
      const response = await SELF.fetch(`https://facade.local${route}`, { headers: { "x-capability": token } });
      expect([route, response.status]).toEqual([route, 409]);
      expect([route, ((await response.json()) as { error: string }).error])
        .toEqual([route, "SESSION_NOT_ACTIVE"]);
    }
    // the iterator route is a POST and refuses identically
    const iterator = await SELF.fetch(`https://facade.local/wal/${db}/${gen}/iterator`, {
      method: "POST", headers: { "x-capability": token },
    });
    expect(iterator.status).toBe(409);
  });

  it("the live actor is unaffected: reads still serve, and each read consumes exactly one grant", async () => {
    const db = "fence-live";
    const session = "sess-live";
    const gen = 1;
    const bytes = new TextEncoder().encode("still-serving");
    await catalogueOne(db, session, gen, bytes);
    const read = await SELF.fetch(`https://facade.local/wal/${db}/${gen}/0`, {
      headers: { "x-capability": await readToken(db, session, gen) },
    });
    expect(read.status).toBe(200);
    const body = (await read.json()) as { ok: boolean; payloadBase64: string };
    expect(body.ok).toBe(true);
    expect(Uint8Array.from(atob(body.payloadBase64), (c) => c.charCodeAt(0))).toEqual(bytes);
    // the grant was consumed by the redemption, not left outstanding
    const stub = testEnv.CONTROLLER.get(testEnv.CONTROLLER.idFromName(localDoName(db)));
    const outstanding = await runInDurableObject(stub, async (instance: DatabaseControllerDO) =>
      instance.countReadLeases(db, session));
    expect(outstanding).toBe(0);
  });
});
