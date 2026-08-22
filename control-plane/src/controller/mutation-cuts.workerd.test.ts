/*
 * R6-CTRL-01 / R6-CTRL-02 through the REAL routes, on workerd.
 *
 * `core/ambiguity-cuts.test.ts` drives all four ambiguity cuts against the
 * authority for every mutation whose effect is local SQLite. This suite is
 * the other half of the evidence:
 *
 *  - it proves the WIRING — that each HTTP route actually records the
 *    effect variant the matrix claims, read back out of `capability_uses`
 *    after a real request. That is the exact thing R6-CTRL-01 found broken:
 *    the reducer branches existed, the routes never bound them;
 *  - it drives cuts (b) EFFECT-COMMITTED-RESOLUTION-LOST, (c)
 *    RESOLVED-RESPONSE-LOST and (d) DELIVERED-AND-RETRIED through the real
 *    worker, by putting the durable use row back into the state a crash
 *    would have left it in and resending the identical request under the
 *    identical token;
 *  - it covers PUT_PAYLOAD, whose physical effect is an R2 object and
 *    therefore cannot be reached from the core lane at all — including the
 *    finest cut there is, between the object store write and the durable
 *    receipt, where ATTEMPT IDENTITY is the only thing that keeps the
 *    answer stable.
 */
import { SELF, env, runInDurableObject } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { DEV_ISSUER_SECRET } from "../shared/key-config.ts";
import { canonicalJson } from "../shared/journal-crypto.ts";
import { localDoName, provisionViaSelf, LOCAL_TENANT } from "./workerd-test-support.ts";
import type { DatabaseControllerDO } from "./database-controller.ts";

interface TestEnv {
  CONTROLLER: DurableObjectNamespace<DatabaseControllerDO>;
  PAYLOADS: R2Bucket;
}
const testEnv = env as unknown as TestEnv;

const DB = "cuts-workerd-db";
const GEN = 1;
const SESSION = "sess-cuts";

async function sha256hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function issue(spec: Record<string, unknown>): Promise<{ token: string; key?: string }> {
  const response = await SELF.fetch("https://facade.local/capability", {
    method: "POST",
    headers: { "content-type": "application/json", "x-issuer-authorization": DEV_ISSUER_SECRET },
    body: JSON.stringify({ principal: "cuts-test", databaseId: DB, ttlMs: 600_000, ...spec }),
  });
  const body = (await response.json()) as { ok?: boolean; token: string; key?: string };
  expect(response.status, JSON.stringify(body)).toBe(200);
  return body;
}

/** The token's nonce — the OPERATION IDENTITY every durable receipt and
 *  every use row for this request is keyed by. */
function nonceOf(token: string): string {
  const b64 = token.split(".")[0].replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return (JSON.parse(atob(padded)) as { nonce: string }).nonce;
}

const controllerStub = () => testEnv.CONTROLLER.get(testEnv.CONTROLLER.idFromName(localDoName(DB)));

/** Run `fn` against the authority's own SQLite (the crash simulator and the
 *  physical-effect probes both need it). */
async function inAuthority<T>(fn: (sql: SqlStorage) => T): Promise<T> {
  return runInDurableObject(controllerStub(), (instance: DatabaseControllerDO) =>
    fn((instance as unknown as { sql: SqlStorage }).sql));
}

/** The effect variant the route durably bound to this use at claim time. */
async function boundEffect(nonce: string): Promise<{ kind: string; method?: string }> {
  const raw = await inAuthority((sql) =>
    sql.exec(`SELECT effect FROM capability_uses WHERE nonce=?`, nonce).toArray());
  expect(raw.length, `no capability use row for ${nonce}`).toBe(1);
  expect(raw[0].effect, `use ${nonce} recorded NO effect`).not.toBeNull();
  return JSON.parse(String(raw[0].effect)) as { kind: string; method?: string };
}

/** CUT (b): the effect committed and the resolution did not. The durable
 *  record a crash there leaves behind is exactly an unresolved claim with
 *  no stored response. */
async function cutAfterEffect(nonce: string): Promise<void> {
  await inAuthority((sql) => {
    sql.exec(`UPDATE capability_uses SET state='IN_FLIGHT', response=NULL WHERE nonce=?`, nonce);
  });
}

/** The finer cut inside a REMOTE effect: the R2 object was written and the
 *  durable receipt was not. Only attempt identity can answer this one. */
async function cutBeforeReceipt(nonce: string): Promise<void> {
  await cutAfterEffect(nonce);
  await inAuthority((sql) => {
    sql.exec(`DELETE FROM operation_receipts WHERE operation_id=?`, nonce);
  });
}

interface Sent { status: number; text: string; body: Record<string, unknown>; nonce: string }

async function send(
  token: string, method: string, path: string, body?: unknown, extra?: HeadersInit,
): Promise<Sent> {
  const headers = new Headers(extra ?? {});
  headers.set("x-capability", token);
  if (body !== undefined) headers.set("content-type", "application/json");
  const response = await SELF.fetch(`https://facade.local${path}`, {
    method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await response.text();
  return { status: response.status, text, body: JSON.parse(text) as Record<string, unknown>,
           nonce: nonceOf(token) };
}

/** One capability, one request — the ordinary path, which also gives us the
 *  nonce to cut on. */
async function once(
  spec: Record<string, unknown>, method: string, path: string, body?: unknown,
): Promise<Sent> {
  const cap = await issue(spec);
  return send(cap.token, method, path, body);
}

/** Publish `content` under its content-addressed key. Returns the response
 *  plus everything needed to replay the identical request. */
async function putPayload(content: string): Promise<{ sent: Sent; token: string; key: string }> {
  const digest = await sha256hex(content);
  const cap = await issue({ method: "PUT_PAYLOAD", digest, maxBytes: content.length });
  const key = cap.key as string;
  const response = await SELF.fetch(`https://facade.local/payload/${key}`, {
    method: "PUT", body: content, headers: { "x-capability": cap.token },
  });
  const text = await response.text();
  return {
    sent: { status: response.status, text, body: JSON.parse(text) as Record<string, unknown>,
            nonce: nonceOf(cap.token) },
    token: cap.token, key,
  };
}

async function rePut(token: string, key: string, content: string): Promise<Sent> {
  const response = await SELF.fetch(`https://facade.local/payload/${key}`, {
    method: "PUT", body: content, headers: { "x-capability": token },
  });
  const text = await response.text();
  return { status: response.status, text, body: JSON.parse(text) as Record<string, unknown>,
           nonce: nonceOf(token) };
}

describe("R6-CTRL-01/02: mutation ambiguity cuts through the real routes (workerd)", () => {
  beforeAll(async () => {
    expect((await provisionViaSelf(DB)).status).toBe(200);
    // reserve -> attest -> activate: the checkpoint and outbox routes both
    // require an actor holding LIVE authority in this generation
    const reserve = await once(
      { method: "SESSION_RESERVE", session: SESSION, generation: GEN },
      "POST", "/session/reserve",
      { databaseId: DB, generation: GEN, startupSessionId: SESSION, holder: "cuts-host" });
    expect(reserve.body.ok, reserve.text).toBe(true);
    const attest = await once(
      { method: "SESSION_ATTEST", session: SESSION },
      "POST", "/session/attest",
      { databaseId: DB, startupSessionId: SESSION, processNonce: "pn-cuts" });
    expect(attest.body.ok, attest.text).toBe(true);
    const activate = await once(
      { method: "SESSION_ACTIVATE", session: SESSION, generation: GEN },
      "POST", "/session/activate",
      { databaseId: DB, generation: GEN, startupSessionId: SESSION,
        processNonce: "pn-cuts", leaseMs: 600_000 });
    expect(activate.body.ok, activate.text).toBe(true);
    // Q-12: a database with no budget row denies every append
    const budgets = await once(
      { method: "BUDGETS_SET", session: SESSION },
      "POST", "/budgets",
      { databaseId: DB, maxUnpublishedOutbox: 1000, maxPayloadLength: 100_000,
        maxTailRecords: 100_000 });
    expect(budgets.body.ok, budgets.text).toBe(true);
  });

  it("PUT_PAYLOAD: the route binds an OPERATION_RECEIPT effect and writes the receipt", async () => {
    const { sent } = await putPayload("cuts-payload-effect");
    expect(sent.status, sent.text).toBe(200);
    expect(await boundEffect(sent.nonce)).toMatchObject(
      { kind: "OPERATION_RECEIPT", method: "PUT_PAYLOAD" });
    const receipt = await inAuthority((sql) =>
      sql.exec(`SELECT method, status, body FROM operation_receipts WHERE operation_id=?`,
        sent.nonce).toArray());
    expect(receipt.length, "the R2 publication recorded no convergence evidence").toBe(1);
    expect(String(receipt[0].method)).toBe("PUT_PAYLOAD");
    // the receipt IS the canonical response: byte-identical to what shipped
    expect(JSON.parse(String(receipt[0].body))).toEqual(sent.body);
  });

  it("PUT_PAYLOAD cuts (c)/(d): a delivered-and-retried request replays byte for byte", async () => {
    const content = "cuts-payload-delivered";
    const { sent, token, key } = await putPayload(content);
    expect(sent.status).toBe(200);
    // (d) the client HAS the response and retries anyway; (c) is the same
    // authority state, only the client's knowledge differs
    const retry = await rePut(token, key, content);
    expect(retry.status).toBe(sent.status);
    expect(retry.text).toBe(sent.text);
    const again = await rePut(token, key, content);
    expect(again.text).toBe(sent.text);
  });

  it("PUT_PAYLOAD cut (b): resolution lost — the durable receipt replays the exact response", async () => {
    const content = "cuts-payload-after-effect";
    const { sent, token, key } = await putPayload(content);
    expect(sent.status).toBe(200);
    await cutAfterEffect(sent.nonce);
    const retry = await rePut(token, key, content);
    expect(retry.text).toBe(sent.text);
  });

  it("PUT_PAYLOAD cut (b'): object written, receipt lost — attempt identity keeps ONE answer", async () => {
    // the finest cut a remote effect has: the R2 create-only put committed
    // and the controller-side receipt did not. Re-executing finds the object
    // already there. Round 5 answered `deduplicated: true` here, i.e. a
    // SECOND canonical body for ONE physical effect under ONE nonce.
    const content = "cuts-payload-before-receipt";
    const { sent, token, key } = await putPayload(content);
    expect(sent.status).toBe(200);
    expect(sent.body.deduplicated).toBeUndefined();
    await cutBeforeReceipt(sent.nonce);
    const retry = await rePut(token, key, content);
    expect(retry.status).toBe(200);
    expect(retry.text).toBe(sent.text);
    expect(retry.body.deduplicated).toBeUndefined();
    // ...and exactly one object exists under the key, with the original bytes
    const object = await testEnv.PAYLOADS.get(key);
    expect(object).not.toBeNull();
    expect(await object!.text()).toBe(content);
    // the flag still MEANS something: a genuinely different upload of the
    // same content, under its own token, is still reported as deduplicated
    const other = await putPayload(content);
    expect(other.sent.body.deduplicated).toBe(true);
  });

  it("PUT_PAYLOAD cut (a): claimed but never uploaded — the retry publishes exactly once", async () => {
    const content = "cuts-payload-before-effect";
    const digest = await sha256hex(content);
    const cap = await issue({ method: "PUT_PAYLOAD", digest, maxBytes: content.length });
    const key = cap.key as string;
    // the worker claimed the use and died before a byte was uploaded: bind
    // the SAME use digest the route computes, so this is that exact state
    const useDigest = await sha256hex(canonicalJson(
      { method: "PUT_PAYLOAD", key, digest, length: content.length }));
    const claimed = await controllerStub().useCapability(
      cap.token,
      { method: "PUT_PAYLOAD", databaseId: DB, tenantId: LOCAL_TENANT, key,
        bodyDigest: digest, bodyLength: content.length },
      useDigest,
      { kind: "OPERATION_RECEIPT", databaseId: DB, method: "PUT_PAYLOAD" });
    expect(claimed.ok, JSON.stringify(claimed)).toBe(true);
    expect(await testEnv.PAYLOADS.get(key)).toBeNull();

    const retry = await rePut(cap.token, key, content);
    expect(retry.status, retry.text).toBe(200);
    expect(retry.body).toEqual({ key, sha256hex: digest, length: content.length });
    expect(await (await testEnv.PAYLOADS.get(key))!.text()).toBe(content);
  });

  it("SESSION_RENEW cut (b): the retry replays the deadline and does NOT extend the lease", async () => {
    const spec = { method: "SESSION_RENEW", session: SESSION };
    const body = { databaseId: DB, startupSessionId: SESSION, leaseMs: 600_000 };
    const cap = await issue(spec);
    const first = await send(cap.token, "POST", "/session/renew", body);
    expect(first.body.ok, first.text).toBe(true);
    expect(await boundEffect(first.nonce)).toMatchObject(
      { kind: "OPERATION_RECEIPT", method: "SESSION_RENEW" });
    const deadline = await inAuthority((sql) => sql.exec(
      `SELECT lease_deadline_ms AS v FROM startup_sessions WHERE startup_session_id=?`,
      SESSION).toArray()[0].v);

    await cutAfterEffect(first.nonce);
    const retry = await send(cap.token, "POST", "/session/renew", body);
    expect(retry.text).toBe(first.text);
    const after = await inAuthority((sql) => sql.exec(
      `SELECT lease_deadline_ms AS v FROM startup_sessions WHERE startup_session_id=?`,
      SESSION).toArray()[0].v);
    expect(after, "the retry advanced durable authority a second time").toBe(deadline);
  });

  it("OUTBOX_ACK cut (b): the retry replays the acknowledged COUNT, not 0", async () => {
    const peek = await once({ method: "OUTBOX" }, "GET", `/outbox/${DB}?limit=50`);
    const events = peek.body.events as { controlSeq: string }[];
    expect(events.length).toBeGreaterThan(0);
    const upTo = events.map((e) => BigInt(e.controlSeq)).reduce((a, b) => (a > b ? a : b)).toString();

    const cap = await issue({ method: "OUTBOX", session: SESSION });
    const ackBody = { upToControlSeq: upTo };
    const first = await send(cap.token, "POST", `/outbox/${DB}/ack`, ackBody);
    expect(first.body.ok, first.text).toBe(true);
    expect(first.body.acked as number).toBeGreaterThan(0);
    expect(await boundEffect(first.nonce)).toMatchObject(
      { kind: "OPERATION_RECEIPT", method: "OUTBOX_ACK" });

    await cutAfterEffect(first.nonce);
    const retry = await send(cap.token, "POST", `/outbox/${DB}/ack`, ackBody);
    expect(retry.text, "the retry reported a different acknowledged count").toBe(first.text);
  });

  it("CHECKPOINT_OPEN cut (b): the retry replays the ORIGINAL cut, not CUT_EXISTS", async () => {
    const cap = await issue({ method: "CHECKPOINT_OPEN", session: SESSION, generation: GEN });
    const body = { cutId: "cuts-cut-1" };
    const first = await send(cap.token, "POST", `/checkpoint/${DB}/${GEN}/cut`, body);
    expect(first.body.ok, first.text).toBe(true);
    // the dead branch, alive: the route binds the cut row as its effect
    expect(await boundEffect(first.nonce)).toMatchObject(
      { kind: "CHECKPOINT_OPEN", cutId: "cuts-cut-1" });

    await cutAfterEffect(first.nonce);
    const retry = await send(cap.token, "POST", `/checkpoint/${DB}/${GEN}/cut`, body);
    expect(retry.body.error, "a lost response re-executed and answered CUT_EXISTS").toBeUndefined();
    expect(retry.text).toBe(first.text);
  });

  it("CHECKPOINT_ACTIVATE cut (b): the retry replays the ORIGINAL success, not CUT_NOT_PENDING", async () => {
    const opened = await once(
      { method: "CHECKPOINT_OPEN", session: SESSION, generation: GEN },
      "POST", `/checkpoint/${DB}/${GEN}/cut`, { cutId: "cuts-cut-2" });
    expect(opened.body.ok, opened.text).toBe(true);

    const HEX64 = "b".repeat(64);
    const evidence = {
      schema: "checkpoint-restore-evidence/v2",
      cutId: "cuts-cut-2",
      walHead: opened.body.headLsn === "-1" ? null : (opened.body.headLsn as string),
      keyspaceRoots: [{ keyspace: "default", rootDigest: HEX64 }],
      logicalDigest: HEX64,
      scratchRestore: { verifier: "cuts-verifier", verifiedAtMs: 1 },
      materializations: ["m-cuts"],
    };
    const cap = await issue({ method: "CHECKPOINT_ACTIVATE", session: SESSION, generation: GEN });
    const first = await send(cap.token, "POST",
      `/checkpoint/${DB}/cut/cuts-cut-2/activate`, evidence);
    expect(first.body.ok, first.text).toBe(true);
    expect(await boundEffect(first.nonce)).toMatchObject(
      { kind: "CHECKPOINT_ACTIVATE", cutId: "cuts-cut-2", logicalDigest: HEX64 });

    await cutAfterEffect(first.nonce);
    const retry = await send(cap.token, "POST",
      `/checkpoint/${DB}/cut/cuts-cut-2/activate`, evidence);
    expect(retry.body.error, "a lost response re-executed and answered CUT_NOT_PENDING").toBeUndefined();
    expect(retry.text).toBe(first.text);
  });

  it("WAL_FINALIZE_BATCH cut (b): the retry replays the ORIGINAL batch receipt", async () => {
    const members = await Promise.all(["batch-bytes-1", "batch-bytes-2"].map(async (content, i) => {
      const put = await putPayload(content);
      expect(put.sent.status, put.sent.text).toBe(200);
      return {
        databaseId: DB, generation: GEN, startupSessionId: SESSION,
        operationId: `cuts-batch-op-${i}`, sequencingKind: "SEQUENCED", recordType: 2,
        logicalKey: null, payloadKey: put.key,
        payloadDigest: await sha256hex(content), payloadLength: content.length,
      };
    }));
    const cap = await issue({ method: "WAL_FINALIZE", session: SESSION, generation: GEN });
    const body = { batchOperationId: "cuts-batch-1", requests: members };
    const first = await send(cap.token, "POST", "/wal/finalize-batch", body);
    expect(first.body.ok, first.text).toBe(true);
    // the second dead branch, alive: the envelope + ordered member digests
    const effect = await boundEffect(first.nonce) as { kind: string; memberDigests?: string[] };
    expect(effect.kind).toBe("WAL_FINALIZE_BATCH");
    expect(effect.memberDigests).toHaveLength(2);

    const tailBefore = await inAuthority((sql) =>
      Number(sql.exec(`SELECT COUNT(*) AS n FROM wal_tail`).toArray()[0].n));
    await cutAfterEffect(first.nonce);
    const retry = await send(cap.token, "POST", "/wal/finalize-batch", body);
    expect(retry.body.ok, retry.text).toBe(true);
    // `replayed` is the documented recovery marker on a reconstructed WAL
    // receipt; every other field, and the physical tail, must be unchanged
    const strip = (r: Sent) => (r.body.results as Record<string, unknown>[])
      .map(({ replayed: _replayed, ...rest }) => rest);
    expect(strip(retry)).toEqual(strip(first));
    const tailAfter = await inAuthority((sql) =>
      Number(sql.exec(`SELECT COUNT(*) AS n FROM wal_tail`).toArray()[0].n));
    expect(tailAfter, "the retry appended a SECOND batch").toBe(tailBefore);
  });

  it("MUTANT: a changed bound field under the same nonce is refused permanently", async () => {
    const cap = await issue({ method: "SESSION_RENEW", session: SESSION });
    const first = await send(cap.token, "POST", "/session/renew",
      { databaseId: DB, startupSessionId: SESSION, leaseMs: 600_000 });
    expect(first.body.ok, first.text).toBe(true);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const conflicting = await send(cap.token, "POST", "/session/renew",
        { databaseId: DB, startupSessionId: SESSION, leaseMs: 599_000 });
      expect(conflicting.status).toBe(403);
      expect(conflicting.body.error).toBe("CAPABILITY_REPLAYED");
    }
    // and the ORIGINAL request still replays its original answer
    const replay = await send(cap.token, "POST", "/session/renew",
      { databaseId: DB, startupSessionId: SESSION, leaseMs: 600_000 });
    expect(replay.text).toBe(first.text);
  });
});
