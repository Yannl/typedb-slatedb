/*
 * R5-PERF-01 mutants: no full buffering on the payload path.
 *
 * Write side — DIGEST-DECLARED STREAMING. The capability binds the content
 * digest (which IS the object key) and the declared length, so authority is
 * decided before a byte is read; the body is then streamed to a unique
 * staging attempt while being hashed, verified against the declaration, and
 * promoted to the content-addressed key with a create-only conditional put
 * (the shape the Rust side uses in `JournaledMultipart`).
 *
 * Read side — CONTENT-NEGOTIATED STREAMING. `accept: application/octet-stream`
 * streams the R2 body straight through as the response body with a
 * `content-digest`; the DEFAULT stays the historical base64-in-JSON shape,
 * byte for byte, which is what every current consumer receives.
 *
 * Mutants:
 *   slow sender (body delivered in chunks over time)  -> succeeds, streamed
 *   cancellation mid-stream                           -> refused, nothing published
 *   six concurrent reads                              -> all serve exact bytes
 *   a reported-size lie (declares more than it sends) -> refused
 *   a reported-size lie (sends more than it declares) -> refused
 *   the negotiated legacy shape                       -> byte-identical
 *   a staged upload never publishes wrong bytes       -> key stays absent
 */
import { SELF, env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { DEV_ISSUER_SECRET } from "../shared/key-config.ts";
import { streamedPayloadPut, type Env as WorkerEnv } from "./worker-entry.ts";
import { provisionViaSelf } from "./workerd-test-support.ts";

interface TestEnv {
  PAYLOADS: R2Bucket;
}
const testEnv = env as unknown as TestEnv;
const workerEnv = env as unknown as WorkerEnv;

/** An in-isolate body stream. `chunks` are delivered in order; `failAfter`
 *  (when set) ERRORS the stream after that many chunks — the client that
 *  vanishes mid-upload, expressed without tearing down an HTTP pipe (a
 *  torn-down pipe is a harness artefact, and what is under test is the
 *  worker's own refusal, not the harness's teardown reporting). */
function bodyStream(chunks: Uint8Array[], failAfter?: number): ReadableStream<Uint8Array> {
  let index = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (failAfter !== undefined && index === failAfter) {
        controller.error(new Error("client went away"));
        return;
      }
      if (index >= chunks.length) {
        controller.close();
        return;
      }
      controller.enqueue(chunks[index]);
      index += 1;
    },
  });
}

async function sha256hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function issue(spec: Record<string, unknown>): Promise<{ token: string; key?: string }> {
  const response = await SELF.fetch("https://facade.local/capability", {
    method: "POST",
    headers: { "content-type": "application/json", "x-issuer-authorization": DEV_ISSUER_SECRET },
    body: JSON.stringify({ principal: "payload-stream-suite", ...spec }),
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

/**
 * A request body delivered over TIME, with a declared length. A
 * `FixedLengthStream` readable is the one request-body shape workerd
 * accepts with a known length, so it is also the only way to express both
 * "slow sender" and "reported-size lie" through the real HTTP route.
 * `declared` defaults to the true byte count; pass a different value to lie.
 */
function slowBody(chunks: Uint8Array[], declared?: number) {
  const total = chunks.reduce((n, c) => n + c.byteLength, 0);
  const fixed = new FixedLengthStream(declared ?? total);
  const feed = (async () => {
    const writer = fixed.writable.getWriter();
    try {
      for (const chunk of chunks) {
        await new Promise((resolve) => setTimeout(resolve, 1));
        await writer.write(chunk);
      }
      await writer.close();
    } catch {
      // the lie mutants make close()/write() throw; the request outcome is
      // what the assertions read, not this
    }
  })();
  return { readable: fixed.readable, feed };
}

function splitBytes(bytes: Uint8Array, parts: number): Uint8Array[] {
  const size = Math.ceil(bytes.byteLength / parts);
  const out: Uint8Array[] = [];
  for (let i = 0; i < bytes.byteLength; i += size) out.push(bytes.subarray(i, Math.min(i + size, bytes.byteLength)));
  return out;
}

/** Provision + register + budget one database, returning the actor id. */
async function bootDatabase(db: string, session: string, gen = 1): Promise<void> {
  expect((await provisionViaSelf(db)).status).toBe(200);
  expect((await postJson("/session/register",
    (await issue({ databaseId: db, method: "SESSION_REGISTER", session, generation: gen })).token,
    { databaseId: db, generation: gen, startupSessionId: session })).status).toBe(200);
  expect((await postJson("/budgets",
    (await issue({ databaseId: db, method: "BUDGETS_SET", session })).token,
    { databaseId: db, maxUnpublishedOutbox: 10_000, maxPayloadLength: 1_000_000, maxTailRecords: 1_000_000 })).status)
    .toBe(200);
}

describe("R5-PERF-01 streaming payload write path (workerd)", () => {
  it("MUTANT (slow sender): a body delivered in chunks over time streams to R2 and publishes exactly", async () => {
    const db = "stream-slow";
    await bootDatabase(db, "sess-slow");
    const bytes = crypto.getRandomValues(new Uint8Array(64 * 1024));
    const digest = await sha256hex(bytes);
    const cap = await issue({ databaseId: db, method: "PUT_PAYLOAD", digest, maxBytes: bytes.byteLength });
    const body = slowBody(splitBytes(bytes, 16));
    const response = await SELF.fetch(`https://facade.local/payload/${cap.key}`, {
      method: "PUT", body: body.readable, headers: { "x-capability": cap.token },
      // @ts-expect-error duplex is required for a streaming request body
      duplex: "half",
    });
    await body.feed;
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ key: cap.key, sha256hex: digest, length: bytes.byteLength });
    const stored = await testEnv.PAYLOADS.get(cap.key as string);
    expect(new Uint8Array(await stored!.arrayBuffer())).toEqual(bytes);
    // the staging attempt is reclaimed on the SUCCESS path too
    expect((await testEnv.PAYLOADS.list({ prefix: `s/${db}/` })).objects).toEqual([]);
  });

  it("MUTANT (reported-size lie, under-delivery): declares more than it sends -> refused, nothing published", async () => {
    const db = "stream-lie-short";
    const bytes = new TextEncoder().encode("only-eighteen-byte");
    const digest = await sha256hex(bytes);
    const key = `p/${db}/${digest}`;
    // declares 1024, delivers 18
    const result = await streamedPayloadPut(workerEnv, bodyStream([bytes]), db, key, digest, 1024);
    expect(result).toEqual({ status: 400, body: {
      ok: false, error: "REQUEST_BODY_LENGTH_MISMATCH", declared: 1024, observed: 18 } });
    expect(await testEnv.PAYLOADS.get(key)).toBeNull();
    expect((await testEnv.PAYLOADS.list({ prefix: `s/${db}/` })).objects).toEqual([]);
  });

  it("MUTANT (reported-size lie, over-delivery): sends more than it declares -> refused at the cap", async () => {
    const db = "stream-lie-long";
    const bytes = crypto.getRandomValues(new Uint8Array(4096));
    const digest = await sha256hex(bytes);
    const key = `p/${db}/${digest}`;
    // declares 100, delivers 4096: the excess is refused the instant the
    // running total crosses the declaration, before it reaches the provider
    const result = await streamedPayloadPut(workerEnv, bodyStream(splitBytes(bytes, 8)), db, key, digest, 100);
    const refusal = result.body as { error: string; declared: number; observed: number };
    expect(result.status).toBe(400);
    expect(refusal.error).toBe("REQUEST_BODY_LENGTH_MISMATCH");
    expect(refusal.declared).toBe(100);
    expect(refusal.observed).toBeGreaterThan(100);
    expect(await testEnv.PAYLOADS.get(key)).toBeNull();
    expect((await testEnv.PAYLOADS.list({ prefix: `s/${db}/` })).objects).toEqual([]);
  });

  it("MUTANT (cancellation mid-stream): an aborted body publishes nothing and leaves no staging object", async () => {
    const db = "stream-cancel";
    const bytes = crypto.getRandomValues(new Uint8Array(8192));
    const digest = await sha256hex(bytes);
    const key = `p/${db}/${digest}`;
    // four chunks promised, the client dies after the first
    const result = await streamedPayloadPut(
      workerEnv, bodyStream(splitBytes(bytes, 4), 1), db, key, digest, bytes.byteLength);
    expect(result.status).toBe(400);
    expect((result.body as { error: string }).error).toBe("REQUEST_BODY_LENGTH_MISMATCH");
    // the content-addressed key was never created ...
    expect(await testEnv.PAYLOADS.get(key)).toBeNull();
    // ... and no staging attempt was left behind
    expect((await testEnv.PAYLOADS.list({ prefix: `s/${db}/` })).objects.map((o) => o.key)).toEqual([]);
  });

  it("a wrong-digest body is refused and NEVER published under the content-addressed key", async () => {
    const db = "stream-wrongbytes";
    await bootDatabase(db, "sess-wb");
    const promised = new TextEncoder().encode("the-bytes-i-promised");
    const digest = await sha256hex(promised);
    const cap = await issue({ databaseId: db, method: "PUT_PAYLOAD", digest, maxBytes: 1024 });
    // same LENGTH, different content: only the streamed digest can catch it
    const impostor = new Uint8Array(promised.byteLength).fill(0x42);
    const response = await SELF.fetch(`https://facade.local/payload/${cap.key}`, {
      method: "PUT", body: impostor, headers: { "x-capability": cap.token },
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { error: string }).error).toBe("PAYLOAD_DIGEST_MISMATCH");
    expect(await testEnv.PAYLOADS.get(cap.key as string)).toBeNull();
    expect((await testEnv.PAYLOADS.list({ prefix: `s/${db}/` })).objects).toEqual([]);
  });

  it("the byte budget is refused BEFORE the body is read (declared length, not buffered length)", async () => {
    const db = "stream-budget";
    await bootDatabase(db, "sess-budget");
    const bytes = new TextEncoder().encode("this body exceeds its budget");
    const digest = await sha256hex(bytes);
    const cap = await issue({ databaseId: db, method: "PUT_PAYLOAD", digest, maxBytes: 4 });
    const response = await SELF.fetch(`https://facade.local/payload/${cap.key}`, {
      method: "PUT", body: bytes, headers: { "x-capability": cap.token },
    });
    expect(response.status).toBe(403);
    expect(((await response.json()) as { error: string }).error).toBe("CAPABILITY_BUDGET_EXCEEDED");
    expect((await testEnv.PAYLOADS.list({ prefix: `s/${db}/` })).objects).toEqual([]);
  });
});

/** Catalogue one record and return its key + the finalize generation. */
async function catalogueRecord(db: string, session: string, gen: number, bytes: Uint8Array): Promise<string> {
  await bootDatabase(db, session, gen);
  const digest = await sha256hex(bytes);
  const cap = await issue({ databaseId: db, method: "PUT_PAYLOAD", digest, maxBytes: bytes.byteLength });
  expect((await SELF.fetch(`https://facade.local/payload/${cap.key}`, {
    method: "PUT", body: bytes, headers: { "x-capability": cap.token },
  })).status).toBe(200);
  const finalize = await postJson("/wal/finalize",
    (await issue({ databaseId: db, method: "WAL_FINALIZE", session, generation: gen })).token, {
      databaseId: db, generation: gen, startupSessionId: session,
      operationId: "op-stream-1", sequencingKind: "SEQUENCED", recordType: 2, logicalKey: null,
      payloadKey: cap.key, payloadDigest: digest, payloadLength: bytes.byteLength,
    });
  expect(((await finalize.json()) as { ok: boolean }).ok).toBe(true);
  return cap.key as string;
}

describe("R5-PERF-01 negotiated streaming read path (workerd)", () => {
  it("MUTANT (legacy shape unchanged): the DEFAULT read is byte-identical base64 JSON", async () => {
    const db = "read-legacy";
    const session = "sess-legacy";
    const bytes = crypto.getRandomValues(new Uint8Array(4096));
    await catalogueRecord(db, session, 1, bytes);
    const digest = await sha256hex(bytes);

    for (const accept of [null, "application/json", "*/*"]) {
      const token = (await issue({ databaseId: db, method: "WAL_READ", session, generation: 1 })).token;
      const headers = new Headers({ "x-capability": token });
      if (accept !== null) headers.set("accept", accept);
      const read = await SELF.fetch(`https://facade.local/wal/${db}/1/0`, { headers });
      expect(read.status).toBe(200);
      expect(read.headers.get("content-type")).toBe("application/json");
      const body = (await read.json()) as Record<string, unknown>;
      // the exact historical field set and order
      expect(Object.keys(body)).toEqual([
        "ok", "payloadKey", "payloadDigest", "typeSequence", "recordType", "payloadBase64",
      ]);
      expect(body.ok).toBe(true);
      expect(body.payloadDigest).toBe(digest);
      expect(Uint8Array.from(atob(body.payloadBase64 as string), (c) => c.charCodeAt(0))).toEqual(bytes);
    }
  });

  it("an explicit accept: application/octet-stream streams the payload with a content-digest", async () => {
    const db = "read-stream";
    const session = "sess-stream";
    const bytes = crypto.getRandomValues(new Uint8Array(64 * 1024));
    await catalogueRecord(db, session, 1, bytes);
    const digest = await sha256hex(bytes);
    const token = (await issue({ databaseId: db, method: "WAL_READ", session, generation: 1 })).token;
    const read = await SELF.fetch(`https://facade.local/wal/${db}/1/0`, {
      headers: { "x-capability": token, accept: "application/octet-stream" },
    });
    expect(read.status).toBe(200);
    expect(read.headers.get("content-type")).toBe("application/octet-stream");
    expect(read.headers.get("x-payload-sha256")).toBe(digest);
    expect(read.headers.get("content-length")).toBe(String(bytes.byteLength));
    expect(read.headers.get("x-append-lsn")).toBe("0");
    expect(read.headers.get("x-record-type")).toBe("2");
    expect(read.headers.get("content-digest")).toMatch(/^sha-256=:[A-Za-z0-9+/=]+:$/);
    expect(new Uint8Array(await read.arrayBuffer())).toEqual(bytes);
  });

  it("MUTANT (six concurrent reads): the platform's subrequest ceiling of concurrent reads all serve exactly", async () => {
    const db = "read-concurrent";
    const session = "sess-conc";
    const bytes = crypto.getRandomValues(new Uint8Array(32 * 1024));
    await catalogueRecord(db, session, 1, bytes);
    const tokens = await Promise.all(Array.from({ length: 6 }, () =>
      issue({ databaseId: db, method: "WAL_READ", session, generation: 1 })));
    const responses = await Promise.all(tokens.map((cap, index) => {
      const headers = new Headers({ "x-capability": cap.token });
      // half legacy, half streamed: both shapes under concurrency
      if (index % 2 === 0) headers.set("accept", "application/octet-stream");
      return SELF.fetch(`https://facade.local/wal/${db}/1/0`, { headers });
    }));
    expect(responses.map((r) => r.status)).toEqual([200, 200, 200, 200, 200, 200]);
    for (const [index, response] of responses.entries()) {
      if (index % 2 === 0) {
        expect(new Uint8Array(await response.arrayBuffer())).toEqual(bytes);
      } else {
        const body = (await response.json()) as { payloadBase64: string };
        expect(Uint8Array.from(atob(body.payloadBase64), (c) => c.charCodeAt(0))).toEqual(bytes);
      }
    }
  });

  it("a streamed read of a CORRUPTED object aborts the response body instead of completing it", async () => {
    const db = "read-stream-corrupt";
    const session = "sess-sc";
    const bytes = new TextEncoder().encode("authentic-streamed-bytes");
    const key = await catalogueRecord(db, session, 1, bytes);
    // tamper behind the catalogue: same length, different content
    await testEnv.PAYLOADS.put(key, new Uint8Array(bytes.byteLength).fill(0x41));
    const token = (await issue({ databaseId: db, method: "WAL_READ", session, generation: 1 })).token;
    const read = await SELF.fetch(`https://facade.local/wal/${db}/1/0`, {
      headers: { "x-capability": token, accept: "application/octet-stream" },
    });
    // headers are already committed (that is the documented limitation of a
    // streaming read); the BODY must fail rather than complete cleanly
    expect(read.status).toBe(200);
    await expect(read.arrayBuffer()).rejects.toThrow();
  });
});
