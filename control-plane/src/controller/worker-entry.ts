/*
 * Worker entry: local-stack (L1) HTTP facade over the control plane.
 *
 * The same topology as production — gateway Worker → R2 data path →
 * DatabaseControllerDO finalisation — served locally by workerd via
 * `wrangler dev` (or vitest-pool-workers). Payload bytes travel through R2
 * (local simulator in dev, real R2 in staging/production); the controller
 * only ever sees keys/digests, and digest verification happens in the data
 * path BEFORE the DO's synchronous finalisation (inv. 151).
 *
 * Endpoints (JSON unless noted):
 *   GET  /health
 *   PUT  /payload/{key}            raw body → R2; returns {key, sha256hex, length}
 *   POST /session/register         {databaseId, generation, startupSessionId}
 *   POST /session/fence            {databaseId, generation, startupSessionId}
 *   POST /budgets                  {databaseId, maxUnpublishedOutbox, maxPayloadLength, maxTailRecords}
 *   POST /wal/finalize             FinalizeRequest → FinalizeResult (verifies R2 object + digest first)
 *   POST /wal/finalize-batch       {requests: FinalizeRequest[]} → all-or-nothing FinalizeResult[]
 *   GET  /wal/{db}/{generation}/{lsn}  exact lookup; returns record metadata + payload bytes (base64)
 *   GET  /wal/{db}/{generation}/audit  contiguity audit
 *   GET  /wal/{db}/{generation}/head   {headLsn, headTypeSequence} (durability current/previous)
 *   POST /wal/{db}/{generation}/iterator  pin a fixed iteration snapshot → {headLsn}
 *   GET  /wal/{db}/{generation}/scan?fromTs=&fromLsn=&throughLsn=&recordType=&limit=
 *                                  ordered replay page (physical LSN order, type_sequence>=fromTs,
 *                                  bounded by the pinned throughLsn); payloads inline, digest-verified
 *   GET  /wal/{db}/{generation}/last?recordType=N  last record of a type + payload (find_last_type)
 *   GET  /outbox/{db}?limit=N      peek unpublished control events (no marking)
 *   POST /outbox/{db}/ack          {upToControlSeq} - ack after durable processing
 */

export { DatabaseControllerDO } from "./database-controller.ts";

interface Env {
  CONTROLLER: DurableObjectNamespace;
  PAYLOADS: R2Bucket;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

async function sha256hex(bytes: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Base64 of a payload buffer, built in bounded chunks: the previous
 * char-at-a-time string concatenation was quadratic-ish over multi-MB
 * payloads — real CommitRecords (schema loads, imports) would hit it long
 * before any platform limit.
 */
function base64Of(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  const CHUNK = 8192;
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i += CHUNK) {
    parts.push(String.fromCharCode(...bytes.subarray(i, i + CHUNK)));
  }
  return btoa(parts.join(""));
}

/** The single fetch-and-verify core both integrity paths share: get the
 *  object, hash it, compare digests (and length when the caller has one).
 *  The two callers map the same outcomes to different protocol shapes —
 *  422 before finalisation (client's receipt is wrong), 500 after (a
 *  catalogued record's payload is missing/corrupt — hard integrity error,
 *  never EOF). */
async function fetchVerified(
  env: Env,
  key: string,
  expectedDigest: string,
  expectedLength?: number,
): Promise<{ buffer: ArrayBuffer } | { error: "MISSING" } | { error: "MISMATCH"; observed: string; length: number }> {
  const object = await env.PAYLOADS.get(key);
  if (object === null) return { error: "MISSING" };
  const buffer = await object.arrayBuffer();
  const observed = await sha256hex(buffer);
  if (observed !== expectedDigest || (expectedLength !== undefined && buffer.byteLength !== expectedLength)) {
    return { error: "MISMATCH", observed, length: buffer.byteLength };
  }
  return { buffer };
}

/** Read-path wrapper: base64 payload or a typed 500 error Response. */
async function verifiedPayloadBase64(
  env: Env,
  record: { payloadKey: string; payloadDigest: string },
): Promise<{ payloadBase64: string } | { errorResponse: Response }> {
  const result = await fetchVerified(env, String(record.payloadKey), String(record.payloadDigest));
  if ("buffer" in result) return { payloadBase64: base64Of(result.buffer) };
  if (result.error === "MISSING") {
    return { errorResponse: json({ ok: false, error: "PAYLOAD_MISSING_FOR_CATALOGUED_RECORD", record }, 500) };
  }
  return {
    errorResponse: json({ ok: false, error: "PAYLOAD_INTEGRITY_VIOLATION", record, observed: result.observed }, 500),
  };
}

/** Bounded-concurrency ordered map: the scan read path and batch receipt
 *  verification issue one R2 get per record — strictly serial awaits would
 *  make a full page pay the whole round-trip latency N times over. Results
 *  keep item order; concurrency is capped so a 1000-record page cannot open
 *  1000 simultaneous R2 reads. */
async function mapBounded<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index]);
    }
  });
  await Promise.all(workers);
  return results;
}

const PAYLOAD_FETCH_CONCURRENCY = 8;

/** Record types are u8 in TypeDB durability; anything else is a client bug
 *  surfaced as a typed 400, never coerced. */
function invalidRecordType(value: unknown): boolean {
  return typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 255;
}

/** Query-string numerics must be non-negative safe integers; anything else
 *  (NaN, negatives, floats) is a typed 400, never a crash or a NaN reaching
 *  SQL. Returns null when invalid. */
function nonNegativeInt(raw: string | null, fallback: number): number | null {
  if (raw === null) return fallback;
  const value = Number(raw);
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "GET" && path === "/health") {
      return json({ ok: true, runtime: "workerd", stack: "L1-local" });
    }

    if (request.method === "PUT" && path.startsWith("/payload/")) {
      const key = decodeURIComponent(path.slice("/payload/".length));
      const bytes = await request.arrayBuffer();
      const digest = await sha256hex(bytes);
      // payload immutability: puts are create-or-identical, never overwrite.
      // The create is a CONDITIONAL put (If-None-Match: *), not get-then-put:
      // two concurrent puts of different bytes must never both succeed, and a
      // read-then-write window would allow exactly that (last-writer-wins over
      // a digest another client may already have receipt-verified). On
      // precondition failure the existing object is compared by digest.
      // (In production the same contract is enforced by object-store
      // conditions/credential policy; the facade upholds it locally.)
      for (let attempt = 0; attempt < 3; attempt++) {
        const created = await env.PAYLOADS.put(key, bytes, {
          onlyIf: new Headers({ "if-none-match": "*" }),
        });
        if (created !== null) {
          return json({ key, sha256hex: digest, length: bytes.byteLength });
        }
        const existing = await env.PAYLOADS.get(key);
        if (existing === null) continue; // lost a delete/create race; retry the conditional create
        const existingDigest = await sha256hex(await existing.arrayBuffer());
        if (existingDigest !== digest) {
          return json({ ok: false, error: "PAYLOAD_IMMUTABILITY_VIOLATION", key, existing: existingDigest }, 409);
        }
        return json({ key, sha256hex: digest, length: bytes.byteLength, deduplicated: true });
      }
      return json({ ok: false, error: "PAYLOAD_RACE_UNRESOLVED", key }, 503);
    }

    // controller routing: one DO per database
    const stubFor = (databaseId: string) =>
      env.CONTROLLER.get(env.CONTROLLER.idFromName(databaseId)) as unknown as {
        registerSession(db: string, generation: number, session: string): Promise<void>;
        fenceSession(db: string, session: string): Promise<void>;
        setBudgets(db: string, budgets: object): Promise<void>;
        finalizeWalRecord(req: object): Promise<Record<string, unknown>>;
        finalizeBatch(reqs: object[]): Promise<Record<string, unknown>[] | Record<string, unknown>>;
        exactLookup(db: string, generation: number, lsn: number): Promise<Record<string, unknown>>;
        auditContiguity(db: string, generation: number): Promise<Record<string, unknown>>;
        head(db: string, generation: number): Promise<Record<string, unknown>>;
        openIterator(db: string, generation: number): Promise<Record<string, unknown>>;
        scan(db: string, generation: number, opts: object): Promise<{
          records: Record<string, unknown>[]; nextFromLsn: number | null;
        }>;
        lastByType(db: string, generation: number, recordType: number): Promise<Record<string, unknown>>;
      };

    if (request.method === "POST" && path === "/session/register") {
      const b = (await request.json()) as { databaseId: string; generation: number; startupSessionId: string };
      await stubFor(b.databaseId).registerSession(b.databaseId, b.generation, b.startupSessionId);
      return json({ ok: true });
    }

    if (request.method === "POST" && path === "/session/fence") {
      const b = (await request.json()) as { databaseId: string; generation: number; startupSessionId: string };
      // the fence is actor-wide: any `generation` in the body is accepted for
      // wire compatibility but does not scope the revocation
      await stubFor(b.databaseId).fenceSession(b.databaseId, b.startupSessionId);
      return json({ ok: true });
    }

    if (request.method === "POST" && path === "/budgets") {
      const b = (await request.json()) as {
        databaseId: string; maxUnpublishedOutbox: number; maxPayloadLength: number; maxTailRecords: number;
      };
      await stubFor(b.databaseId).setBudgets(b.databaseId, {
        maxUnpublishedOutbox: b.maxUnpublishedOutbox,
        maxPayloadLength: b.maxPayloadLength,
        maxTailRecords: b.maxTailRecords,
      });
      return json({ ok: true });
    }

    // data-path receipt verification BEFORE the DO's synchronous
    // finalisation: the object must exist and match digest + length
    const verifyReceipt = async (req: { payloadKey: string; payloadDigest: string; payloadLength: number }) => {
      const result = await fetchVerified(env, req.payloadKey, req.payloadDigest, req.payloadLength);
      if ("buffer" in result) return null;
      if (result.error === "MISSING") return json({ ok: false, error: "PAYLOAD_MISSING", key: req.payloadKey }, 422);
      return json(
        { ok: false, error: "PAYLOAD_DIGEST_MISMATCH", observed: result.observed, length: result.length },
        422,
      );
    };

    if (request.method === "POST" && path === "/wal/finalize") {
      const req = (await request.json()) as {
        databaseId: string; payloadKey: string; payloadDigest: string; payloadLength: number;
      } & Record<string, unknown>;
      if (invalidRecordType(req.recordType)) {
        return json({ ok: false, error: "INVALID_RECORD_TYPE", observed: req.recordType ?? null }, 400);
      }
      const receiptError = await verifyReceipt(req);
      if (receiptError !== null) return receiptError;
      const result = await stubFor(req.databaseId).finalizeWalRecord(req);
      return json(result, result.ok ? 200 : 409);
    }

    if (request.method === "POST" && path === "/wal/finalize-batch") {
      const body = (await request.json()) as {
        requests: ({ databaseId: string; payloadKey: string; payloadDigest: string; payloadLength: number }
          & Record<string, unknown>)[];
      };
      if (!Array.isArray(body.requests) || body.requests.length === 0) {
        return json({ ok: false, error: "EMPTY_BATCH" }, 400);
      }
      const databaseId = body.requests[0].databaseId;
      for (const req of body.requests) {
        if (req.databaseId !== databaseId) {
          // one DO per database: a batch is one transaction on ONE authority
          return json({ ok: false, error: "BATCH_SPANS_DATABASES" }, 400);
        }
        if (invalidRecordType(req.recordType)) {
          return json({ ok: false, error: "INVALID_RECORD_TYPE", observed: req.recordType ?? null }, 400);
        }
      }
      const receiptErrors = await mapBounded(body.requests, PAYLOAD_FETCH_CONCURRENCY, verifyReceipt);
      const firstReceiptError = receiptErrors.find((error) => error !== null);
      if (firstReceiptError) return firstReceiptError;
      const result = await stubFor(databaseId).finalizeBatch(body.requests);
      // all-or-nothing: an array is N successes; a single typed error aborted
      // (and rolled back) the whole batch
      if (Array.isArray(result)) return json({ ok: true, results: result });
      return json(result, 409);
    }

    const walRead = path.match(/^\/wal\/([^/]+)\/(\d+)\/(\d+)$/);
    if (request.method === "GET" && walRead) {
      const [, db, generation, lsn] = walRead;
      const record = await stubFor(db).exactLookup(db, Number(generation), Number(lsn));
      if (!record.ok) return json(record, 404);
      // exact reads re-verify bytes against the catalogued digest: serving
      // corrupted payload under valid metadata is worse than failing; a
      // catalogued record whose payload is missing is a hard integrity
      // error - never EOF (§exact-index rules)
      const payload = await verifiedPayloadBase64(env, record as { payloadKey: string; payloadDigest: string });
      if ("errorResponse" in payload) return payload.errorResponse;
      return json({ ...record, payloadBase64: payload.payloadBase64 });
    }

    const walHead = path.match(/^\/wal\/([^/]+)\/(\d+)\/head$/);
    if (request.method === "GET" && walHead) {
      const [, db, generation] = walHead;
      return json({ ok: true, ...(await stubFor(db).head(db, Number(generation))) });
    }

    const walIterator = path.match(/^\/wal\/([^/]+)\/(\d+)\/iterator$/);
    if (request.method === "POST" && walIterator) {
      const [, db, generation] = walIterator;
      return json({ ok: true, ...(await stubFor(db).openIterator(db, Number(generation))) });
    }

    const walScan = path.match(/^\/wal\/([^/]+)\/(\d+)\/scan$/);
    if (request.method === "GET" && walScan) {
      const [, db, generation] = walScan;
      const recordTypeParam = url.searchParams.get("recordType");
      const recordType = recordTypeParam === null ? null : Number(recordTypeParam);
      if (recordType !== null && invalidRecordType(recordType)) {
        return json({ ok: false, error: "INVALID_RECORD_TYPE", observed: recordTypeParam }, 400);
      }
      const throughLsnParam = url.searchParams.get("throughLsn");
      if (throughLsnParam === null) {
        // an unbounded scan would observe appends made after the iteration
        // started (inv. 41-42): the pinned snapshot bound is mandatory
        return json({ ok: false, error: "MISSING_THROUGH_LSN" }, 400);
      }
      const fromTypeSequence = nonNegativeInt(url.searchParams.get("fromTs"), 0);
      const fromLsn = nonNegativeInt(url.searchParams.get("fromLsn"), 0);
      const throughLsn = nonNegativeInt(throughLsnParam, 0);
      const rawLimit = nonNegativeInt(url.searchParams.get("limit"), 100);
      if (fromTypeSequence === null || fromLsn === null || throughLsn === null || rawLimit === null) {
        return json({ ok: false, error: "INVALID_PARAMETER" }, 400);
      }
      const limit = Math.min(Math.max(rawLimit, 1), 1000);
      const page = await stubFor(db).scan(db, Number(generation), {
        fromTypeSequence, fromLsn, throughLsn, recordType, limit,
      });
      const payloads = await mapBounded(page.records, PAYLOAD_FETCH_CONCURRENCY, (record) =>
        verifiedPayloadBase64(env, record as { payloadKey: string; payloadDigest: string }),
      );
      const records: Record<string, unknown>[] = [];
      for (const [index, payload] of payloads.entries()) {
        if ("errorResponse" in payload) return payload.errorResponse;
        records.push({ ...page.records[index], payloadBase64: payload.payloadBase64 });
      }
      return json({ ok: true, records, nextFromLsn: page.nextFromLsn });
    }

    const walLast = path.match(/^\/wal\/([^/]+)\/(\d+)\/last$/);
    if (request.method === "GET" && walLast) {
      const [, db, generation] = walLast;
      const recordType = Number(url.searchParams.get("recordType") ?? "NaN");
      if (invalidRecordType(recordType)) {
        return json({ ok: false, error: "INVALID_RECORD_TYPE", observed: url.searchParams.get("recordType") }, 400);
      }
      const result = await stubFor(db).lastByType(db, Number(generation), recordType);
      if (!result.ok) return json(result, 404);
      const record = result.record as { payloadKey: string; payloadDigest: string };
      const payload = await verifiedPayloadBase64(env, record);
      if ("errorResponse" in payload) return payload.errorResponse;
      return json({ ok: true, record: { ...record, payloadBase64: payload.payloadBase64 } });
    }

    const outboxPeek = path.match(/^\/outbox\/([^/]+)$/);
    if (request.method === "GET" && outboxPeek) {
      const limit = Number(url.searchParams.get("limit") ?? "100");
      const stub = stubFor(outboxPeek[1]) as unknown as { outboxPeek(limit: number): Promise<unknown[]> };
      return json({ ok: true, events: await stub.outboxPeek(limit) });
    }

    const outboxAck = path.match(/^\/outbox\/([^/]+)\/ack$/);
    if (request.method === "POST" && outboxAck) {
      const b = (await request.json()) as { upToControlSeq: number };
      const stub = stubFor(outboxAck[1]) as unknown as { outboxAck(seq: number): Promise<number> };
      return json({ ok: true, acked: await stub.outboxAck(b.upToControlSeq) });
    }

    const walAudit = path.match(/^\/wal\/([^/]+)\/(\d+)\/audit$/);
    if (request.method === "GET" && walAudit) {
      const [, db, generation] = walAudit;
      return json(await stubFor(db).auditContiguity(db, Number(generation)));
    }

    return json({ ok: false, error: "NOT_FOUND" }, 404);
  },
};
