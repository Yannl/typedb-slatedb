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
 * Every endpoint except /health and POST /capability requires a
 * controller-issued capability token (F9) in the `x-capability` header:
 * audience-bound (databaseId), method-bound, expiring, single-use (nonce
 * burned at the authority), incarnation-bound; payload writes additionally
 * bind the exact object key, the body digest, and a byte budget. Object
 * keys are ISSUER-DERIVED and content-addressed (`p/<db>/<sha256hex>`) -
 * a caller never selects an R2 key. Local issuance is open (the L1 facade
 * is scaffolding, not a security boundary - the refusal matrix is the
 * contract under proof; production issuance is controller-internal).
 *
 * Endpoints (JSON unless noted):
 *   GET  /health
 *   POST /capability               {principal, databaseId, method, digest?, maxBytes?, ttlMs?} → {token, key?}
 *   POST /admin/{db}/incarnation/bump  supersede the controller incarnation (SESSION_ADMIN)
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
 *   GET  /journal/{db}/verify      recompute + verify the authenticated journal (F8)
 *   GET  /outbox/{db}?limit=N      peek unpublished control events (no marking)
 *   POST /outbox/{db}/ack          {upToControlSeq} - ack after durable processing
 */

export { DatabaseControllerDO } from "./database-controller.ts";

import { u64FromWire } from "./core/procedures.ts";

interface Env {
  CONTROLLER: DurableObjectNamespace;
  PAYLOADS: R2Bucket;
}

function json(body: unknown, status = 200): Response {
  // sequence values are bigint end-to-end (F7); their canonical JSON
  // encoding is the decimal string - JSON numbers stop being exact at 2^53
  const encoded = JSON.stringify(body, (_key, value) => (typeof value === "bigint" ? value.toString() : value));
  return new Response(encoded, { status, headers: { "content-type": "application/json" } });
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

/** Hard per-response byte budget for scan pages (payload bytes, pre-base64):
 *  a full page must fit working memory in the 128 MiB worker isolate with
 *  headroom for the base64 expansion and JSON envelope. */
const SCAN_PAGE_BYTE_BUDGET = 8 * 1024 * 1024;

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

/** Sequence-valued query parameters (F7): exact u64 from a decimal string,
 *  over the full range - no 2^53 cliff. Returns null when invalid. */
function nonNegativeU64(raw: string | null, fallback: bigint): bigint | null {
  if (raw === null) return fallback;
  if (!/^\d+$/.test(raw)) return null;
  const value = BigInt(raw);
  return value <= (1n << 64n) - 1n ? value : null;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "GET" && path === "/health") {
      return json({ ok: true, runtime: "workerd", stack: "L1-local" });
    }

    // controller routing: one DO per database
    const stubFor = (databaseId: string) =>
      env.CONTROLLER.get(env.CONTROLLER.idFromName(databaseId)) as unknown as {
        registerSession(db: string, generation: number, session: string): Promise<void>;
        fenceSession(db: string, session: string): Promise<void>;
        setBudgets(db: string, budgets: object): Promise<void>;
        finalizeWalRecord(req: object): Promise<Record<string, unknown>>;
        finalizeBatch(reqs: object[]): Promise<Record<string, unknown>[] | Record<string, unknown>>;
        exactLookup(db: string, generation: number, lsn: bigint): Promise<Record<string, unknown>>;
        auditContiguity(db: string, generation: number): Promise<Record<string, unknown>>;
        head(db: string, generation: number): Promise<Record<string, unknown>>;
        openIterator(db: string, generation: number): Promise<Record<string, unknown>>;
        scan(db: string, generation: number, opts: object): Promise<{
          records: Record<string, unknown>[]; nextFromLsn: bigint | null;
        }>;
        lastByType(db: string, generation: number, recordType: number): Promise<Record<string, unknown>>;
        queryOperation(db: string, generation: number, operationId: string): Promise<Record<string, unknown>>;
      };

    /** F9 middleware: verify-and-burn the request's capability at the
     *  database's authority. null = authorized; otherwise the typed 401/403. */
    const requireCapability = async (
      databaseId: string,
      expect: { method: string; key?: string; bodyDigest?: string; bodyLength?: number },
    ): Promise<Response | null> => {
      const token = request.headers.get("x-capability");
      if (token === null) return json({ ok: false, error: "CAPABILITY_REQUIRED" }, 401);
      const stub = stubFor(databaseId) as unknown as {
        useCapability(token: string, expect: object): Promise<{ ok: boolean } & Record<string, unknown>>;
      };
      const verdict = await stub.useCapability(token, { databaseId, ...expect });
      if (!verdict.ok) return json(verdict, 403);
      return null;
    };

    if (request.method === "POST" && path === "/capability") {
      const spec = (await request.json()) as {
        principal: string; databaseId: string; method: string; digest?: string; maxBytes?: number; ttlMs?: number;
      };
      const stub = stubFor(spec.databaseId) as unknown as {
        issueCapability(spec: object): Promise<Record<string, unknown>>;
      };
      return json({ ok: true, ...(await stub.issueCapability(spec)) });
    }

    const adminBump = path.match(/^\/admin\/([^/]+)\/incarnation\/bump$/);
    if (request.method === "POST" && adminBump) {
      const denied = await requireCapability(adminBump[1], { method: "SESSION_ADMIN" });
      if (denied) return denied;
      const stub = stubFor(adminBump[1]) as unknown as { bumpIncarnation(): Promise<number> };
      return json({ ok: true, incarnation: await stub.bumpIncarnation() });
    }

    if (request.method === "PUT" && path.startsWith("/payload/")) {
      const key = decodeURIComponent(path.slice("/payload/".length));
      // content-addressed, issuer-derived key scheme: p/<databaseId>/<sha256hex>
      const parts = key.split("/");
      if (parts.length !== 3 || parts[0] !== "p") {
        return json({ ok: false, error: "INVALID_PAYLOAD_KEY", key }, 400);
      }
      const bytes = await request.arrayBuffer();
      const digest = await sha256hex(bytes);
      const denied = await requireCapability(parts[1], {
        method: "PUT_PAYLOAD", key, bodyDigest: digest, bodyLength: bytes.byteLength,
      });
      if (denied) return denied;
      // payload immutability: puts are create-or-identical, never overwrite.
      // The create is a CONDITIONAL put (If-None-Match: *), not get-then-put:
      // two concurrent puts of different bytes must never both succeed, and a
      // read-then-write window would allow exactly that. Under the capability
      // boundary a different-bytes put at this key cannot even reach here
      // (digest binding); the conditional create remains as defense in depth.
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

    if (request.method === "POST" && path === "/session/register") {
      const b = (await request.json()) as { databaseId: string; generation: number; startupSessionId: string };
      const denied = await requireCapability(b.databaseId, { method: "SESSION_ADMIN" });
      if (denied) return denied;
      await stubFor(b.databaseId).registerSession(b.databaseId, b.generation, b.startupSessionId);
      return json({ ok: true });
    }

    if (request.method === "POST" && path === "/session/fence") {
      const b = (await request.json()) as { databaseId: string; generation: number; startupSessionId: string };
      // the fence is actor-wide: any `generation` in the body is accepted for
      // wire compatibility but does not scope the revocation
      const denied = await requireCapability(b.databaseId, { method: "SESSION_ADMIN" });
      if (denied) return denied;
      await stubFor(b.databaseId).fenceSession(b.databaseId, b.startupSessionId);
      return json({ ok: true });
    }

    if (request.method === "POST" && path === "/budgets") {
      const b = (await request.json()) as {
        databaseId: string; maxUnpublishedOutbox: number; maxPayloadLength: number; maxTailRecords: number;
      };
      const denied = await requireCapability(b.databaseId, { method: "SESSION_ADMIN" });
      if (denied) return denied;
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
      const denied = await requireCapability(req.databaseId, { method: "WAL_FINALIZE" });
      if (denied) return denied;
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
      const denied = await requireCapability(databaseId, { method: "WAL_FINALIZE" });
      if (denied) return denied;
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
      const denied = await requireCapability(db, { method: "WAL_READ" });
      if (denied) return denied;
      const record = await stubFor(db).exactLookup(db, Number(generation), BigInt(lsn));
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
      const denied = await requireCapability(db, { method: "WAL_READ" });
      if (denied) return denied;
      return json({ ok: true, ...(await stubFor(db).head(db, Number(generation))) });
    }

    const walIterator = path.match(/^\/wal\/([^/]+)\/(\d+)\/iterator$/);
    if (request.method === "POST" && walIterator) {
      const [, db, generation] = walIterator;
      const denied = await requireCapability(db, { method: "WAL_READ" });
      if (denied) return denied;
      return json({ ok: true, ...(await stubFor(db).openIterator(db, Number(generation))) });
    }

    const walScan = path.match(/^\/wal\/([^/]+)\/(\d+)\/scan$/);
    if (request.method === "GET" && walScan) {
      const [, db, generation] = walScan;
      const denied = await requireCapability(db, { method: "WAL_READ" });
      if (denied) return denied;
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
      const fromTypeSequence = nonNegativeU64(url.searchParams.get("fromTs"), 0n);
      const fromLsn = nonNegativeU64(url.searchParams.get("fromLsn"), 0n);
      const throughLsn = nonNegativeU64(throughLsnParam, 0n);
      const rawLimit = nonNegativeInt(url.searchParams.get("limit"), 100);
      const rawMaxBytes = nonNegativeInt(url.searchParams.get("maxBytes"), SCAN_PAGE_BYTE_BUDGET);
      if (fromTypeSequence === null || fromLsn === null || throughLsn === null || rawLimit === null
          || rawMaxBytes === null) {
        return json({ ok: false, error: "INVALID_PARAMETER" }, 400);
      }
      const limit = Math.min(Math.max(rawLimit, 1), 1000);
      const maxBytes = Math.min(Math.max(rawMaxBytes, 1), SCAN_PAGE_BYTE_BUDGET);
      const page = await stubFor(db).scan(db, Number(generation), {
        fromTypeSequence, fromLsn, throughLsn, recordType, limit,
      });
      // Bounded response memory (V16 boundedness rules): the catalogue knows
      // every payload's length, so the page is cut to the byte budget BEFORE
      // any payload is fetched - a worker never materialises an unbounded
      // multi-payload response. Always at least one record makes progress;
      // the cut is reported through nextFromLsn exactly like a limit cut.
      let cut = page.records.length;
      let budget = maxBytes;
      for (const [index, record] of page.records.entries()) {
        const length = Number((record as { payloadLength: number }).payloadLength);
        if (index > 0 && length > budget) {
          cut = index;
          break;
        }
        budget -= length;
      }
      const included = page.records.slice(0, cut);
      const nextFromLsn = cut < page.records.length
        ? (included[included.length - 1] as { appendLsn: bigint }).appendLsn + 1n
        : page.nextFromLsn;
      const payloads = await mapBounded(included, PAYLOAD_FETCH_CONCURRENCY, (record) =>
        verifiedPayloadBase64(env, record as { payloadKey: string; payloadDigest: string }),
      );
      const records: Record<string, unknown>[] = [];
      for (const [index, payload] of payloads.entries()) {
        if ("errorResponse" in payload) return payload.errorResponse;
        records.push({ ...included[index], payloadBase64: payload.payloadBase64 });
      }
      return json({ ok: true, records, nextFromLsn });
    }

    const walOperation = path.match(/^\/wal\/([^/]+)\/(\d+)\/operation\/([^/]+)$/);
    if (request.method === "GET" && walOperation) {
      const [, db, generation, operationId] = walOperation;
      const denied = await requireCapability(db, { method: "WAL_READ" });
      if (denied) return denied;
      // read surface: immutable durable history stays queryable by operation
      // identity even after the finalizing session is fenced (V16; the
      // finalize-RETRY path still answers SESSION_FENCED per inv. 38)
      const result = await stubFor(db).queryOperation(db, Number(generation), decodeURIComponent(operationId));
      if (!result.ok) return json(result, 404);
      return json(result);
    }

    const walLast = path.match(/^\/wal\/([^/]+)\/(\d+)\/last$/);
    if (request.method === "GET" && walLast) {
      const [, db, generation] = walLast;
      const denied = await requireCapability(db, { method: "WAL_READ" });
      if (denied) return denied;
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
      const denied = await requireCapability(outboxPeek[1], { method: "OUTBOX" });
      if (denied) return denied;
      const limit = Number(url.searchParams.get("limit") ?? "100");
      const stub = stubFor(outboxPeek[1]) as unknown as { outboxPeek(limit: number): Promise<unknown[]> };
      return json({ ok: true, events: await stub.outboxPeek(limit) });
    }

    const outboxAck = path.match(/^\/outbox\/([^/]+)\/ack$/);
    if (request.method === "POST" && outboxAck) {
      const denied = await requireCapability(outboxAck[1], { method: "OUTBOX" });
      if (denied) return denied;
      const b = (await request.json()) as { upToControlSeq: number | string };
      const stub = stubFor(outboxAck[1]) as unknown as { outboxAck(seq: bigint): Promise<number> };
      let upTo: bigint;
      try {
        upTo = u64FromWire(b.upToControlSeq, "upToControlSeq");
      } catch {
        return json({ ok: false, error: "INVALID_PARAMETER", field: "upToControlSeq" }, 400);
      }
      return json({ ok: true, acked: await stub.outboxAck(upTo) });
    }

    const journalVerify = path.match(/^\/journal\/([^/]+)\/verify$/);
    if (request.method === "GET" && journalVerify) {
      // F8 read surface: recompute the whole chain + MACs server-side.
      // Routed by databaseId like every DO method (the journal is the DO's
      // global outbox; the id names the authority instance to audit).
      const denied = await requireCapability(journalVerify[1], { method: "JOURNAL_VERIFY" });
      if (denied) return denied;
      const stub = stubFor(journalVerify[1]) as unknown as { verifyJournal(): Promise<Record<string, unknown>> };
      const verdict = await stub.verifyJournal();
      return json(verdict, verdict.ok ? 200 : 409);
    }

    const walAudit = path.match(/^\/wal\/([^/]+)\/(\d+)\/audit$/);
    if (request.method === "GET" && walAudit) {
      const [, db, generation] = walAudit;
      const denied = await requireCapability(db, { method: "WAL_READ" });
      if (denied) return denied;
      return json(await stubFor(db).auditContiguity(db, Number(generation)));
    }

    return json({ ok: false, error: "NOT_FOUND" }, 404);
  },
};
