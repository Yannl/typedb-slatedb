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
 *   GET  /journal/{db}/verify-anchored  journal verification against the newest cut anchor (F6r/F8)
 *   POST /checkpoint/{db}/{gen}/cut          open a CheckpointCut {cutId} (SESSION_ADMIN)
 *   POST /checkpoint/{db}/cut/{cutId}/activate  activate with restore evidence (SESSION_ADMIN)
 *   GET  /checkpoint/{db}/{gen}/active       the ACTIVE cut record
 *   GET  /outbox/{db}?limit=N      peek unpublished control events (no marking)
 *   POST /outbox/{db}/ack          {upToControlSeq} - ack after durable processing
 */

export { DatabaseControllerDO } from "./database-controller.ts";

import { u64FromWire } from "./core/procedures.ts";
import { canonicalJson } from "./core/journal-crypto.ts";
import { resolveKeyConfig } from "./core/key-config.ts";

interface Env {
  CONTROLLER: DurableObjectNamespace;
  PAYLOADS: R2Bucket;
  /** Q-24/Q-02: key posture + issuance credential; see core/key-config.ts. */
  CONTROLLER_KEY_PROFILE?: string;
  CONTROLLER_JOURNAL_KEY?: string;
  CONTROLLER_CAPABILITY_KEY?: string;
  CONTROLLER_ISSUER_SECRET?: string;
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

/** Platform hard ceiling: six simultaneous outgoing connections per Worker
 *  invocation (contract lock `typedb-r2-v16-cloudflare-contract-lock.json`,
 *  brief §"maximum current shape"). The pool was set to eight, which is not
 *  a tuning choice but a request the platform cannot serve - the seventh and
 *  eighth connections queue or fail depending on the runtime, and a local
 *  simulator that tolerates them proves nothing about R2. */
const R2_SUBREQUEST_CEILING = 6;
const PAYLOAD_FETCH_CONCURRENCY = R2_SUBREQUEST_CEILING;

/** Hard admission bound on any single request body, enforced BEFORE the body
 *  is read (contract F9: 8 MiB per data-path object). The payload route used
 *  to buffer the whole body and only then consult the capability's budget, so
 *  the first oversized object was always admitted, fully materialised, and
 *  base64-expanded in a 128 MiB isolate before anything refused it. */
const MAX_REQUEST_BODY_BYTES = 8 * 1024 * 1024;

/** Declared-length admission: refuse before reading. A request with no
 *  content-length is refused too - an unbounded stream cannot be admitted
 *  against a byte budget, and accepting it is how the bound becomes
 *  advisory. Returns null when admissible. */
function refuseOversizedBody(request: Request, limit = MAX_REQUEST_BODY_BYTES): Response | null {
  const declared = request.headers.get("content-length");
  if (declared === null || !/^\d+$/.test(declared)) {
    return json({ ok: false, error: "CONTENT_LENGTH_REQUIRED", limit }, 411);
  }
  const length = Number(declared);
  if (!Number.isSafeInteger(length) || length > limit) {
    return json({ ok: false, error: "REQUEST_BODY_TOO_LARGE", declared, limit }, 413);
  }
  return null;
}

/** Hard per-response byte budget for scan pages (payload bytes, pre-base64):
 *  a full page must fit working memory in the 128 MiB worker isolate with
 *  headroom for the base64 expansion and JSON envelope. */
const SCAN_PAGE_BYTE_BUDGET = 8 * 1024 * 1024;

/** Constant-shape credential comparison: XOR-fold over equal-length byte
 *  views so a mismatch position does not shape the timing. (The length check
 *  leaks length, which the issuer secret does not need to hide.) */
function credentialsEqual(presented: string, expected: string): boolean {
  const a = new TextEncoder().encode(presented);
  const b = new TextEncoder().encode(expected);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

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

/** Generation at the wire boundary (donor A5): body values and `\d+` path
 *  segments alike must be exact non-negative safe integers BEFORE they reach
 *  the DO - `Number("1e300")`-style overflow or a 30-digit path segment
 *  would otherwise round silently and address the wrong generation's rows.
 *  Returns null when invalid; callers answer INVALID_GENERATION 400. */
function exactGeneration(raw: unknown): number | null {
  const value = typeof raw === "string" ? (/^\d+$/.test(raw) ? Number(raw) : NaN) : raw;
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

/**
 * Q-18: the replay/dedupe digest is RECOMPUTED over the canonical request,
 * never taken from the caller.
 *
 * `request_digest` is the key that decides whether a retry is the same
 * operation (return the original receipt) or a different one under a reused
 * id (typed conflict). A caller-supplied digest makes that decision a claim
 * rather than a fact: send operation X's id with body Y and X's digest, and
 * the controller hands back X's receipt for Y. The digest therefore covers
 * exactly the authority-bearing fields of the request, in a fixed order,
 * with the caller's own `requestDigest` excluded from its own input.
 */
const DIGESTED_FIELDS = [
  "databaseId", "generation", "startupSessionId", "operationId", "sequencingKind",
  "recordType", "logicalKey", "payloadKey", "payloadDigest", "payloadLength",
] as const;

async function canonicalRequestDigest(req: Record<string, unknown>): Promise<string> {
  const subject: Record<string, unknown> = {};
  for (const field of DIGESTED_FIELDS) subject[field] = req[field] ?? null;
  return sha256hex(new TextEncoder().encode(canonicalJson(subject)).buffer as ArrayBuffer);
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
        reserveSession(db: string, generation: number, session: string, holder: string):
          Promise<{ ok: boolean } & Record<string, unknown>>;
        attestSession(db: string, session: string, processNonce: string):
          Promise<{ ok: boolean } & Record<string, unknown>>;
        activateSession(db: string, session: string, proof: object):
          Promise<{ ok: boolean } & Record<string, unknown>>;
        renewLease(db: string, session: string, leaseMs: number):
          Promise<{ ok: boolean } & Record<string, unknown>>;
        beginDrain(db: string, session: string): Promise<{ ok: boolean } & Record<string, unknown>>;
        revokeSession(db: string, session: string): Promise<{ ok: boolean } & Record<string, unknown>>;
        fenceSession(db: string, session: string): Promise<void>;
        setBudgets(db: string, budgets: object, session: string):
          Promise<{ ok: true } | { ok: false; error: string }>;
        finalizeWalRecord(req: object): Promise<Record<string, unknown>>;
        finalizeBatch(reqs: object[], envelope?: object):
          Promise<Record<string, unknown>[] | Record<string, unknown>>;
        exactLookup(db: string, generation: number, lsn: bigint): Promise<Record<string, unknown>>;
        auditContiguity(db: string, generation: number): Promise<Record<string, unknown>>;
        head(db: string, generation: number): Promise<Record<string, unknown>>;
        openIterator(db: string, generation: number): Promise<Record<string, unknown>>;
        resolveSnapshot(db: string, generation: number, snapshotId: string):
          Promise<{ ok: true; headLsn: bigint } | { ok: false; error: string }>;
        scan(db: string, generation: number, opts: object): Promise<{
          records: Record<string, unknown>[]; nextFromLsn: bigint | null;
        }>;
        lastByType(db: string, generation: number, recordType: number): Promise<Record<string, unknown>>;
        queryOperation(db: string, generation: number, operationId: string, session: string):
          Promise<Record<string, unknown>>;
      };

    /** F9 middleware: verify-and-burn the request's capability at the
     *  database's authority. null = authorized; otherwise the typed 401/403. */
    const requireCapability = async (
      databaseId: string,
      expect: { method: string; session?: string; key?: string; bodyDigest?: string; bodyLength?: number },
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

    /** Same check, but hands the ACTOR back to the route.
     *
     *  Donor A4: procedures that act on authority state revalidate the actor
     *  at the core, beneath this layer. The route therefore needs to know
     *  which actor the token was issued to, and a token with no session
     *  binding cannot authorize such a procedure at all - it would leave the
     *  core with nothing to revalidate. */
    const requireCapabilityWithSession = async (
      databaseId: string,
      expect: { method: string; key?: string; bodyDigest?: string; bodyLength?: number },
    ): Promise<{ denied: Response } | { session: string }> => {
      const token = request.headers.get("x-capability");
      if (token === null) return { denied: json({ ok: false, error: "CAPABILITY_REQUIRED" }, 401) };
      const stub = stubFor(databaseId) as unknown as {
        useCapability(token: string, expect: object): Promise<
          { ok: boolean; payload?: { session?: string } } & Record<string, unknown>>;
      };
      const verdict = await stub.useCapability(token, { databaseId, ...expect });
      if (!verdict.ok) return { denied: json(verdict, 403) };
      const session = verdict.payload?.session;
      if (typeof session !== "string" || session.length === 0) {
        return { denied: json({ ok: false, error: "CAPABILITY_RESTRICTION_MISSING", restriction: "session" }, 403) };
      }
      return { session };
    };

    /** Core-level authority outcomes surfaced as protocol shapes. */
    const sessionRefusal = (result: { ok: false; error: string }): Response | null =>
      result.error === "SESSION_FENCED" || result.error === "SESSION_UNKNOWN"
        ? json({ ok: false, error: result.error }, 409)
        : null;

    if (request.method === "POST" && path === "/capability") {
      // Q-02: issuance is CREDENTIALED in every posture. The audit's finding
      // was that a self-issued capability does not create authentication;
      // requiring the issuer secret here means no configuration state exists
      // in which an anonymous caller can mint authority. Resolution is
      // fail-closed: a worker whose key config cannot resolve refuses
      // issuance outright rather than falling back to open issuance.
      let issuerSecret: string;
      try {
        issuerSecret = resolveKeyConfig(env).issuerSecret;
      } catch (error) {
        return json({ ok: false, error: "KEY_CONFIG_INVALID",
                      detail: error instanceof Error ? error.message : String(error) }, 500);
      }
      const presented = request.headers.get("x-issuer-authorization");
      if (presented === null || !credentialsEqual(presented, issuerSecret)) {
        return json({ ok: false, error: "ISSUER_UNAUTHORIZED" }, 401);
      }
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
      const tooLarge = refuseOversizedBody(request);
      if (tooLarge) return tooLarge;
      const bytes = await request.arrayBuffer();
      if (bytes.byteLength > MAX_REQUEST_BODY_BYTES) {
        // declared length lied; the read is bounded by the platform anyway,
        // but the refusal must not depend on the client's honesty
        return json({ ok: false, error: "REQUEST_BODY_TOO_LARGE",
                      observed: bytes.byteLength, limit: MAX_REQUEST_BODY_BYTES }, 413);
      }
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
      if (exactGeneration(b.generation) === null) {
        return json({ ok: false, error: "INVALID_GENERATION", observed: b.generation ?? null }, 400);
      }
      const denied = await requireCapability(b.databaseId, { method: "SESSION_ADMIN" });
      if (denied) return denied;
      await stubFor(b.databaseId).registerSession(b.databaseId, b.generation, b.startupSessionId);
      return json({ ok: true });
    }

    // ---- Q-03 / 12.4 lifecycle routes (SESSION_ADMIN-gated) -------------
    // Registration is the legacy macro over these; the real flow is
    // reserve -> attest -> activate, and ONLY activation fences.
    if (request.method === "POST" && path === "/session/reserve") {
      const b = (await request.json()) as {
        databaseId: string; generation: number; startupSessionId: string; holder: string;
      };
      if (exactGeneration(b.generation) === null) {
        return json({ ok: false, error: "INVALID_GENERATION", observed: b.generation ?? null }, 400);
      }
      const denied = await requireCapability(b.databaseId, { method: "SESSION_ADMIN" });
      if (denied) return denied;
      const result = await stubFor(b.databaseId)
        .reserveSession(b.databaseId, b.generation, b.startupSessionId, b.holder);
      return json(result, result.ok ? 200 : 409);
    }

    if (request.method === "POST" && path === "/session/attest") {
      const b = (await request.json()) as { databaseId: string; startupSessionId: string; processNonce: string };
      const denied = await requireCapability(b.databaseId, { method: "SESSION_ADMIN" });
      if (denied) return denied;
      const result = await stubFor(b.databaseId)
        .attestSession(b.databaseId, b.startupSessionId, b.processNonce);
      return json(result, result.ok ? 200 : 409);
    }

    if (request.method === "POST" && path === "/session/activate") {
      const b = (await request.json()) as {
        databaseId: string; startupSessionId: string; processNonce: string; generation: number; leaseMs: number;
      };
      if (exactGeneration(b.generation) === null) {
        return json({ ok: false, error: "INVALID_GENERATION", observed: b.generation ?? null }, 400);
      }
      const denied = await requireCapability(b.databaseId, { method: "SESSION_ADMIN" });
      if (denied) return denied;
      const result = await stubFor(b.databaseId).activateSession(b.databaseId, b.startupSessionId, {
        processNonce: b.processNonce, generation: b.generation, leaseMs: b.leaseMs,
      });
      return json(result, result.ok ? 200 : 409);
    }

    if (request.method === "POST" && path === "/session/renew") {
      const b = (await request.json()) as { databaseId: string; startupSessionId: string; leaseMs: number };
      const denied = await requireCapability(b.databaseId, { method: "SESSION_ADMIN" });
      if (denied) return denied;
      const result = await stubFor(b.databaseId).renewLease(b.databaseId, b.startupSessionId, b.leaseMs);
      return json(result, result.ok ? 200 : 409);
    }

    if (request.method === "POST" && path === "/session/drain") {
      const b = (await request.json()) as { databaseId: string; startupSessionId: string };
      const denied = await requireCapability(b.databaseId, { method: "SESSION_ADMIN" });
      if (denied) return denied;
      const result = await stubFor(b.databaseId).beginDrain(b.databaseId, b.startupSessionId);
      return json(result, result.ok ? 200 : 409);
    }

    if (request.method === "POST" && path === "/session/revoke") {
      const b = (await request.json()) as { databaseId: string; startupSessionId: string };
      const denied = await requireCapability(b.databaseId, { method: "SESSION_ADMIN" });
      if (denied) return denied;
      const result = await stubFor(b.databaseId).revokeSession(b.databaseId, b.startupSessionId);
      return json(result, result.ok ? 200 : 409);
    }

    if (request.method === "POST" && path === "/session/fence") {
      const b = (await request.json()) as { databaseId: string; generation: number; startupSessionId: string };
      if (exactGeneration(b.generation) === null) {
        return json({ ok: false, error: "INVALID_GENERATION", observed: b.generation ?? null }, 400);
      }
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
      const auth = await requireCapabilityWithSession(b.databaseId, { method: "SESSION_ADMIN" });
      if ("denied" in auth) return auth.denied;
      const result = await stubFor(b.databaseId).setBudgets(b.databaseId, {
        maxUnpublishedOutbox: b.maxUnpublishedOutbox,
        maxPayloadLength: b.maxPayloadLength,
        maxTailRecords: b.maxTailRecords,
      }, auth.session);
      if (!result.ok) return sessionRefusal(result) ?? json(result, 409);
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
      if (exactGeneration(req.generation) === null) {
        return json({ ok: false, error: "INVALID_GENERATION", observed: req.generation ?? null }, 400);
      }
      // the finalize capability MUST be bound to the request's session
      // (donor A3): a session id in the body is not by itself write authority
      const denied = await requireCapability(req.databaseId, {
        method: "WAL_FINALIZE", session: String((req as { startupSessionId?: unknown }).startupSessionId ?? ""),
      });
      if (denied) return denied;
      const receiptError = await verifyReceipt(req);
      if (receiptError !== null) return receiptError;
      // Q-18: the dedupe key is derived here, not asserted by the caller
      const computedDigest = await canonicalRequestDigest(req);
      if (typeof req.requestDigest === "string" && req.requestDigest !== computedDigest) {
        return json({ ok: false, error: "REQUEST_DIGEST_MISMATCH",
                      computed: computedDigest, supplied: req.requestDigest }, 400);
      }
      const result = await stubFor(req.databaseId)
        .finalizeWalRecord({ ...req, requestDigest: computedDigest });
      return json(result, result.ok ? 200 : 409);
    }

    if (request.method === "POST" && path === "/wal/finalize-batch") {
      const tooLargeBatch = refuseOversizedBody(request);
      if (tooLargeBatch) return tooLargeBatch;
      const body = (await request.json()) as {
        batchOperationId?: unknown; batchDigest?: unknown;
        requests: ({ databaseId: string; payloadKey: string; payloadDigest: string; payloadLength: number }
          & Record<string, unknown>)[];
      };
      if (!Array.isArray(body.requests) || body.requests.length === 0) {
        return json({ ok: false, error: "EMPTY_BATCH" }, 400);
      }
      // directive 12.6: a batch is ONE authority envelope with an identity.
      // Without it the batch cannot be replayed, conflicted or audited, and
      // the release baseline (one-record finalization) always remains open.
      if (typeof body.batchOperationId !== "string" || body.batchOperationId.length === 0) {
        return json({ ok: false, error: "BATCH_ENVELOPE_REQUIRED",
                      hint: "batchOperationId is required; batchDigest is optional and only checked" }, 400);
      }
      if (body.batchDigest !== undefined && typeof body.batchDigest !== "string") {
        return json({ ok: false, error: "BATCH_DIGEST_MISMATCH" }, 400);
      }
      const databaseId = body.requests[0].databaseId;
      const batchSession = String((body.requests[0] as { startupSessionId?: unknown }).startupSessionId ?? "");
      for (const req of body.requests) {
        if (req.databaseId !== databaseId) {
          // one DO per database: a batch is one transaction on ONE authority
          return json({ ok: false, error: "BATCH_SPANS_DATABASES" }, 400);
        }
        if (String((req as { startupSessionId?: unknown }).startupSessionId ?? "") !== batchSession) {
          // one actor per batch: a batch is one transaction by ONE session,
          // so one session-bound capability authorizes it (donor A3)
          return json({ ok: false, error: "BATCH_SPANS_SESSIONS" }, 400);
        }
        if (invalidRecordType(req.recordType)) {
          return json({ ok: false, error: "INVALID_RECORD_TYPE", observed: req.recordType ?? null }, 400);
        }
        if (exactGeneration(req.generation) === null) {
          return json({ ok: false, error: "INVALID_GENERATION", observed: req.generation ?? null }, 400);
        }
      }
      const denied = await requireCapability(databaseId, { method: "WAL_FINALIZE", session: batchSession });
      if (denied) return denied;
      const receiptErrors = await mapBounded(body.requests, PAYLOAD_FETCH_CONCURRENCY, verifyReceipt);
      const firstReceiptError = receiptErrors.find((error) => error !== null);
      if (firstReceiptError) return firstReceiptError;
      // Q-18: same rule for every batch member - the digest is derived here
      const digested: Record<string, unknown>[] = [];
      for (const req of body.requests) {
        const computed = await canonicalRequestDigest(req);
        if (typeof req.requestDigest === "string" && req.requestDigest !== computed) {
          return json({ ok: false, error: "REQUEST_DIGEST_MISMATCH", operationId: req.operationId ?? null,
                        computed, supplied: req.requestDigest }, 400);
        }
        digested.push({ ...req, requestDigest: computed });
      }
      const result = await stubFor(databaseId).finalizeBatch(digested, {
        batchOperationId: body.batchOperationId,
        ...(body.batchDigest !== undefined ? { batchDigest: body.batchDigest } : {}),
      });
      // all-or-nothing: an array is N successes; a single typed error aborted
      // (and rolled back) the whole batch
      if (Array.isArray(result)) return json({ ok: true, results: result });
      return json(result, 409);
    }

    const walRead = path.match(/^\/wal\/([^/]+)\/(\d+)\/(\d+)$/);
    if (request.method === "GET" && walRead) {
      const [, db, generation, lsn] = walRead;
      const gen = exactGeneration(generation);
      if (gen === null) return json({ ok: false, error: "INVALID_GENERATION", observed: generation }, 400);
      const denied = await requireCapability(db, { method: "WAL_READ" });
      if (denied) return denied;
      const record = await stubFor(db).exactLookup(db, gen, BigInt(lsn));
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
      const gen = exactGeneration(generation);
      if (gen === null) return json({ ok: false, error: "INVALID_GENERATION", observed: generation }, 400);
      const denied = await requireCapability(db, { method: "WAL_READ" });
      if (denied) return denied;
      return json({ ok: true, ...(await stubFor(db).head(db, gen)) });
    }

    const walIterator = path.match(/^\/wal\/([^/]+)\/(\d+)\/iterator$/);
    if (request.method === "POST" && walIterator) {
      const [, db, generation] = walIterator;
      const gen = exactGeneration(generation);
      if (gen === null) return json({ ok: false, error: "INVALID_GENERATION", observed: generation }, 400);
      const denied = await requireCapability(db, { method: "WAL_READ" });
      if (denied) return denied;
      return json({ ok: true, ...(await stubFor(db).openIterator(db, gen)) });
    }

    const walScan = path.match(/^\/wal\/([^/]+)\/(\d+)\/scan$/);
    if (request.method === "GET" && walScan) {
      const [, db, generation] = walScan;
      const gen = exactGeneration(generation);
      if (gen === null) return json({ ok: false, error: "INVALID_GENERATION", observed: generation }, 400);
      const denied = await requireCapability(db, { method: "WAL_READ" });
      if (denied) return denied;
      const recordTypeParam = url.searchParams.get("recordType");
      const recordType = recordTypeParam === null ? null : Number(recordTypeParam);
      if (recordType !== null && invalidRecordType(recordType)) {
        return json({ ok: false, error: "INVALID_RECORD_TYPE", observed: recordTypeParam }, 400);
      }
      // Q-12 / directive 12.6: the cut is SERVER-owned. The caller presents
      // the opaque snapshot id it was given at `POST .../iterator`; it may
      // not name a `throughLsn` itself, because a caller that holds the cut
      // can widen it between pages (observing appends made after iteration
      // started, inv. 41-42) or narrow it (silently skipping records a
      // consumer believes it replayed).
      const snapshotIdParam = url.searchParams.get("snapshotId");
      if (snapshotIdParam === null) {
        return json({ ok: false, error: "MISSING_SNAPSHOT_ID",
                      hint: "POST /wal/{db}/{generation}/iterator returns snapshotId" }, 400);
      }
      if (url.searchParams.get("throughLsn") !== null) {
        return json({ ok: false, error: "CALLER_SUPPLIED_SNAPSHOT_BOUND",
                      hint: "the cut is carried by snapshotId; throughLsn is not accepted" }, 400);
      }
      const resolved = await stubFor(db).resolveSnapshot(db, gen, snapshotIdParam);
      if (!resolved.ok) return json(resolved, 400);
      const throughLsn = resolved.headLsn;
      const fromTypeSequence = nonNegativeU64(url.searchParams.get("fromTs"), 0n);
      const fromLsn = nonNegativeU64(url.searchParams.get("fromLsn"), 0n);
      const rawLimit = nonNegativeInt(url.searchParams.get("limit"), 100);
      const rawMaxBytes = nonNegativeInt(url.searchParams.get("maxBytes"), SCAN_PAGE_BYTE_BUDGET);
      if (fromTypeSequence === null || fromLsn === null || rawLimit === null
          || rawMaxBytes === null) {
        return json({ ok: false, error: "INVALID_PARAMETER" }, 400);
      }
      if (fromLsn > throughLsn) {
        // a continuation outside its own snapshot is a client defect, not an
        // empty page: answering "no records" would look like a completed
        // replay
        return json({ ok: false, error: "CONTINUATION_OUTSIDE_SNAPSHOT",
                      fromLsn, throughLsn }, 400);
      }
      const limit = Math.min(Math.max(rawLimit, 1), 1000);
      const maxBytes = Math.min(Math.max(rawMaxBytes, 1), SCAN_PAGE_BYTE_BUDGET);
      const page = await stubFor(db).scan(db, gen, {
        fromTypeSequence, fromLsn, throughLsn, recordType, limit,
      });
      // Bounded response memory (V16 boundedness rules): the catalogue knows
      // every payload's length, so the page is cut to the byte budget BEFORE
      // any payload is fetched - a worker never materialises an unbounded
      // multi-payload response. Always at least one record makes progress;
      // the cut is reported through nextFromLsn exactly like a limit cut.
      // A descriptor whose declared payload exceeds the whole page budget is
      // REFUSED before any fetch - "record zero" is not an exception
      // (directive §12.6). Admitting it was the one path by which a single
      // oversized object could still be materialised and base64-expanded in
      // a 128 MiB isolate, and it made the byte bound advisory for exactly
      // the record that needed it most. The record stays reachable through
      // the exact-lookup route, so refusing here wedges nothing.
      const first = page.records[0] as { payloadLength: number; appendLsn: unknown } | undefined;
      if (first !== undefined && Number(first.payloadLength) > maxBytes) {
        return json({
          ok: false,
          error: "RECORD_EXCEEDS_PAGE_BUDGET",
          appendLsn: first.appendLsn,
          payloadLength: Number(first.payloadLength),
          maxBytes,
          hint: "fetch this record through /wal/{db}/{generation}/{lsn}",
        }, 413);
      }
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
      const gen = exactGeneration(generation);
      if (gen === null) return json({ ok: false, error: "INVALID_GENERATION", observed: generation }, 400);
      const auth = await requireCapabilityWithSession(db, { method: "WAL_READ" });
      if ("denied" in auth) return auth.denied;
      // Read surface: immutable durable history stays queryable by operation
      // identity across a fence of some OTHER actor (V16; the finalize-RETRY
      // path still answers SESSION_FENCED per inv. 38). "By the current
      // actor" is load-bearing, so the core revalidates the caller's own
      // session (donor A4): a fenced actor holding an unexpired WAL_READ
      // capability reads nothing.
      const result = await stubFor(db).queryOperation(
        db, gen, decodeURIComponent(operationId), auth.session);
      if (!result.ok) {
        const refusal = sessionRefusal(result as { ok: false; error: string });
        return refusal ?? json(result, 404);
      }
      return json(result);
    }

    const walLast = path.match(/^\/wal\/([^/]+)\/(\d+)\/last$/);
    if (request.method === "GET" && walLast) {
      const [, db, generation] = walLast;
      const gen = exactGeneration(generation);
      if (gen === null) return json({ ok: false, error: "INVALID_GENERATION", observed: generation }, 400);
      const denied = await requireCapability(db, { method: "WAL_READ" });
      if (denied) return denied;
      const recordType = Number(url.searchParams.get("recordType") ?? "NaN");
      if (invalidRecordType(recordType)) {
        return json({ ok: false, error: "INVALID_RECORD_TYPE", observed: url.searchParams.get("recordType") }, 400);
      }
      const result = await stubFor(db).lastByType(db, gen, recordType);
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
      const auth = await requireCapabilityWithSession(outboxAck[1], { method: "OUTBOX" });
      if ("denied" in auth) return auth.denied;
      const b = (await request.json()) as { upToControlSeq: number | string };
      const stub = stubFor(outboxAck[1]) as unknown as {
        outboxAck(db: string, seq: bigint, session: string):
          Promise<{ ok: true; acked: number } | { ok: false; error: string }>;
      };
      let upTo: bigint;
      try {
        upTo = u64FromWire(b.upToControlSeq, "upToControlSeq");
      } catch {
        return json({ ok: false, error: "INVALID_PARAMETER", field: "upToControlSeq" }, 400);
      }
      const result = await stub.outboxAck(outboxAck[1], upTo, auth.session);
      if (!result.ok) return sessionRefusal(result) ?? json(result, 409);
      return json({ ok: true, acked: result.acked });
    }

    const cutOpen = path.match(/^\/checkpoint\/([^/]+)\/(\d+)\/cut$/);
    if (request.method === "POST" && cutOpen) {
      const denied = await requireCapability(cutOpen[1], { method: "SESSION_ADMIN" });
      if (denied) return denied;
      const b = (await request.json()) as { cutId: string };
      const stub = stubFor(cutOpen[1]) as unknown as {
        openCheckpointCut(db: string, generation: number, cutId: string): Promise<{ ok: boolean }>;
      };
      const cutGen = exactGeneration(cutOpen[2]);
      if (cutGen === null) return json({ ok: false, error: "INVALID_GENERATION", observed: cutOpen[2] }, 400);
      const result = await stub.openCheckpointCut(cutOpen[1], cutGen, b.cutId);
      return json(result, result.ok ? 200 : 409);
    }

    const cutActivate = path.match(/^\/checkpoint\/([^/]+)\/cut\/([^/]+)\/activate$/);
    if (request.method === "POST" && cutActivate) {
      const denied = await requireCapability(cutActivate[1], { method: "SESSION_ADMIN" });
      if (denied) return denied;
      const b = (await request.json()) as { materializations: string[]; logicalDigest: string };
      const stub = stubFor(cutActivate[1]) as unknown as {
        activateCheckpointCut(db: string, cutId: string, evidence: object): Promise<{ ok: boolean }>;
      };
      const result = await stub.activateCheckpointCut(cutActivate[1], decodeURIComponent(cutActivate[2]), b);
      return json(result, result.ok ? 200 : 409);
    }

    const cutActive = path.match(/^\/checkpoint\/([^/]+)\/(\d+)\/active$/);
    if (request.method === "GET" && cutActive) {
      const denied = await requireCapability(cutActive[1], { method: "WAL_READ" });
      if (denied) return denied;
      const stub = stubFor(cutActive[1]) as unknown as {
        activeCheckpointCut(db: string, generation: number): Promise<{ ok: boolean }>;
      };
      const activeGen = exactGeneration(cutActive[2]);
      if (activeGen === null) return json({ ok: false, error: "INVALID_GENERATION", observed: cutActive[2] }, 400);
      const result = await stub.activeCheckpointCut(cutActive[1], activeGen);
      return json(result, result.ok ? 200 : 404);
    }

    const journalVerifyAnchored = path.match(/^\/journal\/([^/]+)\/verify-anchored$/);
    if (request.method === "GET" && journalVerifyAnchored) {
      const denied = await requireCapability(journalVerifyAnchored[1], { method: "JOURNAL_VERIFY" });
      if (denied) return denied;
      const stub = stubFor(journalVerifyAnchored[1]) as unknown as {
        verifyJournalAnchored(): Promise<{ ok: boolean }>;
      };
      const verdict = await stub.verifyJournalAnchored();
      return json(verdict, verdict.ok ? 200 : 409);
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
      const gen = exactGeneration(generation);
      if (gen === null) return json({ ok: false, error: "INVALID_GENERATION", observed: generation }, 400);
      const denied = await requireCapability(db, { method: "WAL_READ" });
      if (denied) return denied;
      return json(await stubFor(db).auditContiguity(db, gen));
    }

    return json({ ok: false, error: "NOT_FOUND" }, 404);
  },
};
