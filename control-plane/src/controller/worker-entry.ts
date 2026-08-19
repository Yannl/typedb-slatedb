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
 *   POST /provision                internal provisioning transaction (R4 PR1): binds an
 *                                  uninitialized controller authority to its registry record
 *                                  {tenantId, databaseId, budgets?} + x-provision token
 *   POST /capability               {principal, tenantId?, databaseId, method, digest?, maxBytes?, ttlMs?} → {token, key?}
 *   POST /admin/{db}/incarnation/bump  supersede the controller incarnation (INCARNATION_BUMP)
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
 *   POST /checkpoint/{db}/{gen}/cut          open a CheckpointCut {cutId} (CHECKPOINT_OPEN)
 *   POST /checkpoint/{db}/cut/{cutId}/activate  activate with the typed restore-evidence manifest (CHECKPOINT_ACTIVATE)
 *   GET  /checkpoint/{db}/{gen}/active       the ACTIVE cut record
 *   GET  /outbox/{db}?limit=N      peek unpublished control events (no marking)
 *   POST /outbox/{db}/ack          {upToControlSeq} - ack after durable processing
 */

import { DatabaseControllerDO } from "./database-controller.ts";
export { DatabaseControllerDO };

// C-08: the container's durable control-protocol authority. Exported and
// bound (wrangler.toml, migration v2) so the intended container lifecycle
// authority exists as a real binding in every mode; the container PROCESS
// itself is a real-platform residual (matrix CF-02).
import { DatabaseContainerDO } from "../container/database-container.ts";
export { DatabaseContainerDO };

import { MAX_BATCH_BYTES, MAX_BATCH_MEMBERS, u64FromWire, type FinalizeRequest } from "./core/procedures.ts";
import { devOnlyRoute } from "./surface.ts";
import { canonicalJson } from "./core/journal-crypto.ts";
import { verifyCapabilityToken, type CapabilityPayload } from "./core/capability.ts";
import { resolveKeyConfig, type ResolvedKeys } from "./core/key-config.ts";
import { checkBinding, verifyProvisionToken, controllerDoName, type ProvisionBinding } from "./core/registry.ts";

interface Env {
  CONTROLLER: DurableObjectNamespace<DatabaseControllerDO>;
  /** C-08: the container control-protocol authority binding. Present in every
   *  mode (the control protocol must exist even where the container process is
   *  a native substitute); no HTTP route addresses it yet — it is exercised
   *  through the typed RPC surface (recordObservation/getObservations). */
  CONTAINER: DurableObjectNamespace<DatabaseContainerDO>;
  PAYLOADS: R2Bucket;
  /** Q-24: key posture; see core/key-config.ts. */
  CONTROLLER_KEY_PROFILE?: string;
  CONTROLLER_JOURNAL_KEY?: string;
  /** R5-SEC-01/03: managed runtime inputs — environment name + the two
   *  PUBLIC Ed25519 verification keyrings (plain vars; they are not
   *  secret). The runtime holds NO signing material in any posture other
   *  than local-dev's committed dev capability keypair. */
  CONTROLLER_ENVIRONMENT?: string;
  CONTROLLER_CAPABILITY_PUBLIC_KEYS?: string;
  CONTROLLER_PROVISION_PUBLIC_KEYS?: string;
  /** local-dev only: the dev issuance route credential (Q-02). */
  CONTROLLER_ISSUER_SECRET?: string;
  /** RETIRED v2 HMAC inputs — their PRESENCE refuses managed boot. */
  CONTROLLER_CAPABILITY_KEY?: string;
  CONTROLLER_PROVISION_KEY?: string;
  /** Surface posture (audit C-P0-01/03/09, PR0 containment). ONLY the exact
   *  value "local-dev" opens the dev-only routes; anything else - including
   *  unset, which is what a production deployment that lost the variable
   *  looks like - is the production surface. See surface.ts. */
  CONTROLLER_SURFACE?: string;
}

function json(body: unknown, status = 200): Response {
  // sequence values are bigint end-to-end (F7); their canonical JSON
  // encoding is the decimal string - JSON numbers stop being exact at 2^53
  const encoded = JSON.stringify(body, (_key, value) => (typeof value === "bigint" ? value.toString() : value));
  return new Response(encoded, { status, headers: { "content-type": "application/json" } });
}

/** Lowercase hex of a digest buffer - the one place bytes become the wire
 *  digest syntax, shared by the buffered and streaming digest paths. */
function hexOf(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256hex(bytes: ArrayBuffer): Promise<string> {
  return hexOf(await crypto.subtle.digest("SHA-256", bytes));
}

/** Concatenate stream chunks into one contiguous view. The single-chunk case
 *  (every small payload) returns the chunk itself - no copy. */
function concatChunks(chunks: Uint8Array[], total: number): Uint8Array {
  if (chunks.length === 1 && chunks[0].byteLength === total) return chunks[0];
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

/**
 * Bounded, streaming read of an UNTRUSTED request body (C-06). The body is
 * consumed chunk-by-chunk: each chunk is folded into an incremental SHA-256
 * `crypto.DigestStream` and appended to a bounded buffer, and the byte cap is
 * enforced PER CHUNK — never trusting the client's `content-length`. A stream
 * that under-declares its length (or omits it, on chunked transfer) is aborted
 * the instant it crosses the cap, not after a full oversized buffer has been
 * materialised in the isolate.
 *
 * One contiguous copy of the body still remains, by necessity, not oversight:
 * the object must be stored in R2, AND the F9 capability binds the CONTENT
 * digest, so the whole body has to be read (to know the digest) before the
 * write can be authorized. A store-while-streaming path — upload to R2 and
 * authorize concurrently — would have to authorize before the digest is known,
 * which breaks the content-addressed authority model. That is a genuine
 * protocol change (digest-declared-then-verified upload), recorded as a
 * P-WORKER remainder; here the digest is at least computed incrementally with
 * no second full pass over the bytes.
 */
async function readBodyStreamingDigest(request: Request, limit: number):
  Promise<{ bytes: Uint8Array; digest: string } | { errorResponse: Response }> {
  const body = request.body;
  if (body === null) {
    // no readable body: an unbounded/absent stream cannot be admitted against
    // a byte budget (mirrors refuseOversizedBody's missing-length refusal)
    return { errorResponse: json({ ok: false, error: "CONTENT_LENGTH_REQUIRED", limit }, 411) };
  }
  const result = await streamCappedDigest(body, limit);
  if ("overCap" in result) {
    return { errorResponse: json({ ok: false, error: "REQUEST_BODY_TOO_LARGE",
                                   observed: result.total, limit }, 413) };
  }
  return { bytes: result.bytes, digest: result.digest };
}

/**
 * Stream a `ReadableStream<Uint8Array>` through an incremental SHA-256,
 * retaining the chunks, and enforce a cumulative byte cap PER CHUNK (never
 * trusting a declared length). On success returns the buffered bytes, the
 * exact total, and the hex digest; on cap breach returns the observed total
 * so each caller can shape its own typed refusal (a 413 for the inbound
 * request body, an OVER_CAP for a stored object). The digest is computed
 * incrementally — folded first (DigestStream copies into the hash context, it
 * does not detach the view), then the chunk is retained — so there is no
 * second full pass over the bytes.
 */
async function streamCappedDigest(
  stream: ReadableStream<Uint8Array>,
  cap: number,
): Promise<{ bytes: Uint8Array; total: number; digest: string } | { overCap: true; total: number }> {
  const digestStream = new crypto.DigestStream("SHA-256");
  const writer = digestStream.getWriter();
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > cap) {
        await writer.abort().catch(() => {});
        await reader.cancel().catch(() => {});
        return { overCap: true, total };
      }
      await writer.write(value);
      chunks.push(value);
    }
    await writer.close();
  } finally {
    reader.releaseLock();
  }
  return { bytes: concatChunks(chunks, total), total, digest: hexOf(await digestStream.digest) };
}

/**
 * Base64 of a payload buffer, built in bounded chunks: the previous
 * char-at-a-time string concatenation was quadratic-ish over multi-MB
 * payloads — real CommitRecords (schema loads, imports) would hit it long
 * before any platform limit.
 */
function base64Of(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
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
): Promise<
  { bytes: Uint8Array }
  | { error: "MISSING" }
  | { error: "OVER_CAP"; size: number; cap: number }
  | { error: "MISMATCH"; observed: string; length: number }
> {
  const object = await env.PAYLOADS.get(key);
  if (object === null) return { error: "MISSING" };
  // Hard per-object cap enforced BEFORE the body is read (C-06): R2 reports
  // the stored size, so an object the 8 MiB write cap should have refused (a
  // tampered or legacy bucket entry) is rejected without ever being
  // materialised in the isolate.
  if (object.size > MAX_PAYLOAD_OBJECT_BYTES) {
    // release the unread body stream cleanly rather than leaving it for the
    // runtime to cancel (avoids a noisy pump-canceled log)
    await object.body.cancel().catch(() => {});
    return { error: "OVER_CAP", size: object.size, cap: MAX_PAYLOAD_OBJECT_BYTES };
  }
  // Streaming digest verification: the body is read chunk-by-chunk into an
  // incremental DigestStream (no separate arrayBuffer()+hash pass), and the
  // cap is re-checked per chunk in case the reported size lied. The bytes are
  // still buffered because the wire contract returns them base64 inline; the
  // day that contract is dropped, the digest already flows without a copy.
  const result = await streamCappedDigest(object.body, MAX_PAYLOAD_OBJECT_BYTES);
  if ("overCap" in result) {
    return { error: "OVER_CAP", size: result.total, cap: MAX_PAYLOAD_OBJECT_BYTES };
  }
  const observed = result.digest;
  if (observed !== expectedDigest || (expectedLength !== undefined && result.total !== expectedLength)) {
    return { error: "MISMATCH", observed, length: result.total };
  }
  return { bytes: result.bytes };
}

/** Read-path wrapper: base64 payload or a typed error Response. A catalogued
 *  record whose payload is missing/corrupt is a hard integrity error (500,
 *  never EOF); an object over the per-object byte ceiling is a typed 413. */
async function verifiedPayloadBase64(
  env: Env,
  record: { payloadKey: string; payloadDigest: string },
): Promise<{ payloadBase64: string } | { errorResponse: Response }> {
  const result = await fetchVerified(env, String(record.payloadKey), String(record.payloadDigest));
  if ("bytes" in result) return { payloadBase64: base64Of(result.bytes) };
  if (result.error === "MISSING") {
    return { errorResponse: json({ ok: false, error: "PAYLOAD_MISSING_FOR_CATALOGUED_RECORD", record }, 500) };
  }
  if (result.error === "OVER_CAP") {
    return { errorResponse: json({ ok: false, error: "PAYLOAD_EXCEEDS_OBJECT_CAP",
                                   record, size: result.size, cap: result.cap }, 413) };
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

/** Admission bound for the two byte-bearing routes (payload PUT and batch
 *  finalize), enforced BEFORE the body is read (contract F9: 8 MiB per
 *  data-path object). Other routes carry small structural JSON bodies and
 *  are not gated by this constant. The payload route used
 *  to buffer the whole body and only then consult the capability's budget, so
 *  the first oversized object was always admitted, fully materialised, and
 *  base64-expanded in a 128 MiB isolate before anything refused it. */
const MAX_REQUEST_BODY_BYTES = 8 * 1024 * 1024;

/** Hard per-object byte ceiling on the READ path (C-06): the same F9 data-path
 *  object limit as the write side. Enforced against R2's reported object size
 *  before any body is read, so a catalogued object that exceeds the ceiling is
 *  refused rather than materialised. */
const MAX_PAYLOAD_OBJECT_BYTES = MAX_REQUEST_BODY_BYTES;

/** decodeURIComponent that returns a typed 400 instead of throwing an
 *  unhandled URIError (a 500) on malformed percent-encoding (C-06): a `%zz`
 *  or a dangling `%` in a path segment is a client error, surfaced as
 *  BAD_PERCENT_ENCODING, never an isolate crash after a capability may already
 *  have been touched. Returns the decoded value or the typed refusal. */
function safeDecodeComponent(raw: string): { value: string } | { errorResponse: Response } {
  try {
    return { value: decodeURIComponent(raw) };
  } catch {
    return { errorResponse: json({ ok: false, error: "BAD_PERCENT_ENCODING", segment: raw }, 400) };
  }
}

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

/** C-P1-01: structural JSON bodies (session admin, finalize metadata, acks)
 *  are small by construction; 256 KiB is generous headroom, and anything
 *  larger is a malformed client or an attack, refused before parsing. */
const MAX_STRUCTURAL_BODY_BYTES = 256 * 1024;

/** Bounded, fail-closed JSON body read (C-P1-01): declared-length admission
 *  first, then a parse whose failure is a typed 400 - never an unhandled
 *  exception after a capability was already burned. */
async function readJson(request: Request, limit = MAX_STRUCTURAL_BODY_BYTES):
  Promise<{ body: Record<string, unknown> } | { errorResponse: Response }> {
  const oversized = refuseOversizedBody(request, limit);
  if (oversized) return { errorResponse: oversized };
  try {
    const body = await request.json();
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      return { errorResponse: json({ ok: false, error: "MALFORMED_JSON", hint: "object body required" }, 400) };
    }
    return { body: body as Record<string, unknown> };
  } catch {
    return { errorResponse: json({ ok: false, error: "MALFORMED_JSON" }, 400) };
  }
}

/** Canonical digest of the ONE request a capability use authorizes
 *  (C-P0-08): the token's nonce is durably bound to this at the authority,
 *  so an identical retry is admitted (idempotent re-execution) and any
 *  different request under the same token is a replay refusal. */
async function useDigestOf(subject: unknown): Promise<string> {
  return sha256hex(new TextEncoder().encode(canonicalJson(subject)).buffer as ArrayBuffer);
}

/** 64 lowercase hex chars - the only accepted payload digest syntax. */
function invalidSha256Hex(value: unknown): boolean {
  return typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value);
}

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

/** Sequence-valued query/path parameters (F7): exact u64 from a decimal
 *  string, over the full range - no 2^53 cliff. Null-on-invalid wrapper
 *  over the core's u64FromWire, so there is one exact parser, not two. */
function nonNegativeU64(raw: string | null, fallback: bigint): bigint | null {
  if (raw === null) return fallback;
  if (!/^\d+$/.test(raw)) return null;
  try {
    return u64FromWire(raw, "wire parameter");
  } catch {
    return null;
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "GET" && path === "/health") {
      return json({ ok: true, runtime: "workerd", stack: "L1-local" });
    }

    // PR0 containment: on the production surface the dev-only routes do not
    // exist - refused before any parsing, capability work or DO/R2 call.
    if (env.CONTROLLER_SURFACE !== "local-dev" && devOnlyRoute(path)) {
      return json({ ok: false, error: "NOT_FOUND" }, 404);
    }

    /** Fail-closed key/environment resolution shared by every route that
     *  needs it; the typed 500 mirrors the DO's own construction refusal. */
    const resolveKeysOr500 = (): { keys: ResolvedKeys } | { denied: Response } => {
      try {
        return { keys: resolveKeyConfig(env) };
      } catch (error) {
        return { denied: json({ ok: false, error: "KEY_CONFIG_INVALID",
                                detail: error instanceof Error ? error.message : String(error) }, 500) };
      }
    };

    /**
     * Controller routing (R4 PR1): one DO per PROVISIONED database, and the
     * DO name is derived from the registry binding triple (environment +
     * tenant + opaque database id, registry.ts controllerDoName) - never
     * from a caller-supplied database id alone. The map records, per
     * request, which stub each database id resolved to: it is populated
     * ONLY from a verified token's binding (frameCheck) or an explicitly
     * validated provisioning/issuance binding, so every later `stubFor`
     * lookup inside a route body reuses the registry-derived route. The
     * stub is typed straight off the DO class (workers-types RPC), so there
     * is exactly ONE method surface - the class itself - and nothing
     * hand-maintained to drift.
     */
    const routed = new Map<string, DurableObjectStub<DatabaseControllerDO>>();
    const routeBinding = (binding: ProvisionBinding): DurableObjectStub<DatabaseControllerDO> => {
      const stub = env.CONTROLLER.get(env.CONTROLLER.idFromName(controllerDoName(binding)));
      routed.set(binding.databaseId, stub);
      return stub;
    };
    const stubFor = (databaseId: string): DurableObjectStub<DatabaseControllerDO> => {
      const stub = routed.get(databaseId);
      if (stub === undefined) {
        // structurally unreachable: every route verifies a token (which
        // routes its binding) before touching an authority. Loud, not
        // silent, if a future route forgets.
        throw new Error(`UNROUTED_DATABASE: ${databaseId} was never bound to a verified route`);
      }
      return stub;
    };

    type CapExpect = { method: string; session?: string; generation?: string;
                       key?: string; bodyDigest?: string; bodyLength?: number };

    /**
     * Stateless capability FRAMING pre-check at the outer worker (audit
     * C-03): verify schema version/alg, kid/env scope, the Ed25519
     * SIGNATURE (R5-SEC-03 — the worker holds only the public keyring),
     * expiry, audience, method, key/digest/session/generation BEFORE any
     * Durable Object is contacted. A junk, forged, expired, wrong-audience
     * or wrong-method token is refused here, so it never instantiates,
     * migrates or binds a DO. On success the token's verified binding
     * triple decides the DO route (routeBinding); the authoritative
     * incarnation/binding checks and the single-request nonce claim then
     * run inside the DO. Returns the token + verified payload, or the
     * typed denial Response.
     */
    const frameCheck = async (databaseId: string, expect: CapExpect):
      Promise<{ token: string; payload: CapabilityPayload } | { denied: Response }> => {
      const token = request.headers.get("x-capability");
      if (token === null) return { denied: json({ ok: false, error: "CAPABILITY_REQUIRED" }, 401) };
      const resolved = resolveKeysOr500();
      if ("denied" in resolved) return resolved;
      // currentIncarnation omitted: the DO owns the authoritative check
      const framed = await verifyCapabilityToken(resolved.keys.capabilityKeyring, token, {
        databaseId, env: resolved.keys.environment, ...expect, nowMs: Date.now(),
      });
      if (!framed.ok) return { denied: json(framed, framed.error === "CAPABILITY_MALFORMED" ? 400 : 403) };
      // the routing triple comes from the VERIFIED token, and its ids must
      // be normalized bounded identifiers before they name a DO
      const binding = checkBinding({
        environment: framed.payload.env, tenantId: framed.payload.tenantId, databaseId,
      });
      if (!binding.ok) return { denied: json(binding, 400) };
      routeBinding(binding.binding);
      return { token, payload: framed.payload };
    };

    /** Mutating routes: frame-check (no DO on failure), then verify-and-CLAIM
     *  at the authority. `useDigest` is the canonical digest of the ONE
     *  request authorized (C-02): the claim binds the nonce to it, and a
     *  terminal use replays its stored response instead of re-executing. */
    const verifyCapability = async (databaseId: string, expect: CapExpect, useDigest: string) => {
      const framed = await frameCheck(databaseId, expect);
      if ("denied" in framed) return { authorized: false as const, denied: framed.denied };
      // the DO call carries the full expected binding (tenant from the
      // verified token), so the authority can verify it was addressed as
      // the database it is provisioned to be (R4 PR1)
      const verdict = await stubFor(databaseId).useCapability(
        framed.token, { databaseId, tenantId: framed.payload.tenantId, ...expect }, useDigest);
      if (!verdict.ok) return { authorized: false as const, denied: json(verdict, 403) };
      return { authorized: true as const, verdict };
    };

    /** Read routes: frame-check then verify WITHOUT claiming a durable use
     *  row (audit C-07) - reads are side-effect-free, so they must not write
     *  to the control tables. Incarnation and session are still enforced. */
    const verifyRead = async (databaseId: string, expect: CapExpect):
      Promise<{ authorized: true; payload: { session?: string } } | { authorized: false; denied: Response }> => {
      const framed = await frameCheck(databaseId, expect);
      if ("denied" in framed) return { authorized: false as const, denied: framed.denied };
      const verdict = await stubFor(databaseId).checkCapabilityOnly(
        framed.token, { databaseId, tenantId: framed.payload.tenantId, ...expect });
      if (!verdict.ok) return { authorized: false as const, denied: json(verdict, 403) };
      return { authorized: true as const, payload: verdict.payload };
    };

    /** C-02 terminal replay: when a claim is a non-fresh, terminal use, the
     *  stored response is returned verbatim and the route body NEVER runs.
     *  A non-fresh, non-terminal use (a crash between effect and resolve)
     *  is a bounded typed retry, never a blind re-execution. Returns a
     *  Response to short-circuit with, or null to proceed and execute. */
    const replayTerminal = (verdict: { claim?: { fresh: boolean; terminal: boolean; response: string | null } }):
      Response | null => {
      const claim = verdict.claim;
      if (claim === undefined || claim.fresh) return null;
      if (claim.terminal && claim.response !== null) {
        const stored = JSON.parse(claim.response) as { status: number; body: unknown };
        return json(stored.body, stored.status);
      }
      if (claim.terminal) return json({ ok: true, replayed: true }, 200);
      return json({ ok: false, error: "CAPABILITY_IN_FLIGHT",
                    hint: "a prior use of this token has not resolved; retry" }, 409);
    };

    /** Resolve a claimed use to its terminal outcome, storing the response
     *  envelope so an identical retry replays it (C-02). `nonce` comes from
     *  the verified payload. */
    const resolveUse = async (
      databaseId: string, nonce: string, ok: boolean, status: number, body: unknown,
    ): Promise<void> => {
      // sequence values are bigint end-to-end; the stored envelope encodes
      // them as decimal strings exactly as json() sends them on the wire, so
      // a replayed response is byte-identical to the original (C-02)
      await stubFor(databaseId).resolveCapabilityUse(
        nonce, ok ? "RESOLVED_SUCCESS" : "RESOLVED_REJECTED",
        JSON.stringify({ status, body }, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
    };

    /** A mutating route in one wrapper (C-02): frame-check + claim, replay a
     *  terminal use, else execute and resolve. `execute` returns the
     *  {status, body} to send; the wrapper stores it as the use outcome. */
    const withMutation = async (
      databaseId: string, expect: CapExpect, useDigest: string,
      execute: (payload: { session?: string; generation?: string }) => Promise<{ status: number; body: unknown }>,
    ): Promise<Response> => {
      const auth = await verifyCapability(databaseId, expect, useDigest);
      if (!auth.authorized) return auth.denied;
      const replay = replayTerminal(auth.verdict);
      if (replay !== null) return replay;
      const nonce = auth.verdict.payload?.nonce;
      try {
        const result = await execute(auth.verdict.payload);
        if (typeof nonce === "string") {
          const ok = result.status >= 200 && result.status < 300;
          await resolveUse(databaseId, nonce, ok, result.status, result.body);
        }
        return json(result.body, result.status);
      } catch (error) {
        // C-02: infrastructure/transport uncertainty is recorded AMBIGUOUS
        // and stays retryable - never silently converted into a burned token
        if (typeof nonce === "string") {
          await stubFor(databaseId).resolveCapabilityUse(nonce, "AMBIGUOUS",
            JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
        }
        throw error;
      }
    };

    /** Bind a mutating use to the request line (method + path + query) when the
     *  route carries no body of its own (e.g. INCARNATION_BUMP). Read routes claim
     *  no use (C-07) and do not call this. */
    const routeUseDigest = () =>
      useDigestOf({ method: request.method, path, search: url.search });

    /** null = authorized; otherwise the typed 401/403/409. Read helper (no
     *  claim): reads never claim a use (C-07), so no request-line digest is
     *  bound. R4-SEC-05: a WAL_READ token names its session AND generation
     *  (REQUIRED_RESTRICTIONS), and the DO revalidates that the session
     *  holds LIVE authority at use time — MAC validity alone must not keep
     *  a fenced/expired actor reading until token expiry. (The residual
     *  window is one in-flight read racing a fence between the two DO
     *  hops; folding the check into each read RPC is the recorded
     *  optimization remainder.) JOURNAL_VERIFY deliberately skips this:
     *  it is the session-independent recovery/forensics role. */
    const requireCapability = async (
      databaseId: string, expect: CapExpect,
    ): Promise<Response | null> => {
      const auth = await verifyRead(databaseId, expect);
      if (!auth.authorized) return auth.denied;
      if (expect.method === "WAL_READ") {
        const live = await assertLiveReader(databaseId, auth.payload);
        if (live !== null) return live;
      }
      return null;
    };

    /** R4-SEC-05 use-time actor revalidation for a verified WAL_READ
     *  payload; null = live, otherwise the typed refusal Response. */
    const assertLiveReader = async (
      databaseId: string, payload: { session?: string; generation?: string } | undefined,
    ): Promise<Response | null> => {
      const session = payload?.session;
      if (typeof session !== "string" || session.length === 0) {
        return json({ ok: false, error: "CAPABILITY_RESTRICTION_MISSING", restriction: "session" }, 403);
      }
      const gen = exactGeneration(typeof payload?.generation === "string" ? Number(payload.generation) : undefined);
      if (gen === null) {
        return json({ ok: false, error: "CAPABILITY_RESTRICTION_MISSING", restriction: "generation" }, 403);
      }
      const live = await stubFor(databaseId).assertActiveReader(databaseId, session, gen);
      if (!live.ok) return json(live, 409);
      return null;
    };

    /** Read helper that also hands back the session (WAL_READ operation
     *  query). No durable claim (C-07); same use-time revalidation. */
    const requireCapabilityWithSession = async (
      databaseId: string, expect: CapExpect,
    ): Promise<{ denied: Response } | { session: string }> => {
      const auth = await verifyRead(databaseId, expect);
      if (!auth.authorized) return { denied: auth.denied };
      const session = auth.payload?.session;
      if (typeof session !== "string" || session.length === 0) {
        return { denied: json({ ok: false, error: "CAPABILITY_RESTRICTION_MISSING", restriction: "session" }, 403) };
      }
      if (expect.method === "WAL_READ") {
        const live = await assertLiveReader(databaseId, auth.payload);
        if (live !== null) return { denied: live };
      }
      return { session };
    };

    /** Exact generation or the typed 400 (donor A5): the one refusal every
     *  generation-bearing route answers identically. */
    const generationOr = (raw: unknown): number | Response => {
      const gen = exactGeneration(raw);
      return gen === null
        ? json({ ok: false, error: "INVALID_GENERATION", observed: raw ?? null }, 400)
        : gen;
    };

    /** Core-level authority outcomes surfaced as protocol shapes. */
    const sessionRefusal = (result: { ok: false; error: string }): Response | null =>
      result.error === "SESSION_FENCED" || result.error === "SESSION_UNKNOWN"
        ? json({ ok: false, error: result.error }, 409)
        : null;

    if (request.method === "POST" && path === "/provision") {
      // R4 PR1: the internal provisioning transaction - the ONLY path that
      // binds an uninitialized controller authority, and the production
      // bootstrap route (it is NOT dev-only; its authorization is the
      // PROVISION capability, mintable only from the private issuer's
      // provisioning-scope key). The worker frame-checks the token against
      // the exact binding BEFORE any DO is contacted, then the DO
      // re-verifies authoritatively and binds transactionally.
      const resolved = resolveKeysOr500();
      if ("denied" in resolved) return resolved.denied;
      const parsed = await readJson(request);
      if ("errorResponse" in parsed) return parsed.errorResponse;
      const body = parsed.body as { tenantId?: unknown; databaseId?: unknown; budgets?: unknown };
      const binding = checkBinding({
        environment: resolved.keys.environment, tenantId: body.tenantId, databaseId: body.databaseId,
      });
      if (!binding.ok) return json(binding, 400);
      const token = request.headers.get("x-provision");
      if (token === null) return json({ ok: false, error: "PROVISION_TOKEN_REQUIRED" }, 401);
      const framed = await verifyProvisionToken(resolved.keys.provisionKeyring, token, {
        binding: binding.binding, nowMs: Date.now(),
      });
      if (!framed.ok) return json(framed, framed.error === "CAPABILITY_MALFORMED" ? 400 : 403);
      // budgets ride the provisioning transaction because the production
      // surface has no budget-admin route; shape validation is the core's
      const budgets = body.budgets;
      if (budgets !== undefined && (typeof budgets !== "object" || budgets === null || Array.isArray(budgets))) {
        return json({ ok: false, error: "MALFORMED_JSON", hint: "budgets must be an object" }, 400);
      }
      const stub = routeBinding(binding.binding);
      const result = await stub.provision(token, binding.binding,
        budgets as { maxUnpublishedOutbox: number; maxPayloadLength: number; maxTailRecords: number } | undefined);
      const status = result.ok ? 200
        : result.error === "PROVISION_CONFLICT" ? 409
        : result.error === "INVALID_BUDGET" || result.error === "INVALID_BINDING" ? 400
        : 403;
      return json(result, status);
    }

    if (request.method === "POST" && path === "/capability") {
      // Q-02: issuance is CREDENTIALED in every posture. The audit's finding
      // was that a self-issued capability does not create authentication;
      // requiring the issuer secret here means no configuration state exists
      // in which an anonymous caller can mint authority. Resolution is
      // fail-closed: a worker whose key config cannot resolve refuses
      // issuance outright rather than falling back to open issuance.
      const resolved = resolveKeysOr500();
      if ("denied" in resolved) return resolved.denied;
      // the issuance credential exists ONLY under local-dev (the route
      // itself is dev-only); a posture with no credential issues nothing
      const issuerSecret = resolved.keys.issuerSecret;
      const presented = request.headers.get("x-issuer-authorization");
      if (issuerSecret === undefined || presented === null || !credentialsEqual(presented, issuerSecret)) {
        return json({ ok: false, error: "ISSUER_UNAUTHORIZED" }, 401);
      }
      const parsed = await readJson(request);
      if ("errorResponse" in parsed) return parsed.errorResponse;
      const spec = parsed.body as unknown as {
        principal: string; tenantId?: string; databaseId: string; method: string;
        digest?: string; maxBytes?: number; ttlMs?: number;
      };
      // dev-lane routing follows the same registry-derived DO name as the
      // data path (default local tenant), so the dev issuer addresses the
      // SAME authority the tokens it mints will be used against. Issuance
      // to an unprovisioned authority is refused by the DO.
      const binding = checkBinding({
        environment: resolved.keys.environment, tenantId: spec.tenantId ?? "local", databaseId: spec.databaseId,
      });
      if (!binding.ok) return json(binding, 400);
      const stub = routeBinding(binding.binding);
      try {
        return json({ ok: true, ...(await stub.issueCapability(spec)) });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (message.includes("DATABASE_UNPROVISIONED")) {
          return json({ ok: false, error: "DATABASE_UNPROVISIONED" }, 409);
        }
        throw error;
      }
    }

    const adminBump = path.match(/^\/admin\/([^/]+)\/incarnation\/bump$/);
    if (request.method === "POST" && adminBump) {
      // incarnation bump is NOT idempotent (each call increments), so it is a
      // single-request mutation: a replayed token returns the stored result
      return withMutation(adminBump[1], { method: "INCARNATION_BUMP" }, await routeUseDigest(), async () => ({
        status: 200, body: { ok: true, incarnation: await stubFor(adminBump[1]).bumpIncarnation() },
      }));
    }

    if (request.method === "PUT" && path.startsWith("/payload/")) {
      // safe percent-decoding: a malformed `%zz` key is a typed 400, never a
      // 500 from an unhandled URIError (C-06)
      const decodedKey = safeDecodeComponent(path.slice("/payload/".length));
      if ("errorResponse" in decodedKey) return decodedKey.errorResponse;
      const key = decodedKey.value;
      // content-addressed, issuer-derived key scheme: p/<databaseId>/<sha256hex>.
      // Runtime-validate the FULL structure the byte path depends on (C-06):
      // three segments, literal "p" prefix, a non-empty databaseId, and a
      // syntactically valid 64-hex content digest - not just a length check.
      const parts = key.split("/");
      if (parts.length !== 3 || parts[0] !== "p" || parts[1].length === 0 || invalidSha256Hex(parts[2])) {
        return json({ ok: false, error: "INVALID_PAYLOAD_KEY", key }, 400);
      }
      const tooLarge = refuseOversizedBody(request);
      if (tooLarge) return tooLarge;
      // the digest binding genuinely needs the body hashed before the
      // capability verdict; the null-token refusal does not - answer it
      // before reading anything
      if (request.headers.get("x-capability") === null) {
        return json({ ok: false, error: "CAPABILITY_REQUIRED" }, 401);
      }
      // Bounded streaming read (C-06): the body is consumed chunk-by-chunk into
      // an incremental digest with a per-chunk byte cap that does NOT trust the
      // declared content-length. The content-length pre-check above is kept as
      // the fast, pre-read refusal; this is the authoritative bound.
      const streamed = await readBodyStreamingDigest(request, MAX_REQUEST_BODY_BYTES);
      if ("errorResponse" in streamed) return streamed.errorResponse;
      const { bytes, digest } = streamed;
      // payload immutability: puts are create-or-identical, never overwrite.
      // The create is a CONDITIONAL put (If-None-Match: *), not get-then-put:
      // two concurrent puts of different bytes must never both succeed, and a
      // read-then-write window would allow exactly that. Under the capability
      // boundary a different-bytes put at this key cannot even reach here
      // (digest binding); the conditional create remains as defense in depth.
      // withMutation records the terminal outcome so an identical retry
      // replays it, and a thrown provider error is recorded AMBIGUOUS.
      return withMutation(parts[1], {
        method: "PUT_PAYLOAD", key, bodyDigest: digest, bodyLength: bytes.byteLength,
      }, await useDigestOf({ method: "PUT_PAYLOAD", key, digest, length: bytes.byteLength }), async () => {
        for (let attempt = 0; attempt < 3; attempt++) {
          const created = await env.PAYLOADS.put(key, bytes, {
            onlyIf: new Headers({ "if-none-match": "*" }),
          });
          if (created !== null) return { status: 200, body: { key, sha256hex: digest, length: bytes.byteLength } };
          // lost the conditional create: verify the existing object streaming
          // against our digest (no arrayBuffer()+hash pass, per-object cap
          // enforced) to decide dedup vs immutability violation.
          const existing = await fetchVerified(env, key, digest);
          if ("bytes" in existing) {
            return { status: 200, body: { key, sha256hex: digest, length: bytes.byteLength, deduplicated: true } };
          }
          if (existing.error === "MISSING") continue; // lost a delete/create race; retry the conditional create
          if (existing.error === "OVER_CAP") {
            return { status: 413, body: { ok: false, error: "PAYLOAD_EXCEEDS_OBJECT_CAP",
                                          key, size: existing.size, cap: existing.cap } };
          }
          return { status: 409, body: { ok: false, error: "PAYLOAD_IMMUTABILITY_VIOLATION",
                                        key, existing: existing.observed } };
        }
        // exhausted the race retries: surface as retryable, not a burned
        // success - withMutation marks a thrown error AMBIGUOUS
        throw new Error("PAYLOAD_RACE_UNRESOLVED");
      });
    }

    if (request.method === "POST" && path === "/session/register") {
      const parsed = await readJson(request);
      if ("errorResponse" in parsed) return parsed.errorResponse;
      const b = parsed.body as unknown as { databaseId: string; generation: number; startupSessionId: string };
      const gen = generationOr(b.generation);
      if (gen instanceof Response) return gen;
      return withMutation(b.databaseId,
        { method: "SESSION_REGISTER", session: b.startupSessionId, generation: String(gen) },
        await useDigestOf({ path, body: parsed.body }), async () => {
          await stubFor(b.databaseId).registerSession(b.databaseId, gen, b.startupSessionId);
          return { status: 200, body: { ok: true } };
        });
    }

    // ---- Q-03 / 12.4 lifecycle routes (exact per-action capabilities, ----
    //      R4-SEC-04: each token names its action AND its exact target actor)
    // Registration is the legacy macro over these; the real flow is
    // reserve -> attest -> activate, and ONLY activation fences.
    if (request.method === "POST" && path === "/session/reserve") {
      const parsed = await readJson(request);
      if ("errorResponse" in parsed) return parsed.errorResponse;
      const b = parsed.body as unknown as {
        databaseId: string; generation: number; startupSessionId: string; holder: string;
      };
      const gen = generationOr(b.generation);
      if (gen instanceof Response) return gen;
      return withMutation(b.databaseId,
        { method: "SESSION_RESERVE", session: b.startupSessionId, generation: String(gen) },
        await useDigestOf({ path, body: parsed.body }), async () => {
          const result = await stubFor(b.databaseId)
            .reserveSession(b.databaseId, gen, b.startupSessionId, b.holder);
          return { status: result.ok ? 200 : 409, body: result };
        });
    }

    if (request.method === "POST" && path === "/session/attest") {
      const parsed = await readJson(request);
      if ("errorResponse" in parsed) return parsed.errorResponse;
      const b = parsed.body as unknown as { databaseId: string; startupSessionId: string; processNonce: string };
      return withMutation(b.databaseId, { method: "SESSION_ATTEST", session: b.startupSessionId },
        await useDigestOf({ path, body: parsed.body }), async () => {
          const result = await stubFor(b.databaseId)
            .attestSession(b.databaseId, b.startupSessionId, b.processNonce);
          return { status: result.ok ? 200 : 409, body: result };
        });
    }

    if (request.method === "POST" && path === "/session/activate") {
      const parsed = await readJson(request);
      if ("errorResponse" in parsed) return parsed.errorResponse;
      const b = parsed.body as unknown as {
        databaseId: string; startupSessionId: string; processNonce: string; generation: number; leaseMs: number;
      };
      const gen = generationOr(b.generation);
      if (gen instanceof Response) return gen;
      return withMutation(b.databaseId,
        { method: "SESSION_ACTIVATE", session: b.startupSessionId, generation: String(gen) },
        await useDigestOf({ path, body: parsed.body }), async () => {
          const result = await stubFor(b.databaseId).activateSession(b.databaseId, b.startupSessionId, {
            processNonce: b.processNonce, generation: gen, leaseMs: b.leaseMs,
          });
          return { status: result.ok ? 200 : 409, body: result };
        });
    }

    if (request.method === "POST" && path === "/session/renew") {
      const parsed = await readJson(request);
      if ("errorResponse" in parsed) return parsed.errorResponse;
      const b = parsed.body as unknown as { databaseId: string; startupSessionId: string; leaseMs: number };
      return withMutation(b.databaseId, { method: "SESSION_RENEW", session: b.startupSessionId },
        await useDigestOf({ path, body: parsed.body }), async () => {
          const result = await stubFor(b.databaseId).renewLease(b.databaseId, b.startupSessionId, b.leaseMs);
          return { status: result.ok ? 200 : 409, body: result };
        });
    }

    if (request.method === "POST" && path === "/session/drain") {
      const parsed = await readJson(request);
      if ("errorResponse" in parsed) return parsed.errorResponse;
      const b = parsed.body as unknown as { databaseId: string; startupSessionId: string };
      return withMutation(b.databaseId, { method: "SESSION_DRAIN", session: b.startupSessionId },
        await useDigestOf({ path, body: parsed.body }), async () => {
          const result = await stubFor(b.databaseId).beginDrain(b.databaseId, b.startupSessionId);
          return { status: result.ok ? 200 : 409, body: result };
        });
    }

    if (request.method === "POST" && path === "/session/revoke") {
      const parsed = await readJson(request);
      if ("errorResponse" in parsed) return parsed.errorResponse;
      const b = parsed.body as unknown as { databaseId: string; startupSessionId: string };
      // The token names the TARGET session (its minter decides which actor
      // may be revoked); the revocation power is not a generic bearer right.
      return withMutation(b.databaseId, { method: "SESSION_REVOKE", session: b.startupSessionId },
        await useDigestOf({ path, body: parsed.body }), async () => {
          const result = await stubFor(b.databaseId).revokeSession(b.databaseId, b.startupSessionId);
          return { status: result.ok ? 200 : 409, body: result };
        });
    }

    if (request.method === "POST" && path === "/session/fence") {
      const parsed = await readJson(request);
      if ("errorResponse" in parsed) return parsed.errorResponse;
      const b = parsed.body as unknown as { databaseId: string; generation: number; startupSessionId: string };
      const gen = generationOr(b.generation);
      if (gen instanceof Response) return gen;
      // the fence is actor-wide: any `generation` in the body is accepted for
      // wire compatibility but does not scope the revocation
      return withMutation(b.databaseId, { method: "SESSION_FENCE", session: b.startupSessionId },
        await useDigestOf({ path, body: parsed.body }), async () => {
          await stubFor(b.databaseId).fenceSession(b.databaseId, b.startupSessionId);
          return { status: 200, body: { ok: true } };
        });
    }

    if (request.method === "POST" && path === "/budgets") {
      const parsed = await readJson(request);
      if ("errorResponse" in parsed) return parsed.errorResponse;
      const b = parsed.body as unknown as {
        databaseId: string; maxUnpublishedOutbox: number; maxPayloadLength: number; maxTailRecords: number;
      };
      // BUDGETS_SET appends a journal row per call, so budgets is a
      // single-request mutation: the audit's "reuse one token twice -> two
      // BUDGETS_SET rows" mutant is killed by the terminal replay (C-02).
      return withMutation(b.databaseId, { method: "BUDGETS_SET" },
        await useDigestOf({ path, body: parsed.body }), async (payload) => {
          const session = payload.session;
          if (typeof session !== "string" || session.length === 0) {
            return { status: 403, body: { ok: false, error: "CAPABILITY_RESTRICTION_MISSING", restriction: "session" } };
          }
          const result = await stubFor(b.databaseId).setBudgets(b.databaseId, {
            maxUnpublishedOutbox: b.maxUnpublishedOutbox,
            maxPayloadLength: b.maxPayloadLength,
            maxTailRecords: b.maxTailRecords,
          }, session);
          return { status: result.ok ? 200 : 409, body: result.ok ? { ok: true } : result };
        });
    }

    // data-path receipt verification BEFORE the DO's synchronous
    // finalisation: the object must exist and match digest + length
    const verifyReceipt = async (req: { payloadKey: string; payloadDigest: string; payloadLength: number }):
      Promise<{ status: number; body: unknown } | null> => {
      const result = await fetchVerified(env, req.payloadKey, req.payloadDigest, req.payloadLength);
      if ("bytes" in result) return null;
      if (result.error === "MISSING") return { status: 422, body: { ok: false, error: "PAYLOAD_MISSING", key: req.payloadKey } };
      if (result.error === "OVER_CAP") {
        return { status: 413, body: { ok: false, error: "PAYLOAD_EXCEEDS_OBJECT_CAP",
                                      key: req.payloadKey, size: result.size, cap: result.cap } };
      }
      return { status: 422, body: { ok: false, error: "PAYLOAD_DIGEST_MISMATCH", observed: result.observed, length: result.length } };
    };

    /** C-P0-07: the R2 payload key is SERVER-derived and content-addressed;
     *  a finalize (or batch member) naming any other key - notably another
     *  database's `p/<db>/<digest>` object - refuses BEFORE any R2 GET or
     *  DO call. This closes the cross-tenant reference path: a database-A
     *  actor cannot catalogue a global object it did not itself upload
     *  under A's capability boundary. Returns null when canonical. */
    const nonCanonicalPayloadRef = (req: {
      databaseId: string; payloadKey: unknown; payloadDigest: unknown; payloadLength: unknown;
    }): Response | null => {
      if (invalidSha256Hex(req.payloadDigest)) {
        return json({ ok: false, error: "INVALID_PAYLOAD_DIGEST", observed: req.payloadDigest ?? null }, 400);
      }
      if (typeof req.payloadLength !== "number" || !Number.isSafeInteger(req.payloadLength)
          || req.payloadLength < 0) {
        return json({ ok: false, error: "INVALID_PAYLOAD_LENGTH", observed: req.payloadLength ?? null }, 400);
      }
      const canonical = `p/${req.databaseId}/${req.payloadDigest}`;
      if (req.payloadKey !== canonical) {
        return json({ ok: false, error: "NON_CANONICAL_PAYLOAD_KEY", expected: canonical }, 400);
      }
      return null;
    };

    if (request.method === "POST" && path === "/wal/finalize") {
      const parsedFinalize = await readJson(request);
      if ("errorResponse" in parsedFinalize) return parsedFinalize.errorResponse;
      const req = parsedFinalize.body as unknown as {
        databaseId: string; payloadKey: string; payloadDigest: string; payloadLength: number;
      } & Record<string, unknown>;
      if (invalidRecordType(req.recordType)) {
        return json({ ok: false, error: "INVALID_RECORD_TYPE", observed: req.recordType ?? null }, 400);
      }
      const gen = generationOr(req.generation);
      if (gen instanceof Response) return gen;
      const badRef = nonCanonicalPayloadRef(req);
      if (badRef !== null) return badRef;
      // Q-18: the dedupe key is derived here, not asserted by the caller -
      // and computed BEFORE the capability claim, because it is also the
      // use digest the token's nonce gets bound to (C-P0-08)
      const computedDigest = await canonicalRequestDigest(req);
      if (typeof req.requestDigest === "string" && req.requestDigest !== computedDigest) {
        return json({ ok: false, error: "REQUEST_DIGEST_MISMATCH",
                      computed: computedDigest, supplied: req.requestDigest }, 400);
      }
      // the finalize capability MUST be bound to the request's session AND
      // generation (donor A3 + audit C-05): neither a session id in the body
      // nor a token from another generation is write authority
      return withMutation(req.databaseId, {
        method: "WAL_FINALIZE",
        session: String((req as { startupSessionId?: unknown }).startupSessionId ?? ""),
        generation: String(gen),
      }, computedDigest, async () => {
        const receiptError = await verifyReceipt(req);
        if (receiptError !== null) return receiptError;
        // the wire body is validated field-by-field above and again in the
        // core; the cast is the JSON boundary, not a trust statement
        const result = await stubFor(req.databaseId)
          .finalizeWalRecord({ ...req, requestDigest: computedDigest } as unknown as FinalizeRequest);
        return { status: result.ok ? 200 : 409, body: result };
      });
    }

    if (request.method === "POST" && path === "/wal/finalize-batch") {
      const parsedBatch = await readJson(request);
      if ("errorResponse" in parsedBatch) return parsedBatch.errorResponse;
      const body = parsedBatch.body as unknown as {
        batchOperationId?: unknown; batchDigest?: unknown;
        requests: ({ databaseId: string; payloadKey: string; payloadDigest: string; payloadLength: number }
          & Record<string, unknown>)[];
      };
      if (!Array.isArray(body.requests) || body.requests.length === 0) {
        return json({ ok: false, error: "EMPTY_BATCH" }, 400);
      }
      // C-P0-09: the K/aggregate-byte bounds are enforced HERE, before the
      // capability claim and before any receipt GET - a 65-member or
      // over-budget batch makes zero R2/DO calls and burns nothing.
      if (body.requests.length > MAX_BATCH_MEMBERS) {
        return json({ ok: false, error: "BATCH_TOO_MANY_MEMBERS", limit: MAX_BATCH_MEMBERS }, 400);
      }
      // directive 12.6: a batch is ONE authority envelope with an identity.
      // Without it the batch cannot be replayed, conflicted or audited, and
      // the release baseline (one-record finalization) always remains open.
      if (typeof body.batchOperationId !== "string" || body.batchOperationId.length === 0) {
        return json({ ok: false, error: "BATCH_ENVELOPE_REQUIRED",
                      hint: "batchOperationId is required; batchDigest is optional and only checked" }, 400);
      }
      if (body.batchDigest !== undefined && typeof body.batchDigest !== "string") {
        // a non-string digest is a malformed request, not a failed
        // comparison - the comparison verdicts are MISMATCH (member) and
        // CONFLICT (envelope), and this is neither
        return json({ ok: false, error: "BATCH_DIGEST_MALFORMED", observed: typeof body.batchDigest }, 400);
      }
      const databaseId = body.requests[0].databaseId;
      const batchSession = String((body.requests[0] as { startupSessionId?: unknown }).startupSessionId ?? "");
      let declaredBytes = 0;
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
        const memberGen = generationOr(req.generation);
        if (memberGen instanceof Response) return memberGen;
        const badRef = nonCanonicalPayloadRef(req);
        if (badRef !== null) return badRef;
        declaredBytes += req.payloadLength;
      }
      if (declaredBytes > MAX_BATCH_BYTES) {
        // still pre-I/O: nothing has been fetched or burned (C-P0-09)
        return json({ ok: false, error: "BATCH_TOO_MANY_BYTES", limit: MAX_BATCH_BYTES, declared: declaredBytes }, 400);
      }
      // Q-18: same rule for every batch member - the digest is derived here,
      // BEFORE the capability claim (they form the batch's use digest)
      const digested: Record<string, unknown>[] = [];
      const memberDigests: string[] = [];
      for (const req of body.requests) {
        const computed = await canonicalRequestDigest(req);
        if (typeof req.requestDigest === "string" && req.requestDigest !== computed) {
          return json({ ok: false, error: "REQUEST_DIGEST_MISMATCH", operationId: req.operationId ?? null,
                        computed, supplied: req.requestDigest }, 400);
        }
        digested.push({ ...req, requestDigest: computed });
        memberDigests.push(computed);
      }
      // the capability use binds the batch identity AND the generation (all
      // members share one generation, checked above): same batch retries,
      // any other batch under the same token replays (audit C-02/C-05)
      const batchGeneration = String(exactGeneration(body.requests[0].generation));
      const batchOperationId = body.batchOperationId; // narrowed to string above
      const batchDigest = body.batchDigest;
      return withMutation(databaseId,
        { method: "WAL_FINALIZE", session: batchSession, generation: batchGeneration },
        await useDigestOf({ batchOperationId, members: memberDigests }), async () => {
          const receiptErrors = await mapBounded(body.requests, PAYLOAD_FETCH_CONCURRENCY, verifyReceipt);
          const firstReceiptError = receiptErrors.find((error) => error !== null);
          if (firstReceiptError) return firstReceiptError;
          const result = await stubFor(databaseId).finalizeBatch(digested as unknown as FinalizeRequest[], {
            batchOperationId,
            ...(batchDigest !== undefined ? { batchDigest } : {}),
          });
          // all-or-nothing: an array is N successes; a single typed error
          // aborted (and rolled back) the whole batch
          return Array.isArray(result)
            ? { status: 200, body: { ok: true, results: result } }
            : { status: 409, body: result };
        });
    }

    const walRead = path.match(/^\/wal\/([^/]+)\/(\d+)\/(\d+)$/);
    if (request.method === "GET" && walRead) {
      const [, db, generation, lsn] = walRead;
      const gen = generationOr(generation);
      if (gen instanceof Response) return gen;
      // the LSN segment is u64-bounded like every sequence parameter: an
      // overflowing value is a typed 400 here, never an exception (500)
      // after the caller's single-use capability was already burned
      const lsnValue = nonNegativeU64(lsn, 0n);
      if (lsnValue === null) return json({ ok: false, error: "INVALID_PARAMETER", field: "lsn" }, 400);
      const denied = await requireCapability(db, { method: "WAL_READ" });
      if (denied) return denied;
      const record = await stubFor(db).exactLookup(db, gen, lsnValue);
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
      const gen = generationOr(generation);
      if (gen instanceof Response) return gen;
      const denied = await requireCapability(db, { method: "WAL_READ" });
      if (denied) return denied;
      return json({ ok: true, ...(await stubFor(db).head(db, gen)) });
    }

    const walIterator = path.match(/^\/wal\/([^/]+)\/(\d+)\/iterator$/);
    if (request.method === "POST" && walIterator) {
      const [, db, generation] = walIterator;
      const gen = generationOr(generation);
      if (gen instanceof Response) return gen;
      const denied = await requireCapability(db, { method: "WAL_READ" });
      if (denied) return denied;
      return json({ ok: true, ...(await stubFor(db).openIterator(db, gen)) });
    }

    const walScan = path.match(/^\/wal\/([^/]+)\/(\d+)\/scan$/);
    if (request.method === "GET" && walScan) {
      const [, db, generation] = walScan;
      const gen = generationOr(generation);
      if (gen instanceof Response) return gen;
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
      const gen = generationOr(generation);
      if (gen instanceof Response) return gen;
      // safe percent-decoding of the operation id: a malformed `%zz` is a
      // typed 400, never a 500 from an unhandled URIError (C-06)
      const decodedOp = safeDecodeComponent(operationId);
      if ("errorResponse" in decodedOp) return decodedOp.errorResponse;
      const auth = await requireCapabilityWithSession(db, { method: "WAL_READ" });
      if ("denied" in auth) return auth.denied;
      // Read surface: immutable durable history stays queryable by operation
      // identity across a fence of some OTHER actor (V16; the finalize-RETRY
      // path still answers SESSION_FENCED per inv. 38). "By the current
      // actor" is load-bearing, so the core revalidates the caller's own
      // session (donor A4): a fenced actor holding an unexpired WAL_READ
      // capability reads nothing.
      const result = await stubFor(db).queryOperation(
        db, gen, decodedOp.value, auth.session);
      if (!result.ok) {
        const refusal = sessionRefusal(result as { ok: false; error: string });
        return refusal ?? json(result, 404);
      }
      return json(result);
    }

    const walLast = path.match(/^\/wal\/([^/]+)\/(\d+)\/last$/);
    if (request.method === "GET" && walLast) {
      const [, db, generation] = walLast;
      const gen = generationOr(generation);
      if (gen instanceof Response) return gen;
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
      // validated and clamped like scan's: a negative LIMIT is documented by
      // SQLite as "no upper bound", so an unchecked value here was the one
      // route where a caller could request an unbounded page
      const rawPeek = nonNegativeInt(url.searchParams.get("limit"), 100);
      if (rawPeek === null) return json({ ok: false, error: "INVALID_PARAMETER", field: "limit" }, 400);
      const limit = Math.min(Math.max(rawPeek, 1), 1000);
      return json({ ok: true, events: await stubFor(outboxPeek[1]).outboxPeek(limit) });
    }

    const outboxAck = path.match(/^\/outbox\/([^/]+)\/ack$/);
    if (request.method === "POST" && outboxAck) {
      const parsedAck = await readJson(request);
      if ("errorResponse" in parsedAck) return parsedAck.errorResponse;
      const b = parsedAck.body as unknown as { upToControlSeq: number | string };
      // parse the bound BEFORE the claim: a malformed value is a 400 that
      // must not burn the token
      let upTo: bigint;
      try {
        upTo = u64FromWire(b.upToControlSeq, "upToControlSeq");
      } catch {
        return json({ ok: false, error: "INVALID_PARAMETER", field: "upToControlSeq" }, 400);
      }
      // ack marks rows published (a mutation): single-request via withMutation
      return withMutation(outboxAck[1], { method: "OUTBOX" },
        await useDigestOf({ path, body: parsedAck.body }), async (payload) => {
          const session = payload.session;
          if (typeof session !== "string" || session.length === 0) {
            return { status: 403, body: { ok: false, error: "CAPABILITY_RESTRICTION_MISSING", restriction: "session" } };
          }
          const result = await stubFor(outboxAck[1]).outboxAck(outboxAck[1], upTo, session);
          return result.ok
            ? { status: 200, body: { ok: true, acked: result.acked } }
            : { status: 409, body: result };
        });
    }

    const cutOpen = path.match(/^\/checkpoint\/([^/]+)\/(\d+)\/cut$/);
    if (request.method === "POST" && cutOpen) {
      // invalid input refuses BEFORE the capability check, like every other
      // route family: a 400 must not burn the caller's single-use token
      const cutGen = generationOr(cutOpen[2]);
      if (cutGen instanceof Response) return cutGen;
      const parsedCut = await readJson(request);
      if ("errorResponse" in parsedCut) return parsedCut.errorResponse;
      const b = parsedCut.body as unknown as { cutId: string };
      return withMutation(cutOpen[1], { method: "CHECKPOINT_OPEN", generation: String(cutGen) },
        await useDigestOf({ path, body: parsedCut.body }), async (payload) => {
          // R4-SEC-04/06: the acting session must hold LIVE authority in
          // this generation at use time - a fenced/stale actor cannot open
          // a cut with a still-valid token.
          const actor = typeof payload.session === "string" ? payload.session : "";
          const live = await stubFor(cutOpen[1]).assertActiveReader(cutOpen[1], actor, cutGen);
          if (!live.ok) return { status: 409, body: live };
          const result = await stubFor(cutOpen[1]).openCheckpointCut(cutOpen[1], cutGen, b.cutId);
          return { status: result.ok ? 200 : 409, body: result };
        });
    }

    const cutActivate = path.match(/^\/checkpoint\/([^/]+)\/cut\/([^/]+)\/activate$/);
    if (request.method === "POST" && cutActivate) {
      // safe percent-decoding of the cut id BEFORE the capability claim: a
      // malformed `%zz` is a typed 400 that burns no token, never a 500 (C-06)
      const decodedCut = safeDecodeComponent(cutActivate[2]);
      if ("errorResponse" in decodedCut) return decodedCut.errorResponse;
      const parsedEvidence = await readJson(request);
      if ("errorResponse" in parsedEvidence) return parsedEvidence.errorResponse;
      // R4-SEC-06: the body is the versioned restore-evidence manifest,
      // validated MATERIALLY by the core (schema, cut id, recorded WAL
      // head, 64-hex digests, scratch-restore verifier) - never cast.
      return withMutation(cutActivate[1], { method: "CHECKPOINT_ACTIVATE" },
        await useDigestOf({ path, body: parsedEvidence.body }), async (payload) => {
          const actor = typeof payload.session === "string" ? payload.session : "";
          const gen = exactGeneration(
            typeof payload.generation === "string" ? Number(payload.generation) : undefined);
          if (gen === null) {
            return { status: 403, body: { ok: false, error: "CAPABILITY_RESTRICTION_MISSING", restriction: "generation" } };
          }
          const live = await stubFor(cutActivate[1]).assertActiveReader(cutActivate[1], actor, gen);
          if (!live.ok) return { status: 409, body: live };
          const result = await stubFor(cutActivate[1])
            .activateCheckpointCut(cutActivate[1], decodedCut.value, parsedEvidence.body);
          return { status: result.ok ? 200 : 409, body: result };
        });
    }

    const cutActive = path.match(/^\/checkpoint\/([^/]+)\/(\d+)\/active$/);
    if (request.method === "GET" && cutActive) {
      const activeGen = generationOr(cutActive[2]);
      if (activeGen instanceof Response) return activeGen;
      const denied = await requireCapability(cutActive[1], { method: "WAL_READ" });
      if (denied) return denied;
      const result = await stubFor(cutActive[1]).activeCheckpointCut(cutActive[1], activeGen);
      return json(result, result.ok ? 200 : 404);
    }

    const journalVerifyAnchored = path.match(/^\/journal\/([^/]+)\/verify-anchored$/);
    if (request.method === "GET" && journalVerifyAnchored) {
      const denied = await requireCapability(journalVerifyAnchored[1], { method: "JOURNAL_VERIFY" });
      if (denied) return denied;
      const verdict = await stubFor(journalVerifyAnchored[1]).verifyJournalAnchored();
      return json(verdict, verdict.ok ? 200 : 409);
    }

    const journalVerify = path.match(/^\/journal\/([^/]+)\/verify$/);
    if (request.method === "GET" && journalVerify) {
      // F8 read surface: recompute the whole chain + MACs server-side.
      // Routed by databaseId like every DO method (the journal is the DO's
      // global outbox; the id names the authority instance to audit).
      const denied = await requireCapability(journalVerify[1], { method: "JOURNAL_VERIFY" });
      if (denied) return denied;
      const verdict = await stubFor(journalVerify[1]).verifyJournal();
      return json(verdict, verdict.ok ? 200 : 409);
    }

    const walAudit = path.match(/^\/wal\/([^/]+)\/(\d+)\/audit$/);
    if (request.method === "GET" && walAudit) {
      const [, db, generation] = walAudit;
      const gen = generationOr(generation);
      if (gen instanceof Response) return gen;
      const denied = await requireCapability(db, { method: "WAL_READ" });
      if (denied) return denied;
      return json({ ok: true, ...(await stubFor(db).auditContiguity(db, gen)) });
    }

    return json({ ok: false, error: "NOT_FOUND" }, 404);
  },
};
