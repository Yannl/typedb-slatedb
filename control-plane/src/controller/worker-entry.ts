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
 * R5-SEC-05: every READ route is ONE authoritative Durable Object hop -
 * the same call verifies the capability, revalidates that the bound actor
 * still holds live read authority, and performs the catalogue read, with no
 * await between the check and the read. Reads that carry payload bytes also
 * receive a durable ONE-SHOT, short-TTL read lease over the exact object
 * keys the worker will fetch; the worker REDEEMS it after the fetch and
 * before serving, and every fence/revoke/expiry/incarnation transition
 * deletes that actor's leases in its own transaction. A fence that commits
 * while bytes are in flight therefore refuses the read instead of racing it.
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
 *                                  (R5-PERF-01: digest-declared STREAMING upload - the
 *                                  body is streamed to a unique staging attempt while
 *                                  hashed, verified against the capability's declared
 *                                  digest+length, then promoted to the content-addressed
 *                                  key with a create-only conditional put; nothing is
 *                                  buffered in the isolate)
 *   POST /session/register         {databaseId, generation, startupSessionId}
 *   POST /session/fence            {databaseId, generation, startupSessionId}
 *   POST /budgets                  {databaseId, maxUnpublishedOutbox, maxPayloadLength, maxTailRecords}
 *   POST /wal/finalize             FinalizeRequest → FinalizeResult (verifies R2 object + digest first)
 *   POST /wal/finalize-batch       {requests: FinalizeRequest[]} → all-or-nothing FinalizeResult[]
 *   GET  /wal/{db}/{generation}/{lsn}  exact lookup; returns record metadata + payload bytes (base64).
 *                                  R5-PERF-01: with `accept: application/octet-stream` the
 *                                  payload STREAMS as the response body with a
 *                                  content-digest header instead; the base64 JSON shape
 *                                  remains the default and is byte-identical to before.
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

import { MAX_BATCH_BYTES, MAX_BATCH_MEMBERS, u64FromWire, type FinalizeRequest,
         type ReadLeaseGrant, type ReadOutcome, type ReadRequest } from "./core/procedures.ts";
import { devOnlyRoute } from "./surface.ts";
import { canonicalJson } from "./core/journal-crypto.ts";
import { verifyCapabilityToken, type CapabilityPayload } from "./core/capability.ts";
import type { CapabilityEffect } from "./core/procedures.ts";

/**
 * R6-CTRL-01: THE MUTATION ROUTE TABLE.
 *
 * Every mutating HTTP route names itself here and `withMutation` takes that
 * name together with a mandatory `CapabilityEffect`. Two things follow, and
 * both are the point:
 *
 *  - a new mutation cannot COMPILE without an explicit ambiguity policy —
 *    there is no default effect to fall into, and no unnamed route;
 *  - the route -> effect binding is machine-readable from this source, so
 *    the coverage matrix is a TEST (core/route-effects.test.ts) rather than
 *    a paragraph that drifts.
 *
 * The round-5 code had neither: `withMutation`'s fifth parameter defaulted
 * to `{kind:"IDEMPOTENT_REEXECUTE"}`, so `/wal/finalize-batch`, checkpoint
 * open and checkpoint activation stored a convergence claim instead of the
 * authoritative effect that was already implemented for them, and seven
 * lifecycle/outbox routes claimed a convergence they never had.
 */
export const MUTATION_ROUTES = {
  INCARNATION_BUMP: "POST /admin/:databaseId/incarnation/bump",
  PAYLOAD_PUT: "PUT /payload/:key",
  SESSION_REGISTER: "POST /session/register",
  SESSION_RESERVE: "POST /session/reserve",
  SESSION_ATTEST: "POST /session/attest",
  SESSION_ACTIVATE: "POST /session/activate",
  SESSION_RENEW: "POST /session/renew",
  SESSION_DRAIN: "POST /session/drain",
  SESSION_REVOKE: "POST /session/revoke",
  SESSION_FENCE: "POST /session/fence",
  BUDGETS_SET: "POST /budgets",
  WAL_FINALIZE: "POST /wal/finalize",
  WAL_FINALIZE_BATCH: "POST /wal/finalize-batch",
  OUTBOX_ACK: "POST /outbox/:databaseId/ack",
  CHECKPOINT_OPEN: "POST /checkpoint/:databaseId/:generation/cut",
  CHECKPOINT_ACTIVATE: "POST /checkpoint/:databaseId/cut/:cutId/activate",
} as const;
export type MutationRouteId = keyof typeof MUTATION_ROUTES;
import { resolveKeyConfig, type ResolvedKeys } from "./core/key-config.ts";
import { checkBinding, verifyProvisionToken, controllerDoName, type ProvisionBinding } from "./core/registry.ts";

export interface Env {
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
 * R5-PERF-01: DIGEST-DECLARED STREAMING UPLOAD, stage half.
 *
 * The request body is streamed straight into R2 under a globally unique
 * STAGING key while an incremental SHA-256 is folded over the same chunks.
 * Nothing is retained: the isolate holds one chunk at a time, never the
 * whole object plus a contiguous copy of it (the previous reader hashed
 * incrementally but kept every chunk and concatenated them, so an 8 MiB
 * upload materialised 8 MiB — and six concurrent ones, 48 MiB — inside a
 * 128 MiB isolate).
 *
 * PLATFORM CONSTRAINT, stated exactly: `R2Bucket.put` refuses a stream of
 * unknown length ("Provided readable stream must have a known length
 * (request/response body or readable half of FixedLengthStream)"). The
 * declared `content-length` — already mandatory on this route — therefore
 * becomes the length of a `FixedLengthStream`, which ALSO makes the
 * platform enforce the declaration: a body that delivers fewer bytes than
 * it declared ends the fixed-length pipe prematurely and a body that
 * delivers more is refused mid-write. A reported-size lie cannot be staged,
 * in either direction.
 *
 * The digest is NOT trusted from the caller either: it is recomputed here
 * and compared against the digest the CAPABILITY bound (which is also the
 * content-addressed key), by the promote half below.
 */
async function stageStreamedObject(
  env: Env, body: ReadableStream<Uint8Array>, stagingKey: string, declaredLength: number,
): Promise<{ ok: true; digest: string } | { ok: false; refusal: { status: number; body: unknown } }> {
  const digestStream = new crypto.DigestStream("SHA-256");
  const hash = digestStream.getWriter();
  const fixed = new FixedLengthStream(declaredLength);
  let total = 0;
  const pump = (async () => {
    const reader = body.getReader();
    // a client that disconnects rejects the reader's `closed` promise as
    // well as the pending read; both must be OBSERVED or the runtime
    // reports an unhandled rejection long after the request was refused
    reader.closed.catch(() => {});
    const sink = fixed.writable.getWriter();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        // the declared length is the cap: refuse the instant it is crossed,
        // before the extra bytes are handed to the provider
        if (total > declaredLength) throw new Error("DECLARED_LENGTH_EXCEEDED");
        await hash.write(value);
        await sink.write(value);
      }
      await hash.close();
      await sink.close();
    } catch (error) {
      digestStream.digest.catch(() => {}); // observe the aborted digest
      await sink.abort(error).catch(() => {});
      await hash.abort(error).catch(() => {});
      throw error;
    } finally {
      reader.releaseLock();
    }
  })();
  // both halves are always settled, so a failing pump can never surface as
  // an unhandled rejection while the put is still in flight. The explicit
  // `.catch` on each is belt-and-braces: allSettled only observes them once
  // BOTH have settled, and a client that disconnects rejects one of them
  // strictly before the other.
  pump.catch(() => {});
  const staging = env.PAYLOADS.put(stagingKey, fixed.readable);
  staging.catch(() => {});
  const [put, pumped] = await Promise.allSettled([staging, pump]);
  if (pumped.status === "rejected" || put.status === "rejected" || put.value === null) {
    if (total !== declaredLength) {
      // a caller whose body contradicts its own declaration: typed, terminal
      return { ok: false, refusal: { status: 400, body: {
        ok: false, error: "REQUEST_BODY_LENGTH_MISMATCH", declared: declaredLength, observed: total } } };
    }
    // genuine provider/transport failure: THROW so the wrapping mutation
    // records AMBIGUOUS (retryable), never a burned terminal rejection
    throw new Error("PAYLOAD_STAGING_FAILED");
  }
  return { ok: true, digest: hexOf(await digestStream.digest) };
}

/**
 * R5-PERF-01: DIGEST-DECLARED STREAMING UPLOAD, promote half — the same
 * stage/verify/create-only-promote shape the Rust side uses for multipart
 * completion (fork/typedb/storage/keyspace/slate.rs `JournaledMultipart`):
 * a unique attempt key nobody else can contend for, verification of the
 * staged bytes against the streamed accounting, then an ATOMIC create-only
 * publish to the target name, with an occupied target settled by content
 * comparison rather than by overwriting.
 *
 * Publishing directly to the content-addressed key and deleting on mismatch
 * was rejected: between the publish and the delete, a concurrent reader
 * would observe bytes that do not hash to the key they are stored under —
 * which is precisely the invariant the content-addressed scheme exists to
 * guarantee. Staging costs one extra R2 round trip per upload and keeps the
 * invariant absolute.
 */
async function promoteStagedObject(
  env: Env, stagingKey: string, key: string, digest: string, length: number,
  /** R6-CTRL-02 ATTEMPT IDENTITY. True when the capability nonce that
   *  authorizes this publication has already been claimed once — i.e. this
   *  is a retry of an upload that may itself have published the object. A
   *  create-only collision is then OUR OWN prior attempt, not somebody
   *  else's upload, so the answer is the first attempt's answer and NOT
   *  `deduplicated: true`. Without this the same nonce produced two
   *  different canonical bodies for one physical effect. */
  priorAttempt: boolean,
): Promise<{ status: number; body: unknown }> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const staged = await env.PAYLOADS.get(stagingKey);
    if (staged === null) throw new Error("PAYLOAD_STAGING_LOST");
    // atomic create-only publish: two concurrent uploads of different bytes
    // can never both win a key, and an identical re-upload never overwrites
    const created = await env.PAYLOADS.put(key, staged.body, {
      onlyIf: new Headers({ "if-none-match": "*" }),
    });
    if (created !== null) return { status: 200, body: { key, sha256hex: digest, length } };
    // occupied: settle by content, streaming (retain: false) so the dedup
    // check never materialises the existing object either
    const existing = await fetchVerified(env, key, digest, undefined, false);
    if ("bytes" in existing) {
      return priorAttempt
        ? { status: 200, body: { key, sha256hex: digest, length } }
        : { status: 200, body: { key, sha256hex: digest, length, deduplicated: true } };
    }
    if (existing.error === "MISSING") continue; // lost a delete/create race; retry
    if (existing.error === "OVER_CAP") {
      return { status: 413, body: { ok: false, error: "PAYLOAD_EXCEEDS_OBJECT_CAP",
                                    key, size: existing.size, cap: existing.cap } };
    }
    return { status: 409, body: { ok: false, error: "PAYLOAD_IMMUTABILITY_VIOLATION",
                                  key, existing: existing.observed } };
  }
  // exhausted the race retries: surface as retryable, not a burned success -
  // the wrapping mutation marks a thrown error AMBIGUOUS
  throw new Error("PAYLOAD_RACE_UNRESOLVED");
}

/** One streamed upload, end to end (R5-PERF-01): stage under a unique
 *  attempt key, verify the streamed digest against the DECLARED one (which
 *  the capability bound and the content-addressed key encodes), then
 *  promote create-only. The staging object is reclaimed on every path. */
export async function streamedPayloadPut(
  env: Env, body: ReadableStream<Uint8Array>, databaseId: string, key: string,
  declaredDigest: string, declaredLength: number,
  /** see promoteStagedObject: false for a first claim of the authorizing
   *  nonce, true for a retry of one that was already claimed. */
  priorAttempt = false,
): Promise<{ status: number; body: unknown }> {
  // a top-level prefix the payload route can never address (its keys must
  // be `p/<db>/<sha256hex>`), so a staging object is unreachable through
  // the capability boundary and cannot be mistaken for a published payload
  const stagingKey = `s/${databaseId}/${crypto.randomUUID()}`;
  try {
    const staged = await stageStreamedObject(env, body, stagingKey, declaredLength);
    if (!staged.ok) return staged.refusal;
    if (staged.digest !== declaredDigest) {
      // the bytes are not what the capability authorized; nothing was ever
      // published under the content-addressed name
      return { status: 422, body: { ok: false, error: "PAYLOAD_DIGEST_MISMATCH",
                                    key, declared: declaredDigest, observed: staged.digest } };
    }
    return await promoteStagedObject(env, stagingKey, key, declaredDigest, declaredLength, priorAttempt);
  } finally {
    await env.PAYLOADS.delete(stagingKey).catch(() => {});
  }
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
  /** R5-PERF-01: retain the chunks (a caller that must return the bytes) or
   *  discard them as they are hashed (a caller that only needs the verdict:
   *  finalize receipt verification, upload dedup). Discarding is the memory
   *  difference between "verify an 8 MiB object" and "hold an 8 MiB
   *  object". */
  retain = true,
): Promise<
  { bytes: Uint8Array; total: number; digest: string }
  | { overCap: true; total: number }
  /** the stream itself failed mid-read (a client that disconnected, a
   *  truncated fixed-length body, a provider fault). Returned rather than
   *  thrown so each caller decides: an INBOUND request body error is a
   *  client fact and gets a typed refusal; an R2 body error is an
   *  infrastructure fact and is rethrown as retryable. */
  | { streamError: true; total: number; reason: string }
> {
  const digestStream = new crypto.DigestStream("SHA-256");
  const writer = digestStream.getWriter();
  const reader = stream.getReader();
  reader.closed.catch(() => {}); // see stageStreamedObject
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      let step: ReadableStreamReadResult<Uint8Array>;
      try {
        step = await reader.read();
      } catch (error) {
        digestStream.digest.catch(() => {});
        await writer.abort().catch(() => {});
        return { streamError: true, total, reason: error instanceof Error ? error.message : String(error) };
      }
      const { done, value } = step;
      if (done) break;
      total += value.byteLength;
      if (total > cap) {
        // the aborted digest promise must be observed, or the abort surfaces
        // as an unhandled rejection long after the request was refused
        digestStream.digest.catch(() => {});
        await writer.abort().catch(() => {});
        await reader.cancel().catch(() => {});
        return { overCap: true, total };
      }
      await writer.write(value);
      if (retain) chunks.push(value);
    }
    await writer.close();
  } finally {
    reader.releaseLock();
  }
  return {
    bytes: retain ? concatChunks(chunks, total) : EMPTY_BYTES,
    total,
    digest: hexOf(await digestStream.digest),
  };
}

/** The stand-in for "no bytes were retained" (see streamCappedDigest). */
const EMPTY_BYTES = new Uint8Array(0);

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
  /** R5-PERF-01: retain the verified bytes, or verify and discard. Only the
   *  legacy base64 read shape needs the bytes; receipt verification and
   *  upload dedup need only the verdict. */
  retain = true,
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
  // cap is re-checked per chunk in case the reported size lied. R5-PERF-01:
  // `retain` decides whether the bytes are kept. Only the LEGACY base64 read
  // shape keeps them, and it keeps them because its wire contract embeds
  // them inline - that shape's buffering is a compatibility obligation, and
  // the non-buffering path for the same record is the negotiated streaming
  // variant (`accept: application/octet-stream`). Receipt verification and
  // upload dedup pass retain=false and hold nothing.
  const result = await streamCappedDigest(object.body, MAX_PAYLOAD_OBJECT_BYTES, retain);
  if ("overCap" in result) {
    return { error: "OVER_CAP", size: result.total, cap: MAX_PAYLOAD_OBJECT_BYTES };
  }
  if ("streamError" in result) {
    // a stored object whose body cannot be read through is an infrastructure
    // fault, not a caller error: throw so the wrapping mutation records it
    // AMBIGUOUS (retryable) rather than burning a terminal rejection
    throw new Error(`PAYLOAD_STREAM_FAILED: ${key}: ${result.reason}`);
  }
  const observed = result.digest;
  if (observed !== expectedDigest || (expectedLength !== undefined && result.total !== expectedLength)) {
    return { error: "MISMATCH", observed, length: result.total };
  }
  return { bytes: result.bytes };
}

/** R5-PERF-01: the media type that selects the STREAMING read variant.
 *  Content negotiation, not a new route: the default (no `accept`, or any
 *  other accept value) is the historical base64-in-JSON shape, which every
 *  current consumer — the Rust WAL client, both e2e lanes — keeps reading
 *  byte for byte unchanged. */
const PAYLOAD_STREAM_MEDIA_TYPE = "application/octet-stream";

/** True when the caller EXPLICITLY asked for the streaming variant. A
 *  wildcard accept value does NOT select it: negotiation must never flip
 *  an existing consumer onto a different response shape by accident. */
function wantsPayloadStream(request: Request): boolean {
  const accept = request.headers.get("accept");
  if (accept === null) return false;
  return accept.split(",").some((part) => part.trim().split(";")[0].toLowerCase() === PAYLOAD_STREAM_MEDIA_TYPE);
}

/**
 * A TransformStream that passes bytes through while folding them into an
 * incremental SHA-256 and enforcing a byte cap (R5-PERF-01).
 *
 * DOCUMENTED LIMITATION, stated plainly: on a STREAMING response the
 * integrity verdict is only knowable after the last byte, so it cannot
 * gate the first. This transform therefore ERRORS the response body when
 * the digest (or the length) does not match, which aborts the HTTP
 * response mid-transfer: a conforming consumer sees a truncated,
 * failed transfer and MUST NOT treat the bytes as a complete record. It
 * does not — and cannot — prevent a consumer from having already observed
 * earlier bytes. That is exactly why the streaming variant is opt-in and
 * the DEFAULT read path stays verify-then-serve: the buffered path refuses
 * before a single byte is emitted, and it remains what unmodified
 * consumers get.
 */
function digestVerifyingPassthrough(
  expectedDigest: string, expectedLength: number, cap: number,
): TransformStream<Uint8Array, Uint8Array> {
  const digestStream = new crypto.DigestStream("SHA-256");
  const writer = digestStream.getWriter();
  let total = 0;
  return new TransformStream<Uint8Array, Uint8Array>({
    async transform(chunk, controller) {
      total += chunk.byteLength;
      if (total > cap) {
        digestStream.digest.catch(() => {}); // observe the aborted digest
        await writer.abort(new Error("PAYLOAD_EXCEEDS_OBJECT_CAP")).catch(() => {});
        controller.error(new Error("PAYLOAD_EXCEEDS_OBJECT_CAP"));
        return;
      }
      await writer.write(chunk);
      controller.enqueue(chunk);
    },
    async flush(controller) {
      await writer.close();
      const observed = hexOf(await digestStream.digest);
      if (observed !== expectedDigest || total !== expectedLength) {
        controller.error(new Error("PAYLOAD_INTEGRITY_VIOLATION"));
      }
    },
  });
}

/**
 * R5-PERF-01 streaming read: the R2 object body becomes the RESPONSE body.
 * No `arrayBuffer()`, no base64 expansion, no JSON envelope — the isolate
 * holds one stream chunk at a time instead of the whole payload plus its
 * ~1.33x base64 copy.
 *
 * The lease is redeemed BEFORE the response is handed back (the
 * authoritative cut point, R5-SEC-05); the catalogued digest travels in
 * `content-digest` (RFC 9530) and `x-payload-sha256` so a consumer can
 * verify independently of the in-band abort described above.
 */
async function streamedPayloadResponse(
  env: Env,
  record: { payloadKey: string; payloadDigest: string; payloadLength: number;
            typeSequence: bigint; recordType: number },
  meta: { appendLsn: bigint },
  redeem: (keys: string[]) => Promise<Response | null>,
): Promise<Response> {
  const object = await env.PAYLOADS.get(record.payloadKey);
  if (object === null) {
    return json({ ok: false, error: "PAYLOAD_MISSING_FOR_CATALOGUED_RECORD", record }, 500);
  }
  // size checks BEFORE any body is read (C-06), against BOTH the hard
  // per-object ceiling and the catalogued length: a stored object whose size
  // contradicts the catalogue is an integrity error, not a short read
  if (object.size > MAX_PAYLOAD_OBJECT_BYTES) {
    await object.body.cancel().catch(() => {});
    return json({ ok: false, error: "PAYLOAD_EXCEEDS_OBJECT_CAP", record,
                  size: object.size, cap: MAX_PAYLOAD_OBJECT_BYTES }, 413);
  }
  if (object.size !== record.payloadLength) {
    await object.body.cancel().catch(() => {});
    return json({ ok: false, error: "PAYLOAD_INTEGRITY_VIOLATION", record, observed: object.size }, 500);
  }
  const revoked = await redeem([record.payloadKey]);
  if (revoked !== null) {
    await object.body.cancel().catch(() => {});
    return revoked;
  }
  const verified = object.body.pipeThrough(
    digestVerifyingPassthrough(record.payloadDigest, record.payloadLength, MAX_PAYLOAD_OBJECT_BYTES));
  return new Response(verified, {
    status: 200,
    headers: {
      "content-type": PAYLOAD_STREAM_MEDIA_TYPE,
      "content-length": String(record.payloadLength),
      // RFC 9530 Content-Digest over the CATALOGUED digest
      "content-digest": `sha-256=:${base64Of(hexToBytes(record.payloadDigest))}:`,
      "x-payload-sha256": record.payloadDigest,
      "x-payload-length": String(record.payloadLength),
      "x-append-lsn": meta.appendLsn.toString(),
      "x-type-sequence": record.typeSequence.toString(),
      "x-record-type": String(record.recordType),
    },
  });
}

/** 64 lowercase hex chars -> the 32 raw bytes they encode. */
function hexToBytes(hexText: string): Uint8Array {
  const bytes = new Uint8Array(hexText.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hexText.slice(i * 2, i * 2 + 2), 16);
  return bytes;
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
 *  headroom for the base64 expansion and JSON envelope.
 *
 *  R5-PERF-01, stated exactly: the SCAN page is the one read shape that
 *  still buffers. Its wire contract is an array of records with inline
 *  base64 payloads, so streaming it would be a different protocol, not a
 *  different encoding — and the compatibility constraint on this pass is
 *  that current consumers keep their shape. The bound is therefore a
 *  DOCUMENTED THRESHOLD rather than a stream: the authority cuts the page
 *  to this budget BEFORE any payload is fetched, so the ceiling is enforced
 *  by the catalogue rather than discovered by running out of memory. A
 *  consumer that wants unbuffered bytes reads records individually through
 *  the negotiated streaming exact-read route. */
const SCAN_PAGE_BYTE_BUDGET = 8 * 1024 * 1024;

/** C-P1-01: structural JSON bodies (session admin, finalize metadata, acks)
 *  are small by construction; 256 KiB is generous headroom, and anything
 *  larger is a malformed client or an attack, refused before parsing. */
const MAX_STRUCTURAL_BODY_BYTES = 256 * 1024;

/** R5-PERF-02: structural nesting bound for JSON bodies. Every body this
 *  surface accepts is a flat-ish record (session admin, finalize metadata,
 *  acks, a batch of finalize records, a restore-evidence manifest); the
 *  deepest legitimate shape is a manifest's nested arrays of objects, well
 *  under ten. 32 is generous headroom and still far below the recursion
 *  depth at which `JSON.parse` would blow the stack, so a nesting bomb is a
 *  TYPED refusal computed by a flat scan rather than a RangeError thrown
 *  from inside the parser. */
const MAX_JSON_DEPTH = 32;

/** Strict UTF-8: `fatal` makes an invalid or truncated multibyte sequence
 *  THROW instead of silently becoming U+FFFD. A body that is not valid
 *  UTF-8 is not a JSON document, and replacing its bad bytes would let two
 *  different byte strings normalise to one accepted request. */
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

/** Maximum structural nesting depth of a JSON text, computed by one linear
 *  scan that tracks string/escape state. Runs BEFORE `JSON.parse`, so a
 *  nesting bomb never builds a single object. */
function jsonNestingDepth(text: string): number {
  let depth = 0;
  let deepest = 0;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (c === "\\") escaped = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') inString = true;
    else if (c === "{" || c === "[") {
      depth += 1;
      if (depth > deepest) deepest = depth;
    } else if (c === "}" || c === "]") depth -= 1;
  }
  return deepest;
}

/** The part of a `Request` a body reader actually uses. Narrowing to this
 *  is what makes the reader directly exercisable against hand-built
 *  streams and hand-set headers (an under-declared `content-length` cannot
 *  be produced through `fetch`, which recomputes it), so the mutants below
 *  test the SHIPPED code path rather than a copy of it. */
export interface BodyBearingRequest {
  headers: Headers;
  body: ReadableStream<Uint8Array> | null;
}

/**
 * Bounded, fail-closed JSON body read (C-P1-01, R5-PERF-02).
 *
 * The previous implementation checked `content-length` and then called
 * `request.json()`. That made the cap a property of a CLIENT-SUPPLIED
 * HEADER: a chunked body (no length at all, which this surface refuses) or,
 * more dangerously, a body that under-declares its length on a transport
 * that does not police the two against each other, could materialise past
 * the cap inside the isolate before anything refused it. The bound is now
 * on ACTUAL BYTES:
 *
 *   1. the declared length is still required and still pre-refused when it
 *      exceeds the cap - that refusal costs nothing and rejects the honest
 *      oversized client before a byte is read;
 *   2. the body is then read through the same per-chunk capped streaming
 *      reader the payload path uses, which aborts the stream the instant
 *      the cumulative count crosses the cap - never trusting the header;
 *   3. actual bytes must EQUAL the declared length: an under-declared or
 *      over-declared body is a typed refusal, not a silent acceptance;
 *   4. the bytes are decoded as STRICT UTF-8 (invalid sequences refuse
 *      rather than becoming U+FFFD);
 *   5. the text is depth-bounded by a flat scan BEFORE `JSON.parse` runs.
 */
export async function readJson(request: BodyBearingRequest, limit = MAX_STRUCTURAL_BODY_BYTES):
  Promise<{ body: Record<string, unknown> } | { errorResponse: Response }> {
  // a refusal releases the unread body stream cleanly rather than leaving
  // the sender's pipe to be torn down by the runtime
  const discardBody = async (): Promise<void> => { await request.body?.cancel().catch(() => {}); };
  const declared = request.headers.get("content-length");
  if (declared === null || !/^\d+$/.test(declared)) {
    await discardBody();
    return { errorResponse: json({ ok: false, error: "CONTENT_LENGTH_REQUIRED", limit }, 411) };
  }
  const declaredLength = Number(declared);
  if (!Number.isSafeInteger(declaredLength) || declaredLength > limit) {
    await discardBody();
    return { errorResponse: json({ ok: false, error: "REQUEST_BODY_TOO_LARGE", declared, limit }, 413) };
  }
  if (request.body === null) {
    return { errorResponse: json({ ok: false, error: "CONTENT_LENGTH_REQUIRED", limit }, 411) };
  }
  // authoritative bound: actual bytes, enforced per chunk. (The digest this
  // shares with the payload reader is unused here - one capped reader is
  // worth more than a second near-copy of the cap logic.)
  const read = await streamCappedDigest(request.body, limit);
  if ("overCap" in read) {
    return { errorResponse: json({ ok: false, error: "REQUEST_BODY_TOO_LARGE",
                                   observed: read.total, limit }, 413) };
  }
  if ("streamError" in read) {
    // the caller's body ended early or the connection dropped: a typed
    // refusal, never an exception escaping the route
    return { errorResponse: json({ ok: false, error: "REQUEST_BODY_INCOMPLETE",
                                   declared: declaredLength, observed: read.total }, 400) };
  }
  if (read.total !== declaredLength) {
    return { errorResponse: json({ ok: false, error: "CONTENT_LENGTH_MISMATCH",
                                   declared: declaredLength, observed: read.total }, 400) };
  }
  let text: string;
  try {
    text = STRICT_UTF8.decode(read.bytes);
  } catch {
    return { errorResponse: json({ ok: false, error: "MALFORMED_UTF8" }, 400) };
  }
  if (jsonNestingDepth(text) > MAX_JSON_DEPTH) {
    return { errorResponse: json({ ok: false, error: "JSON_TOO_DEEP", limit: MAX_JSON_DEPTH }, 400) };
  }
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return { errorResponse: json({ ok: false, error: "MALFORMED_JSON" }, 400) };
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return { errorResponse: json({ ok: false, error: "MALFORMED_JSON", hint: "object body required" }, 400) };
  }
  return { body: body as Record<string, unknown> };
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
    const verifyCapability = async (
      databaseId: string, expect: CapExpect, useDigest: string,
      // R5-SEC-04/R6-CTRL-01: bound with the claim so an unresolved use is
      // settleable. MANDATORY — there is no generic default to inherit.
      effect: CapabilityEffect,
    ) => {
      const framed = await frameCheck(databaseId, expect);
      if ("denied" in framed) return { authorized: false as const, denied: framed.denied };
      // the DO call carries the full expected binding (tenant from the
      // verified token), so the authority can verify it was addressed as
      // the database it is provisioned to be (R4 PR1)
      const verdict = await stubFor(databaseId).useCapability(
        framed.token, { databaseId, tenantId: framed.payload.tenantId, ...expect }, useDigest, effect);
      if (!verdict.ok) return { authorized: false as const, denied: json(verdict, 403) };
      return { authorized: true as const, verdict };
    };

    /** C-02 terminal replay: when a claim is a non-fresh, terminal use, the
     *  stored response is returned verbatim and the route body NEVER runs.
     *  A non-fresh, non-terminal use (a crash between effect and resolve)
     *  is a bounded typed retry, never a blind re-execution. Returns a
     *  Response to short-circuit with, or null to proceed and execute. */
    const replayTerminal = async (
      databaseId: string,
      verdict: { claim?: { fresh: boolean; terminal: boolean; response: string | null } },
      nonce?: string,
    ): Promise<Response | null> => {
      const claim = verdict.claim;
      if (claim === undefined || claim.fresh) return null;
      if (claim.terminal && claim.response !== null) {
        const stored = JSON.parse(claim.response) as { status: number; body: unknown };
        return json(stored.body, stored.status);
      }
      if (claim.terminal) return json({ ok: true, replayed: true }, 200);
      // R5-SEC-04: an UNRESOLVED prior use no longer answers a permanent
      // 409. The authority re-derives the outcome from the effect the use
      // was bound to at claim time:
      //   SETTLED     -> replay the exact original outcome (the timeout
      //                  happened AFTER the effect);
      //   RE_EXECUTE  -> no effect exists (timeout BEFORE it, or the
      //                  procedure is idempotent by identity): fall
      //                  through and execute the identical request again;
      //   QUARANTINED -> durable evidence contradicts the recorded
      //                  operation: fail closed, terminally;
      //   otherwise   -> the bounded legacy 409 (pre-effect rows), which
      //                  token expiry prunes.
      const claimNonce = nonce ?? (verdict as { payload?: { nonce?: string } }).payload?.nonce;
      if (typeof claimNonce !== "string") {
        return json({ ok: false, error: "CAPABILITY_IN_FLIGHT",
                      hint: "a prior use of this token has not resolved; retry" }, 409);
      }
      const settled = await stubFor(databaseId).resolveAmbiguousUse(claimNonce);
      if (settled.ok && settled.disposition === "SETTLED") {
        if (settled.response === null) return json({ ok: true, replayed: true }, 200);
        const stored = JSON.parse(settled.response) as { status: number; body: unknown };
        return json(stored.body, stored.status);
      }
      if (settled.ok && settled.disposition === "RE_EXECUTE") return null;
      if (!settled.ok && settled.error === "CAPABILITY_USE_QUARANTINED") {
        return json({ ok: false, error: "CAPABILITY_USE_QUARANTINED", reason: settled.reason }, 409);
      }
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

    /** What a mutation route body is handed (R6-CTRL-02): the verified
     *  capability restrictions, the OPERATION IDENTITY of this one
     *  authorized use (the token nonce, which the DO records receipts
     *  under), and whether this claim is the first one for that identity. */
    type MutationContext = {
      session?: string;
      generation?: string;
      /** the token nonce: the operation identity every durable receipt for
       *  this mutation is keyed by */
      operationId: string;
      /** false when a previous claim of the same nonce already ran: a route
       *  whose physical effect is remote (the R2 publication) uses it to
       *  tell "somebody else already published this content" from "I
       *  already published it and lost the answer". */
      firstAttempt: boolean;
    };

    /**
     * A mutating route in one wrapper (C-02, R5-SEC-04, R6-CTRL-01/02):
     * frame-check + claim, replay a terminal use, else execute and resolve.
     *
     * Every field is REQUIRED, and that is the finding's fix. `route` names
     * the mutation in MUTATION_ROUTES so the coverage matrix can be a test;
     * `effect` is the AUTHORITATIVE EFFECT this use is bound to, recorded
     * durably with the claim so a use left unresolved by a lost response is
     * settled later by querying the effect instead of wedging at 409
     * forever. There is no default: a new mutation does not compile until
     * its author states what a lost response to it means.
     */
    const withMutation = async (spec: {
      route: MutationRouteId;
      databaseId: string;
      expect: CapExpect;
      useDigest: string;
      effect: CapabilityEffect;
      execute: (context: MutationContext) => Promise<{ status: number; body: unknown }>;
    }): Promise<Response> => {
      const { route, databaseId, expect, useDigest, effect, execute } = spec;
      const auth = await verifyCapability(databaseId, expect, useDigest, effect);
      if (!auth.authorized) return auth.denied;
      const claim = auth.verdict.claim;
      const replay = await replayTerminal(databaseId, auth.verdict);
      if (replay !== null) return replay;
      const nonce = auth.verdict.payload?.nonce;
      if (typeof nonce !== "string" || nonce.length === 0) {
        // a verified payload always carries a nonce (capability.ts refuses
        // one that does not); failing closed here keeps the receipt/resolve
        // path from being silently skipped if that ever stops being true
        return json({ ok: false, error: "CAPABILITY_MALFORMED", field: "nonce" }, 403);
      }
      try {
        const result = await execute({
          ...auth.verdict.payload, operationId: nonce,
          // an absent claim means the authority did not run the use machine
          // at all; treat that as a first attempt, which is what it is
          firstAttempt: claim === undefined || claim.fresh,
        });
        const ok = result.status >= 200 && result.status < 300;
        await resolveUse(databaseId, nonce, ok, result.status, result.body);
        return json(result.body, result.status);
      } catch (error) {
        // C-02: infrastructure/transport uncertainty is recorded AMBIGUOUS
        // and stays retryable - never silently converted into a burned token
        await stubFor(databaseId).resolveCapabilityUse(nonce, "AMBIGUOUS",
          JSON.stringify({ route, error: error instanceof Error ? error.message : String(error) }));
        throw error;
      }
    };

    /** Bind a mutating use to the request line (method + path + query) when the
     *  route carries no body of its own (e.g. INCARNATION_BUMP). Read routes claim
     *  no use (C-07) and do not call this. */
    const routeUseDigest = () =>
      useDigestOf({ method: request.method, path, search: url.search });

    /** R5-SEC-05, session-independent reads (OUTBOX consumers and the
     *  JOURNAL_VERIFY recovery/forensics role, neither of which carries a
     *  startup session). Same rule as the WAL_READ path: frame-check at the
     *  worker, then ONE authoritative hop that verifies and reads — never a
     *  check followed by a separate read. No durable use is claimed (C-07). */
    type ControlRead =
      | { kind: "OUTBOX_PEEK"; limit: number }
      | { kind: "JOURNAL_VERIFY" }
      | { kind: "JOURNAL_VERIFY_ANCHORED" };
    type ControlOutcome =
      | { ok: true; kind: "OUTBOX_PEEK"; events: { controlSeq: bigint; kind: string; body: string }[] }
      | { ok: true; kind: "JOURNAL_VERIFY"; verified: boolean; verdict: Record<string, unknown> }
      | { ok: true; kind: "JOURNAL_VERIFY_ANCHORED"; verified: boolean; verdict: Record<string, unknown> };
    const authorizedControlRead = async <R extends ControlRead>(
      databaseId: string, expect: CapExpect, read: R,
    ): Promise<{ outcome: Extract<ControlOutcome, { kind: R["kind"] }> } | { denied: Response }> => {
      const framed = await frameCheck(databaseId, expect);
      if ("denied" in framed) return { denied: framed.denied };
      const outcome = await stubFor(databaseId).authorizedControlRead(
        framed.token, { databaseId, tenantId: framed.payload.tenantId, ...expect }, read);
      if (!outcome.ok) return { denied: json(outcome, readRefusalStatus(outcome.error)) };
      return { outcome: outcome as unknown as Extract<ControlOutcome, { kind: R["kind"] }> };
    };

    /**
     * R5-SEC-05: map an authoritative read refusal to its protocol status.
     * SESSION_* and READ_LEASE_* are both 409 CONFLICT: the caller is not
     * (or is no longer) the actor entitled to this read.
     */
    const readRefusalStatus = (error: string): number => {
      if (error === "NOT_FOUND") return 404;
      if (error === "RECORD_EXCEEDS_PAGE_BUDGET") return 413;
      if (error === "INVALID_SNAPSHOT_ID" || error === "CONTINUATION_OUTSIDE_SNAPSHOT"
          || error === "CAPABILITY_MALFORMED") return 400;
      if (error.startsWith("CAPABILITY_") || error === "DATABASE_UNPROVISIONED"
          || error === "DO_BINDING_MISMATCH") return 403;
      return 409;
    };

    /**
     * R5-SEC-05: THE session-bound read path — one authoritative hop.
     *
     * The worker still frame-checks the token statelessly (a junk or forged
     * token must not reach a Durable Object at all, audit C-03), and then
     * makes exactly ONE call in which the authority verifies the token
     * again, revalidates that the bound actor still holds live read
     * authority, and performs the catalogue read — with no await between
     * the check and the read. Reads that carry payload bytes come back with
     * a durable one-shot LEASE over the exact object keys the worker will
     * fetch; `redeemRead` below is the second half.
     */
    const authorizedRead = async <R extends ReadRequest>(
      databaseId: string, expect: CapExpect, read: R,
      /** per-error extra wire fields (client remedies), by error name */
      hints: Record<string, Record<string, unknown>> = {},
    ): Promise<{ outcome: Extract<ReadOutcome, { ok: true; kind: R["kind"] }> } | { denied: Response }> => {
      const framed = await frameCheck(databaseId, expect);
      if ("denied" in framed) return { denied: framed.denied };
      const outcome = await stubFor(databaseId).authorizedRead(
        framed.token, { databaseId, tenantId: framed.payload.tenantId, ...expect }, read);
      if (!outcome.ok) {
        const extra = hints[outcome.error];
        return { denied: json(extra === undefined ? outcome : { ...outcome, ...extra },
                              readRefusalStatus(outcome.error)) };
      }
      // the RPC return type is the outcome union intersected with the
      // platform's Disposable stub wrapper; the kind was fixed by the
      // request, so narrow it explicitly here rather than at every call site
      return { outcome: outcome as unknown as Extract<ReadOutcome, { ok: true; kind: R["kind"] }> };
    };

    /**
     * R5-SEC-05: redeem the one-shot read lease AFTER the payload bytes have
     * been fetched and BEFORE they are served. The authority re-checks, at
     * this instant, that the lease still exists (a fence deletes it in the
     * fence's own transaction), is unexpired, unconsumed, covers exactly the
     * keys fetched, and that its actor is still a live reader. Returns null
     * when the read may be served, otherwise the typed refusal — the bytes
     * already in hand are DISCARDED, never served.
     */
    const redeemRead = async (
      databaseId: string, lease: ReadLeaseGrant, keys: string[],
    ): Promise<Response | null> => {
      const redeemed = await stubFor(databaseId).redeemReadLease(lease.leaseId, keys);
      if (redeemed.ok) return null;
      return json(redeemed, readRefusalStatus(redeemed.error));
    };

    /** Exact generation or the typed 400 (donor A5): the one refusal every
     *  generation-bearing route answers identically. */
    const generationOr = (raw: unknown): number | Response => {
      const gen = exactGeneration(raw);
      return gen === null
        ? json({ ok: false, error: "INVALID_GENERATION", observed: raw ?? null }, 400)
        : gen;
    };

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
      return withMutation({
        route: "INCARNATION_BUMP",
        databaseId: adminBump[1],
        expect: { method: "INCARNATION_BUMP" },
        useDigest: await routeUseDigest(),
        // R5-SEC-04: a bump is NOT idempotent (each call increments), so its
        // effect is the journaled CONTROLLER_INCARNATION_BUMPED command
        // carrying this use's nonce — a lost response settles from that row
        // instead of double-bumping on retry.
        effect: { kind: "INCARNATION_BUMP" },
        execute: async ({ operationId }) => ({
          status: 200,
          body: { ok: true, incarnation: await stubFor(adminBump[1]).bumpIncarnation(operationId) },
        }),
      });
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
      if (request.headers.get("x-capability") === null) {
        return json({ ok: false, error: "CAPABILITY_REQUIRED" }, 401);
      }
      const body = request.body;
      if (body === null) {
        return json({ ok: false, error: "CONTENT_LENGTH_REQUIRED", limit: MAX_REQUEST_BODY_BYTES }, 411);
      }
      // R5-PERF-01, the DIGEST-DECLARED protocol. The upload no longer has
      // to read the whole body before it can be authorized: the object key
      // IS the declared content digest (`p/<db>/<sha256hex>`, issuer-derived
      // and bound into the capability), and `content-length` is already
      // mandatory here. So the authority decision is made from the
      // DECLARATION — digest + length — before a single byte is read, and
      // the bytes are then streamed and VERIFIED against that same
      // declaration. The conjunction is exactly what it was before
      // (capability digest == actual content digest); only the order
      // changed, and with it the memory profile: an over-budget or
      // wrong-key upload is now refused having buffered nothing at all.
      // ONE wire-visible consequence, stated so it is not a surprise: a body
      // whose bytes do not hash to the digest its own capability declares can
      // only be detected AFTER the stream, so it answers 422
      // PAYLOAD_DIGEST_MISMATCH instead of the old pre-stream 403
      // CAPABILITY_DIGEST_MISMATCH. Both refuse; nothing is ever published.
      const declaredDigest = parts[2];
      const declaredLength = Number(request.headers.get("content-length"));
      // payload immutability is unchanged: publication is an ATOMIC
      // create-only put after the streamed digest is verified, so two
      // concurrent uploads of different bytes can never both win a key.
      // withMutation records the terminal outcome so an identical retry
      // replays it, and a thrown provider error is recorded AMBIGUOUS.
      return withMutation({
        route: "PAYLOAD_PUT",
        databaseId: parts[1],
        expect: { method: "PUT_PAYLOAD", key, bodyDigest: declaredDigest, bodyLength: declaredLength },
        useDigest: await useDigestOf(
          { method: "PUT_PAYLOAD", key, digest: declaredDigest, length: declaredLength }),
        // R6-CTRL-02: the ONE effect on this branch is remote (an R2
        // object), so it cannot commit inside the controller's transaction.
        // The protocol is two durable controller-side steps instead: the
        // CLAIM row carrying this effect is the intent, written before a
        // byte is uploaded, and `recordOperationReceipt` below is the
        // convergence evidence, written before the response can be
        // delivered. Between the two, attempt identity (`firstAttempt`)
        // keeps a re-executed publication from answering `deduplicated:
        // true` for an object this very nonce published.
        effect: { kind: "OPERATION_RECEIPT", databaseId: parts[1], method: "PUT_PAYLOAD" },
        execute: async ({ operationId, firstAttempt }) => {
          const result = await streamedPayloadPut(
            env, body, parts[1], key, declaredDigest, declaredLength, !firstAttempt);
          await stubFor(parts[1]).recordOperationReceipt(
            operationId, parts[1], "PUT_PAYLOAD", result.status,
            result.body as Record<string, unknown>);
          return result;
        },
      });
    }

    if (request.method === "POST" && path === "/session/register") {
      const parsed = await readJson(request);
      if ("errorResponse" in parsed) return parsed.errorResponse;
      const b = parsed.body as unknown as { databaseId: string; generation: number; startupSessionId: string };
      const gen = generationOr(b.generation);
      if (gen instanceof Response) return gen;
      return withMutation({
        route: "SESSION_REGISTER",
        databaseId: b.databaseId,
        expect: { method: "SESSION_REGISTER", session: b.startupSessionId, generation: String(gen) },
        useDigest: await useDigestOf({ path, body: parsed.body }),
        // R6-CTRL-02: the legacy macro refreshes the lease to
        // `controllerNow + 15m` every time it runs, so re-execution after a
        // lost response moved durable authority again. The receipt commits
        // with the registration.
        effect: { kind: "OPERATION_RECEIPT", databaseId: b.databaseId, method: "SESSION_REGISTER" },
        execute: async ({ operationId }) => {
          await stubFor(b.databaseId).registerSession(b.databaseId, gen, b.startupSessionId, operationId);
          return { status: 200, body: { ok: true } };
        },
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
      return withMutation({
        route: "SESSION_RESERVE",
        databaseId: b.databaseId,
        expect: { method: "SESSION_RESERVE", session: b.startupSessionId, generation: String(gen) },
        useDigest: await useDigestOf({ path, body: parsed.body }),
        // R6-CTRL-02: a reservation is single-use per id, so a re-execution
        // that arrives after the session has moved on answers
        // SESSION_ID_ALREADY_USED where the original answered RESERVED.
        effect: { kind: "OPERATION_RECEIPT", databaseId: b.databaseId, method: "SESSION_RESERVE" },
        execute: async ({ operationId }) => {
          const result = await stubFor(b.databaseId)
            .reserveSession(b.databaseId, gen, b.startupSessionId, b.holder, operationId);
          return { status: result.ok ? 200 : 409, body: result };
        },
      });
    }

    if (request.method === "POST" && path === "/session/attest") {
      const parsed = await readJson(request);
      if ("errorResponse" in parsed) return parsed.errorResponse;
      const b = parsed.body as unknown as { databaseId: string; startupSessionId: string; processNonce: string };
      return withMutation({
        route: "SESSION_ATTEST",
        databaseId: b.databaseId,
        expect: { method: "SESSION_ATTEST", session: b.startupSessionId },
        useDigest: await useDigestOf({ path, body: parsed.body }),
        // R6-CTRL-02: attestation is a state transition out of RESERVED; a
        // re-execution after activation answers SESSION_NOT_RESERVED.
        effect: { kind: "OPERATION_RECEIPT", databaseId: b.databaseId, method: "SESSION_ATTEST" },
        execute: async ({ operationId }) => {
          const result = await stubFor(b.databaseId)
            .attestSession(b.databaseId, b.startupSessionId, b.processNonce, operationId);
          return { status: result.ok ? 200 : 409, body: result };
        },
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
      return withMutation({
        route: "SESSION_ACTIVATE",
        databaseId: b.databaseId,
        expect: { method: "SESSION_ACTIVATE", session: b.startupSessionId, generation: String(gen) },
        useDigest: await useDigestOf({ path, body: parsed.body }),
        // R6-CTRL-02: activation is the ONE fencing transition, and its
        // receipt carries the count it fenced and the lease it granted —
        // neither of which a re-execution can recompute (the ACTIVE-self
        // path used to answer `fencedPredecessors: 0`).
        effect: { kind: "OPERATION_RECEIPT", databaseId: b.databaseId, method: "SESSION_ACTIVATE" },
        execute: async ({ operationId }) => {
          const result = await stubFor(b.databaseId).activateSession(b.databaseId, b.startupSessionId, {
            processNonce: b.processNonce, generation: gen, leaseMs: b.leaseMs,
          }, operationId);
          return { status: result.ok ? 200 : 409, body: result };
        },
      });
    }

    if (request.method === "POST" && path === "/session/renew") {
      const parsed = await readJson(request);
      if ("errorResponse" in parsed) return parsed.errorResponse;
      const b = parsed.body as unknown as { databaseId: string; startupSessionId: string; leaseMs: number };
      return withMutation({
        route: "SESSION_RENEW",
        databaseId: b.databaseId,
        expect: { method: "SESSION_RENEW", session: b.startupSessionId },
        useDigest: await useDigestOf({ path, body: parsed.body }),
        // R6-CTRL-02, the audit's headline case: `deadline = controllerNow +
        // leaseMs` on EVERY call, so an identical retry both extended
        // durable authority a second time and answered a different deadline
        // (the auditor measured 1,061,000 then 1,062,000). The chosen
        // deadline is now recorded with the UPDATE that sets it.
        effect: { kind: "OPERATION_RECEIPT", databaseId: b.databaseId, method: "SESSION_RENEW" },
        execute: async ({ operationId }) => {
          const result = await stubFor(b.databaseId)
            .renewLease(b.databaseId, b.startupSessionId, b.leaseMs, operationId);
          return { status: result.ok ? 200 : 409, body: result };
        },
      });
    }

    if (request.method === "POST" && path === "/session/drain") {
      const parsed = await readJson(request);
      if ("errorResponse" in parsed) return parsed.errorResponse;
      const b = parsed.body as unknown as { databaseId: string; startupSessionId: string };
      return withMutation({
        route: "SESSION_DRAIN",
        databaseId: b.databaseId,
        expect: { method: "SESSION_DRAIN", session: b.startupSessionId },
        useDigest: await useDigestOf({ path, body: parsed.body }),
        // R6-CTRL-02: ACTIVE -> DRAINING is one-way; a re-execution after a
        // successor activated answers SESSION_NOT_ACTIVE.
        effect: { kind: "OPERATION_RECEIPT", databaseId: b.databaseId, method: "SESSION_DRAIN" },
        execute: async ({ operationId }) => {
          const result = await stubFor(b.databaseId)
            .beginDrain(b.databaseId, b.startupSessionId, operationId);
          return { status: result.ok ? 200 : 409, body: result };
        },
      });
    }

    if (request.method === "POST" && path === "/session/revoke") {
      const parsed = await readJson(request);
      if ("errorResponse" in parsed) return parsed.errorResponse;
      const b = parsed.body as unknown as { databaseId: string; startupSessionId: string };
      // The token names the TARGET session (its minter decides which actor
      // may be revoked); the revocation power is not a generic bearer right.
      return withMutation({
        route: "SESSION_REVOKE",
        databaseId: b.databaseId,
        expect: { method: "SESSION_REVOKE", session: b.startupSessionId },
        useDigest: await useDigestOf({ path, body: parsed.body }),
        // R6-CTRL-02: revocation is terminal and journals a command; the
        // receipt is what a lost response replays.
        effect: { kind: "OPERATION_RECEIPT", databaseId: b.databaseId, method: "SESSION_REVOKE" },
        execute: async ({ operationId }) => {
          const result = await stubFor(b.databaseId)
            .revokeSession(b.databaseId, b.startupSessionId, operationId);
          return { status: result.ok ? 200 : 409, body: result };
        },
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
      return withMutation({
        route: "SESSION_FENCE",
        databaseId: b.databaseId,
        expect: { method: "SESSION_FENCE", session: b.startupSessionId },
        useDigest: await useDigestOf({ path, body: parsed.body }),
        // R6-CTRL-02: a fence revokes read leases and journals SESSION_FENCED
        // only when it actually fenced something; the receipt makes the
        // route's answer stable across a retry.
        effect: { kind: "OPERATION_RECEIPT", databaseId: b.databaseId, method: "SESSION_FENCE" },
        execute: async ({ operationId }) => {
          await stubFor(b.databaseId).fenceSession(b.databaseId, b.startupSessionId, operationId);
          return { status: 200, body: { ok: true } };
        },
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
      return withMutation({
        route: "BUDGETS_SET",
        databaseId: b.databaseId,
        expect: { method: "BUDGETS_SET" },
        useDigest: await useDigestOf({ path, body: parsed.body }),
        // R5-SEC-04: the effect is the journaled BUDGETS_SET command
        // carrying this use's nonce as its operation identity.
        effect: { kind: "BUDGETS_SET", databaseId: b.databaseId },
        execute: async (payload) => {
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
        },
      });
    }

    // data-path receipt verification BEFORE the DO's synchronous
    // finalisation: the object must exist and match digest + length
    const verifyReceipt = async (req: { payloadKey: string; payloadDigest: string; payloadLength: number }):
      Promise<{ status: number; body: unknown } | null> => {
      // R5-PERF-01: receipt verification needs the VERDICT, not the bytes -
      // a batch of 64 members no longer materialises 64 payloads to prove
      // they hash to what the caller catalogued.
      const result = await fetchVerified(env, req.payloadKey, req.payloadDigest, req.payloadLength, false);
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
      return withMutation({
        route: "WAL_FINALIZE",
        databaseId: req.databaseId,
        expect: {
          method: "WAL_FINALIZE",
          session: String((req as { startupSessionId?: unknown }).startupSessionId ?? ""),
          generation: String(gen),
        },
        useDigest: computedDigest,
        // R5-SEC-04: the authoritative effect of a finalize is its wal_tail
        // row under this operation identity. If the response is lost, the
        // resolver finds that row (or its status-singleton alias) and
        // replays the exact original receipt; a row under the same operation
        // id but a DIFFERENT request digest is contradictory evidence and
        // quarantines the use.
        effect: { kind: "WAL_FINALIZE", databaseId: req.databaseId, generation: gen,
                  operationId: String((req as { operationId?: unknown }).operationId ?? ""),
                  requestDigest: computedDigest },
        execute: async () => {
          const receiptError = await verifyReceipt(req);
          if (receiptError !== null) return receiptError;
          // the wire body is validated field-by-field above and again in the
          // core; the cast is the JSON boundary, not a trust statement
          const result = await stubFor(req.databaseId)
            .finalizeWalRecord({ ...req, requestDigest: computedDigest } as unknown as FinalizeRequest);
          return { status: result.ok ? 200 : 409, body: result };
        },
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
      const batchGen = exactGeneration(body.requests[0].generation);
      if (batchGen === null) {
        // unreachable: every member's generation passed generationOr above.
        // Stated explicitly because the effect binding is built from this
        // number, and a binding must never be built from an unvalidated one.
        return json({ ok: false, error: "INVALID_GENERATION" }, 400);
      }
      const batchGeneration = String(batchGen);
      const batchOperationId = body.batchOperationId; // narrowed to string above
      const batchDigest = body.batchDigest;
      return withMutation({
        route: "WAL_FINALIZE_BATCH",
        databaseId,
        expect: { method: "WAL_FINALIZE", session: batchSession, generation: batchGeneration },
        useDigest: await useDigestOf({ batchOperationId, members: memberDigests }),
        // R6-CTRL-01: the batch's authoritative effect is its ENVELOPE row
        // plus each member's wal_tail receipt — implemented since round 5
        // but unreachable, because this route stored the generic default
        // instead of binding it. The binding is constructed HERE: after
        // every untrusted field (member count, byte budget, database and
        // session agreement, record types, canonical payload refs, per-member
        // digests) has been structurally validated, and BEFORE the claim.
        // The ordered member digests are part of the binding, so the same
        // batch id under different members is contradictory evidence and
        // quarantines rather than replaying somebody else's receipt.
        effect: { kind: "WAL_FINALIZE_BATCH", databaseId, generation: batchGen,
                  batchOperationId, memberDigests },
        execute: async () => {
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
        },
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
      // R5-SEC-05: ONE authoritative hop — verify, revalidate the actor,
      // read the catalogue row, and take a one-shot lease over the exact
      // object the byte fetch below will touch.
      const auth = await authorizedRead(db, { method: "WAL_READ" },
        { kind: "EXACT", generation: gen, appendLsn: lsnValue });
      if ("denied" in auth) return auth.denied;
      const record = auth.outcome.record;
      // R5-PERF-01 content negotiation: the DEFAULT is unchanged (the
      // verify-then-serve base64 JSON shape every current consumer reads);
      // an explicit `accept: application/octet-stream` selects the
      // streaming variant.
      if (wantsPayloadStream(request)) {
        return streamedPayloadResponse(env, record, { appendLsn: lsnValue },
          (keys: string[]) => redeemRead(db, auth.outcome.lease, keys));
      }
      // exact reads re-verify bytes against the catalogued digest: serving
      // corrupted payload under valid metadata is worse than failing; a
      // catalogued record whose payload is missing is a hard integrity
      // error - never EOF (§exact-index rules)
      const payload = await verifiedPayloadBase64(env, record);
      if ("errorResponse" in payload) return payload.errorResponse;
      // the bytes are in hand but NOT yet authorized to leave: redemption is
      // the authoritative cut point (a fence that committed while they were
      // in flight has already revoked this lease)
      const revoked = await redeemRead(db, auth.outcome.lease, [record.payloadKey]);
      if (revoked !== null) return revoked;
      return json({ ok: true, payloadKey: record.payloadKey, payloadDigest: record.payloadDigest,
                    typeSequence: record.typeSequence, recordType: record.recordType,
                    payloadBase64: payload.payloadBase64 });
    }

    const walHead = path.match(/^\/wal\/([^/]+)\/(\d+)\/head$/);
    if (request.method === "GET" && walHead) {
      const [, db, generation] = walHead;
      const gen = generationOr(generation);
      if (gen instanceof Response) return gen;
      const auth = await authorizedRead(db, { method: "WAL_READ" }, { kind: "HEAD", generation: gen });
      if ("denied" in auth) return auth.denied;
      return json({ ok: true, headLsn: auth.outcome.headLsn,
                    headTypeSequence: auth.outcome.headTypeSequence });
    }

    const walIterator = path.match(/^\/wal\/([^/]+)\/(\d+)\/iterator$/);
    if (request.method === "POST" && walIterator) {
      const [, db, generation] = walIterator;
      const gen = generationOr(generation);
      if (gen instanceof Response) return gen;
      const auth = await authorizedRead(db, { method: "WAL_READ" }, { kind: "ITERATOR", generation: gen });
      if ("denied" in auth) return auth.denied;
      return json({ ok: true, headLsn: auth.outcome.headLsn, snapshotId: auth.outcome.snapshotId });
    }

    const walScan = path.match(/^\/wal\/([^/]+)\/(\d+)\/scan$/);
    if (request.method === "GET" && walScan) {
      const [, db, generation] = walScan;
      const gen = generationOr(generation);
      if (gen instanceof Response) return gen;
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
      const fromTypeSequence = nonNegativeU64(url.searchParams.get("fromTs"), 0n);
      const fromLsn = nonNegativeU64(url.searchParams.get("fromLsn"), 0n);
      const rawLimit = nonNegativeInt(url.searchParams.get("limit"), 100);
      const rawMaxBytes = nonNegativeInt(url.searchParams.get("maxBytes"), SCAN_PAGE_BYTE_BUDGET);
      if (fromTypeSequence === null || fromLsn === null || rawLimit === null
          || rawMaxBytes === null) {
        return json({ ok: false, error: "INVALID_PARAMETER" }, 400);
      }
      const limit = Math.min(Math.max(rawLimit, 1), 1000);
      const maxBytes = Math.min(Math.max(rawMaxBytes, 1), SCAN_PAGE_BYTE_BUDGET);
      // R5-SEC-05: snapshot resolution, the continuation bound, the page
      // read and its RESPONSE BYTE CUT all happen inside the one
      // authoritative hop, so the lease can cover exactly the keys this
      // page will fetch — not the keys of a page that was cut afterwards.
      // The byte cut itself is unchanged (V16 boundedness rules): the
      // catalogue knows every payload's length, so the page is trimmed
      // BEFORE any payload is fetched, at least one record always makes
      // progress, and a first record larger than the whole budget is
      // REFUSED rather than admitted as an exception (directive §12.6) —
      // it stays reachable through the exact-lookup route.
      const auth = await authorizedRead(db, { method: "WAL_READ" }, {
        kind: "SCAN", generation: gen, snapshotId: snapshotIdParam,
        fromTypeSequence, fromLsn, recordType, limit, maxBytes,
      }, { RECORD_EXCEEDS_PAGE_BUDGET: { hint: "fetch this record through /wal/{db}/{generation}/{lsn}" } });
      if ("denied" in auth) return auth.denied;
      const included = auth.outcome.records;
      const payloads = await mapBounded(included, PAYLOAD_FETCH_CONCURRENCY, (record) =>
        verifiedPayloadBase64(env, record),
      );
      const records: Record<string, unknown>[] = [];
      for (const [index, payload] of payloads.entries()) {
        if ("errorResponse" in payload) return payload.errorResponse;
        records.push({ ...included[index], payloadBase64: payload.payloadBase64 });
      }
      const revoked = await redeemRead(db, auth.outcome.lease, included.map((r) => r.payloadKey));
      if (revoked !== null) return revoked;
      return json({ ok: true, records, nextFromLsn: auth.outcome.nextFromLsn });
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
      // Read surface: immutable durable history stays queryable by operation
      // identity across a fence of some OTHER actor (V16; the finalize-RETRY
      // path still answers SESSION_FENCED per inv. 38). "By the current
      // actor" is load-bearing, so the authority revalidates the caller's
      // own session in the same hop (donor A4 + R5-SEC-05): a fenced actor
      // holding an unexpired WAL_READ capability reads nothing.
      const auth = await authorizedRead(db, { method: "WAL_READ" },
        { kind: "OPERATION", generation: gen, operationId: decodedOp.value });
      if ("denied" in auth) return auth.denied;
      return json(auth.outcome.inner);
    }

    const walLast = path.match(/^\/wal\/([^/]+)\/(\d+)\/last$/);
    if (request.method === "GET" && walLast) {
      const [, db, generation] = walLast;
      const gen = generationOr(generation);
      if (gen instanceof Response) return gen;
      const recordType = Number(url.searchParams.get("recordType") ?? "NaN");
      if (invalidRecordType(recordType)) {
        return json({ ok: false, error: "INVALID_RECORD_TYPE", observed: url.searchParams.get("recordType") }, 400);
      }
      const auth = await authorizedRead(db, { method: "WAL_READ" },
        { kind: "LAST_BY_TYPE", generation: gen, recordType });
      if ("denied" in auth) return auth.denied;
      const record = auth.outcome.record;
      const payload = await verifiedPayloadBase64(env, record);
      if ("errorResponse" in payload) return payload.errorResponse;
      const revoked = await redeemRead(db, auth.outcome.lease, [record.payloadKey]);
      if (revoked !== null) return revoked;
      return json({ ok: true, record: { ...record, payloadBase64: payload.payloadBase64 } });
    }

    const outboxPeek = path.match(/^\/outbox\/([^/]+)$/);
    if (request.method === "GET" && outboxPeek) {
      // validated and clamped like scan's: a negative LIMIT is documented by
      // SQLite as "no upper bound", so an unchecked value here was the one
      // route where a caller could request an unbounded page
      const rawPeek = nonNegativeInt(url.searchParams.get("limit"), 100);
      if (rawPeek === null) return json({ ok: false, error: "INVALID_PARAMETER", field: "limit" }, 400);
      const limit = Math.min(Math.max(rawPeek, 1), 1000);
      const auth = await authorizedControlRead(outboxPeek[1], { method: "OUTBOX" },
        { kind: "OUTBOX_PEEK", limit });
      if ("denied" in auth) return auth.denied;
      return json({ ok: true, events: auth.outcome.events });
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
      return withMutation({
        route: "OUTBOX_ACK",
        databaseId: outboxAck[1],
        expect: { method: "OUTBOX" },
        useDigest: await useDigestOf({ path, body: parsedAck.body }),
        // R6-CTRL-02: the acknowledged COUNT is destroyed by the ack itself
        // — the rows are published, so a re-execution reports `acked: 0`
        // where the original reported N. The count and the bound are
        // recorded in the acking transaction; the bound is part of the use
        // digest, so an ack of a DIFFERENT bound under the same token is
        // CAPABILITY_REPLAYED, not a second ack.
        effect: { kind: "OPERATION_RECEIPT", databaseId: outboxAck[1], method: "OUTBOX_ACK" },
        execute: async ({ operationId, session }) => {
          if (typeof session !== "string" || session.length === 0) {
            return { status: 403, body: { ok: false, error: "CAPABILITY_RESTRICTION_MISSING", restriction: "session" } };
          }
          const result = await stubFor(outboxAck[1]).outboxAck(outboxAck[1], upTo, session, operationId);
          return result.ok
            ? { status: 200, body: { ok: true, acked: result.acked } }
            : { status: 409, body: result };
        },
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
      if (typeof b.cutId !== "string" || b.cutId.length === 0 || b.cutId.length > 128) {
        // the cut id is part of the effect binding, so it is structurally
        // validated BEFORE authority is claimed, not inside the route body
        return json({ ok: false, error: "INVALID_PARAMETER", field: "cutId" }, 400);
      }
      return withMutation({
        route: "CHECKPOINT_OPEN",
        databaseId: cutOpen[1],
        expect: { method: "CHECKPOINT_OPEN", generation: String(cutGen) },
        useDigest: await useDigestOf({ path, body: parsedCut.body }),
        // R6-CTRL-01: the authoritative effect is the checkpoint_cuts row
        // keyed by this cut id — implemented since round 5 and never
        // reached, so a lost response re-executed and answered CUT_EXISTS
        // instead of the original cut receipt. The binding is built from the
        // validated database, generation and cut id, before the claim.
        effect: { kind: "CHECKPOINT_OPEN", databaseId: cutOpen[1], generation: cutGen, cutId: b.cutId },
        execute: async (payload) => {
          // R4-SEC-04/06: the acting session must hold LIVE authority in
          // this generation at use time - a fenced/stale actor cannot open
          // a cut with a still-valid token.
          const actor = typeof payload.session === "string" ? payload.session : "";
          const live = await stubFor(cutOpen[1]).assertActiveReader(cutOpen[1], actor, cutGen);
          if (!live.ok) return { status: 409, body: live };
          const result = await stubFor(cutOpen[1]).openCheckpointCut(cutOpen[1], cutGen, b.cutId);
          return { status: result.ok ? 200 : 409, body: result };
        },
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
      // R6-CTRL-01: the activation's effect BINDS the manifest's logical
      // digest, so the fields the binding is built from are validated here,
      // before authority is claimed — a manifest that cannot produce a
      // binding refuses without burning the token. Only the binding's own
      // fields are checked at the worker: the MATERIAL validation (walHead
      // against the recorded cut head, keyspace roots, scratch-restore
      // proof) needs the authority's durable cut row and stays in the core,
      // which re-validates everything regardless.
      const evidenceBody = parsedEvidence.body as {
        schema?: unknown; cutId?: unknown; logicalDigest?: unknown;
      };
      // the refusal keeps the core's typed verdict AND its 409 status: this
      // is the same CUT_EVIDENCE_INVALID answer the authority gives, moved
      // earlier so that a manifest which cannot produce a binding also
      // cannot burn a token. The reason strings are the core's, verbatim.
      if (evidenceBody.schema !== "checkpoint-restore-evidence/v2") {
        return json({ ok: false, error: "CUT_EVIDENCE_INVALID",
                      reason: "schema must be checkpoint-restore-evidence/v2" }, 409);
      }
      if (evidenceBody.cutId !== decodedCut.value) {
        return json({ ok: false, error: "CUT_EVIDENCE_INVALID",
                      reason: "evidence.cutId does not name the cut being activated" }, 409);
      }
      if (invalidSha256Hex(evidenceBody.logicalDigest)) {
        return json({ ok: false, error: "CUT_EVIDENCE_INVALID",
                      reason: "logicalDigest is not 64-hex" }, 409);
      }
      const boundLogicalDigest = evidenceBody.logicalDigest as string;
      return withMutation({
        route: "CHECKPOINT_ACTIVATE",
        databaseId: cutActivate[1],
        expect: { method: "CHECKPOINT_ACTIVATE" },
        useDigest: await useDigestOf({ path, body: parsedEvidence.body }),
        // R6-CTRL-01: the authoritative effect is the cut's
        // ACTIVE/SUPERSEDED transition plus the journaled
        // CHECKPOINT_CUT_ACTIVATED command — implemented since round 5 and
        // never reached, so a lost response re-executed and answered
        // CUT_NOT_PENDING instead of the original success. Binding the
        // logical digest makes an activation of the same cut under DIFFERENT
        // evidence contradictory rather than replayable.
        effect: { kind: "CHECKPOINT_ACTIVATE", databaseId: cutActivate[1], cutId: decodedCut.value,
                  logicalDigest: boundLogicalDigest },
        execute: async (payload) => {
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
        },
      });
    }

    const cutActive = path.match(/^\/checkpoint\/([^/]+)\/(\d+)\/active$/);
    if (request.method === "GET" && cutActive) {
      const activeGen = generationOr(cutActive[2]);
      if (activeGen instanceof Response) return activeGen;
      const auth = await authorizedRead(cutActive[1], { method: "WAL_READ" },
        { kind: "ACTIVE_CUT", generation: activeGen });
      if ("denied" in auth) return auth.denied;
      return json(auth.outcome.inner, 200);
    }

    const journalVerifyAnchored = path.match(/^\/journal\/([^/]+)\/verify-anchored$/);
    if (request.method === "GET" && journalVerifyAnchored) {
      const auth = await authorizedControlRead(journalVerifyAnchored[1], { method: "JOURNAL_VERIFY" },
        { kind: "JOURNAL_VERIFY_ANCHORED" });
      if ("denied" in auth) return auth.denied;
      return json(auth.outcome.verdict, auth.outcome.verified ? 200 : 409);
    }

    const journalVerify = path.match(/^\/journal\/([^/]+)\/verify$/);
    if (request.method === "GET" && journalVerify) {
      // F8 read surface: recompute the whole chain + MACs server-side.
      // Routed by databaseId like every DO method (the journal is the DO's
      // global outbox; the id names the authority instance to audit).
      const auth = await authorizedControlRead(journalVerify[1], { method: "JOURNAL_VERIFY" },
        { kind: "JOURNAL_VERIFY" });
      if ("denied" in auth) return auth.denied;
      return json(auth.outcome.verdict, auth.outcome.verified ? 200 : 409);
    }

    const walAudit = path.match(/^\/wal\/([^/]+)\/(\d+)\/audit$/);
    if (request.method === "GET" && walAudit) {
      const [, db, generation] = walAudit;
      const gen = generationOr(generation);
      if (gen instanceof Response) return gen;
      const auth = await authorizedRead(db, { method: "WAL_READ" }, { kind: "AUDIT", generation: gen });
      if ("denied" in auth) return auth.denied;
      return json({ ok: true, contiguous: auth.outcome.contiguous,
                    count: auth.outcome.count, maxLsn: auth.outcome.maxLsn });
    }

    return json({ ok: false, error: "NOT_FOUND" }, 404);
  },
};
