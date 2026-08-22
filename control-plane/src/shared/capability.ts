/*
 * F9 (data-path hardening): controller-issued capability tokens.
 *
 * A capability is a short-lived, audience-bound authorization for ONE
 * data-path operation class, minted by the PRIVATE ISSUER and verified by
 * the worker before any storage or DO work happens. The token binds:
 *
 *   principal        - who the issuer issued it to (attribution);
 *   databaseId       - the audience: one database's data path;
 *   method           - the operation class (PUT_PAYLOAD, WAL_READ, ...);
 *   key/digest/      - for payload writes: the EXACT object key (derived
 *   maxBytes           by the issuer - caller-selected keys die), the
 *                      required content digest, and the byte budget;
 *   incarnation      - the controller incarnation that minted it: tokens
 *                      from a superseded controller die with it;
 *   nonce            - single use, burned transactionally at first use;
 *   expiresAtMs      - hard expiry.
 *
 * SCHEMA v3 (R5-SEC-03): the schema-v2 HMAC is replaced by an Ed25519
 * SIGNATURE. Encoding:
 *
 *   base64url(canonicalJson(payload)) + "." + hex(ed25519_sig)   (128 hex)
 *
 * The verifier holds ONLY public keys (a two-slot rotation keyring per
 * scope); the private signing keys live with the issuer (core/issuer.ts —
 * dev constants under local-dev, per-run ephemeral keys for managed local
 * runs, a provisioned private issuer in production). Verification is
 * therefore mathematically one-way: a component that can validate tokens
 * has NO material capable of minting them — the §2.3 "verifier keys can
 * mint" property of the HMAC design is dead by construction, not by
 * discipline. Verification is async (WebCrypto); the synchronous core
 * (procedures.ts) keeps receiving only pre-verified payloads.
 *
 * Everything in this module either VERIFIES or is pure schema; minting
 * lives exclusively in core/issuer.ts.
 */

import { canonicalJson, CANONICAL_U64, fromHex, utf8 } from "./journal-crypto.ts";
import { ed25519Verify } from "./ed25519.ts";

const UTF8_DECODER = new TextDecoder();

/** The one token schema version this verifier understands. v1 (implicit)
 *  and v2 (HMAC) are RETIRED: any other value refuses. */
export const CAPABILITY_TOKEN_VERSION = 3;
/** The one signature algorithm of schema v3. A token naming any other
 *  algorithm refuses — "alg confusion" is a version refusal here, never a
 *  downgrade negotiation. */
export const CAPABILITY_TOKEN_ALG = "Ed25519";

export interface CapabilityPayload {
  /** Token schema version. Exactly 3; any other value - including the
   *  retired v2 HMAC shape and the absent field of the v1 shape - is
   *  refused, so a schema change can never be smuggled past an old
   *  verifier. */
  v: 3;
  /** Signature algorithm. Exactly "Ed25519"; part of the signed body, so
   *  an attacker cannot re-frame a token under a weaker algorithm. */
  alg: "Ed25519";
  /** Key id: names the exact issuer key this token is signed under.
   *  Syntax: `cap:<env>` | `prov:<env>`, optionally suffixed `/<slot>`
   *  for rotation (e.g. `cap:prod/2`). The verifier requires the kid to
   *  (a) name the scope+environment the presented method belongs to and
   *  (b) resolve to a NON-RETIRED key in its keyring. */
  kid: string;
  /** Environment the token is bound to; must equal the verifier's own. */
  env: string;
  /** Tenant of the registry record this token was issued against. Together
   *  with env + databaseId it is the FULL routing/binding triple: the
   *  Worker derives the controller DO id from these verified fields, and
   *  the DO cross-checks them against its provisioned binding. */
  tenantId: string;
  principal: string;
  databaseId: string;
  method: string;
  /** the startup session this capability authorizes (WAL_FINALIZE only): the
   *  actor identity is BOUND into the token, so a disclosed session id (e.g.
   *  via a SESSION_FENCED attribution) is not by itself a write credential -
   *  the controller only issues a session-bound finalize capability to the
   *  actor it admitted as that session (donor A3). */
  session?: string;
  /** the database generation this capability authorizes (WAL_FINALIZE only),
   *  as a CANONICAL DECIMAL STRING so the full u64 range is exact on the wire
   *  (audit C-05): a finalize token minted for generation N cannot be
   *  replayed against generation N+1 after a rollover - the generation is
   *  part of the authority, not just a request field. */
  generation?: string;
  /** exact object key (PUT_PAYLOAD only; issuer-derived, content-addressed) */
  key?: string;
  /** required sha256 hex of the body (PUT_PAYLOAD only) */
  digest?: string;
  /** byte budget for the operation (PUT_PAYLOAD: max body length) */
  maxBytes?: number;
  incarnation: number;
  nonce: string;
  expiresAtMs: number;
}

export type CapabilityCheck =
  | { ok: true; payload: CapabilityPayload }
  | { ok: false; error:
      | "CAPABILITY_MALFORMED"
      | "CAPABILITY_VERSION_UNKNOWN"
      | "CAPABILITY_ALG_UNKNOWN"
      | "CAPABILITY_FIELD_UNKNOWN"
      | "CAPABILITY_KID_MISMATCH"
      | "CAPABILITY_KID_UNKNOWN"
      | "CAPABILITY_KID_RETIRED"
      | "CAPABILITY_ENV_MISMATCH"
      | "CAPABILITY_TENANT_MISMATCH"
      | "CAPABILITY_SIGNATURE_INVALID"
      | "CAPABILITY_EXPIRED"
      | "CAPABILITY_METHOD_MISMATCH"
      | "CAPABILITY_AUDIENCE_MISMATCH"
      | "CAPABILITY_SESSION_MISMATCH"
      | "CAPABILITY_KEY_MISMATCH"
      | "CAPABILITY_DIGEST_MISMATCH"
      | "CAPABILITY_BUDGET_EXCEEDED"
      | "CAPABILITY_RESTRICTION_MISSING"
      | "CAPABILITY_BUDGET_ABOVE_CEILING"
      | "CAPABILITY_GENERATION_MISMATCH"
      | "CAPABILITY_METHOD_UNKNOWN"
      | "CAPABILITY_STALE_INCARNATION" };

// ---------------------------------------------------------------------------
// Verification keyrings (R5-SEC-03 rotation): two slots, explicit retirement
// ---------------------------------------------------------------------------

/** One public verification key of a keyring. `retired: true` keeps the kid
 *  RECOGNIZED but REFUSED (typed CAPABILITY_KID_RETIRED, distinguishable
 *  from an attacker-invented kid) — the explicit end of a rotation overlap
 *  window. */
export interface VerificationKey {
  kid: string;
  /** raw 32-byte Ed25519 public key */
  publicKey: Uint8Array;
  retired: boolean;
}

/** A per-scope verification keyring: at most two slots (current + previous)
 *  so rotation is an overlap-then-retire protocol, never an unbounded key
 *  list. keys[0] is the CURRENT key (never retired; new tokens are minted
 *  under its kid); keys[1], when present, is the previous key — accepted
 *  during the overlap window, refused once retired. */
export interface VerificationKeyring {
  scope: "cap" | "prov";
  environment: string;
  keys: VerificationKey[];
}

/** The scope a method's tokens must be signed under: the PROVISION power
 *  lives under "prov:<env>", everything else under "cap:<env>". */
function requiredScope(method: string): "cap" | "prov" {
  return method === "PROVISION" ? "prov" : "cap";
}

/** kid syntax: `<scope>:<env>` optionally + `/<slot digits>`. */
export function kidNamesScope(kid: string, scope: "cap" | "prov", environment: string): boolean {
  if (kid === `${scope}:${environment}`) return true;
  const prefix = `${scope}:${environment}/`;
  return kid.startsWith(prefix) && /^[0-9]{1,9}$/.test(kid.slice(prefix.length));
}

/**
 * Restrictions that are MANDATORY for a method, not optional decoration.
 *
 * Every restriction used to be checked as `if (payload.X !== undefined)`, so
 * a correctly-signed token that simply OMITTED key, digest and maxBytes
 * satisfied all three checks and authorized any key, any body, any length.
 * That is not a narrower capability - it is a wider one, and it is exactly
 * how a capability system inverts into a bearer token. A method's
 * restrictions are therefore required by name; a token missing one is
 * refused before any of the value comparisons run.
 */
export const REQUIRED_RESTRICTIONS: Record<string, ReadonlyArray<"session" | "generation" | "key" | "digest" | "maxBytes">> = {
  PUT_PAYLOAD: ["key", "digest", "maxBytes"],
  // the batch route authorizes as WAL_FINALIZE (one session-bound token, one
  // transaction) - a separate batch method name here would be unreachable
  // policy nothing mints or expects. Finalize binds session AND generation
  // (audit C-05): the token authorizes one actor in one generation, so a
  // rollover invalidates it.
  WAL_FINALIZE: ["session", "generation"],
  // R4-SEC-05: runtime WAL reads are actor-bound. A read token names the
  // active session AND the generation it reads under, and the DO
  // revalidates both at use time (assertActiveReader) - a fenced stale
  // container cannot keep reading history until token expiry.
  // Session-independent history access is the separate, deliberately
  // narrow JOURNAL_VERIFY recovery role below.
  WAL_READ: ["session", "generation"],
  // Outbox consumers are downstream services, not startup-session actors;
  // their tokens carry no session by design. Kept in the closed registry
  // with method-exact scope + expiry + incarnation as the authority bound.
  OUTBOX: [],
  // R4-SEC-04: the generic SESSION_ADMIN bearer method is GONE. Every
  // lifecycle transition is its own exact action, bound to the exact
  // actor it administers (token.session must equal the route's target
  // startupSessionId; generation-bearing actions bind the exact canonical
  // generation). A token minted for one action/actor authorizes nothing
  // else, and the DO transaction revalidates the current role at use.
  SESSION_REGISTER: ["session", "generation"], // legacy macro (dev-only route)
  SESSION_RESERVE: ["session", "generation"],
  SESSION_ATTEST: ["session"],
  SESSION_ACTIVATE: ["session", "generation"],
  SESSION_RENEW: ["session"],
  SESSION_DRAIN: ["session"],
  SESSION_REVOKE: ["session"],
  SESSION_FENCE: ["session"],
  BUDGETS_SET: ["session"],
  // Checkpoint transitions are controller/recovery roles, bound to the
  // acting session and generation; activation additionally requires the
  // typed restore-evidence manifest (R4-SEC-06, procedures.ts).
  CHECKPOINT_OPEN: ["session", "generation"],
  CHECKPOINT_ACTIVATE: ["session", "generation"],
  // Incarnation supersession deliberately binds NO session: it is the
  // recovery power that fences every predecessor (a successor cannot hold
  // a predecessor's session). Its authority is the exact method plus the
  // single-use request-line-bound claim (withMutation use digest).
  INCARNATION_BUMP: [],
  // Recovery/forensic journal verification: session-independent BY DESIGN
  // (history must stay auditable after every actor is fenced), private
  // and read-only.
  JOURNAL_VERIFY: [],
  // R4 PR1: the internal provisioning power - the ONLY method that may bind
  // an uninitialized controller DO to its registry record. Its authority IS
  // the binding triple (env/tenantId/databaseId are mandatory core fields
  // of every v3 token) under the SEPARATE "prov:<env>" scope keypair
  // (issuer.ts): ordinary capability-scope material cannot mint it.
  PROVISION: [],
};

/**
 * R4-SEC-04: the capability method space is a CLOSED registry — exactly
 * the keys of REQUIRED_RESTRICTIONS. Minting or verifying an unknown
 * method used to fall through `?? []` (no required restrictions at all),
 * which is how a generic bearer method sneaks back in. Both ends refuse
 * unknown methods outright.
 */
export function isKnownCapabilityMethod(method: string): boolean {
  return Object.prototype.hasOwnProperty.call(REQUIRED_RESTRICTIONS, method);
}

/**
 * Hard ceiling on any byte budget a capability may carry (contract F9: the
 * data path admits at most 8 MiB per object). A budget is a NARROWING of
 * this ceiling, never a widening of it: a token minted - or tampered into -
 * carrying 999,999,999 is refused at verification, so the ceiling does not
 * depend on the issuer being correct.
 */
export const MAX_CAPABILITY_BYTES = 8 * 1024 * 1024;

export function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(text: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(text)) return null;
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

/** The canonical signed body bytes of a payload — shared with the issuer
 *  (core/issuer.ts) so the two ends cannot disagree about what is signed. */
export function capabilityBodyBytes(payload: CapabilityPayload): Uint8Array {
  return utf8(canonicalJson(payload as unknown as Record<string, unknown>));
}

/** The CLOSED field set of a v3 token. Any key outside this list refuses
 *  the whole token (audit 4.4 item 4): an unknown field is a schema the
 *  verifier does not understand, and "ignore it" is how a future
 *  authority-bearing field gets silently dropped by old verifiers. */
const V3_FIELDS = new Set([
  "v", "alg", "kid", "env", "tenantId", "principal", "databaseId", "method",
  "session", "generation", "key", "digest", "maxBytes",
  "incarnation", "nonce", "expiresAtMs",
]);

export interface CapabilityExpectation {
  method: string;
  databaseId: string;
  /** the verifier's own environment; the token's `env` (and its kid's
   *  scope) must name exactly this. */
  env: string;
  /** when set (the DO passes its provisioned tenant; a provision check
   *  passes the binding's tenant), the token's tenantId must match. */
  tenantId?: string;
  /** the authority's current incarnation. OMIT it (undefined) for a
   *  stateless FRAMING pre-check at the outer worker (audit C-03): the
   *  worker verifies signature/expiry/audience/method/key/digest/session/
   *  generation before ANY Durable Object contact, so a junk token never
   *  instantiates, migrates or binds a DO; the authoritative incarnation
   *  check + nonce claim then run inside the DO. */
  currentIncarnation?: number;
  nowMs: number;
  /** when set, the capability MUST carry a matching session binding - a
   *  finalize request cannot be authorized by a session-unbound token
   *  (donor A3): the actor identity is part of the authority, not just a
   *  field in the request body. */
  session?: string;
  /** the request's generation as a canonical decimal string; when set, the
   *  token's bound generation must match exactly (audit C-05). */
  generation?: string;
  key?: string;
  bodyDigest?: string;
  bodyLength?: number;
}

/**
 * Verify a token against what the REQUEST actually is: schema/alg first
 * (a token the verifier does not understand refuses before anything else),
 * then key selection by kid (scope + environment + keyring membership +
 * retirement), then the SIGNATURE — nothing inside an unauthenticated
 * token is trusted beyond what key selection needs — then expiry,
 * incarnation, method, audience, key, digest, budget. The nonce is NOT
 * claimed here - the use claim is transactional state and belongs to the
 * authority (ControllerCore.claimCapability), called after this check
 * passes.
 *
 * This is THE verification seam (R5-SEC-03): async because WebCrypto is,
 * called from the worker fetch frame and the DO's async RPC methods; the
 * sync core only ever sees the returned pre-verified payload.
 */
export async function verifyCapabilityToken(
  keyring: VerificationKeyring,
  token: string,
  expect: CapabilityExpectation,
): Promise<CapabilityCheck> {
  const dot = token.lastIndexOf(".");
  if (dot <= 0) return { ok: false, error: "CAPABILITY_MALFORMED" };
  const bodyBytes = base64urlDecode(token.slice(0, dot));
  const sigHex = token.slice(dot + 1);
  if (bodyBytes === null || !/^[0-9a-f]{128}$/.test(sigHex)) return { ok: false, error: "CAPABILITY_MALFORMED" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(UTF8_DECODER.decode(bodyBytes));
  } catch {
    return { ok: false, error: "CAPABILITY_MALFORMED" };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { ok: false, error: "CAPABILITY_MALFORMED" };
  }
  // schema versioning (audit 4.4 item 4): version FIRST - a v1/v2-shaped or
  // future-versioned token is a version refusal, not a field-by-field guess;
  // then the algorithm - unknown alg fails closed, never negotiates down
  const record = parsed as Record<string, unknown>;
  if (record.v !== CAPABILITY_TOKEN_VERSION) return { ok: false, error: "CAPABILITY_VERSION_UNKNOWN" };
  if (record.alg !== CAPABILITY_TOKEN_ALG) return { ok: false, error: "CAPABILITY_ALG_UNKNOWN" };
  for (const field of Object.keys(record)) {
    if (!V3_FIELDS.has(field)) return { ok: false, error: "CAPABILITY_FIELD_UNKNOWN" };
  }
  const payload = record as unknown as CapabilityPayload;
  if (typeof payload.kid !== "string" || typeof payload.env !== "string"
      || typeof payload.tenantId !== "string" || typeof payload.method !== "string"
      || typeof payload.databaseId !== "string"
      || typeof payload.nonce !== "string" || typeof payload.expiresAtMs !== "number") {
    return { ok: false, error: "CAPABILITY_MALFORMED" };
  }
  // key selection (R5-SEC-03 rotation): the kid must name the exact scope
  // the presented method belongs to IN THE VERIFIER'S OWN ENVIRONMENT - a
  // token cannot claim one scope while validating under another - and must
  // resolve to a live key in the keyring. An attacker-invented kid is a
  // typed KID_UNKNOWN; a rotation-retired kid is a typed KID_RETIRED. Both
  // fail closed BEFORE any signature work.
  const scope = requiredScope(payload.method);
  if (keyring.scope !== scope || !kidNamesScope(payload.kid, scope, expect.env)) {
    return { ok: false, error: "CAPABILITY_KID_MISMATCH" };
  }
  const verificationKey = keyring.keys.find((key) => key.kid === payload.kid);
  if (verificationKey === undefined) return { ok: false, error: "CAPABILITY_KID_UNKNOWN" };
  if (verificationKey.retired) return { ok: false, error: "CAPABILITY_KID_RETIRED" };
  // the SIGNATURE: everything after this line trusts the payload
  if (!(await ed25519Verify(verificationKey.publicKey, fromHex(sigHex), bodyBytes))) {
    return { ok: false, error: "CAPABILITY_SIGNATURE_INVALID" };
  }
  if (expect.nowMs >= payload.expiresAtMs) return { ok: false, error: "CAPABILITY_EXPIRED" };
  if (expect.currentIncarnation !== undefined && payload.incarnation !== expect.currentIncarnation) {
    return { ok: false, error: "CAPABILITY_STALE_INCARNATION" };
  }
  if (payload.method !== expect.method) return { ok: false, error: "CAPABILITY_METHOD_MISMATCH" };
  // R4-SEC-04: closed method registry — a token naming a method outside
  // REQUIRED_RESTRICTIONS is refused even when the route (buggily) expects
  // it; the `?? []` fallback below must never launder an unknown method
  // into a restriction-free bearer token.
  if (!isKnownCapabilityMethod(payload.method)) return { ok: false, error: "CAPABILITY_METHOD_UNKNOWN" };
  // environment binding (R4 PR1): the token must name the verifier's own
  // environment (the kid scope check above already pinned the kid to it;
  // this pins the payload's own env field too).
  if (payload.env !== expect.env) return { ok: false, error: "CAPABILITY_ENV_MISMATCH" };
  if (expect.tenantId !== undefined && payload.tenantId !== expect.tenantId) {
    return { ok: false, error: "CAPABILITY_TENANT_MISMATCH" };
  }
  if (payload.databaseId !== expect.databaseId) return { ok: false, error: "CAPABILITY_AUDIENCE_MISMATCH" };
  // session binding: when the route demands a session (finalize), the token
  // must carry exactly that session - a session-unbound token is refused, so
  // knowing a session id cannot be turned into write authority
  if (expect.session !== undefined && payload.session !== expect.session) {
    return { ok: false, error: "CAPABILITY_SESSION_MISMATCH" };
  }
  // generation binding (audit C-05): a finalize token authorizes one
  // generation. The bound value must be canonical decimal, and it must equal
  // the request's generation - a token minted for N cannot finalize N+1.
  if (payload.generation !== undefined && !CANONICAL_U64.test(payload.generation)) {
    return { ok: false, error: "CAPABILITY_MALFORMED" };
  }
  if (expect.generation !== undefined && payload.generation !== expect.generation) {
    return { ok: false, error: "CAPABILITY_GENERATION_MISMATCH" };
  }
  // mandatory-by-method restrictions: absence is refusal, not permission
  for (const required of REQUIRED_RESTRICTIONS[payload.method] ?? []) {
    if (payload[required] === undefined) {
      return { ok: false, error: "CAPABILITY_RESTRICTION_MISSING" };
    }
  }
  // a restriction the REQUEST needs must also be present in the token: a
  // route that checks a key/digest/length cannot be satisfied by a token
  // that declines to bind one
  if (expect.key !== undefined && payload.key === undefined) return { ok: false, error: "CAPABILITY_RESTRICTION_MISSING" };
  if (expect.bodyDigest !== undefined && payload.digest === undefined) {
    return { ok: false, error: "CAPABILITY_RESTRICTION_MISSING" };
  }
  if (expect.bodyLength !== undefined && payload.maxBytes === undefined) {
    return { ok: false, error: "CAPABILITY_RESTRICTION_MISSING" };
  }
  if (payload.key !== undefined && payload.key !== expect.key) return { ok: false, error: "CAPABILITY_KEY_MISMATCH" };
  if (payload.digest !== undefined && payload.digest !== expect.bodyDigest) {
    return { ok: false, error: "CAPABILITY_DIGEST_MISMATCH" };
  }
  if (payload.maxBytes !== undefined) {
    if (!Number.isSafeInteger(payload.maxBytes) || payload.maxBytes < 0 || payload.maxBytes > MAX_CAPABILITY_BYTES) {
      return { ok: false, error: "CAPABILITY_BUDGET_ABOVE_CEILING" };
    }
    if (expect.bodyLength === undefined || expect.bodyLength > payload.maxBytes) {
      return { ok: false, error: "CAPABILITY_BUDGET_EXCEEDED" };
    }
  }
  return { ok: true, payload };
}
