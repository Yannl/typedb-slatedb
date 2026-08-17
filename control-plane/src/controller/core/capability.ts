/*
 * F9 (data-path hardening): controller-issued capability tokens.
 *
 * A capability is a short-lived, audience-bound authorization for ONE
 * data-path operation class, minted by the controller and verified by the
 * worker before any storage or DO work happens. The token binds:
 *
 *   principal        - who the controller issued it to (attribution);
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
 * Encoding: base64url(canonicalJson(payload)) + "." + hex(HMAC-SHA-256)
 * under the controller's capability key (distinct from the journal key).
 * Everything is synchronous and runtime-agnostic, like the journal crypto.
 */

import { bytesEqual, canonicalJson, fromHex, hmacSha256, hex, utf8 } from "./journal-crypto.ts";

export interface CapabilityPayload {
  principal: string;
  databaseId: string;
  method: string;
  /** the startup session this capability authorizes (WAL_FINALIZE only): the
   *  actor identity is BOUND into the token, so a disclosed session id (e.g.
   *  via a SESSION_FENCED attribution) is not by itself a write credential -
   *  the controller only issues a session-bound finalize capability to the
   *  actor it admitted as that session (donor A3). */
  session?: string;
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
      | "CAPABILITY_MAC_INVALID"
      | "CAPABILITY_EXPIRED"
      | "CAPABILITY_METHOD_MISMATCH"
      | "CAPABILITY_AUDIENCE_MISMATCH"
      | "CAPABILITY_SESSION_MISMATCH"
      | "CAPABILITY_KEY_MISMATCH"
      | "CAPABILITY_DIGEST_MISMATCH"
      | "CAPABILITY_BUDGET_EXCEEDED"
      | "CAPABILITY_STALE_INCARNATION" };

function base64urlEncode(bytes: Uint8Array): string {
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

export function mintCapability(capabilityKey: Uint8Array, payload: CapabilityPayload): string {
  const body = utf8(canonicalJson(payload as unknown as Record<string, unknown>));
  const mac = hmacSha256(capabilityKey, body);
  return `${base64urlEncode(body)}.${hex(mac)}`;
}

/**
 * Verify a token against what the REQUEST actually is. MAC first (nothing
 * inside an unauthenticated token is trusted, including its expiry), then
 * expiry, incarnation, method, audience, key, digest, budget. The nonce is
 * NOT burned here - burning is transactional state and belongs to the
 * authority (ControllerCore.burnCapabilityNonce), called after this check
 * passes.
 */
export function checkCapability(
  capabilityKey: Uint8Array,
  token: string,
  expect: {
    method: string;
    databaseId: string;
    currentIncarnation: number;
    nowMs: number;
    /** when set, the capability MUST carry a matching session binding - a
     *  finalize request cannot be authorized by a session-unbound token
     *  (donor A3): the actor identity is part of the authority, not just a
     *  field in the request body. */
    session?: string;
    key?: string;
    bodyDigest?: string;
    bodyLength?: number;
  },
): CapabilityCheck {
  const dot = token.lastIndexOf(".");
  if (dot <= 0) return { ok: false, error: "CAPABILITY_MALFORMED" };
  const bodyBytes = base64urlDecode(token.slice(0, dot));
  const macHex = token.slice(dot + 1);
  if (bodyBytes === null || !/^[0-9a-f]{64}$/.test(macHex)) return { ok: false, error: "CAPABILITY_MALFORMED" };
  if (!bytesEqual(hmacSha256(capabilityKey, bodyBytes), fromHex(macHex))) {
    return { ok: false, error: "CAPABILITY_MAC_INVALID" };
  }
  let payload: CapabilityPayload;
  try {
    payload = JSON.parse(new TextDecoder().decode(bodyBytes)) as CapabilityPayload;
  } catch {
    return { ok: false, error: "CAPABILITY_MALFORMED" };
  }
  if (typeof payload.nonce !== "string" || typeof payload.expiresAtMs !== "number") {
    return { ok: false, error: "CAPABILITY_MALFORMED" };
  }
  if (expect.nowMs >= payload.expiresAtMs) return { ok: false, error: "CAPABILITY_EXPIRED" };
  if (payload.incarnation !== expect.currentIncarnation) return { ok: false, error: "CAPABILITY_STALE_INCARNATION" };
  if (payload.method !== expect.method) return { ok: false, error: "CAPABILITY_METHOD_MISMATCH" };
  if (payload.databaseId !== expect.databaseId) return { ok: false, error: "CAPABILITY_AUDIENCE_MISMATCH" };
  // session binding: when the route demands a session (finalize), the token
  // must carry exactly that session - a session-unbound token is refused, so
  // knowing a session id cannot be turned into write authority
  if (expect.session !== undefined && payload.session !== expect.session) {
    return { ok: false, error: "CAPABILITY_SESSION_MISMATCH" };
  }
  if (payload.key !== undefined && payload.key !== expect.key) return { ok: false, error: "CAPABILITY_KEY_MISMATCH" };
  if (payload.digest !== undefined && payload.digest !== expect.bodyDigest) {
    return { ok: false, error: "CAPABILITY_DIGEST_MISMATCH" };
  }
  if (payload.maxBytes !== undefined && (expect.bodyLength === undefined || expect.bodyLength > payload.maxBytes)) {
    return { ok: false, error: "CAPABILITY_BUDGET_EXCEEDED" };
  }
  return { ok: true, payload };
}
