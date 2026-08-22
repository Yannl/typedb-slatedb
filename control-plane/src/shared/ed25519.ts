/*
 * R5-SEC-03: Ed25519 signing/verification over WebCrypto (`crypto.subtle`).
 *
 * Both runtimes this control plane targets support the standard "Ed25519"
 * WebCrypto algorithm natively — verified empirically (2026-08-19 spike):
 *
 *   node v22.22.2                     pkcs8 import, raw public import, jwk
 *                                     export, sign/verify, generateKey: OK
 *   workerd (wrangler 4.123.0,        identical surface: OK at the pinned
 *     compatibility_date 2025-11-01)  compat date, no flag needed
 *
 * Key material conventions (fixed, so config parsing has ONE shape):
 *   - public keys travel as the 32-byte RAW Ed25519 point (64 hex chars);
 *   - private keys travel as PKCS#8 (48 bytes: the fixed 16-byte Ed25519
 *     PKCS#8 prefix + the 32-byte seed), which is what WebCrypto imports.
 *
 * WebCrypto is Promise-only, so everything here is async — which is exactly
 * why signature verification lives at the async frame (worker fetch, DO RPC
 * methods) and the synchronous core (procedures.ts) keeps receiving only
 * pre-verified payloads. The journal MAC deliberately stays on the sync
 * HMAC implementation in journal-crypto.ts (see key-config.ts, R5-SEC-08):
 * its writer and verifier are the same DO, so asymmetry buys nothing there.
 */

import { hex } from "./journal-crypto.ts";

/** The fixed PKCS#8 prefix for an Ed25519 private key: a 48-byte PKCS#8
 *  document is this prefix followed by the 32-byte seed (RFC 8410). */
const ED25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

const ED25519_PUBLIC_KEY_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;

/** Wrap a raw 32-byte Ed25519 seed as the PKCS#8 document WebCrypto imports. */
export function pkcs8FromSeed(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) throw new Error(`ed25519 seed must be 32 bytes, got ${seed.length}`);
  const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + seed.length);
  pkcs8.set(ED25519_PKCS8_PREFIX);
  pkcs8.set(seed, ED25519_PKCS8_PREFIX.length);
  return pkcs8;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

/** Verification-key import cache: keys are few (a two-slot keyring per
 *  scope) and immutable, and worker-entry resolves fresh byte arrays per
 *  request, so the cache is keyed by hex value, not object identity. */
const VERIFY_KEY_CACHE = new Map<string, Promise<CryptoKey>>();

function importEd25519PublicKey(publicKey: Uint8Array): Promise<CryptoKey> {
  if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new Error(`ed25519 public key must be ${ED25519_PUBLIC_KEY_BYTES} bytes, got ${publicKey.length}`);
  }
  const cacheKey = hex(publicKey);
  let imported = VERIFY_KEY_CACHE.get(cacheKey);
  if (imported === undefined) {
    imported = crypto.subtle.importKey("raw", toArrayBuffer(publicKey), { name: "Ed25519" }, true, ["verify"]);
    VERIFY_KEY_CACHE.set(cacheKey, imported);
  }
  return imported;
}

/** Verify `signature` over `message` under the raw public key. Returns a
 *  boolean verdict; throws only on malformed KEY material (a config bug,
 *  never wire input — signatures of any shape just fail verification). */
export async function ed25519Verify(
  publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array,
): Promise<boolean> {
  if (signature.length !== ED25519_SIGNATURE_BYTES) return false;
  const key = await importEd25519PublicKey(publicKey);
  return crypto.subtle.verify({ name: "Ed25519" }, key, toArrayBuffer(signature), toArrayBuffer(message));
}

/** Sign `message` with a PKCS#8 private key (issuer side only — no runtime
 *  posture other than local-dev ever resolves one; key-config.ts). */
export async function ed25519Sign(privateKeyPkcs8: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "pkcs8", toArrayBuffer(privateKeyPkcs8), { name: "Ed25519" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, toArrayBuffer(message)));
}

/** Derive the raw public key from a PKCS#8 private key (via jwk export —
 *  supported by node and workerd alike; used to pin the committed dev
 *  public constants to their seeds in tests, and by ephemeral issuers). */
export async function ed25519PublicKeyFromPkcs8(privateKeyPkcs8: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "pkcs8", toArrayBuffer(privateKeyPkcs8), { name: "Ed25519" }, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", key);
  const x = (jwk as JsonWebKey).x;
  if (typeof x !== "string") throw new Error("ed25519 jwk export did not carry a public point");
  const padded = x.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (x.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Generate a fresh keypair (per-run ephemeral issuers). */
export async function generateEd25519KeyPair(): Promise<{ publicKey: Uint8Array; privateKeyPkcs8: Uint8Array }> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  return {
    publicKey: new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer),
    privateKeyPkcs8: new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer),
  };
}
