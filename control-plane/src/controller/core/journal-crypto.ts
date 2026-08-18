/*
 * F8 (authenticated control journal): synchronous SHA-256 + HMAC-SHA-256 +
 * canonical JSON, runtime-agnostic.
 *
 * Why not crypto.subtle: journal entries are hashed and signed INSIDE the
 * single synchronous finalisation transaction (inv. 151 - no await between
 * validation and commit), and SubtleCrypto is Promise-only in both node and
 * workerd. node:crypto is sync but does not exist on workerd. So the core
 * carries its own implementation - pure, allocation-light, and pinned by
 * FIPS 180-4 / RFC 4231 test vectors in the suite (any deviation fails the
 * known-answer tests, so a transcription bug cannot ship silently).
 */

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/** SHA-256 (FIPS 180-4) of the concatenation of the given byte chunks. */
export function sha256(...chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const chunk of chunks) total += chunk.length;
  // message + 0x80 + zero pad + 64-bit bit length, padded to a 64-byte block
  const padded = new Uint8Array(((total + 8) >> 6 << 6) + 64);
  let offset = 0;
  for (const chunk of chunks) {
    padded.set(chunk, offset);
    offset += chunk.length;
  }
  padded[total] = 0x80;
  const view = new DataView(padded.buffer);
  view.setBigUint64(padded.length - 8, BigInt(total) * 8n);

  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const w = new Uint32Array(64);
  for (let block = 0; block < padded.length; block += 64) {
    for (let t = 0; t < 16; t++) w[t] = view.getUint32(block + t * 4);
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
      const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (hh + S1 + ch + K[t] + w[t]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) | 0;
      hh = g; g = f; f = e; e = (d + temp1) | 0;
      d = c; c = b; b = a; a = (temp1 + temp2) | 0;
    }
    h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
    h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
  }
  const digest = new Uint8Array(32);
  const digestView = new DataView(digest.buffer);
  for (let i = 0; i < 8; i++) digestView.setUint32(i * 4, h[i]);
  return digest;
}

function rotr(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

/** HMAC-SHA-256 (RFC 2104; vectors RFC 4231). */
export function hmacSha256(key: Uint8Array, ...message: Uint8Array[]): Uint8Array {
  const normalized = key.length > 64 ? sha256(key) : key;
  const inner = new Uint8Array(64).fill(0x36);
  const outer = new Uint8Array(64).fill(0x5c);
  for (let i = 0; i < normalized.length; i++) {
    inner[i] ^= normalized[i];
    outer[i] ^= normalized[i];
  }
  return sha256(outer, sha256(inner, ...message));
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

const UTF8_ENCODER = new TextEncoder();

export function utf8(text: string): Uint8Array {
  return UTF8_ENCODER.encode(text);
}

export function hex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

export function fromHex(text: string): Uint8Array {
  if (!/^([0-9a-fA-F]{2})*$/.test(text)) throw new Error(`invalid hex: ${text.slice(0, 32)}`);
  const bytes = new Uint8Array(text.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

/**
 * Canonical deterministic JSON (F8): lexicographically sorted object keys,
 * no whitespace, and ONLY JSON-representable values - bigint and undefined
 * throw (sequence values must already be encoded as decimal strings by the
 * caller; silently coercing here would create two encodings of one value),
 * as do NaN/Infinity. Two semantically equal bodies therefore serialize to
 * byte-identical text, which is what the hash chain signs.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new Error("canonicalJson: non-finite number");
      return JSON.stringify(value);
    case "bigint":
      throw new Error("canonicalJson: bigint must be pre-encoded as a decimal string");
    case "object":
      if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
      return `{${Object.keys(value as Record<string, unknown>)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`)
        .join(",")}}`;
    default:
      throw new Error(`canonicalJson: unsupported ${typeof value}`);
  }
}
