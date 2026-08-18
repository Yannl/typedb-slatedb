/*
 * Semantic redaction for probe evidence (round-3 audit finding P-01).
 *
 * The pre-fix evidence writer recorded request/response headers and
 * 256-byte body previews VERBATIM. A real Cloudflare temporary-credential
 * response fits accessKeyId, secretAccessKey and sessionToken entirely
 * inside that preview, and authority/bearer tokens were captured from
 * headers. This module is the single choke point that prevents that:
 *
 *   1. headers pass a strict ALLOWLIST — a header name not on the list is
 *      dropped (its NAME is recorded, its value never). Authorization,
 *      Cookie, Set-Cookie and every token-carrying header are not on the
 *      list and structurally cannot be added to it (see the deny assert);
 *   2. a recursive semantic redactor walks parsed JSON: any key whose
 *      name matches the secret-name pattern (key/token/secret/password/
 *      credential/...) has its VALUE replaced before hashing into the
 *      evidence record or serializing;
 *   3. value-shape canaries (AWS-style access key ids, bearer tokens,
 *      JWTs, PEM private-key blocks, SigV4 signatures) are replaced
 *      wherever they appear in free text, so a secret leaking under an
 *      innocent key name is still caught;
 *   4. credential/token ENDPOINTS (classified by route, not by content)
 *      get no body preview at all — only length and sha256.
 *
 * Redaction happens BEFORE hashing/serialization: the recorded
 * body_sha256 is over the raw bytes (integrity), but every string that
 * lands in the evidence JSON has passed this module.
 */

// ---------------------------------------------------------------------------
// Header allowlist.
// ---------------------------------------------------------------------------

/**
 * Exact, lowercase header names whose VALUES may appear in evidence.
 * Everything else is dropped (name recorded, value never). This is an
 * allowlist by construction: a new secret-bearing header added by a
 * provider is invisible to evidence until someone consciously lists it.
 */
export const HEADER_ALLOWLIST: ReadonlySet<string> = new Set([
  "content-type",
  "content-length",
  "etag",
  "date",
  "last-modified",
  "retry-after",
  "accept-ranges",
  "cache-control",
  "cf-ray",
  "x-amz-request-id",
  "x-amz-checksum-sha256",
  // deterministic mock diagnostics (no secrets by construction)
  "x-mock-commit-seq",
  "x-mock-precondition",
  "x-mock-simulated",
  "x-mock-injected",
  "x-mock-composite",
  "x-shed-reason",
  "x-buffer-bound",
  "x-max-buffered-bytes",
  "x-success-receipt",
]);

/**
 * Names that must NEVER be allowlisted. This is a structural guard, not a
 * filter: if a future edit adds one of these to HEADER_ALLOWLIST the
 * module throws at load time and every probe run fails.
 */
const FOREVER_DENIED = [
  "authorization",
  "cookie",
  "set-cookie",
  "proxy-authorization",
  "x-amz-security-token",
  "x-authority-token",
  "x-api-key",
];
for (const name of FOREVER_DENIED) {
  if (HEADER_ALLOWLIST.has(name)) {
    throw new Error(`redact.ts: '${name}' must never be in the evidence header allowlist`);
  }
}

/** Any header name that looks token-bearing is denied even if allowlisted. */
const DENY_NAME_PATTERN = /token|auth|cookie|secret|credential|signature|session/i;

export interface RedactedHeaders {
  /** Allowlisted headers, values passed through the value redactor. */
  headers: Record<string, string>;
  /** Names (only) of headers whose values were withheld. */
  redacted_header_names: string[];
}

export function redactHeaders(raw: Record<string, string>): RedactedHeaders {
  const headers: Record<string, string> = {};
  const redacted: string[] = [];
  for (const [k, v] of Object.entries(raw)) {
    const name = k.toLowerCase();
    if (HEADER_ALLOWLIST.has(name) && !DENY_NAME_PATTERN.test(name)) {
      headers[name] = redactText(v);
    } else {
      redacted.push(name);
    }
  }
  redacted.sort();
  return { headers, redacted_header_names: redacted };
}

// ---------------------------------------------------------------------------
// Semantic value redaction.
// ---------------------------------------------------------------------------

/** JSON key names whose values are secrets regardless of value shape. */
export const SECRET_KEY_PATTERN =
  /key|token|secret|password|passwd|credential|authorization|cookie|signature|cert|private/i;

/**
 * Value shapes that are secrets regardless of key name. Ordered; each is
 * replaced with a typed marker. sha256 hex digests are deliberately NOT
 * matched — they are evidence, not secrets.
 */
const VALUE_SHAPES: ReadonlyArray<{ tag: string; re: RegExp }> = [
  // PEM private-key (and general PEM) blocks, including partial previews
  { tag: "pem-block", re: /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(?:-----END [A-Z0-9 ]+-----|$)/g },
  // AWS-style access key ids (Cloudflare R2 temporary credentials reuse the shape)
  { tag: "aws-key-id", re: /\b(?:AKIA|ASIA|AGPA|AROA|AIPA|ANPA)[0-9A-Z]{16}\b/g },
  // Bearer / SigV4 authorization material
  { tag: "bearer-token", re: /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/g },
  { tag: "sigv4", re: /\bAWS4-HMAC-SHA256\s+Credential=[^\s,]+(?:,\s*SignedHeaders=[^\s,]+)?(?:,\s*Signature=[^\s,]+)?/g },
  // JWTs: three dot-separated base64url segments starting with eyJ
  { tag: "jwt", re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b/g },
  // Explicit canary markers (mock credentials embed CANARY so the
  // self-test can grep the whole evidence tree for zero occurrences)
  { tag: "canary", re: /[A-Za-z0-9._-]*CANARY[A-Za-z0-9._-]*/g },
];

/** Replace every secret-shaped substring in free text. */
export function redactText(text: string): string {
  let out = text;
  for (const { tag, re } of VALUE_SHAPES) {
    out = out.replace(re, `[REDACTED:${tag}]`);
  }
  return out;
}

/**
 * Recursive semantic redactor over parsed JSON. Any value under a
 * secret-named key is replaced whole; every string is additionally passed
 * through the value-shape redactor.
 */
export function redactJsonValue(value: unknown, keyName?: string): unknown {
  if (keyName !== undefined && SECRET_KEY_PATTERN.test(keyName)) {
    return `[REDACTED:${keyName}]`;
  }
  if (typeof value === "string") return redactText(value);
  if (Array.isArray(value)) return value.map((v) => redactJsonValue(v));
  if (typeof value === "object" && value !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = redactJsonValue(v, k);
    return out;
  }
  return value;
}

// ---------------------------------------------------------------------------
// Route classification: credential endpoints get NO body preview.
// ---------------------------------------------------------------------------

export type RedactionClass = "credential-endpoint" | "generic";

/**
 * Classify a seam route. Classification is by ROUTE, never by response
 * content: a credential endpoint whose response happens to look harmless
 * still gets no preview.
 */
export function classifyRoute(service: string, path: string): RedactionClass {
  const p = path.split("?", 1)[0].toLowerCase();
  if (
    /temp-access-credentials/.test(p) ||
    /\/tokens?(\/|$)/.test(p) ||
    /credential/.test(p) ||
    /\/auth(\/|$)/.test(p)
  ) {
    return "credential-endpoint";
  }
  // The authority-token surface mints bearer-like tokens.
  if (service === "harness" && /\/do\/authority\/mint$/.test(p)) return "credential-endpoint";
  return "generic";
}

/**
 * Produce the evidence-safe preview of a body: nothing at all for
 * credential endpoints; for everything else, redacted JSON when the body
 * parses, redacted text otherwise. Applied BEFORE any serialization.
 */
export function redactedBodyPreview(body: Uint8Array, cls: RedactionClass): string {
  if (cls === "credential-endpoint") {
    return "[REDACTED:credential-endpoint — no body preview recorded]";
  }
  const raw = new TextDecoder().decode(body.subarray(0, 256));
  const printable = raw.replace(/[^\x20-\x7e\n\t]/g, "?");
  // Try semantic JSON redaction over the FULL body (a secret split by the
  // 256-byte cut must not leak its head), then preview the redacted form.
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(body));
    return JSON.stringify(redactJsonValue(parsed)).slice(0, 256);
  } catch {
    return redactText(printable);
  }
}
