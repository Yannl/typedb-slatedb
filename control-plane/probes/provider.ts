/*
 * Provider seam for the platform probe harness.
 *
 * Every probe talks EXCLUSIVELY through this fetch-like interface — no
 * probe touches the network or any global directly. That is what lets the
 * self-test controls run the identical probe code against a deterministic
 * in-process fake (mock-provider.ts), inject per-probe faults, and replay
 * the audit's exact counterexample (every response HTTP 500) to prove the
 * harness turns red.
 *
 * Services behind the seam:
 *   "r2"      — the R2 S3 API (bucket-relative paths, SigV4-signed in
 *               real mode; the request's optional `credentials` field
 *               carries temporary credentials for scope probes);
 *   "cfapi"   — Cloudflare account API (temp-credential minting, bucket
 *               lock configuration);
 *   "harness" — the deployed probe-harness Worker exposing the DO /
 *               container / gateway probe endpoints (/do/*, /ctr/*,
 *               /worker/*).
 *
 * Real mode is fail-closed: a service whose credentials are absent is
 * reported as not-capable and every probe requiring it becomes
 * PREREQUISITE_MISSING (exit 3). Credentials are never fabricated and a
 * probe is never "simulated" in real mode.
 */

import { createHash, createHmac, randomBytes } from "node:crypto";

export type ProviderService = "r2" | "cfapi" | "harness";

export interface SeamCredentials {
  keyId: string;
  secret: string;
  /** Present for temporary (STS-style) credentials. */
  sessionToken?: string;
}

export interface SeamRequest {
  service: ProviderService;
  method: string;
  /** Service-relative path, always starting with "/". May carry a query. */
  path: string;
  headers?: Record<string, string>;
  body?: Uint8Array;
  /** Override signing credentials (temporary-credential probes). */
  credentials?: SeamCredentials;
}

export interface SeamResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

export interface ProviderCapabilities {
  r2: boolean;
  cfapi: boolean;
  harness: boolean;
}

export interface PlatformProvider {
  readonly mode: "real" | "mock";
  readonly capabilities: ProviderCapabilities;
  fetch(req: SeamRequest): Promise<SeamResponse>;
}

// ---------------------------------------------------------------------------
// Shared hashing helpers (also used by the evidence writer).
// ---------------------------------------------------------------------------

export function sha256hex(data: Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Cryptographically random lowercase hex string of `bytes` bytes. */
export function randomHex(bytes: number): string {
  // Byte-wise formatting instead of Buffer#toString("hex"): the Workers
  // node-compat type shims in this tsconfig type toString() as 0-ary.
  return Array.from(randomBytes(bytes))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hmac(key: Uint8Array | string, data: string): Buffer {
  return createHmac("sha256", key).update(data, "utf8").digest();
}

export const EMPTY_BODY: Uint8Array = new Uint8Array(0);

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function text(body: Uint8Array): string {
  return new TextDecoder().decode(body);
}

export function json(body: Uint8Array): unknown {
  return JSON.parse(text(body));
}

// ---------------------------------------------------------------------------
// Real provider.
// ---------------------------------------------------------------------------

export interface RealProviderConfig {
  /** R2 S3 credentials (R2_* environment). Absent => r2 not capable. */
  r2?: {
    accountId: string;
    keyId: string;
    secret: string;
    bucket: string;
  };
  /** Cloudflare account API token (CF_API_TOKEN / CF_ACCOUNT_ID). */
  cfapi?: {
    accountId: string;
    apiToken: string;
  };
  /** Deployed probe-harness Worker (CF_PROBE_HARNESS_URL + token). */
  harness?: {
    baseUrl: string;
    apiToken: string;
  };
}

/** Read real-mode configuration strictly from the environment. */
export function realConfigFromEnv(env: NodeJS.ProcessEnv): RealProviderConfig {
  const cfg: RealProviderConfig = {};
  if (env.R2_ACCOUNT_ID && env.R2_ACCESS_KEY_ID && env.R2_SECRET_ACCESS_KEY && env.R2_PROBE_BUCKET) {
    cfg.r2 = {
      accountId: env.R2_ACCOUNT_ID,
      keyId: env.R2_ACCESS_KEY_ID,
      secret: env.R2_SECRET_ACCESS_KEY,
      bucket: env.R2_PROBE_BUCKET,
    };
  }
  if (env.CF_ACCOUNT_ID && env.CF_API_TOKEN) {
    cfg.cfapi = { accountId: env.CF_ACCOUNT_ID, apiToken: env.CF_API_TOKEN };
  }
  if (env.CF_PROBE_HARNESS_URL && env.CF_API_TOKEN) {
    cfg.harness = { baseUrl: env.CF_PROBE_HARNESS_URL.replace(/\/+$/, ""), apiToken: env.CF_API_TOKEN };
  }
  return cfg;
}

/**
 * Minimal SigV4 signer for R2's S3 API (region "auto"). This is the same
 * signing scheme the pre-audit run-r2-probes.ts used, kept verbatim in
 * behavior and extended only with session-token support for temporary
 * credentials.
 */
async function signedS3Fetch(
  host: string,
  creds: SeamCredentials,
  method: string,
  path: string,
  body: Uint8Array,
  headers: Record<string, string>,
): Promise<SeamResponse> {
  const now = new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, "").slice(0, 15) + "Z";
  const date = amzDate.slice(0, 8);
  const payloadHash = sha256hex(body);
  const h: Record<string, string> = {
    host,
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amzDate,
    ...Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])),
  };
  if (creds.sessionToken !== undefined) h["x-amz-security-token"] = creds.sessionToken;
  const [rawPath, rawQuery = ""] = path.split("?", 2);
  const canonicalQuery = rawQuery
    .split("&")
    .filter((p) => p.length > 0)
    .map((p) => {
      const [k, v = ""] = p.split("=", 2);
      return `${encodeURIComponent(decodeURIComponent(k))}=${encodeURIComponent(decodeURIComponent(v))}`;
    })
    .sort()
    .join("&");
  const signedHeaderNames = Object.keys(h).sort();
  const canonical = [
    method,
    rawPath,
    canonicalQuery,
    ...signedHeaderNames.map((k) => `${k}:${h[k].trim()}`),
    "",
    signedHeaderNames.join(";"),
    payloadHash,
  ].join("\n");
  const scope = `${date}/auto/s3/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256hex(canonical)].join("\n");
  const kSigning = hmac(hmac(hmac(hmac("AWS4" + creds.secret, date), "auto"), "s3"), "aws4_request");
  const signature = createHmac("sha256", kSigning).update(toSign).digest("hex");
  h["authorization"] =
    `AWS4-HMAC-SHA256 Credential=${creds.keyId}/${scope}, ` +
    `SignedHeaders=${signedHeaderNames.join(";")}, Signature=${signature}`;
  const res = await fetch(`https://${host}${path}`, {
    method,
    headers: h,
    body: body.length ? body : undefined,
  });
  return {
    status: res.status,
    headers: Object.fromEntries(res.headers.entries()),
    body: new Uint8Array(await res.arrayBuffer()),
  };
}

export class RealPlatformProvider implements PlatformProvider {
  readonly mode = "real" as const;
  readonly capabilities: ProviderCapabilities;
  private readonly cfg: RealProviderConfig;

  constructor(cfg: RealProviderConfig) {
    this.cfg = cfg;
    this.capabilities = {
      r2: cfg.r2 !== undefined,
      cfapi: cfg.cfapi !== undefined,
      harness: cfg.harness !== undefined,
    };
  }

  /** The probe bucket name (real mode only; probes read it from context). */
  get bucket(): string | undefined {
    return this.cfg.r2?.bucket;
  }

  async fetch(req: SeamRequest): Promise<SeamResponse> {
    switch (req.service) {
      case "r2": {
        const r2 = this.cfg.r2;
        // Fail closed: reaching here without credentials is a runner bug —
        // the probe should have been PREREQUISITE_MISSING before running.
        if (!r2) throw new Error("real provider: r2 request without R2 credentials");
        const creds = req.credentials ?? { keyId: r2.keyId, secret: r2.secret };
        return signedS3Fetch(
          `${r2.accountId}.r2.cloudflarestorage.com`,
          creds,
          req.method,
          req.path,
          req.body ?? EMPTY_BODY,
          req.headers ?? {},
        );
      }
      case "cfapi": {
        const cf = this.cfg.cfapi;
        if (!cf) throw new Error("real provider: cfapi request without CF credentials");
        const res = await fetch(
          `https://api.cloudflare.com/client/v4/accounts/${cf.accountId}${req.path}`,
          {
            method: req.method,
            headers: {
              authorization: `Bearer ${cf.apiToken}`,
              "content-type": "application/json",
              ...(req.headers ?? {}),
            },
            body: req.body && req.body.length ? req.body : undefined,
          },
        );
        return {
          status: res.status,
          headers: Object.fromEntries(res.headers.entries()),
          body: new Uint8Array(await res.arrayBuffer()),
        };
      }
      case "harness": {
        const hn = this.cfg.harness;
        if (!hn) throw new Error("real provider: harness request without CF_PROBE_HARNESS_URL");
        const res = await fetch(`${hn.baseUrl}${req.path}`, {
          method: req.method,
          headers: { authorization: `Bearer ${hn.apiToken}`, ...(req.headers ?? {}) },
          body: req.body && req.body.length ? req.body : undefined,
        });
        return {
          status: res.status,
          headers: Object.fromEntries(res.headers.entries()),
          body: new Uint8Array(await res.arrayBuffer()),
        };
      }
    }
  }
}
