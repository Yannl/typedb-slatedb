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
 *               lock configuration). Requests carry a PRINCIPAL:
 *               "admin" (bootstrap/admin token) or "runtime" (a separate,
 *               deliberately less-privileged token) — round-3 P-02
 *               requires the two principals to be distinct credentials,
 *               not a header pretending to be one;
 *   "harness" — the deployed probe-harness Worker exposing the DO /
 *               container / gateway probe endpoints (/do/*, /ctr/*,
 *               /worker/*).
 *
 * Round-3 P-01 credential hygiene, enforced here fail-closed:
 *   - the harness has its OWN token (CF_PROBE_HARNESS_TOKEN); reusing the
 *     Cloudflare account token for an arbitrary harness URL is a hard
 *     configuration error (equality is rejected), because that URL is
 *     operator-supplied and a typo would ship the account token to it;
 *   - the harness URL must be HTTPS and its hostname must be on the
 *     exact, operator-approved allowlist (CF_PROBE_HARNESS_ALLOWED_HOSTS);
 *   - real fetches never follow redirects (redirect:"manual"), so a
 *     cross-origin 30x can never re-send a bearer token elsewhere;
 *   - every real fetch carries an AbortSignal deadline (P-04).
 *
 * Real mode is fail-closed: a service whose credentials are absent is
 * reported as not-capable and every probe requiring it becomes
 * PREREQUISITE_MISSING (exit 3). Credentials are never fabricated and a
 * probe is never "simulated" in real mode.
 */

import { createHash, createHmac, randomBytes } from "node:crypto";

export type ProviderService = "r2" | "cfapi" | "harness";
export type CfApiPrincipal = "admin" | "runtime";

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
  /**
   * cfapi only: which principal's token signs the request. Defaults to
   * "admin". "runtime" uses the separate runtime token (real mode) /
   * runtime identity (mock) — P-R2-03's unauthorized-mutation check is a
   * real principal difference, not a spoofable header.
   */
  principal?: CfApiPrincipal;
  /** Per-request deadline in ms; the provider aborts the fetch after it. */
  deadlineMs?: number;
}

export interface SeamResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

export interface ProviderCapabilities {
  r2: boolean;
  cfapi: boolean;
  /** Separate runtime-principal token for cfapi (P-R2-03's real-mode check). */
  cfapi_runtime: boolean;
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
// Real provider configuration (P-01: separate principals, hard rejections).
// ---------------------------------------------------------------------------

export interface RealProviderConfig {
  /** R2 S3 credentials (R2_* environment). Absent => r2 not capable. */
  r2?: {
    accountId: string;
    keyId: string;
    secret: string;
    bucket: string;
  };
  /**
   * Cloudflare account API. adminApiToken is the BOOTSTRAP/ADMIN
   * principal (mints credentials, configures locks); runtimeApiToken is
   * the deliberately less-privileged RUNTIME principal used to prove
   * runtime cannot alter policy. They must be different secrets.
   */
  cfapi?: {
    accountId: string;
    adminApiToken: string;
    runtimeApiToken?: string;
  };
  /** Deployed probe-harness Worker (CF_PROBE_HARNESS_URL + its OWN token). */
  harness?: {
    baseUrl: string;
    apiToken: string;
    /** Exact approved hostnames; the harness URL's host must be one of them. */
    allowedHosts: string[];
  };
}

/** Thrown for configurations that must never be run, only fixed. */
export class ProviderConfigError extends Error {}

/**
 * Read real-mode configuration strictly from the environment.
 * Misconfigurations that could leak credentials are HARD errors (throw),
 * never a silent "not capable".
 */
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
    cfg.cfapi = { accountId: env.CF_ACCOUNT_ID, adminApiToken: env.CF_API_TOKEN };
    if (env.CF_RUNTIME_API_TOKEN) {
      if (env.CF_RUNTIME_API_TOKEN === env.CF_API_TOKEN) {
        throw new ProviderConfigError(
          "CF_RUNTIME_API_TOKEN equals CF_API_TOKEN — the runtime principal must be a " +
            "genuinely separate, less-privileged credential; refusing to run",
        );
      }
      cfg.cfapi.runtimeApiToken = env.CF_RUNTIME_API_TOKEN;
    }
  }
  if (env.CF_PROBE_HARNESS_URL) {
    // The harness gets its OWN token. Reusing the account API token for an
    // arbitrary operator-supplied URL is the exact leak P-01 names.
    const token = env.CF_PROBE_HARNESS_TOKEN;
    if (!token) {
      throw new ProviderConfigError(
        "CF_PROBE_HARNESS_URL is set but CF_PROBE_HARNESS_TOKEN is not — the harness " +
          "requires its own token (CF_API_TOKEN is never sent to the harness)",
      );
    }
    if (env.CF_API_TOKEN !== undefined && token === env.CF_API_TOKEN) {
      throw new ProviderConfigError(
        "CF_PROBE_HARNESS_TOKEN equals CF_API_TOKEN — refusing to send the account " +
          "API token to the probe harness URL",
      );
    }
    let url: URL;
    try {
      url = new URL(env.CF_PROBE_HARNESS_URL);
    } catch {
      throw new ProviderConfigError(`CF_PROBE_HARNESS_URL is not a valid URL: ${env.CF_PROBE_HARNESS_URL}`);
    }
    if (url.protocol !== "https:") {
      throw new ProviderConfigError("CF_PROBE_HARNESS_URL must be https:// — bearer tokens never travel plaintext");
    }
    const allowedHosts = (env.CF_PROBE_HARNESS_ALLOWED_HOSTS ?? "")
      .split(",")
      .map((h) => h.trim().toLowerCase())
      .filter((h) => h.length > 0);
    if (allowedHosts.length === 0) {
      throw new ProviderConfigError(
        "CF_PROBE_HARNESS_ALLOWED_HOSTS is required with CF_PROBE_HARNESS_URL: an exact " +
          "approved-hostname allowlist, never an implicit trust of whatever URL is set",
      );
    }
    if (!allowedHosts.includes(url.hostname.toLowerCase())) {
      throw new ProviderConfigError(
        `CF_PROBE_HARNESS_URL host '${url.hostname}' is not on the approved allowlist ` +
          `(${allowedHosts.join(", ")}) — refusing to send credentials to it`,
      );
    }
    cfg.harness = {
      baseUrl: env.CF_PROBE_HARNESS_URL.replace(/\/+$/, ""),
      apiToken: token,
      allowedHosts,
    };
  }
  return cfg;
}

/** Default per-request deadline when the caller does not set one (P-04). */
export const DEFAULT_REQUEST_DEADLINE_MS = 30_000;

function abortSignalFor(deadlineMs: number | undefined): AbortSignal {
  return AbortSignal.timeout(deadlineMs ?? DEFAULT_REQUEST_DEADLINE_MS);
}

/**
 * Minimal SigV4 signer for R2's S3 API (region "auto"). This is the same
 * signing scheme the pre-audit run-r2-probes.ts used, kept verbatim in
 * behavior and extended with session-token support and a request deadline.
 */
async function signedS3Fetch(
  host: string,
  creds: SeamCredentials,
  method: string,
  path: string,
  body: Uint8Array,
  headers: Record<string, string>,
  deadlineMs: number | undefined,
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
    redirect: "manual", // never re-send signed material across a redirect
    signal: abortSignalFor(deadlineMs),
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
      cfapi_runtime: cfg.cfapi?.runtimeApiToken !== undefined,
      harness: cfg.harness !== undefined,
    };
  }

  /** The probe bucket name (real mode only; probes read it from context). */
  get bucket(): string | undefined {
    return this.cfg.r2?.bucket;
  }

  /** Parent R2 access key id (temp-credential minting names its parent). */
  get parentAccessKeyId(): string | undefined {
    return this.cfg.r2?.keyId;
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
          req.deadlineMs,
        );
      }
      case "cfapi": {
        const cf = this.cfg.cfapi;
        if (!cf) throw new Error("real provider: cfapi request without CF credentials");
        const principal: CfApiPrincipal = req.principal ?? "admin";
        let token: string;
        if (principal === "admin") {
          token = cf.adminApiToken;
        } else {
          if (cf.runtimeApiToken === undefined) {
            // Never silently substitute the admin token for the runtime
            // principal — the whole point is that they are different.
            throw new Error(
              "real provider: runtime-principal cfapi request without CF_RUNTIME_API_TOKEN " +
                "(the probe should have been PREREQUISITE_MISSING)",
            );
          }
          token = cf.runtimeApiToken;
        }
        const res = await fetch(
          `https://api.cloudflare.com/client/v4/accounts/${cf.accountId}${req.path}`,
          {
            method: req.method,
            headers: {
              authorization: `Bearer ${token}`,
              "content-type": "application/json",
              ...(req.headers ?? {}),
            },
            body: req.body && req.body.length ? req.body : undefined,
            redirect: "manual",
            signal: abortSignalFor(req.deadlineMs),
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
        // Defense in depth: re-validate the destination host on EVERY
        // request, not only at configuration time.
        const target = new URL(`${hn.baseUrl}${req.path}`);
        if (target.protocol !== "https:" || !hn.allowedHosts.includes(target.hostname.toLowerCase())) {
          throw new Error(`real provider: harness request escapes the approved host allowlist (${target.hostname})`);
        }
        const res = await fetch(target, {
          method: req.method,
          headers: { authorization: `Bearer ${hn.apiToken}`, ...(req.headers ?? {}) },
          body: req.body && req.body.length ? req.body : undefined,
          redirect: "manual", // a cross-origin redirect must never carry the token
          signal: abortSignalFor(req.deadlineMs),
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
