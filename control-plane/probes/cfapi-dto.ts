/*
 * Typed DTOs + runtime validators for the two Cloudflare account-API
 * surfaces the probes exercise (round-3 audit finding P-02).
 *
 * Shapes are transcribed from the CURRENT official API schemas
 * (verified 2026-08-18):
 *
 *   POST /accounts/{account_id}/r2/temp-access-credentials
 *     https://developers.cloudflare.com/api/resources/r2/subresources/temporary_credentials/methods/create/
 *     request:  { bucket, parentAccessKeyId, permission (SINGULAR enum),
 *                 ttlSeconds, objects?, prefixes? }
 *     response: { errors[], messages[], success,
 *                 result: { accessKeyId, secretAccessKey, sessionToken } }
 *
 *   GET/PUT /accounts/{account_id}/r2/buckets/{bucket_name}/lock
 *     https://developers.cloudflare.com/api/resources/r2/subresources/buckets/subresources/locks/
 *     rules: [{ id, enabled, prefix?, condition:
 *               {type:"Age",maxAgeSeconds} | {type:"Date",date} | {type:"Indefinite"} }]
 *
 * There is NO revoke-parent route in the official API: revoking the
 * parent means deleting/rotating the parent R2 access key itself, which
 * would destroy the harness's own credentials mid-run — so the probe no
 * longer pretends to exercise it (the pre-fix code called a nonexistent
 * endpoint that only its own mock implemented).
 *
 * The mock provider serves EXACTLY these shapes and validates incoming
 * requests against them, so the mock lane exercises the real wire format.
 */

// ---------------------------------------------------------------------------
// Temporary credentials.
// ---------------------------------------------------------------------------

export const TEMP_CREDENTIAL_PERMISSIONS = [
  "admin-read-write",
  "admin-read-only",
  "object-read-write",
  "object-read-only",
] as const;
export type TempCredentialPermission = (typeof TEMP_CREDENTIAL_PERMISSIONS)[number];

export interface TempCredentialsCreateRequest {
  bucket: string;
  parentAccessKeyId: string;
  /** SINGULAR permission enum — the old {permissions:["put","get"]} array shape does not exist. */
  permission: TempCredentialPermission;
  ttlSeconds: number;
  objects?: string[];
  prefixes?: string[];
}

export interface CloudflareEnvelope<T> {
  errors: Array<{ code?: number; message?: string }>;
  messages: unknown[];
  success: boolean;
  result: T;
}

export interface TempCredentialsResult {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
}

function fail(context: string, detail: string): never {
  throw new Error(`cfapi DTO validation failed (${context}): ${detail}`);
}

function asObject(v: unknown, context: string): Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) fail(context, "not a JSON object");
  return v as Record<string, unknown>;
}

function asStringArray(v: unknown, context: string): string[] {
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) fail(context, "not a string array");
  return v as string[];
}

/** Validate an incoming create request (used by the MOCK server side). */
export function validateTempCredentialsCreateRequest(v: unknown): TempCredentialsCreateRequest {
  const o = asObject(v, "temp-credentials request");
  if (typeof o.bucket !== "string" || o.bucket.length === 0) fail("temp-credentials request", "bucket missing");
  if (typeof o.parentAccessKeyId !== "string" || o.parentAccessKeyId.length === 0) {
    fail("temp-credentials request", "parentAccessKeyId missing (required by the current API)");
  }
  if (!TEMP_CREDENTIAL_PERMISSIONS.includes(o.permission as TempCredentialPermission)) {
    fail(
      "temp-credentials request",
      `permission must be one of ${TEMP_CREDENTIAL_PERMISSIONS.join("|")} (SINGULAR), got ${JSON.stringify(o.permission)}`,
    );
  }
  if ("permissions" in o) {
    fail("temp-credentials request", "'permissions' array is not the current API shape; use singular 'permission'");
  }
  if (typeof o.ttlSeconds !== "number" || !Number.isFinite(o.ttlSeconds) || o.ttlSeconds <= 0) {
    fail("temp-credentials request", "ttlSeconds must be a positive number");
  }
  const req: TempCredentialsCreateRequest = {
    bucket: o.bucket,
    parentAccessKeyId: o.parentAccessKeyId,
    permission: o.permission as TempCredentialPermission,
    ttlSeconds: o.ttlSeconds,
  };
  if (o.objects !== undefined) req.objects = asStringArray(o.objects, "temp-credentials request objects");
  if (o.prefixes !== undefined) req.prefixes = asStringArray(o.prefixes, "temp-credentials request prefixes");
  return req;
}

/** Validate a create response (used by the PROBE client side, mock and real). */
export function validateTempCredentialsResponse(v: unknown): CloudflareEnvelope<TempCredentialsResult> {
  const o = asObject(v, "temp-credentials response");
  if (typeof o.success !== "boolean") fail("temp-credentials response", "missing success flag");
  if (!Array.isArray(o.errors)) fail("temp-credentials response", "missing errors[]");
  if (!Array.isArray(o.messages)) fail("temp-credentials response", "missing messages[]");
  const result = asObject(o.result, "temp-credentials response result");
  for (const k of ["accessKeyId", "secretAccessKey", "sessionToken"] as const) {
    if (typeof result[k] !== "string" || (result[k] as string).length === 0) {
      fail("temp-credentials response", `result.${k} missing (credentials live INSIDE the result envelope)`);
    }
  }
  return o as unknown as CloudflareEnvelope<TempCredentialsResult>;
}

// ---------------------------------------------------------------------------
// Bucket locks.
// ---------------------------------------------------------------------------

export type BucketLockCondition =
  | { type: "Age"; maxAgeSeconds: number }
  | { type: "Date"; date: string }
  | { type: "Indefinite" };

export interface BucketLockRule {
  id: string;
  enabled: boolean;
  condition: BucketLockCondition;
  prefix?: string;
}

export interface BucketLockRulesBody {
  rules: BucketLockRule[];
}

export function validateBucketLockCondition(v: unknown): BucketLockCondition {
  const o = asObject(v, "bucket-lock condition");
  switch (o.type) {
    case "Age":
      if (typeof o.maxAgeSeconds !== "number" || o.maxAgeSeconds <= 0) {
        fail("bucket-lock condition", "Age condition requires positive maxAgeSeconds");
      }
      return { type: "Age", maxAgeSeconds: o.maxAgeSeconds };
    case "Date":
      if (typeof o.date !== "string" || Number.isNaN(Date.parse(o.date))) {
        fail("bucket-lock condition", "Date condition requires an ISO date string");
      }
      return { type: "Date", date: o.date };
    case "Indefinite":
      return { type: "Indefinite" };
    default:
      fail("bucket-lock condition", `unknown condition type ${JSON.stringify(o.type)} (Age|Date|Indefinite)`);
  }
}

export function validateBucketLockRule(v: unknown): BucketLockRule {
  const o = asObject(v, "bucket-lock rule");
  if (typeof o.id !== "string" || o.id.length === 0) fail("bucket-lock rule", "id (string) is required");
  if (typeof o.enabled !== "boolean") fail("bucket-lock rule", "enabled (boolean) is required");
  for (const legacy of ["allowOverwrite", "allowDelete"]) {
    if (legacy in o) fail("bucket-lock rule", `'${legacy}' is not a Cloudflare lock-rule field`);
  }
  const rule: BucketLockRule = {
    id: o.id,
    enabled: o.enabled,
    condition: validateBucketLockCondition(o.condition),
  };
  if (o.prefix !== undefined) {
    if (typeof o.prefix !== "string") fail("bucket-lock rule", "prefix must be a string");
    rule.prefix = o.prefix;
  }
  return rule;
}

export function validateBucketLockRulesBody(v: unknown): BucketLockRulesBody {
  const o = asObject(v, "bucket-lock rules body");
  if (!Array.isArray(o.rules)) fail("bucket-lock rules body", "rules[] is required");
  const rules = o.rules.map(validateBucketLockRule);
  const ids = new Set(rules.map((r) => r.id));
  if (ids.size !== rules.length) fail("bucket-lock rules body", "rule ids must be unique");
  return { rules };
}

/** Validate a GET .../lock response envelope. */
export function validateBucketLockGetResponse(v: unknown): CloudflareEnvelope<BucketLockRulesBody> {
  const o = asObject(v, "bucket-lock GET response");
  if (typeof o.success !== "boolean") fail("bucket-lock GET response", "missing success flag");
  if (!Array.isArray(o.errors)) fail("bucket-lock GET response", "missing errors[]");
  if (!Array.isArray(o.messages)) fail("bucket-lock GET response", "missing messages[]");
  const result = validateBucketLockRulesBody(o.result);
  return { ...(o as object), result } as CloudflareEnvelope<BucketLockRulesBody>;
}

/**
 * Key-order-independent canonical form of a lock-rule list. The single
 * definition shared by the P-R2-03 probe assertions and the runner's
 * lock-baseline capture/restore (R4-CF-00), so "same policy" cannot mean
 * two different things in the probe and in cleanup.
 */
export function canonicalRules(rules: ReadonlyArray<BucketLockRule>): string {
  return JSON.stringify(
    rules.map((r) => ({
      id: r.id,
      enabled: r.enabled,
      prefix: r.prefix ?? null,
      condition_type: r.condition.type,
      condition_max_age: r.condition.type === "Age" ? r.condition.maxAgeSeconds : null,
      condition_date: r.condition.type === "Date" ? r.condition.date : null,
    })),
  );
}
