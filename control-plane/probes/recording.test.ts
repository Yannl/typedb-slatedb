/*
 * Tests for the round-3 P-04 recording/deadline fixes and the P-01
 * redaction pipeline. Run with:
 *
 *   node --experimental-strip-types --test probes/recording.test.ts
 *
 * P-04: every transport failure mode — throw before send, reject
 * mid-flight, a never-resolving fetch — must leave a COMPLETE
 * intent+outcome pair in the exchange record: sanitized intent recorded
 * before dispatch, typed outcome + end time + duration recorded in a
 * finally. The pre-fix RecordingProvider recorded nothing at all unless
 * the inner fetch resolved.
 *
 * P-01 (executed mutant): a synthetic credential response stuffed with
 * canary values must produce evidence with ZERO canaries anywhere.
 */

import assert from "node:assert/strict";
import { test } from "node:test";
import { RecordingProvider } from "./evidence.ts";
import type { PlatformProvider, SeamRequest, SeamResponse } from "./provider.ts";
import { utf8 } from "./provider.ts";
import { classifyRoute, redactedBodyPreview, redactHeaders, redactJsonValue, redactText } from "./redact.ts";
import { MockPlatformProvider } from "./mock-provider.ts";

function providerOf(fetchImpl: (req: SeamRequest) => Promise<SeamResponse>): PlatformProvider {
  return {
    mode: "mock",
    capabilities: { r2: true, cfapi: true, cfapi_runtime: true, harness: true },
    fetch: fetchImpl,
  };
}

const REQ: SeamRequest = {
  service: "r2",
  method: "PUT",
  path: "/bucket/probes/n/x",
  headers: { authorization: "Bearer super-secret-value-123456", "content-type": "text/plain" },
  body: utf8("hello"),
};

// ---------------------------------------------------------------------------
// P-04: complete intent+outcome pairs on every failure mode.
// ---------------------------------------------------------------------------

function assertCompletePair(rec: RecordingProvider, outcomeType: string): void {
  assert.equal(rec.exchanges.length, 1, "exactly one exchange record");
  const ex = rec.exchanges[0];
  // Intent recorded (before dispatch): request fields present.
  assert.equal(ex.request.method, "PUT");
  assert.equal(ex.request.path, "/bucket/probes/n/x");
  assert.equal(ex.request.body_length, 5);
  // Outcome finalized in the finally: typed outcome, end time, duration.
  assert.equal(ex.outcome.type, outcomeType);
  assert.notEqual(ex.finished_at, null, "finished_at recorded");
  assert.notEqual(ex.duration_ms, null, "duration recorded");
}

test("throw-before-send leaves a complete intent+outcome pair", async () => {
  const rec = new RecordingProvider(
    providerOf(() => {
      throw new Error("synchronous connect failure");
    }),
  );
  await assert.rejects(() => rec.fetch(REQ), /synchronous connect failure/);
  assertCompletePair(rec, "error");
});

test("reject mid-flight leaves a complete intent+outcome pair", async () => {
  const rec = new RecordingProvider(
    providerOf(async () => {
      await new Promise((r) => setTimeout(r, 10));
      throw new Error("connection reset mid-flight (response may have committed server-side)");
    }),
  );
  await assert.rejects(() => rec.fetch(REQ), /mid-flight/);
  assertCompletePair(rec, "error");
});

test("never-resolving fetch is aborted by the deadline with a typed abort outcome", async () => {
  const rec = new RecordingProvider(
    providerOf(() => new Promise<SeamResponse>(() => undefined)), // never resolves
    50, // ms deadline
  );
  await assert.rejects(() => rec.fetch(REQ), /deadline 50ms exceeded/);
  assertCompletePair(rec, "abort");
});

test("successful fetch records intent, response, success outcome and duration", async () => {
  const rec = new RecordingProvider(
    providerOf(async () => ({ status: 200, headers: { etag: '"abc"' }, body: utf8("ok") })),
  );
  const res = await rec.fetch(REQ);
  assert.equal(res.status, 200);
  assertCompletePair(rec, "success");
  const ex = rec.exchanges[0];
  assert.equal(ex.response?.status, 200);
  assert.equal(ex.response?.headers["etag"], '"abc"');
});

// ---------------------------------------------------------------------------
// P-01: header allowlist and semantic redaction.
// ---------------------------------------------------------------------------

test("authorization/cookie/token headers never reach evidence, names recorded", () => {
  const out = redactHeaders({
    Authorization: "Bearer abcdefabcdefabcdefabcdef",
    Cookie: "session=deadbeef",
    "Set-Cookie": "a=b",
    "x-amz-security-token": "FQoGZXIvYXdzE...",
    "x-authority-token": "authority-token-1",
    "content-type": "application/json",
    etag: '"e"',
  });
  assert.deepEqual(Object.keys(out.headers).sort(), ["content-type", "etag"]);
  assert.deepEqual(out.redacted_header_names, [
    "authorization",
    "cookie",
    "set-cookie",
    "x-amz-security-token",
    "x-authority-token",
  ]);
  const s = JSON.stringify(out);
  assert.ok(!s.includes("Bearer abcdef"), "bearer value gone");
  assert.ok(!s.includes("deadbeef"), "cookie value gone");
});

test("recursive redactor replaces secret-named keys and secret-shaped values", () => {
  const red = redactJsonValue({
    result: {
      accessKeyId: "AKIA0123456789ABCDEF",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      sessionToken: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIx.abcdEFGH",
      nested: { password: "hunter2", note: "Bearer abcdefabcdefabcdefabcdef" },
    },
    safe: "plain text stays",
  }) as Record<string, unknown>;
  const s = JSON.stringify(red);
  assert.ok(!s.includes("AKIA0123456789ABCDEF"));
  assert.ok(!s.includes("wJalrXUtnFEMI"));
  assert.ok(!s.includes("eyJhbGciOiJIUzI1NiJ9"));
  assert.ok(!s.includes("hunter2"));
  assert.ok(!s.includes("Bearer abcdef"));
  assert.ok(s.includes("plain text stays"));
});

test("value-shape canaries caught in free text (PEM, SigV4, AWS ids)", () => {
  const s = redactText(
    "prefix -----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY----- " +
      "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260818/auto/s3/aws4_request, Signature=abc " +
      "ASIA0123456789ABCDEF suffix",
  );
  assert.ok(!s.includes("BEGIN RSA"));
  assert.ok(!s.includes("AKIAIOSFODNN7EXAMPLE"));
  assert.ok(!s.includes("ASIA0123456789ABCDEF"));
  assert.ok(s.startsWith("prefix "));
  assert.ok(s.endsWith(" suffix"));
});

test("credential endpoints are classified by route and get NO body preview", () => {
  assert.equal(classifyRoute("cfapi", "/r2/temp-access-credentials"), "credential-endpoint");
  assert.equal(classifyRoute("harness", "/do/authority/mint"), "credential-endpoint");
  assert.equal(classifyRoute("r2", "/bucket/probes/n/x"), "generic");
  const body = utf8(JSON.stringify({ result: { secretAccessKey: "MOCKSECRETCANARY000001" } }));
  const preview = redactedBodyPreview(body, "credential-endpoint");
  assert.ok(!preview.includes("CANARY"));
  assert.ok(preview.includes("no body preview"));
});

// ---------------------------------------------------------------------------
// P-01 executed mutant: synthetic credential response full of canaries
// => zero canaries anywhere in the produced evidence records.
// ---------------------------------------------------------------------------

test("MUTANT: canary credential response leaves zero canaries in evidence", async () => {
  const mock = new MockPlatformProvider();
  const rec = new RecordingProvider(mock);
  const mint = await rec.fetch({
    service: "cfapi",
    method: "POST",
    path: "/r2/temp-access-credentials",
    body: utf8(
      JSON.stringify({
        bucket: "mock-bucket",
        parentAccessKeyId: "mock-parent-access-key",
        permission: "object-read-write",
        ttlSeconds: 900,
        prefixes: ["probes/t/"],
      }),
    ),
  });
  assert.equal(mint.status, 200);
  // The RESPONSE itself carries the canaries (that is the point) ...
  const raw = new TextDecoder().decode(mint.body);
  assert.ok(raw.includes("CANARY"), "mock mint really returns canary credentials");
  // ... but the EVIDENCE record must not contain a single one.
  const evidence = JSON.stringify(rec.exchanges);
  assert.ok(!evidence.includes("CANARY"), "no canary anywhere in evidence");
  assert.ok(!evidence.includes("AKIA"), "no AWS-style key id in evidence");
  assert.ok(!/Bearer\s+[A-Za-z0-9]/.test(evidence), "no bearer token in evidence");
});
