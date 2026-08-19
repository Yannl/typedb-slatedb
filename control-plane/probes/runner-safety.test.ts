/*
 * Round-4 destructive-stop mutants (R4-CF-00, R4-CF-01, R4-CF-03).
 *
 * The round-4 audit dynamically reproduced the worst possible probe-runner
 * defect: a real-mode run with a RED preflight (forbidden bucket name
 * `actual-production-data`, no envelope, no nonce) still issued exactly one
 * network request — `PUT .../lock {"rules":[]}` — from its unconditional
 * cleanup, i.e. a refusal path that erases every Bucket Lock on a refused
 * target. These tests re-run that exact scenario with the global fetch
 * intercepted and require ZERO escaped calls, plus the envelope-budget,
 * lock-baseline-conflict, post-deadline-refusal and seal-scanner mutants
 * the audit demanded.
 *
 * Run: node --experimental-strip-types --test probes/runner-safety.test.ts
 */

import { strict as assert } from "node:assert";
import { afterEach, beforeEach, test } from "node:test";
import { mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { main } from "./run-platform-probes.ts";
import { budgetFromEnvelope, EnvelopeExceededError, MeteredProvider, RefusedProvider, ZeroAuthorityError } from "./envelope.ts";
import { captureLockBaseline, restoreLockBaseline } from "./lock-baseline.ts";
import { EvidenceBundle, RecordingProvider, SealViolationError } from "./evidence.ts";
import type { PlatformProvider, SeamRequest, SeamResponse } from "./provider.ts";
import { utf8 } from "./provider.ts";

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

const PROBE_ENV_KEYS = [
  "R2_ACCOUNT_ID",
  "R2_ACCESS_KEY_ID",
  "R2_SECRET_ACCESS_KEY",
  "R2_PROBE_BUCKET",
  "CF_ACCOUNT_ID",
  "CF_API_TOKEN",
  "CF_RUNTIME_API_TOKEN",
  "CF_PROBE_HARNESS_URL",
  "CF_PROBE_HARNESS_TOKEN",
  "CF_PROBE_HARNESS_ALLOWED_HOSTS",
  "R2_PROBE_OWNERSHIP_NONCE",
];

let savedEnv: Record<string, string | undefined> = {};
let savedFetch: typeof globalThis.fetch;
let scratch: string;

beforeEach(() => {
  savedEnv = Object.fromEntries(PROBE_ENV_KEYS.map((k) => [k, process.env[k]]));
  savedFetch = globalThis.fetch;
  scratch = mkdtempSync(join(tmpdir(), "probe-safety-"));
});

afterEach(() => {
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  globalThis.fetch = savedFetch;
  rmSync(scratch, { recursive: true, force: true });
});

function envelope(limits: Record<string, number>): string {
  const path = join(scratch, "envelope.json");
  writeFileSync(
    path,
    JSON.stringify({
      approved_by: "test-owner",
      approved_at: new Date().toISOString(),
      limits: {
        max_total_requests: 1000,
        max_total_bytes_written: 10_000_000,
        max_run_seconds: 900,
        max_probe_seconds: 60,
        max_request_seconds: 10,
        max_cost_usd_cents: 100,
        ...limits,
      },
    }),
  );
  return path;
}

/** A scriptable in-memory provider for baseline/meter tests. */
class ScriptedProvider implements PlatformProvider {
  readonly mode = "real" as const;
  readonly capabilities = { r2: true, cfapi: true, cfapi_runtime: true, harness: true };
  readonly calls: SeamRequest[] = [];
  private readonly handler: (req: SeamRequest) => SeamResponse;
  constructor(handler: (req: SeamRequest) => SeamResponse) {
    this.handler = handler;
  }
  async fetch(req: SeamRequest): Promise<SeamResponse> {
    this.calls.push(req);
    return this.handler(req);
  }
}

function jsonRes(status: number, body: unknown): SeamResponse {
  return { status, headers: {}, body: utf8(JSON.stringify(body)) };
}

const lockEnvelope = (rules: unknown[]): unknown => ({ success: true, errors: [], messages: [], result: { rules } });

// ---------------------------------------------------------------------------
// R4-CF-00: the audit's exact destructive mutant, now required to be inert.
// ---------------------------------------------------------------------------

test("RED preflight makes ZERO external calls — cleanup included (the audit's reproduced mutant)", async () => {
  // Complete dummy credentials + the audit's forbidden bucket name; no
  // envelope, no ownership nonce, no harness approval => preflight RED.
  process.env.R2_ACCOUNT_ID = "acct";
  process.env.R2_ACCESS_KEY_ID = "AKIDDUMMYDUMMYDUMMY0";
  process.env.R2_SECRET_ACCESS_KEY = "dummy-secret-dummy-secret-dummy!";
  process.env.R2_PROBE_BUCKET = "actual-production-data";
  process.env.CF_ACCOUNT_ID = "acct";
  process.env.CF_API_TOKEN = "dummy-admin-token-dummy-admin!";
  process.env.CF_RUNTIME_API_TOKEN = "dummy-runtime-token-dummy-run!";
  delete process.env.CF_PROBE_HARNESS_URL;
  delete process.env.R2_PROBE_OWNERSHIP_NONCE;

  let escaped = 0;
  globalThis.fetch = (async () => {
    escaped += 1;
    throw new Error("network escape: a RED-preflight run must never dispatch a request");
  }) as typeof globalThis.fetch;

  const code = await main(["--evidence-root", join(scratch, "evidence")]);
  assert.equal(code, 3, "RED preflight run exits 3 (PREREQUISITE_MISSING)");
  assert.equal(escaped, 0, "ZERO network requests may escape a refused run — the audit captured exactly one PUT .../lock rules:[] here before the fix");
});

test("RefusedProvider throws before any I/O and counts the attempt", async () => {
  const refused = new RefusedProvider("test");
  await assert.rejects(
    refused.fetch({ service: "cfapi", method: "PUT", path: "/r2/buckets/x/lock", body: utf8("{}") }),
    ZeroAuthorityError,
  );
  assert.equal(refused.attempts, 1);
});

// ---------------------------------------------------------------------------
// R4-CF-00: lock baseline snapshot / conservative restore.
// ---------------------------------------------------------------------------

const OPERATOR_RULES = [
  { id: "operator-retention", enabled: true, prefix: "wal/", condition: { type: "Indefinite" } },
  { id: "operator-age", enabled: true, prefix: "cold/", condition: { type: "Age", maxAgeSeconds: 3600 } },
];

test("cleanup restores the exact captured baseline; unrelated operator rules survive", async () => {
  let rules: unknown[] = [...OPERATOR_RULES];
  const provider = new ScriptedProvider((req) => {
    if (req.method === "GET") return jsonRes(200, lockEnvelope(rules));
    if (req.method === "PUT") {
      rules = (JSON.parse(new TextDecoder().decode(req.body)) as { rules: unknown[] }).rules;
      return jsonRes(200, lockEnvelope(rules));
    }
    return jsonRes(404, {});
  });
  const baseline = await captureLockBaseline((r) => provider.fetch(r), "bkt");
  assert.equal(baseline.rules.length, 2);
  // The run adds its own rule (read-modify-write, as P-R2-03 now does).
  rules = [...rules, { id: "probe-lock-run1", enabled: true, prefix: "probes/run1/", condition: { type: "Indefinite" } }];
  const restore = await restoreLockBaseline((r) => provider.fetch(r), baseline, "run1");
  assert.equal(restore.status, "executed", restore.detail);
  assert.equal((rules as { id: string }[]).length, 2, "exactly the operator rules remain");
  assert.deepEqual(
    (rules as { id: string }[]).map((r) => r.id).sort(),
    ["operator-age", "operator-retention"],
    "cleanup never used rules:[] — the operator rules survived",
  );
});

test("a concurrent operator rule change is a CONFLICT: restore refuses to overwrite", async () => {
  let rules: unknown[] = [...OPERATOR_RULES];
  let putCount = 0;
  const provider = new ScriptedProvider((req) => {
    if (req.method === "GET") return jsonRes(200, lockEnvelope(rules));
    if (req.method === "PUT") {
      putCount += 1;
      return jsonRes(200, lockEnvelope(rules));
    }
    return jsonRes(404, {});
  });
  const baseline = await captureLockBaseline((r) => provider.fetch(r), "bkt");
  // Mid-run: the run adds its rule AND an operator adds a new one.
  rules = [
    ...rules,
    { id: "probe-lock-run1", enabled: true, prefix: "probes/run1/", condition: { type: "Indefinite" } },
    { id: "operator-new-mid-run", enabled: true, prefix: "hot/", condition: { type: "Indefinite" } },
  ];
  const restore = await restoreLockBaseline((r) => provider.fetch(r), baseline, "run1");
  assert.equal(restore.status, "conflict");
  assert.equal(putCount, 0, "a conflicted restore writes NOTHING");
});

// ---------------------------------------------------------------------------
// R4-CF-01: the envelope is an enforced side-effect budget.
// ---------------------------------------------------------------------------

test("MeteredProvider refuses over-budget requests BEFORE dispatch", async () => {
  const inner = new ScriptedProvider(() => jsonRes(200, {}));
  const meter = new MeteredProvider(inner, {
    maxTotalRequests: 1,
    maxTotalBytesWritten: 1000,
    runDeadlineAtMs: Date.now() + 60_000,
    maxRequestMs: 1000,
  });
  await meter.fetch({ service: "r2", method: "GET", path: "/b/x" });
  await assert.rejects(meter.fetch({ service: "r2", method: "GET", path: "/b/y" }), EnvelopeExceededError);
  assert.equal(inner.calls.length, 1, "the over-budget call never reached the provider");
});

test("MeteredProvider refuses a write that would exceed the byte budget", async () => {
  const inner = new ScriptedProvider(() => jsonRes(200, {}));
  const meter = new MeteredProvider(inner, {
    maxTotalRequests: 10,
    maxTotalBytesWritten: 4,
    runDeadlineAtMs: Date.now() + 60_000,
    maxRequestMs: 1000,
  });
  await assert.rejects(
    meter.fetch({ service: "r2", method: "PUT", path: "/b/x", body: utf8("12345") }),
    EnvelopeExceededError,
  );
  assert.equal(inner.calls.length, 0);
});

test("MeteredProvider refuses every call after the run deadline", async () => {
  const inner = new ScriptedProvider(() => jsonRes(200, {}));
  const meter = new MeteredProvider(inner, {
    maxTotalRequests: 10,
    maxTotalBytesWritten: 1000,
    runDeadlineAtMs: Date.now() - 1, // already past
    maxRequestMs: 1000,
  });
  await assert.rejects(meter.fetch({ service: "r2", method: "GET", path: "/b/x" }), EnvelopeExceededError);
  assert.equal(inner.calls.length, 0, "post-deadline calls never dispatch");
});

test("MeteredProvider journals write INTENT before dispatch (timeout-after-commit safety)", async () => {
  const inner = new ScriptedProvider(() => {
    throw new Error("simulated network loss after possible commit");
  });
  const meter = new MeteredProvider(inner, {
    maxTotalRequests: 10,
    maxTotalBytesWritten: 1000,
    runDeadlineAtMs: Date.now() + 60_000,
    maxRequestMs: 1000,
  });
  await assert.rejects(meter.fetch({ service: "r2", method: "PUT", path: "/b/probes/r/k?x=1", body: utf8("v") }));
  assert.ok(meter.attemptedWrites.has("/b/probes/r/k"), "the lost-response write is journaled for cleanup");
});

test("budgetFromEnvelope rejects garbage limits fail-closed", () => {
  assert.throws(() => budgetFromEnvelope({ max_total_requests: -1 }, Date.now()), EnvelopeExceededError);
  assert.throws(() => budgetFromEnvelope({}, Date.now()), EnvelopeExceededError);
});

test("real run under envelope max_total_requests=6 is bounded and nonzero", async () => {
  // GREEN preflight (valid nonce/bucket/envelope) but a tiny request
  // budget: the run must fail bounded (every probe red or prerequisite),
  // never hang, never exit 0 — and the interceptor bounds actual calls.
  process.env.R2_ACCOUNT_ID = "acct";
  process.env.R2_ACCESS_KEY_ID = "AKIDDUMMYDUMMYDUMMY0";
  process.env.R2_SECRET_ACCESS_KEY = "dummy-secret-dummy-secret-dummy!";
  process.env.R2_PROBE_OWNERSHIP_NONCE = "testnonce1";
  process.env.R2_PROBE_BUCKET = "typedb-probe-testnonce1";
  process.env.CF_ACCOUNT_ID = "acct";
  process.env.CF_API_TOKEN = "dummy-admin-token-dummy-admin!";
  process.env.CF_RUNTIME_API_TOKEN = "dummy-runtime-token-dummy-run!";
  process.env.CF_PROBE_HARNESS_URL = "https://harness.example.com";
  process.env.CF_PROBE_HARNESS_TOKEN = "dummy-harness-token-dummy!";
  process.env.CF_PROBE_HARNESS_ALLOWED_HOSTS = "harness.example.com";

  let dispatched = 0;
  globalThis.fetch = (async () => {
    dispatched += 1;
    // Empty-bucket LIST shape for the pre-run gate; anything else 200-empty.
    return new Response("<ListBucketResult></ListBucketResult>", { status: 200 });
  }) as typeof globalThis.fetch;

  const code = await main([
    "--evidence-root",
    join(scratch, "evidence"),
    "--envelope",
    envelope({ max_total_requests: 6 }),
    "--probe-deadline-ms",
    "2000",
    "--run-deadline-ms",
    "8000",
  ]);
  assert.notEqual(code, 0, "an envelope-starved run can never be green");
  assert.ok(dispatched <= 6, `at most 6 requests may dispatch under max_total_requests=6; saw ${dispatched}`);
});

// ---------------------------------------------------------------------------
// R4-CF-01: post-deadline probe stragglers lose their provider.
// ---------------------------------------------------------------------------

test("RecordingProvider.close() turns further probe calls into typed refusals", async () => {
  const inner = new ScriptedProvider(() => jsonRes(200, {}));
  const recording = new RecordingProvider(inner);
  await recording.fetch({ service: "r2", method: "GET", path: "/b/x" });
  recording.close("probe deadline exceeded");
  await assert.rejects(recording.fetch({ service: "r2", method: "GET", path: "/b/y" }));
  assert.equal(inner.calls.length, 1, "post-close calls never reach the provider");
});

// ---------------------------------------------------------------------------
// R4-CF-03: redaction as a serialization invariant + seal-time scanner.
// ---------------------------------------------------------------------------

test("a canary in assertion detail / notes is redacted at write time", () => {
  const bundle = new EvidenceBundle(join(scratch, "ev1"));
  bundle.writeProbeEvidence({
    probe_id: "P-TEST",
    title: "t",
    spec_section: "s",
    mode: "mock",
    injected_fault: null,
    started_at: new Date().toISOString(),
    finished_at: new Date().toISOString(),
    verdict: "PASS",
    expected_outcome: "x",
    // The audit's exact vector: an innocent-looking harness JSON field
    // stringified into assertion detail.
    actual_outcome: 'harness said {"harmless":"LEAK_CANARY_SECRET_0123456789"}',
    checks: [{ assertion_id: "a", ok: true, detail: 'body: {"harmless":"LEAK_CANARY_SECRET_0123456789"}' }],
    unsatisfied_required_assertions: [],
    exchanges: [],
    notes: ["note with LEAK_CANARY_SECRET_0123456789 embedded"],
  });
  const written = readFileSync(join(bundle.runDir, "probes", "P-TEST.json"), "utf8");
  assert.ok(!written.includes("LEAK_CANARY_SECRET"), "the canary must not survive serialization");
  assert.ok(written.includes("[REDACTED:canary]"), "the redaction marker replaces it");
  const root = bundle.seal(["irrelevant-secret-value"]);
  assert.ok(root.length === 64, "bundle seals cleanly once redacted");
});

test("seal() refuses a bundle containing a smuggled secret file (no COMPLETE)", () => {
  const bundle = new EvidenceBundle(join(scratch, "ev2"));
  bundle.writeRunRecord({ schema: "x" });
  // A file written OUTSIDE the redacting writer (the write-time invariant
  // cannot see it) — the seal-time scanner must catch it.
  writeFileSync(join(bundle.runDir, "smuggled.json"), JSON.stringify({ note: "the-exact-secret-value-123456" }));
  assert.throws(() => bundle.seal(["the-exact-secret-value-123456"]), SealViolationError);
  assert.ok(!existsSync(join(bundle.runDir, "COMPLETE")), "a leaking bundle is never sealed");
});

test("seal() refuses value-shape leaks (bearer token) even when unknown", () => {
  const bundle = new EvidenceBundle(join(scratch, "ev3"));
  bundle.writeRunRecord({ schema: "x" });
  writeFileSync(join(bundle.runDir, "smuggled.txt"), "authorization: Bearer abcdefghijklmnopqrstuvwxyz012345");
  assert.throws(() => bundle.seal([]), SealViolationError);
});
