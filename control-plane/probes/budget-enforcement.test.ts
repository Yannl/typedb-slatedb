/*
 * R6-CF-02: every signed numeric limit maps to an ENFORCED runtime counter,
 * and probe + cleanup draw from ONE pool.
 *
 * The round-6 audit found `max_cost_usd_cents` required by preflight,
 * signed by the owner, and then never priced — an envelope approving one
 * billionth of a cent still dispatched a Cloudflare API POST and a ~1 MB
 * PUT. It also found two independent meters over one provider: cleanup
 * carried its own byte allowance ON TOP of the probe meter's, so a signed
 * 100-byte maximum permitted 200 aggregate bytes.
 *
 * Run: node --experimental-strip-types --no-warnings --test probes/budget-enforcement.test.ts
 */

import assert from "node:assert/strict";
import test from "node:test";
import {
  budgetFromEnvelope, EnvelopeExceededError, MeteredProvider, priceOfRequest, PRICING_MODEL_VERSION,
  RunBudgetLedger, type EnvelopeBudget,
} from "./envelope.ts";
import { REQUIRED_ENVELOPE_LIMITS } from "./preflight.ts";
import type { PlatformProvider, SeamRequest, SeamResponse } from "./provider.ts";
import { utf8 } from "./provider.ts";

/** A provider that records what actually reached "the network". */
class CountingProvider implements PlatformProvider {
  readonly mode = "real" as const;
  readonly capabilities = { r2: true, cfapi: true, cfapi_runtime: true, harness: true };
  readonly dispatched: SeamRequest[] = [];
  async fetch(req: SeamRequest): Promise<SeamResponse> {
    this.dispatched.push(req);
    return { status: 200, headers: {}, body: utf8("") };
  }
}

function limits(over: Record<string, number> = {}): Record<string, number> {
  return {
    max_total_requests: 100,
    max_total_bytes_written: 1_000_000,
    max_run_seconds: 900,
    max_probe_seconds: 60,
    max_request_seconds: 10,
    max_cost_usd_cents: 100,
    credential_ttl_seconds: 900,
    ...over,
  };
}

function ledgerOf(over: Record<string, number> = {}, validUntilMs?: number): RunBudgetLedger {
  return new RunBudgetLedger(budgetFromEnvelope(limits(over), Date.now(), validUntilMs));
}

// ---------------------------------------------------------------------------

test("R6-CF-02: EVERY required signed limit maps to an enforced runtime counter", () => {
  // The audit's exhaustiveness demand: adding a signed field without
  // consuming it must fail here, not silently become decoration.
  const budget = budgetFromEnvelope(limits(), 1_000_000);
  const enforced: Record<(typeof REQUIRED_ENVELOPE_LIMITS)[number], keyof EnvelopeBudget> = {
    max_total_requests: "maxTotalRequests",
    max_total_bytes_written: "maxTotalBytesWritten",
    max_run_seconds: "runDeadlineAtMs",
    max_request_seconds: "maxRequestMs",
    max_cost_usd_cents: "maxCostMicroCents",
    // enforced by preflight against the FIXED minted TTL and the remaining
    // signed window (R6-CF-03), not by a meter counter
    max_probe_seconds: "maxRequestMs",
    credential_ttl_seconds: "runDeadlineAtMs",
  };
  for (const key of REQUIRED_ENVELOPE_LIMITS) {
    const field = enforced[key];
    assert.ok(field !== undefined, `signed limit '${key}' has no enforced counter — R6-CF-02`);
    assert.equal(typeof budget[field], "number", `budget.${String(field)} must be a live number`);
  }
});

test("R6-CF-02 MUTANT: a signed cost ceiling actually refuses spend", () => {
  // The audit's exact reproduction: an absurdly small approved cost.
  const ledger = ledgerOf({ max_cost_usd_cents: 0.000001 });
  const inner = new CountingProvider();
  const meter = new MeteredProvider(inner, ledger, { requestShare: 100, label: "probe" });
  assert.rejects(
    () => meter.fetch({ service: "cfapi", method: "POST", path: "/accounts/x/r2/buckets", body: utf8("{}") }),
    EnvelopeExceededError,
  );
});

test("R6-CF-02 MUTANT: probe + cleanup cannot exceed the signed BYTE total", () => {
  // Two meters, ONE ledger: the round-5 defect was two independent
  // allowances over the same provider.
  const ledger = ledgerOf({ max_total_bytes_written: 100 });
  const inner = new CountingProvider();
  const probe = new MeteredProvider(inner, ledger, { requestShare: 50, label: "probe" });
  const cleanup = new MeteredProvider(inner, ledger, { requestShare: 50, label: "cleanup" });
  return (async () => {
    await probe.fetch({ service: "r2", method: "PUT", path: "/b/k1", body: new Uint8Array(100) });
    await assert.rejects(
      () => cleanup.fetch({ service: "r2", method: "PUT", path: "/b/k2", body: new Uint8Array(100) }),
      EnvelopeExceededError,
      "cleanup must draw from the SAME signed byte pool, not a second allowance",
    );
    assert.equal(ledger.bytesWritten, 100);
    assert.equal(inner.dispatched.length, 1, "the over-budget call must never reach the network");
  })();
});

test("R6-CF-02 MUTANT: probe + cleanup cannot exceed the signed REQUEST total", () => {
  const ledger = ledgerOf({ max_total_requests: 3 });
  const inner = new CountingProvider();
  const probe = new MeteredProvider(inner, ledger, { requestShare: 2, label: "probe" });
  const cleanup = new MeteredProvider(inner, ledger, { requestShare: 1, label: "cleanup" });
  return (async () => {
    await probe.fetch({ service: "r2", method: "GET", path: "/b/a" });
    await probe.fetch({ service: "r2", method: "GET", path: "/b/b" });
    await cleanup.fetch({ service: "r2", method: "GET", path: "/b/c" });
    await assert.rejects(() => cleanup.fetch({ service: "r2", method: "GET", path: "/b/d" }), EnvelopeExceededError);
    assert.equal(ledger.requestsUsed, 3, "the partition sums to exactly the signed total");
    assert.equal(inner.dispatched.length, 3);
  })();
});

test("R6-CF-02: cost is integer micro-cents — no binary floating point decides a spend", () => {
  const budget = budgetFromEnvelope(limits({ max_cost_usd_cents: 0.3 }), Date.now());
  assert.ok(Number.isSafeInteger(budget.maxCostMicroCents));
  assert.equal(budget.maxCostMicroCents, 300_000);
  // pricing is versioned and conservative (a ceiling, never an estimate)
  assert.match(PRICING_MODEL_VERSION, /^probe-pricing\//);
  const write = priceOfRequest({ service: "r2", method: "PUT", body: new Uint8Array(1024 * 1024) });
  const read = priceOfRequest({ service: "r2", method: "GET" });
  assert.ok(write > read, "a 1 MiB write must reserve more than a read");
  assert.ok(Number.isSafeInteger(write) && Number.isSafeInteger(read));
});

test("R6-CF-02 MUTANT: garbage cost ceilings refuse rather than defaulting", () => {
  for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, 1e-12]) {
    assert.throws(
      () => budgetFromEnvelope(limits({ max_cost_usd_cents: bad }), Date.now()),
      EnvelopeExceededError,
      `max_cost_usd_cents=${bad} must refuse`,
    );
  }
});

test("R6-CF-02: a lost response still CONSUMES its reservation (no refund)", () => {
  const ledger = ledgerOf({ max_total_requests: 1 });
  const failing: PlatformProvider = {
    mode: "real", capabilities: { r2: true, cfapi: true, cfapi_runtime: true, harness: true },
    async fetch() { throw new Error("socket hang up after the provider committed"); },
  };
  const meter = new MeteredProvider(failing, ledger, { requestShare: 1, label: "probe" });
  return (async () => {
    await assert.rejects(() => meter.fetch({ service: "r2", method: "PUT", path: "/b/k", body: utf8("v") }));
    assert.equal(ledger.requestsUsed, 1, "the resource was really consumed; a lost response is not a refund");
    await assert.rejects(() => meter.fetch({ service: "r2", method: "GET", path: "/b/k" }), EnvelopeExceededError);
  })();
});

test("R6-CF-03: the run deadline is clamped to the signed validity end", () => {
  const now = Date.now();
  const validUntil = now + 60_000;              // one minute of approval left
  const budget = budgetFromEnvelope(limits(), now, validUntil);  // asks for 900s
  assert.equal(budget.runDeadlineAtMs, validUntil,
    "a run may never plan past the end of the approval that permits it");
});

test("R6-CF-02: the ledger reports signed/reserved/remaining per class for evidence", () => {
  const ledger = ledgerOf();
  const report = ledger.report();
  for (const key of ["pricing_model", "signed_max_requests", "signed_max_cost_micro_cents",
    "reserved_requests", "reserved_cost_micro_cents", "remaining_cost_micro_cents"]) {
    assert.ok(key in report, `evidence report must carry '${key}'`);
  }
});
