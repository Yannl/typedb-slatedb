/*
 * Direct tests for the disposable probe-harness Worker (R4-CF-02).
 *
 * These exercise harness-worker.ts's fetch handler in-process with
 * constructed Request objects and a fake env — no wrangler, no network:
 *
 *   - authentication: no token / wrong token => 401; unprovisioned secret
 *     => 503 (fail closed, never fall open); health is the only
 *     unauthenticated path and returns build identity only;
 *   - the P-DO-01 interleaving contract (park at a non-storage await,
 *     conflicting commit, stale rejection, one legal trace) responds with
 *     exactly the shapes probes-do.ts asserts;
 *   - the P-CTR-01 lifecycle contract (idempotent start, converging stop,
 *     generation advance, stale callback rejection) responds with exactly
 *     the shapes probes-ctr.ts asserts;
 *   - durable slices genuinely round-trip storage: a FRESH ProbeHarnessDO
 *     over the same storage still sees acknowledged writes and the
 *     durable alarm intent.
 *
 * The DO storage stub implements exactly the surface the harness uses
 * (HarnessStorage: get/put) so the stub stays honest.
 *
 * Run: node --experimental-strip-types --no-warnings --test probes/harness-worker.test.ts
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";
import worker, { ProbeHarnessDO } from "./harness-worker.ts";
import type { HarnessEnv, HarnessStorage } from "./harness-worker.ts";

const TOKEN = "test-harness-token-0123456789";
const BASE = "https://probe-harness.test";

// ---------------------------------------------------------------------------
// Fake env: in-memory storage implementing exactly the HarnessStorage
// surface, one DO instance per env (recreatable over the same storage).
// ---------------------------------------------------------------------------

class MemoryStorage implements HarnessStorage {
  private readonly map = new Map<string, unknown>();
  async get<T = unknown>(key: string): Promise<T | undefined> {
    return this.map.get(key) as T | undefined;
  }
  async put(key: string, value: unknown): Promise<void> {
    // structuredClone: like real DO storage, values are serialized, never
    // shared by reference — an unserializable value would throw here.
    this.map.set(key, structuredClone(value));
  }
}

interface FakeHarness {
  env: HarnessEnv;
  storage: MemoryStorage;
  /** Drop the live DO instance (simulates a DO restart over same storage). */
  restartDO(): void;
}

function makeHarness(token: string | undefined): FakeHarness {
  const storage = new MemoryStorage();
  let instance: ProbeHarnessDO | null = null;
  const id = { toString: () => "probe-harness-singleton", equals: () => false, name: "probe-harness-singleton" };
  const env: HarnessEnv = {
    ...(token !== undefined ? { PROBE_HARNESS_TOKEN: token } : {}),
    PROBE_HARNESS_DO: {
      idFromName: () => id,
      get: () => ({
        fetch: (request: Request) => {
          if (instance === null) instance = new ProbeHarnessDO({ storage }, env);
          return instance.fetch(request);
        },
      }),
    },
  };
  return {
    env,
    storage,
    restartDO: () => {
      instance = null;
    },
  };
}

function req(path: string, opts: { method?: string; token?: string; body?: unknown; headers?: Record<string, string> } = {}): Request {
  const headers: Record<string, string> = { ...opts.headers };
  if (opts.token !== undefined) headers["authorization"] = `Bearer ${opts.token}`;
  if (opts.body !== undefined) headers["content-type"] = "application/json";
  return new Request(`${BASE}${path}`, {
    method: opts.method ?? "POST",
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
}

async function asJson(res: Response): Promise<Record<string, unknown>> {
  return (await res.json()) as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Authentication.
// ---------------------------------------------------------------------------

test("requests without a bearer token are 401 and labeled harness", async () => {
  const h = makeHarness(TOKEN);
  const res = await worker.fetch(req("/do/interleave/reset"), h.env);
  assert.equal(res.status, 401);
  const body = await asJson(res);
  assert.equal(body.harness, true, "even refusals are labeled harness output");
});

test("requests with a WRONG bearer token are 401", async () => {
  const h = makeHarness(TOKEN);
  const res = await worker.fetch(req("/ctr/lifecycle/status", { method: "GET", token: "wrong-token" }), h.env);
  assert.equal(res.status, 401);
});

test("an unprovisioned PROBE_HARNESS_TOKEN fails CLOSED (503), never open", async () => {
  const h = makeHarness(undefined);
  const res = await worker.fetch(req("/do/interleave/reset", { token: "anything" }), h.env);
  assert.equal(res.status, 503);
});

test("a valid token does not open non-harness paths", async () => {
  const h = makeHarness(TOKEN);
  const res = await worker.fetch(req("/admin/anything", { token: TOKEN }), h.env);
  assert.equal(res.status, 404);
});

// ---------------------------------------------------------------------------
// Health (the single unauthenticated path).
// ---------------------------------------------------------------------------

test("GET /harness/health returns ok + build identity without auth", async () => {
  const h = makeHarness(TOKEN);
  const res = await worker.fetch(req("/harness/health", { method: "GET" }), h.env);
  assert.equal(res.status, 200);
  const body = await asJson(res);
  assert.equal(body.ok, true);
  assert.equal(body.harness, true);
  const source = body.source as Record<string, unknown>;
  assert.equal(source.entry, "control-plane/probes/harness-worker.ts");
  assert.equal(source.wrangler_config, "control-plane/wrangler.probe-harness.toml");
});

// ---------------------------------------------------------------------------
// P-DO-01 contract: interleaving with a parked non-storage await.
// ---------------------------------------------------------------------------

test("P-DO-01 path contract: parked slow-op loses to the conflicting commit", async () => {
  const h = makeHarness(TOKEN);
  const call = (path: string, body?: unknown) => worker.fetch(req(path, { token: TOKEN, body }), h.env);

  const reset = await call("/do/interleave/reset");
  assert.equal(reset.status, 200);

  // Start the slow op WITHOUT awaiting: it parks at the gate.
  const slowPromise = call("/do/interleave/slow-op", { value: "slow-A" });
  const conflict = await call("/do/interleave/conflict", { value: "conflict-B" });
  assert.equal(conflict.status, 200);
  const release = await call("/do/interleave/release");
  assert.equal(release.status, 200);

  const slow = await slowPromise;
  assert.equal(slow.status, 409, "the resumed operation must NOT commit its stale validation");

  const trace = await asJson(await worker.fetch(req("/do/interleave/trace", { method: "GET", token: TOKEN }), h.env));
  assert.equal(Number(trace.commits), 1, "exactly one commit");
  assert.equal(trace.value, "conflict-B", "the winner's value");
  const t = trace.trace as string[];
  assert.ok(t.includes("slow:read@v1") && t.includes("conflict:commit") && t.includes("slow:rejected-stale"), JSON.stringify(t));
});

// ---------------------------------------------------------------------------
// P-CTR-01 contract: lifecycle state machine.
// ---------------------------------------------------------------------------

test("P-CTR-01 path contract: idempotent start, converging stop, stale callback rejected", async () => {
  const h = makeHarness(TOKEN);
  const call = (path: string, body?: unknown) => worker.fetch(req(path, { token: TOKEN, body }), h.env);

  assert.equal((await call("/ctr/lifecycle/reset")).status, 200);

  const start1 = await asJson(await call("/ctr/lifecycle/start"));
  assert.equal(start1.state, "starting");
  assert.equal(Number(start1.generation), 1);
  const start2 = await asJson(await call("/ctr/lifecycle/start"));
  assert.equal(start2.idempotent, true, "duplicate start is idempotent");
  assert.equal(Number(start2.generation), 1);

  const stop1 = await asJson(await call("/ctr/lifecycle/stop"));
  assert.equal(stop1.state, "stopped", "stop while starting converges");
  const stop2 = await asJson(await call("/ctr/lifecycle/stop"));
  assert.equal(stop2.noop, true, "duplicate stop is an explicit no-op");

  const start3 = await asJson(await call("/ctr/lifecycle/start"));
  assert.equal(Number(start3.generation), 2, "restart advances the generation");
  const ready = await asJson(await call("/ctr/lifecycle/port-ready", { generation: 2 }));
  assert.equal(ready.state, "running");

  const stale = await call("/ctr/lifecycle/port-ready", { generation: 1 });
  assert.equal(stale.status, 409, "stale lifecycle callback rejected");
  const status = await asJson(await worker.fetch(req("/ctr/lifecycle/status", { method: "GET", token: TOKEN }), h.env));
  assert.equal(status.state, "running");
  assert.equal(Number(status.generation), 2);
});

// ---------------------------------------------------------------------------
// Durability: the slices whose protocol claims durability genuinely
// round-trip storage across a DO restart.
// ---------------------------------------------------------------------------

test("acked writes and durable alarm intent survive a DO restart over the same storage", async () => {
  const h = makeHarness(TOKEN);
  const call = (path: string, body?: unknown) => worker.fetch(req(path, { token: TOKEN, body }), h.env);

  assert.equal((await call("/ctr/sleep/reset", { sleepAfter: 3 })).status, 200);
  assert.equal((await asJson(await call("/ctr/sleep/write", { data: "w1" }))).acked, true);
  assert.equal((await call("/do/alarm/reset-all")).status, 200);
  assert.equal((await call("/do/alarm/schedule", { workId: "work-1", at: 2 })).status, 200);

  h.restartDO(); // a FRESH instance over the same storage

  const sleepState = await asJson(await worker.fetch(req("/ctr/sleep/state", { method: "GET", token: TOKEN }), h.env));
  assert.deepEqual(sleepState.acked, ["w1"], "acknowledged writes survive the restart");
  const alarmState = await asJson(await worker.fetch(req("/do/alarm/state", { method: "GET", token: TOKEN }), h.env));
  assert.equal(alarmState.alarmScheduled, true, "the durable alarm intent survives the restart");
});

// ---------------------------------------------------------------------------
// Honesty labels: simulated platform behavior says so.
// ---------------------------------------------------------------------------

test("simulated behavior is labeled {harness:true, simulated:true}", async () => {
  const h = makeHarness(TOKEN);
  const call = (path: string, body?: unknown) => worker.fetch(req(path, { token: TOKEN, body }), h.env);
  assert.equal((await call("/ctr/net/reset", { allowlist: [], enableInternet: true })).status, 200);
  const placement = await asJson(await worker.fetch(req("/ctr/net/placement", { method: "GET", token: TOKEN }), h.env));
  assert.equal(placement.harness, true);
  assert.equal(placement.simulated, true, "a Worker cannot place real containers — the response must say so");
});
