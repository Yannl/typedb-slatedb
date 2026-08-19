/*
 * Disposable probe-harness Worker (R4-CF-02).
 *
 * The round-4 audit found that nine of the fourteen "real" probes call
 * /do/*, /ctr/* and /worker/* endpoints that only the in-process mock
 * implemented — a supplied CF_PROBE_HARNESS_URL therefore referred to an
 * undefined external implementation that could not be reproduced from
 * this repository. This file IS that implementation: a real Cloudflare
 * Worker entry (deployed with control-plane/wrangler.probe-harness.toml)
 * serving the exact endpoint surface the probe clients (probes-do.ts,
 * probes-ctr.ts) assert, in the same source/package/config graph as the
 * probes themselves. run-platform-probes.ts binds this file's sha256 and
 * the wrangler config's sha256 into every run record (harness_source), so
 * the harness a real run talked to is reproducible from the repo.
 *
 * Honesty policy (the R4-CF-04 quality bar):
 *   - every response is labeled "harness": true — nothing served here can
 *     masquerade as the product;
 *   - where a Worker CANNOT faithfully run the real platform behavior
 *     (container lifecycle, SIGKILL, virtual clocks, egress policy,
 *     placement, gateway buffer accounting) the response additionally
 *     carries "simulated": true — the corresponding assertions are class
 *     "provider-fact" (see probes-do.ts / probes-ctr.ts) and can never
 *     satisfy a product-conformance obligation;
 *   - state that the protocol CLAIMS is durable (alarm intent, acked
 *     writes, committed ops, authority incarnation) round-trips through
 *     the ProbeHarnessDO's SQLite-backed storage, so it genuinely
 *     survives DO instance restarts; everything else is in-memory
 *     protocol shim state, disposable with the harness.
 *
 * Authentication: EVERY request must carry
 * `Authorization: Bearer <PROBE_HARNESS_TOKEN>` (a Worker secret, never a
 * var), compared constant-time via SHA-256 digests; anything else is 401.
 * The single unauthenticated path is GET /harness/health, which returns
 * only {ok, harness, source} build identity.
 */

// ---------------------------------------------------------------------------
// Environment / Durable Object seams (kept minimal so tests can stub them
// honestly: harness-worker.test.ts drives this fetch handler directly with
// an in-memory storage implementing exactly this surface).
// ---------------------------------------------------------------------------

/** The only storage surface ProbeHarnessDO uses (subset of DO storage). */
export interface HarnessStorage {
  get<T = unknown>(key: string): Promise<T | undefined>;
  put(key: string, value: unknown): Promise<void>;
}

export interface HarnessDOContext {
  readonly storage: HarnessStorage;
}

export interface HarnessEnv {
  /** Secret bearer token; unset means the harness refuses ALL traffic. */
  PROBE_HARNESS_TOKEN?: string;
  PROBE_HARNESS_DO: {
    idFromName(name: string): DurableObjectId;
    get(id: DurableObjectId): { fetch(request: Request): Promise<Response> };
  };
}

/** Build identity returned by /harness/health and bound into run bundles. */
export const HARNESS_SOURCE = {
  entry: "control-plane/probes/harness-worker.ts",
  wrangler_config: "control-plane/wrangler.probe-harness.toml",
} as const;

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

/** JSON response, always labeled as harness output. */
function j(status: number, body: Record<string, unknown>, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify({ harness: true, ...body }), {
    status,
    headers: { "content-type": "application/json", "x-harness": "true", ...headers },
  });
}

/** JSON response for behavior a Worker can only SIMULATE (labeled). */
function sim(status: number, body: Record<string, unknown>, headers: Record<string, string> = {}): Response {
  return j(status, { simulated: true, ...body }, headers);
}

async function bodyJson(request: Request): Promise<Record<string, unknown>> {
  const text = await request.text();
  if (text.length === 0) return {};
  const parsed: unknown = JSON.parse(text);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("harness: expected a JSON object body");
  }
  return parsed as Record<string, unknown>;
}

/**
 * Constant-time bearer comparison: both sides are SHA-256 hashed (fixed
 * length, no early exit) and the digests XOR-compared byte-wise.
 */
export async function tokenMatches(presented: string, expected: string): Promise<boolean> {
  const enc = new TextEncoder();
  const a = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(presented)));
  const b = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(expected)));
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---------------------------------------------------------------------------
// Durable state slices (persisted through ProbeHarnessDO storage as plain
// JSON-able shapes so an in-memory test stub and real SQLite-backed DO
// storage behave identically).
// ---------------------------------------------------------------------------

interface AlarmSlice {
  virtualNow: number;
  durableIntent: { workId: string; at: number } | null;
  inMemoryAlarmAt: number | null;
  throwFirst: boolean;
  thrown: boolean;
  retries: number;
  workDone: string[];
  deliveries: number;
}

interface SleepSlice {
  sleepAfter: number;
  idleTicks: number;
  openTxns: number;
  state: string;
  acked: string[];
  deniedStops: number;
}

interface AuthoritySlice {
  incarnation: number;
  tokenSeq: number;
  tokens: Array<[string, number]>;
  actions: string[];
}

interface NetSlice {
  allowlist: string[];
  enableInternet: boolean;
  opSeq: number;
  ops: Array<[string, string]>;
}

const freshAlarm = (): AlarmSlice => ({
  virtualNow: 0,
  durableIntent: null,
  inMemoryAlarmAt: null,
  throwFirst: false,
  thrown: false,
  retries: 0,
  workDone: [],
  deliveries: 0,
});

const freshSleep = (): SleepSlice => ({
  sleepAfter: 3,
  idleTicks: 0,
  openTxns: 0,
  state: "running",
  acked: [],
  deniedStops: 0,
});

const freshAuthority = (): AuthoritySlice => ({ incarnation: 1, tokenSeq: 0, tokens: [], actions: [] });

const freshNet = (): NetSlice => ({ allowlist: [], enableInternet: true, opSeq: 0, ops: [] });

// ---------------------------------------------------------------------------
// ProbeHarnessDO — the single harness Durable Object. All /do/*, /ctr/*
// and /worker/* endpoints route here (one named instance per deployment)
// so probe state is consistent across requests and, for the durable
// slices, across DO restarts.
// ---------------------------------------------------------------------------

export class ProbeHarnessDO {
  private readonly ctx: HarnessDOContext;

  // --- in-memory protocol shim state (disposable with the instance) ---
  private interleave = {
    version: 1,
    value: "v1",
    trace: [] as string[],
    commits: 0,
    gate: null as { release: () => void } | null,
  };
  private overload = { softBudgetRows: 8, hardLimitRows: 12, rows: 0, shedCount: 0, alertFired: false };
  private lifecycle = { state: "stopped", generation: 0, startCount: 0 };
  private rollout = {
    workerVersion: 2,
    supportedImages: [] as number[],
    deployedImage: null as number | null,
    accepted: false,
    converged: false,
  };
  private gateway = { bufferBound: 65536 };

  // --- durable slices (loaded lazily, persisted on every mutation) ---
  private alarm: AlarmSlice = freshAlarm();
  private sleep: SleepSlice = freshSleep();
  private authority: AuthoritySlice = freshAuthority();
  private net: NetSlice = freshNet();
  private loaded = false;

  constructor(ctx: HarnessDOContext, _env: unknown) {
    this.ctx = ctx;
  }

  private async ensureLoaded(): Promise<void> {
    if (this.loaded) return;
    this.loaded = true;
    this.alarm = (await this.ctx.storage.get<AlarmSlice>("alarm")) ?? this.alarm;
    this.sleep = (await this.ctx.storage.get<SleepSlice>("sleep")) ?? this.sleep;
    this.authority = (await this.ctx.storage.get<AuthoritySlice>("authority")) ?? this.authority;
    this.net = (await this.ctx.storage.get<NetSlice>("net")) ?? this.net;
  }

  async fetch(request: Request): Promise<Response> {
    await this.ensureLoaded();
    const url = new URL(request.url);
    const path = url.pathname;
    try {
      if (path.startsWith("/do/interleave/")) return await this.doInterleave(request, path);
      if (path.startsWith("/do/alarm/")) return await this.doAlarm(request, path);
      if (path.startsWith("/do/overload/")) return await this.doOverload(request, path);
      if (path.startsWith("/do/authority/")) return await this.doAuthority(request, path);
      if (path.startsWith("/ctr/lifecycle/")) return await this.ctrLifecycle(request, path);
      if (path.startsWith("/ctr/rollout/")) return await this.ctrRollout(request, path);
      if (path.startsWith("/ctr/sleep/")) return await this.ctrSleep(request, path);
      if (path.startsWith("/ctr/net/")) return await this.ctrNet(request, path);
      if (path === "/worker/gateway/reset") return await this.gatewayReset(request);
      if (path === "/worker/gateway/saturate") return await this.gatewaySaturate(request);
      if (path.startsWith("/worker/gateway/")) return this.workerGateway(url, path);
      return j(404, { error: `unhandled harness path ${path}` });
    } catch (err) {
      return j(400, { error: err instanceof Error ? err.message : String(err) });
    }
  }

  // --- P-DO-01: request interleaving (GENUINE in-DO interleaving: the
  // slow operation parks at a real non-storage await; a concurrent
  // request commits underneath it; post-await re-validation rejects) -----

  private async doInterleave(request: Request, path: string): Promise<Response> {
    const s = this.interleave;
    switch (path) {
      case "/do/interleave/reset":
        this.interleave = { version: 1, value: "v1", trace: [], commits: 0, gate: null };
        return j(200, { ok: true });
      case "/do/interleave/slow-op": {
        const body = await bodyJson(request);
        const readVersion = s.version;
        s.trace.push(`slow:read@v${readVersion}`);
        await new Promise<void>((resolve) => {
          s.gate = { release: resolve };
        });
        if (s.version !== readVersion) {
          // Post-await re-validation: state moved underneath the parked
          // operation — the stale intention must NOT commit.
          s.trace.push("slow:rejected-stale");
          return j(409, { error: "stale validation" });
        }
        s.version += 1;
        s.value = String(body.value);
        s.commits += 1;
        s.trace.push("slow:commit");
        return j(200, { committed: true });
      }
      case "/do/interleave/conflict": {
        const body = await bodyJson(request);
        s.version += 1;
        s.value = String(body.value);
        s.commits += 1;
        s.trace.push("conflict:commit");
        return j(200, { committed: true });
      }
      case "/do/interleave/release": {
        if (!s.gate) return j(409, { error: "no parked operation" });
        s.gate.release();
        s.gate = null;
        return j(200, { released: true });
      }
      case "/do/interleave/trace":
        return j(200, { trace: s.trace, commits: s.commits, version: s.version, value: s.value });
    }
    return j(404, { error: path });
  }

  // --- P-DO-02: alarm durability (durable intent survives via storage;
  // the tick clock is VIRTUAL, so delivery itself is simulated) ----------

  private async saveAlarm(): Promise<void> {
    await this.ctx.storage.put("alarm", this.alarm);
  }

  private async doAlarm(request: Request, path: string): Promise<Response> {
    const a = this.alarm;
    switch (path) {
      case "/do/alarm/reset-all":
        this.alarm = freshAlarm();
        await this.saveAlarm();
        return j(200, { ok: true });
      case "/do/alarm/schedule": {
        const body = await bodyJson(request);
        // Durable intent is written BEFORE the (virtual) alarm: required
        // work must be reconstructible without trusting alarm delivery.
        a.durableIntent = { workId: String(body.workId), at: Number(body.at) };
        a.inMemoryAlarmAt = Number(body.at);
        await this.saveAlarm();
        return j(200, { scheduled: true });
      }
      case "/do/alarm/config": {
        const body = await bodyJson(request);
        a.throwFirst = body.throwFirst === true;
        await this.saveAlarm();
        return j(200, { ok: true });
      }
      case "/do/alarm/tick": {
        a.virtualNow += 1;
        const duplicate = (request.headers.get("x-mock-duplicate") ?? "") === "1";
        const deliveries = duplicate ? 2 : 1;
        const wasDue = a.inMemoryAlarmAt !== null && a.virtualNow >= a.inMemoryAlarmAt;
        let handled = false;
        const results: string[] = [];
        for (let i = 0; i < deliveries; i++) {
          if (!wasDue) {
            results.push("not-due");
            continue;
          }
          a.deliveries += 1;
          if (a.throwFirst && !a.thrown) {
            a.thrown = true;
            a.retries += 1;
            results.push("threw");
            continue;
          }
          const workId = a.durableIntent?.workId;
          if (workId !== undefined && !a.workDone.includes(workId)) {
            a.workDone.push(workId); // idempotent application
            results.push("done");
          } else {
            results.push("duplicate-ignored");
          }
          handled = true;
        }
        if (handled) a.inMemoryAlarmAt = null;
        await this.saveAlarm();
        return sim(200, { results });
      }
      case "/do/alarm/do-reset": {
        // Simulated DO restart: the in-memory alarm evaporates; the
        // durable intent (which DID round-trip storage) reconstructs it.
        a.inMemoryAlarmAt = null;
        if (a.durableIntent && !a.workDone.includes(a.durableIntent.workId)) {
          a.inMemoryAlarmAt = a.durableIntent.at;
        }
        await this.saveAlarm();
        return sim(200, { ok: true });
      }
      case "/do/alarm/state":
        return j(200, {
          workCount: a.workDone.length,
          alarmScheduled: a.inMemoryAlarmAt !== null,
          retries: a.retries,
          deliveries: a.deliveries,
          virtualNow: a.virtualNow,
        });
    }
    return j(404, { error: path });
  }

  // --- P-DO-03: overload and storage budgets (the row budget is a shim
  // policy, not real SQLite growth — labeled simulated) ------------------

  private async doOverload(request: Request, path: string): Promise<Response> {
    const o = this.overload;
    switch (path) {
      case "/do/overload/reset": {
        const body = await bodyJson(request);
        this.overload = {
          softBudgetRows: Number(body.softBudgetRows ?? 8),
          hardLimitRows: Number(body.hardLimitRows ?? 12),
          rows: 0,
          shedCount: 0,
          alertFired: false,
        };
        return j(200, { ok: true });
      }
      case "/do/overload/mutate": {
        if (o.rows >= o.softBudgetRows) {
          o.shedCount += 1;
          o.alertFired = true;
          return sim(429, { error: "shed" }, { "x-shed-reason": "row-budget" });
        }
        o.rows += 1;
        return sim(200, { rows: o.rows });
      }
      case "/do/overload/metrics":
        return j(200, {
          rows: o.rows,
          shedCount: o.shedCount,
          alertFired: o.alertFired,
          softBudgetRows: o.softBudgetRows,
          hardLimitRows: o.hardLimitRows,
        });
    }
    return j(404, { error: path });
  }

  // --- P-DO-04: incarnation and old-authority rejection (durable) -------

  private async saveAuthority(): Promise<void> {
    await this.ctx.storage.put("authority", this.authority);
  }

  private async doAuthority(request: Request, path: string): Promise<Response> {
    const au = this.authority;
    switch (path) {
      case "/do/authority/reset":
        this.authority = freshAuthority();
        await this.saveAuthority();
        return j(200, { ok: true });
      case "/do/authority/mint": {
        const token = `authority-token-${++au.tokenSeq}-${crypto.randomUUID()}`;
        au.tokens.push([token, au.incarnation]);
        await this.saveAuthority();
        return j(200, { token, incarnation: au.incarnation });
      }
      case "/do/authority/rotate":
        au.incarnation += 1;
        await this.saveAuthority();
        return j(200, { incarnation: au.incarnation });
      case "/do/authority/act": {
        const body = await bodyJson(request);
        const token = request.headers.get("x-authority-token") ?? "";
        const minted = au.tokens.find(([t]) => t === token)?.[1];
        if (minted === undefined) return j(401, { error: "unknown token" });
        if (minted !== au.incarnation) return j(401, { error: "superseded incarnation" });
        au.actions.push(String(body.action));
        await this.saveAuthority();
        return j(200, { performed: String(body.action) });
      }
      case "/do/authority/actions":
        return j(200, { actions: au.actions });
    }
    return j(404, { error: path });
  }

  // --- P-CTR-01: lifecycle state machine (no real container behind it —
  // a labeled simulation of the controller's convergence protocol) -------

  private async ctrLifecycle(request: Request, path: string): Promise<Response> {
    const lc = this.lifecycle;
    switch (path) {
      case "/ctr/lifecycle/reset":
        this.lifecycle = { state: "stopped", generation: 0, startCount: 0 };
        return j(200, { ok: true });
      case "/ctr/lifecycle/start": {
        if (lc.state === "starting" || lc.state === "running") {
          return sim(200, { state: lc.state, generation: lc.generation, idempotent: true });
        }
        lc.generation += 1;
        lc.startCount += 1;
        lc.state = "starting";
        return sim(200, { state: lc.state, generation: lc.generation });
      }
      case "/ctr/lifecycle/port-ready": {
        const body = await bodyJson(request);
        const generation = Number(body.generation);
        if (generation !== lc.generation || lc.state !== "starting") {
          return sim(409, { error: "stale lifecycle callback", generation: lc.generation });
        }
        lc.state = "running";
        return sim(200, { state: lc.state });
      }
      case "/ctr/lifecycle/stop": {
        const wasStopped = lc.state === "stopped";
        lc.state = "stopped";
        return sim(200, { state: lc.state, noop: wasStopped });
      }
      case "/ctr/lifecycle/status":
        return j(200, { state: lc.state, generation: lc.generation, startCount: lc.startCount });
    }
    return j(404, { error: path });
  }

  // --- P-CTR-02: mixed rollout (simulated compatibility envelope) -------

  private async ctrRollout(request: Request, path: string): Promise<Response> {
    const r = this.rollout;
    switch (path) {
      case "/ctr/rollout/reset": {
        const body = await bodyJson(request);
        this.rollout = {
          workerVersion: Number(body.workerVersion ?? 2),
          supportedImages: Array.isArray(body.supportedImages) ? (body.supportedImages as number[]) : [],
          deployedImage: null,
          accepted: false,
          converged: false,
        };
        return j(200, { ok: true });
      }
      case "/ctr/rollout/deploy": {
        const body = await bodyJson(request);
        const image = Number(body.image);
        if (!r.supportedImages.includes(image)) {
          return sim(409, { error: "outside compatibility envelope", accepted: false });
        }
        r.deployedImage = image;
        r.accepted = true;
        r.converged = false;
        return sim(200, { accepted: true, image });
      }
      case "/ctr/rollout/observe-convergence": {
        if (!r.accepted) return sim(409, { error: "nothing deployed" });
        r.converged = true;
        return sim(200, { converged: true });
      }
      case "/ctr/rollout/status":
        return j(200, { image: r.deployedImage, ready: r.accepted && r.converged });
    }
    return j(404, { error: path });
  }

  // --- P-CTR-03: sleep and shutdown (virtual ticks; SIGKILL simulated;
  // acked writes are DURABLE via storage, so they honestly survive) ------

  private async saveSleep(): Promise<void> {
    await this.ctx.storage.put("sleep", this.sleep);
  }

  private async ctrSleep(request: Request, path: string): Promise<Response> {
    const s = this.sleep;
    switch (path) {
      case "/ctr/sleep/reset": {
        const body = await bodyJson(request);
        this.sleep = { ...freshSleep(), sleepAfter: Number(body.sleepAfter ?? 3) };
        await this.saveSleep();
        return j(200, { ok: true });
      }
      case "/ctr/sleep/txn-open":
        s.openTxns += 1;
        await this.saveSleep();
        return j(200, { openTxns: s.openTxns });
      case "/ctr/sleep/txn-close":
        s.openTxns = Math.max(0, s.openTxns - 1);
        await this.saveSleep();
        return j(200, { openTxns: s.openTxns });
      case "/ctr/sleep/write": {
        const body = await bodyJson(request);
        if (s.state !== "running") return j(409, { error: "not running" });
        s.acked.push(String(body.data)); // durably acknowledged (storage)
        await this.saveSleep();
        return j(200, { acked: true });
      }
      case "/ctr/sleep/tick": {
        s.idleTicks += 1;
        if (s.state === "running" && s.idleTicks >= s.sleepAfter) {
          if (s.openTxns > 0) s.deniedStops += 1;
          else s.state = "stopped";
        }
        await this.saveSleep();
        return sim(200, { state: s.state, idleTicks: s.idleTicks });
      }
      case "/ctr/sleep/kill":
        s.state = "killed";
        await this.saveSleep();
        return sim(200, { state: s.state });
      case "/ctr/sleep/recover":
        s.state = "running";
        s.idleTicks = 0;
        await this.saveSleep();
        return sim(200, { state: s.state });
      case "/ctr/sleep/state":
        return j(200, { state: s.state, openTxns: s.openTxns, acked: s.acked, deniedStops: s.deniedStops });
    }
    return j(404, { error: path });
  }

  // --- P-CTR-04: networking and placement (a Worker cannot place real
  // containers or enforce real egress — every response is simulated;
  // committed ops are durable via storage) -------------------------------

  private async saveNet(): Promise<void> {
    await this.ctx.storage.put("net", this.net);
  }

  private async ctrNet(request: Request, path: string): Promise<Response> {
    const n = this.net;
    switch (path) {
      case "/ctr/net/reset": {
        const body = await bodyJson(request);
        this.net = {
          ...freshNet(),
          allowlist: Array.isArray(body.allowlist) ? (body.allowlist as string[]) : [],
          enableInternet: body.enableInternet !== false,
        };
        await this.saveNet();
        return j(200, { ok: true });
      }
      case "/ctr/net/placement":
        return sim(200, { doLocation: "ewr", containerLocation: "fra", internalHttp: "ok" });
      case "/ctr/net/config": {
        const body = await bodyJson(request);
        if (body.enableInternet !== undefined) n.enableInternet = body.enableInternet === true;
        await this.saveNet();
        return sim(200, { enableInternet: n.enableInternet });
      }
      case "/ctr/net/egress": {
        const body = await bodyJson(request);
        const host = String(body.host);
        if (!n.enableInternet) return sim(403, { error: "enableInternet=false" });
        if (!n.allowlist.includes(host)) return sim(403, { error: `egress to ${host} not allowlisted` });
        return sim(200, { egress: host });
      }
      case "/ctr/net/op-prepare": {
        const opId = `op-${++n.opSeq}`;
        await this.saveNet();
        return j(200, { opId });
      }
      case "/ctr/net/commit-with-disconnect": {
        const body = await bodyJson(request);
        const opId = String(body.opId);
        // The operation commits durably; the client-visible failure is a
        // SIMULATED dropped connection (599 stand-in status).
        n.ops.push([opId, "committed"]);
        await this.saveNet();
        return sim(599, { error: "client-disconnect (simulated)" });
      }
    }
    const opMatch = /^\/ctr\/net\/op\/(.+)$/.exec(path);
    if (opMatch) {
      const state = n.ops.find(([id]) => id === opMatch[1])?.[1];
      return state !== undefined ? j(200, { state }) : j(404, { error: "unknown op" });
    }
    return j(404, { error: path });
  }

  // --- P-WORKER-01: gateway bounds (deterministic pattern stream; the
  // buffer accounting is self-reported => simulated) ---------------------

  private async gatewayReset(request: Request): Promise<Response> {
    const body = await bodyJson(request);
    this.gateway = { bufferBound: Number(body.bufferBound ?? 65536) };
    return j(200, { ok: true });
  }

  /** Six-connection saturation model (permit accounting is simulated). */
  private async gatewaySaturate(request: Request): Promise<Response> {
    const body = await bodyJson(request);
    const connections = Number(body.connections ?? 0);
    const permits = 6; // platform six-connection limit
    return sim(200, {
      peakConcurrent: Math.min(connections, permits),
      queued: Math.max(0, connections - permits),
      incorrectSuccess: false,
    });
  }

  private workerGateway(url: URL, path: string): Response {
    switch (path) {
      case "/worker/gateway/stream": {
        const bytes = Number(url.searchParams.get("bytes") ?? 0);
        const body = new Uint8Array(bytes);
        for (let i = 0; i < bytes; i++) body[i] = i % 251; // deterministic pattern
        return new Response(body, {
          status: 200,
          headers: {
            "x-harness": "true",
            "x-harness-simulated": "gateway-buffer-accounting",
            "x-max-buffered-bytes": String(Math.min(bytes, this.gateway.bufferBound)),
            "x-buffer-bound": String(this.gateway.bufferBound),
          },
        });
      }
      case "/worker/gateway/object": {
        if (url.searchParams.get("fail") === "r2-500") {
          return sim(502, { error: "upstream r2 500 (simulated)" }, { "x-success-receipt": "none" });
        }
        return sim(200, { ok: true }, { "x-success-receipt": "resolved" });
      }
    }
    return j(404, { error: path });
  }
}

// ---------------------------------------------------------------------------
// Worker entry: authentication, health, DO routing.
// ---------------------------------------------------------------------------

const HARNESS_SURFACE = /^\/(do|ctr|worker)\//;

export default {
  async fetch(request: Request, env: HarnessEnv): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // The ONLY unauthenticated path: build-identity health.
    if (request.method === "GET" && path === "/harness/health") {
      return j(200, { ok: true, source: HARNESS_SOURCE });
    }

    // Fail closed on a missing secret: an unprovisioned harness serves
    // NOTHING (it must never fall open to unauthenticated traffic).
    const expected = env.PROBE_HARNESS_TOKEN;
    if (expected === undefined || expected.length === 0) {
      return j(503, { error: "PROBE_HARNESS_TOKEN is not provisioned; harness refuses all traffic" });
    }
    const auth = request.headers.get("authorization") ?? "";
    const presented = auth.startsWith("Bearer ") ? auth.slice("Bearer ".length) : "";
    if (presented.length === 0 || !(await tokenMatches(presented, expected))) {
      return j(401, { error: "missing or invalid bearer token" });
    }

    if (!HARNESS_SURFACE.test(path)) return j(404, { error: `unhandled harness path ${path}` });

    // One named DO instance per deployment: probe state is consistent
    // across requests, and the durable slices survive instance restarts.
    const stub = env.PROBE_HARNESS_DO.get(env.PROBE_HARNESS_DO.idFromName("probe-harness-singleton"));
    return stub.fetch(request);
  },
};
