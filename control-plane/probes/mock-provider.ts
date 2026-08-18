/*
 * Deterministic in-process fake of every platform surface the probes
 * exercise (R2 S3 API, Cloudflare account API, DO / container / gateway
 * probe-harness endpoints).
 *
 * Purpose (audit C-P0-10): the probe HARNESS itself must be testable in
 * CI with no credentials. This fake implements the semantics each probe
 * asserts — conditional-PUT preconditions, single-winner concurrency,
 * temporary-credential scope, bucket locks, multipart attempt identity,
 * completion-order consistency and bounded 429 pressure, DO
 * interleaving/alarm/overload/incarnation, container lifecycle / rollout /
 * sleep / networking, and gateway streaming bounds — plus, per probe, one
 * named injectable FAULT that violates exactly those semantics. A probe
 * that cannot be made to FAIL by its fault proves nothing; self-test.sh
 * exercises every fault and the all-500 counterexample from the audit.
 *
 * Everything is deterministic: virtual time only advances through explicit
 * mock endpoints (`/__mock/advance-window`, `/do/alarm/tick`,
 * `/ctr/sleep/tick`), etags derive from content hashes, and in-process
 * handlers run to completion atomically unless a probe explicitly parks an
 * operation at an await point (P-DO-01's gate).
 */

import type { PlatformProvider, ProviderCapabilities, SeamRequest, SeamResponse } from "./provider.ts";
import { EMPTY_BODY, sha256hex, text, utf8 } from "./provider.ts";
import type { BucketLockRule, TempCredentialPermission } from "./cfapi-dto.ts";
import { validateBucketLockRulesBody, validateTempCredentialsCreateRequest } from "./cfapi-dto.ts";

// ---------------------------------------------------------------------------
// Small response helpers.
// ---------------------------------------------------------------------------

function respond(status: number, headers: Record<string, string> = {}, body: Uint8Array = EMPTY_BODY): SeamResponse {
  return { status, headers, body };
}

function jsonResponse(status: number, value: unknown, headers: Record<string, string> = {}): SeamResponse {
  return respond(status, { "content-type": "application/json", ...headers }, utf8(JSON.stringify(value)));
}

function etagOf(body: Uint8Array): string {
  return `"${sha256hex(body).slice(0, 16)}"`;
}

function bodyJson(req: SeamRequest): Record<string, unknown> {
  if (!req.body || req.body.length === 0) return {};
  const parsed: unknown = JSON.parse(text(req.body));
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("mock: expected a JSON object body");
  }
  return parsed as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Internal state shapes.
// ---------------------------------------------------------------------------

interface StoredObject {
  body: Uint8Array;
  etag: string;
  checksumSha256?: string;
  /** Monotonic commit sequence — completion order for P-R2-05. */
  commitSeq: number;
}

interface MultipartPart {
  attemptId: string;
  bytes: Uint8Array;
  etag: string;
}

interface MultipartUpload {
  bucketKey: string;
  parts: Map<number, MultipartPart>;
  aborted: boolean;
  completed: boolean;
}

interface TempCredScope {
  bucket: string;
  prefixes: string[];
  /** SINGULAR official permission enum (round-3 P-02). */
  permission: TempCredentialPermission;
  ttlSeconds: number;
  parentAccessKeyId: string;
}

export class MockPlatformProvider implements PlatformProvider {
  readonly mode = "mock" as const;
  // The fake implements every surface, so all capabilities are present.
  readonly capabilities: ProviderCapabilities = { r2: true, cfapi: true, cfapi_runtime: true, harness: true };

  /** Probe-id -> injected fault name (validated against the manifest by the CLI). */
  private readonly faults: ReadonlyMap<string, string>;
  /** Audit counterexample: every response is HTTP 500. */
  private readonly force500: boolean;

  constructor(opts: { faults?: ReadonlyMap<string, string>; force500?: boolean } = {}) {
    this.faults = opts.faults ?? new Map();
    this.force500 = opts.force500 ?? false;
  }

  private hasFault(probeId: string, fault: string): boolean {
    return this.faults.get(probeId) === fault;
  }

  // --- R2 state ---
  private objects = new Map<string, StoredObject>();
  private uploads = new Map<string, MultipartUpload>();
  private uploadSeq = 0;
  private commitSeq = 0;
  private rateWindow = 0;
  private rateCounts = new Map<string, { window: number; count: number }>();
  private static readonly RATE_LIMIT_PER_WINDOW = 4;

  // --- cfapi state ---
  private tempCreds = new Map<string, TempCredScope>();
  private tempCredSeq = 0;
  private lockRules = new Map<string, BucketLockRule[]>(); // bucket -> rules

  // --- DO state ---
  private interleave = {
    version: 1,
    value: "v1",
    trace: [] as string[],
    commits: 0,
    gate: null as { promise: Promise<void>; release: () => void } | null,
  };
  private alarm = {
    virtualNow: 0,
    durableIntent: null as { workId: string; at: number } | null,
    inMemoryAlarmAt: null as number | null,
    throwFirst: false,
    thrown: false,
    retries: 0,
    workDone: new Set<string>(),
    deliveries: 0,
  };
  private overload = {
    softBudgetRows: 8,
    hardLimitRows: 12,
    rows: 0,
    shedCount: 0,
    alertFired: false,
  };
  private authority = {
    incarnation: 1,
    tokenSeq: 0,
    tokens: new Map<string, number>(), // token -> incarnation minted under
    actions: [] as string[],
  };

  // --- container state ---
  private lifecycle = { state: "stopped", generation: 0, startCount: 0 };
  private rollout = {
    workerVersion: 2,
    supportedImages: [] as number[],
    deployedImage: null as number | null,
    accepted: false,
    converged: false,
  };
  private sleep = {
    sleepAfter: 3,
    idleTicks: 0,
    openTxns: 0,
    state: "running",
    acked: [] as string[],
    deniedStops: 0,
  };
  private net = {
    allowlist: [] as string[],
    enableInternet: true,
    opSeq: 0,
    ops: new Map<string, string>(), // opId -> "committed"
  };
  private gateway = { bufferBound: 65536 };

  async fetch(req: SeamRequest): Promise<SeamResponse> {
    if (this.force500) {
      // The audit's exact counterexample: everything is a server error.
      // The harness must classify this as FAIL for every probe and exit 1.
      return respond(500, { "x-mock-injected": "http-500" }, utf8("injected 500"));
    }
    switch (req.service) {
      case "r2":
        return this.r2(req);
      case "cfapi":
        return this.cfapi(req);
      case "harness":
        return this.harness(req);
    }
  }

  // -------------------------------------------------------------------------
  // R2 (S3 API surface).
  // -------------------------------------------------------------------------

  private r2(req: SeamRequest): SeamResponse | Promise<SeamResponse> {
    const [pathOnly, query = ""] = req.path.split("?", 2);
    const params = new URLSearchParams(query);
    const headers = Object.fromEntries(
      Object.entries(req.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]),
    );

    // Mock-only virtual time: advance the same-key rate-limit window.
    if (req.method === "POST" && pathOnly === "/__mock/advance-window") {
      this.rateWindow += 1;
      return jsonResponse(200, { window: this.rateWindow });
    }

    const m = /^\/([^/]+)\/(.+)$/.exec(pathOnly);
    if (!m) return jsonResponse(400, { error: "bad r2 path" });
    const bucket = m[1];
    const key = decodeURIComponent(m[2]);
    const bucketKey = `${bucket}/${key}`;

    // Temporary-credential scope enforcement (P-R2-02). Real R2 enforces
    // this server-side; the fake enforces it identically unless the
    // scope-not-enforced fault is injected.
    const credCheck = this.checkTempCredentials(req, bucket, key);
    if (credCheck !== null) return credCheck;

    // Multipart surface (P-R2-04).
    if (params.has("uploads") && req.method === "POST") {
      const uploadId = `upload-${++this.uploadSeq}`;
      this.uploads.set(uploadId, { bucketKey, parts: new Map(), aborted: false, completed: false });
      return jsonResponse(200, { uploadId });
    }
    if (params.has("uploadId")) {
      return this.r2Multipart(req, params, headers, bucketKey);
    }

    if (req.method === "GET") {
      const obj = this.objects.get(bucketKey);
      if (!obj) return respond(404);
      const h: Record<string, string> = { etag: obj.etag, "x-mock-commit-seq": String(obj.commitSeq) };
      if (obj.checksumSha256 !== undefined) h["x-amz-checksum-sha256"] = obj.checksumSha256;
      return respond(200, h, obj.body);
    }

    if (req.method === "HEAD") {
      const obj = this.objects.get(bucketKey);
      return obj ? respond(200, { etag: obj.etag }) : respond(404);
    }

    if (req.method === "DELETE") {
      const lockDenied = this.checkLock(bucket, key, "delete");
      if (lockDenied) return lockDenied;
      this.objects.delete(bucketKey);
      return respond(204);
    }

    if (req.method === "PUT") {
      return this.r2Put(headers, bucket, key, bucketKey, req.body ?? EMPTY_BODY);
    }

    return jsonResponse(405, { error: `unhandled r2 ${req.method} ${req.path}` });
  }

  private r2Put(
    headers: Record<string, string>,
    bucket: string,
    key: string,
    bucketKey: string,
    body: Uint8Array,
  ): SeamResponse {
    const existing = this.objects.get(bucketKey);

    // Bucket locks (P-R2-03): locked mutations fail as documented.
    if (existing) {
      const lockDenied = this.checkLock(bucket, key, "overwrite");
      if (lockDenied) return lockDenied;
    }

    // Conditional semantics (P-R2-01). Handlers are synchronous, so two
    // "concurrent" conditional PUTs are serialized exactly as R2's
    // per-key ordering serializes them: exactly one winner.
    const fault01 = this.hasFault("P-R2-01", "precondition-ignored");
    if (headers["if-none-match"] === "*" && existing && !fault01) {
      return respond(412, { "x-mock-precondition": "if-none-match" });
    }
    if (headers["if-match"] !== undefined && !fault01) {
      if (!existing || existing.etag !== headers["if-match"]) {
        return respond(412, { "x-mock-precondition": "if-match" });
      }
    }

    // Same-key rate pressure (P-R2-05): opt-in via header so other probes
    // are unaffected. RATE_LIMIT_PER_WINDOW writes per key per virtual
    // window; excess is 429. The 429-commits-write fault models the one
    // behavior the spec forbids: overload creating an incorrect success.
    if (headers["x-mock-rate-limited"] === "1") {
      const entry = this.rateCounts.get(bucketKey);
      const count = entry && entry.window === this.rateWindow ? entry.count : 0;
      this.rateCounts.set(bucketKey, { window: this.rateWindow, count: count + 1 });
      if (count >= MockPlatformProvider.RATE_LIMIT_PER_WINDOW) {
        if (this.hasFault("P-R2-05", "429-commits-write")) {
          this.commitObject(bucketKey, body, undefined); // incorrect success
        }
        return respond(429, { "retry-after": "1" });
      }
    }

    // Checksum echo (P-R2-04): provider verifies and echoes the checksum;
    // it never substitutes for the application SHA-256 the probe asserts.
    let checksum: string | undefined;
    if (headers["x-amz-checksum-sha256"] !== undefined) {
      const actual = Buffer.from(sha256hex(body), "hex").toString("base64");
      if (headers["x-amz-checksum-sha256"] !== actual) {
        return jsonResponse(400, { error: "checksum mismatch" });
      }
      checksum = actual;
    }

    const obj = this.commitObject(bucketKey, body, checksum);

    // Ambiguity simulation (P-R2-01): the server committed, but the client
    // sees a network-level failure. Status 599 stands in for a timeout.
    if (headers["x-mock-simulate"] === "commit-then-timeout") {
      return respond(599, { "x-mock-simulated": "timeout-after-commit" });
    }

    const h: Record<string, string> = { etag: obj.etag, "x-mock-commit-seq": String(obj.commitSeq) };
    if (checksum !== undefined) h["x-amz-checksum-sha256"] = checksum;
    return respond(200, h);
  }

  private commitObject(bucketKey: string, body: Uint8Array, checksum: string | undefined): StoredObject {
    const obj: StoredObject = {
      body,
      etag: etagOf(body),
      checksumSha256: checksum,
      commitSeq: ++this.commitSeq,
    };
    this.objects.set(bucketKey, obj);
    return obj;
  }

  private r2Multipart(
    req: SeamRequest,
    params: URLSearchParams,
    headers: Record<string, string>,
    bucketKey: string,
  ): SeamResponse {
    const uploadId = params.get("uploadId") ?? "";
    const upload = this.uploads.get(uploadId);
    if (!upload || upload.bucketKey !== bucketKey || upload.aborted) {
      return jsonResponse(404, { error: "no such upload" });
    }

    if (req.method === "PUT") {
      const partNumber = Number(params.get("partNumber"));
      const attemptId = headers["x-upload-attempt-id"];
      if (!Number.isInteger(partNumber) || partNumber < 1 || attemptId === undefined) {
        return jsonResponse(400, { error: "partNumber and x-upload-attempt-id required" });
      }
      const bytes = req.body ?? EMPTY_BODY;
      const prev = upload.parts.get(partNumber);
      if (prev && prev.attemptId === attemptId && !Buffer.from(prev.bytes).equals(Buffer.from(bytes))) {
        // Changed bytes under the SAME UploadAttemptId: the contract says
        // this is attempt corruption and must be refused — a retry is only
        // a retry if it is byte-identical.
        if (!this.hasFault("P-R2-04", "changed-bytes-accepted")) {
          return jsonResponse(409, { error: "attempt-corruption: changed bytes under same UploadAttemptId" });
        }
      }
      const part: MultipartPart = { attemptId, bytes, etag: etagOf(bytes) };
      upload.parts.set(partNumber, part);
      return respond(200, { etag: part.etag });
    }

    if (req.method === "POST") {
      // Complete: concatenate parts in part-number order.
      const ordered = [...upload.parts.entries()].sort((a, b) => a[0] - b[0]).map(([, p]) => p.bytes);
      const total = Buffer.concat(ordered.map((b) => Buffer.from(b)));
      upload.completed = true;
      const obj = this.commitObject(bucketKey, new Uint8Array(total), undefined);
      return respond(200, { etag: obj.etag, "x-mock-composite": "true" });
    }

    if (req.method === "DELETE") {
      upload.aborted = true;
      return respond(204);
    }

    return jsonResponse(405, { error: "unhandled multipart op" });
  }

  /** Returns a denial response, or null when the request is in scope. */
  private checkTempCredentials(req: SeamRequest, bucket: string, key: string): SeamResponse | null {
    const keyId = req.credentials?.keyId;
    if (keyId === undefined) return null; // parent credentials
    if (this.hasFault("P-R2-02", "scope-not-enforced")) return null;
    const scope = this.tempCreds.get(keyId);
    if (!scope) {
      return jsonResponse(403, { error: "credential unknown or expired" });
    }
    // The official SINGULAR permission enum maps to S3 operations. Note
    // there is deliberately NO put+get-without-delete member: an
    // object-read-write credential can delete inside its scope
    // (P-R2-02 asserts exactly that platform reality).
    const opByMethod: Record<string, string> = { PUT: "put", GET: "get", HEAD: "head", DELETE: "delete", POST: "put" };
    const op = opByMethod[req.method] ?? "admin";
    const allowed: Record<TempCredentialPermission, ReadonlySet<string>> = {
      "admin-read-write": new Set(["put", "get", "head", "delete", "admin"]),
      "admin-read-only": new Set(["get", "head", "admin"]),
      "object-read-write": new Set(["put", "get", "head", "delete"]),
      "object-read-only": new Set(["get", "head"]),
    };
    if (!allowed[scope.permission].has(op)) {
      return jsonResponse(403, { error: `action ${op} not permitted by ${scope.permission}` });
    }
    if (scope.bucket !== bucket || (scope.prefixes.length > 0 && !scope.prefixes.some((p) => key.startsWith(p)))) {
      return jsonResponse(403, { error: "key outside credential prefix scope" });
    }
    return null;
  }

  /** Returns a denial response when a lock rule forbids the mutation. */
  private checkLock(bucket: string, key: string, kind: "overwrite" | "delete"): SeamResponse | null {
    if (this.hasFault("P-R2-03", "lock-not-enforced")) return null;
    for (const rule of this.lockRules.get(bucket) ?? []) {
      if (!rule.enabled) continue;
      if (rule.prefix !== undefined && !key.startsWith(rule.prefix)) continue;
      // Retention active: Indefinite always; Age/Date are treated as
      // active for stored objects (the mock's virtual clock never
      // advances past a retention window during a probe run). A locked
      // object can be neither overwritten nor deleted.
      return jsonResponse(403, { error: `bucket lock rule ${rule.id} forbids ${kind}` });
    }
    return null;
  }

  // -------------------------------------------------------------------------
  // Cloudflare account API surface.
  // -------------------------------------------------------------------------

  private cfapi(req: SeamRequest): SeamResponse {
    // Envelope helper: the mock serves the OFFICIAL response envelope
    // ({errors, messages, result, success}) so the mock lane exercises
    // the real wire format (round-3 P-02).
    const envelope = (status: number, result: unknown, errors: Array<{ code: number; message: string }> = []) =>
      jsonResponse(status, { errors, messages: [], result, success: errors.length === 0 });

    if (req.method === "POST" && req.path === "/r2/temp-access-credentials") {
      // Validate the incoming request against the official DTO — the old
      // {bucket,prefixes,permissions:[...]} shape must be REFUSED, exactly
      // as the real API refuses it.
      let parsed;
      try {
        parsed = validateTempCredentialsCreateRequest(bodyJson(req));
      } catch (err) {
        return envelope(400, null, [
          { code: 10001, message: err instanceof Error ? err.message : String(err) },
        ]);
      }
      const seq = ++this.tempCredSeq;
      // Canary-shaped credentials (AWS-style key id, CANARY markers): the
      // self-test greps the whole evidence tree for these; a single hit
      // means the P-01 redaction pipeline regressed.
      const accessKeyId = `AKIACANARYMOCK${String(seq).padStart(6, "0")}`;
      this.tempCreds.set(accessKeyId, {
        bucket: parsed.bucket,
        prefixes: parsed.prefixes ?? [],
        permission: parsed.permission,
        ttlSeconds: parsed.ttlSeconds,
        parentAccessKeyId: parsed.parentAccessKeyId,
      });
      return envelope(200, {
        accessKeyId,
        secretAccessKey: `MOCKSECRETCANARY${String(seq).padStart(6, "0")}${"x".repeat(24)}`,
        sessionToken: `eyJCANARYMOCKSESSION${seq}.payloadCANARY${seq}.sigCANARY${seq}`,
      });
    }

    const lockMatch = /^\/r2\/buckets\/([^/]+)\/lock$/.exec(req.path);
    if (lockMatch) {
      const bucket = lockMatch[1];
      if (req.method === "GET") {
        // Policy must be continuously machine-verifiable (result envelope).
        return envelope(200, { rules: this.lockRules.get(bucket) ?? [] });
      }
      if (req.method === "PUT") {
        // Only the ADMIN principal may configure locks; the runtime
        // principal (a genuinely different credential in real mode) is
        // refused (P-R2-03 "unauthorized policy mutation").
        if ((req.principal ?? "admin") !== "admin" && !this.hasFault("P-R2-03", "lock-not-enforced")) {
          return envelope(403, null, [{ code: 10000, message: "runtime principal cannot alter lock policy" }]);
        }
        let parsed;
        try {
          parsed = validateBucketLockRulesBody(bodyJson(req));
        } catch (err) {
          return envelope(400, null, [
            { code: 10001, message: err instanceof Error ? err.message : String(err) },
          ]);
        }
        this.lockRules.set(bucket, parsed.rules);
        return envelope(200, { rules: parsed.rules });
      }
    }

    // NOTE: there is no /r2/temp-access-credentials/revoke-parent route in
    // the official API — the pre-fix probe called one that only this mock
    // implemented. It is gone; anything unhandled is 404, like the real API.
    return envelope(404, null, [{ code: 7000, message: `no route for ${req.method} ${req.path}` }]);
  }

  // -------------------------------------------------------------------------
  // Probe-harness surface (DO / container / gateway fakes).
  // -------------------------------------------------------------------------

  private harness(req: SeamRequest): SeamResponse | Promise<SeamResponse> {
    const [path] = req.path.split("?", 2);
    if (path.startsWith("/do/interleave/")) return this.doInterleave(req, path);
    if (path.startsWith("/do/alarm/")) return this.doAlarm(req, path);
    if (path.startsWith("/do/overload/")) return this.doOverload(req, path);
    if (path.startsWith("/do/authority/")) return this.doAuthority(req, path);
    if (path.startsWith("/ctr/lifecycle/")) return this.ctrLifecycle(req, path);
    if (path.startsWith("/ctr/rollout/")) return this.ctrRollout(req, path);
    if (path.startsWith("/ctr/sleep/")) return this.ctrSleep(req, path);
    if (path.startsWith("/ctr/net/")) return this.ctrNet(req, path);
    if (path.startsWith("/worker/gateway/")) return this.workerGateway(req, path);
    return jsonResponse(404, { error: `unhandled harness path ${path}` });
  }

  // --- P-DO-01: request interleaving -------------------------------------

  private doInterleave(req: SeamRequest, path: string): SeamResponse | Promise<SeamResponse> {
    const s = this.interleave;
    switch (path) {
      case "/do/interleave/reset":
        this.interleave = { version: 1, value: "v1", trace: [], commits: 0, gate: null };
        return jsonResponse(200, { ok: true });
      case "/do/interleave/slow-op": {
        // Models a controller procedure that validates, then crosses a
        // non-storage await (the gate), then commits. The probe holds the
        // gate open, lands a conflicting commit, then releases.
        const body = bodyJson(req);
        const readVersion = s.version;
        s.trace.push(`slow:read@v${readVersion}`);
        let release = (): void => undefined;
        const promise = new Promise<void>((resolve) => {
          release = resolve;
        });
        s.gate = { promise, release };
        return promise.then(() => {
          if (s.version !== readVersion && !this.hasFault("P-DO-01", "stale-commit")) {
            // Post-await re-validation: the state moved underneath us, so
            // the stale intention must NOT commit.
            s.trace.push("slow:rejected-stale");
            return jsonResponse(409, { error: "stale validation" });
          }
          s.version += 1;
          s.value = String(body.value);
          s.commits += 1;
          s.trace.push(s.version === readVersion + 1 ? "slow:commit" : "slow:commit-STALE");
          return jsonResponse(200, { committed: true });
        });
      }
      case "/do/interleave/conflict": {
        const body = bodyJson(req);
        s.version += 1;
        s.value = String(body.value);
        s.commits += 1;
        s.trace.push("conflict:commit");
        return jsonResponse(200, { committed: true });
      }
      case "/do/interleave/release": {
        if (!s.gate) return jsonResponse(409, { error: "no parked operation" });
        s.gate.release();
        s.gate = null;
        return jsonResponse(200, { released: true });
      }
      case "/do/interleave/trace":
        return jsonResponse(200, { trace: s.trace, commits: s.commits, version: s.version, value: s.value });
    }
    return jsonResponse(404, { error: path });
  }

  // --- P-DO-02: alarm durability ------------------------------------------

  private doAlarm(req: SeamRequest, path: string): SeamResponse {
    const a = this.alarm;
    switch (path) {
      case "/do/alarm/reset-all":
        this.alarm = {
          virtualNow: 0, durableIntent: null, inMemoryAlarmAt: null,
          throwFirst: false, thrown: false, retries: 0, workDone: new Set(), deliveries: 0,
        };
        return jsonResponse(200, { ok: true });
      case "/do/alarm/schedule": {
        const body = bodyJson(req);
        const workId = String(body.workId);
        const at = Number(body.at);
        // Durable intent is written BEFORE the platform alarm: required
        // work must be reconstructible without trusting alarm delivery.
        a.durableIntent = { workId, at };
        a.inMemoryAlarmAt = at;
        return jsonResponse(200, { scheduled: true });
      }
      case "/do/alarm/config": {
        const body = bodyJson(req);
        a.throwFirst = body.throwFirst === true;
        return jsonResponse(200, { ok: true });
      }
      case "/do/alarm/tick": {
        a.virtualNow += 1;
        const duplicate = (req.headers?.["x-mock-duplicate"] ?? "") === "1";
        const deliveries = duplicate ? 2 : 1;
        // Duplicate delivery models the platform firing ONE due alarm
        // twice: both deliveries observe the same due alarm; only handler
        // idempotency keeps the work single-application.
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
            // Handler throw: the platform retries; the alarm stays set.
            a.thrown = true;
            a.retries += 1;
            results.push("threw");
            continue;
          }
          const workId = a.durableIntent?.workId;
          if (workId !== undefined && !a.workDone.has(workId)) {
            a.workDone.add(workId); // idempotent application
            results.push("done");
          } else {
            results.push("duplicate-ignored");
          }
          handled = true;
        }
        if (handled) a.inMemoryAlarmAt = null;
        return jsonResponse(200, { results });
      }
      case "/do/alarm/do-reset": {
        // DO restart / code update: the in-memory alarm evaporates. A
        // correct controller reconstructs it from the durable intent.
        a.inMemoryAlarmAt = null;
        if (this.hasFault("P-DO-02", "alarm-lost-on-reset")) {
          a.durableIntent = null; // fault: intent lost, work unreconstructible
        } else if (a.durableIntent && !a.workDone.has(a.durableIntent.workId)) {
          a.inMemoryAlarmAt = a.durableIntent.at; // rescheduled from intent
        }
        return jsonResponse(200, { ok: true });
      }
      case "/do/alarm/state":
        return jsonResponse(200, {
          workCount: a.workDone.size,
          alarmScheduled: a.inMemoryAlarmAt !== null,
          retries: a.retries,
          deliveries: a.deliveries,
          virtualNow: a.virtualNow,
        });
    }
    return jsonResponse(404, { error: path });
  }

  // --- P-DO-03: overload and storage budgets ------------------------------

  private doOverload(req: SeamRequest, path: string): SeamResponse {
    const o = this.overload;
    switch (path) {
      case "/do/overload/reset": {
        const body = bodyJson(req);
        this.overload = {
          softBudgetRows: Number(body.softBudgetRows ?? 8),
          hardLimitRows: Number(body.hardLimitRows ?? 12),
          rows: 0, shedCount: 0, alertFired: false,
        };
        return jsonResponse(200, { ok: true });
      }
      case "/do/overload/mutate": {
        if (!this.hasFault("P-DO-03", "no-shedding") && o.rows >= o.softBudgetRows) {
          // Shed BEFORE unsafe growth, with an explicit signal — no blind
          // acceptance up to the hard limit.
          o.shedCount += 1;
          o.alertFired = true;
          return jsonResponse(429, { error: "shed" }, { "x-shed-reason": "row-budget" });
        }
        o.rows += 1;
        return jsonResponse(200, { rows: o.rows });
      }
      case "/do/overload/metrics":
        return jsonResponse(200, {
          rows: o.rows, shedCount: o.shedCount, alertFired: o.alertFired,
          softBudgetRows: o.softBudgetRows, hardLimitRows: o.hardLimitRows,
        });
    }
    return jsonResponse(404, { error: path });
  }

  // --- P-DO-04: incarnation and old-authority rejection --------------------

  private doAuthority(req: SeamRequest, path: string): SeamResponse {
    const au = this.authority;
    switch (path) {
      case "/do/authority/reset":
        this.authority = { incarnation: 1, tokenSeq: 0, tokens: new Map(), actions: [] };
        return jsonResponse(200, { ok: true });
      case "/do/authority/mint": {
        const token = `authority-token-${++au.tokenSeq}`;
        au.tokens.set(token, au.incarnation);
        return jsonResponse(200, { token, incarnation: au.incarnation });
      }
      case "/do/authority/rotate":
        au.incarnation += 1;
        return jsonResponse(200, { incarnation: au.incarnation });
      case "/do/authority/act": {
        const body = bodyJson(req);
        const token = req.headers?.["x-authority-token"] ?? "";
        const minted = au.tokens.get(token);
        if (minted === undefined) return jsonResponse(401, { error: "unknown token" });
        if (minted !== au.incarnation && !this.hasFault("P-DO-04", "old-authority-accepted")) {
          // Old-incarnation authority must be rejected outright.
          return jsonResponse(401, { error: "superseded incarnation" });
        }
        au.actions.push(String(body.action));
        return jsonResponse(200, { performed: String(body.action) });
      }
      case "/do/authority/actions":
        return jsonResponse(200, { actions: au.actions });
    }
    return jsonResponse(404, { error: path });
  }

  // --- P-CTR-01: lifecycle state machine ----------------------------------

  private ctrLifecycle(req: SeamRequest, path: string): SeamResponse {
    const lc = this.lifecycle;
    switch (path) {
      case "/ctr/lifecycle/reset":
        this.lifecycle = { state: "stopped", generation: 0, startCount: 0 };
        return jsonResponse(200, { ok: true });
      case "/ctr/lifecycle/start": {
        if (lc.state === "starting" || lc.state === "running") {
          // Concurrent / duplicate start is idempotent: one instance.
          return jsonResponse(200, { state: lc.state, generation: lc.generation, idempotent: true });
        }
        lc.generation += 1;
        lc.startCount += 1;
        lc.state = "starting";
        return jsonResponse(200, { state: lc.state, generation: lc.generation });
      }
      case "/ctr/lifecycle/port-ready": {
        const body = bodyJson(req);
        const generation = Number(body.generation);
        if (generation !== lc.generation || lc.state !== "starting") {
          if (this.hasFault("P-CTR-01", "stale-callback-applied")) {
            lc.state = "running"; // fault: platform truth corrupted by a stale callback
            return jsonResponse(200, { state: lc.state, appliedStale: true });
          }
          // Stale callback (old generation, or no longer starting): ignored.
          return jsonResponse(409, { error: "stale lifecycle callback", generation: lc.generation });
        }
        lc.state = "running";
        return jsonResponse(200, { state: lc.state });
      }
      case "/ctr/lifecycle/stop": {
        const wasStopped = lc.state === "stopped";
        lc.state = "stopped";
        return jsonResponse(200, { state: lc.state, noop: wasStopped });
      }
      case "/ctr/lifecycle/status":
        return jsonResponse(200, { state: lc.state, generation: lc.generation, startCount: lc.startCount });
    }
    return jsonResponse(404, { error: path });
  }

  // --- P-CTR-02: mixed rollout ---------------------------------------------

  private ctrRollout(req: SeamRequest, path: string): SeamResponse {
    const r = this.rollout;
    switch (path) {
      case "/ctr/rollout/reset": {
        const body = bodyJson(req);
        this.rollout = {
          workerVersion: Number(body.workerVersion ?? 2),
          supportedImages: (body.supportedImages as number[] | undefined) ?? [],
          deployedImage: null, accepted: false, converged: false,
        };
        return jsonResponse(200, { ok: true });
      }
      case "/ctr/rollout/deploy": {
        const body = bodyJson(req);
        const image = Number(body.image);
        const supported = r.supportedImages.includes(image);
        if (!supported && !this.hasFault("P-CTR-02", "unsupported-image-ready")) {
          // The compatibility envelope admits only declared tuples.
          return jsonResponse(409, { error: "outside compatibility envelope", accepted: false });
        }
        r.deployedImage = image;
        r.accepted = true;
        // Fault: an unsupported image becomes ready with no convergence.
        r.converged = !supported && this.hasFault("P-CTR-02", "unsupported-image-ready");
        return jsonResponse(200, { accepted: true, image });
      }
      case "/ctr/rollout/observe-convergence": {
        if (!r.accepted) return jsonResponse(409, { error: "nothing deployed" });
        r.converged = true;
        return jsonResponse(200, { converged: true });
      }
      case "/ctr/rollout/status":
        // ready (database-ready) requires OBSERVED convergence, never
        // deployment submission alone.
        return jsonResponse(200, { image: r.deployedImage, ready: r.accepted && r.converged });
    }
    return jsonResponse(404, { error: path });
  }

  // --- P-CTR-03: sleep and shutdown ---------------------------------------

  private ctrSleep(req: SeamRequest, path: string): SeamResponse {
    const s = this.sleep;
    switch (path) {
      case "/ctr/sleep/reset": {
        const body = bodyJson(req);
        this.sleep = {
          sleepAfter: Number(body.sleepAfter ?? 3),
          idleTicks: 0, openTxns: 0, state: "running", acked: [], deniedStops: 0,
        };
        return jsonResponse(200, { ok: true });
      }
      case "/ctr/sleep/txn-open":
        s.openTxns += 1;
        return jsonResponse(200, { openTxns: s.openTxns });
      case "/ctr/sleep/txn-close":
        s.openTxns = Math.max(0, s.openTxns - 1);
        return jsonResponse(200, { openTxns: s.openTxns });
      case "/ctr/sleep/write": {
        const body = bodyJson(req);
        if (s.state !== "running") return jsonResponse(409, { error: "not running" });
        s.acked.push(String(body.data)); // durably acknowledged
        return jsonResponse(200, { acked: true });
      }
      case "/ctr/sleep/tick": {
        s.idleTicks += 1;
        if (s.state === "running" && s.idleTicks >= s.sleepAfter) {
          if (s.openTxns > 0 && !this.hasFault("P-CTR-03", "sleep-with-open-txn")) {
            // Controller denies hibernation: an open transaction means the
            // inactivity stop would be unsafe.
            s.deniedStops += 1;
          } else {
            s.state = "stopped";
          }
        }
        return jsonResponse(200, { state: s.state, idleTicks: s.idleTicks });
      }
      case "/ctr/sleep/kill":
        // SIGKILL: no graceful path; acknowledged state is durable.
        s.state = "killed";
        return jsonResponse(200, { state: s.state });
      case "/ctr/sleep/recover":
        s.state = "running";
        s.idleTicks = 0;
        return jsonResponse(200, { state: s.state });
      case "/ctr/sleep/state":
        return jsonResponse(200, {
          state: s.state, openTxns: s.openTxns, acked: s.acked, deniedStops: s.deniedStops,
        });
    }
    return jsonResponse(404, { error: path });
  }

  // --- P-CTR-04: networking and placement ----------------------------------

  private ctrNet(req: SeamRequest, path: string): SeamResponse {
    const n = this.net;
    switch (path) {
      case "/ctr/net/reset": {
        const body = bodyJson(req);
        this.net = {
          allowlist: (body.allowlist as string[] | undefined) ?? [],
          enableInternet: body.enableInternet !== false,
          opSeq: 0, ops: new Map(),
        };
        return jsonResponse(200, { ok: true });
      }
      case "/ctr/net/placement":
        // Lifecycle DO and container deliberately in different locations:
        // internal HTTP must not assume colocation.
        return jsonResponse(200, { doLocation: "ewr", containerLocation: "fra", internalHttp: "ok" });
      case "/ctr/net/config": {
        const body = bodyJson(req);
        if (body.enableInternet !== undefined) n.enableInternet = body.enableInternet === true;
        return jsonResponse(200, { enableInternet: n.enableInternet });
      }
      case "/ctr/net/egress": {
        const body = bodyJson(req);
        const host = String(body.host);
        if (!n.enableInternet) return jsonResponse(403, { error: "enableInternet=false" });
        if (!n.allowlist.includes(host) && !this.hasFault("P-CTR-04", "egress-not-denied")) {
          return jsonResponse(403, { error: `egress to ${host} not allowlisted` });
        }
        return jsonResponse(200, { egress: host });
      }
      case "/ctr/net/op-prepare": {
        const opId = `op-${++n.opSeq}`;
        return jsonResponse(200, { opId });
      }
      case "/ctr/net/commit-with-disconnect": {
        const body = bodyJson(req);
        const opId = String(body.opId);
        // The operation commits server-side; the client sees a dropped
        // connection (599). It must remain queryable as committed.
        n.ops.set(opId, "committed");
        return respond(599, { "x-mock-simulated": "client-disconnect" });
      }
    }
    const opMatch = /^\/ctr\/net\/op\/(.+)$/.exec(path);
    if (opMatch) {
      const state = n.ops.get(opMatch[1]);
      return state ? jsonResponse(200, { state }) : jsonResponse(404, { error: "unknown op" });
    }
    return jsonResponse(404, { error: path });
  }

  // --- P-WORKER-01: gateway bounds -----------------------------------------

  private workerGateway(req: SeamRequest, path: string): SeamResponse {
    const [, query = ""] = req.path.split("?", 2);
    const params = new URLSearchParams(query);
    switch (path) {
      case "/worker/gateway/reset": {
        const body = bodyJson(req);
        this.gateway = { bufferBound: Number(body.bufferBound ?? 65536) };
        return jsonResponse(200, { ok: true });
      }
      case "/worker/gateway/stream": {
        const bytes = Number(params.get("bytes") ?? 0);
        const body = new Uint8Array(bytes);
        for (let i = 0; i < bytes; i++) body[i] = i % 251; // deterministic pattern
        // A streaming gateway holds at most bufferBound bytes at once; the
        // full-buffering fault models the forbidden buffer-everything path.
        const maxBuffered = this.hasFault("P-WORKER-01", "full-buffering")
          ? bytes
          : Math.min(bytes, this.gateway.bufferBound);
        return respond(200, {
          "x-max-buffered-bytes": String(maxBuffered),
          "x-buffer-bound": String(this.gateway.bufferBound),
        }, body);
      }
      case "/worker/gateway/object": {
        if (params.get("fail") === "r2-500") {
          // Remote 5xx: the gateway must surface failure and must never
          // hand out a success receipt before exact remote resolution.
          return jsonResponse(502, { error: "upstream r2 500" }, { "x-success-receipt": "none" });
        }
        return jsonResponse(200, { ok: true }, { "x-success-receipt": "resolved" });
      }
      case "/worker/gateway/saturate": {
        const body = bodyJson(req);
        const connections = Number(body.connections ?? 0);
        const permits = 6; // platform six-connection limit
        return jsonResponse(200, {
          peakConcurrent: Math.min(connections, permits),
          queued: Math.max(0, connections - permits),
          incorrectSuccess: false,
        });
      }
    }
    return jsonResponse(404, { error: path });
  }
}
