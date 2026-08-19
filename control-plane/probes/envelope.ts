/*
 * Zero-authority refusal and enforced side-effect budgets for the
 * platform probe runner (round-4 findings R4-CF-00 and R4-CF-01).
 *
 * R4-CF-00 (dynamically reproduced by the round-4 audit): the previous
 * runner constructed a REAL provider even when preflight was RED, and its
 * unconditional cleanup issued `PUT .../lock {"rules":[]}` against the
 * refused target. The structural fix is that a refusal path must have
 * ZERO authority: when preflight is RED the runner holds a
 * RefusedProvider whose every fetch throws before any DNS/HTTP work, and
 * cleanup is recorded as refused-zero-authority without touching the
 * network. The provider counts attempts so the run can additionally
 * assert that the count is zero — a nonzero count is itself a failed run.
 *
 * R4-CF-01: the owner-approved envelope was parsed but never enforced.
 * MeteredProvider turns the envelope into a hard side-effect budget:
 *
 *   - request/byte budget is RESERVED BEFORE dispatch — an over-budget
 *     call is refused without reaching the provider;
 *   - the run deadline is absolute wall-clock: any call after it is
 *     refused (a timed-out probe cannot continue making provider calls);
 *   - per-request deadlines are clamped to the envelope's
 *     max_request_seconds AND the remaining run budget;
 *   - every R2 write INTENT (PUT/POST, multipart initiation included) is
 *     journaled before dispatch, so cleanup can reconcile objects whose
 *     responses were lost (timeout-after-commit), not only observed 200s;
 *   - close(reason) makes every further call a typed refusal — the
 *     runner closes the meter when a probe deadline fires and when the
 *     run moves to cleanup, so a raced-out async task loses its provider.
 */

import type { PlatformProvider, ProviderCapabilities, SeamRequest, SeamResponse } from "./provider.ts";

/** Thrown by RefusedProvider: a refusal path holds zero authority. */
export class ZeroAuthorityError extends Error {
  constructor(detail: string) {
    super(`zero-authority provider: ${detail}`);
    this.name = "ZeroAuthorityError";
  }
}

/** Thrown by MeteredProvider when a call would exceed the approved envelope. */
export class EnvelopeExceededError extends Error {
  constructor(detail: string) {
    super(`approved envelope exceeded: ${detail}`);
    this.name = "EnvelopeExceededError";
  }
}

const NO_CAPABILITIES: ProviderCapabilities = { r2: false, cfapi: false, cfapi_runtime: false, harness: false };

/**
 * The provider a RED-preflight real run holds. It can DO nothing: every
 * fetch throws synchronously before any network machinery, and the
 * attempt counter lets the runner prove (and record) that the count was
 * zero. A nonzero count means some code path tried to act on a refused
 * target — that is a runner bug and the run must fail, not merely skip.
 */
export class RefusedProvider implements PlatformProvider {
  readonly mode = "real" as const;
  readonly capabilities: ProviderCapabilities = NO_CAPABILITIES;
  /** Number of fetches attempted against the refused target. Must stay 0. */
  attempts = 0;
  private readonly reason: string;

  constructor(reason: string) {
    this.reason = reason;
  }

  fetch(req: SeamRequest): Promise<SeamResponse> {
    this.attempts += 1;
    return Promise.reject(
      new ZeroAuthorityError(
        `refused run attempted ${req.method} ${req.service}:${req.path} (${this.reason}); ` +
          "a preflight refusal makes zero external calls, cleanup included",
      ),
    );
  }
}

/** The numeric budget derived from a validated owner envelope. */
export interface EnvelopeBudget {
  maxTotalRequests: number;
  maxTotalBytesWritten: number;
  /** Absolute wall-clock instant (ms since epoch) after which every call refuses. */
  runDeadlineAtMs: number;
  maxRequestMs: number;
}

/**
 * Derive the enforced budget from the preflight-validated envelope
 * limits. The caller passes the envelope's `limits` object; every field
 * was already validated positive-finite by preflight, but this re-checks
 * fail-closed because a budget must never be constructed from garbage.
 */
export function budgetFromEnvelope(limits: Record<string, unknown>, nowMs: number): EnvelopeBudget {
  const num = (key: string): number => {
    const v = limits[key];
    if (typeof v !== "number" || !Number.isFinite(v) || v <= 0) {
      throw new EnvelopeExceededError(`envelope limit '${key}' is not a positive finite number; refusing to run`);
    }
    return v;
  };
  return {
    maxTotalRequests: num("max_total_requests"),
    maxTotalBytesWritten: num("max_total_bytes_written"),
    runDeadlineAtMs: nowMs + num("max_run_seconds") * 1000,
    maxRequestMs: num("max_request_seconds") * 1000,
  };
}

/**
 * Enforcing meter around a real provider. Budget is reserved BEFORE
 * dispatch; refusals are typed and never reach the network.
 */
export class MeteredProvider implements PlatformProvider {
  readonly mode: "real" | "mock";
  readonly capabilities: ProviderCapabilities;
  /** R2 write paths journaled BEFORE dispatch (query stripped). */
  readonly attemptedWrites = new Set<string>();
  requestsUsed = 0;
  bytesWritten = 0;
  private closedReason: string | null = null;
  private readonly inner: PlatformProvider;
  private readonly budget: EnvelopeBudget;

  constructor(inner: PlatformProvider, budget: EnvelopeBudget) {
    this.inner = inner;
    this.mode = inner.mode;
    this.capabilities = inner.capabilities;
    this.budget = budget;
  }

  /** After close(), every further call is a typed refusal. */
  close(reason: string): void {
    if (this.closedReason === null) this.closedReason = reason;
  }

  get closed(): boolean {
    return this.closedReason !== null;
  }

  async fetch(req: SeamRequest): Promise<SeamResponse> {
    if (this.closedReason !== null) {
      throw new EnvelopeExceededError(`provider closed (${this.closedReason}); the call was refused before dispatch`);
    }
    const now = Date.now();
    if (now >= this.budget.runDeadlineAtMs) {
      this.close("run deadline reached");
      throw new EnvelopeExceededError("run deadline reached; post-deadline provider calls are refused");
    }
    // --- reserve BEFORE dispatch: an over-budget call never leaves the process ---
    if (this.requestsUsed + 1 > this.budget.maxTotalRequests) {
      throw new EnvelopeExceededError(
        `max_total_requests=${this.budget.maxTotalRequests} exhausted (used ${this.requestsUsed})`,
      );
    }
    const bodyBytes = req.body?.length ?? 0;
    const isWrite = req.method === "PUT" || req.method === "POST";
    if (isWrite && this.bytesWritten + bodyBytes > this.budget.maxTotalBytesWritten) {
      throw new EnvelopeExceededError(
        `max_total_bytes_written=${this.budget.maxTotalBytesWritten} would be exceeded ` +
          `(written ${this.bytesWritten}, next ${bodyBytes})`,
      );
    }
    this.requestsUsed += 1;
    if (isWrite) this.bytesWritten += bodyBytes;
    // --- journal write intent BEFORE dispatch (timeout-after-commit safety) ---
    if (req.service === "r2" && isWrite) {
      this.attemptedWrites.add(req.path.split("?", 1)[0]);
    }
    // --- clamp the request deadline to the envelope and the remaining run ---
    const remainingRunMs = this.budget.runDeadlineAtMs - now;
    const requested = req.deadlineMs ?? this.budget.maxRequestMs;
    const deadlineMs = Math.max(1, Math.min(requested, this.budget.maxRequestMs, remainingRunMs));
    return this.inner.fetch({ ...req, deadlineMs });
  }
}
