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
  /**
   * R6-CF-02: the owner signs `max_cost_usd_cents` and the round-5 code
   * never priced anything, so the economic ceiling was inert (the audit ran
   * an envelope approving one billionth of a cent and still dispatched a
   * Cloudflare API POST and a ~1 MB PUT). Cost is carried in INTEGER
   * MICRO-CENTS: binary floating point must never decide whether a spend is
   * within an owner's approval.
   */
  maxCostMicroCents: number;
}

/**
 * R6-CF-02 pricing. Deliberately CONSERVATIVE and VERSIONED: when a
 * request's true charge is unknowable before dispatch, reserve an upper
 * bound. Reconciling downward would require trustworthy provider evidence,
 * which we do not have mid-run, so nothing is ever refunded — including a
 * request whose response was lost, which really did consume the resource.
 *
 * These are ceilings, not a billing model: they exist so a signed cost can
 * be ENFORCED, and they are intentionally above published list prices.
 */
export const PRICING_MODEL_VERSION = "probe-pricing/v1-conservative";

/** micro-cents (1 cent = 1_000_000 µ¢) reserved per request class. */
const PRICE_MICRO_CENTS = {
  /** R2 Class A (mutating: PUT/POST/DELETE/multipart) — $4.50/million ⇒ 0.45 µ¢/op, reserved 10× */
  r2ClassA: 5,
  /** R2 Class B (GET/HEAD/LIST) — $0.36/million ⇒ 0.036 µ¢/op, reserved ~30× */
  r2ClassB: 1,
  /** Cloudflare API mutation: no per-call price, reserved as a nonzero floor */
  cfApiMutation: 5,
  cfApiRead: 1,
  /** harness/worker call */
  harness: 1,
  /** per MiB of upload, reserved generously against egress/ops amplification */
  perMebibyteWritten: 100,
} as const;

/** The conservative upper-bound charge of one request, in micro-cents. */
export function priceOfRequest(req: { service: string; method: string; body?: Uint8Array | null }): number {
  const isWrite = req.method === "PUT" || req.method === "POST" || req.method === "DELETE";
  let micro: number;
  if (req.service === "r2") micro = isWrite ? PRICE_MICRO_CENTS.r2ClassA : PRICE_MICRO_CENTS.r2ClassB;
  else if (req.service === "harness") micro = PRICE_MICRO_CENTS.harness;
  else micro = isWrite ? PRICE_MICRO_CENTS.cfApiMutation : PRICE_MICRO_CENTS.cfApiRead;
  const bytes = req.body?.length ?? 0;
  if (bytes > 0) {
    micro += Math.ceil((bytes / (1024 * 1024)) * PRICE_MICRO_CENTS.perMebibyteWritten);
  }
  return micro;
}

/**
 * R6-CF-02: ONE shared budget for the whole run.
 *
 * The round-5 runner built two independent meters over the same provider,
 * so cleanup carried its own byte allowance ON TOP of the probe meter's
 * full allowance — two meters configured from a signed 100-byte maximum
 * dispatched 200 aggregate bytes. Every meter now reserves from this single
 * object, and the request partition is explicit:
 * `probeRequests + cleanupRequests === signed max_total_requests`.
 */
export class RunBudgetLedger {
  readonly budget: EnvelopeBudget;
  requestsUsed = 0;
  bytesWritten = 0;
  costMicroCentsUsed = 0;

  constructor(budget: EnvelopeBudget) {
    this.budget = budget;
  }

  /** Reserve one request's resources or throw. Never partially applied. */
  reserve(kind: string, requests: number, bytes: number, costMicroCents: number): void {
    if (this.requestsUsed + requests > this.budget.maxTotalRequests) {
      throw new EnvelopeExceededError(
        `max_total_requests=${this.budget.maxTotalRequests} exhausted across the whole run ` +
          `(used ${this.requestsUsed}, ${kind} needs ${requests})`,
      );
    }
    if (this.bytesWritten + bytes > this.budget.maxTotalBytesWritten) {
      throw new EnvelopeExceededError(
        `max_total_bytes_written=${this.budget.maxTotalBytesWritten} would be exceeded across the ` +
          `whole run (written ${this.bytesWritten}, ${kind} needs ${bytes})`,
      );
    }
    if (this.costMicroCentsUsed + costMicroCents > this.budget.maxCostMicroCents) {
      throw new EnvelopeExceededError(
        `max_cost_usd_cents budget exhausted across the whole run ` +
          `(reserved ${this.costMicroCentsUsed}µ¢ of ${this.budget.maxCostMicroCents}µ¢, ` +
          `${kind} needs ${costMicroCents}µ¢; pricing ${PRICING_MODEL_VERSION})`,
      );
    }
    this.requestsUsed += requests;
    this.bytesWritten += bytes;
    this.costMicroCentsUsed += costMicroCents;
  }

  /** Non-secret accounting for the evidence bundle. */
  report(): Record<string, number | string> {
    return {
      pricing_model: PRICING_MODEL_VERSION,
      signed_max_requests: this.budget.maxTotalRequests,
      signed_max_bytes_written: this.budget.maxTotalBytesWritten,
      signed_max_cost_micro_cents: this.budget.maxCostMicroCents,
      reserved_requests: this.requestsUsed,
      reserved_bytes_written: this.bytesWritten,
      reserved_cost_micro_cents: this.costMicroCentsUsed,
      remaining_requests: this.budget.maxTotalRequests - this.requestsUsed,
      remaining_bytes_written: this.budget.maxTotalBytesWritten - this.bytesWritten,
      remaining_cost_micro_cents: this.budget.maxCostMicroCents - this.costMicroCentsUsed,
    };
  }
}

/**
 * Derive the enforced budget from the preflight-validated envelope
 * limits. The caller passes the envelope's `limits` object; every field
 * was already validated positive-finite by preflight, but this re-checks
 * fail-closed because a budget must never be constructed from garbage.
 */
export function budgetFromEnvelope(
  limits: Record<string, unknown>, nowMs: number, validUntilMs?: number,
): EnvelopeBudget {
  const num = (key: string): number => {
    const v = limits[key];
    if (typeof v !== "number" || !Number.isFinite(v) || v <= 0) {
      throw new EnvelopeExceededError(`envelope limit '${key}' is not a positive finite number; refusing to run`);
    }
    return v;
  };
  // R6-CF-03: the run deadline may never exceed the SIGNED validity end.
  // `nowMs + max_run_seconds` alone let a run plan past its own approval.
  const runDeadlineAtMs = nowMs + num("max_run_seconds") * 1000;
  const clamped = validUntilMs === undefined ? runDeadlineAtMs : Math.min(runDeadlineAtMs, validUntilMs);
  const costCents = num("max_cost_usd_cents");
  const maxCostMicroCents = Math.floor(costCents * 1_000_000);
  if (!Number.isSafeInteger(maxCostMicroCents) || maxCostMicroCents <= 0) {
    throw new EnvelopeExceededError(
      `envelope limit 'max_cost_usd_cents'=${costCents} does not convert to a positive safe integer of ` +
        "micro-cents; refusing (an unrepresentable ceiling cannot be enforced)",
    );
  }
  return {
    maxTotalRequests: num("max_total_requests"),
    maxTotalBytesWritten: num("max_total_bytes_written"),
    runDeadlineAtMs: clamped,
    maxRequestMs: num("max_request_seconds") * 1000,
    maxCostMicroCents,
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
  /** R6-CF-02: the ONE shared run ledger. Every meter reserves here. */
  private readonly ledger: RunBudgetLedger;
  /** This meter's slice of the signed request count (the explicit
   *  probe/cleanup partition), never an allowance ON TOP of the global. */
  private readonly requestShare: number;
  private readonly label: string;

  constructor(
    inner: PlatformProvider,
    ledger: RunBudgetLedger,
    options: { requestShare: number; label: string },
  ) {
    this.inner = inner;
    this.mode = inner.mode;
    this.capabilities = inner.capabilities;
    this.ledger = ledger;
    this.budget = ledger.budget;
    this.requestShare = options.requestShare;
    this.label = options.label;
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
    // This meter's own slice first (the probe/cleanup partition)...
    if (this.requestsUsed + 1 > this.requestShare) {
      throw new EnvelopeExceededError(
        `${this.label} request share=${this.requestShare} exhausted (used ${this.requestsUsed})`,
      );
    }
    const bodyBytes = req.body?.length ?? 0;
    const isWrite = req.method === "PUT" || req.method === "POST";
    // ...then the SHARED run ledger, which is what the owner actually
    // signed. Requests, written bytes and conservative cost all come from
    // one pool, so probe + cleanup can never sum past the approval.
    this.ledger.reserve(this.label, 1, isWrite ? bodyBytes : 0, priceOfRequest(req));
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
