/*
 * Probe implementation contract.
 *
 * A probe receives a context whose ONLY I/O channel is the recording
 * provider seam — it can neither reach the network directly nor bypass
 * evidence capture. Every assertion is DECLARED up front (id +
 * required_in modes) and referenced by id when recorded; the runner
 * derives the verdict fail-closed:
 *
 *   - any failed check                        => FAIL
 *   - any thrown error                        => FAIL (never a pass)
 *   - zero recorded checks                    => FAIL (asserted nothing)
 *   - a check against an UNDECLARED id        => FAIL (out-of-plan)
 *   - a declared assertion required in the current mode with NO recorded
 *     result                                  => FAIL (a probe cannot
 *     silently drop an assertion, and a note can never satisfy one)
 *   - all declared+required satisfied, all recorded pass => PASS
 */

import type { SeamCredentials, SeamRequest, SeamResponse } from "./provider.ts";
import { text, utf8 } from "./provider.ts";

export type ProbeMode = "real" | "mock";

/** One planned assertion. The plan exists before any result does. */
export interface AssertionSpec {
  /** Stable id, unique within the probe (e.g. "cond-create-412"). */
  id: string;
  /** What the assertion claims when it passes. */
  title: string;
  /**
   * Modes in which this assertion MUST produce a result. An assertion
   * only exercisable under mock controllability declares ["mock"]; the
   * run record then shows explicitly that real mode did not cover it.
   */
  required_in: ReadonlyArray<ProbeMode>;
}

export interface ProbeContext {
  fetch(req: SeamRequest): Promise<SeamResponse>;
  readonly mode: ProbeMode;
  /** R2 probe bucket ("mock-bucket" in mock mode). */
  readonly bucket: string;
  /** Unique per run; isolates real-mode keys between runs. */
  readonly runNonce: string;
  /** Parent R2 access key id (temp-credential minting names its parent). */
  readonly parentAccessKeyId: string;
  /**
   * Record one assertion result against a DECLARED assertion id. A false
   * `ok` makes the probe FAIL; an undeclared id makes the probe FAIL.
   */
  check(assertionId: string, ok: boolean, detail: string): void;
  /**
   * Free-form evidence note. Recorded, NEVER verdict-affecting: a note
   * cannot satisfy a required assertion (round-3 P-05).
   */
  note(msg: string): void;
}

export interface ProbeImpl {
  /** Normative probe ID; must appear in the manifest. */
  readonly id: string;
  /** Expected outcome, mirrored into the evidence record. */
  readonly expected: string;
  /** The full assertion plan for this probe (round-3 P-05). */
  readonly assertions: ReadonlyArray<AssertionSpec>;
  run(ctx: ProbeContext): Promise<void>;
}

/** Both modes: the normal case. */
export const BOTH: ReadonlyArray<ProbeMode> = ["mock", "real"];
/** Mock-only: needs fault/timing controllability a live platform lacks. */
export const MOCK_ONLY: ReadonlyArray<ProbeMode> = ["mock"];

// ---------------------------------------------------------------------------
// Shared helpers for probe bodies.
// ---------------------------------------------------------------------------

/** Deterministic filler bytes: `tag` repeated to exactly `length` bytes. */
export function patternBytes(tag: string, length: number): Uint8Array {
  const unit = utf8(tag);
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = unit[i % unit.length];
  return out;
}

/** Parse a JSON object response body; throws (=> probe FAIL) otherwise. */
export function asJson(res: SeamResponse): Record<string, unknown> {
  const parsed: unknown = JSON.parse(text(res.body));
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`expected JSON object body, got: ${text(res.body).slice(0, 120)}`);
  }
  return parsed as Record<string, unknown>;
}

/** Bucket-relative R2 object path namespaced to this run. */
export function r2Key(ctx: ProbeContext, suffix: string): string {
  return `/${ctx.bucket}/probes/${ctx.runNonce}/${suffix}`;
}

export function r2Put(
  ctx: ProbeContext,
  path: string,
  body: Uint8Array,
  headers: Record<string, string> = {},
  credentials?: SeamCredentials,
): Promise<SeamResponse> {
  return ctx.fetch({ service: "r2", method: "PUT", path, headers, body, credentials });
}

export function r2Get(
  ctx: ProbeContext,
  path: string,
  credentials?: SeamCredentials,
): Promise<SeamResponse> {
  return ctx.fetch({ service: "r2", method: "GET", path, credentials });
}

export function r2Delete(
  ctx: ProbeContext,
  path: string,
  credentials?: SeamCredentials,
): Promise<SeamResponse> {
  return ctx.fetch({ service: "r2", method: "DELETE", path, credentials });
}

/** POST a JSON body to the probe-harness surface. */
export function harnessPost(
  ctx: ProbeContext,
  path: string,
  body?: Record<string, unknown>,
  headers: Record<string, string> = {},
): Promise<SeamResponse> {
  return ctx.fetch({
    service: "harness",
    method: "POST",
    path,
    headers: { "content-type": "application/json", ...headers },
    body: body === undefined ? undefined : utf8(JSON.stringify(body)),
  });
}

export function harnessGet(ctx: ProbeContext, path: string): Promise<SeamResponse> {
  return ctx.fetch({ service: "harness", method: "GET", path });
}
