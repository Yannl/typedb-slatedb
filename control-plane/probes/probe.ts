/*
 * Probe implementation contract.
 *
 * A probe receives a context whose ONLY I/O channel is the recording
 * provider seam — it can neither reach the network directly nor bypass
 * evidence capture. Every assertion goes through ctx.check(); the runner
 * derives the verdict fail-closed:
 *
 *   - any failed check          => FAIL
 *   - any thrown error          => FAIL (an exception is never a pass)
 *   - zero recorded checks      => FAIL (a probe that asserted nothing
 *                                  proved nothing — audit C-P0-10)
 *   - all checks pass (>= 1)    => PASS
 */

import type { SeamCredentials, SeamRequest, SeamResponse } from "./provider.ts";
import { text, utf8 } from "./provider.ts";

export interface ProbeContext {
  fetch(req: SeamRequest): Promise<SeamResponse>;
  readonly mode: "real" | "mock";
  /** R2 probe bucket ("mock-bucket" in mock mode). */
  readonly bucket: string;
  /** Unique per run; isolates real-mode keys between runs. */
  readonly runNonce: string;
  /** Record one assertion. A false `ok` makes the probe FAIL. */
  check(ok: boolean, label: string): void;
  /** Free-form evidence note (recorded, not verdict-affecting). */
  note(msg: string): void;
}

export interface ProbeImpl {
  /** Normative probe ID; must appear in the manifest. */
  readonly id: string;
  /** Expected outcome, mirrored into the evidence record. */
  readonly expected: string;
  run(ctx: ProbeContext): Promise<void>;
}

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
