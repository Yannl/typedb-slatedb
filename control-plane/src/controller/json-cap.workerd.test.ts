/*
 * R5-PERF-02 mutants: the structural JSON cap must bind ACTUAL BYTES.
 *
 * The audit's finding: `readJson` checked `content-length` and then called
 * `request.json()`, so the cap was a property of a client-supplied header.
 * A chunked body (no length) or an under-declared one could materialise
 * past the cap inside the isolate before anything refused it.
 *
 * These exercise the SHIPPED reader (`readJson`, imported from the worker
 * entry — not a copy) against hand-built streams and hand-set headers,
 * because `fetch` recomputes `content-length` and therefore cannot express
 * the under-declaration mutant at all. The route wiring is then pinned with
 * real requests through `SELF`.
 *
 * Mutants:
 *   chunked (no declared length) oversized body -> refused
 *   declared-small / actual-large               -> refused, cap not exceeded
 *   exactly at the cap                          -> ACCEPTED
 *   one byte over the cap                       -> refused
 *   invalid multibyte UTF-8                     -> refused (not U+FFFD)
 *   deep nesting                                -> refused before parsing
 */
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { readJson } from "./worker-entry.ts";
import { provisionViaSelf } from "./workerd-test-support.ts";

const CAP = 1024;

/** A request-shaped value carrying exactly what the reader consumes: the
 *  headers (including a DELIBERATELY WRONG content-length where the mutant
 *  needs one) and the body stream. */
function bodyBearing(bytes: Uint8Array, declared?: number | null, chunk = 64) {
  const headers = new Headers();
  if (declared !== null) headers.set("content-length", String(declared ?? bytes.byteLength));
  return {
    headers,
    body: new ReadableStream<Uint8Array>({
      start(controller) {
        for (let i = 0; i < bytes.byteLength; i += chunk) {
          controller.enqueue(bytes.subarray(i, Math.min(i + chunk, bytes.byteLength)));
        }
        controller.close();
      },
    }),
  };
}

async function refusal(result: Awaited<ReturnType<typeof readJson>>): Promise<{ status: number; error: string }> {
  expect("errorResponse" in result).toBe(true);
  const response = (result as { errorResponse: Response }).errorResponse;
  return { status: response.status, error: ((await response.json()) as { error: string }).error };
}

/** A JSON object whose UTF-8 encoding is EXACTLY `size` bytes. */
function jsonOfExactly(size: number): Uint8Array {
  const envelope = '{"pad":""}';
  const pad = "a".repeat(size - envelope.length);
  const bytes = new TextEncoder().encode(`{"pad":"${pad}"}`);
  expect(bytes.byteLength).toBe(size);
  return bytes;
}

describe("R5-PERF-02 structural JSON cap binds actual bytes", () => {
  it("MUTANT: a chunked body (no declared length) is refused — an unbounded stream is never admitted", async () => {
    const oversized = new TextEncoder().encode(`{"pad":"${"a".repeat(CAP * 4)}"}`);
    expect(await refusal(await readJson(bodyBearing(oversized, null), CAP)))
      .toEqual({ status: 411, error: "CONTENT_LENGTH_REQUIRED" });
    // and through the real route, with the real default cap
    const chunked = await SELF.fetch("https://facade.local/session/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: new ReadableStream<Uint8Array>({
        start(controller) { controller.enqueue(oversized); controller.close(); },
      }),
      // @ts-expect-error duplex is required for a streaming request body
      duplex: "half",
    });
    expect(chunked.status).toBe(411);
    expect(((await chunked.json()) as { error: string }).error).toBe("CONTENT_LENGTH_REQUIRED");
  });

  it("MUTANT: a body that DECLARES 10 bytes and sends far more is refused on actual bytes", async () => {
    const oversized = jsonOfExactly(CAP * 4);
    const verdict = await refusal(await readJson(bodyBearing(oversized, 10), CAP));
    expect(verdict).toEqual({ status: 413, error: "REQUEST_BODY_TOO_LARGE" });
  });

  it("MUTANT: an under-declared body that still fits the cap is refused as a length contradiction", async () => {
    const body = jsonOfExactly(512);
    const verdict = await refusal(await readJson(bodyBearing(body, 10), CAP));
    expect(verdict).toEqual({ status: 400, error: "CONTENT_LENGTH_MISMATCH" });
  });

  it("MUTANT: an OVER-declared body (declares more than it sends) is refused too", async () => {
    const body = jsonOfExactly(512);
    const verdict = await refusal(await readJson(bodyBearing(body, 900), CAP));
    expect(verdict).toEqual({ status: 400, error: "CONTENT_LENGTH_MISMATCH" });
  });

  it("MUTANT: a body of EXACTLY the cap is accepted", async () => {
    const body = jsonOfExactly(CAP);
    const result = await readJson(bodyBearing(body, CAP), CAP);
    expect("body" in result).toBe(true);
    expect(Object.keys((result as { body: Record<string, unknown> }).body)).toEqual(["pad"]);
  });

  it("MUTANT: one byte over the cap is refused", async () => {
    const body = jsonOfExactly(CAP + 1);
    // honestly declared: refused before a byte is read
    expect(await refusal(await readJson(bodyBearing(body, CAP + 1), CAP)))
      .toEqual({ status: 413, error: "REQUEST_BODY_TOO_LARGE" });
    // declared AT the cap but one byte longer on the wire: the stream cap
    // catches it, which is the property the header check cannot provide
    expect(await refusal(await readJson(bodyBearing(body, CAP), CAP)))
      .toEqual({ status: 413, error: "REQUEST_BODY_TOO_LARGE" });
  });

  it("MUTANT: invalid multibyte UTF-8 is refused, never replaced with U+FFFD", async () => {
    // a valid JSON frame with a truncated 3-byte sequence inside the string
    const body = new Uint8Array([
      ...new TextEncoder().encode('{"pad":"'), 0xe2, 0x82, ...new TextEncoder().encode('"}'),
    ]);
    const verdict = await refusal(await readJson(bodyBearing(body, body.byteLength), CAP));
    expect(verdict).toEqual({ status: 400, error: "MALFORMED_UTF8" });
    // a lone continuation byte is refused as well
    const lone = new Uint8Array([
      ...new TextEncoder().encode('{"pad":"'), 0x80, ...new TextEncoder().encode('"}'),
    ]);
    expect(await refusal(await readJson(bodyBearing(lone, lone.byteLength), CAP)))
      .toEqual({ status: 400, error: "MALFORMED_UTF8" });
  });

  it("MUTANT: deep nesting is refused by the documented depth bound, before JSON.parse runs", async () => {
    const depth = 200;
    const text = `{"a":${"[".repeat(depth)}${"]".repeat(depth)}}`;
    const body = new TextEncoder().encode(text);
    const verdict = await refusal(await readJson(bodyBearing(body, body.byteLength), CAP));
    expect(verdict).toEqual({ status: 400, error: "JSON_TOO_DEEP" });
    // a shape at the documented bound still parses (the limit is 32; the
    // outer object counts as one level)
    const okText = `{"a":${"[".repeat(31)}1${"]".repeat(31)}}`;
    const okBody = new TextEncoder().encode(okText);
    const okResult = await readJson(bodyBearing(okBody, okBody.byteLength), CAP);
    expect("body" in okResult).toBe(true);
    // brackets inside a STRING do not count toward depth
    const stringy = new TextEncoder().encode(`{"a":"${"[".repeat(200)}"}`);
    expect("body" in await readJson(bodyBearing(stringy, stringy.byteLength), CAP)).toBe(true);
  });

  it("the route wiring is unchanged for honest bodies: a normal request still works", async () => {
    const db = "json-cap-db";
    expect((await provisionViaSelf(db)).status).toBe(200);
    // no capability header -> the body is read and parsed, then the token
    // check refuses; proves the reader admitted the well-formed body
    const response = await SELF.fetch("https://facade.local/session/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ databaseId: db, generation: 1, startupSessionId: "sess-json" }),
    });
    expect(response.status).toBe(401);
    expect(((await response.json()) as { error: string }).error).toBe("CAPABILITY_REQUIRED");
  });

  it("an oversized HONEST body is refused at the declared-length gate on the real route", async () => {
    const huge = "a".repeat(300 * 1024);
    const response = await SELF.fetch("https://facade.local/session/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ databaseId: "x", generation: 1, startupSessionId: huge }),
    });
    expect(response.status).toBe(413);
    expect(((await response.json()) as { error: string }).error).toBe("REQUEST_BODY_TOO_LARGE");
  });
});
