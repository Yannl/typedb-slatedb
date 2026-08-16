/*
 * Payload facade contract under REAL workerd: puts are create-or-identical
 * with a CONDITIONAL create (If-None-Match: *). Regression for the review
 * finding that the previous get-then-put window let two concurrent puts of
 * different bytes both succeed (last-writer-wins over a digest another
 * client may already have receipt-verified).
 */
import { SELF, env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

interface TestEnv {
  PAYLOADS: R2Bucket;
}
const testEnv = env as unknown as TestEnv;

async function putPayload(key: string, body: string): Promise<Response> {
  return SELF.fetch(`https://facade.local/payload/${key}`, { method: "PUT", body });
}

describe("payload facade on workerd", () => {
  beforeEach(async () => {
    await testEnv.PAYLOADS.delete(["race-key", "seq-key"]);
  });

  it("concurrent puts of DIFFERENT bytes: exactly one create wins, the loser gets 409", async () => {
    const [a, b] = await Promise.all([putPayload("race-key", "bytes-A"), putPayload("race-key", "bytes-B")]);
    const statuses = [a.status, b.status].sort();
    expect(statuses).toEqual([200, 409]);
    const winner = a.status === 200 ? a : b;
    const loser = a.status === 200 ? b : a;
    const winnerBody = (await winner.json()) as { sha256hex: string };
    const loserBody = (await loser.json()) as { ok: boolean; error: string; existing: string };
    expect(loserBody).toMatchObject({ ok: false, error: "PAYLOAD_IMMUTABILITY_VIOLATION" });
    // the stored object is the winner's bytes, attested by the loser's receipt
    expect(loserBody.existing).toBe(winnerBody.sha256hex);
    const stored = await testEnv.PAYLOADS.get("race-key");
    expect(await stored?.text()).toBe(winner === a ? "bytes-A" : "bytes-B");
  });

  it("concurrent puts of IDENTICAL bytes: both succeed, at most one creates", async () => {
    const [a, b] = await Promise.all([putPayload("race-key", "same-bytes"), putPayload("race-key", "same-bytes")]);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    const bodies = (await Promise.all([a.json(), b.json()])) as { deduplicated?: boolean }[];
    expect(bodies.filter((x) => x.deduplicated).length).toBeGreaterThanOrEqual(1);
    const stored = await testEnv.PAYLOADS.get("race-key");
    expect(await stored?.text()).toBe("same-bytes");
  });

  it("sequential create-then-identical is deduplicated; different bytes are 409", async () => {
    const created = await putPayload("seq-key", "v1");
    expect(created.status).toBe(200);
    const dedup = await putPayload("seq-key", "v1");
    expect(dedup.status).toBe(200);
    expect(((await dedup.json()) as { deduplicated?: boolean }).deduplicated).toBe(true);
    const conflict = await putPayload("seq-key", "v2");
    expect(conflict.status).toBe(409);
    // immutable: the original bytes survive the conflicting attempt
    const stored = await testEnv.PAYLOADS.get("seq-key");
    expect(await stored?.text()).toBe("v1");
  });
});
