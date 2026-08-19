/*
 * C-08 under a REAL workerd DO runtime: the container control-protocol
 * authority AFTER R5-SEC-06/09 — a PROVISIONED authority (the provisioning
 * seam itself is exercised in container-provisioning.workerd.test.ts) whose
 * advisory observation store is bounded in rows AND bytes.
 *
 * Executed here: observation record/read round-trips under the provisioned
 * identity; the identity fence refuses a foreign caller typed, before any
 * write; the ring refuses past its ROW limit and past every BYTE cap
 * (R5-SEC-09 mutants: boundary exact, one-byte-over, multibyte character
 * straddling the cap, huge detail, aggregate budget) and self-heals via the
 * idempotent GC; the HTTP ingress caps ACTUAL streamed bytes without
 * trusting Content-Length; the durable alarm re-arms into the future; and —
 * the load-bearing invariant (inv. 149) — observations are advisory and can
 * never be used as authority.
 */
import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  MAX_OBSERVATIONS, MAX_OBSERVATION_DETAIL_BYTES, MAX_OBSERVATION_KIND_BYTES,
  MAX_OBSERVATION_NONCE_BYTES, MAX_OBSERVATION_REQUEST_BYTES, MAX_OBSERVATION_STORED_BYTES,
  OBSERVATION_LOW_WATER, OBSERVATION_STORED_BYTES_LOW_WATER,
  type ContainerIdentity, type DatabaseContainerDO, type Observation,
} from "./database-container.ts";
import {
  containerBinding, containerStub, provisionContainerInstance, TEST_RUNTIME, testIdentity,
} from "./container-test-support.ts";

const RUNTIME_CLAIM = {
  imageDigest: TEST_RUNTIME.imageDigest, protocolVersion: TEST_RUNTIME.protocolVersion,
};

function obs(kind: string, overrides: Record<string, unknown> = {}): Observation {
  return { kind, at: Date.now(), processNonce: "proc-A", ...overrides } as Observation;
}

/** Provisioned instance helper: routes to the derived name and provisions. */
async function withProvisioned(
  databaseId: string,
  fn: (instance: DatabaseContainerDO, identity: ContainerIdentity) => Promise<void> | void,
): Promise<void> {
  const binding = containerBinding(databaseId);
  await runInDurableObject(containerStub(binding), async (instance: DatabaseContainerDO) => {
    await provisionContainerInstance(instance, binding);
    await fn(instance, testIdentity(databaseId));
  });
}

describe("DatabaseContainerDO on workerd (C-08 control protocol)", () => {
  it("records and reads advisory observations under the provisioned identity, round-trip", async () => {
    await withProvisioned("ctr-roundtrip", (instance, identity) => {
      const r1 = instance.recordObservation(identity, obs("STARTED"), RUNTIME_CLAIM);
      const r2 = instance.recordObservation(identity, obs("HEALTH_OK", { detail: "port 7000 ready" }), RUNTIME_CLAIM);
      expect(r1).toMatchObject({ ok: true, advisory: true });
      expect(r2).toMatchObject({ ok: true, advisory: true });

      const read = instance.getObservations(identity);
      expect(read.ok).toBe(true);
      if (!read.ok) return;
      expect(read.advisory).toBe(true);
      expect(read.observations.map((o) => o.kind)).toEqual(["STARTED", "HEALTH_OK"]);
      expect(read.observations[1].detail).toBe("port 7000 ready");
      // sinceSeq paginates forward over the advisory log
      const tail = instance.getObservations(identity, { sinceSeq: read.observations[0].seq });
      expect(tail.ok && tail.observations.map((o) => o.kind)).toEqual(["HEALTH_OK"]);
    });
  });

  it("cross-checks the PROVISIONED identity: a foreign-identity call is a typed refusal before any write", async () => {
    await withProvisioned("ctr-fence", (instance, identity) => {
      expect(instance.recordObservation(identity, obs("STARTED"), RUNTIME_CLAIM)).toMatchObject({ ok: true });
      // every component of the identity is load-bearing: changing ANY one is
      // a foreign identity and is refused typed BEFORE any write
      const foreignByDb = { ...identity, databaseId: "db-other" };
      const foreignByGen = { ...identity, generation: identity.generation + 1 };
      const foreignByInc = { ...identity, incarnation: identity.incarnation + 1 };
      const foreignBySess = { ...identity, startupSessionId: "sess-OTHER" };
      for (const foreign of [foreignByDb, foreignByGen, foreignByInc, foreignBySess]) {
        expect(instance.recordObservation(foreign, obs("STARTED"), RUNTIME_CLAIM))
          .toEqual({ ok: false, error: "DO_CONTAINER_BINDING_MISMATCH" });
        expect(instance.getObservations(foreign)).toEqual({ ok: false, error: "DO_CONTAINER_BINDING_MISMATCH" });
      }
      // malformed identity is its own typed refusal, and binds nothing
      const empty = { databaseId: "", generation: 0, incarnation: 0, startupSessionId: "" };
      expect(instance.recordObservation(empty as ContainerIdentity, obs("STARTED"), RUNTIME_CLAIM))
        .toEqual({ ok: false, error: "CONTAINER_IDENTITY_MALFORMED" });
      // the bound identity keeps working; the foreign attempts left no rows
      const read = instance.getObservations(identity);
      expect(read.ok && read.observations.length).toBe(1);
    });
  });

  it("MUTANT (old image): a caller presenting a stale/foreign runtime descriptor is refused typed (R5-SEC-07)", async () => {
    await withProvisioned("ctr-runtime", (instance, identity) => {
      const staleImage = { ...RUNTIME_CLAIM, imageDigest: `sha256:${"ee".repeat(32)}` };
      expect(instance.recordObservation(identity, obs("STARTED"), staleImage))
        .toEqual({ ok: false, error: "CONTAINER_RUNTIME_MISMATCH", field: "imageDigest" });
      const wrongProto = { ...RUNTIME_CLAIM, protocolVersion: "typedb-container-control/999" };
      expect(instance.recordObservation(identity, obs("STARTED"), wrongProto))
        .toEqual({ ok: false, error: "CONTAINER_RUNTIME_MISMATCH", field: "protocolVersion" });
      // a claim omitting the descriptor is a refusal, not a bypass
      expect(instance.recordObservation(identity, obs("STARTED"), {}))
        .toEqual({ ok: false, error: "CONTAINER_RUNTIME_MISMATCH", field: "imageDigest" });
      // nothing was written by any of the refusals
      const read = instance.getObservations(identity);
      expect(read.ok && read.observations.length).toBe(0);
    });
  });

  it("bounds the observation ring by ROWS: a runaway producer is refused past the limit, then GC self-heals", async () => {
    await withProvisioned("ctr-bound", (instance, identity) => {
      for (let i = 0; i < MAX_OBSERVATIONS; i++) {
        const r = instance.recordObservation(identity, obs("HEALTH_OK", { detail: String(i) }), RUNTIME_CLAIM);
        expect(r.ok).toBe(true);
      }
      // the ring is full: the next observation is a TYPED refusal, not
      // unbounded storage growth
      const overflow = instance.recordObservation(identity, obs("HEALTH_OK", { detail: "overflow" }), RUNTIME_CLAIM);
      expect(overflow).toEqual({ ok: false, error: "OBSERVATION_LIMIT_EXCEEDED" });

      // the idempotent GC drains the ring to the low-water mark and re-opens it
      const gc = instance.gcObservations();
      expect(gc.pruned).toBe(MAX_OBSERVATIONS - OBSERVATION_LOW_WATER);
      expect(instance.gcObservations().pruned).toBe(0); // idempotent
      expect(instance.recordObservation(identity, obs("HEALTH_OK", { detail: "after-gc" }), RUNTIME_CLAIM))
        .toMatchObject({ ok: true });
    });
  });

  describe("R5-SEC-09: observation BYTES are bounded (typed refusal, never truncation)", () => {
    it("MUTANT (boundary exact / one-byte-over): detail at exactly the cap passes; one byte over refuses, naming the field", async () => {
      await withProvisioned("ctr-bytes-boundary", (instance, identity) => {
        const exact = instance.recordObservation(
          identity, obs("HEALTH_OK", { detail: "a".repeat(MAX_OBSERVATION_DETAIL_BYTES) }), RUNTIME_CLAIM);
        expect(exact).toMatchObject({ ok: true, advisory: true });
        const over = instance.recordObservation(
          identity, obs("HEALTH_OK", { detail: "a".repeat(MAX_OBSERVATION_DETAIL_BYTES + 1) }), RUNTIME_CLAIM);
        expect(over).toEqual({
          ok: false, error: "OBSERVATION_FIELD_TOO_LARGE", field: "detail",
          maxBytes: MAX_OBSERVATION_DETAIL_BYTES, actualBytes: MAX_OBSERVATION_DETAIL_BYTES + 1,
        });
        // the refusal wrote nothing: exactly one observation stands, intact
        const read = instance.getObservations(identity);
        expect(read.ok && read.observations.length).toBe(1);
        expect(read.ok && read.observations[0].detail?.length).toBe(MAX_OBSERVATION_DETAIL_BYTES);
      });
    });

    it("MUTANT (multibyte straddle): UTF-8 BYTES are capped, not UTF-16 length — 3-byte chars cannot smuggle 3x the budget", async () => {
      await withProvisioned("ctr-bytes-multibyte", (instance, identity) => {
        // 1365 x '€' (3 bytes) + 'a' = exactly 4096 bytes -> admitted
        const exact = "€".repeat(1365) + "a";
        expect(instance.recordObservation(identity, obs("HEALTH_OK", { detail: exact }), RUNTIME_CLAIM))
          .toMatchObject({ ok: true });
        // 1366 x '€' = 4098 bytes but .length is only 1366 — a UTF-16 length
        // check would admit it with 4098 stored bytes; the byte cap refuses
        const straddle = "€".repeat(1366);
        expect(straddle.length).toBeLessThan(MAX_OBSERVATION_DETAIL_BYTES);
        expect(instance.recordObservation(identity, obs("HEALTH_OK", { detail: straddle }), RUNTIME_CLAIM))
          .toEqual({
            ok: false, error: "OBSERVATION_FIELD_TOO_LARGE", field: "detail",
            maxBytes: MAX_OBSERVATION_DETAIL_BYTES, actualBytes: 4098,
          });
        // kind and processNonce byte caps refuse the same way, named
        expect(instance.recordObservation(identity, obs("k".repeat(MAX_OBSERVATION_KIND_BYTES + 1)), RUNTIME_CLAIM))
          .toMatchObject({ ok: false, error: "OBSERVATION_FIELD_TOO_LARGE", field: "kind" });
        expect(instance.recordObservation(
          identity, obs("HEALTH_OK", { processNonce: "n".repeat(MAX_OBSERVATION_NONCE_BYTES + 1) }), RUNTIME_CLAIM))
          .toMatchObject({ ok: false, error: "OBSERVATION_FIELD_TOO_LARGE", field: "processNonce" });
      });
    });

    it("MUTANT (huge detail): a multi-hundred-KiB detail is refused outright", async () => {
      await withProvisioned("ctr-bytes-huge", (instance, identity) => {
        const huge = instance.recordObservation(
          identity, obs("HEALTH_OK", { detail: "x".repeat(512 * 1024) }), RUNTIME_CLAIM);
        expect(huge).toMatchObject({ ok: false, error: "OBSERVATION_FIELD_TOO_LARGE", field: "detail" });
        const read = instance.getObservations(identity);
        expect(read.ok && read.observations.length).toBe(0);
      });
    });

    it("MUTANT (aggregate budget): max-size details exhaust the stored-byte budget LONG before the row cap; typed refusal, GC self-heals", async () => {
      await withProvisioned("ctr-bytes-budget", (instance, identity) => {
        const detail = "d".repeat(MAX_OBSERVATION_DETAIL_BYTES);
        let refusal: unknown = null;
        let admitted = 0;
        for (let i = 0; i < MAX_OBSERVATIONS; i++) {
          const r = instance.recordObservation(identity, obs("HEALTH_OK", { detail }), RUNTIME_CLAIM);
          if (!r.ok) { refusal = r; break; }
          admitted += 1;
        }
        // the budget bound, not the row bound, is what stopped the producer
        expect(admitted).toBeLessThan(MAX_OBSERVATIONS / 4);
        expect(refusal).toMatchObject({
          ok: false, error: "OBSERVATION_BUDGET_EXCEEDED", maxBytes: MAX_OBSERVATION_STORED_BYTES,
        });
        // GC trims to the BYTE low-water mark too, and the ring re-opens
        const gc = instance.gcObservations();
        expect(gc.pruned).toBeGreaterThan(0);
        const read = instance.getObservations(identity, { limit: MAX_OBSERVATIONS });
        const keptBytes = read.ok
          ? read.observations.reduce((sum, o) => sum + new TextEncoder().encode(
              o.kind + o.processNonce + (o.detail ?? "")).byteLength, 0)
          : Infinity;
        expect(keptBytes).toBeLessThanOrEqual(OBSERVATION_STORED_BYTES_LOW_WATER);
        expect(instance.recordObservation(identity, obs("HEALTH_OK", { detail }), RUNTIME_CLAIM))
          .toMatchObject({ ok: true });
      });
    });

    it("MUTANT (underdeclared/chunked body): the HTTP ingress caps ACTUAL streamed bytes — Content-Length is never trusted", async () => {
      await withProvisioned("ctr-ingress", async (instance, identity) => {
        // (a) an oversized STREAMED body (no trustworthy Content-Length at
        // all) is refused at the cap on actual bytes — 413, nothing parsed
        const oversized = new Uint8Array(MAX_OBSERVATION_REQUEST_BYTES + 1).fill(0x61);
        const lying = await instance.fetch(new Request("https://container/observe", {
          method: "POST",
          headers: { "content-length": "10" }, // a lie; the reader never consults it
          body: new ReadableStream<Uint8Array>({
            start(controller) {
              // chunked: two halves, so no single enqueue equals the total
              controller.enqueue(oversized.subarray(0, 8 * 1024));
              controller.enqueue(oversized.subarray(8 * 1024));
              controller.close();
            },
          }),
        }));
        expect(lying.status).toBe(413);
        expect(((await lying.json()) as { error: string }).error).toBe("OBSERVATION_REQUEST_TOO_LARGE");

        // (b) a well-formed request lands in the SAME gated recordObservation
        const good = await instance.fetch(new Request("https://container/observe", {
          method: "POST",
          body: JSON.stringify({
            identity, observation: obs("STARTED"), containerRuntime: RUNTIME_CLAIM,
          }),
        }));
        expect(good.status).toBe(200);
        expect(await good.json()).toMatchObject({ ok: true, advisory: true });

        // (c) a foreign identity through the ingress is the same typed 403
        const foreign = await instance.fetch(new Request("https://container/observe", {
          method: "POST",
          body: JSON.stringify({
            identity: { ...identity, startupSessionId: "sess-OTHER" },
            observation: obs("STARTED"), containerRuntime: RUNTIME_CLAIM,
          }),
        }));
        expect(foreign.status).toBe(403);
        expect(((await foreign.json()) as { error: string }).error).toBe("DO_CONTAINER_BINDING_MISMATCH");
      });
    });
  });

  it("durable alarm re-arms into the future and backs off an unknown task", async () => {
    const binding = containerBinding("ctr-alarm");
    await runInDurableObject(containerStub(binding), async (instance: DatabaseContainerDO) => {
      const before = Date.now();
      await instance.scheduleTask("unknown-task", 60_000);
      const sql = (instance as unknown as { sql: SqlStorage }).sql;
      sql.exec(`UPDATE container_alarm_schedule SET next_due_at = ? WHERE task = 'unknown-task'`, before - 1);
      await instance.alarm();
      const row = sql
        .exec(`SELECT next_due_at, attempts FROM container_alarm_schedule WHERE task = 'unknown-task'`)
        .one() as { next_due_at: number; attempts: number };
      expect(Number(row.attempts)).toBe(1);
      expect(Number(row.next_due_at)).toBeGreaterThan(before); // never re-armed into the past
    });
  });

  it("observations are ADVISORY, never authority (inv. 149)", async () => {
    await withProvisioned("ctr-advisory", (instance, identity) => {
      // a producer fabricates an authority-claiming observation
      const forged = instance.recordObservation(identity, obs("GRANT_AUTHORITY", {
        detail: JSON.stringify({ appendLsn: 0, typeSequence: 0, epoch: 999, fence: "sess-victim" }),
      }), RUNTIME_CLAIM);
      // it is accepted only as ADVISORY data — the return says so explicitly
      expect(forged).toMatchObject({ ok: true, advisory: true });
      const read = instance.getObservations(identity);
      expect(read.ok && read.advisory).toBe(true);
      // and it round-trips as opaque data, nothing more
      expect(read.ok && read.observations[0].kind).toBe("GRANT_AUTHORITY");

      // structural proof the surface holds NO authority: none of the
      // sequence/epoch/capability/fence/checkpoint methods exist on it
      // (inv. 148-150). This DO cannot allocate or fence anything.
      const surface = instance as unknown as Record<string, unknown>;
      for (const authorityMethod of [
        "finalizeWalRecord", "finalizeBatch", "issueCapability", "useCapability",
        "bumpIncarnation", "registerSession", "fenceSession", "activateSession",
        "openCheckpointCut", "activateCheckpointCut", "resolveCapabilityUse",
      ]) {
        expect(typeof surface[authorityMethod]).toBe("undefined");
      }
    });
  });
});
