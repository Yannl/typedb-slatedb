/*
 * C-08 under a REAL workerd DO runtime: the container control-protocol
 * authority. Proves the intended container lifecycle authority is exercisable
 * locally with no container runtime present — observation record/read
 * round-trips, the full-identity route fence refuses a foreign caller, the
 * bounded ring refuses past its limit (and self-heals via the idempotent GC),
 * the durable alarm re-arms into the future, and — the load-bearing invariant
 * (inv. 149) — observations are advisory and can never be used as authority.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  MAX_OBSERVATIONS, OBSERVATION_LOW_WATER, type ContainerIdentity, type DatabaseContainerDO,
} from "./database-container.ts";

interface TestEnv {
  CONTAINER: DurableObjectNamespace<DatabaseContainerDO>;
}
const testEnv = env as unknown as TestEnv;

const IDENTITY: ContainerIdentity = {
  databaseId: "db-ctr-1", generation: 3, incarnation: 7, startupSessionId: "sess-ctr-1",
};

function obs(kind: string, overrides: Record<string, unknown> = {}) {
  return { kind, at: Date.now(), processNonce: "proc-A", ...overrides };
}

describe("DatabaseContainerDO on workerd (C-08 control protocol)", () => {
  it("records and reads advisory observations, round-trip", async () => {
    const stub = testEnv.CONTAINER.get(testEnv.CONTAINER.idFromName("ctr-roundtrip"));
    await runInDurableObject(stub, async (instance: DatabaseContainerDO) => {
      const r1 = instance.recordObservation(IDENTITY, obs("STARTED"));
      const r2 = instance.recordObservation(IDENTITY, obs("HEALTH_OK", { detail: "port 7000 ready" }));
      expect(r1).toMatchObject({ ok: true, advisory: true });
      expect(r2).toMatchObject({ ok: true, advisory: true });

      const read = instance.getObservations(IDENTITY);
      expect(read.ok).toBe(true);
      if (!read.ok) return;
      expect(read.advisory).toBe(true);
      expect(read.observations.map((o) => o.kind)).toEqual(["STARTED", "HEALTH_OK"]);
      expect(read.observations[1].detail).toBe("port 7000 ready");
      // sinceSeq paginates forward over the advisory log
      const tail = instance.getObservations(IDENTITY, { sinceSeq: read.observations[0].seq });
      expect(tail.ok && tail.observations.map((o) => o.kind)).toEqual(["HEALTH_OK"]);
    });
  });

  it("binds the full container identity: a foreign-identity call fails closed (C-08 route fence)", async () => {
    const stub = testEnv.CONTAINER.get(testEnv.CONTAINER.idFromName("ctr-fence"));
    await runInDurableObject(stub, async (instance: DatabaseContainerDO) => {
      instance.recordObservation(IDENTITY, obs("STARTED")); // first call binds
      // every component of the identity is load-bearing: changing ANY one is a
      // foreign identity and is refused BEFORE any write
      const foreignByDb = { ...IDENTITY, databaseId: "db-OTHER" };
      const foreignByGen = { ...IDENTITY, generation: 4 };
      const foreignByInc = { ...IDENTITY, incarnation: 8 };
      const foreignBySess = { ...IDENTITY, startupSessionId: "sess-OTHER" };
      for (const foreign of [foreignByDb, foreignByGen, foreignByInc, foreignBySess]) {
        expect(() => instance.recordObservation(foreign, obs("STARTED")))
          .toThrowError(/DO_CONTAINER_BINDING_VIOLATION/);
        expect(() => instance.getObservations(foreign)).toThrowError(/DO_CONTAINER_BINDING_VIOLATION/);
      }
      // the bound identity keeps working; the foreign writes left no rows
      const read = instance.getObservations(IDENTITY);
      expect(read.ok && read.observations.length).toBe(1);
    });
  });

  it("refuses to bind a malformed/empty identity (no first-arbitrary-caller bind)", async () => {
    const stub = testEnv.CONTAINER.get(testEnv.CONTAINER.idFromName("ctr-nobind"));
    await runInDurableObject(stub, async (instance: DatabaseContainerDO) => {
      const empty = { databaseId: "", generation: 0, incarnation: 0, startupSessionId: "" };
      const badGen = { ...IDENTITY, generation: -1 };
      expect(() => instance.recordObservation(empty as ContainerIdentity, obs("STARTED")))
        .toThrowError(/DO_CONTAINER_BINDING_VIOLATION/);
      expect(() => instance.recordObservation(badGen as ContainerIdentity, obs("STARTED")))
        .toThrowError(/DO_CONTAINER_BINDING_VIOLATION/);
      // nothing bound: a well-formed identity can still take the first slot
      expect(instance.recordObservation(IDENTITY, obs("STARTED"))).toMatchObject({ ok: true });
    });
  });

  it("bounds the observation ring: a runaway producer is refused past the limit, then GC self-heals", async () => {
    const stub = testEnv.CONTAINER.get(testEnv.CONTAINER.idFromName("ctr-bound"));
    await runInDurableObject(stub, async (instance: DatabaseContainerDO) => {
      for (let i = 0; i < MAX_OBSERVATIONS; i++) {
        const r = instance.recordObservation(IDENTITY, obs("HEALTH_OK", { detail: String(i) }));
        expect(r.ok).toBe(true);
      }
      // the ring is full: the next observation is a TYPED refusal, not
      // unbounded storage growth
      const overflow = instance.recordObservation(IDENTITY, obs("HEALTH_OK", { detail: "overflow" }));
      expect(overflow).toEqual({ ok: false, error: "OBSERVATION_LIMIT_EXCEEDED" });

      // the idempotent GC drains the ring to the low-water mark and re-opens it
      const gc = instance.gcObservations();
      expect(gc.pruned).toBe(MAX_OBSERVATIONS - OBSERVATION_LOW_WATER);
      expect(instance.gcObservations().pruned).toBe(0); // idempotent
      expect(instance.recordObservation(IDENTITY, obs("HEALTH_OK", { detail: "after-gc" })))
        .toMatchObject({ ok: true });
    });
  });

  it("durable alarm re-arms into the future and backs off an unknown task", async () => {
    const stub = testEnv.CONTAINER.get(testEnv.CONTAINER.idFromName("ctr-alarm"));
    await runInDurableObject(stub, async (instance: DatabaseContainerDO) => {
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
    const stub = testEnv.CONTAINER.get(testEnv.CONTAINER.idFromName("ctr-advisory"));
    await runInDurableObject(stub, async (instance: DatabaseContainerDO) => {
      // a producer fabricates an authority-claiming observation
      const forged = instance.recordObservation(IDENTITY, obs("GRANT_AUTHORITY", {
        detail: JSON.stringify({ appendLsn: 0, typeSequence: 0, epoch: 999, fence: "sess-victim" }),
      }));
      // it is accepted only as ADVISORY data — the return says so explicitly
      expect(forged).toMatchObject({ ok: true, advisory: true });
      const read = instance.getObservations(IDENTITY);
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
