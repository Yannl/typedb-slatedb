/*
 * CT-P3 under a REAL workerd DO runtime: validates that ControllerCore's
 * SyncSql contract binds correctly to DO SqlStorage + transactionSync,
 * exercising finalisation, replay idempotency, digest conflict, and the
 * status singleton in the actual Durable Object environment.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { DatabaseControllerDO } from "./database-controller.ts";

interface TestEnv {
  CONTROLLER: DurableObjectNamespace<DatabaseControllerDO>;
}
const testEnv = env as unknown as TestEnv;

function finalizeReq(operationId: string, overrides: Record<string, unknown> = {}) {
  return {
    databaseId: "db1",
    generation: 1,
    startupSessionId: "sess-1",
    operationId,
    requestDigest: `digest-${operationId}`,
    sequencingKind: "SEQUENCED" as const,
    logicalKey: null,
    payloadKey: `payload/${operationId}`,
    payloadDigest: `pd-${operationId}`,
    payloadLength: 10,
    ...overrides,
  };
}

describe("DatabaseControllerDO on workerd", () => {
  it("finalises, replays idempotently, and rejects digest conflicts", async () => {
    const stub = testEnv.CONTROLLER.get(testEnv.CONTROLLER.idFromName("t1"));
    await runInDurableObject(stub, async (instance: DatabaseControllerDO) => {
      instance.registerSession("db1", 1, "sess-1");
      const r1 = instance.finalizeWalRecord(finalizeReq("op-1"));
      expect(r1).toMatchObject({ ok: true, appendLsn: 0, typeSequence: 1, replayed: false });
      const replay = instance.finalizeWalRecord(finalizeReq("op-1"));
      expect(replay).toMatchObject({ ok: true, appendLsn: 0, replayed: true });
      const conflict = instance.finalizeWalRecord(finalizeReq("op-1", { requestDigest: "tampered" }));
      expect(conflict).toEqual({ ok: false, error: "OPERATION_DIGEST_CONFLICT" });
    });
  });

  it("alarm always re-arms into the future and backs off failing tasks", async () => {
    const stub = testEnv.CONTROLLER.get(testEnv.CONTROLLER.idFromName("t-alarm"));
    await runInDurableObject(stub, async (instance: DatabaseControllerDO) => {
      const before = Date.now();
      await instance.scheduleTask("unknown-task", 60_000);
      // force the row due, then fire: the unknown task throws, so the backoff
      // path must advance next_due_at into the future and count the attempt
      const sql = (instance as unknown as { sql: SqlStorage }).sql;
      sql.exec(`UPDATE alarm_schedule SET next_due_at = ? WHERE task = 'unknown-task'`, before - 1);
      await instance.alarm();
      const row = sql
        .exec(`SELECT next_due_at, attempts FROM alarm_schedule WHERE task = 'unknown-task'`)
        .one() as { next_due_at: number; attempts: number };
      expect(row.attempts).toBe(1);
      expect(Number(row.next_due_at)).toBeGreaterThan(before); // never re-armed into the past
    });
  });

  it("enforces the status singleton inside real transactionSync", async () => {
    const stub = testEnv.CONTROLLER.get(testEnv.CONTROLLER.idFromName("t2"));
    await runInDurableObject(stub, async (instance: DatabaseControllerDO) => {
      instance.registerSession("db1", 1, "sess-1");
      const s1 = instance.finalizeWalRecord(
        finalizeReq("st-1", { sequencingKind: "UNSEQUENCED", logicalKey: "status:cp", payloadDigest: "pd-A" }),
      );
      expect(s1).toMatchObject({ ok: true });
      const dupDifferent = instance.finalizeWalRecord(
        finalizeReq("st-2", { sequencingKind: "UNSEQUENCED", logicalKey: "status:cp", payloadDigest: "pd-B" }),
      );
      expect(dupDifferent).toEqual({ ok: false, error: "STATUS_CONFLICT" });
    });
  });
});
