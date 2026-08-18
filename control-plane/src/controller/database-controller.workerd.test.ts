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
    recordType: 2,
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
      expect(r1).toMatchObject({ ok: true, appendLsn: 0n, typeSequence: 1n, replayed: false });
      const replay = instance.finalizeWalRecord(finalizeReq("op-1"));
      expect(replay).toMatchObject({ ok: true, appendLsn: 0n, replayed: true });
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

  it("register fences the predecessor and serves the U3 read surface on real SqlStorage", async () => {
    const stub = testEnv.CONTROLLER.get(testEnv.CONTROLLER.idFromName("t3"));
    await runInDurableObject(stub, async (instance: DatabaseControllerDO) => {
      instance.registerSession("db1", 1, "sess-1");
      expect(instance.finalizeWalRecord(finalizeReq("a-1"))).toMatchObject({ ok: true });
      expect(
        instance.finalizeWalRecord(finalizeReq("a-2", { sequencingKind: "UNSEQUENCED", recordType: 10 })),
      ).toMatchObject({ ok: true });
      // takeover: the new actor's register revokes the old actor's authority
      instance.registerSession("db1", 1, "sess-2");
      expect(instance.finalizeWalRecord(finalizeReq("a-3"))).toEqual({ ok: false, error: "SESSION_FENCED" });
      expect(
        instance.finalizeWalRecord(finalizeReq("a-4", { startupSessionId: "sess-2" })),
      ).toMatchObject({ ok: true, appendLsn: 2n });

      expect(instance.head("db1", 1)).toEqual({ headLsn: 2n, headTypeSequence: 2n });
      const pinned = instance.openIterator("db1", 1).headLsn;
      const page = instance.scan("db1", 1, {
        fromTypeSequence: 1n, fromLsn: 0n, throughLsn: pinned, recordType: null, limit: 100,
      });
      expect(page.records.map((r) => [r.appendLsn, r.recordType])).toEqual([[0n, 2], [1n, 10], [2n, 2]]);
      const last = instance.lastByType("db1", 1, 10);
      expect(last).toMatchObject({ ok: true });
      if (last.ok) expect(last.record.appendLsn).toBe(1n);
    });
  });
});
