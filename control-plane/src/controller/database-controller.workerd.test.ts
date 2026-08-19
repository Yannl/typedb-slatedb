/*
 * CT-P3 under a REAL workerd DO runtime: validates that ControllerCore's
 * SyncSql contract binds correctly to DO SqlStorage + transactionSync,
 * exercising finalisation, replay idempotency, digest conflict, and the
 * status singleton in the actual Durable Object environment.
 */
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { DatabaseControllerDO } from "./database-controller.ts";
import { provisionInstance } from "./workerd-test-support.ts";

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
      await provisionInstance(instance, "db1");
      instance.registerSession("db1", 1, "sess-1");
      instance.setBudgets("db1",
        { maxUnpublishedOutbox: 1000, maxPayloadLength: 100_000, maxTailRecords: 100_000 }, "sess-1");
      const r1 = instance.finalizeWalRecord(finalizeReq("op-1"));
      expect(r1).toMatchObject({ ok: true, appendLsn: 0n, typeSequence: 1n, replayed: false });
      const replay = instance.finalizeWalRecord(finalizeReq("op-1"));
      expect(replay).toMatchObject({ ok: true, appendLsn: 0n, replayed: true });
      const conflict = instance.finalizeWalRecord(finalizeReq("op-1", { requestDigest: "tampered" }));
      expect(conflict).toEqual({ ok: false, error: "OPERATION_DIGEST_CONFLICT" });
    });
  });

  it("binds the database identity durably: a cross-database call fails closed (C-P0-02)", async () => {
    const stub = testEnv.CONTROLLER.get(testEnv.CONTROLLER.idFromName("t-binding"));
    await runInDurableObject(stub, async (instance: DatabaseControllerDO) => {
      await provisionInstance(instance, "db1"); // ONLY provisioning binds (R4 PR1)
      instance.registerSession("db1", 1, "sess-1");
      expect(() => instance.registerSession("db-OTHER", 1, "sess-x"))
        .toThrowError(/DO_DATABASE_BINDING_VIOLATION/);
      expect(() => instance.finalizeWalRecord(finalizeReq("op-x", { databaseId: "db-OTHER" })))
        .toThrowError(/DO_DATABASE_BINDING_VIOLATION/);
      expect(() => instance.head("db-OTHER", 1)).toThrowError(/DO_DATABASE_BINDING_VIOLATION/);
      // the bound identity keeps working
      instance.registerSession("db1", 1, "sess-2");
    });
  });

  it("R5-SEC-04: a lost response CONVERGES on the exact original outcome (no permanent 409)", async () => {
    const stub = testEnv.CONTROLLER.get(testEnv.CONTROLLER.idFromName("t-ambiguous"));
    await runInDurableObject(stub, async (instance: DatabaseControllerDO) => {
      await provisionInstance(instance, "db1");
      instance.registerSession("db1", 1, "sess-1");
      instance.setBudgets("db1",
        { maxUnpublishedOutbox: 1000, maxPayloadLength: 100_000, maxTailRecords: 100_000 }, "sess-1");

      // the use is claimed and bound to its authoritative effect, the effect
      // COMMITS, and then the response is lost — recorded AMBIGUOUS
      const core = (instance as unknown as { controllerCore: {
        claimCapability: (n: string, d: string, e: number, w: number, eff?: unknown) => { ok: boolean };
        resolveCapabilityUse: (n: string, s: string, r: string) => unknown;
      } }).controllerCore;
      const req = finalizeReq("op-lost");
      core.claimCapability("nonce-lost", "usedigest-lost", Date.now() + 600_000, Date.now() - 120_000,
        { kind: "WAL_FINALIZE", databaseId: "db1", generation: 1,
          operationId: "op-lost", requestDigest: req.requestDigest });
      const receipt = instance.finalizeWalRecord(req);
      expect(receipt).toMatchObject({ ok: true });
      core.resolveCapabilityUse("nonce-lost", "AMBIGUOUS", JSON.stringify({ error: "socket hang up" }));

      // the retry path asks the authority to settle it: SETTLED with the
      // exact original receipt, not CAPABILITY_IN_FLIGHT forever
      const settled = await instance.resolveAmbiguousUse("nonce-lost");
      expect(settled).toMatchObject({ ok: true, disposition: "SETTLED", state: "RESOLVED_SUCCESS" });
      const body = JSON.parse((settled as { response: string }).response) as
        { status: number; body: Record<string, unknown> };
      expect(body.status).toBe(200);
      expect(String(body.body.appendLsn)).toBe(String((receipt as { appendLsn: bigint }).appendLsn));
    });
  });

  it("R5-SEC-04: contradictory durable evidence quarantines the use terminally", async () => {
    const stub = testEnv.CONTROLLER.get(testEnv.CONTROLLER.idFromName("t-quarantine"));
    await runInDurableObject(stub, async (instance: DatabaseControllerDO) => {
      await provisionInstance(instance, "db1");
      instance.registerSession("db1", 1, "sess-1");
      instance.setBudgets("db1",
        { maxUnpublishedOutbox: 1000, maxPayloadLength: 100_000, maxTailRecords: 100_000 }, "sess-1");
      const core = (instance as unknown as { controllerCore: {
        claimCapability: (n: string, d: string, e: number, w: number, eff?: unknown) => { ok: boolean };
        resolveCapabilityUse: (n: string, s: string, r: string) => unknown;
      } }).controllerCore;

      instance.finalizeWalRecord(finalizeReq("op-contra"));
      // same operation identity recorded under a DIFFERENT request digest
      core.claimCapability("nonce-contra", "usedigest-contra", Date.now() + 600_000, Date.now() - 120_000,
        { kind: "WAL_FINALIZE", databaseId: "db1", generation: 1,
          operationId: "op-contra", requestDigest: "f".repeat(64) });
      core.resolveCapabilityUse("nonce-contra", "AMBIGUOUS", JSON.stringify({ error: "lost" }));

      const settled = await instance.resolveAmbiguousUse("nonce-contra");
      expect(settled).toMatchObject({ ok: false, error: "CAPABILITY_USE_QUARANTINED" });
      // and it stays refused — the quarantine is terminal
      expect(await instance.resolveAmbiguousUse("nonce-contra"))
        .toMatchObject({ ok: false, error: "CAPABILITY_USE_QUARANTINED" });
    });
  });

  it("R5-SEC-04: the alarm reducer settles aged unresolved uses without any retry", async () => {
    const stub = testEnv.CONTROLLER.get(testEnv.CONTROLLER.idFromName("t-sweep"));
    await runInDurableObject(stub, async (instance: DatabaseControllerDO) => {
      await provisionInstance(instance, "db1");
      instance.registerSession("db1", 1, "sess-1");
      instance.setBudgets("db1",
        { maxUnpublishedOutbox: 1000, maxPayloadLength: 100_000, maxTailRecords: 100_000 }, "sess-1");
      const core = (instance as unknown as { controllerCore: {
        claimCapability: (n: string, d: string, e: number, w: number, eff?: unknown) => { ok: boolean };
        resolveCapabilityUse: (n: string, s: string, r: string) => unknown;
      } }).controllerCore;

      const req = finalizeReq("op-swept");
      core.claimCapability("nonce-swept", "usedigest-swept", Date.now() + 600_000, Date.now() - 300_000,
        { kind: "WAL_FINALIZE", databaseId: "db1", generation: 1,
          operationId: "op-swept", requestDigest: req.requestDigest });
      instance.finalizeWalRecord(req);
      core.resolveCapabilityUse("nonce-swept", "AMBIGUOUS", JSON.stringify({ error: "lost" }));

      // nobody retries; the scheduled reducer converges it anyway
      await instance.alarm();
      const after = await instance.resolveAmbiguousUse("nonce-swept");
      expect(after).toMatchObject({ ok: true, disposition: "SETTLED", state: "RESOLVED_SUCCESS" });
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
      await provisionInstance(instance, "db1");
      instance.registerSession("db1", 1, "sess-1");
      instance.setBudgets("db1",
        { maxUnpublishedOutbox: 1000, maxPayloadLength: 100_000, maxTailRecords: 100_000 }, "sess-1");
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
      await provisionInstance(instance, "db1");
      instance.registerSession("db1", 1, "sess-1");
      instance.setBudgets("db1",
        { maxUnpublishedOutbox: 1000, maxPayloadLength: 100_000, maxTailRecords: 100_000 }, "sess-1");
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
