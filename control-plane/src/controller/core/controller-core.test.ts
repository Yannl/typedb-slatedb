/*
 * CT-P1/CT-P3/CT-P5 deterministic-lane test suite over a real SQLite
 * (better-sqlite3), mirroring the Rust remote-wal-spike's kill matrix at the
 * controller-procedure level. Negative controls are included as mutant
 * switches (CONTROLLER_MUTANT env) that MUST make named tests fail.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import Database from "better-sqlite3";
import { ControllerCore, type FinalizeRequest, type SyncSql } from "./procedures.ts";
import { replay, type WalRecordEvent } from "./reducer.ts";

const MUTANT = process.env.CONTROLLER_MUTANT ?? "";

function makeSql(): SyncSql {
  const db = new Database(":memory:");
  return {
    exec(sql: string, ...params: unknown[]) {
      if (params.length === 0 && /;\s*\S/.test(sql)) {
        db.exec(sql);
        return [];
      }
      const stmt = db.prepare(sql);
      if (stmt.reader) return stmt.all(...params) as Record<string, unknown>[];
      stmt.run(...params);
      return [];
    },
    transaction<T>(fn: () => T): T {
      return db.transaction(fn)();
    },
  };
}

let opCounter = 0;
function req(overrides: Partial<FinalizeRequest> = {}): FinalizeRequest {
  opCounter += 1;
  const id = `op-${opCounter}`;
  return {
    databaseId: "db1",
    generation: 3,
    startupSessionId: "sess-1",
    operationId: id,
    requestDigest: `digest-${id}`,
    sequencingKind: "SEQUENCED",
    recordType: 2, // CommitRecord's durability record type
    logicalKey: null,
    payloadKey: `payload/${id}`,
    payloadDigest: `pd-${id}`,
    payloadLength: 100,
    ...overrides,
  };
}

function boot(): ControllerCore {
  const core = new ControllerCore(makeSql());
  core.registerSession("db1", 3, "sess-1");
  return core;
}

test("contiguous LSN allocation, monotone type sequence", () => {
  const core = boot();
  const r1 = core.finalizeWalRecord(req({ sequencingKind: "SEQUENCED" }));
  const r2 = core.finalizeWalRecord(req({ sequencingKind: "UNSEQUENCED" }));
  const r3 = core.finalizeWalRecord(req({ sequencingKind: "SEQUENCED" }));
  assert.ok(r1.ok && r2.ok && r3.ok);
  assert.deepEqual([r1.appendLsn, r2.appendLsn, r3.appendLsn], [0, 1, 2]);
  assert.deepEqual([r1.typeSequence, r2.typeSequence, r3.typeSequence], [1, 1, 2]);
  assert.ok(core.auditContiguity("db1", 3).contiguous);
});

test("kill-point idempotency: same operation replayed at every point returns the original allocation", () => {
  const core = boot();
  const first = req();
  const r1 = core.finalizeWalRecord(first);
  assert.ok(r1.ok && !r1.replayed);
  // client crash after finalisation, retries with identical request
  const r2 = core.finalizeWalRecord(first);
  assert.ok(r2.ok && r2.replayed);
  assert.equal(r2.appendLsn, r1.appendLsn);
  assert.equal(r2.controlSeq, r1.controlSeq);
  // no double allocation
  assert.equal(core.auditContiguity("db1", 3).count, 1);
});

test("operation identity with a different digest is a typed conflict, never a second allocation", () => {
  const core = boot();
  const first = req();
  assert.ok(core.finalizeWalRecord(first).ok);
  const conflicting = { ...first, requestDigest: "digest-tampered" };
  const r = core.finalizeWalRecord(conflicting);
  assert.deepEqual(r, { ok: false, error: "OPERATION_DIGEST_CONFLICT" });
  assert.equal(core.auditContiguity("db1", 3).count, 1);
});

test("status singleton: identical duplicate is idempotent, conflicting duplicate is rejected", () => {
  const core = boot();
  const status = req({ sequencingKind: "UNSEQUENCED", logicalKey: "status:checkpoint", payloadDigest: "pd-s1" });
  const r1 = core.finalizeWalRecord(status);
  assert.ok(r1.ok);
  // duplicate with identical content, new operation id (lost response, new attempt)
  const dup = req({ sequencingKind: "UNSEQUENCED", logicalKey: "status:checkpoint", payloadDigest: "pd-s1" });
  const r2 = core.finalizeWalRecord(dup);
  assert.ok(r2.ok && r2.replayed && r2.appendLsn === r1.appendLsn);
  // conflicting content for the same singleton key
  const conflict = req({ sequencingKind: "UNSEQUENCED", logicalKey: "status:checkpoint", payloadDigest: "pd-DIFFERENT" });
  const r3 = core.finalizeWalRecord(conflict);
  assert.deepEqual(r3, { ok: false, error: "STATUS_CONFLICT" });
});

test("stale session fencing: fenced or unknown sessions cannot finalise", () => {
  const core = boot();
  core.fenceSession("db1", "sess-1");
  assert.deepEqual(core.finalizeWalRecord(req()), { ok: false, error: "SESSION_FENCED", fencedBy: null });
  assert.deepEqual(
    core.finalizeWalRecord(req({ startupSessionId: "sess-ghost" })),
    { ok: false, error: "SESSION_UNKNOWN" },
  );
  assert.equal(core.auditContiguity("db1", 3).count, 0);
});

test("fenced replay: a fenced session retrying a durable finalize gets SESSION_FENCED, not the receipt (inv. 38)", () => {
  // brief inv. 38: fencing cannot revoke the durable record, but it DOES
  // prevent the old holder from having it reported back. Both Rust reference
  // lanes (remote-wal-spike Controller::finalize, wal_model WalState::finalize)
  // fence before the replay lookup; the core must match that trace exactly.
  const core = boot();
  const first = req();
  const r1 = core.finalizeWalRecord(first);
  assert.ok(r1.ok && !r1.replayed);
  core.fenceSession("db1", "sess-1");
  // identical retry (lost-response recovery) after the fence
  assert.deepEqual(core.finalizeWalRecord(first), { ok: false, error: "SESSION_FENCED", fencedBy: null });
  // the record itself is untouched durable history (fencing revokes reporting,
  // never durability): still exactly one record, still contiguous
  const audit = core.auditContiguity("db1", 3);
  assert.equal(audit.count, 1);
  assert.ok(audit.contiguous);
});

test("bounded admission fail-closed: payload, outbox depth, tail budget", () => {
  const core = boot();
  core.setBudgets("db1", { maxUnpublishedOutbox: 2, maxPayloadLength: 1000, maxTailRecords: 5 });

  const tooBig = core.finalizeWalRecord(req({ payloadLength: 1001 }));
  assert.ok(!tooBig.ok && tooBig.error === "ADMISSION_REJECTED_PAYLOAD_LENGTH");

  assert.ok(core.finalizeWalRecord(req()).ok);
  assert.ok(core.finalizeWalRecord(req()).ok);
  const overDepth = core.finalizeWalRecord(req());
  assert.ok(!overDepth.ok && overDepth.error === "ADMISSION_REJECTED_OUTBOX_DEPTH");

  // draining the outbox restores admission (overload recovery)
  const published: number[] = [];
  core.drainOutbox((row) => published.push(row.controlSeq));
  assert.deepEqual(published, [1, 2]);
  assert.ok(core.finalizeWalRecord(req()).ok);

  // tail budget
  core.setBudgets("db1", { maxUnpublishedOutbox: 100, maxPayloadLength: 1000, maxTailRecords: 4 });
  assert.ok(core.finalizeWalRecord(req()).ok); // 4th record
  const overTail = core.finalizeWalRecord(req());
  assert.ok(!overTail.ok && overTail.error === "ADMISSION_REJECTED_TAIL_BUDGET");
});

test("outbox drain is exactly-once per control_seq across repeated alarms", () => {
  const core = boot();
  core.finalizeWalRecord(req());
  core.finalizeWalRecord(req());
  const seen: number[] = [];
  core.drainOutbox((r) => seen.push(r.controlSeq));
  core.drainOutbox((r) => seen.push(r.controlSeq)); // repeated alarm: nothing new
  core.finalizeWalRecord(req());
  core.drainOutbox((r) => seen.push(r.controlSeq));
  assert.deepEqual(seen, [1, 2, 3]);
});

test("batch candidate: all-or-nothing equivalence with per-record finalisation", () => {
  const perRecord = boot();
  const batched = boot();
  // build identical request triples for both cores (opCounter rewind gives
  // the second core the same operation ids)
  const savedCounter = opCounter;
  const triple1 = [req(), req({ sequencingKind: "UNSEQUENCED" }), req()];
  opCounter = savedCounter;
  const triple2 = [req(), req({ sequencingKind: "UNSEQUENCED" }), req()];

  for (const r of triple1) assert.ok(perRecord.finalizeWalRecord(r).ok);
  const batchResult = batched.finalizeBatch(triple2);
  assert.ok(Array.isArray(batchResult));
  assert.deepEqual(
    batchResult.map((r) => (r.ok ? [r.appendLsn, r.typeSequence] : r)),
    [[0, 1], [1, 1], [2, 2]],
  );
  assert.deepEqual(perRecord.auditContiguity("db1", 3), batched.auditContiguity("db1", 3));

  // failing member aborts the whole batch: nothing allocated
  const failing = boot();
  failing.setBudgets("db1", { maxUnpublishedOutbox: 100, maxPayloadLength: 10, maxTailRecords: 100 });
  const aborted = failing.finalizeBatch([req({ payloadLength: 5 }), req({ payloadLength: 50 })]);
  assert.ok(!Array.isArray(aborted) && aborted.error === "ADMISSION_REJECTED_PAYLOAD_LENGTH");
  assert.equal(failing.auditContiguity("db1", 3).count, 0);
});

test("exact lookup: missing rows are typed NOT_FOUND, never EOF", () => {
  const core = boot();
  core.finalizeWalRecord(req());
  const hit = core.exactLookup("db1", 3, 0);
  assert.ok(hit.ok);
  const miss = core.exactLookup("db1", 3, 1);
  assert.deepEqual(miss, { ok: false, error: "NOT_FOUND" });
  const wrongGen = core.exactLookup("db1", 4, 0);
  assert.deepEqual(wrongGen, { ok: false, error: "NOT_FOUND" });
});

test("fixed iterator head: records finalised after open stay invisible to the pinned head", () => {
  const core = boot();
  core.finalizeWalRecord(req());
  core.finalizeWalRecord(req());
  const iter = core.openIterator("db1", 3);
  assert.equal(iter.headLsn, 1);
  core.finalizeWalRecord(req());
  // the pinned head does not move; exact reads beyond it are the caller's
  // typed NOT_FOUND/visibility decision, never silent EOF-extension
  assert.equal(iter.headLsn, 1);
  assert.equal(core.openIterator("db1", 3).headLsn, 2);
});

test("SQL projection and pure reducer replay are trace-equivalent over a generated schedule", () => {
  const core = boot();
  core.registerSession("db1", 4, "sess-1");
  // deterministic pseudo-random schedule (seeded LCG; no Date/Math.random)
  let seed = 0x5eed;
  const rand = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  const events: WalRecordEvent[] = [];
  for (let i = 0; i < 200; i++) {
    const generation = rand() < 0.5 ? 3 : 4;
    const sequenced = rand() < 0.7;
    const status = !sequenced && rand() < 0.3;
    const r = core.finalizeWalRecord(
      req({
        generation,
        sequencingKind: sequenced ? "SEQUENCED" : "UNSEQUENCED",
        logicalKey: status ? `status:${Math.floor(rand() * 8)}` : null,
      }),
    );
    if (!r.ok) continue; // STATUS_CONFLICT / duplicates are legal schedule outcomes
  }
  // rebuild the event stream from the outbox (the canonical bus contents)
  core.drainOutbox((row) => events.push(JSON.parse(row.body) as WalRecordEvent));

  const reduced = replay(
    MUTANT === "drop-outbox-event" ? events.slice(0, -1) : events,
  );
  for (const generation of [3, 4]) {
    const audit = core.auditContiguity("db1", generation);
    const g = reduced.generations.get(`db1#${generation}`);
    assert.ok(g, `reducer missing generation ${generation}`);
    assert.equal(g.headLsn, audit.maxLsn, `generation ${generation} head`);
    assert.equal(g.records.size, audit.count, `generation ${generation} record count`);
    for (const [lsn, rec] of g.records) {
      const row = core.exactLookup("db1", generation, lsn);
      assert.ok(row.ok);
      assert.equal(rec.payloadDigest, row.payloadDigest);
      assert.equal(rec.typeSequence, row.typeSequence);
      assert.equal(rec.recordType, row.recordType);
    }
  }
});

test("status recovery is never blocked by budgets: duplicate status retry succeeds at full tail", () => {
  const core = boot();
  // write one status record, then fill the tail to its budget
  const status = req({ sequencingKind: "UNSEQUENCED", logicalKey: "status:cp", payloadDigest: "pd-s" });
  const original = core.finalizeWalRecord(status);
  assert.ok(original.ok);
  core.setBudgets("db1", { maxUnpublishedOutbox: 1000, maxPayloadLength: 1000, maxTailRecords: 3 });
  assert.ok(core.finalizeWalRecord(req()).ok);
  assert.ok(core.finalizeWalRecord(req()).ok); // tail now at 3 = budget
  // lost-response recovery: identical status content, fresh operation id -
  // must replay the original allocation despite the exhausted tail budget
  const retry = core.finalizeWalRecord(
    req({ sequencingKind: "UNSEQUENCED", logicalKey: "status:cp", payloadDigest: "pd-s" }),
  );
  assert.ok(retry.ok && retry.replayed, `expected replay, got ${JSON.stringify(retry)}`);
  assert.equal(retry.ok && retry.appendLsn, original.ok && original.appendLsn);
  // a genuinely NEW write is still rejected by the budget
  const fresh = core.finalizeWalRecord(req());
  assert.ok(!fresh.ok && fresh.error === "ADMISSION_REJECTED_TAIL_BUDGET");
  // and a CONFLICTING status is still a typed conflict, not an admission error
  const conflicting = core.finalizeWalRecord(
    req({ sequencingKind: "UNSEQUENCED", logicalKey: "status:cp", payloadDigest: "pd-DIFFERENT" }),
  );
  assert.deepEqual(conflicting, { ok: false, error: "STATUS_CONFLICT" });
});

test("register fences the predecessor: a new actor's register revokes the old actor's append authority (inv. 17, three-lane pin)", () => {
  // Both Rust reference lanes open sessions through a monotone counter that
  // implicitly fences every predecessor (remote-wal-spike open_session,
  // wal_model open_session + stale_session_is_fenced_without_allocation);
  // the SQL lane must produce the same trace: register(new) -> old is fenced.
  const core = boot();
  assert.ok(core.finalizeWalRecord(req()).ok);
  core.registerSession("db1", 3, "sess-2"); // restart: strictly newer actor
  assert.deepEqual(core.finalizeWalRecord(req()), { ok: false, error: "SESSION_FENCED", fencedBy: "sess-2" });
  assert.ok(core.finalizeWalRecord(req({ startupSessionId: "sess-2" })).ok);
  assert.equal(core.auditContiguity("db1", 3).count, 2);
});

test("a fenced actor cannot re-take authority by re-registering", () => {
  const core = boot();
  core.registerSession("db1", 3, "sess-2"); // fences sess-1
  core.registerSession("db1", 3, "sess-1"); // stale actor retries registration
  // sess-1 stays fenced; sess-2 keeps authority (and the attribution names it)
  assert.deepEqual(core.finalizeWalRecord(req()), { ok: false, error: "SESSION_FENCED", fencedBy: "sess-2" });
  assert.ok(core.finalizeWalRecord(req({ startupSessionId: "sess-2" })).ok);
});

test("fencing is actor-wide: revoking a rollover-spanning actor covers every generation it registered", () => {
  const core = boot();
  core.registerSession("db1", 4, "sess-1"); // same actor, next generation
  assert.ok(core.finalizeWalRecord(req()).ok);
  assert.ok(core.finalizeWalRecord(req({ generation: 4 })).ok);
  core.fenceSession("db1", "sess-1");
  // both generations are revoked — a per-generation fence would leave the
  // actor blocked from re-registering yet still able to append elsewhere
  assert.deepEqual(core.finalizeWalRecord(req()), { ok: false, error: "SESSION_FENCED", fencedBy: null });
  assert.deepEqual(core.finalizeWalRecord(req({ generation: 4 })), { ok: false, error: "SESSION_FENCED", fencedBy: null });
});

test("one actor spans a generation rollover without fencing itself", () => {
  const core = boot();
  assert.ok(core.finalizeWalRecord(req()).ok);
  core.registerSession("db1", 4, "sess-1"); // same actor, next generation
  assert.ok(core.finalizeWalRecord(req()).ok); // generation 3 still writable
  assert.ok(core.finalizeWalRecord(req({ generation: 4 })).ok);
});

test("head reports the TypeSequence, not the physical LSN", () => {
  const core = boot();
  assert.deepEqual(core.head("db1", 3), { headLsn: -1, headTypeSequence: 0 });
  core.finalizeWalRecord(req({ sequencingKind: "SEQUENCED" }));
  core.finalizeWalRecord(req({ sequencingKind: "UNSEQUENCED" }));
  core.finalizeWalRecord(req({ sequencingKind: "UNSEQUENCED" }));
  // 3 physical records, 1 sequenced: lsn head 2, sequence head 1 — the two
  // MUST diverge here or `current()`/`previous()` built on this endpoint
  // would corrupt recovery arithmetic
  assert.deepEqual(core.head("db1", 3), { headLsn: 2, headTypeSequence: 1 });
});

test("scan replays in physical order with type_sequence floor, type filter, pinned bound, and paging", () => {
  const core = boot();
  core.finalizeWalRecord(req({ sequencingKind: "SEQUENCED", recordType: 2 }));    // lsn 0, ts 1
  core.finalizeWalRecord(req({ sequencingKind: "UNSEQUENCED", recordType: 10 })); // lsn 1, ts 1
  core.finalizeWalRecord(req({ sequencingKind: "SEQUENCED", recordType: 2 }));    // lsn 2, ts 2
  core.finalizeWalRecord(req({ sequencingKind: "SEQUENCED", recordType: 2 }));    // lsn 3, ts 3
  const pinned = core.openIterator("db1", 3).headLsn;
  core.finalizeWalRecord(req({ sequencingKind: "SEQUENCED", recordType: 2 }));    // lsn 4 - after the pin

  // full replay from sequence 1 under the pinned bound: physical order,
  // unsequenced records interleaved, the post-pin append invisible
  const all = core.scan("db1", 3, { fromTypeSequence: 1, fromLsn: 0, throughLsn: pinned, recordType: null, limit: 100 });
  assert.deepEqual(all.records.map((r) => [r.appendLsn, r.typeSequence, r.recordType]),
    [[0, 1, 2], [1, 1, 10], [2, 2, 2], [3, 3, 2]]);
  assert.equal(all.nextFromLsn, null);

  // sequence floor: from ts 2 excludes the ts-1 records (both of them)
  const fromTs2 = core.scan("db1", 3, { fromTypeSequence: 2, fromLsn: 0, throughLsn: pinned, recordType: null, limit: 100 });
  assert.deepEqual(fromTs2.records.map((r) => r.appendLsn), [2, 3]);

  // type filter is a catalogue property, no payload fetch required
  const statsOnly = core.scan("db1", 3, { fromTypeSequence: 0, fromLsn: 0, throughLsn: pinned, recordType: 10, limit: 100 });
  assert.deepEqual(statsOnly.records.map((r) => r.appendLsn), [1]);

  // paging: limit 2 hands back a cursor that resumes exactly, no overlap
  const page1 = core.scan("db1", 3, { fromTypeSequence: 1, fromLsn: 0, throughLsn: pinned, recordType: null, limit: 2 });
  assert.deepEqual(page1.records.map((r) => r.appendLsn), [0, 1]);
  assert.equal(page1.nextFromLsn, 2);
  const page2 = core.scan("db1", 3, { fromTypeSequence: 1, fromLsn: page1.nextFromLsn!, throughLsn: pinned, recordType: null, limit: 2 });
  assert.deepEqual(page2.records.map((r) => r.appendLsn), [2, 3]);
  assert.equal(page2.nextFromLsn, null);
});

test("lastByType returns the physically last record of the type; absence is typed NOT_FOUND", () => {
  const core = boot();
  assert.deepEqual(core.lastByType("db1", 3, 10), { ok: false, error: "NOT_FOUND" });
  core.finalizeWalRecord(req({ sequencingKind: "UNSEQUENCED", recordType: 10 }));
  core.finalizeWalRecord(req({ sequencingKind: "SEQUENCED", recordType: 2 }));
  core.finalizeWalRecord(req({ sequencingKind: "UNSEQUENCED", recordType: 10 }));
  const last = core.lastByType("db1", 3, 10);
  assert.ok(last.ok);
  assert.equal(last.record.appendLsn, 2);
  assert.equal(last.record.recordType, 10);
});

test("negative control: reducer refuses LSN holes (mutant must fail equivalence)", () => {
  const events: WalRecordEvent[] = [
    { databaseId: "db1", generation: 1, appendLsn: 0, typeSequence: 1, sequencingKind: "SEQUENCED",
      recordType: 2, payloadKey: "k0", payloadDigest: "d0", logicalKey: null },
    { databaseId: "db1", generation: 1, appendLsn: 2, typeSequence: 2, sequencingKind: "SEQUENCED",
      recordType: 2, payloadKey: "k2", payloadDigest: "d2", logicalKey: null },
  ];
  assert.throws(() => replay(events), /contiguity violation/);
});
