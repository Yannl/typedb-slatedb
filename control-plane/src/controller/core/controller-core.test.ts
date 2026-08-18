/*
 * CT-P1/CT-P3/CT-P5 deterministic-lane test suite over a real SQLite
 * (better-sqlite3), mirroring the Rust remote-wal-spike's kill matrix at the
 * controller-procedure level. Negative controls are included as mutant
 * switches (CONTROLLER_MUTANT env) that MUST make named tests fail.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ControllerCore, MAX_BATCH_BYTES, MAX_BATCH_MEMBERS,
  MAX_OUTBOX_DEPTH_CEILING, MAX_PAYLOAD_LENGTH_CEILING, MAX_TAIL_RECORDS_CEILING,
  u64Blob, type SyncSql,
} from "./procedures.ts";
import { replay, type WalRecordEvent } from "./reducer.ts";
import { boot as bootFixture, makeSql as makeSqlFixture, reqFactory } from "./test-support.ts";

const MUTANT = process.env.CONTROLLER_MUTANT ?? "";

const req = reqFactory("op", { generation: 3, payloadLength: 100 });

function makeSql(): SyncSql {
  return makeSqlFixture().sql;
}

function boot(): ControllerCore {
  return bootFixture({ generation: 3 }).core;
}

test("contiguous LSN allocation, monotone type sequence", () => {
  const core = boot();
  const r1 = core.finalizeWalRecord(req({ sequencingKind: "SEQUENCED" }));
  const r2 = core.finalizeWalRecord(req({ sequencingKind: "UNSEQUENCED" }));
  const r3 = core.finalizeWalRecord(req({ sequencingKind: "SEQUENCED" }));
  assert.ok(r1.ok && r2.ok && r3.ok);
  assert.deepEqual([r1.appendLsn, r2.appendLsn, r3.appendLsn], [0n, 1n, 2n]);
  assert.deepEqual([r1.typeSequence, r2.typeSequence, r3.typeSequence], [1n, 1n, 2n]);
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
  assert.deepEqual(core.finalizeWalRecord(req()), { ok: false, error: "SESSION_FENCED" });
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
  assert.deepEqual(core.finalizeWalRecord(first), { ok: false, error: "SESSION_FENCED" });
  // the record itself is untouched durable history (fencing revokes reporting,
  // never durability): still exactly one record, still contiguous
  const audit = core.auditContiguity("db1", 3);
  assert.equal(audit.count, 1);
  assert.ok(audit.contiguous);
});

test("bounded admission fail-closed: payload, outbox depth, tail budget", () => {
  const core = boot();
  // boot() leaves 2 unpublished command rows (register + fixture budget);
  // this set adds a third, so a depth of 5 admits exactly two finalisations
  core.setBudgets("db1", { maxUnpublishedOutbox: 5, maxPayloadLength: 1000, maxTailRecords: 5 }, "sess-1");

  const tooBig = core.finalizeWalRecord(req({ payloadLength: 1001 }));
  assert.ok(!tooBig.ok && tooBig.error === "ADMISSION_REJECTED_PAYLOAD_LENGTH");

  assert.ok(core.finalizeWalRecord(req()).ok);
  assert.ok(core.finalizeWalRecord(req()).ok);
  const overDepth = core.finalizeWalRecord(req());
  assert.ok(!overDepth.ok && overDepth.error === "ADMISSION_REJECTED_OUTBOX_DEPTH");

  // draining the outbox restores admission (overload recovery)
  const published: bigint[] = [];
  core.drainOutbox((row) => published.push(row.controlSeq));
  // the bus carries the command ledger too: register(1), budgets-set(2),
  // then the two finalisations and the budgets-set of this test's setup
  assert.ok(published.length >= 4 && new Set(published).size === published.length,
    `bus drains every control event exactly once: ${published}`);
  assert.ok(core.finalizeWalRecord(req()).ok);

  // tail budget
  core.setBudgets("db1", { maxUnpublishedOutbox: 100, maxPayloadLength: 1000, maxTailRecords: 4 }, "sess-1");
  assert.ok(core.finalizeWalRecord(req()).ok); // 4th record
  const overTail = core.finalizeWalRecord(req());
  assert.ok(!overTail.ok && overTail.error === "ADMISSION_REJECTED_TAIL_BUDGET");
});

test("outbox drain is exactly-once per control_seq across repeated alarms", () => {
  const core = boot();
  core.finalizeWalRecord(req());
  core.finalizeWalRecord(req());
  const seen: bigint[] = [];
  core.drainOutbox((r) => seen.push(r.controlSeq));
  core.drainOutbox((r) => seen.push(r.controlSeq)); // repeated alarm: nothing new
  core.finalizeWalRecord(req());
  core.drainOutbox((r) => seen.push(r.controlSeq));
  // register command (1) + fixture budgets-set (2) + two finalisations,
  // then the third finalisation: exactly once each, in order, across
  // repeated drains
  assert.deepEqual(seen, [1n, 2n, 3n, 4n, 5n]);
});

test("batch candidate: all-or-nothing equivalence with per-record finalisation", () => {
  const perRecord = boot();
  const batched = boot();
  // identical request triples for both cores: same operation ids, same bytes
  const triple1 = [req(), req({ sequencingKind: "UNSEQUENCED" }), req()];
  const triple2 = triple1.map((r) => ({ ...r }));

  for (const r of triple1) assert.ok(perRecord.finalizeWalRecord(r).ok);
  const batchResult = batched.finalizeBatch(triple2, { batchOperationId: "batch-triple" });
  assert.ok(Array.isArray(batchResult));
  assert.deepEqual(
    batchResult.map((r) => (r.ok ? [r.appendLsn, r.typeSequence] : r)),
    [[0n, 1n], [1n, 1n], [2n, 2n]],
  );
  assert.deepEqual(perRecord.auditContiguity("db1", 3), batched.auditContiguity("db1", 3));

  // one batch, one authority scope: a member from another generation would
  // be recorded (and replayable) nowhere - typed refusal, nothing allocated
  const mixed = boot();
  const mixedResult = mixed.finalizeBatch(
    [req(), req({ generation: 4 })], { batchOperationId: "batch-mixed" });
  assert.ok(!Array.isArray(mixedResult) && mixedResult.error === "BATCH_MIXED_SCOPE");
  assert.equal(mixed.auditContiguity("db1", 3).count, 0);

  // failing member aborts the whole batch: nothing allocated
  const failing = boot();
  failing.setBudgets("db1", { maxUnpublishedOutbox: 100, maxPayloadLength: 10, maxTailRecords: 100 }, "sess-1");
  const aborted = failing.finalizeBatch([req({ payloadLength: 5 }), req({ payloadLength: 50 })], { batchOperationId: "batch-1" });
  assert.ok(!Array.isArray(aborted) && aborted.error === "ADMISSION_REJECTED_PAYLOAD_LENGTH");
  assert.equal(failing.auditContiguity("db1", 3).count, 0);
});

test("a finalized operation stays queryable by operation id after its session is fenced (V16 read surface)", () => {
  const core = boot();
  const first = req();
  const r1 = core.finalizeWalRecord(first);
  assert.ok(r1.ok);
  core.registerSession("db1", 3, "sess-2"); // takeover fences sess-1
  // the finalize-RETRY path stays fenced (inv. 38 - reporting is revoked)...
  assert.deepEqual(core.finalizeWalRecord(first), { ok: false, error: "SESSION_FENCED" });
  // ...but the immutable durable record is queryable by operation identity:
  // authority gates mutation, never hides finalized history
  const query = core.queryOperation("db1", 3, first.operationId, "sess-2");
  assert.ok(query.ok);
  assert.equal(query.record.appendLsn, r1.ok && r1.appendLsn);
  assert.equal(query.requestDigest, first.requestDigest);
  assert.equal(query.controlSeq, r1.ok && r1.controlSeq);
  // absence stays typed
  assert.deepEqual(core.queryOperation("db1", 3, "op-never", "sess-2"), { ok: false, error: "NOT_FOUND" });
  // ...and donor A4: the FENCED actor cannot read it, capability or not.
  // The capability layer above cannot close this window - a token minted
  // before the fence is still MAC-valid and unexpired afterwards - so the
  // refusal has to come from the authority state itself.
  assert.deepEqual(core.queryOperation("db1", 3, first.operationId, "sess-1"),
    { ok: false, error: "SESSION_FENCED" });
  assert.deepEqual(core.queryOperation("db1", 3, first.operationId, "sess-nobody"),
    { ok: false, error: "SESSION_UNKNOWN" });
});

test("exact lookup: missing rows are typed NOT_FOUND, never EOF", () => {
  const core = boot();
  core.finalizeWalRecord(req());
  const hit = core.exactLookup("db1", 3, 0n);
  assert.ok(hit.ok);
  const miss = core.exactLookup("db1", 3, 1n);
  assert.deepEqual(miss, { ok: false, error: "NOT_FOUND" });
  const wrongGen = core.exactLookup("db1", 4, 0n);
  assert.deepEqual(wrongGen, { ok: false, error: "NOT_FOUND" });
});

test("fixed iterator head: records finalised after open stay invisible to the pinned head", () => {
  const core = boot();
  core.finalizeWalRecord(req());
  core.finalizeWalRecord(req());
  const iter = core.openIterator("db1", 3);
  assert.equal(iter.headLsn, 1n);
  core.finalizeWalRecord(req());
  // the pinned head does not move; exact reads beyond it are the caller's
  // typed NOT_FOUND/visibility decision, never silent EOF-extension
  assert.equal(iter.headLsn, 1n);
  assert.equal(core.openIterator("db1", 3).headLsn, 2n);
});

test("SQL projection and pure reducer replay are trace-equivalent over a generated schedule", () => {
  const core = boot();
  // deterministic pseudo-random schedule (seeded LCG; no Date/Math.random).
  // Generations are SEQUENTIAL with a rollover mid-schedule: commit
  // authority is bound to the session's current generation (C-P0-04), so an
  // interleaved-generation schedule is unreachable by construction now.
  let seed = 0x5eed;
  const rand = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  const events: WalRecordEvent[] = [];
  for (let i = 0; i < 200; i++) {
    if (i === 100) core.registerSession("db1", 4, "sess-1"); // rollover
    const generation = i < 100 ? 3 : 4;
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
  core.drainOutbox((row) => {
    if (row.kind === "WAL_RECORD_FINALIZED") events.push(JSON.parse(row.body) as WalRecordEvent);
  });

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
  core.setBudgets("db1", { maxUnpublishedOutbox: 1000, maxPayloadLength: 1000, maxTailRecords: 3 }, "sess-1");
  assert.ok(core.finalizeWalRecord(req()).ok);
  assert.ok(core.finalizeWalRecord(req()).ok); // tail now at 3 = budget
  // lost-response recovery: identical status content, fresh operation id -
  // must replay the original allocation despite the exhausted tail budget
  const retry = core.finalizeWalRecord(
    req({ sequencingKind: "UNSEQUENCED", logicalKey: "status:cp", payloadDigest: "pd-s" }),
  );
  assert.ok(
    retry.ok && retry.replayed,
    `expected replay, got ${JSON.stringify(retry, (_k, v) => (typeof v === "bigint" ? v.toString() : v))}`,
  );
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
  assert.deepEqual(core.finalizeWalRecord(req()), { ok: false, error: "SESSION_FENCED" });
  assert.ok(core.finalizeWalRecord(req({ startupSessionId: "sess-2" })).ok);
  assert.equal(core.auditContiguity("db1", 3).count, 2);
});

test("a fenced actor cannot re-take authority by re-registering", () => {
  const core = boot();
  core.registerSession("db1", 3, "sess-2"); // fences sess-1
  core.registerSession("db1", 3, "sess-1"); // stale actor retries registration
  // sess-1 stays fenced; sess-2 keeps authority (and the attribution names it)
  assert.deepEqual(core.finalizeWalRecord(req()), { ok: false, error: "SESSION_FENCED" });
  assert.ok(core.finalizeWalRecord(req({ startupSessionId: "sess-2" })).ok);
});

test("fencing is actor-wide: revoking a rollover-spanning actor covers every generation it registered", () => {
  const core = boot();
  assert.ok(core.finalizeWalRecord(req()).ok);
  core.registerSession("db1", 4, "sess-1"); // same actor, next generation
  assert.ok(core.finalizeWalRecord(req({ generation: 4 })).ok);
  core.fenceSession("db1", "sess-1");
  // both generations are revoked — a per-generation fence would leave the
  // actor blocked from re-registering yet still able to append elsewhere
  assert.deepEqual(core.finalizeWalRecord(req()), { ok: false, error: "SESSION_FENCED" });
  assert.deepEqual(core.finalizeWalRecord(req({ generation: 4 })), { ok: false, error: "SESSION_FENCED" });
});

test("one actor spans a generation rollover; commit authority MOVES with it (audit C-P0-04)", () => {
  const core = boot();
  assert.ok(core.finalizeWalRecord(req()).ok);
  core.registerSession("db1", 4, "sess-1"); // same actor, next generation
  // the audit's executed violation was "registered in generations 1 and 2,
  // finalized in both": after rollover the session's lifecycle row binds
  // generation 4 and ONLY generation 4 accepts its commits
  const stale = core.finalizeWalRecord(req());
  assert.deepEqual(stale, { ok: false, error: "SESSION_GENERATION_MISMATCH", sessionGeneration: 4 });
  assert.ok(core.finalizeWalRecord(req({ generation: 4 })).ok);
  // the actor itself was never fenced by its own rollover
  assert.equal(core.auditContiguity("db1", 4).count, 1);
});

test("head reports the TypeSequence, not the physical LSN", () => {
  const core = boot();
  assert.deepEqual(core.head("db1", 3), { headLsn: -1n, headTypeSequence: 0n });
  core.finalizeWalRecord(req({ sequencingKind: "SEQUENCED" }));
  core.finalizeWalRecord(req({ sequencingKind: "UNSEQUENCED" }));
  core.finalizeWalRecord(req({ sequencingKind: "UNSEQUENCED" }));
  // 3 physical records, 1 sequenced: lsn head 2, sequence head 1 — the two
  // MUST diverge here or `current()`/`previous()` built on this endpoint
  // would corrupt recovery arithmetic
  assert.deepEqual(core.head("db1", 3), { headLsn: 2n, headTypeSequence: 1n });
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
  const all = core.scan("db1", 3, { fromTypeSequence: 1n, fromLsn: 0n, throughLsn: pinned, recordType: null, limit: 100 });
  assert.deepEqual(all.records.map((r) => [r.appendLsn, r.typeSequence, r.recordType]),
    [[0n, 1n, 2], [1n, 1n, 10], [2n, 2n, 2], [3n, 3n, 2]]);
  assert.equal(all.nextFromLsn, null);

  // sequence floor: from ts 2 excludes the ts-1 records (both of them)
  const fromTs2 = core.scan("db1", 3, { fromTypeSequence: 2n, fromLsn: 0n, throughLsn: pinned, recordType: null, limit: 100 });
  assert.deepEqual(fromTs2.records.map((r) => r.appendLsn), [2n, 3n]);

  // type filter is a catalogue property, no payload fetch required
  const statsOnly = core.scan("db1", 3, { fromTypeSequence: 0n, fromLsn: 0n, throughLsn: pinned, recordType: 10, limit: 100 });
  assert.deepEqual(statsOnly.records.map((r) => r.appendLsn), [1n]);

  // paging: limit 2 hands back a cursor that resumes exactly, no overlap
  const page1 = core.scan("db1", 3, { fromTypeSequence: 1n, fromLsn: 0n, throughLsn: pinned, recordType: null, limit: 2 });
  assert.deepEqual(page1.records.map((r) => r.appendLsn), [0n, 1n]);
  assert.equal(page1.nextFromLsn, 2n);
  const page2 = core.scan("db1", 3, { fromTypeSequence: 1n, fromLsn: page1.nextFromLsn!, throughLsn: pinned, recordType: null, limit: 2 });
  assert.deepEqual(page2.records.map((r) => r.appendLsn), [2n, 3n]);
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
  assert.equal(last.record.appendLsn, 2n);
  assert.equal(last.record.recordType, 10);
});

test("u64 exactness beyond 2^53: allocation, replay, scan and wire encoding stay exact (F7 blob representation)", () => {
  // Under the previous number-based representation every value here
  // collapses: 2^53 + 1 === 2^53 in JS doubles, so the allocator would
  // re-issue the same LSN and the exactness guard could only fail closed.
  // The BE-blob representation must be EXACT instead.
  const sql = makeSql();
  const core = new ControllerCore(sql);
  core.registerSession("db1", 3, "sess-1");
  core.setBudgets("db1", { maxUnpublishedOutbox: 10_000, maxPayloadLength: 1_000_000, maxTailRecords: 1_000_000 }, "sess-1");
  const beyond = 2n ** 53n; // 9007199254740992: the first non-exact double integer
  // seed a durable head directly at the boundary (the representation under
  // test is the storage contract, not the allocator's path to get there)
  sql.exec(
    `INSERT INTO wal_tail(database_id, generation, append_lsn, type_sequence, sequencing_kind,
       payload_key, payload_digest, payload_length, finalization_operation_id, request_digest,
       unsequenced_logical_key, startup_session_id, control_seq, record_type)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    "db1", 3, u64Blob(beyond, "seed_lsn"), u64Blob(beyond, "seed_ts"), "SEQUENCED",
    "payload/seed", "pd-seed", 1, "op-seed", "digest-seed", null, "sess-1",
    u64Blob(beyond, "seed_control"), 2,
  );
  // the global ControlSeq allocates from the OUTBOX head - seed it too
  const seedHash = new Uint8Array(32); // journal chain fields: NOT NULL placeholders (F8 chain not under test here)
  sql.exec(
    `INSERT INTO control_outbox(control_seq, database_id, kind, canonical_body, prev_hash, entry_hash, mac)
     VALUES (?,?,?,?,?,?,?)`,
    u64Blob(beyond, "seed_outbox"), "db1", "SEED", "{}", seedHash, seedHash, seedHash,
  );
  const r = core.finalizeWalRecord(req());
  assert.ok(r.ok);
  assert.equal(r.appendLsn, beyond + 1n, "allocation beyond 2^53 must be exact, not collapsed");
  assert.equal(r.typeSequence, beyond + 1n);
  assert.equal(r.controlSeq, beyond + 1n);
  // exact read-back through every read path
  const lookup = core.exactLookup("db1", 3, beyond + 1n);
  assert.ok(lookup.ok);
  assert.equal(lookup.typeSequence, beyond + 1n);
  assert.deepEqual(core.head("db1", 3), { headLsn: beyond + 1n, headTypeSequence: beyond + 1n });
  const audit = core.auditContiguity("db1", 3);
  assert.equal(audit.maxLsn, beyond + 1n);
  // the outbox wire body carries the DECIMAL STRING, exact by construction
  const bodies: string[] = [];
  core.drainOutbox((row) => bodies.push(row.body));
  const event = JSON.parse(bodies[bodies.length - 1]) as { appendLsn: string };
  assert.equal(event.appendLsn, (beyond + 1n).toString());
  // and the scan path pages exactly at the boundary
  const page = core.scan("db1", 3, {
    fromTypeSequence: 0n, fromLsn: beyond + 1n, throughLsn: beyond + 1n, recordType: null, limit: 10,
  });
  assert.deepEqual(page.records.map((rec) => rec.appendLsn), [beyond + 1n]);
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

test("donor A4: authority procedures revalidate the actor at the core, beneath the capability layer", () => {
  const core = boot();
  assert.ok(core.finalizeWalRecord(req()).ok);

  // baseline: the live actor may set budgets and ack the outbox
  assert.deepEqual(
    core.setBudgets("db1", { maxUnpublishedOutbox: 100, maxPayloadLength: 1000, maxTailRecords: 100 }, "sess-1"),
    { ok: true },
  );
  const acked = core.outboxAck("db1", 1n, "sess-1");
  assert.ok(acked.ok);

  // an actor that never registered is not an authority, however well
  // authenticated its token is
  assert.deepEqual(
    core.setBudgets("db1", { maxUnpublishedOutbox: 1, maxPayloadLength: 1, maxTailRecords: 1 }, "sess-ghost"),
    { ok: false, error: "SESSION_UNKNOWN" },
  );
  assert.deepEqual(core.outboxAck("db1", 99n, "sess-ghost"), { ok: false, error: "SESSION_UNKNOWN" });

  // takeover fences sess-1; its capability may still be minutes from expiry
  core.registerSession("db1", 3, "sess-2");
  assert.deepEqual(
    core.setBudgets("db1", { maxUnpublishedOutbox: 1, maxPayloadLength: 1, maxTailRecords: 1 }, "sess-1"),
    { ok: false, error: "SESSION_FENCED" },
  );
  assert.deepEqual(core.outboxAck("db1", 99n, "sess-1"), { ok: false, error: "SESSION_FENCED" });
  // the refusal carries no holder attribution (inv. 38 / ADR-0006): a fenced
  // actor learns that it is fenced, never who superseded it
  const refusal = core.setBudgets("db1", { maxUnpublishedOutbox: 1, maxPayloadLength: 1, maxTailRecords: 1 }, "sess-1");
  assert.equal(Object.keys(refusal).sort().join(","), "error,ok");

  // and the budgets a fenced actor tried to install were never written:
  // the refusal is before the transaction, not a rollback after it
  assert.ok(core.finalizeWalRecord(req({ startupSessionId: "sess-2", payloadLength: 500 })).ok);

  // the successor is a full authority
  assert.deepEqual(
    core.setBudgets("db1", { maxUnpublishedOutbox: 50, maxPayloadLength: 900, maxTailRecords: 50 }, "sess-2"),
    { ok: true },
  );
  assert.ok(core.outboxAck("db1", 2n, "sess-2").ok);
});

test("Q-09: a database created before record_type existed can still be opened and migrated", () => {
  // Reproduce the pre-migration shape exactly: wal_tail WITHOUT record_type,
  // and no schema_migrations table. This is the state that could not be
  // opened at all - the schema script created an index over a column the
  // table did not have, so construction threw before any migration ran.
  const sql = makeSql();
  sql.exec(`CREATE TABLE wal_tail(
    database_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    append_lsn BLOB NOT NULL,
    type_sequence BLOB NOT NULL,
    sequencing_kind TEXT NOT NULL CHECK(sequencing_kind IN ('SEQUENCED','UNSEQUENCED')),
    payload_key TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    payload_length INTEGER NOT NULL,
    finalization_operation_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    unsequenced_logical_key TEXT,
    startup_session_id TEXT NOT NULL,
    control_seq BLOB NOT NULL,
    PRIMARY KEY(database_id, generation, append_lsn),
    UNIQUE(database_id, generation, finalization_operation_id)
  )`);

  const core = new ControllerCore(sql);
  const columns = sql.exec(`PRAGMA table_info(wal_tail)`).map((r) => String(r.name));
  assert.ok(columns.includes("record_type"), `record_type was added: ${columns.join(",")}`);
  const indexes = sql.exec(`PRAGMA index_list(wal_tail)`).map((r) => String(r.name));
  assert.ok(indexes.includes("wal_type_scan"), `the dependent index exists: ${indexes.join(",")}`);

  // the migrated database is fully usable
  core.registerSession("db1", 3, "sess-1");
  core.setBudgets("db1", { maxUnpublishedOutbox: 100, maxPayloadLength: 1000, maxTailRecords: 100 }, "sess-1");
  assert.ok(core.finalizeWalRecord(req()).ok);

  // and re-opening is idempotent: the same versions are not re-applied
  const before = sql.exec(`SELECT version FROM schema_migrations ORDER BY version`).map((r) => Number(r.version));
  new ControllerCore(sql);
  const after = sql.exec(`SELECT version FROM schema_migrations ORDER BY version`).map((r) => Number(r.version));
  assert.deepEqual(after, before, "re-opening applies nothing twice");
  // versions are dense and ordered from 1: a gap means a step was skipped
  assert.deepEqual(before, before.map((_, i) => i + 1), `dense from 1: ${before}`);
  assert.ok(before.length >= 3, `every declared migration ran: ${before}`);
});

test("Q-11: a dedupe answer is durable under the operation id the client actually used", () => {
  const core = boot();
  const statusA = req({
    sequencingKind: "UNSEQUENCED", logicalKey: "status:cp", payloadDigest: "pd-status",
  });
  const original = core.finalizeWalRecord(statusA);
  assert.ok(original.ok);

  // lost response: the client retries the SAME content under a FRESH
  // operation id and is answered with the original record's receipt
  const statusB = req({
    sequencingKind: "UNSEQUENCED", logicalKey: "status:cp", payloadDigest: "pd-status",
  });
  const deduped = core.finalizeWalRecord(statusB);
  assert.ok(deduped.ok && deduped.replayed === true);
  assert.equal(deduped.ok && deduped.appendLsn, original.ok && original.appendLsn);

  // ...and the answer is now queryable under B's own id. Before the alias
  // this returned NOT_FOUND: the client held a receipt for an operation the
  // controller had no record of, so a SECOND lost response was unrecoverable.
  const byB = core.queryOperation("db1", 3, statusB.operationId, "sess-1");
  assert.ok(byB.ok, `operation ${statusB.operationId} resolves through its alias`);
  assert.equal(byB.record.appendLsn, original.ok && original.appendLsn);
  // the original id still resolves directly
  assert.ok(core.queryOperation("db1", 3, statusA.operationId, "sess-1").ok);

  // re-asking under B is stable
  const again = core.finalizeWalRecord(statusB);
  assert.ok(again.ok && again.replayed === true);

  // a DIFFERENT request under B's id is a typed conflict, never a re-point
  const impostor = { ...statusB, requestDigest: "digest-different" };
  assert.deepEqual(core.finalizeWalRecord(impostor), { ok: false, error: "OPERATION_DIGEST_CONFLICT" });
  assert.equal(core.queryOperation("db1", 3, statusB.operationId, "sess-1").ok
    && (core.queryOperation("db1", 3, statusB.operationId, "sess-1") as { record: { appendLsn: bigint } })
      .record.appendLsn, original.ok && original.appendLsn);

  // an id nobody ever used stays typed NOT_FOUND
  assert.deepEqual(core.queryOperation("db1", 3, "op-never-used", "sess-1"),
    { ok: false, error: "NOT_FOUND" });
});

test("Q-17: maintained usage counters agree with the history they replace, on every path", () => {
  // The counters exist so admission stops answering "how deep is the outbox?"
  // and "how long is the tail?" with a COUNT(*) over the whole table on every
  // finalisation. A maintained counter is only safe if EVERY path that moves
  // a row also moves it - the failure this checks for is silent drift, which
  // wedges admission at a depth that no longer exists.
  const sql = makeSql();
  const core = new ControllerCore(sql);
  core.registerSession("db1", 3, "sess-1");
  core.registerSession("db2", 1, "sess-b");
  core.setBudgets("db1", { maxUnpublishedOutbox: 10_000, maxPayloadLength: 1_000_000, maxTailRecords: 1_000_000 }, "sess-1");

  const counter = (db: string, generation: number, scope: string) => {
    const rows = sql.exec(
      `SELECT value FROM usage_counters WHERE database_id=? AND generation=? AND scope=?`,
      db, generation, scope);
    return rows.length ? Number(rows[0].value) : 0;
  };
  const truth = {
    tail: (db: string, generation: number) => Number(sql.exec(
      `SELECT COUNT(*) AS n FROM wal_tail WHERE database_id=? AND generation=?`, db, generation)[0].n),
    outbox: (db: string) => Number(sql.exec(
      `SELECT COUNT(*) AS n FROM control_outbox WHERE database_id=? AND published=0`, db)[0].n),
  };
  const agree = (where: string) => {
    for (const [db, gen] of [["db1", 3], ["db2", 1]] as [string, number][]) {
      assert.equal(counter(db, gen, "tail"), truth.tail(db, gen), `tail counter after ${where} (${db})`);
      assert.equal(counter(db, -1, "outbox_unpublished"), truth.outbox(db),
        `outbox counter after ${where} (${db})`);
    }
  };

  agree("registration");

  for (let i = 0; i < 5; i++) assert.ok(core.finalizeWalRecord(req()).ok);
  agree("finalisations");

  const batched = core.finalizeBatch([req(), req()], { batchOperationId: "batch-2" });
  assert.ok(Array.isArray(batched) && batched.length === 2);
  agree("a batch");

  // a REJECTED finalisation must move nothing
  core.setBudgets("db1", { maxUnpublishedOutbox: 100, maxPayloadLength: 10, maxTailRecords: 100 }, "sess-1");
  const rejected = core.finalizeWalRecord(req({ payloadLength: 1000 }));
  assert.ok(!rejected.ok);
  agree("a rejected finalisation");

  // partial ack, then a full drain
  const acked = core.outboxAck("db1", 3n, "sess-1");
  assert.ok(acked.ok);
  agree("a partial ack");
  core.drainOutbox(() => {});
  agree("a full drain");
  assert.equal(counter("db1", -1, "outbox_unpublished"), 0);

  // a re-ack of already-published rows must not drive the counter negative
  assert.ok(core.outboxAck("db1", 99n, "sess-1").ok);
  agree("a redundant ack");
  assert.ok(counter("db1", -1, "outbox_unpublished") >= 0);

  // and the second database's counters were never touched by the first's work
  assert.equal(counter("db2", 1, "tail"), 0);
});

test("Q-12: the iteration cut is server-owned - a snapshot id cannot be forged, widened or reused", () => {
  const core = boot();
  for (let i = 0; i < 3; i++) assert.ok(core.finalizeWalRecord(req()).ok);
  const opened = core.openIterator("db1", 3);
  assert.equal(opened.headLsn, 2n);
  assert.match(opened.snapshotId, /^2\.[0-9a-f]{64}$/);

  const resolved = core.resolveSnapshot("db1", 3, opened.snapshotId);
  assert.ok(resolved.ok && resolved.headLsn === 2n);

  // rewriting the head keeps the MAC but changes what it covers: refused.
  // Without this the caller holds the cut, and a widened cut observes
  // appends made after iteration started (inv. 41-42).
  const [, mac] = opened.snapshotId.split(".");
  assert.deepEqual(core.resolveSnapshot("db1", 3, `99.${mac}`),
    { ok: false, error: "INVALID_SNAPSHOT_ID" });
  assert.deepEqual(core.resolveSnapshot("db1", 3, `1.${mac}`),
    { ok: false, error: "INVALID_SNAPSHOT_ID" });

  // the binding covers database and generation, not just the number
  assert.deepEqual(core.resolveSnapshot("db1", 4, opened.snapshotId),
    { ok: false, error: "INVALID_SNAPSHOT_ID" });
  assert.deepEqual(core.resolveSnapshot("other-db", 3, opened.snapshotId),
    { ok: false, error: "INVALID_SNAPSHOT_ID" });

  // and malformed ids are typed, never a crash or a silent zero cut
  for (const bad of ["", ".", "2.", "2.zz", "abc.".padEnd(68, "0"), mac]) {
    assert.deepEqual(core.resolveSnapshot("db1", 3, bad),
      { ok: false, error: "INVALID_SNAPSHOT_ID" }, `malformed id ${JSON.stringify(bad)}`);
  }

  // a controller incarnation bump invalidates outstanding snapshots: a new
  // incarnation may have recovered to a different frontier, so a cut pinned
  // under the old one is not a cut this controller ever promised
  core.bumpIncarnation();
  assert.deepEqual(core.resolveSnapshot("db1", 3, opened.snapshotId),
    { ok: false, error: "INVALID_SNAPSHOT_ID" });
  const reopened = core.openIterator("db1", 3);
  assert.ok(core.resolveSnapshot("db1", 3, reopened.snapshotId).ok);
  assert.notEqual(reopened.snapshotId, opened.snapshotId);
});

test("12.6: a batch is one authority envelope with an identity, a digest and limits", () => {
  const core = boot();
  const members = [req(), req()];

  // an unnamed batch is refused: it cannot be replayed, conflicted or
  // audited, and one-record finalization always remains open
  assert.deepEqual(core.finalizeBatch(members), { ok: false, error: "BATCH_ENVELOPE_REQUIRED" });
  assert.deepEqual(core.finalizeBatch([], { batchOperationId: "b" }),
    { ok: false, error: "EMPTY_BATCH" });

  // K and byte ceilings, before any allocation
  const many = Array.from({ length: MAX_BATCH_MEMBERS + 1 }, () => req());
  const tooMany = core.finalizeBatch(many, { batchOperationId: "b-many" });
  assert.ok(!Array.isArray(tooMany) && tooMany.error === "BATCH_TOO_MANY_MEMBERS");
  const tooBig = core.finalizeBatch(
    [req({ payloadLength: MAX_BATCH_BYTES }), req({ payloadLength: 1 })],
    { batchOperationId: "b-big" });
  assert.ok(!Array.isArray(tooBig) && tooBig.error === "BATCH_TOO_MANY_BYTES");
  assert.equal(core.auditContiguity("db1", 3).count, 0, "a refused batch allocates nothing");

  // the digest is computed from the ordered members; a supplied one is only
  // ever CHECKED against it (Q-18's rule, applied to the envelope)
  const wrongDigest = core.finalizeBatch(members,
    { batchOperationId: "b-1", batchDigest: "f".repeat(64) });
  assert.ok(!Array.isArray(wrongDigest) && wrongDigest.error === "BATCH_DIGEST_MISMATCH");

  const ok = core.finalizeBatch(members, { batchOperationId: "b-1" });
  assert.ok(Array.isArray(ok) && ok.length === 2);

  // one batch id, one set of members, forever: the same id with DIFFERENT
  // members is a permanent conflict, not a second batch under a used name
  const different = core.finalizeBatch([req(), req()], { batchOperationId: "b-1" });
  assert.ok(!Array.isArray(different) && different.error === "BATCH_DIGEST_CONFLICT");

  // ...and the members that conflict allocated nothing
  assert.equal(core.auditContiguity("db1", 3).count, 2);

  // member ORDER is part of the identity
  const reversed = core.finalizeBatch([members[1], members[0]], { batchOperationId: "b-1" });
  assert.ok(!Array.isArray(reversed) && reversed.error === "BATCH_DIGEST_CONFLICT");
});

test("Q-12: a database with no validated budget row denies writes - missing budget is deny, never unlimited", () => {
  const core = new ControllerCore(makeSql());
  core.registerSession("db1", 3, "sess-1");
  // no setBudgets: the exact state a database nobody configured is in
  const denied = core.finalizeWalRecord(req());
  assert.deepEqual(denied, { ok: false, error: "ADMISSION_REJECTED_NO_BUDGET" });
  // nothing was allocated by the refusal
  assert.equal(core.auditContiguity("db1", 3).count, 0);

  // configuring a budget opens admission
  assert.ok(core.setBudgets("db1",
    { maxUnpublishedOutbox: 100, maxPayloadLength: 1000, maxTailRecords: 100 }, "sess-1").ok);
  const first = core.finalizeWalRecord(req());
  assert.ok(first.ok);

  // and a lost-response retry still replays WITHOUT a budget consult
  // blocking it: replay allocates nothing (the check sits after replay)
  const retryReq = req();
  assert.ok(core.finalizeWalRecord(retryReq).ok);
  const replay = core.finalizeWalRecord(retryReq);
  assert.ok(replay.ok && replay.replayed === true);
});

test("Q-10: budgets and payload lengths are exact at the boundary - floats, negatives and overflow refuse", () => {
  const core = boot();
  const okBudget = { maxUnpublishedOutbox: 10, maxPayloadLength: 1000, maxTailRecords: 10 };

  // each field individually: float, zero, negative, non-number, above ceiling
  for (const [field, bad] of [
    ["maxUnpublishedOutbox", 1.5], ["maxUnpublishedOutbox", 0], ["maxUnpublishedOutbox", -1],
    ["maxUnpublishedOutbox", MAX_OUTBOX_DEPTH_CEILING + 1],
    ["maxPayloadLength", Number.NaN], ["maxPayloadLength", MAX_PAYLOAD_LENGTH_CEILING + 1],
    ["maxPayloadLength", "1000"],
    ["maxTailRecords", 2 ** 53], ["maxTailRecords", MAX_TAIL_RECORDS_CEILING + 1],
  ] as [string, unknown][]) {
    const refused = core.setBudgets("db1", { ...okBudget, [field]: bad } as never, "sess-1");
    assert.deepEqual(refused, { ok: false, error: "INVALID_BUDGET", field }, `${field}=${String(bad)}`);
  }
  // a refused budget writes nothing: the previous (fixture) budget still admits
  assert.ok(core.finalizeWalRecord(req()).ok);

  // payloadLength on the finalize wire: exact or refused, never coerced
  for (const bad of [1.5, -1, Number.NaN, 2 ** 53, "10", null, undefined]) {
    const refused = core.finalizeWalRecord(req({ payloadLength: bad as never }));
    assert.ok(!refused.ok && refused.error === "INVALID_PAYLOAD_LENGTH", `payloadLength=${String(bad)}`);
  }
});
