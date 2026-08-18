/*
 * Q-17 controls: hot-path SQL is index-backed, and append latency is bounded
 * by the REQUEST, not by history.
 *
 * Two layers, because EXPLAIN QUERY PLAN alone cannot see everything:
 *
 * 1. Plan assertions - every statement the hot paths actually execute is
 *    captured by a recording shim and EXPLAINed. A bare `SCAN table` is a
 *    missing index and fails the suite. This is the deterministic layer.
 *
 * 2. A latency-ratio control over a large synthetic fixture - because plan
 *    text LIES about aggregates: the old head lookup
 *    (`SELECT MAX(append_lsn), MAX(type_sequence) ... WHERE database_id=?
 *    AND generation=?`) printed the same SEARCH line as an O(1) seek while
 *    walking every row of the generation on every append (two aggregates
 *    over different columns defeat SQLite's min/max optimisation). Only the
 *    measured growth exposes it, so the mutant for this closure is "revert
 *    the head lookup to the double MAX" and the killer is the ratio test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type Database from "better-sqlite3";
import { ControllerCore, u64Blob } from "./procedures.ts";
import { boot as bootFixture, reqFactory, type TestDb } from "./test-support.ts";

interface Recorded {
  sql: string;
  params: unknown[];
}

const req = reqFactory("qp-op", { generation: 3, payloadLength: 100 });

/** Directly seed `n` finalized WAL rows (and the tail counter that admission
 *  reads) so history exists without paying n journal appends in test time. */
function seedHistory(db: InstanceType<typeof Database>, n: number): void {
  const insert = db.prepare(
    `INSERT INTO wal_tail(database_id, generation, append_lsn, type_sequence, sequencing_kind,
       payload_key, payload_digest, payload_length, finalization_operation_id, request_digest,
       unsequenced_logical_key, startup_session_id, control_seq, record_type)
     VALUES ('db1', 3, ?, ?, 'SEQUENCED', 'payload/seed', 'pd-seed', 100, ?, ?, NULL, 'sess-1', ?, 2)`,
  );
  db.transaction(() => {
    for (let i = 0; i < n; i += 1) {
      const lsn = u64Blob(BigInt(i), "seed_lsn");
      insert.run(lsn, u64Blob(BigInt(i + 1), "seed_ts"), `seed-${i}`, `seed-digest-${i}`, u64Blob(0n, "seed_cs"));
    }
    db.prepare(
      `INSERT OR REPLACE INTO usage_counters(database_id, generation, scope, value) VALUES ('db1', 3, 'tail', ?)`,
    ).run(n);
  })();
}

function bootCore(): { core: ControllerCore; db: TestDb; recorded: Recorded[]; recording: { on: boolean } } {
  const recorded: Recorded[] = [];
  const recording = { on: false };
  const { core, db } = bootFixture({
    generation: 3,
    budgets: { maxUnpublishedOutbox: 100_000, maxPayloadLength: 1_000_000, maxTailRecords: 10_000_000 },
    observe: (sql, params) => {
      if (recording.on && /^\s*(SELECT|UPDATE|DELETE)\b/i.test(sql)) recorded.push({ sql, params });
    },
  });
  return { core, db, recorded, recording };
}

/**
 * A plan row is acceptable when it is a SEARCH (index seek / range walk), or
 * one of two deliberately allowed SCAN shapes:
 *  - a walk of the partial `outbox_unpublished` index: its cardinality is the
 *    unpublished backlog, bounded by the outbox-depth budget, not by history;
 *  - an early-terminating `... LIMIT 1` walk down an index (the journal tail
 *    peek): one step, whatever the table size.
 * A bare `SCAN table` with no index, or an unbounded full-index scan, is a
 * missing index on the hot path and fails.
 */
function assertIndexBacked(db: InstanceType<typeof Database>, entry: Recorded): void {
  const plan = db.prepare(`EXPLAIN QUERY PLAN ${entry.sql}`).all(...entry.params) as { detail: string }[];
  for (const row of plan) {
    if (!/^SCAN\b/.test(row.detail)) continue;
    const usesIndex = /USING (COVERING )?INDEX/.test(row.detail);
    const unpublishedWalk = /INDEX outbox_unpublished/.test(row.detail);
    const singleRowPeek = /\bLIMIT 1\b/.test(entry.sql);
    assert.ok(
      usesIndex && (unpublishedWalk || singleRowPeek),
      `hot-path statement is not index-backed:\n  plan: ${row.detail}\n  sql: ${entry.sql.replace(/\s+/g, " ").trim()}`,
    );
  }
}

test("every statement the hot paths execute is index-backed (EXPLAIN QUERY PLAN)", () => {
  const { core, db, recorded, recording } = bootCore();
  recording.on = true;

  // the write path: sequenced, unsequenced-with-key, replayed, batched
  const r1 = core.finalizeWalRecord(req());
  assert.ok(r1.ok);
  const statusReq = req({ sequencingKind: "UNSEQUENCED", logicalKey: "status" });
  assert.ok(core.finalizeWalRecord(statusReq).ok);
  const replay = core.finalizeWalRecord(statusReq);
  assert.ok(replay.ok && replay.replayed);
  const batch = core.finalizeBatch([req(), req()], { batchOperationId: "qp-batch-1" });
  assert.ok(Array.isArray(batch) && batch.every((r) => r.ok));

  // the read path: exact, head, pinned scan (typed + untyped), operation, type
  assert.ok(core.exactLookup("db1", 3, 0n).ok);
  const head = core.head("db1", 3);
  assert.ok(head.headLsn >= 0n);
  const iter = core.openIterator("db1", 3);
  core.scan("db1", 3, { fromTypeSequence: 0n, fromLsn: 0n, throughLsn: iter.headLsn, recordType: null, limit: 10 });
  core.scan("db1", 3, { fromTypeSequence: 0n, fromLsn: 0n, throughLsn: iter.headLsn, recordType: 2, limit: 10 });
  assert.ok(core.queryOperation("db1", 3, r1.ok ? "qp-op-1" : "", "sess-1").ok);
  assert.ok(core.lastByType("db1", 3, 2).ok);

  // the consumer path and the authority path
  core.outboxPeek(10);
  const acked = core.outboxAck("db1", 1n, "sess-1");
  assert.ok(acked.ok);
  assert.ok(core.burnCapabilityNonce("qp-nonce-1", Date.now() + 60_000, Date.now()));

  recording.on = false;
  // the recorder must actually be wired through the paths above
  assert.ok(recorded.length >= 15, `only ${recorded.length} statements captured`);
  for (const entry of recorded) assertIndexBacked(db, entry);
});

test("append latency is ~constant in history (large synthetic fixture)", () => {
  // Plans cannot prove this one (see the header): measure it. The mutant -
  // head lookup reverted to MAX(append_lsn), MAX(type_sequence) - walks all
  // seeded rows on every append and blows the ratio far past the bound.
  const APPENDS = 300;
  const WARMUP = 30;
  const timePerAppend = (historyRows: number): number => {
    const { core, db, recording } = bootCore();
    void recording;
    seedHistory(db, historyRows);
    for (let i = 0; i < WARMUP; i += 1) assert.ok(core.finalizeWalRecord(req()).ok);
    const started = process.hrtime.bigint();
    for (let i = 0; i < APPENDS; i += 1) assert.ok(core.finalizeWalRecord(req()).ok);
    return Number(process.hrtime.bigint() - started) / APPENDS;
  };

  const shallow = timePerAppend(1_000);
  const deep = timePerAppend(500_000);
  const ratio = deep / shallow;
  // O(1) sits near 1x with scheduler noise; the O(history) mutant lands
  // >50x at this fixture size. 8x is the generous CI-safe boundary.
  assert.ok(
    ratio < 8,
    `append latency grew with history: ${Math.round(shallow)}ns/append at 1k rows, ` +
      `${Math.round(deep)}ns/append at 500k rows (${ratio.toFixed(1)}x)`,
  );
});
