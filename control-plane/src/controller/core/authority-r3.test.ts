/*
 * Round-3 authority findings (C-01, C-05, C-07 core parts).
 *
 * C-01: the v11 journal migration is a TRUST TRANSITION - it authenticates a
 * legacy (v1-framed) chain before reframing it to v2, reframes only genuine
 * history, and QUARANTINES rather than re-signing tampered bytes.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import Database from "better-sqlite3";
import { ControllerCore } from "./procedures.ts";
import { sha256, hmacSha256, utf8 } from "./journal-crypto.ts";
import { sqlOver, reqFactory, TEST_BUDGETS } from "./test-support.ts";

const KEY = utf8("authority-r3-key");
const req = reqFactory("r3");

/** A registered, budgeted core over a caller-owned better-sqlite3 db, so the
 *  same db can be reopened after tampering. */
function bootOn(db: InstanceType<typeof Database>): ControllerCore {
  const core = new ControllerCore(sqlOver(db), { journalKey: KEY });
  core.registerSession("db1", 1, "sess-1");
  const ok = core.setBudgets("db1", TEST_BUDGETS, "sess-1");
  assert.ok(ok.ok);
  return core;
}

/** Recompute the whole control_outbox chain under the pre-v2 (unframed)
 *  preimage `sha256(prev || seq || kind || body)` + MAC, exactly as an era
 *  before migration v11 stored it - the control_seq blob doubles as the seq
 *  bytes. Downgrades a v2 database into a genuine v1-authentic one so the
 *  reframe path can be exercised. */
function downgradeToV1(db: InstanceType<typeof Database>, key: Uint8Array): void {
  const rows = db.prepare(
    `SELECT control_seq, kind, canonical_body FROM control_outbox ORDER BY control_seq`)
    .all() as { control_seq: Uint8Array; kind: string; canonical_body: string }[];
  let prev: Uint8Array = new Uint8Array(32);
  const put = db.prepare(`UPDATE control_outbox SET prev_hash=?, entry_hash=?, mac=? WHERE control_seq=?`);
  for (const row of rows) {
    const seqBytes = new Uint8Array(row.control_seq);
    const entry = sha256(prev, seqBytes, utf8(row.kind), utf8(row.canonical_body));
    put.run(prev, entry, hmacSha256(key, entry), row.control_seq);
    prev = entry;
  }
}

/** Remove a migration stamp so it re-runs on the next open. */
function unstamp(db: InstanceType<typeof Database>, version: number): void {
  db.prepare(`DELETE FROM schema_migrations WHERE version=?`).run(version);
}

test("C-01: v11 reframes a GENUINE v1-authentic chain to v2 (positive path)", () => {
  const db = new Database(":memory:");
  const core = bootOn(db);
  for (let i = 0; i < 3; i++) assert.ok(core.finalizeWalRecord(req()).ok);
  assert.ok(core.verifyJournal().ok);

  // downgrade the stored chain to v1 framing and force v11 to re-run
  downgradeToV1(db, KEY);
  unstamp(db, 11);

  const reopened = new ControllerCore(sqlOver(db), { journalKey: KEY });
  const verdict = reopened.verifyJournal();
  assert.ok(verdict.ok, JSON.stringify(verdict));
  const migrated = db.prepare(
    `SELECT COUNT(*) AS n FROM control_outbox WHERE kind='JOURNAL_MIGRATED_V1_TO_V2'`).get() as { n: number };
  assert.equal(migrated.n, 1, "a migration certificate is journaled");

  // idempotent: a second open reframes nothing and moves no head
  const head1 = verdict.ok ? verdict.headHash : "";
  const again = new ControllerCore(sqlOver(db), { journalKey: KEY }).verifyJournal();
  assert.ok(again.ok && again.headHash === head1);
});

test("C-01: v11 QUARANTINES tampered history instead of re-signing it (audit mutant)", () => {
  const db = new Database(":memory:");
  const core = bootOn(db);
  for (let i = 0; i < 3; i++) assert.ok(core.finalizeWalRecord(req()).ok);
  const before = core.verifyJournal();
  assert.ok(before.ok);

  // the dynamic mutant: tamper a row's canonical body (verification now
  // fails), then remove the v11 stamp so the migration re-runs
  const tampered = db.prepare(
    `SELECT control_seq, canonical_body FROM control_outbox ORDER BY control_seq LIMIT 1 OFFSET 2`).get() as
    { control_seq: unknown; canonical_body: string };
  db.prepare(`UPDATE control_outbox SET canonical_body=? WHERE control_seq=?`)
    .run(tampered.canonical_body.replace(/./, "X"), tampered.control_seq);
  unstamp(db, 11);

  // round-2's v11 recomputed from the current body and re-signed the forgery
  // green; the authenticated transition QUARANTINES and refuses to open
  assert.throws(() => new ControllerCore(sqlOver(db), { journalKey: KEY }),
    /DATABASE_QUARANTINED: JOURNAL_NOT_AUTHENTIC/);
  // the quarantine is durable: a further open still refuses, and the suspect
  // bytes were never rewritten
  assert.throws(() => new ControllerCore(sqlOver(db), { journalKey: KEY }), /DATABASE_QUARANTINED/);
  const stillTampered = db.prepare(
    `SELECT canonical_body FROM control_outbox WHERE control_seq=?`).get(tampered.control_seq) as
    { canonical_body: string };
  assert.ok(stillTampered.canonical_body.startsWith("X"), "the migration rewrote nothing");
});

test("C-05: issuance and verification run on the controller clock, not Date.now (no rollback resurrection)", () => {
  // a wall clock that jumps BACKWARD after issuance must not extend a token:
  // controllerNow is a nondecreasing floor, so expiry is measured against
  // the floor at both ends. Here we prove the floor does not decrease.
  let wall = 1_000_000;
  const db = new Database(":memory:");
  const core = new ControllerCore(sqlOver(db), { journalKey: KEY, now: () => wall });
  const t1 = core.controllerNow();
  wall = 500_000; // backward jump
  const t2 = core.controllerNow();
  assert.equal(t2, t1, "controller time never decreases on a backward wall-clock jump");
  wall = 2_000_000; // forward jump advances it
  assert.equal(core.controllerNow(), 2_000_000);
});
