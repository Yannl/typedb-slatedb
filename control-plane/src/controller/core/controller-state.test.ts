/*
 * F6r/F7r test battery: command ledger + CheckpointCut state machine +
 * anchored journal verification.
 *
 * - every authority mutation is a journaled command, exactly once
 *   (idempotent re-register journals nothing);
 * - cut lifecycle: open captures head + journal anchor in one transaction;
 *   activation requires restore evidence, supersedes the previous ACTIVE
 *   cut, and both transitions are journaled;
 * - the recorded anchor makes truncation AT OR BELOW the newest cut a
 *   typed detection (the F8 boundary test's staged answer, now real for
 *   the anchored prefix; adversarial rewrite of anchor+journal together
 *   still requires the immutable R2 publication - staged).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import Database from "better-sqlite3";
import { ControllerCore, u64Blob, type FinalizeRequest, type SyncSql } from "./procedures.ts";
import { utf8 } from "./journal-crypto.ts";

function makeSql(): { sql: SyncSql; db: InstanceType<typeof Database> } {
  const db = new Database(":memory:");
  const sql: SyncSql = {
    exec(query: string, ...params: unknown[]) {
      if (params.length === 0 && /;\s*\S/.test(query)) {
        db.exec(query);
        return [];
      }
      const stmt = db.prepare(query);
      if (stmt.reader) return stmt.all(...params) as Record<string, unknown>[];
      stmt.run(...params);
      return [];
    },
    transaction<T>(fn: () => T): T {
      return db.transaction(fn)();
    },
  };
  return { sql, db };
}

let opCounter = 0;
function req(overrides: Partial<FinalizeRequest> = {}): FinalizeRequest {
  opCounter += 1;
  const id = `sop-${opCounter}`;
  return {
    databaseId: "db1", generation: 1, startupSessionId: "sess-1",
    operationId: id, requestDigest: `digest-${id}`,
    sequencingKind: "SEQUENCED", recordType: 2, logicalKey: null,
    payloadKey: `payload/${id}`, payloadDigest: `pd-${id}`, payloadLength: 10,
    ...overrides,
  };
}

function boot(): { core: ControllerCore; db: InstanceType<typeof Database> } {
  const { sql, db } = makeSql();
  const core = new ControllerCore(sql, { journalKey: utf8("state-test-key") });
  core.registerSession("db1", 1, "sess-1");
  // Q-12: writes are denied without a validated budget row
  core.setBudgets("db1", { maxUnpublishedOutbox: 10_000, maxPayloadLength: 1_000_000, maxTailRecords: 1_000_000 }, "sess-1");
  return { core, db };
}

function kinds(db: InstanceType<typeof Database>): string[] {
  return (db.prepare(`SELECT kind FROM control_outbox ORDER BY control_seq`).all() as { kind: string }[])
    .map((r) => r.kind);
}

test("authority mutations are journaled commands, exactly once", () => {
  const { core, db } = boot();
  core.registerSession("db1", 1, "sess-1"); // idempotent: no new command
  assert.deepEqual(kinds(db), ["SESSION_REGISTERED", "BUDGETS_SET"]); // register + the fixture budget (Q-12)
  core.setBudgets("db1", { maxUnpublishedOutbox: 100, maxPayloadLength: 1000, maxTailRecords: 100 }, "sess-1");
  core.fenceSession("db1", "sess-1");
  core.fenceSession("db1", "sess-1"); // already fenced: no new command
  core.fenceSession("db1", "sess-ghost"); // unknown actor: no state change, no command
  core.registerSession("db1", 1, "sess-2"); // takeover: journaled
  assert.deepEqual(kinds(db),
    ["SESSION_REGISTERED", "BUDGETS_SET", "BUDGETS_SET", "SESSION_FENCED", "SESSION_REGISTERED"]);
  // and the ledger is an authenticated journal: every command verifies
  const verdict = core.verifyJournal();
  assert.ok(verdict.ok && verdict.length === 5, JSON.stringify(verdict));
});

test("cut lifecycle: open captures head + anchor; activation needs evidence and supersedes", () => {
  const { core } = boot();
  core.finalizeWalRecord(req());
  core.finalizeWalRecord(req());

  const opened = core.openCheckpointCut("db1", 1, "cut-1");
  assert.ok(opened.ok, String(opened.ok ? "" : (opened as { error: string }).error));
  assert.equal(opened.headLsn, 1n);
  // the anchor includes the cut event itself
  assert.equal(opened.journalLength, 5); // register + fixture budget + 2 finalisations + cut-opened

  assert.deepEqual(core.openCheckpointCut("db1", 1, "cut-1"), { ok: false, error: "CUT_EXISTS" });

  // activation without evidence fails closed (inv. 102)
  assert.deepEqual(
    core.activateCheckpointCut("db1", "cut-1", { materializations: [], logicalDigest: "" }),
    { ok: false, error: "CUT_EVIDENCE_MISSING" },
  );
  assert.deepEqual(core.activeCheckpointCut("db1", 1), { ok: false, error: "NOT_FOUND" });

  const activated = core.activateCheckpointCut("db1", "cut-1", {
    materializations: ["m-a", "m-b"], logicalDigest: "ld-1",
  });
  assert.ok(activated.ok && activated.superseded === null);
  const active = core.activeCheckpointCut("db1", 1);
  assert.ok(active.ok && active.cutId === "cut-1" && active.logicalDigest === "ld-1");

  // re-activation of a non-PENDING cut is refused
  assert.deepEqual(
    core.activateCheckpointCut("db1", "cut-1", { materializations: ["m-a"], logicalDigest: "x" }),
    { ok: false, error: "CUT_NOT_PENDING" },
  );

  // a newer cut supersedes on ITS activation, exactly one ACTIVE at a time
  core.finalizeWalRecord(req());
  const opened2 = core.openCheckpointCut("db1", 1, "cut-2");
  assert.ok(opened2.ok && opened2.headLsn === 2n);
  const activated2 = core.activateCheckpointCut("db1", "cut-2", {
    materializations: ["m-c"], logicalDigest: "ld-2",
  });
  assert.ok(activated2.ok && activated2.superseded === "cut-1");
  const nowActive = core.activeCheckpointCut("db1", 1);
  assert.ok(nowActive.ok && nowActive.cutId === "cut-2");
});

test("anchored verification: truncation at or below the newest cut is a typed detection", () => {
  const { core, db } = boot();
  core.finalizeWalRecord(req());
  core.finalizeWalRecord(req());
  const opened = core.openCheckpointCut("db1", 1, "cut-anchor");
  assert.ok(opened.ok);
  // un-anchored tail beyond the cut
  core.finalizeWalRecord(req());

  const clean = core.verifyJournalAnchored();
  assert.ok(clean.ok && clean.anchor !== null && opened.ok && clean.anchor.length === opened.journalLength,
    JSON.stringify(clean, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));

  // truncating the un-anchored tail: chain-consistent, still verifies
  // (the residual window every new cut shrinks; immutable publication is
  // the staged full answer)
  db.prepare(`DELETE FROM control_outbox WHERE control_seq = ?`).run(u64Blob(6n, "t"));
  const tailCut = core.verifyJournalAnchored();
  assert.ok(tailCut.ok, "truncation strictly above the anchor stays undetectable by design");

  // truncating INTO the anchored prefix: DETECTED
  db.prepare(`DELETE FROM control_outbox WHERE control_seq = ?`).run(u64Blob(5n, "t"));
  const belowAnchor = core.verifyJournalAnchored();
  assert.deepEqual(belowAnchor, { ok: false, error: "JOURNAL_TRUNCATED_BELOW_ANCHOR" });
});

test("anchored verification: a rewritten-then-rechained prefix mismatches the anchor", () => {
  const { core, db } = boot();
  core.finalizeWalRecord(req());
  const opened = core.openCheckpointCut("db1", 1, "cut-a");
  assert.ok(opened.ok);
  // adversary WITH the journal key rewrites the whole journal from scratch
  // (delete + re-append a different history of the same length): the chain
  // and MACs verify, but the running hash at the anchor position cannot
  // match the recorded anchor
  db.prepare(`DELETE FROM control_outbox`).run();
  core.finalizeWalRecord(req());
  core.finalizeWalRecord(req());
  core.finalizeWalRecord(req());
  core.finalizeWalRecord(req());
  const verdict = core.verifyJournalAnchored();
  assert.deepEqual(verdict, { ok: false, error: "JOURNAL_ANCHOR_MISMATCH" });
});

test("a cut over a tampered journal is refused", () => {
  const { core, db } = boot();
  core.finalizeWalRecord(req());
  db.prepare(`UPDATE control_outbox SET kind='FORGED' WHERE control_seq=?`).run(u64Blob(2n, "t"));
  assert.throws(() => core.openCheckpointCut("db1", 1, "cut-x"), /CHECKPOINT_CUT_REFUSED/);
});
