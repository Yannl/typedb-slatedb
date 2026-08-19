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
import type Database from "better-sqlite3";
import { ControllerCore, u64Blob } from "./procedures.ts";
import { utf8 } from "./journal-crypto.ts";
import { boot as bootFixture, reqFactory } from "./test-support.ts";

const req = reqFactory("sop");

function boot(): { core: ControllerCore; db: InstanceType<typeof Database> } {
  return bootFixture({ journalKey: utf8("state-test-key") });
}

function kinds(db: InstanceType<typeof Database>): string[] {
  return (db.prepare(`SELECT kind FROM control_outbox ORDER BY control_seq`).all() as { kind: string }[])
    .map((r) => r.kind);
}

test("authority mutations are journaled commands, exactly once", () => {
  const { core, db } = boot();
  core.registerSession("db1", 1, "sess-1"); // idempotent: no new command
  // register now routes through the lifecycle: activation is the one
  // operation that fences, and SESSION_ACTIVATED is its honest name (Q-03)
  assert.deepEqual(kinds(db), ["SESSION_ACTIVATED", "BUDGETS_SET"]);
  core.setBudgets("db1", { maxUnpublishedOutbox: 100, maxPayloadLength: 1000, maxTailRecords: 100 }, "sess-1");
  core.fenceSession("db1", "sess-1");
  core.fenceSession("db1", "sess-1"); // already fenced: no new command
  core.fenceSession("db1", "sess-ghost"); // unknown actor: no state change, no command
  core.registerSession("db1", 1, "sess-2"); // takeover: journaled
  assert.deepEqual(kinds(db),
    ["SESSION_ACTIVATED", "BUDGETS_SET", "BUDGETS_SET", "SESSION_FENCED", "SESSION_ACTIVATED"]);
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

  // R4-SEC-06: activation takes a VERSIONED, materially checked manifest;
  // the legacy loose shape and every malformed/mismatched field are typed
  // refusals that leave no active cut behind.
  const HEX = "a".repeat(64);
  const manifest = (cutId: string, walHead: string | null, over: Record<string, unknown> = {}) => ({
    schema: "checkpoint-restore-evidence/v2",
    cutId,
    walHead,
    keyspaceRoots: [{ keyspace: "default", rootDigest: HEX }],
    logicalDigest: HEX,
    scratchRestore: { verifier: "test-scratch-restore", verifiedAtMs: 1 },
    materializations: ["m-a", "m-b"],
    ...over,
  });
  assert.deepEqual(
    core.activateCheckpointCut("db1", "cut-1", { materializations: [], logicalDigest: "" }),
    { ok: false, error: "CUT_EVIDENCE_INVALID", reason: "schema must be checkpoint-restore-evidence/v2" },
  );
  // wrong cut id inside the manifest
  assert.equal(
    (core.activateCheckpointCut("db1", "cut-1", manifest("cut-other", "1")) as { error: string }).error,
    "CUT_EVIDENCE_INVALID",
  );
  // wrong WAL head (the cut recorded head 1)
  assert.equal(
    (core.activateCheckpointCut("db1", "cut-1", manifest("cut-1", "999")) as { error: string }).error,
    "CUT_EVIDENCE_INVALID",
  );
  // malformed root digest
  assert.equal(
    (core.activateCheckpointCut("db1", "cut-1",
      manifest("cut-1", "1", { keyspaceRoots: [{ keyspace: "default", rootDigest: "nothex" }] })) as { error: string }).error,
    "CUT_EVIDENCE_INVALID",
  );
  assert.deepEqual(core.activeCheckpointCut("db1", 1), { ok: false, error: "NOT_FOUND" });

  const activated = core.activateCheckpointCut("db1", "cut-1", manifest("cut-1", "1"));
  assert.ok(activated.ok && activated.superseded === null,
    JSON.stringify(activated));
  const active = core.activeCheckpointCut("db1", 1);
  assert.ok(active.ok && active.cutId === "cut-1" && active.logicalDigest === HEX);

  // re-activation of a non-PENDING cut is refused
  assert.deepEqual(
    core.activateCheckpointCut("db1", "cut-1", manifest("cut-1", "1")),
    { ok: false, error: "CUT_NOT_PENDING" },
  );

  // a newer cut supersedes on ITS activation, exactly one ACTIVE at a time
  core.finalizeWalRecord(req());
  const opened2 = core.openCheckpointCut("db1", 1, "cut-2");
  assert.ok(opened2.ok && opened2.headLsn === 2n);
  const activated2 = core.activateCheckpointCut("db1", "cut-2",
    manifest("cut-2", "2", { materializations: ["m-c"] }));
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
