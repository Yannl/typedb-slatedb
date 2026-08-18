/*
 * Audit C-P0-06: historical-schema migration against a BYTE-EXACT era-A
 * fixture.
 *
 * ERA_A_SCHEMA below is the verbatim SCHEMA constant from commit 732ffb5
 * (the first released controller shape): INTEGER sequence columns and a
 * hash-less control_outbox, no schema_migrations, no controller_meta. The
 * previous migration test constructed a mostly-current database and
 * therefore missed the real path - the audit's executed reproduction was
 * "migrations recorded 1..8, old control_outbox shape remained, first
 * registration: no such column: entry_hash".
 *
 * Covered here: shape repair (INTEGER -> u64 blob, hash chain computed),
 * lossless conversion at and beyond 2^53, legacy-session quarantine
 * (C-P0-05), idempotent re-open, crash-after-every-statement convergence,
 * and unknown-future-schema refusal.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import Database from "better-sqlite3";
import { ControllerCore, u64FromWire } from "./procedures.ts";
import { utf8 } from "./journal-crypto.ts";
import { sqlOver, TEST_BUDGETS } from "./test-support.ts";

const KEY = utf8("migration-fixture-key");

/** Verbatim from commit 732ffb5 (era A). Do not modernize. */
const ERA_A_SCHEMA = `
  CREATE TABLE IF NOT EXISTS wal_tail(
    database_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    append_lsn INTEGER NOT NULL,
    type_sequence INTEGER NOT NULL,
    sequencing_kind TEXT NOT NULL CHECK(sequencing_kind IN ('SEQUENCED','UNSEQUENCED')),
    payload_key TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    payload_length INTEGER NOT NULL,
    finalization_operation_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    unsequenced_logical_key TEXT,
    startup_session_id TEXT NOT NULL,
    control_seq INTEGER NOT NULL,
    PRIMARY KEY(database_id, generation, append_lsn),
    UNIQUE(database_id, generation, finalization_operation_id)
  );
  CREATE UNIQUE INDEX IF NOT EXISTS wal_status_singleton
    ON wal_tail(database_id, generation, unsequenced_logical_key)
    WHERE unsequenced_logical_key IS NOT NULL;
  CREATE TABLE IF NOT EXISTS control_outbox(
    control_seq INTEGER PRIMARY KEY,
    database_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    canonical_body TEXT NOT NULL,
    published INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS budgets(
    database_id TEXT PRIMARY KEY,
    max_unpublished_outbox INTEGER NOT NULL,
    max_payload_length INTEGER NOT NULL,
    max_tail_records INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions(
    database_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    startup_session_id TEXT NOT NULL,
    fenced INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(database_id, generation, startup_session_id)
  );
`;

/** 2^53 + 1: not representable as a JS number; the conversion must not
 *  round it. 2^62 + 3 exercises the high half of the i64 range. */
const BEYOND_DOUBLE = 9007199254740993n;
const HIGH_I64 = (1n << 62n) + 3n;

/** A populated era-A database: one live legacy session, one fenced one,
 *  three catalogued records (one a status singleton, one carrying
 *  beyond-2^53 sequence values), two published-flag-mixed outbox rows. */
function eraAFixture(): InstanceType<typeof Database> {
  const db = new Database(":memory:");
  db.exec(ERA_A_SCHEMA);
  const wal = db.prepare(
    `INSERT INTO wal_tail(database_id, generation, append_lsn, type_sequence, sequencing_kind,
       payload_key, payload_digest, payload_length, finalization_operation_id, request_digest,
       unsequenced_logical_key, startup_session_id, control_seq)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  wal.run("dbA", 1, 0, 1, "SEQUENCED", "p/dbA/pd-1", "pd-1", 10, "op-1", "digest-op-1", null, "legacy-sess", 1);
  wal.run("dbA", 1, 1, 1, "UNSEQUENCED", "p/dbA/pd-2", "pd-2", 12, "op-2", "digest-op-2", "status:cp", "legacy-sess", 2);
  wal.run("dbA", 1, 2, BEYOND_DOUBLE, "SEQUENCED", "p/dbA/pd-3", "pd-3", 14, "op-3", "digest-op-3", null, "legacy-sess", HIGH_I64);
  const outbox = db.prepare(
    `INSERT INTO control_outbox(control_seq, database_id, kind, canonical_body, published) VALUES (?,?,?,?,?)`);
  outbox.run(1, "dbA", "SESSION_REGISTERED", '{"databaseId":"dbA","generation":1,"startupSessionId":"legacy-sess"}', 1);
  outbox.run(2, "dbA", "WAL_RECORD_FINALIZED", '{"appendLsn":"0","databaseId":"dbA","generation":1}', 0);
  const sessions = db.prepare(
    `INSERT INTO sessions(database_id, generation, startup_session_id, fenced) VALUES (?,?,?,?)`);
  sessions.run("dbA", 1, "legacy-sess", 0);
  sessions.run("dbA", 1, "old-sess", 1);
  db.prepare(`INSERT INTO budgets VALUES ('dbA', 100, 1000, 1000)`).run();
  return db;
}

function migrationVersions(db: InstanceType<typeof Database>): number[] {
  return (db.prepare(`SELECT version FROM schema_migrations ORDER BY version`).all() as { version: number }[])
    .map((r) => r.version);
}

test("era-A fixture migrates to the current shape with an authenticated journal", () => {
  const db = eraAFixture();
  const core = new ControllerCore(sqlOver(db), { journalKey: KEY });

  // migrations are dense from 1 and include the repair steps
  const versions = migrationVersions(db);
  assert.deepEqual(versions, versions.map((_, i) => i + 1));
  assert.ok(versions.length >= 12, `v9-v12 applied: ${versions}`);

  // the rebuilt outbox verifies as a v2-framed chain, quarantine included
  const verdict = core.verifyJournal();
  assert.ok(verdict.ok, JSON.stringify(verdict));
  const kinds = db.prepare(`SELECT kind, COUNT(*) AS n FROM control_outbox GROUP BY kind`).all() as
    { kind: string; n: number }[];
  const quarantined = kinds.find((k) => k.kind === "SESSION_QUARANTINED_BY_MIGRATION");
  assert.equal(quarantined?.n, 2, "both historical sessions quarantined, journaled");

  // exact value preservation across the INTEGER -> blob rebuild
  assert.deepEqual(core.head("dbA", 1), { headLsn: 2n, headTypeSequence: BEYOND_DOUBLE });
  const record = core.exactLookup("dbA", 1, 2n);
  assert.ok(record.ok && record.typeSequence === BEYOND_DOUBLE);
  const audit = core.auditContiguity("dbA", 1);
  assert.ok(audit.contiguous && audit.count === 3);

  // C-P0-05: NO grandfathering. The live historical session is terminal
  // EXPIRED (bounded refusal), the fenced one stays fenced, a ghost id is
  // unknown - none of them can finalize.
  const finalize = (session: string) => core.finalizeWalRecord({
    databaseId: "dbA", generation: 1, startupSessionId: session, operationId: `new-${session}`,
    requestDigest: `d-${session}`, sequencingKind: "SEQUENCED", recordType: 2,
    logicalKey: null, payloadKey: "p/dbA/pd-x", payloadDigest: "pd-x", payloadLength: 1,
  });
  assert.deepEqual(finalize("legacy-sess"), { ok: false, error: "SESSION_NOT_ACTIVE", state: "EXPIRED" });
  assert.deepEqual(finalize("old-sess"), { ok: false, error: "SESSION_FENCED" });
  assert.deepEqual(finalize("ghost-sess"), { ok: false, error: "SESSION_UNKNOWN" });

  // serving readiness: a NEW actor establishes through the lifecycle and works
  core.registerSession("dbA", 2, "new-sess");
  const fresh = core.finalizeWalRecord({
    databaseId: "dbA", generation: 2, startupSessionId: "new-sess", operationId: "op-new",
    requestDigest: "d-new", sequencingKind: "SEQUENCED", recordType: 2,
    logicalKey: null, payloadKey: "p/dbA/pd-new", payloadDigest: "pd-new", payloadLength: 1,
  });
  assert.ok(fresh.ok, JSON.stringify(fresh, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));

  // idempotence: re-opening applies nothing twice and moves no hashes
  const headBefore = verdict.ok ? verdict.headHash : "";
  const reopened = new ControllerCore(sqlOver(db), { journalKey: KEY });
  const verdict2 = reopened.verifyJournal();
  assert.ok(verdict2.ok);
  assert.deepEqual(migrationVersions(db), versions);
  const quarantineCount = db.prepare(
    `SELECT COUNT(*) AS n FROM control_outbox WHERE kind='SESSION_QUARANTINED_BY_MIGRATION'`).get() as { n: number };
  assert.equal(quarantineCount.n, 2, "re-open quarantines nobody twice");
  // the fresh finalize moved the head after the first verify; the re-open
  // itself must not move it further
  assert.notEqual(verdict2.headHash, headBefore);
  const verdict3 = new ControllerCore(sqlOver(db), { journalKey: KEY }).verifyJournal();
  assert.ok(verdict3.ok && verdict3.headHash === verdict2.headHash);
});

test("crash after every migration statement converges on restart (C-P0-06 crash matrix)", () => {
  // reference terminal state from an uninterrupted migration
  const referenceDb = eraAFixture();
  new ControllerCore(sqlOver(referenceDb), { journalKey: KEY });
  const reference = {
    versions: migrationVersions(referenceDb),
    outbox: referenceDb.prepare(
      `SELECT kind, canonical_body FROM control_outbox ORDER BY control_seq`).all(),
    wal: referenceDb.prepare(
      `SELECT database_id, generation, hex(append_lsn) AS lsn FROM wal_tail ORDER BY database_id, generation, append_lsn`).all(),
  };

  let crashPoint = 1;
  for (;;) {
    const db = eraAFixture();
    let statements = 0;
    let crashed = false;
    const bomb = crashPoint;
    try {
      new ControllerCore(sqlOver(db, () => {
        statements += 1;
        if (statements === bomb) throw new Error(`injected crash at statement ${bomb}`);
      }), { journalKey: KEY });
    } catch (error) {
      crashed = true;
      assert.match(String(error), /injected crash/, `only the injected fault may abort: ${error}`);
    }
    // restart with no fault: must converge to exactly the reference state
    const recovered = new ControllerCore(sqlOver(db), { journalKey: KEY });
    assert.deepEqual(migrationVersions(db), reference.versions, `crash point ${bomb}: versions`);
    assert.ok(recovered.verifyJournal().ok, `crash point ${bomb}: journal verifies`);
    assert.deepEqual(
      db.prepare(`SELECT kind, canonical_body FROM control_outbox ORDER BY control_seq`).all(),
      reference.outbox, `crash point ${bomb}: outbox content`);
    assert.deepEqual(
      db.prepare(`SELECT database_id, generation, hex(append_lsn) AS lsn FROM wal_tail ORDER BY database_id, generation, append_lsn`).all(),
      reference.wal, `crash point ${bomb}: wal content`);
    if (!crashed) break; // the fault point lies beyond the whole migration: matrix complete
    crashPoint += 1;
    assert.ok(crashPoint < 10_000, "runaway crash matrix");
  }
  assert.ok(crashPoint > 10, `the matrix actually exercised the migration (${crashPoint} points)`);
});

test("a database stamped by a FUTURE schema refuses to open (C-P0-06)", () => {
  const db = eraAFixture();
  new ControllerCore(sqlOver(db), { journalKey: KEY });
  db.prepare(`INSERT INTO schema_migrations(version, applied_at_ms) VALUES (999, 0)`).run();
  assert.throws(() => new ControllerCore(sqlOver(db), { journalKey: KEY }), /SCHEMA_FROM_THE_FUTURE/);
});

test("u64FromWire accepts exactly one decimal encoding per value (C-P1-02)", () => {
  assert.equal(u64FromWire("0", "t"), 0n);
  assert.equal(u64FromWire("9007199254740993", "t"), BEYOND_DOUBLE);
  assert.equal(u64FromWire("18446744073709551615", "t"), (1n << 64n) - 1n);
  for (const alias of ["00", "01", "007", "+1", " 1", "1 ", "0x10", "1e3", "-0", ""]) {
    assert.throws(() => u64FromWire(alias, "t"), /INTEGER_RANGE_VIOLATION/, `alias ${JSON.stringify(alias)}`);
  }
  assert.throws(() => u64FromWire("18446744073709551616", "t"), /INTEGER_RANGE_VIOLATION/, "u64 max + 1");
});

test("incarnation bump terminalizes every live session and fences every actor (C-P0-04)", () => {
  const db = new Database(":memory:");
  const core = new ControllerCore(sqlOver(db), { journalKey: KEY });
  core.registerSession("db1", 1, "sess-1");
  const budgeted = core.setBudgets("db1", TEST_BUDGETS, "sess-1");
  assert.ok(budgeted.ok);
  const next = core.bumpIncarnation();
  assert.equal(next, 2);
  // the pre-bump actor cannot finalize under the new incarnation
  const stale = core.finalizeWalRecord({
    databaseId: "db1", generation: 1, startupSessionId: "sess-1", operationId: "op-stale",
    requestDigest: "d-stale", sequencingKind: "SEQUENCED", recordType: 2,
    logicalKey: null, payloadKey: "p/db1/pd", payloadDigest: "pd", payloadLength: 1,
  });
  assert.deepEqual(stale, { ok: false, error: "SESSION_FENCED" });
  // the bump command records the sweep it performed
  const bumped = db.prepare(
    `SELECT canonical_body FROM control_outbox WHERE kind='CONTROLLER_INCARNATION_BUMPED'`).get() as
    { canonical_body: string };
  const body = JSON.parse(bumped.canonical_body) as { revokedSessions: number; fencedActors: number };
  assert.equal(body.revokedSessions, 1);
  assert.equal(body.fencedActors, 1);
  // a session id that never went through the lifecycle refuses UNMIGRATED
  // even where the sessions row was forged in directly (C-P0-05 fail-closed)
  db.prepare(`INSERT INTO sessions(database_id, generation, startup_session_id, fenced) VALUES ('db1',1,'forged',0)`).run();
  const forged = core.finalizeWalRecord({
    databaseId: "db1", generation: 1, startupSessionId: "forged", operationId: "op-forged",
    requestDigest: "d-forged", sequencingKind: "SEQUENCED", recordType: 2,
    logicalKey: null, payloadKey: "p/db1/pd", payloadDigest: "pd", payloadLength: 1,
  });
  assert.deepEqual(forged, { ok: false, error: "SESSION_UNMIGRATED" });
});

test("capability use is an idempotent outcome machine, not a bare burn (C-P0-08)", () => {
  const db = new Database(":memory:");
  const core = new ControllerCore(sqlOver(db), { journalKey: KEY });
  const now = 1_000;
  const expires = 10_000;
  // first presentation admits and records IN_FLIGHT (non-terminal)
  const first = core.claimCapability("nonce-1", "use-digest-A", expires, now);
  assert.deepEqual(first, { ok: true, fresh: true, state: "IN_FLIGHT", terminal: false, response: null });
  // identical retry admits with the recorded state - a lost response is
  // recoverable because the authorized procedures are idempotent
  const retry = core.claimCapability("nonce-1", "use-digest-A", expires, now + 1);
  assert.deepEqual(retry, { ok: true, fresh: false, state: "IN_FLIGHT", terminal: false, response: null });
  // a DIFFERENT request under the used token is a replay refusal
  const stolen = core.claimCapability("nonce-1", "use-digest-B", expires, now + 2);
  assert.deepEqual(stolen, { ok: false, error: "CAPABILITY_REPLAYED" });
  // resolution stores the response envelope; an identical retry of a
  // TERMINAL use replays it verbatim and is marked terminal (C-02)
  core.resolveCapabilityUse("nonce-1", "RESOLVED_SUCCESS", '{"status":200,"body":{"appendLsn":"7"}}');
  const afterResolve = core.claimCapability("nonce-1", "use-digest-A", expires, now + 3);
  assert.deepEqual(afterResolve, {
    ok: true, fresh: false, state: "RESOLVED_SUCCESS", terminal: true,
    response: '{"status":200,"body":{"appendLsn":"7"}}',
  });
  // C-02: a SECOND, DIFFERENT terminal transition is a consistency
  // violation - it quarantines rather than mutating a settled outcome
  assert.throws(() => core.resolveCapabilityUse("nonce-1", "RESOLVED_REJECTED", "{}"),
    /DATABASE_QUARANTINED/);
  // and the database is now terminally quarantined: a reopen refuses
  assert.throws(() => new ControllerCore(sqlOver(db), { journalKey: KEY }), /DATABASE_QUARANTINED/);
  // expiry prunes the use record with the token it belongs to (fresh core,
  // since the first was quarantined by the consistency-violation test above)
  const db2 = new Database(":memory:");
  const core2 = new ControllerCore(sqlOver(db2), { journalKey: KEY });
  const expired = core2.claimCapability("nonce-2", "use-digest-C", now + 5, now + 5);
  assert.ok(expired.ok && expired.fresh);
  const reused = core2.claimCapability("nonce-2", "use-digest-DIFFERENT", expires, now + 6);
  assert.ok(reused.ok && reused.fresh, "an expired use is pruned, the nonce check is over live tokens");
});
