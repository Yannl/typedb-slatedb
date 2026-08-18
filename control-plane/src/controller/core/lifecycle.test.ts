/*
 * Q-03 / directive §12.4: the startup-session lifecycle.
 *
 * The defect this closes: takeover-at-open. Any fresh session id could fence
 * every live actor by calling register. Now identity is split from
 * authority: reservation and attestation grant nothing, activation is one
 * transaction that revalidates reservation + nonce + incarnation +
 * generation before it fences anyone, and authority lives under a
 * controller-time lease with a persisted nondecreasing floor.
 *
 * The clock is injected, so the directive's clock-jump matrix is executed,
 * not argued: backward jumps cannot extend a lease, forward jumps expire it
 * (fail closed), and expiry is terminal - no resurrection.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import Database from "better-sqlite3";
import { ControllerCore, type FinalizeRequest, type SyncSql } from "./procedures.ts";

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
function req(session: string, overrides: Partial<FinalizeRequest> = {}): FinalizeRequest {
  opCounter += 1;
  return {
    databaseId: "db1", generation: 1, startupSessionId: session,
    operationId: `op-${opCounter}`, requestDigest: `digest-op-${opCounter}`,
    sequencingKind: "SEQUENCED", recordType: 2, logicalKey: null,
    payloadKey: `payload/op-${opCounter}`, payloadDigest: `pd-op-${opCounter}`, payloadLength: 10,
    ...overrides,
  };
}

/** A core with a fully controllable clock. */
function bootClocked(startMs = 1_000_000) {
  const clock = { now: startMs };
  const core = new ControllerCore(makeSql(), { now: () => clock.now });
  return { core, clock };
}

/** reserve -> attest -> activate one session, generous lease. */
function activate(core: ControllerCore, session: string, opts: { generation?: number; leaseMs?: number } = {}) {
  const generation = opts.generation ?? 1;
  assert.ok(core.reserveSession("db1", generation, session, `holder-${session}`).ok);
  assert.ok(core.attestSession("db1", session, `nonce-${session}`).ok);
  const activated = core.activateSession("db1", session, {
    processNonce: `nonce-${session}`, generation, leaseMs: opts.leaseMs ?? 60_000,
  });
  assert.ok(activated.ok, JSON.stringify(activated));
  return activated;
}

function budget(core: ControllerCore, session: string) {
  const set = core.setBudgets("db1",
    { maxUnpublishedOutbox: 10_000, maxPayloadLength: 1_000_000, maxTailRecords: 1_000_000 }, session);
  assert.ok(set.ok, JSON.stringify(set));
}

test("12.4: reservation and attestation grant NOTHING - only activation fences and authorizes", () => {
  const { core } = bootClocked();
  activate(core, "sess-1");
  budget(core, "sess-1");
  assert.ok(core.finalizeWalRecord(req("sess-1")).ok);

  // a rival reserves and attests: the incumbent is untouched and the rival
  // still cannot append
  assert.ok(core.reserveSession("db1", 1, "sess-rival", "holder-r").ok);
  assert.ok(core.attestSession("db1", "sess-rival", "nonce-r").ok);
  assert.ok(core.finalizeWalRecord(req("sess-1")).ok, "incumbent unaffected by a reservation");
  const rivalAppend = core.finalizeWalRecord(req("sess-rival"));
  assert.ok(!rivalAppend.ok && rivalAppend.error === "SESSION_UNKNOWN",
    `an attested-but-unactivated session appends nothing: ${JSON.stringify(rivalAppend)}`);

  // activation is the takeover
  const takeover = core.activateSession("db1", "sess-rival", {
    processNonce: "nonce-r", generation: 1, leaseMs: 60_000,
  });
  assert.ok(takeover.ok && takeover.fencedPredecessors === 1);
  assert.deepEqual(core.finalizeWalRecord(req("sess-1")), { ok: false, error: "SESSION_FENCED" });
  assert.ok(core.finalizeWalRecord(req("sess-rival")).ok);
});

test("12.4: a fresh random session id cannot fence anyone (the Q-03 defect, refuted directly)", () => {
  const { core } = bootClocked();
  activate(core, "sess-1");
  budget(core, "sess-1");
  assert.ok(core.finalizeWalRecord(req("sess-1")).ok);

  // the attacker skips the protocol entirely: activation without a
  // reservation, activation without attestation, appends under a made-up id
  assert.deepEqual(core.activateSession("db1", "sess-evil", {
    processNonce: "n", generation: 1, leaseMs: 60_000,
  }), { ok: false, error: "SESSION_NOT_RESERVED" });
  assert.ok(core.reserveSession("db1", 1, "sess-evil", "holder-evil").ok);
  assert.deepEqual(core.activateSession("db1", "sess-evil", {
    processNonce: "n", generation: 1, leaseMs: 60_000,
  }), { ok: false, error: "SESSION_NOT_ATTESTED" });
  // ...and through every refusal, the incumbent still appends
  assert.ok(core.finalizeWalRecord(req("sess-1")).ok);
});

test("12.4: activation revalidates the attested nonce - a hijacked reservation is refused", () => {
  const { core } = bootClocked();
  assert.ok(core.reserveSession("db1", 1, "sess-a", "holder-a").ok);
  assert.ok(core.attestSession("db1", "sess-a", "nonce-real").ok);
  // a different process presenting a different nonce cannot attest over it...
  assert.deepEqual(core.attestSession("db1", "sess-a", "nonce-imposter"),
    { ok: false, error: "SESSION_NOT_RESERVED" });
  // ...and cannot activate with its own nonce
  assert.deepEqual(core.activateSession("db1", "sess-a", {
    processNonce: "nonce-imposter", generation: 1, leaseMs: 60_000,
  }), { ok: false, error: "PROCESS_NONCE_MISMATCH" });
  // the real process activates
  assert.ok(core.activateSession("db1", "sess-a", {
    processNonce: "nonce-real", generation: 1, leaseMs: 60_000,
  }).ok);
});

test("12.4: activation revalidates incarnation and generation inside the transaction", () => {
  const { core } = bootClocked();
  assert.ok(core.reserveSession("db1", 1, "sess-a", "holder-a").ok);
  assert.ok(core.attestSession("db1", "sess-a", "nonce-a").ok);
  // the controller moves on between reservation and activation
  core.bumpIncarnation();
  const stale = core.activateSession("db1", "sess-a", {
    processNonce: "nonce-a", generation: 1, leaseMs: 60_000,
  });
  assert.ok(!stale.ok && stale.error === "STALE_INCARNATION",
    "a reservation from a superseded controller is evidence about a dead authority");

  // generation mismatch is its own refusal
  assert.ok(core.reserveSession("db1", 1, "sess-b", "holder-b").ok);
  assert.ok(core.attestSession("db1", "sess-b", "nonce-b").ok);
  const wrongGen = core.activateSession("db1", "sess-b", {
    processNonce: "nonce-b", generation: 2, leaseMs: 60_000,
  });
  assert.ok(!wrongGen.ok && wrongGen.error === "GENERATION_MISMATCH");
});

test("12.4: session ids are single-use - a spent id is a permanent refusal, never a fresh slot", () => {
  const { core } = bootClocked();
  activate(core, "sess-a");
  activate(core, "sess-b"); // fences and revokes sess-a
  assert.deepEqual(core.reserveSession("db1", 1, "sess-a", "someone-else"),
    { ok: false, error: "SESSION_ID_ALREADY_USED" });
  // idempotent retry of a live reservation is fine (lost response)
  assert.ok(core.reserveSession("db1", 1, "sess-c", "holder-c").ok);
  assert.ok(core.reserveSession("db1", 1, "sess-c", "holder-c").ok);
  // but the same id under a different holder is a conflict
  assert.deepEqual(core.reserveSession("db1", 1, "sess-c", "other-holder"),
    { ok: false, error: "SESSION_ID_ALREADY_USED" });
});

test("12.4: expiry blocks mutations before any counter/outbox is consumed; reads survive", () => {
  const { core, clock } = bootClocked();
  activate(core, "sess-1", { leaseMs: 10_000 });
  budget(core, "sess-1");
  const first = core.finalizeWalRecord(req("sess-1"));
  assert.ok(first.ok);
  const opId = "op-durable";
  assert.ok(core.finalizeWalRecord(req("sess-1", { operationId: opId })).ok);

  clock.now += 10_001; // the lease runs out
  const expired = core.finalizeWalRecord(req("sess-1"));
  assert.deepEqual(expired, { ok: false, error: "SESSION_LEASE_EXPIRED" });
  assert.equal(core.auditContiguity("db1", 1).count, 2, "the refused mutation consumed nothing");
  // mutations of every kind are blocked...
  assert.deepEqual(core.setBudgets("db1",
    { maxUnpublishedOutbox: 1, maxPayloadLength: 1, maxTailRecords: 1 }, "sess-1"),
    { ok: false, error: "SESSION_NOT_ACTIVE", state: "EXPIRED" });
  // ...but durable history stays readable (12.4: expiry blocks new
  // mutations, it does not make historical results unreadable)
  const read = core.queryOperation("db1", 1, opId, "sess-1");
  assert.ok(read.ok, JSON.stringify(read, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
});

test("12.4: expiry is terminal - renewal cannot resurrect a dead session", () => {
  const { core, clock } = bootClocked();
  activate(core, "sess-1", { leaseMs: 10_000 });
  clock.now += 10_001;
  assert.deepEqual(core.renewLease("db1", "sess-1", 60_000), { ok: false, error: "SESSION_LEASE_EXPIRED" });
  // and again, later: EXPIRED is a terminal state, not a retry hint
  clock.now += 1;
  const again = core.renewLease("db1", "sess-1", 60_000);
  assert.ok(!again.ok && again.error === "SESSION_NOT_ACTIVE"
    && (again as { state: string }).state === "EXPIRED");
});

test("12.4: a backward clock jump cannot extend a lease (nondecreasing controller time)", () => {
  const { core, clock } = bootClocked();
  activate(core, "sess-1", { leaseMs: 10_000 });
  budget(core, "sess-1");
  // advance controller time close to the deadline, then jump the WALL clock
  // backward by an hour: controllerNow keeps the floor
  clock.now += 9_000;
  assert.ok(core.finalizeWalRecord(req("sess-1")).ok); // advances the floor
  clock.now -= 3_600_000;
  const renewed = core.renewLease("db1", "sess-1", 5_000);
  assert.ok(renewed.ok, "renewal against the FLOOR, not the jumped-back wall clock");
  // the deadline is floor + 5000, NOT (wall - 1h) + 5000: floor time still
  // expires it 5s later even though the wall clock reads an hour earlier
  clock.now = 1_000_000 + 9_000 + 5_001;
  assert.deepEqual(core.finalizeWalRecord(req("sess-1")), { ok: false, error: "SESSION_LEASE_EXPIRED" });
});

test("12.4: a forward clock jump fails closed - leases expire early, nothing is grandfathered", () => {
  const { core, clock } = bootClocked();
  activate(core, "sess-1", { leaseMs: 60_000 });
  budget(core, "sess-1");
  clock.now += 3_600_000; // one hour forward
  assert.deepEqual(core.finalizeWalRecord(req("sess-1")), { ok: false, error: "SESSION_LEASE_EXPIRED" });
});

test("12.4: renewal extends only an unexpired lease, from controller time", () => {
  const { core, clock } = bootClocked();
  activate(core, "sess-1", { leaseMs: 10_000 });
  budget(core, "sess-1");
  clock.now += 8_000;
  const renewed = core.renewLease("db1", "sess-1", 10_000);
  assert.ok(renewed.ok && renewed.leaseDeadlineMs === 1_000_000 + 8_000 + 10_000);
  clock.now += 9_999;
  assert.ok(core.finalizeWalRecord(req("sess-1")).ok, "inside the renewed lease");
});

test("12.4: drain retains authority for in-flight work; revoke ends it; both are journaled", () => {
  const { core } = bootClocked();
  activate(core, "sess-1");
  budget(core, "sess-1");
  assert.ok(core.beginDrain("db1", "sess-1").ok);
  assert.ok(core.finalizeWalRecord(req("sess-1")).ok, "draining still serves in-flight work");
  assert.ok(core.revokeSession("db1", "sess-1").ok);
  assert.deepEqual(core.finalizeWalRecord(req("sess-1")), { ok: false, error: "SESSION_FENCED" });
  // revoke is idempotent
  assert.ok(core.revokeSession("db1", "sess-1").ok);
});

test("12.4: activation is idempotent for a lost response, conflicting for anything else", () => {
  const { core } = bootClocked();
  const first = activate(core, "sess-1");
  const retry = core.activateSession("db1", "sess-1", {
    processNonce: "nonce-sess-1", generation: 1, leaseMs: 60_000,
  });
  assert.ok(first.ok && retry.ok && retry.leaseDeadlineMs === first.leaseDeadlineMs,
    "same nonce: the completed activation's outcome again");
  const conflicting = core.activateSession("db1", "sess-1", {
    processNonce: "someone-else", generation: 1, leaseMs: 60_000,
  });
  assert.ok(!conflicting.ok && conflicting.error === "SESSION_NOT_ATTESTED");
});

test("12.4: the legacy register macro routes through the lifecycle - same trace, one mechanism", () => {
  const { core } = bootClocked();
  core.registerSession("db1", 1, "sess-legacy");
  budget(core, "sess-legacy");
  assert.ok(core.finalizeWalRecord(req("sess-legacy")).ok);
  // the lifecycle row exists and is leased, so expiry applies to legacy too
  const renewal = core.renewLease("db1", "sess-legacy", 60_000);
  assert.ok(renewal.ok, "a legacy-registered session is lifecycle-managed");
  // takeover through register still fences (the three-lane pin holds)...
  core.registerSession("db1", 1, "sess-legacy-2");
  assert.deepEqual(core.finalizeWalRecord(req("sess-legacy")), { ok: false, error: "SESSION_FENCED" });
  // ...and a fenced actor's re-register remains a no-op
  core.registerSession("db1", 1, "sess-legacy");
  assert.deepEqual(core.finalizeWalRecord(req("sess-legacy")), { ok: false, error: "SESSION_FENCED" });
});
