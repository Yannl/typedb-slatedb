/*
 * R6-CTRL-01 / R6-CTRL-02: THE FOUR AMBIGUITY CUTS, FOR EVERY MUTATION.
 *
 * The audit's acceptance criterion is not "the effect converges". It is:
 * for EVERY mutation route, cut the request at each of the four points
 * where a client can lose certainty, restart the authority, resend the
 * identical request under the identical token, and observe
 *
 *   (i)  exactly ONE physical effect, and
 *   (ii) a byte-equivalent canonical response;
 *
 * then change any bound field under the same nonce and observe a PERMANENT
 * replay refusal.
 *
 * The four cuts, named as the audit names them:
 *   (a) BEFORE_EFFECT     the claim committed, the effect did not;
 *   (b) AFTER_EFFECT      the effect committed, the resolution did not;
 *   (c) AFTER_RESOLUTION  both committed, the response never left;
 *   (d) DELIVERED         the client HAS the response and retries anyway.
 *
 * `serve()` below is a faithful transcription of `withMutation` in
 * worker-entry.ts - claim, terminal replay, ambiguity reduction, execute,
 * resolve - reduced to the authority calls, because those are the only
 * parts that survive a restart. `route-effects.test.ts` pins the wrapper's
 * shape so the two cannot drift apart silently, and
 * `mutation-cuts.workerd.test.ts` drives cuts (b)-(d) through the REAL HTTP
 * routes on workerd.
 *
 * Every case is measured against a REFERENCE run of the same request at the
 * same clock, so "byte-equivalent" means byte-equivalent to what one clean
 * execution produces, not merely "equal to itself".
 *
 * Run: node --experimental-strip-types --test src/controller/core/ambiguity-cuts.test.ts
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import Database from "better-sqlite3";
import { ControllerCore, type CapabilityEffect } from "./procedures.ts";
import { sqlOver, reqFactory, TEST_BUDGETS, type TestDb } from "./test-support.ts";

type Envelope = { status: number; body: unknown };

/** The exact encoding `json()` puts on the wire: bigints are decimal
 *  strings, so a reconstructed receipt and a live one are comparable as
 *  BYTES rather than as loosely-equal objects. */
const wire = (envelope: Envelope): string =>
  JSON.stringify(envelope, (_k, v) => (typeof v === "bigint" ? v.toString() : v));

type Cut = "BEFORE_EFFECT" | "AFTER_EFFECT" | "AFTER_RESOLUTION" | "DELIVERED";
const CUTS: Cut[] = ["BEFORE_EFFECT", "AFTER_EFFECT", "AFTER_RESOLUTION", "DELIVERED"];

const T0 = 1_000_000;
/** How far the clock moves between the cut and the retry. It is deliberately
 *  the audit's own measurement interval: a renew that recomputed
 *  `controllerNow + leaseMs` produced 1,061,000 and then 1,062,000, and the
 *  byte comparison below is what turns that into a failure. */
const RETRY_DELAY_MS = 1_000;
const EXPIRES = T0 + 1_000_000_000;

/** A controllable authority over a controllable clock. */
function makeAuthority(): { core: ControllerCore; db: TestDb; clock: { t: number };
                            restart: () => ControllerCore } {
  const db = new Database(":memory:");
  const clock = { t: T0 };
  const build = () => new ControllerCore(sqlOver(db), { now: () => clock.t });
  const core = build();
  // the fixture's own boot: a registered, budgeted authority. Neither call
  // carries an operation identity, so neither writes a receipt - they are
  // the direct-core bootstrap path, not a capability use.
  core.registerSession("db1", 1, "sess-1");
  const budgeted = core.setBudgets("db1", TEST_BUDGETS, "sess-1");
  assert.ok(budgeted.ok, JSON.stringify(budgeted));
  return { core, db, clock, restart: build };
}

/**
 * withMutation's authority protocol, verbatim in its decision structure.
 * Returns the envelope the client receives, or null when the cut happened
 * before delivery.
 */
function serve(
  core: ControllerCore, nonce: string, useDigest: string, effect: CapabilityEffect,
  execute: (operationId: string) => Envelope, cut: Cut, nowMs: number,
): Envelope | null {
  const claim = core.claimCapability(nonce, useDigest, EXPIRES, nowMs, effect);
  if (!claim.ok) return { status: 403, body: claim };
  if (!claim.fresh) {
    if (claim.terminal) {
      return claim.response === null
        ? { status: 200, body: { ok: true, replayed: true } }
        : (JSON.parse(claim.response) as Envelope);
    }
    const settled = core.resolveAmbiguousUse(nonce);
    if (settled.ok && settled.disposition === "SETTLED") {
      return settled.response === null
        ? { status: 200, body: { ok: true, replayed: true } }
        : (JSON.parse(settled.response) as Envelope);
    }
    if (!settled.ok) return { status: 409, body: settled };
    // RE_EXECUTE: no effect exists, so the identical request may run again
  }
  if (cut === "BEFORE_EFFECT") return null;
  const result = execute(nonce);
  if (cut === "AFTER_EFFECT") return null;
  const ok = result.status >= 200 && result.status < 300;
  core.resolveCapabilityUse(nonce, ok ? "RESOLVED_SUCCESS" : "RESOLVED_REJECTED", wire(result));
  if (cut === "AFTER_RESOLUTION") return null;
  return result;
}

interface RouteCase {
  /** the MUTATION_ROUTES id this case stands for */
  route: string;
  useDigest: string;
  /** everything the request presupposes; runs before the clock is read */
  setup?: (core: ControllerCore) => void;
  effect: CapabilityEffect;
  execute: (core: ControllerCore, operationId: string) => Envelope;
  /** the PHYSICAL effect, as a value that a second execution would change */
  probe: (core: ControllerCore, db: TestDb) => unknown;
  /** normalize the ONE documented recovery marker (`replayed`) before the
   *  byte comparison; every other field must match exactly */
  canonical?: (envelope: Envelope) => Envelope;
  /** an extra, route-specific assertion on the canonical response */
  expect?: (body: Record<string, unknown>) => void;
}

const count = (db: TestDb, sql: string, ...params: unknown[]): number =>
  Number((db.prepare(sql).get(...(params as never[])) as { n: number }).n);

const HEX64 = "e".repeat(64);
const manifest = (cutId: string, walHead: string | null) => ({
  schema: "checkpoint-restore-evidence/v2",
  cutId,
  walHead,
  keyspaceRoots: [{ keyspace: "default", rootDigest: HEX64 }],
  logicalDigest: HEX64,
  scratchRestore: { verifier: "cuts-scratch-restore", verifiedAtMs: 1 },
  materializations: ["m-cuts-1"],
});

/** Strip the documented `replayed` recovery marker from a WAL receipt: it
 *  is the ONE field a reconstructed finalize receipt sets differently, by
 *  design (it tells the client the receipt came from durable state). */
const stripReplayed = (envelope: Envelope): Envelope => {
  const body = envelope.body as Record<string, unknown>;
  if (body === null || typeof body !== "object") return envelope;
  const clone: Record<string, unknown> = { ...body };
  delete clone.replayed;
  if (Array.isArray(clone.results)) {
    clone.results = clone.results.map((r) => {
      const member = { ...(r as Record<string, unknown>) };
      delete member.replayed;
      return member;
    });
  }
  return { status: envelope.status, body: clone };
};

const finalizeReq = reqFactory("cuts", { generation: 1 });
const FINALIZE_A = finalizeReq({ operationId: "cuts-op-a" });
const BATCH_A = finalizeReq({ operationId: "cuts-batch-a" });
const BATCH_B = finalizeReq({ operationId: "cuts-batch-b" });
// hoisted, not built per setup(): the factory's ids increment, and a cut's
// journal head hash must be comparable to the reference run's byte for byte
const PRE_CUT = finalizeReq({ operationId: "cuts-pre-cut" });

const CASES: RouteCase[] = [
  {
    route: "INCARNATION_BUMP",
    useDigest: "ud-bump",
    effect: { kind: "INCARNATION_BUMP" },
    execute: (core, op) => ({ status: 200, body: { ok: true, incarnation: core.bumpIncarnation(op) } }),
    probe: (core) => core.currentIncarnation(),
    expect: (body) => assert.equal(body.incarnation, 2),
  },
  {
    route: "SESSION_REGISTER",
    useDigest: "ud-register",
    effect: { kind: "OPERATION_RECEIPT", databaseId: "db1", method: "SESSION_REGISTER" },
    execute: (core, op) => {
      core.registerSession("db1", 1, "sess-legacy", op);
      return { status: 200, body: { ok: true } };
    },
    // the audit's complaint: the legacy macro refreshes the lease to
    // `controllerNow + 15m` on every execution
    probe: (_core, db) => db.prepare(
      `SELECT lease_deadline_ms AS v FROM startup_sessions WHERE startup_session_id='sess-legacy'`).get(),
  },
  {
    route: "SESSION_RESERVE",
    useDigest: "ud-reserve",
    effect: { kind: "OPERATION_RECEIPT", databaseId: "db1", method: "SESSION_RESERVE" },
    execute: (core, op) => {
      const r = core.reserveSession("db1", 1, "sess-x", "holder-a", op);
      return { status: r.ok ? 200 : 409, body: r };
    },
    probe: (_core, db) => db.prepare(
      `SELECT state, generation, holder FROM startup_sessions WHERE startup_session_id='sess-x'`).get(),
    expect: (body) => assert.equal(body.state, "RESERVED"),
  },
  {
    route: "SESSION_ATTEST",
    useDigest: "ud-attest",
    setup: (core) => { core.reserveSession("db1", 1, "sess-x", "holder-a"); },
    effect: { kind: "OPERATION_RECEIPT", databaseId: "db1", method: "SESSION_ATTEST" },
    execute: (core, op) => {
      const r = core.attestSession("db1", "sess-x", "pn-1", op);
      return { status: r.ok ? 200 : 409, body: r };
    },
    probe: (_core, db) => db.prepare(
      `SELECT state, process_nonce FROM startup_sessions WHERE startup_session_id='sess-x'`).get(),
    expect: (body) => assert.equal(body.state, "ATTESTED"),
  },
  {
    route: "SESSION_ACTIVATE",
    useDigest: "ud-activate",
    setup: (core) => {
      core.reserveSession("db1", 1, "sess-x", "holder-a");
      core.attestSession("db1", "sess-x", "pn-1");
    },
    effect: { kind: "OPERATION_RECEIPT", databaseId: "db1", method: "SESSION_ACTIVATE" },
    execute: (core, op) => {
      const r = core.activateSession("db1", "sess-x",
        { processNonce: "pn-1", generation: 1, leaseMs: 60_000 }, op);
      return { status: r.ok ? 200 : 409, body: r };
    },
    probe: (_core, db) => ({
      fenced: count(db, `SELECT COUNT(*) AS n FROM sessions WHERE fenced=1`),
      activations: count(db,
        `SELECT COUNT(*) AS n FROM control_outbox WHERE kind='SESSION_ACTIVATED'`),
      deadline: db.prepare(
        `SELECT lease_deadline_ms AS v FROM startup_sessions WHERE startup_session_id='sess-x'`).get(),
    }),
    // the audit's exact case: the original takeover fenced the predecessor,
    // and every later answer must keep saying so
    expect: (body) => assert.equal(body.fencedPredecessors, 1),
  },
  {
    route: "SESSION_RENEW",
    useDigest: "ud-renew",
    setup: (core) => {
      core.reserveSession("db1", 1, "sess-x", "holder-a");
      core.attestSession("db1", "sess-x", "pn-1");
      core.activateSession("db1", "sess-x", { processNonce: "pn-1", generation: 1, leaseMs: 60_000 });
    },
    effect: { kind: "OPERATION_RECEIPT", databaseId: "db1", method: "SESSION_RENEW" },
    execute: (core, op) => {
      const r = core.renewLease("db1", "sess-x", 60_000, op);
      return { status: r.ok ? 200 : 409, body: r };
    },
    probe: (_core, db) => db.prepare(
      `SELECT lease_deadline_ms AS v FROM startup_sessions WHERE startup_session_id='sess-x'`).get(),
    expect: (body) => assert.equal(body.leaseDeadlineMs, T0 + 60_000),
  },
  {
    route: "SESSION_DRAIN",
    useDigest: "ud-drain",
    setup: (core) => {
      core.reserveSession("db1", 1, "sess-x", "holder-a");
      core.attestSession("db1", "sess-x", "pn-1");
      core.activateSession("db1", "sess-x", { processNonce: "pn-1", generation: 1, leaseMs: 60_000 });
    },
    effect: { kind: "OPERATION_RECEIPT", databaseId: "db1", method: "SESSION_DRAIN" },
    execute: (core, op) => {
      const r = core.beginDrain("db1", "sess-x", op);
      return { status: r.ok ? 200 : 409, body: r };
    },
    probe: (_core, db) => ({
      state: db.prepare(
        `SELECT state AS v FROM startup_sessions WHERE startup_session_id='sess-x'`).get(),
      journaled: count(db, `SELECT COUNT(*) AS n FROM control_outbox WHERE kind='SESSION_DRAINING'`),
    }),
    expect: (body) => assert.equal(body.state, "DRAINING"),
  },
  {
    route: "SESSION_REVOKE",
    useDigest: "ud-revoke",
    setup: (core) => {
      core.reserveSession("db1", 1, "sess-x", "holder-a");
      core.attestSession("db1", "sess-x", "pn-1");
      core.activateSession("db1", "sess-x", { processNonce: "pn-1", generation: 1, leaseMs: 60_000 });
    },
    effect: { kind: "OPERATION_RECEIPT", databaseId: "db1", method: "SESSION_REVOKE" },
    execute: (core, op) => {
      const r = core.revokeSession("db1", "sess-x", op);
      return { status: r.ok ? 200 : 409, body: r };
    },
    probe: (_core, db) => count(db, `SELECT COUNT(*) AS n FROM control_outbox WHERE kind='SESSION_REVOKED'`),
    expect: (body) => assert.equal(body.state, "REVOKED"),
  },
  {
    route: "SESSION_FENCE",
    useDigest: "ud-fence",
    effect: { kind: "OPERATION_RECEIPT", databaseId: "db1", method: "SESSION_FENCE" },
    execute: (core, op) => {
      core.fenceSession("db1", "sess-1", op);
      return { status: 200, body: { ok: true } };
    },
    probe: (_core, db) => ({
      fenced: count(db, `SELECT COUNT(*) AS n FROM sessions WHERE fenced=1`),
      journaled: count(db, `SELECT COUNT(*) AS n FROM control_outbox WHERE kind='SESSION_FENCED'`),
    }),
  },
  {
    route: "BUDGETS_SET",
    useDigest: "ud-budgets",
    effect: { kind: "BUDGETS_SET", databaseId: "db1" },
    execute: (core, op) => {
      const r = core.setBudgets("db1",
        { maxUnpublishedOutbox: 500, maxPayloadLength: 4096, maxTailRecords: 9999 }, "sess-1", op);
      return { status: r.ok ? 200 : 409, body: r.ok ? { ok: true } : r };
    },
    // the audit's round-2 mutant: one token, two BUDGETS_SET journal rows
    probe: (_core, db) => count(db, `SELECT COUNT(*) AS n FROM control_outbox WHERE kind='BUDGETS_SET'`),
  },
  {
    route: "WAL_FINALIZE",
    useDigest: FINALIZE_A.requestDigest,
    effect: { kind: "WAL_FINALIZE", databaseId: "db1", generation: 1,
              operationId: FINALIZE_A.operationId, requestDigest: FINALIZE_A.requestDigest },
    execute: (core) => {
      const r = core.finalizeWalRecord(FINALIZE_A);
      return { status: r.ok ? 200 : 409, body: r };
    },
    probe: (_core, db) => count(db, `SELECT COUNT(*) AS n FROM wal_tail`),
    canonical: stripReplayed,
  },
  {
    route: "WAL_FINALIZE_BATCH",
    useDigest: "ud-batch",
    effect: { kind: "WAL_FINALIZE_BATCH", databaseId: "db1", generation: 1,
              batchOperationId: "batch-1",
              memberDigests: [BATCH_A.requestDigest, BATCH_B.requestDigest] },
    execute: (core) => {
      const r = core.finalizeBatch([BATCH_A, BATCH_B], { batchOperationId: "batch-1" });
      return Array.isArray(r) ? { status: 200, body: { ok: true, results: r } } : { status: 409, body: r };
    },
    probe: (_core, db) => ({
      tail: count(db, `SELECT COUNT(*) AS n FROM wal_tail`),
      envelopes: count(db, `SELECT COUNT(*) AS n FROM batch_operations`),
    }),
    canonical: stripReplayed,
    expect: (body) => assert.equal((body.results as unknown[]).length, 2),
  },
  {
    route: "OUTBOX_ACK",
    useDigest: "ud-ack",
    effect: { kind: "OPERATION_RECEIPT", databaseId: "db1", method: "OUTBOX_ACK" },
    execute: (core, op) => {
      const r = core.outboxAck("db1", 1_000n, "sess-1", op);
      return r.ok
        ? { status: 200, body: { ok: true, acked: r.acked } }
        : { status: 409, body: r };
    },
    probe: (_core, db) => count(db, `SELECT COUNT(*) AS n FROM control_outbox WHERE published=0`),
    // the audit's exact case: the second call reports 0 where the original
    // reported N, and N is destroyed by the ack itself
    expect: (body) => assert.ok((body.acked as number) > 0, `acked=${String(body.acked)}`),
  },
  {
    route: "CHECKPOINT_OPEN",
    useDigest: "ud-cut-open",
    setup: (core) => { core.finalizeWalRecord(PRE_CUT); },
    effect: { kind: "CHECKPOINT_OPEN", databaseId: "db1", generation: 1, cutId: "cut-1" },
    execute: (core) => {
      const r = core.openCheckpointCut("db1", 1, "cut-1");
      return { status: r.ok ? 200 : 409, body: r };
    },
    probe: (_core, db) => count(db, `SELECT COUNT(*) AS n FROM checkpoint_cuts`),
    // the audit's exact case: re-execution answered CUT_EXISTS and the
    // original cut receipt was lost
    expect: (body) => assert.equal(body.cutId, "cut-1"),
  },
  {
    route: "CHECKPOINT_ACTIVATE",
    useDigest: "ud-cut-activate",
    setup: (core) => {
      core.finalizeWalRecord(PRE_CUT);
      const opened = core.openCheckpointCut("db1", 1, "cut-1");
      assert.ok(opened.ok, opened.ok ? "" : opened.error);
    },
    effect: { kind: "CHECKPOINT_ACTIVATE", databaseId: "db1", cutId: "cut-1", logicalDigest: HEX64 },
    execute: (core) => {
      const r = core.activateCheckpointCut("db1", "cut-1", manifest("cut-1", "0"));
      return { status: r.ok ? 200 : 409, body: r };
    },
    probe: (_core, db) => ({
      active: count(db, `SELECT COUNT(*) AS n FROM checkpoint_cuts WHERE state='ACTIVE'`),
      journaled: count(db,
        `SELECT COUNT(*) AS n FROM control_outbox WHERE kind='CHECKPOINT_CUT_ACTIVATED'`),
    }),
    // the audit's exact case: re-execution answered CUT_NOT_PENDING
    expect: (body) => assert.equal(body.ok, true),
  },
];

/** One clean execution of the case at `now`, on its own authority: the
 *  reference the cut runs must reproduce. */
function reference(kase: RouteCase, now: number): { envelope: Envelope; probe: unknown } {
  const { core, db, clock } = makeAuthority();
  kase.setup?.(core);
  clock.t = now;
  const envelope = serve(core, "ref-nonce", kase.useDigest, kase.effect,
    (op) => kase.execute(core, op), "DELIVERED", now);
  assert.ok(envelope !== null);
  return { envelope, probe: kase.probe(core, db) };
}

for (const kase of CASES) {
  test(`ambiguity-cuts: ${kase.route} — four cuts, restart, one effect, exact replay`, () => {
    // the reference answers for the two instants that matter: the instant
    // the effect would have happened, and the (later) instant of the retry
    const atCut = reference(kase, T0);
    const atRetry = reference(kase, T0 + RETRY_DELAY_MS);
    const canonical = kase.canonical ?? ((e: Envelope) => e);

    // the reference answer is itself well-formed for this route
    kase.expect?.(atCut.envelope.body as Record<string, unknown>);
    assert.ok(atCut.envelope.status >= 200 && atCut.envelope.status < 300,
      `${kase.route}: the reference execution refused: ${wire(atCut.envelope)}`);

    for (const cut of CUTS) {
      const { core, db, clock, restart } = makeAuthority();
      kase.setup?.(core);
      const first = serve(core, "n-1", kase.useDigest, kase.effect,
        (op) => kase.execute(core, op), cut, clock.t);

      // cuts (a)-(c) deliver nothing; (d) delivers the canonical response
      assert.equal(first === null, cut !== "DELIVERED", `${kase.route}/${cut}: delivery`);
      if (first !== null) {
        assert.equal(wire(canonical(first)), wire(canonical(atCut.envelope)),
          `${kase.route}/${cut}: the delivered response is not the canonical one`);
      }

      // the authority restarts, and the client resends the IDENTICAL request
      // under the IDENTICAL token at a LATER instant
      clock.t = T0 + RETRY_DELAY_MS;
      const revived = restart();
      const second = serve(revived, "n-1", kase.useDigest, kase.effect,
        (op) => kase.execute(revived, op), "DELIVERED", clock.t);
      assert.ok(second !== null, `${kase.route}/${cut}: the retry delivered nothing`);

      if (cut === "BEFORE_EFFECT") {
        // nothing had happened, so the retry legitimately establishes the
        // outcome — at the RETRY instant. One effect, and the answer a
        // single clean execution at that instant produces.
        assert.equal(wire(canonical(second)), wire(canonical(atRetry.envelope)),
          `${kase.route}/BEFORE_EFFECT: the retry is not a clean single execution`);
        assert.deepEqual(kase.probe(revived, db), atRetry.probe,
          `${kase.route}/BEFORE_EFFECT: the retry did not produce exactly one effect`);
      } else {
        // the effect had already committed: the retry must reproduce the
        // ORIGINAL answer, computed at the ORIGINAL instant, and must not
        // touch the durable state again
        assert.equal(wire(canonical(second)), wire(canonical(atCut.envelope)),
          `${kase.route}/${cut}: the retry did not replay the original canonical response`);
        assert.deepEqual(kase.probe(revived, db), atCut.probe,
          `${kase.route}/${cut}: the retry produced a SECOND physical effect`);
        kase.expect?.(second.body as Record<string, unknown>);
      }

      // and a third, immediate retry is still the same answer (no drift)
      const third = serve(revived, "n-1", kase.useDigest, kase.effect,
        (op) => kase.execute(revived, op), "DELIVERED", clock.t);
      assert.equal(wire(canonical(third as Envelope)), wire(canonical(second)),
        `${kase.route}/${cut}: repeated retries do not agree`);
    }
  });

  test(`ambiguity-cuts: ${kase.route} — a changed bound field under the same nonce refuses forever`, () => {
    const { core, clock, restart } = makeAuthority();
    kase.setup?.(core);
    // cut (b): the effect committed, the resolution did not - the worst
    // state to present a DIFFERENT request in
    serve(core, "n-1", kase.useDigest, kase.effect, (op) => kase.execute(core, op),
      "AFTER_EFFECT", clock.t);

    clock.t = T0 + RETRY_DELAY_MS;
    const revived = restart();
    const conflicting = serve(revived, "n-1", `${kase.useDigest}-MUTATED`, kase.effect,
      (op) => kase.execute(revived, op), "DELIVERED", clock.t);
    assert.ok(conflicting !== null, `${kase.route}: the conflicting request produced no response`);
    assert.equal((conflicting.body as { error?: string }).error, "CAPABILITY_REPLAYED",
      `${kase.route}: a different request under a used nonce was admitted`);

    // permanent: it is still refused after the use settles and after another
    // restart, and the ORIGINAL request still replays correctly
    const again = restart();
    const stillRefused = serve(again, "n-1", `${kase.useDigest}-MUTATED`, kase.effect,
      (op) => kase.execute(again, op), "DELIVERED", clock.t);
    assert.ok(stillRefused !== null, `${kase.route}: the post-restart retry produced no response`);
    assert.equal((stillRefused.body as { error?: string }).error, "CAPABILITY_REPLAYED");
    const original = serve(again, "n-1", kase.useDigest, kase.effect,
      (op) => kase.execute(again, op), "DELIVERED", clock.t);
    assert.ok(original !== null && original.status >= 200 && original.status < 300,
      `${kase.route}: the original request stopped replaying: ${wire(original as Envelope)}`);
  });
}

test("MUTANT: a receipt recorded under a DIFFERENT method than the effect names quarantines", () => {
  const { core, db, clock, restart } = makeAuthority();
  const effect: CapabilityEffect =
    { kind: "OPERATION_RECEIPT", databaseId: "db1", method: "SESSION_RENEW" };
  core.reserveSession("db1", 1, "sess-x", "holder-a");
  core.attestSession("db1", "sess-x", "pn-1");
  core.activateSession("db1", "sess-x", { processNonce: "pn-1", generation: 1, leaseMs: 60_000 });
  serve(core, "n-q", "ud-q", effect,
    (op) => {
      const r = core.renewLease("db1", "sess-x", 60_000, op);
      return { status: r.ok ? 200 : 409, body: r };
    }, "AFTER_EFFECT", clock.t);

  // durable evidence is tampered to disagree with the recorded operation
  db.prepare(`UPDATE operation_receipts SET method='OUTBOX_ACK' WHERE operation_id='n-q'`).run();

  const revived = restart();
  const settled = revived.resolveAmbiguousUse("n-q");
  assert.equal(settled.ok, false);
  assert.equal((settled as { error: string }).error, "CAPABILITY_USE_QUARANTINED");
  // fail-closed forever, at the earliest gate
  const retry = revived.claimCapability("n-q", "ud-q", EXPIRES, clock.t, effect);
  assert.equal(retry.ok, false);
  assert.equal((retry as { error: string }).error, "CAPABILITY_USE_QUARANTINED");
});

test("MUTANT: a pre-R6 row carrying the retired generic effect still re-executes", () => {
  const { core, db, clock, restart } = makeAuthority();
  core.claimCapability("n-legacy", "ud-legacy", EXPIRES, clock.t,
    { kind: "OPERATION_RECEIPT", databaseId: "db1", method: "SESSION_FENCE" });
  // rewrite the row exactly as a round-5 build would have written it
  db.prepare(`UPDATE capability_uses SET effect='{"kind":"IDEMPOTENT_REEXECUTE"}' WHERE nonce='n-legacy'`).run();
  const revived = restart();
  const settled = revived.resolveAmbiguousUse("n-legacy");
  assert.ok(settled.ok, JSON.stringify(settled));
  assert.equal(settled.disposition, "RE_EXECUTE");
});

test("MUTANT: renewal does NOT extend authority a second time under the same nonce", () => {
  // the audit's executed measurement, as an assertion: the same logical
  // request at two later instants used to yield 1,061,000 then 1,062,000
  const { core, db, clock, restart } = makeAuthority();
  core.reserveSession("db1", 1, "sess-x", "holder-a");
  core.attestSession("db1", "sess-x", "pn-1");
  core.activateSession("db1", "sess-x", { processNonce: "pn-1", generation: 1, leaseMs: 60_000 });
  const effect: CapabilityEffect =
    { kind: "OPERATION_RECEIPT", databaseId: "db1", method: "SESSION_RENEW" };
  const renew = (c: ControllerCore) => (op: string): Envelope => {
    const r = c.renewLease("db1", "sess-x", 60_000, op);
    return { status: r.ok ? 200 : 409, body: r };
  };
  serve(core, "n-renew", "ud-renew", effect, renew(core), "AFTER_EFFECT", clock.t);
  const recordedDeadline = db.prepare(
    `SELECT lease_deadline_ms AS v FROM startup_sessions WHERE startup_session_id='sess-x'`)
    .get() as { v: number };
  assert.equal(recordedDeadline.v, T0 + 60_000);

  for (const advance of [1_000, 2_000, 60_000]) {
    clock.t = T0 + advance;
    const revived = restart();
    const replay = serve(revived, "n-renew", "ud-renew", effect, renew(revived), "DELIVERED", clock.t);
    assert.ok(replay !== null, `a retry at +${advance}ms produced no response`);
    assert.equal((replay.body as { leaseDeadlineMs: number }).leaseDeadlineMs, T0 + 60_000,
      `a retry at +${advance}ms recomputed the deadline instead of replaying it`);
    assert.equal((db.prepare(
      `SELECT lease_deadline_ms AS v FROM startup_sessions WHERE startup_session_id='sess-x'`)
      .get() as { v: number }).v, T0 + 60_000, "the retry extended durable authority again");
  }
});
