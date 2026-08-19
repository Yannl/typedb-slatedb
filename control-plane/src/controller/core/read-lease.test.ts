/*
 * R5-SEC-05 mutants at the authority: the read fence has no TOCTOU window.
 *
 * The round-5 audit's finding was that the token AND the "is this session
 * still an active reader" question were answered in the ControllerDO, and
 * the R2/data read then happened in a SEPARATE hop — so a fence could
 * commit between them and a superseded actor could still be served.
 *
 * The design under test: `authorizeRead` revalidates the actor AND performs
 * the catalogue read inside ONE synchronous transaction, and hands back a
 * durable ONE-SHOT lease over the exact object keys the byte hop will
 * touch. Every fence/revoke/expiry/incarnation transition deletes that
 * actor's leases in its OWN transaction, and `redeemReadLease` re-checks
 * validity AT REDEMPTION TIME. The audit's acceptance is executed here:
 *
 *   pause after authorization -> fence -> resume  => typed refusal, no serve
 *   an already-open scan page  (the iterator case) => same
 *   a lease replayed after expiry                  => typed refusal
 *   a lease replayed after use (single-shot)       => typed refusal
 *   a lease redeemed for OTHER keys                => typed refusal
 *   an incarnation bump                            => every lease dies
 *
 * Run: node --experimental-strip-types --test src/controller/core/read-lease.test.ts
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { ControllerCore, READ_LEASE_TTL_MS, type ReadOutcome } from "./procedures.ts";
import { makeSql, reqFactory, TEST_BUDGETS } from "./test-support.ts";

/** Assertion detail that survives bigint sequence values. */
const show = (value: unknown): string =>
  JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? v.toString() : v));

const GEN = 1;
const DB = "db1";
const READER = "sess-1";

/** A core with one catalogued record, over a controllable clock. */
function bootWithRecord(clock?: { now: number }) {
  const { sql } = makeSql();
  const core = new ControllerCore(sql, clock ? { now: () => clock.now } : {});
  core.registerSession(DB, GEN, READER);
  const budgeted = core.setBudgets(DB, TEST_BUDGETS, READER);
  assert.ok(budgeted.ok, show(budgeted));
  const req = reqFactory("rl", { generation: GEN, payloadLength: 10 });
  const request = req({ startupSessionId: READER });
  const finalized = core.finalizeWalRecord(request);
  assert.ok(finalized.ok, show(finalized));
  return { core, key: request.payloadKey };
}

function okExact(outcome: ReadOutcome) {
  assert.equal(outcome.ok, true, show(outcome));
  assert.equal((outcome as { kind: string }).kind, "EXACT");
  return outcome as Extract<ReadOutcome, { ok: true; kind: "EXACT" }>;
}

test("R5-SEC-05 MUTANT: pause after authorization, fence the actor, resume the read -> refused, never served", () => {
  const { core, key } = bootWithRecord();
  // 1. the authoritative hop: actor revalidated AND catalogue read, one txn
  const authorized = okExact(core.authorizeRead(DB, READER, GEN, { kind: "EXACT", generation: GEN, appendLsn: 0n }));
  assert.equal(authorized.record.payloadKey, key);
  assert.equal(core.countReadLeases(DB, READER), 1);

  // 2. PAUSE: the worker is now fetching the R2 bytes. The replacement
  //    activates and fences the old actor while those bytes are in flight.
  core.fenceSession(DB, READER);

  // 3. RESUME: the bytes are in hand; redemption is the authoritative cut.
  const redeemed = core.redeemReadLease(authorized.lease.leaseId, [key]);
  assert.equal(redeemed.ok, false, show(redeemed));
  // the fence deleted the grant in the fence's own transaction
  assert.equal((redeemed as { error: string }).error, "READ_LEASE_UNKNOWN");
  assert.equal(core.countReadLeases(DB, READER), 0);
});

test("R5-SEC-05 MUTANT: a fenced actor cannot open a NEW read at all (single hop refuses)", () => {
  const { core } = bootWithRecord();
  core.fenceSession(DB, READER);
  const outcome = core.authorizeRead(DB, READER, GEN, { kind: "EXACT", generation: GEN, appendLsn: 0n });
  assert.equal(outcome.ok, false, show(outcome));
  assert.equal((outcome as { error: string }).error, "SESSION_NOT_ACTIVE");
});

test("R5-SEC-05 MUTANT: an already-open scan page (pinned iterator) cannot be served after a fence", () => {
  const { core, key } = bootWithRecord();
  const iterator = core.authorizeRead(DB, READER, GEN, { kind: "ITERATOR", generation: GEN });
  assert.equal(iterator.ok, true, show(iterator));
  const snapshotId = (iterator as { snapshotId: string }).snapshotId;

  // the scan page is authorized and its keys leased in the same hop
  const page = core.authorizeRead(DB, READER, GEN, {
    kind: "SCAN", generation: GEN, snapshotId, fromTypeSequence: 0n, fromLsn: 0n,
    recordType: null, limit: 100, maxBytes: 8 * 1024 * 1024,
  });
  assert.equal(page.ok, true, show(page));
  const scan = page as Extract<ReadOutcome, { ok: true; kind: "SCAN" }>;
  assert.equal(scan.records.length, 1);

  // the replacement activates mid-iteration
  core.fenceSession(DB, READER);

  // the in-flight page cannot be served ...
  const redeemed = core.redeemReadLease(scan.lease.leaseId, [key]);
  assert.equal(redeemed.ok, false, show(redeemed));
  // ... and the NEXT page of the same pinned snapshot cannot even be opened
  const next = core.authorizeRead(DB, READER, GEN, {
    kind: "SCAN", generation: GEN, snapshotId, fromTypeSequence: 0n, fromLsn: 0n,
    recordType: null, limit: 100, maxBytes: 8 * 1024 * 1024,
  });
  assert.equal(next.ok, false, show(next));
});

test("R5-SEC-05 MUTANT: a lease replayed after its TTL is refused (typed EXPIRED)", () => {
  const clock = { now: Date.now() };
  const { core, key } = bootWithRecord(clock);
  const authorized = okExact(core.authorizeRead(DB, READER, GEN, { kind: "EXACT", generation: GEN, appendLsn: 0n }));
  assert.equal(authorized.lease.expiresAtMs, clock.now + READ_LEASE_TTL_MS);

  // the byte hop takes longer than the whole lease window
  clock.now += READ_LEASE_TTL_MS + 1;
  const redeemed = core.redeemReadLease(authorized.lease.leaseId, [key]);
  assert.equal(redeemed.ok, false, show(redeemed));
  assert.equal((redeemed as { error: string }).error, "READ_LEASE_EXPIRED");
});

test("R5-SEC-05 MUTANT: a lease is ONE-SHOT — the second redemption is refused", () => {
  const { core, key } = bootWithRecord();
  const authorized = okExact(core.authorizeRead(DB, READER, GEN, { kind: "EXACT", generation: GEN, appendLsn: 0n }));
  assert.equal(core.redeemReadLease(authorized.lease.leaseId, [key]).ok, true);
  const again = core.redeemReadLease(authorized.lease.leaseId, [key]);
  assert.equal(again.ok, false, show(again));
  assert.equal((again as { error: string }).error, "READ_LEASE_CONSUMED");
});

test("R5-SEC-05 MUTANT: a lease cannot be widened — redeeming for other keys is refused", () => {
  const { core } = bootWithRecord();
  const authorized = okExact(core.authorizeRead(DB, READER, GEN, { kind: "EXACT", generation: GEN, appendLsn: 0n }));
  const stolen = core.redeemReadLease(authorized.lease.leaseId, [`p/${DB}/${"0".repeat(64)}`]);
  assert.equal(stolen.ok, false, show(stolen));
  assert.equal((stolen as { error: string }).error, "READ_LEASE_KEY_MISMATCH");
  // an unknown lease id is refused too (a forged ticket is not a grant)
  const forged = core.redeemReadLease("rl-forged", [`p/${DB}/${"0".repeat(64)}`]);
  assert.equal((forged as { error: string }).error, "READ_LEASE_UNKNOWN");
});

test("R5-SEC-05: revocation and an incarnation bump both kill outstanding read grants", () => {
  const { core, key } = bootWithRecord();
  const revoked = okExact(core.authorizeRead(DB, READER, GEN, { kind: "EXACT", generation: GEN, appendLsn: 0n }));
  assert.equal(core.revokeSession(DB, READER).ok, true);
  assert.equal(core.redeemReadLease(revoked.lease.leaseId, [key]).ok, false);

  // a fresh actor, a fresh grant, then a controller incarnation bump
  core.registerSession(DB, GEN, "sess-2");
  const afterBump = okExact(core.authorizeRead(DB, "sess-2", GEN, { kind: "EXACT", generation: GEN, appendLsn: 0n }));
  core.bumpIncarnation();
  const redeemed = core.redeemReadLease(afterBump.lease.leaseId, [key]);
  assert.equal(redeemed.ok, false, show(redeemed));
  assert.equal((redeemed as { error: string }).error, "READ_LEASE_UNKNOWN");
});

test("R5-SEC-05: metadata-only reads take NO lease — the single hop is the whole read", () => {
  const { core } = bootWithRecord();
  const head = core.authorizeRead(DB, READER, GEN, { kind: "HEAD", generation: GEN });
  assert.equal(head.ok, true, show(head));
  assert.ok(!("lease" in head));
  assert.equal(core.countReadLeases(DB, READER), 0);
});

test("R5-SEC-05: the happy path still serves — authorize, redeem, done", () => {
  const { core, key } = bootWithRecord();
  const authorized = okExact(core.authorizeRead(DB, READER, GEN, { kind: "EXACT", generation: GEN, appendLsn: 0n }));
  assert.equal(authorized.record.payloadDigest.length > 0, true);
  assert.equal(authorized.record.payloadLength, 10);
  const redeemed = core.redeemReadLease(authorized.lease.leaseId, [key]);
  assert.equal(redeemed.ok, true, show(redeemed));
});
