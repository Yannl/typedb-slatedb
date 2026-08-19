/*
 * R5-SEC-04 mutants: an AMBIGUOUS capability use must CONVERGE.
 *
 * The round-5 audit's finding was that `AMBIGUOUS -> terminal` was a legal
 * transition nothing performed: a provider committed, the response was
 * lost, the wrapper marked the nonce ambiguous, and every identical retry
 * then received 409 forever. These tests drive the recovery reducer over a
 * real SQLite and require the audit's exact acceptance list:
 *
 *   timeout BEFORE the effect  -> resolves retryably (no effect, re-execute)
 *   timeout AFTER  the effect  -> resolves to the EXACT original success
 *   contradictory evidence     -> QUARANTINED, terminally, fail-closed
 *   restart                    -> a new core over the same storage resumes
 *   same token, different request -> still CAPABILITY_REPLAYED
 *   new token, same operation  -> cannot duplicate the effect
 *
 * Run: node --experimental-strip-types --test src/controller/core/ambiguity.test.ts
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { ControllerCore } from "./procedures.ts";
import { makeSql as makeSqlFixture, reqFactory } from "./test-support.ts";

const GEN = 3;
const req = reqFactory("op", { generation: GEN, payloadLength: 100 });

/** A core plus a `rebuild()` that opens a SECOND ControllerCore over the
 *  SAME durable storage — the audit's restart-resumption case. The shared
 *  fixture's boot() owns its own database, so the shared-storage variant is
 *  constructed here explicitly (mirroring boot()'s session+budget setup). */
function bootWithSql() {
  const { sql } = makeSqlFixture();
  const build = () => new ControllerCore(sql, {});
  const core = build();
  core.registerSession("db1", GEN, "sess-1");
  const budgeted = core.setBudgets("db1", {
    maxUnpublishedOutbox: 1_000, maxPayloadLength: 1_000_000, maxTailRecords: 1_000_000,
  }, "sess-1");
  assert.ok(budgeted.ok, JSON.stringify(budgeted));
  return { core, sql, rebuild: build };
}

// The sweep compares `used_at_ms` against the CONTROLLER clock, so claim
// times must be real and in the past for an aged row to be sweepable.
const NOW = Date.now() - 120_000;
const EXPIRES = Date.now() + 600_000;

function finalizeEffect(operationId: string, requestDigest: string) {
  return { kind: "WAL_FINALIZE" as const, databaseId: "db1", generation: GEN, operationId, requestDigest };
}

test("timeout AFTER the effect resolves to the exact original success", () => {
  const { core } = bootWithSql();
  const request = req({ operationId: "op-after", sequencingKind: "SEQUENCED" });
  const digest = request.requestDigest;

  // the use is claimed and bound to its effect, the effect COMMITS, and then
  // the response is lost: the wrapper records AMBIGUOUS instead of a receipt
  const claim = core.claimCapability("nonce-after", "usedigest-after", EXPIRES, NOW,
    finalizeEffect("op-after", digest));
  assert.ok(claim.ok && claim.fresh);
  const receipt = core.finalizeWalRecord(request);
  assert.ok(receipt.ok);
  core.resolveCapabilityUse("nonce-after", "AMBIGUOUS", JSON.stringify({ error: "socket hang up" }));

  // the retry no longer wedges: the reducer finds the wal_tail row under
  // this operation identity and settles the use to the original receipt
  const settled = core.resolveAmbiguousUse("nonce-after");
  assert.ok(settled.ok, JSON.stringify(settled));
  assert.equal(settled.disposition, "SETTLED");
  assert.equal(settled.state, "RESOLVED_SUCCESS");
  const replayed = JSON.parse(settled.response as string) as { status: number; body: Record<string, unknown> };
  assert.equal(replayed.status, 200);
  assert.equal(String(replayed.body.appendLsn), String(receipt.appendLsn));

  // and an identical retry now replays that terminal outcome
  const retry = core.claimCapability("nonce-after", "usedigest-after", EXPIRES, NOW);
  assert.ok(retry.ok && !retry.fresh && retry.terminal);
});

test("timeout BEFORE the effect resolves retryably, and the retry succeeds cleanly", () => {
  const { core } = bootWithSql();
  const request = req({ operationId: "op-before", sequencingKind: "SEQUENCED" });

  // claimed, bound — but the effect never happened before the timeout
  const claim = core.claimCapability("nonce-before", "usedigest-before", EXPIRES, NOW,
    finalizeEffect("op-before", request.requestDigest));
  assert.ok(claim.ok && claim.fresh);
  core.resolveCapabilityUse("nonce-before", "AMBIGUOUS", JSON.stringify({ error: "timeout" }));

  const settled = core.resolveAmbiguousUse("nonce-before");
  assert.ok(settled.ok, JSON.stringify(settled));
  assert.equal(settled.disposition, "RE_EXECUTE");

  // the identical request may now execute and resolve normally
  const receipt = core.finalizeWalRecord(request);
  assert.ok(receipt.ok);
});

test("MUTANT: contradictory durable evidence QUARANTINES the use, terminally", () => {
  const { core } = bootWithSql();
  const request = req({ operationId: "op-contra", sequencingKind: "SEQUENCED" });
  const receipt = core.finalizeWalRecord(request);
  assert.ok(receipt.ok);

  // the recorded binding names the SAME operation id under a DIFFERENT
  // request digest: the physical evidence contradicts the operation
  core.claimCapability("nonce-contra", "usedigest-contra", EXPIRES, NOW,
    finalizeEffect("op-contra", "f".repeat(64)));
  core.resolveCapabilityUse("nonce-contra", "AMBIGUOUS", JSON.stringify({ error: "lost" }));

  const settled = core.resolveAmbiguousUse("nonce-contra");
  assert.equal(settled.ok, false);
  assert.equal((settled as { error: string }).error, "CAPABILITY_USE_QUARANTINED");

  // fail-closed FOREVER: the claim gate itself refuses from now on
  const retry = core.claimCapability("nonce-contra", "usedigest-contra", EXPIRES, NOW);
  assert.equal(retry.ok, false);
  assert.equal((retry as { error: string }).error, "CAPABILITY_USE_QUARANTINED");
  // and re-resolving keeps the same terminal answer (no oscillation)
  assert.equal((core.resolveAmbiguousUse("nonce-contra") as { error: string }).error,
    "CAPABILITY_USE_QUARANTINED");
});

test("a RESTART resumes resolution: a new core over the same storage settles the use", () => {
  const { core, rebuild } = bootWithSql();
  const request = req({ operationId: "op-restart", sequencingKind: "SEQUENCED" });
  core.claimCapability("nonce-restart", "usedigest-restart", EXPIRES, NOW,
    finalizeEffect("op-restart", request.requestDigest));
  const receipt = core.finalizeWalRecord(request);
  assert.ok(receipt.ok);
  core.resolveCapabilityUse("nonce-restart", "AMBIGUOUS", JSON.stringify({ error: "evicted mid-flight" }));

  // the process/DO dies here; a fresh core opens the same durable state
  const revived = rebuild();
  const swept = revived.sweepAmbiguousUses({ limit: 64, minAgeMs: 0 });
  assert.equal(swept.settled, 1, JSON.stringify(swept));

  const retry = revived.claimCapability("nonce-restart", "usedigest-restart", EXPIRES, NOW);
  assert.ok(retry.ok && retry.terminal, JSON.stringify(retry));
  const stored = JSON.parse(retry.response as string) as { body: Record<string, unknown> };
  assert.equal(String(stored.body.appendLsn), String(receipt.appendLsn));
});

test("MUTANT: the same token with a DIFFERENT request is still CAPABILITY_REPLAYED", () => {
  const { core } = bootWithSql();
  core.claimCapability("nonce-diff", "usedigest-A", EXPIRES, NOW,
    finalizeEffect("op-diff", "a".repeat(64)));
  core.resolveCapabilityUse("nonce-diff", "AMBIGUOUS", JSON.stringify({ error: "lost" }));
  const other = core.claimCapability("nonce-diff", "usedigest-B", EXPIRES, NOW);
  assert.equal(other.ok, false);
  assert.equal((other as { error: string }).error, "CAPABILITY_REPLAYED");
});

test("MUTANT: a NEW token for the same operation cannot duplicate the effect", () => {
  const { core } = bootWithSql();
  const request = req({ operationId: "op-dup", sequencingKind: "SEQUENCED" });
  core.claimCapability("nonce-dup-1", "usedigest-dup", EXPIRES, NOW,
    finalizeEffect("op-dup", request.requestDigest));
  const first = core.finalizeWalRecord(request);
  assert.ok(first.ok);
  core.resolveCapabilityUse("nonce-dup-1", "AMBIGUOUS", JSON.stringify({ error: "lost" }));

  // a fresh token (different nonce) presenting the SAME operation identity:
  // idempotency is by OPERATION, not by token, so the second finalize
  // reproduces the original receipt instead of appending a second row
  const second = core.claimCapability("nonce-dup-2", "usedigest-dup", EXPIRES, NOW,
    finalizeEffect("op-dup", request.requestDigest));
  assert.ok(second.ok && second.fresh);
  const replayed = core.finalizeWalRecord(request);
  assert.ok(replayed.ok);
  assert.equal(String(replayed.appendLsn), String(first.appendLsn));
  assert.ok(core.auditContiguity("db1", GEN).contiguous);
});

test("the sweep is bounded and leaves genuinely in-flight uses alone", () => {
  const { core } = bootWithSql();
  // a use claimed RIGHT NOW must not be raced by the sweep
  core.claimCapability("nonce-fresh", "usedigest-fresh", EXPIRES, Date.now(),
    finalizeEffect("op-fresh", "b".repeat(64)));
  const swept = core.sweepAmbiguousUses({ limit: 64, minAgeMs: 60_000 });
  assert.equal(swept.scanned, 0, JSON.stringify(swept));
  // and it is bounded per pass
  assert.ok(core.sweepAmbiguousUses({ limit: 1, minAgeMs: 0 }).scanned <= 1);
});
