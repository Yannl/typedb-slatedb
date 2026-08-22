// The executable promotion gate (round-6 R6-LOCAL-01).
//
// The audit's instruction was to make RustFS the agent-local default AND to
// condition the qualification of that default on a lane that has actually
// run. The failure mode this program keeps hitting is a constant flipped
// and a sentence written claiming the lane is green. These tests exist to
// make that failure mode impossible to reach silently:
//
//   * with no evidence the gate MUST be OPEN and every lane must report
//     NOT_EXECUTED — there is no code path from "empty ledger" to GREEN;
//   * a recorded FAIL must not count as a pass;
//   * evidence recorded against a DIFFERENT binary digest must not count
//     for this one (R6-EVID-01 binding);
//   * an unreadable/foreign ledger is no evidence, not green evidence;
//   * the selection is always labelled: EXPLICIT / DEFAULT_QUALIFIED /
//     DEFAULT_PROVISIONAL, so no consumer can read "rustfs" without also
//     reading what that choice is worth.

// R8-P0-03: CAPABILITY-REQUIRED. This suite drives real process supervision
// and/or local networking; on a host without proc-identity, loopback-bind it does not run
// and reports INFRASTRUCTURE (exit 3), never a pass and never a silent skip.
import { require_ as requireCapability } from "./capability.mjs";
await requireCapability("proc-identity", "loopback-bind");

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  COMPARATOR_PROVIDER,
  DEFAULT_PROVIDER,
  REQUIRED_LANES,
  evaluateGate,
  formatGate,
  readLedger,
  recordLaneResult,
  resolveProvider,
} from "../local-parity.mjs";
import { LOCAL_S3_PROVIDER_COMPARATOR, LOCAL_S3_PROVIDER_DEFAULT, toGraph } from "../graph.data.mjs";

const newLedger = () => path.join(mkdtempSync(path.join(os.tmpdir(), "lane-ledger-")), "ledger.json");

const DIGEST_A = "a".repeat(64);
const DIGEST_B = "b".repeat(64);

function recordAll(file, { provider = DEFAULT_PROVIDER, status = "pass", binarySha256 = DIGEST_A } = {}) {
  for (const lane of REQUIRED_LANES) {
    recordLaneResult({
      lane: lane.id,
      provider,
      status,
      binarySha256,
      command: `pretend-runner --lane ${lane.id}`,
      file,
    });
  }
}

test("the default provider comes from the canonical graph, and the graph uses it", () => {
  assert.equal(DEFAULT_PROVIDER, LOCAL_S3_PROVIDER_DEFAULT);
  assert.equal(COMPARATOR_PROVIDER, LOCAL_S3_PROVIDER_COMPARATOR);
  assert.equal(DEFAULT_PROVIDER, "rustfs", "R6-LOCAL-01: RustFS is the agent-local default");
  assert.equal(COMPARATOR_PROVIDER, "minio", "R6-LOCAL-01: MinIO stays as the comparator");
  // provider-neutral graph: default and explicit selection both work, and
  // the cloudflare variant is untouched by local provider choice
  assert.equal(toGraph("local-native").s3.provider, "rustfs");
  assert.equal(toGraph("local-native", undefined, { s3Provider: "minio" }).s3.provider, "minio");
  assert.equal(toGraph("local-parity", undefined, { s3Provider: "minio" }).s3.provider, "minio");
  assert.equal(toGraph("cloudflare-real").s3.provider, "cloudflare-r2");
  assert.throws(() => toGraph("local-native", undefined, { s3Provider: "ceph" }), /unknown local S3 provider/);
});

test("with no evidence the gate is OPEN and every required lane says NOT_EXECUTED", () => {
  const file = newLedger();
  const gate = evaluateGate({ provider: DEFAULT_PROVIDER, file });
  assert.equal(gate.state, "OPEN");
  assert.equal(gate.ledgerEntries, 0);
  assert.deepEqual(gate.missing.sort(), REQUIRED_LANES.map((l) => l.id).sort());
  for (const lane of REQUIRED_LANES) {
    const l = gate.lanes[lane.id];
    assert.equal(l.executed, false, `${lane.id} must not claim execution`);
    assert.equal(l.status, "NOT_EXECUTED");
    assert.equal(l.runs, 0);
    assert.match(l.reason, /not executed in this session/);
    assert.ok(l.description.length > 0, "each lane states what it requires");
  }
  // and the structured status is what the machinery reports, not prose
  assert.equal(gate.schema, "typedb-r2-stack/provider-gate@1");
  assert.match(formatGate(gate), /NOT_EXECUTED/);
});

test("the default takes effect but is labelled DEFAULT_PROVISIONAL until the lane is green", () => {
  const file = newLedger();
  const sel = resolveProvider({ env: {}, file });
  assert.equal(sel.provider, DEFAULT_PROVIDER, "RustFS is the default, as instructed");
  assert.equal(sel.selection, "DEFAULT_PROVISIONAL", "and the machinery says what that is worth");
  assert.equal(sel.gate.state, "OPEN");
  assert.equal(sel.comparator, COMPARATOR_PROVIDER);
});

test("recording every required lane as pass is the ONLY way to reach GREEN", () => {
  const file = newLedger();
  assert.equal(evaluateGate({ file }).state, "OPEN");
  recordAll(file);
  const gate = evaluateGate({ provider: DEFAULT_PROVIDER, binarySha256: DIGEST_A, file });
  assert.equal(gate.state, "GREEN");
  assert.deepEqual(gate.missing, []);
  for (const lane of REQUIRED_LANES) {
    assert.equal(gate.lanes[lane.id].status, "pass");
    assert.equal(gate.lanes[lane.id].binarySha256, DIGEST_A);
    assert.ok(gate.lanes[lane.id].lastRunAt);
  }
  const sel = resolveProvider({ env: {}, binarySha256: DIGEST_A, file });
  assert.equal(sel.selection, "DEFAULT_QUALIFIED");
});

test("one failed lane keeps the gate OPEN and reports the failure", () => {
  const file = newLedger();
  recordAll(file);
  recordLaneResult({
    lane: "multipart",
    provider: DEFAULT_PROVIDER,
    status: "fail",
    binarySha256: DIGEST_A,
    command: "pretend-runner --lane multipart",
    detail: "fallback path exceeded the RSS bound",
    file,
  });
  const gate = evaluateGate({ provider: DEFAULT_PROVIDER, binarySha256: DIGEST_A, file });
  assert.equal(gate.state, "OPEN");
  assert.deepEqual(gate.missing, ["multipart"]);
  assert.equal(gate.lanes.multipart.status, "fail");
  assert.match(gate.lanes.multipart.reason, /last run FAILED: fallback path exceeded the RSS bound/);
});

test("R6-EVID-01 binding: evidence for a different binary digest does not qualify this one", () => {
  const file = newLedger();
  recordAll(file, { binarySha256: DIGEST_B });
  // unbound view sees the runs...
  assert.equal(evaluateGate({ provider: DEFAULT_PROVIDER, file }).state, "GREEN");
  // ...but a run bound to digest A must not inherit digest B's evidence
  const bound = evaluateGate({ provider: DEFAULT_PROVIDER, binarySha256: DIGEST_A, file });
  assert.equal(bound.state, "OPEN");
  assert.deepEqual(bound.missing.sort(), REQUIRED_LANES.map((l) => l.id).sort());
});

test("evidence for one provider never qualifies another", () => {
  const file = newLedger();
  recordAll(file, { provider: COMPARATOR_PROVIDER });
  assert.equal(evaluateGate({ provider: COMPARATOR_PROVIDER, file }).state, "GREEN");
  assert.equal(evaluateGate({ provider: DEFAULT_PROVIDER, file }).state, "OPEN");
});

test("--require-qualified-provider turns a provisional default into a typed refusal", () => {
  const file = newLedger();
  assert.throws(
    () => resolveProvider({ env: {}, requireQualified: true, file }),
    (err) => {
      assert.equal(err.code, "PROVIDER_NOT_QUALIFIED");
      assert.equal(err.gate.state, "OPEN");
      assert.match(err.message, /lanes not passed in this session/);
      return true;
    },
  );
  recordAll(file);
  const sel = resolveProvider({ env: {}, requireQualified: true, file });
  assert.equal(sel.selection, "DEFAULT_QUALIFIED");
});

test("an explicit provider request wins and is labelled EXPLICIT", () => {
  const file = newLedger();
  const flag = resolveProvider({ requested: COMPARATOR_PROVIDER, env: {}, file });
  assert.equal(flag.provider, COMPARATOR_PROVIDER);
  assert.equal(flag.selection, "EXPLICIT");
  assert.equal(flag.requestedBy, "flag");
  // an explicit choice is honoured even when its gate is OPEN — the gate
  // grades the DEFAULT, it does not veto a deliberate comparator run
  assert.equal(flag.gate.state, "OPEN");

  const viaEnv = resolveProvider({ env: { S3_PROVIDER: COMPARATOR_PROVIDER }, file });
  assert.equal(viaEnv.provider, COMPARATOR_PROVIDER);
  assert.equal(viaEnv.selection, "EXPLICIT");
  assert.match(viaEnv.requestedBy, /S3_PROVIDER/);

  assert.throws(() => resolveProvider({ requested: "ceph", env: {}, file }), /unknown S3 provider/);
});

test("the ledger refuses junk: unknown lanes, unknown providers, non-binary statuses", () => {
  const file = newLedger();
  assert.throws(
    () => recordLaneResult({ lane: "vibes", provider: DEFAULT_PROVIDER, status: "pass", file }),
    /unknown lane/,
  );
  assert.throws(
    () => recordLaneResult({ lane: "u2s3", provider: "ceph", status: "pass", file }),
    /unknown provider/,
  );
  for (const status of ["mostly", "green", "PASS", true, null]) {
    assert.throws(
      () => recordLaneResult({ lane: "u2s3", provider: DEFAULT_PROVIDER, status, file }),
      /lane status must be "pass" or "fail"/,
      `status ${JSON.stringify(status)} must be refused`,
    );
  }
  assert.equal(readLedger(file).entries.length, 0, "nothing junk was written");
});

test("an unreadable or foreign ledger is NO evidence, never green evidence", () => {
  const file = newLedger();
  writeFileSync(file, "{ not json at all");
  assert.equal(readLedger(file).entries.length, 0);
  assert.equal(evaluateGate({ file }).state, "OPEN");

  // a file with the right shape but the wrong schema is also ignored
  writeFileSync(
    file,
    JSON.stringify({
      schema: "some-other-thing@1",
      entries: REQUIRED_LANES.map((l) => ({ lane: l.id, provider: DEFAULT_PROVIDER, status: "pass" })),
    }),
  );
  assert.equal(evaluateGate({ file }).state, "OPEN", "a foreign schema must not qualify anything");
});

test("recorded entries carry the evidence a later reader needs", () => {
  const file = newLedger();
  const entry = recordLaneResult({
    lane: "supervision",
    provider: DEFAULT_PROVIDER,
    status: "pass",
    binarySha256: DIGEST_A,
    command: "node cli.mjs up --s3-only && node cli.mjs down --verify-clean",
    detail: "TEARDOWN_CLEAN",
    file,
  });
  assert.equal(entry.lane, "supervision");
  assert.equal(entry.provider, DEFAULT_PROVIDER);
  assert.equal(entry.status, "pass");
  assert.equal(entry.binarySha256, DIGEST_A);
  assert.match(entry.command, /cli\.mjs/);
  assert.ok(Date.parse(entry.at) > 0, "each entry is timestamped");
  assert.equal(entry.pid, process.pid, "each entry records who produced it");
  const onDisk = JSON.parse(readFileSync(file, "utf8"));
  assert.equal(onDisk.schema, "typedb-r2-stack/lane-ledger@1");
  assert.equal(onDisk.entries.length, 1);
});
