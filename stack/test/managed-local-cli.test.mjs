// One command up, one verified command down — across REAL process
// boundaries (round-6 PR6 exit criterion).
//
// Every step here is a separate `node cli.mjs ...` invocation, because the
// thing R6-LOCAL-02 says is broken is precisely the boundary between
// invocations: the process that started the child is gone by the time the
// agent wants to stop it. In-process tests cannot see that failure.
//
// The teardown result must be TYPED (a schema and a code), not merely an
// exit status, and the second teardown must be a clean idempotent
// ALREADY_CLEAN rather than an error.

// R8-P0-03: CAPABILITY-REQUIRED. This suite drives real process supervision
// and/or local networking; on a host without loopback-bind it does not run
// and reports INFRASTRUCTURE (exit 3), never a pass and never a silent skip.
import { require_ as requireCapability } from "./capability.mjs";
await requireCapability("loopback-bind");

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const STACK_DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const CLI = path.join(STACK_DIR, "cli.mjs");

function cli(args, env, { timeout = 180_000 } = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: STACK_DIR,
    encoding: "utf8",
    timeout,
    env: { ...process.env, ...env },
  });
}

test("stack up --s3-only, then a SEPARATE invocation tears it down and verifies it", async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "cli-run-root-"));
  const ledger = path.join(mkdtempSync(path.join(os.tmpdir(), "cli-ledger-")), "ledger.json");
  const env = { STACK_RUN_ROOT: root, STACK_LANE_LEDGER: ledger };

  // ---- invocation 1: bring the topology up ------------------------------
  const up = cli(["up", "--s3-only", "--provider", "rustfs"], env);
  assert.equal(up.status, 0, `up failed:\n${up.stdout}\n${up.stderr}`);
  assert.match(up.stdout, /supervision mechanisms available:/);
  assert.match(up.stdout, /S3 provider rustfs \[EXPLICIT\]/);
  assert.match(up.stdout, /ready on http:\/\/127\.0\.0\.1:/);
  const runDir = readFileSync(path.join(root, "current-run"), "utf8").trim();
  const manifest = JSON.parse(readFileSync(path.join(runDir, "run.json"), "utf8"));
  assert.equal(manifest.mode, "native-s3-only");
  assert.equal(manifest.provider, "rustfs");
  // the manifest carries the STRUCTURED gate, so no reader can take the
  // default for a qualified default
  assert.equal(manifest.providerGate.schema, "typedb-r2-stack/provider-gate@1");
  assert.ok(["OPEN", "GREEN"].includes(manifest.providerGate.state));
  assert.equal(manifest.components.s3.credentials, undefined, "run.json must never carry credentials");
  assert.ok(existsSync(manifest.components.s3.credentialsFile));
  assert.equal(manifest.identity.s3Provider, "rustfs");
  assert.match(manifest.identity.s3BinarySha256, /^[0-9a-f]{64}$/);

  // ---- invocation 2: ask the OWNER what it holds ------------------------
  const status = cli(["status"], env, { timeout: 60_000 });
  assert.equal(status.status, 0, `status failed:\n${status.stdout}\n${status.stderr}`);
  const statusDoc = JSON.parse(status.stdout);
  assert.equal(statusDoc.components.s3.childAlive, true, "the child outlived the invocation that started it");
  if (manifest.components.s3.supervision.mechanism === "owner-socket") {
    assert.equal(statusDoc.components.s3.via, "owner-socket");
  }

  // ---- invocation 3: tear it down and VERIFY ---------------------------
  const down = cli(["down", "--verify-clean", "--json"], env, { timeout: 120_000 });
  assert.equal(down.status, 0, `down failed:\n${down.stdout}\n${down.stderr}`);
  const report = JSON.parse(down.stdout);
  assert.equal(report.schema, "typedb-r2-stack/stack-teardown@1");
  assert.equal(report.code, "TEARDOWN_CLEAN", JSON.stringify(report.problems));
  assert.equal(report.ok, true);
  assert.deepEqual(report.survivors, []);
  const s3 = report.components.find((c) => c.component === "s3");
  assert.ok(s3, "the S3 component is reported");
  assert.equal(s3.provider, "rustfs");
  for (const check of s3.checks) assert.equal(check.ok, true, `${check.name}: ${check.detail}`);
  for (const required of ["child-stopped", "port-released", "socket-removed", "nonce-revoked"]) {
    assert.ok(s3.checks.some((c) => c.name === required), `teardown must verify ${required}`);
  }
  // the report is also persisted for the run
  assert.equal(JSON.parse(readFileSync(path.join(runDir, "down.json"), "utf8")).code, "TEARDOWN_CLEAN");

  // ---- invocation 4: idempotent ----------------------------------------
  const again = cli(["down", "--verify-clean", "--json"], env, { timeout: 120_000 });
  assert.equal(again.status, 0, `second down failed:\n${again.stdout}\n${again.stderr}`);
  assert.equal(JSON.parse(again.stdout).code, "TEARDOWN_ALREADY_CLEAN");

  // ---- the supervision lane result was recorded because it RAN ---------
  const laneStatus = cli(["lane-status", "--json"], env, { timeout: 60_000 });
  const gate = JSON.parse(laneStatus.stdout);
  assert.equal(gate.lanes.supervision.status, "pass", "a real start/teardown cycle records the supervision lane");
  assert.equal(gate.lanes.supervision.binarySha256, manifest.identity.s3BinarySha256);
  // ...and nothing else was recorded, because nothing else ran
  for (const lane of ["u2s3", "fault", "recovery", "multipart", "evidence-binding"]) {
    assert.equal(gate.lanes[lane].status, "NOT_EXECUTED", `${lane} must not be claimed`);
  }
  assert.equal(gate.state, "OPEN", "one executed lane is not a green gate");
});

test("lane-status --require-green fails while the gate is open (and the plain report does not)", () => {
  const ledger = path.join(mkdtempSync(path.join(os.tmpdir(), "cli-ledger2-")), "ledger.json");
  const env = { STACK_LANE_LEDGER: ledger, STACK_RUN_ROOT: mkdtempSync(path.join(os.tmpdir(), "cli-root2-")) };
  const report = cli(["lane-status"], env, { timeout: 30_000 });
  assert.equal(report.status, 0, "reporting an open gate is a successful report");
  assert.match(report.stdout, /NOT_EXECUTED/);
  const strict = cli(["lane-status", "--require-green"], env, { timeout: 30_000 });
  assert.equal(strict.status, 1, "a consumer that requires a green gate must fail on an open one");
});

test("--require-qualified-provider refuses to start on an open gate (typed, nothing started)", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "cli-root3-"));
  const ledger = path.join(mkdtempSync(path.join(os.tmpdir(), "cli-ledger3-")), "ledger.json");
  const res = cli(["up", "--s3-only", "--require-qualified-provider"], {
    STACK_RUN_ROOT: root,
    STACK_LANE_LEDGER: ledger,
  });
  assert.equal(res.status, 1);
  assert.match(res.stderr, /PROVIDER_NOT_QUALIFIED/);
  assert.match(res.stderr, /lanes not passed in this session/);
  assert.equal(existsSync(path.join(root, "current-run")), false, "no run was started");
});

test("cli refuses to start anything when supervision is unsupported", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "cli-root4-"));
  const res = cli(["up", "--s3-only", "--provider", "rustfs"], {
    STACK_RUN_ROOT: root,
    STACK_LANE_LEDGER: path.join(mkdtempSync(path.join(os.tmpdir(), "cli-ledger4-")), "ledger.json"),
    // simulate a host with neither AF_UNIX nor a usable /proc
    STACK_SUPERVISION_FORCE_UNAVAILABLE: "socket,proc",
  });
  assert.equal(res.status, 1);
  assert.match(res.stderr, /SUPERVISION_UNSUPPORTED/);
  assert.match(res.stderr, /owner socket:/);
  assert.match(res.stderr, /\/proc identity:/);
  assert.equal(existsSync(path.join(root, "current-run")), false, "no run pointer was written");
});
