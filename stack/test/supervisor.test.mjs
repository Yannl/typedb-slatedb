// Owner-socket supervision (round-6 R6-LOCAL-02).
//
// What these tests must actually establish, in order of how badly the
// audit needs them:
//
//   1. a control request WITHOUT the exact per-run nonce is refused, and
//      refused with a typed code — a socket you can talk to anonymously is
//      not an authentication boundary;
//   2. when BOTH mechanisms are probed unavailable, startSupervised refuses
//      with SUPERVISION_UNSUPPORTED and NO CHILD IS STARTED. This is
//      simulated for real (the probe is forced to report unavailable), not
//      skipped, because "we would refuse on such a host" is a claim about
//      code that has never run;
//   3. teardown is VERIFIED (child gone, owner gone, port released, socket
//      removed, nonce revoked) and idempotent, with a typed report;
//   4. the whole cycle survives a process boundary: one invocation starts,
//      a DIFFERENT invocation stops. That is the workflow that is broken
//      without an owner;
//   5. a live pid that cannot be positively identified is never signalled.

// R8-P0-03: CAPABILITY-REQUIRED. This suite drives real process supervision
// and/or local networking; on a host without af-unix, proc-identity, loopback-bind it does not run
// and reports INFRASTRUCTURE (exit 3), never a pass and never a silent skip.
import { require_ as requireCapability } from "./capability.mjs";
await requireCapability("af-unix", "proc-identity", "loopback-bind");

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, statSync } from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  MAX_UNIX_SOCKET_PATH,
  controlRequest,
  nonceMatches,
  probeProcIdentity,
  probeSupervisionCapabilities,
  probeUnixSocket,
  processAlive,
  readNonce,
  resolveSocketPath,
  startSupervised,
  stopSupervised,
  supervisedStatus,
} from "../supervisor.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = path.join(HERE, "fixtures", "start-supervised.mjs");

function newRunDir(tag = "sup-") {
  const dir = path.join(mkdtempSync(path.join(os.tmpdir(), tag)), "run-1");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

function freePort() {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

/** A trivial long-lived child: a loopback listener that answers "ok". */
function bannerChildArgs(port) {
  return [
    "-e",
    `const net=require("node:net");net.createServer(c=>c.end("ok\\n")).listen(${port},"127.0.0.1");setInterval(()=>{},1<<30);`,
  ];
}

function bannerReadiness(port) {
  return () =>
    new Promise((resolve, reject) => {
      const c = net.connect({ port, host: "127.0.0.1" });
      const t = setTimeout(() => {
        c.destroy();
        reject(new Error("timeout"));
      }, 1000);
      c.on("error", (e) => {
        clearTimeout(t);
        reject(e);
      });
      c.on("data", (d) => {
        clearTimeout(t);
        c.destroy();
        d.toString().includes("ok") ? resolve() : reject(new Error("bad banner"));
      });
    });
}

async function startBanner(runDir, { component = "fixture", forceUnavailable } = {}) {
  const port = await freePort();
  const probe = await probeSupervisionCapabilities({ runDir, forceUnavailable });
  const { record } = await startSupervised({
    runDir,
    component,
    command: process.execPath,
    args: bannerChildArgs(port),
    env: { PATH: process.env.PATH },
    readiness: bannerReadiness(port),
    readyTimeoutMs: 20_000,
    port,
    probe,
  });
  return { record, port, probe };
}

// ---------------------------------------------------------------------------

test("capability probe really exercises both mechanisms", async () => {
  const dir = newRunDir("sup-probe-");
  const sock = await probeUnixSocket(dir);
  const proc = probeProcIdentity();
  // These assertions describe THIS host. Both are expected to work in a
  // normal Linux container; if one does not, the probe must still return a
  // structured reason rather than throwing.
  assert.equal(typeof sock.available, "boolean");
  assert.ok(sock.reason.length > 0);
  assert.equal(typeof proc.available, "boolean");
  assert.ok(proc.reason.length > 0);

  const caps = await probeSupervisionCapabilities({ runDir: dir });
  assert.equal(caps.usable, caps.mechanisms.length > 0);
  if (caps.socketOwner.available) {
    assert.equal(caps.preferred, "owner-socket", "owner-socket must be preferred when available");
  }
});

test("R6-LOCAL-02: SUPERVISION_UNSUPPORTED is raised BEFORE any child is started", async (t) => {
  const runDir = newRunDir("sup-unsup-");
  const marker = path.join(runDir, "child-ran");
  const prev = process.env.STACK_SUPERVISION_FORCE_UNAVAILABLE;
  // simulate a host with neither AF_UNIX nor a readable /proc
  process.env.STACK_SUPERVISION_FORCE_UNAVAILABLE = "socket,proc";
  t.after(() => {
    if (prev === undefined) delete process.env.STACK_SUPERVISION_FORCE_UNAVAILABLE;
    else process.env.STACK_SUPERVISION_FORCE_UNAVAILABLE = prev;
  });

  const err = await startSupervised({
    runDir,
    component: "must-not-start",
    command: process.execPath,
    // if this ever runs, it leaves proof behind
    args: ["-e", `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "ran");setInterval(()=>{},1<<30);`],
    env: { PATH: process.env.PATH },
    readiness: async () => {},
  }).then(
    () => null,
    (e) => e,
  );

  assert.ok(err, "startSupervised must reject");
  assert.equal(err.code, "SUPERVISION_UNSUPPORTED");
  assert.equal(err.name, "SupervisionUnsupportedError");
  assert.match(err.message, /neither supervision mechanism/);
  // both reasons must be reported, not just the first
  assert.match(err.message, /owner socket:/);
  assert.match(err.message, /\/proc identity:/);
  // THE point of the test: nothing was started
  assert.equal(existsSync(marker), false, "no child may be spawned when supervision is unsupported");
  assert.equal(existsSync(path.join(runDir, "must-not-start.owner.json")), false);
  assert.equal(existsSync(path.join(runDir, "must-not-start.nonce")), false);
});

test("owner-socket: status and shutdown go through the OWNER, not pid re-discovery", async (t) => {
  const runDir = newRunDir("sup-owner-");
  const { record, probe } = await startBanner(runDir);
  t.after(async () => {
    await stopSupervised(record).catch(() => {});
  });
  if (!probe.socketOwner.available) {
    assert.fail("this host cannot bind AF_UNIX; the owner path cannot be exercised here");
  }
  assert.equal(record.mechanism, "owner-socket");
  assert.ok(record.ownerPid && record.ownerPid !== record.pid, "owner is a separate process from the child");
  assert.ok(record.socketInRunDir, "control socket lives inside the 0700 run dir");

  // 0600 socket inside a 0700 directory; 0600 nonce
  assert.equal(statSync(record.socketPath).mode & 0o777, 0o600, "control socket must be 0600");
  assert.equal(statSync(runDir).mode & 0o777, 0o700, "run dir must be 0700");
  assert.equal(statSync(record.noncePath).mode & 0o777, 0o600, "nonce file must be 0600");

  const status = await supervisedStatus(record);
  assert.equal(status.via, "owner-socket");
  assert.equal(status.childAlive, true);
  assert.equal(status.childPid, record.pid);
  assert.equal(status.ownerPid, record.ownerPid);
});

test("R6-LOCAL-02: control refuses a wrong, missing, short and truncated nonce", async (t) => {
  const runDir = newRunDir("sup-nonce-");
  const { record, probe } = await startBanner(runDir);
  t.after(async () => {
    await stopSupervised(record).catch(() => {});
  });
  if (!probe.socketOwner.available) assert.fail("AF_UNIX unavailable on this host");
  const good = readNonce(runDir, record.component);
  assert.equal(good.length, 64, "nonce is 32 random bytes, hex");

  const bad = [
    ["wrong nonce of the same length", "f".repeat(64)],
    ["missing nonce", undefined],
    ["empty nonce", ""],
    ["truncated correct nonce", good.slice(0, 63)],
    ["correct nonce plus a byte", `${good}0`],
  ];
  for (const [name, nonce] of bad) {
    const err = await controlRequest({ socketPath: record.socketPath, nonce, verb: "status", timeoutMs: 5000 }).then(
      () => null,
      (e) => e,
    );
    assert.ok(err, `${name} must be refused`);
    assert.equal(err.code, "NONCE_REFUSED", `${name}: expected NONCE_REFUSED, got ${err.code}: ${err.message}`);
  }
  // even `shutdown` — the destructive verb — is refused without the nonce
  const shutdownErr = await controlRequest({
    socketPath: record.socketPath,
    nonce: "0".repeat(64),
    verb: "shutdown",
    timeoutMs: 5000,
  }).then(
    () => null,
    (e) => e,
  );
  assert.equal(shutdownErr.code, "NONCE_REFUSED");
  // and the child is untouched by the refused shutdown
  const after = await supervisedStatus(record);
  assert.equal(after.childAlive, true, "a refused shutdown must not stop the child");

  // the correct nonce still works (the refusals were about the nonce, not
  // about a broken socket)
  const ok = await controlRequest({ socketPath: record.socketPath, nonce: good, verb: "ping" });
  assert.equal(ok.ownerPid, record.ownerPid);
});

test("nonceMatches is length-checked and constant-time-safe", () => {
  const n = "a".repeat(64);
  assert.equal(nonceMatches(n, n), true);
  assert.equal(nonceMatches(n, `${n}x`), false);
  assert.equal(nonceMatches(n, n.slice(0, 63)), false);
  assert.equal(nonceMatches(n, undefined), false);
  assert.equal(nonceMatches("", ""), false, "an empty nonce can never match");
  assert.equal(nonceMatches(n, "b".repeat(64)), false);
});

test("unknown verbs and non-protocol requests are refused (still nonce-first)", async (t) => {
  const runDir = newRunDir("sup-verb-");
  const { record, probe } = await startBanner(runDir);
  t.after(async () => {
    await stopSupervised(record).catch(() => {});
  });
  if (!probe.socketOwner.available) assert.fail("AF_UNIX unavailable on this host");
  const nonce = readNonce(runDir, record.component);
  const unknown = await controlRequest({ socketPath: record.socketPath, nonce, verb: "rm-rf" }).then(
    () => null,
    (e) => e,
  );
  assert.equal(unknown.code, "UNKNOWN_VERB");

  // a request with a valid nonce but the wrong protocol tag is refused
  // BEFORE the verb is considered
  const badProto = await new Promise((resolve) => {
    const c = net.connect(record.socketPath);
    let buf = "";
    c.on("data", (d) => {
      buf += d.toString();
      if (buf.includes("\n")) {
        c.destroy();
        resolve(JSON.parse(buf));
      }
    });
    c.on("connect", () => c.write(`${JSON.stringify({ protocol: "other@9", nonce, verb: "shutdown" })}\n`));
  });
  assert.equal(badProto.ok, false);
  assert.equal(badProto.error.code, "BAD_PROTOCOL");
});

test("teardown is verified, typed, and idempotent", async () => {
  const runDir = newRunDir("sup-down-");
  const { record, port } = await startBanner(runDir);
  assert.equal(processAlive(record.pid), true);

  const first = await stopSupervised(record);
  assert.equal(first.schema, "typedb-r2-stack/teardown@1");
  assert.equal(first.code, "TEARDOWN_CLEAN", JSON.stringify(first.problems));
  assert.equal(first.ok, true);
  assert.deepEqual(first.problems, []);

  const names = first.checks.map((c) => c.name);
  for (const required of ["child-stopped", "port-released", "socket-removed", "nonce-revoked"]) {
    assert.ok(names.includes(required), `teardown must verify ${required} (got ${names.join(", ")})`);
  }
  if (record.ownerPid) assert.ok(names.includes("owner-stopped"));
  for (const c of first.checks) assert.equal(c.ok, true, `${c.name}: ${c.detail}`);

  // the verification is REAL, not a recital of intentions
  assert.equal(processAlive(record.pid), false, "child process is gone");
  if (record.ownerPid) assert.equal(processAlive(record.ownerPid), false, "owner process is gone");
  if (record.socketPath) assert.equal(existsSync(record.socketPath), false, "control socket removed");
  assert.equal(existsSync(record.noncePath), false, "control nonce revoked");
  assert.equal(existsSync(record.ownerConfigPath), false, "owner config (carries child env) removed");
  await new Promise((r) => setTimeout(r, 200));
  const stillListening = await new Promise((resolve) => {
    const c = net.connect({ port, host: "127.0.0.1" });
    c.on("connect", () => {
      c.destroy();
      resolve(true);
    });
    c.on("error", () => resolve(false));
  });
  assert.equal(stillListening, false, "port released");

  // idempotent: a second teardown is a typed ALREADY_CLEAN, not an error
  const second = await stopSupervised(record);
  assert.equal(second.code, "TEARDOWN_ALREADY_CLEAN");
  assert.equal(second.ok, true);
  const third = await stopSupervised(record);
  assert.equal(third.code, "TEARDOWN_ALREADY_CLEAN");
});

test("R6-LOCAL-02: a run started in ANOTHER process invocation can be torn down here", async () => {
  // The failure this whole design exists to fix: `stack up` exits, and a
  // later, separate `stack down` must still be able to stop the child.
  const runDir = newRunDir("sup-xproc-");
  const port = await freePort();
  const started = spawnSync(process.execPath, [FIXTURE, runDir, String(port)], {
    encoding: "utf8",
    timeout: 60_000,
  });
  assert.equal(started.status, 0, `fixture failed: ${started.stderr}`);
  const record = JSON.parse(readFileSync(path.join(runDir, "record.json"), "utf8"));

  // the starting process is gone; the owner and child are not
  assert.equal(processAlive(record.pid), true, "child outlives the process that started it");
  if (record.mechanism === "owner-socket") {
    assert.equal(processAlive(record.ownerPid), true, "owner outlives the process that started it");
    const status = await supervisedStatus(record);
    assert.equal(status.via, "owner-socket");
    assert.equal(status.childAlive, true);
  }

  const report = await stopSupervised(record);
  assert.equal(report.code, "TEARDOWN_CLEAN", JSON.stringify(report.problems));
  assert.equal(processAlive(record.pid), false);
});

test("proc-identity fallback drives the SAME lifecycle when AF_UNIX is unavailable", async () => {
  // A normal host without AF_UNIX (or with it disabled) must still get a
  // working, verified start/stop — the /proc check is retained precisely
  // for this, and it is the STRONGER check where it works.
  const runDir = newRunDir("sup-procfb-");
  const { record, probe } = await startBanner(runDir, { forceUnavailable: "socket" });
  assert.equal(probe.socketOwner.available, false);
  assert.equal(record.mechanism, "proc-identity");
  assert.equal(record.socketPath, null);
  assert.equal(processAlive(record.pid), true);

  const status = await supervisedStatus(record);
  assert.equal(status.via, "proc-identity");
  assert.equal(status.identityVerified, true, status.reason);

  const report = await stopSupervised(record);
  assert.equal(report.code, "TEARDOWN_CLEAN", JSON.stringify(report.problems));
  assert.equal(report.via, "proc-identity");
  assert.equal(processAlive(record.pid), false);
});

test("a live pid that cannot be positively identified is NEVER signalled", async () => {
  // The old design's one genuinely good property: refuse rather than kill.
  // Point a proc-identity record at THIS test process but with the wrong
  // executable — teardown must report incomplete and leave us running.
  const record = {
    schema: "typedb-r2-stack/supervised@1",
    component: "impostor",
    mechanism: "proc-identity",
    runDir: newRunDir("sup-impostor-"),
    pid: process.pid,
    pgid: process.pid,
    startTimeTicks: 1, // deliberately wrong
    executable: "/nonexistent/definitely-not-node",
  };
  const report = await stopSupervised(record);
  assert.equal(report.code, "TEARDOWN_INCOMPLETE");
  assert.equal(report.ok, false);
  assert.ok(
    report.problems.some((p) => /refusing to signal|unverifiable/.test(p)),
    `expected a refusal, got ${JSON.stringify(report.problems)}`,
  );
  assert.equal(processAlive(process.pid), true, "we are still here");
});

test("socket path length is handled explicitly, not by crashing", () => {
  const runDir = newRunDir("sup-len-");
  // (a) normal: inside the run dir
  const normal = resolveSocketPath({ runDir, component: "s3" });
  assert.equal(normal.inRunDir, true);
  assert.ok(Buffer.byteLength(normal.socketPath) <= MAX_UNIX_SOCKET_PATH);

  // (b) run dir too long for sun_path: fall back to a short 0700 dir.
  // One byte under the primary path's own length is enough to force it and
  // still leave room for the short fallback.
  const forced = resolveSocketPath({
    runDir,
    component: "s3",
    maxLen: Buffer.byteLength(normal.socketPath) - 1,
  });
  assert.equal(forced.inRunDir, false);
  assert.ok(forced.fallbackDir, "a fallback directory is used");
  assert.equal(statSync(forced.fallbackDir).mode & 0o777, 0o700, "fallback dir must be 0700");

  // (c) nothing fits: typed refusal naming the limit, never an EINVAL crash
  assert.throws(
    () => resolveSocketPath({ runDir, component: "s3", maxLen: 1 }),
    (err) => {
      assert.equal(err.code, "SOCKET_PATH_TOO_LONG");
      assert.match(err.message, /sun_path limit/);
      return true;
    },
  );
});

test("an oversized control request is refused by size, before parsing", async (t) => {
  const runDir = newRunDir("sup-size-");
  const { record, probe } = await startBanner(runDir);
  t.after(async () => {
    await stopSupervised(record).catch(() => {});
  });
  if (!probe.socketOwner.available) assert.fail("AF_UNIX unavailable on this host");
  const nonce = readNonce(runDir, record.component);
  const reply = await new Promise((resolve) => {
    const c = net.connect(record.socketPath);
    let buf = "";
    c.on("data", (d) => {
      buf += d.toString();
      if (buf.includes("\n")) {
        c.destroy();
        resolve(JSON.parse(buf));
      }
    });
    c.on("error", () => resolve({ ok: false, error: { code: "SOCKET_ERROR" } }));
    c.on("connect", () => {
      c.write(`${JSON.stringify({ protocol: "typedb-r2-stack/control@1", nonce, verb: "status", payload: { pad: "A".repeat(20_000) } })}\n`);
    });
  });
  assert.equal(reply.ok, false);
  assert.equal(reply.error.code, "REQUEST_TOO_LARGE");
  // the child survived an oversized request
  assert.equal((await supervisedStatus(record)).childAlive, true);
});
