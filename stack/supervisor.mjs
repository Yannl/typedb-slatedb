// Provider-neutral, owner-socket supervision (round-6 R6-LOCAL-02).
//
// PROBLEM (audit R6-LOCAL-02). The pre-round-6 supervisor authenticated a
// child at teardown time by re-discovering it: pid → /proc/<pid>/cmdline →
// /proc/<pid>/stat start ticks. That is the SAFE direction (it refuses
// instead of killing an unverifiable pid), but many LLM/container sandboxes
// restrict /proc, so a separate `down` invocation cannot clean up a run a
// previous invocation started. An agent is then permanently unable to
// release its own resources.
//
// DESIGN IMPLEMENTED HERE.
//
//   1. OWNER PROCESS. A long-lived supervisor (supervisor-owner.mjs) is the
//      real parent of the managed child. It holds the ChildProcess handle
//      for the whole life of the run, so `status` and `shutdown` never need
//      to re-discover anything: the owner knows its own child by handle and
//      observes its exit through the kernel's parent/child relationship.
//
//   2. 0600 UNIX SOCKET INSIDE THE 0700 RUN DIRECTORY. Control travels over
//      an AF_UNIX socket created inside the per-run 0700 directory and
//      chmod'ed to 0600. Filesystem permissions are the outer fence.
//
//   3. PER-RUN NONCE. Every control request must carry the exact per-run
//      nonce, stored 0600 next to the socket. Comparison is length-checked
//      and timing-safe. A request with a missing/short/wrong nonce is
//      refused with a typed NONCE_REFUSED error and the connection is
//      dropped. The nonce is the inner fence: it survives a host whose
//      abstract/filesystem socket permissions are weaker than expected.
//
//   4. PID + START-TIME FALLBACK IS KEPT, NOT DELETED. On a normal host
//      /proc identity is the STRONGER check (it proves the exact process),
//      so it stays: it is recorded at spawn, used when no owner socket is
//      available, and used as corroboration during teardown verification.
//
//   5. CAPABILITY PROBE BEFORE ANY CHILD. Both mechanisms are probed for
//      real (bind + connect + round-trip a byte; parse /proc/self/stat)
//      BEFORE a child is spawned. If neither works, startSupervised throws
//      a typed SUPERVISION_UNSUPPORTED error and NOTHING is started. There
//      is no blind-PID-signalling fallback, by construction.
//
//   6. SOCKET PATH LENGTH. sockaddr_un.sun_path is 108 bytes on Linux
//      (107 usable). That limit is checked explicitly; an over-long run
//      directory falls back to a short 0700 per-uid socket directory, and
//      if even that does not fit the error is typed (SOCKET_PATH_TOO_LONG)
//      rather than an EINVAL crash deep inside libuv.
//
// This module is provider-neutral: it supervises a {command, args, env}
// spawn spec with a caller-supplied readiness probe. s3-provider.mjs turns
// a source-locked S3 provider (MinIO / RustFS) into such a spec; cli.mjs
// uses the same code path for the Alchemy dev child.

import { spawn } from "node:child_process";
import { randomBytes, timingSafeEqual } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  rmdirSync,
  statSync,
  unlinkSync,
} from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  ensureRunRoot,
  portInUse,
  procStartTimeTicks,
  processAlive,
  verifyRecordedProcess,
  writeFileAtomic,
} from "./minio.mjs";

export const STACK_DIR = path.dirname(fileURLToPath(import.meta.url));
const OWNER_ENTRY = path.join(STACK_DIR, "supervisor-owner.mjs");

/** sockaddr_un.sun_path is 108 bytes on Linux; 107 usable + NUL. */
export const MAX_UNIX_SOCKET_PATH = 107;
/** Hard cap on a single control request, so a hostile peer cannot grow us. */
export const MAX_CONTROL_REQUEST_BYTES = 8192;
export const CONTROL_PROTOCOL = "typedb-r2-stack/control@1";
export const SUPERVISED_SCHEMA = "typedb-r2-stack/supervised@1";
export const TEARDOWN_SCHEMA = "typedb-r2-stack/teardown@1";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// typed errors
// ---------------------------------------------------------------------------

export class SupervisionUnsupportedError extends Error {
  constructor(message, probe) {
    super(message);
    this.name = "SupervisionUnsupportedError";
    this.code = "SUPERVISION_UNSUPPORTED";
    this.probe = probe;
  }
}

export class SocketPathTooLongError extends Error {
  constructor(message, detail) {
    super(message);
    this.name = "SocketPathTooLongError";
    this.code = "SOCKET_PATH_TOO_LONG";
    this.detail = detail;
  }
}

export class ControlRefusedError extends Error {
  constructor(message, code = "CONTROL_REFUSED") {
    super(message);
    this.name = "ControlRefusedError";
    this.code = code;
  }
}

export class ControlUnavailableError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = "ControlUnavailableError";
    this.code = "CONTROL_UNAVAILABLE";
    this.cause = cause;
  }
}

export class ReadinessTimeoutError extends Error {
  constructor(message) {
    super(message);
    this.name = "ReadinessTimeoutError";
    this.code = "READINESS_TIMEOUT";
  }
}

export class ChildExitedError extends Error {
  constructor(message) {
    super(message);
    this.name = "ChildExitedError";
    this.code = "CHILD_EXITED_BEFORE_READY";
  }
}

// ---------------------------------------------------------------------------
// nonce
// ---------------------------------------------------------------------------

/** 32 random bytes, hex. Long enough that guessing is not a threat model. */
export function generateNonce() {
  return randomBytes(32).toString("hex");
}

/**
 * Constant-time nonce comparison. Buffers of unequal length cannot go into
 * timingSafeEqual, so length is compared first — the length of a random
 * 64-char hex string is not a secret.
 */
export function nonceMatches(expected, got) {
  if (typeof expected !== "string" || typeof got !== "string") return false;
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(got, "utf8");
  if (a.length === 0 || a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export function noncePath(runDir, component) {
  return path.join(runDir, `${component}.nonce`);
}

export function writeNonce(runDir, component, nonce = generateNonce()) {
  const file = noncePath(runDir, component);
  writeFileAtomic(file, `${nonce}\n`, { mode: 0o600 });
  const mode = statSync(file).mode & 0o777;
  if (mode !== 0o600) {
    throw new Error(`control nonce ${file} is mode ${mode.toString(8)}, refusing (must be 0600)`);
  }
  return { nonce, file };
}

export function readNonce(runDir, component) {
  return readFileSync(noncePath(runDir, component), "utf8").trim();
}

// ---------------------------------------------------------------------------
// socket path resolution (explicit length handling)
// ---------------------------------------------------------------------------

function uidTag() {
  return typeof process.getuid === "function" ? String(process.getuid()) : "nouid";
}

/**
 * Where the control socket for `component` lives. Preference order:
 *   1. inside the 0700 run directory (the documented, auditable location);
 *   2. a short 0700 per-uid fallback directory when (1) would exceed
 *      sun_path — recorded in the manifest so teardown removes it too.
 * A path that fits nowhere is a typed refusal, never a crash.
 */
export function resolveSocketPath({ runDir, component, maxLen = MAX_UNIX_SOCKET_PATH }) {
  const primary = path.join(runDir, `${component}.sock`);
  if (Buffer.byteLength(primary, "utf8") <= maxLen) {
    return { socketPath: primary, fallbackDir: null, inRunDir: true };
  }
  const dir = path.join(os.tmpdir(), `tdbs-${uidTag()}`);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  const st = statSync(dir);
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  if (uid !== undefined && st.uid !== uid) {
    throw new SocketPathTooLongError(
      `socket fallback directory ${dir} is owned by uid ${st.uid}, not ${uid} — refusing`,
      { primary, dir },
    );
  }
  if ((statSync(dir).mode & 0o077) !== 0) {
    throw new SocketPathTooLongError(
      `socket fallback directory ${dir} is wider than 0700 — refusing`,
      { primary, dir },
    );
  }
  const fallback = path.join(dir, `${randomBytes(5).toString("hex")}.sock`);
  if (Buffer.byteLength(fallback, "utf8") > maxLen) {
    throw new SocketPathTooLongError(
      `no usable AF_UNIX path: run-dir path ${primary} (${Buffer.byteLength(primary)} bytes) and ` +
        `fallback ${fallback} (${Buffer.byteLength(fallback)} bytes) both exceed the ${maxLen}-byte ` +
        `sun_path limit — shorten TMPDIR or STACK_RUN_ROOT`,
      { primary, fallback, maxLen },
    );
  }
  return { socketPath: fallback, fallbackDir: dir, inRunDir: false };
}

// ---------------------------------------------------------------------------
// capability probe (runs BEFORE any child is started)
// ---------------------------------------------------------------------------

/**
 * Really bind an AF_UNIX socket in `dir`, connect to it, round-trip a byte
 * and unlink it. Nothing short of that proves the mechanism works: a host
 * can have net.Server and still refuse AF_UNIX binds (seccomp, noexec-ish
 * mounts, path length, read-only tmp).
 */
export async function probeUnixSocket(dir) {
  let probePath;
  try {
    probePath = path.join(dir, `.probe-${randomBytes(5).toString("hex")}.sock`);
    if (Buffer.byteLength(probePath, "utf8") > MAX_UNIX_SOCKET_PATH) {
      return {
        available: false,
        reason: `probe socket path ${probePath} exceeds the ${MAX_UNIX_SOCKET_PATH}-byte sun_path limit`,
      };
    }
    const server = net.createServer((sock) => {
      sock.on("data", (d) => sock.end(d));
    });
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(probePath, resolve);
    });
    try {
      const echoed = await new Promise((resolve, reject) => {
        const c = net.connect(probePath);
        const t = setTimeout(() => {
          c.destroy();
          reject(new Error("probe connect/echo timed out"));
        }, 3000);
        c.on("error", (e) => {
          clearTimeout(t);
          reject(e);
        });
        c.on("data", (d) => {
          clearTimeout(t);
          c.end();
          resolve(d.toString());
        });
        c.write("x");
      });
      if (echoed !== "x") {
        return { available: false, reason: `probe echo returned ${JSON.stringify(echoed)}` };
      }
    } finally {
      await new Promise((r) => server.close(r));
    }
    return { available: true, reason: "AF_UNIX bind + connect + echo succeeded" };
  } catch (err) {
    return { available: false, reason: `AF_UNIX probe failed: ${String(err.message ?? err)}` };
  } finally {
    try {
      if (probePath) unlinkSync(probePath);
    } catch {}
  }
}

/**
 * Can we establish process identity the /proc way? Requires BOTH a
 * parseable start time and a readable command line for our own pid — those
 * are exactly the two facts verifyRecordedProcess() needs.
 */
export function probeProcIdentity() {
  if (process.platform !== "linux") {
    // verifyRecordedProcess falls back to `ps` off-Linux; probe that.
    const check = verifyRecordedProcess({
      pid: process.pid,
      startTimeTicks: null,
      executable: process.execPath,
    });
    return check.ok
      ? { available: true, reason: "ps-based command-line identity available" }
      : { available: false, reason: `ps-based identity unavailable: ${check.reason}` };
  }
  const ticks = procStartTimeTicks(process.pid);
  if (!Number.isFinite(ticks)) {
    return { available: false, reason: "/proc/<pid>/stat start ticks unreadable or unparseable" };
  }
  let cmdline = null;
  try {
    cmdline = readFileSync(`/proc/${process.pid}/cmdline`, "utf8");
  } catch (err) {
    return { available: false, reason: `/proc/<pid>/cmdline unreadable: ${String(err.message ?? err)}` };
  }
  if (!cmdline || cmdline.replace(/\0/g, "").length === 0) {
    return { available: false, reason: "/proc/<pid>/cmdline is empty (restricted /proc)" };
  }
  return { available: true, reason: "/proc start ticks + cmdline readable" };
}

/**
 * Probe both supervision mechanisms. `forceUnavailable` (CLI/env/test) may
 * only ever REMOVE a mechanism — it can make the stack refuse to start, it
 * can never make it weaker. That asymmetry is what makes it safe to expose
 * as STACK_SUPERVISION_FORCE_UNAVAILABLE for restricted-host simulation.
 */
export async function probeSupervisionCapabilities({
  runDir,
  forceUnavailable = process.env.STACK_SUPERVISION_FORCE_UNAVAILABLE ?? "",
  socketProbe = probeUnixSocket,
  procProbe = probeProcIdentity,
} = {}) {
  const forced = new Set(
    String(forceUnavailable)
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );
  const socketOwner = forced.has("socket")
    ? { available: false, reason: "disabled by STACK_SUPERVISION_FORCE_UNAVAILABLE=socket" }
    : await socketProbe(runDir);
  const procIdentity = forced.has("proc")
    ? { available: false, reason: "disabled by STACK_SUPERVISION_FORCE_UNAVAILABLE=proc" }
    : procProbe();
  const mechanisms = [];
  if (socketOwner.available) mechanisms.push("owner-socket");
  if (procIdentity.available) mechanisms.push("proc-identity");
  return {
    schema: "typedb-r2-stack/supervision-probe@1",
    probedAt: new Date().toISOString(),
    socketOwner,
    procIdentity,
    mechanisms,
    // owner-socket first: it is the only mechanism that survives a
    // restricted /proc, and it does not depend on re-discovery at all
    preferred: mechanisms[0] ?? null,
    usable: mechanisms.length > 0,
  };
}

export function assertSupervisable(probe) {
  if (probe.usable) return probe;
  throw new SupervisionUnsupportedError(
    "SUPERVISION_UNSUPPORTED: neither supervision mechanism is available on this host — " +
      `owner socket: ${probe.socketOwner.reason}; /proc identity: ${probe.procIdentity.reason}. ` +
      "Refusing to start any child: without one of these, teardown could only signal a bare pid, " +
      "which this stack never does (R6-LOCAL-02).",
    probe,
  );
}

// ---------------------------------------------------------------------------
// control client
// ---------------------------------------------------------------------------

/**
 * One request, one response, one connection. Newline-delimited JSON.
 * Errors are typed: an owner that refuses the nonce is NONCE_REFUSED, an
 * absent/dead owner is CONTROL_UNAVAILABLE — the caller must be able to
 * tell "you are not allowed" from "there is nobody there".
 */
export function controlRequest({ socketPath, nonce, verb, payload = {}, timeoutMs = 15_000 }) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(socketPath);
    let buf = "";
    let settled = false;
    const finish = (fn, arg) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        sock.destroy();
      } catch {}
      fn(arg);
    };
    const timer = setTimeout(
      () => finish(reject, new ControlUnavailableError(`control request ${verb} timed out after ${timeoutMs}ms on ${socketPath}`)),
      timeoutMs,
    );
    sock.on("error", (err) =>
      finish(reject, new ControlUnavailableError(`control socket ${socketPath} unavailable: ${String(err.message ?? err)}`, err)),
    );
    sock.on("data", (d) => {
      buf += d.toString();
      const nl = buf.indexOf("\n");
      if (nl < 0) {
        if (buf.length > MAX_CONTROL_REQUEST_BYTES * 8) {
          finish(reject, new ControlUnavailableError("control response exceeded the size ceiling"));
        }
        return;
      }
      let msg;
      try {
        msg = JSON.parse(buf.slice(0, nl));
      } catch (err) {
        finish(reject, new ControlUnavailableError(`unparseable control response: ${String(err.message ?? err)}`));
        return;
      }
      if (msg.ok) finish(resolve, msg.result);
      else finish(reject, new ControlRefusedError(msg.error?.message ?? "control request refused", msg.error?.code ?? "CONTROL_REFUSED"));
    });
    sock.on("close", () => {
      if (!settled) finish(reject, new ControlUnavailableError(`control socket ${socketPath} closed without a response`));
    });
    sock.on("connect", () => {
      const req = `${JSON.stringify({ protocol: CONTROL_PROTOCOL, nonce, verb, payload })}\n`;
      if (Buffer.byteLength(req) > MAX_CONTROL_REQUEST_BYTES) {
        finish(reject, new ControlRefusedError("control request exceeds the size ceiling", "REQUEST_TOO_LARGE"));
        return;
      }
      sock.write(req);
    });
  });
}

// ---------------------------------------------------------------------------
// start
// ---------------------------------------------------------------------------

function ensureDir(dir, mode = 0o700) {
  mkdirSync(dir, { recursive: true, mode });
  chmodSync(dir, mode); // umask masks mkdir's mode bits
  return dir;
}

/**
 * Start `command args` under supervision and wait for `readiness()`.
 *
 * Returns { record, probe }. `record` is manifest material (no secrets:
 * the child env lives only in the 0600 owner config) and is everything a
 * LATER, SEPARATE process needs to stop the run.
 */
export async function startSupervised({
  runDir,
  component,
  command,
  args = [],
  env = {},
  cwd,
  logPath,
  readiness,
  readyTimeoutMs = 60_000,
  killTimeoutMs = 10_000,
  ownerLingerMs = 15 * 60_000,
  probe,
  port,
  extra = {},
}) {
  if (!runDir) throw new Error("startSupervised requires runDir");
  if (!component) throw new Error("startSupervised requires component");
  ensureDir(runDir, 0o700);
  const resolvedLog = logPath ?? path.join(runDir, `${component}.log`);

  // (5) capability probe FIRST — no child exists yet if this refuses
  const caps = probe ?? (await probeSupervisionCapabilities({ runDir }));
  assertSupervisable(caps);

  const startedAt = new Date().toISOString();
  if (caps.socketOwner.available) {
    return { record: await startViaOwner(), probe: caps };
  }
  return { record: await startDirect(), probe: caps };

  async function startViaOwner() {
    const { nonce } = writeNonce(runDir, component);
    const { socketPath, fallbackDir, inRunDir } = resolveSocketPath({ runDir, component });
    const ownerStatePath = path.join(runDir, `${component}.owner.json`);
    const ownerLogPath = path.join(runDir, `${component}.owner.log`);
    const ownerConfigPath = path.join(runDir, `${component}.owner-config.json`);
    for (const stale of [ownerStatePath, socketPath]) {
      try {
        unlinkSync(stale);
      } catch {}
    }
    // 0600: this file carries the child's env, which may hold per-run
    // credentials. The run manifest records its PATH, never its contents.
    writeFileAtomic(
      ownerConfigPath,
      `${JSON.stringify(
        {
          protocol: CONTROL_PROTOCOL,
          runDir,
          component,
          socketPath,
          noncePath: noncePath(runDir, component),
          ownerStatePath,
          killTimeoutMs,
          lingerMs: ownerLingerMs,
          child: { command, args, env, cwd: cwd ?? process.cwd(), logPath: resolvedLog },
        },
        null,
        2,
      )}\n`,
      { mode: 0o600 },
    );

    const ownerLogFd = openSync(ownerLogPath, "a", 0o600);
    let owner;
    try {
      owner = spawn(process.execPath, [OWNER_ENTRY, ownerConfigPath], {
        detached: true, // survives THIS process: that is the whole point
        stdio: ["ignore", ownerLogFd, ownerLogFd],
        env: { PATH: process.env.PATH, HOME: runDir, NODE_OPTIONS: "" },
      });
    } finally {
      closeSync(ownerLogFd);
    }
    owner.unref();
    const ownerStartTimeTicks = procStartTimeTicks(owner.pid);
    let ownerExit = null;
    owner.on("exit", (code, signal) => {
      ownerExit = { code, signal };
    });

    // wait for the owner to publish its state (it does so only AFTER the
    // child is spawned and the socket is bound+chmod'ed)
    const ownerDeadline = Date.now() + 30_000;
    let state = null;
    for (;;) {
      if (existsSync(ownerStatePath)) {
        try {
          state = JSON.parse(readFileSync(ownerStatePath, "utf8"));
          if (state.ready) break;
        } catch {} // partially visible file: retry (writeFileAtomic makes this rare)
      }
      if (ownerExit) {
        throw new Error(
          `supervisor owner exited before publishing state (code=${ownerExit.code} signal=${ownerExit.signal}); ` +
            `owner log: ${ownerLogPath}: ${tail(ownerLogPath)}`,
        );
      }
      if (Date.now() > ownerDeadline) {
        throw new Error(`supervisor owner did not publish state within 30s; owner log: ${ownerLogPath}: ${tail(ownerLogPath)}`);
      }
      await sleep(50);
    }

    const record = {
      schema: SUPERVISED_SCHEMA,
      component,
      mechanism: "owner-socket",
      fallbackMechanism: caps.procIdentity.available ? "proc-identity" : null,
      runDir,
      socketPath,
      socketInRunDir: inRunDir,
      socketFallbackDir: fallbackDir,
      noncePath: noncePath(runDir, component),
      ownerConfigPath,
      ownerLogPath,
      ownerStatePath,
      ownerPid: owner.pid,
      ownerPgid: owner.pid,
      ownerStartTimeTicks,
      ownerExecutable: process.execPath,
      pid: state.childPid,
      pgid: state.childPid,
      startTimeTicks: state.childStartTimeTicks,
      executable: command,
      args,
      logPath: resolvedLog,
      port,
      startedAt,
      ...extra,
    };

    await awaitReady({
      record,
      nonce,
      readiness,
      readyTimeoutMs,
      childStatus: async () => {
        try {
          return await controlRequest({ socketPath, nonce, verb: "status", timeoutMs: 5000 });
        } catch {
          return null;
        }
      },
      onFail: async () => {
        try {
          await controlRequest({ socketPath, nonce, verb: "shutdown", timeoutMs: killTimeoutMs + 5000 });
        } catch {}
      },
    });
    return record;
  }

  async function startDirect() {
    // fallback path for hosts WITHOUT AF_UNIX but WITH /proc identity: the
    // pre-round-6 behaviour, kept because on such a host it is sound.
    const logFd = openSync(resolvedLog, "a", 0o600);
    let child;
    try {
      child = spawn(command, args, {
        detached: true,
        stdio: ["ignore", logFd, logFd],
        env,
        cwd: cwd ?? process.cwd(),
      });
    } finally {
      closeSync(logFd);
    }
    child.unref();
    const startTimeTicks = procStartTimeTicks(child.pid);
    let exited = null;
    child.on("exit", (code, signal) => {
      exited = { code, signal };
    });
    const record = {
      schema: SUPERVISED_SCHEMA,
      component,
      mechanism: "proc-identity",
      fallbackMechanism: null,
      runDir,
      socketPath: null,
      noncePath: null,
      pid: child.pid,
      pgid: child.pid,
      startTimeTicks,
      executable: command,
      args,
      logPath: resolvedLog,
      port,
      startedAt,
      ...extra,
    };
    await awaitReady({
      record,
      readiness,
      readyTimeoutMs,
      childStatus: async () => (exited ? { childAlive: false, childExit: exited } : { childAlive: true }),
      onFail: async () => {
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {}
      },
    });
    return record;
  }
}

function tail(file, bytes = 2000) {
  try {
    return readFileSync(file, "utf8").slice(-bytes);
  } catch {
    return "<no log>";
  }
}

async function awaitReady({ record, readiness, readyTimeoutMs, childStatus, onFail }) {
  if (typeof readiness !== "function") return;
  const deadline = Date.now() + readyTimeoutMs;
  let lastErr = null;
  for (;;) {
    const st = await childStatus();
    if (st && st.childAlive === false) {
      await onFail();
      throw new ChildExitedError(
        `${record.component} exited before ready (code=${st.childExit?.code} signal=${st.childExit?.signal}); log: ${record.logPath}: ${tail(record.logPath, 800)}`,
      );
    }
    try {
      await readiness(record);
      return;
    } catch (err) {
      lastErr = err;
    }
    if (Date.now() > deadline) {
      await onFail();
      throw new ReadinessTimeoutError(
        `${record.component} not ready within ${readyTimeoutMs}ms: ${String(lastErr?.message ?? lastErr)}; log: ${record.logPath}: ${tail(record.logPath, 800)}`,
      );
    }
    await sleep(200);
  }
}

// ---------------------------------------------------------------------------
// status / stop / verified teardown
// ---------------------------------------------------------------------------

/** Ask the owner (never re-discovery) what it holds. */
export async function supervisedStatus(record, { nonce } = {}) {
  if (record.mechanism !== "owner-socket") {
    const check = verifyRecordedProcess({
      pid: record.pid,
      startTimeTicks: record.startTimeTicks,
      executable: record.executable,
    });
    return {
      via: "proc-identity",
      childAlive: check.alive,
      identityVerified: check.ok,
      reason: check.reason ?? null,
    };
  }
  const n = nonce ?? readNonce(record.runDir, record.component);
  const result = await controlRequest({ socketPath: record.socketPath, nonce: n, verb: "status" });
  return { via: "owner-socket", ...result };
}

/**
 * Stop a supervised component and VERIFY the teardown. Idempotent: a run
 * that is already down returns TEARDOWN_ALREADY_CLEAN rather than throwing
 * or, worse, signalling something.
 *
 * Returns a typed report — never a bare exit code.
 */
export async function stopSupervised(record, { killTimeoutMs = 10_000, nonce } = {}) {
  const checks = [];
  const problems = [];
  const add = (name, ok, detail) => {
    checks.push({ name, ok, detail: detail ?? null });
    if (!ok) problems.push(`${name}: ${detail}`);
  };

  let via = "none";
  let ownerReport = null;
  const socketExisted = Boolean(record.socketPath && existsSync(record.socketPath));

  if (record.mechanism === "owner-socket" && socketExisted) {
    let n = nonce;
    if (!n) {
      try {
        n = readNonce(record.runDir, record.component);
      } catch (err) {
        add("nonce-readable", false, `control nonce unreadable: ${String(err.message ?? err)}`);
      }
    }
    if (n) {
      try {
        ownerReport = await controlRequest({
          socketPath: record.socketPath,
          nonce: n,
          verb: "shutdown",
          payload: { killTimeoutMs },
          timeoutMs: killTimeoutMs + 15_000,
        });
        via = "owner-socket";
        add("owner-shutdown", ownerReport.childStopped === true, ownerReport.childStopped === true ? "owner reaped its child" : `owner reported ${JSON.stringify(ownerReport)}`);
      } catch (err) {
        if (err.code === "CONTROL_UNAVAILABLE") {
          via = "owner-gone";
          add("owner-shutdown", true, `owner already gone (${err.message})`);
        } else {
          add("owner-shutdown", false, `owner refused shutdown: ${err.code}: ${err.message}`);
        }
      }
    }
  } else if (record.mechanism === "owner-socket") {
    via = "owner-gone";
    add("owner-shutdown", true, "no control socket present — owner already exited");
  }

  // proc-identity path (fallback host, or corroboration after the owner)
  const identity = { pid: record.pid, startTimeTicks: record.startTimeTicks, executable: record.executable };
  const procUsable = probeProcIdentity().available;
  if (via === "none" || via === "owner-gone") {
    if (record.pid && processAlive(record.pid)) {
      const check = verifyRecordedProcess(identity);
      if (check.ok) {
        via = via === "none" ? "proc-identity" : `${via}+proc-identity`;
        try {
          process.kill(-(record.pgid ?? record.pid), "SIGTERM");
        } catch {}
        const deadline = Date.now() + killTimeoutMs;
        while (processAlive(record.pid) && Date.now() < deadline) await sleep(100);
        if (processAlive(record.pid) && verifyRecordedProcess(identity).ok) {
          try {
            process.kill(-(record.pgid ?? record.pid), "SIGKILL");
          } catch {}
          await sleep(500);
        }
      } else {
        // never signal an unverifiable pid — that is the rule that made the
        // old design safe, and it survives here unchanged
        add(
          "child-identity",
          false,
          `pid ${record.pid} is alive but unverifiable (${check.reason}) and no owner socket is available — refusing to signal it`,
        );
      }
    }
  }

  // ---- verification --------------------------------------------------
  const ownerSaysStopped = ownerReport?.childStopped === true;
  if (ownerSaysStopped) {
    add("child-stopped", true, `owner observed exit code=${ownerReport.childExit?.code} signal=${ownerReport.childExit?.signal}`);
  } else if (!record.pid) {
    add("child-stopped", true, "no child pid recorded");
  } else if (!processAlive(record.pid)) {
    add("child-stopped", true, `pid ${record.pid} is gone`);
  } else if (procUsable) {
    const check = verifyRecordedProcess(identity);
    add(
      "child-stopped",
      !check.ok,
      check.ok ? `pid ${record.pid} still alive and still identifies as ${record.executable}` : `pid ${record.pid} is now a different process (${check.reason}) — our child is gone`,
    );
  } else {
    add("child-stopped", false, `pid ${record.pid} is alive and this host offers neither owner report nor /proc identity`);
  }

  if (record.ownerPid) {
    const ownerDeadline = Date.now() + 5_000;
    while (processAlive(record.ownerPid) && Date.now() < ownerDeadline) await sleep(100);
    const ownerAlive = processAlive(record.ownerPid);
    const ownerIdentityOk = ownerAlive && procUsable
      ? verifyRecordedProcess({ pid: record.ownerPid, startTimeTicks: record.ownerStartTimeTicks, executable: record.ownerExecutable }).ok
      : ownerAlive;
    add("owner-stopped", !ownerIdentityOk, ownerIdentityOk ? `owner pid ${record.ownerPid} still running` : `owner pid ${record.ownerPid} gone`);
  }

  if (record.port) {
    const portDeadline = Date.now() + 5_000;
    while ((await portInUse(record.port)) && Date.now() < portDeadline) await sleep(100);
    const busy = await portInUse(record.port);
    add("port-released", !busy, busy ? `port ${record.port} still accepting connections` : `port ${record.port} released`);
  }

  // ---- run-directory release ------------------------------------------
  if (record.socketPath) {
    try {
      unlinkSync(record.socketPath);
    } catch {}
    add("socket-removed", !existsSync(record.socketPath), existsSync(record.socketPath) ? `socket ${record.socketPath} still present` : `socket ${record.socketPath} removed`);
  }
  for (const secret of [record.noncePath, record.ownerConfigPath]) {
    if (!secret) continue;
    try {
      unlinkSync(secret);
    } catch {}
  }
  if (record.noncePath) {
    add("nonce-revoked", !existsSync(record.noncePath), existsSync(record.noncePath) ? `nonce ${record.noncePath} still present` : "control nonce revoked");
  }
  if (record.socketFallbackDir) {
    try {
      rmdirSync(record.socketFallbackDir);
    } catch {} // non-empty means another run still owns it: not a problem
  }

  const alreadyClean = via === "owner-gone" && !socketExisted && (!record.pid || !processAlive(record.pid));
  const ok = problems.length === 0;
  return {
    schema: TEARDOWN_SCHEMA,
    component: record.component,
    code: ok ? (alreadyClean ? "TEARDOWN_ALREADY_CLEAN" : "TEARDOWN_CLEAN") : "TEARDOWN_INCOMPLETE",
    ok,
    via,
    pid: record.pid ?? null,
    ownerPid: record.ownerPid ?? null,
    port: record.port ?? null,
    stoppedAt: new Date().toISOString(),
    checks,
    problems,
  };
}

export { ensureRunRoot, portInUse, processAlive, verifyRecordedProcess, writeFileAtomic };
