#!/usr/bin/env node
// The long-lived supervisor OWNER (round-6 R6-LOCAL-02).
//
//   node supervisor-owner.mjs <owner-config.json>
//
// This process is the real parent of one managed child. It is spawned
// detached by supervisor.mjs and deliberately OUTLIVES the command that
// started the run, because that is what makes agent-shaped workflows
// possible: `stack up` exits, the agent runs tests in other invocations,
// and a much later `stack down` still reaches a process that has held the
// child handle the whole time.
//
// Why an owner instead of re-discovery: the owner never has to ask "is pid
// 1234 still the process I started?". It holds the ChildProcess handle, so
// the kernel's parent/child relationship answers that question exactly —
// including on hosts where /proc is restricted and re-discovery is
// impossible. A recycled pid cannot be mistaken for the child because the
// owner never looks a pid up.
//
// Control surface: a 0600 AF_UNIX socket, one newline-delimited JSON
// request per connection, every request authenticated with the per-run
// nonce (timing-safe compare). Verbs: ping, status, shutdown.
//
// The owner exits (and unlinks its socket) when: shutdown is requested, it
// is signalled, or the child has been dead for `lingerMs` and nobody asked
// about it. In every exit path it makes a best effort to leave no orphan:
// the child's whole process group is signalled first.

import { spawn } from "node:child_process";
import { existsSync, openSync, closeSync, chmodSync, readFileSync, statSync, unlinkSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { procStartTimeTicks, writeFileAtomic } from "./minio.mjs";
import { CONTROL_PROTOCOL, MAX_CONTROL_REQUEST_BYTES, nonceMatches } from "./supervisor.mjs";

const configPath = process.argv[2];
if (!configPath) {
  console.error("usage: supervisor-owner.mjs <owner-config.json>");
  process.exit(2);
}

const log = (msg) => console.error(`[owner ${process.pid}] ${new Date().toISOString()} ${msg}`);

const config = JSON.parse(readFileSync(configPath, "utf8"));
const {
  component,
  socketPath,
  noncePath,
  ownerStatePath,
  child: childSpec,
  killTimeoutMs = 10_000,
  lingerMs = 15 * 60_000,
} = config;

// The nonce file must be 0600 and readable only by us; if the file the
// starter wrote has drifted, refuse rather than serve a weakly protected
// control surface.
const nonceMode = statSync(noncePath).mode & 0o777;
if (nonceMode !== 0o600) {
  log(`refusing: nonce file ${noncePath} is mode ${nonceMode.toString(8)}, must be 0600`);
  process.exit(3);
}
const NONCE = readFileSync(noncePath, "utf8").trim();
if (NONCE.length < 32) {
  log("refusing: control nonce is shorter than 32 characters");
  process.exit(3);
}

// ---------------------------------------------------------------------------
// child
// ---------------------------------------------------------------------------

const logFd = openSync(childSpec.logPath, "a", 0o600);
let child;
try {
  child = spawn(childSpec.command, childSpec.args ?? [], {
    detached: true, // its own process group → we can signal the whole tree
    stdio: ["ignore", logFd, logFd],
    env: childSpec.env ?? {},
    cwd: childSpec.cwd,
  });
} finally {
  closeSync(logFd);
}

const childStartTimeTicks = procStartTimeTicks(child.pid);
let childExit = null;
child.on("exit", (code, signal) => {
  childExit = { code, signal, at: new Date().toISOString() };
  log(`child ${child.pid} exited code=${code} signal=${signal}`);
  scheduleLinger();
});
child.on("error", (err) => {
  childExit = { code: null, signal: null, error: String(err.message ?? err), at: new Date().toISOString() };
  log(`child spawn error: ${err.message ?? err}`);
  scheduleLinger();
});

let lingerTimer = null;
function scheduleLinger() {
  if (lingerTimer) return;
  lingerTimer = setTimeout(() => {
    log(`child has been gone for ${lingerMs}ms and nobody asked — owner exiting`);
    cleanupAndExit(0);
  }, lingerMs);
  lingerTimer.unref?.();
}

function childAlive() {
  return childExit === null;
}

/** Signal the child's whole group, escalate, and wait for the real exit. */
async function stopChild(timeoutMs) {
  if (!childAlive()) return { childStopped: true, childExit };
  try {
    process.kill(-child.pid, "SIGTERM");
  } catch {
    try {
      child.kill("SIGTERM");
    } catch {}
  }
  const deadline = Date.now() + timeoutMs;
  while (childAlive() && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
  if (childAlive()) {
    log(`child ${child.pid} survived SIGTERM — escalating to SIGKILL`);
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch {
      try {
        child.kill("SIGKILL");
      } catch {}
    }
    const hard = Date.now() + 5_000;
    while (childAlive() && Date.now() < hard) await new Promise((r) => setTimeout(r, 50));
  }
  // childExit is set by the 'exit' handler: this is the AUTHORITATIVE
  // observation of the child's death — no pid lookup involved.
  return { childStopped: !childAlive(), childExit };
}

// ---------------------------------------------------------------------------
// control socket
// ---------------------------------------------------------------------------

function refuse(sock, code, message) {
  try {
    sock.end(`${JSON.stringify({ ok: false, error: { code, message } })}\n`);
  } catch {}
}

const server = net.createServer((sock) => {
  let buf = "";
  const timer = setTimeout(() => {
    refuse(sock, "REQUEST_TIMEOUT", "no complete request within 10s");
    sock.destroy();
  }, 10_000);
  sock.on("error", () => {});
  sock.on("data", async (d) => {
    buf += d.toString();
    if (Buffer.byteLength(buf) > MAX_CONTROL_REQUEST_BYTES) {
      clearTimeout(timer);
      refuse(sock, "REQUEST_TOO_LARGE", `request exceeded ${MAX_CONTROL_REQUEST_BYTES} bytes`);
      sock.destroy();
      return;
    }
    const nl = buf.indexOf("\n");
    if (nl < 0) return;
    clearTimeout(timer);
    const line = buf.slice(0, nl);
    buf = "";
    let req;
    try {
      req = JSON.parse(line);
    } catch {
      refuse(sock, "BAD_REQUEST", "request was not newline-terminated JSON");
      return;
    }
    if (req.protocol !== CONTROL_PROTOCOL) {
      refuse(sock, "BAD_PROTOCOL", `expected protocol ${CONTROL_PROTOCOL}`);
      return;
    }
    // AUTHENTICATION: exact nonce or nothing. No verb — not even `ping` —
    // is served without it, so an unauthenticated peer cannot even confirm
    // which component this socket belongs to.
    if (!nonceMatches(NONCE, req.nonce)) {
      log(`refused ${JSON.stringify(req.verb)}: nonce mismatch`);
      refuse(sock, "NONCE_REFUSED", "control nonce missing or incorrect");
      return;
    }
    if (lingerTimer) {
      clearTimeout(lingerTimer);
      lingerTimer = null;
      if (!childAlive()) scheduleLinger();
    }
    const reply = (result) => {
      try {
        sock.end(`${JSON.stringify({ ok: true, result })}\n`);
      } catch {}
    };
    switch (req.verb) {
      case "ping":
        reply({ protocol: CONTROL_PROTOCOL, component, ownerPid: process.pid });
        return;
      case "status":
        reply({
          component,
          ownerPid: process.pid,
          childPid: child.pid,
          childStartTimeTicks,
          childAlive: childAlive(),
          childExit,
          socketPath,
          logPath: childSpec.logPath,
          startedAt: startedAt,
        });
        return;
      case "shutdown": {
        const result = await stopChild(Number(req.payload?.killTimeoutMs ?? killTimeoutMs));
        reply({ component, ownerPid: process.pid, childPid: child.pid, ...result, shutdownAt: new Date().toISOString() });
        // give the reply a moment to flush, then release the socket
        setTimeout(() => cleanupAndExit(result.childStopped ? 0 : 1), 150);
        return;
      }
      default:
        refuse(sock, "UNKNOWN_VERB", `unknown verb ${JSON.stringify(req.verb)}`);
    }
  });
});

const startedAt = new Date().toISOString();

function cleanupAndExit(code) {
  try {
    server.close();
  } catch {}
  try {
    if (existsSync(socketPath)) unlinkSync(socketPath);
  } catch {}
  process.exit(code);
}

for (const sig of ["SIGTERM", "SIGINT", "SIGHUP"]) {
  process.on(sig, () => {
    log(`received ${sig} — stopping child and releasing socket`);
    stopChild(killTimeoutMs).finally(() => cleanupAndExit(0));
  });
}

// bind with a umask that makes the socket 0600 at creation time, then
// chmod + verify: the socket must never be even briefly group/other
// accessible in a shared /tmp.
const prevUmask = process.umask(0o177);
try {
  if (existsSync(socketPath)) unlinkSync(socketPath);
} catch {}
server.listen(socketPath, () => {
  process.umask(prevUmask);
  try {
    chmodSync(socketPath, 0o600);
  } catch {}
  const mode = statSync(socketPath).mode & 0o777;
  if (mode !== 0o600) {
    log(`refusing: control socket ${socketPath} is mode ${mode.toString(8)}, must be 0600`);
    stopChild(killTimeoutMs).finally(() => cleanupAndExit(4));
    return;
  }
  // publish ONLY after the child exists and the socket is bound+verified:
  // the starter waits for ready:true, so it never races the socket
  writeFileAtomic(
    ownerStatePath,
    `${JSON.stringify(
      {
        schema: "typedb-r2-stack/owner-state@1",
        ready: true,
        component,
        ownerPid: process.pid,
        ownerStartTimeTicks: procStartTimeTicks(process.pid),
        ownerExecutable: process.execPath,
        childPid: child.pid,
        childStartTimeTicks,
        socketPath,
        socketMode: "0600",
        logPath: childSpec.logPath,
        startedAt,
      },
      null,
      2,
    )}\n`,
    { mode: 0o600 },
  );
  log(`owning ${component} child pid ${child.pid}; control socket ${path.basename(socketPath)} ready`);
});
server.on("error", (err) => {
  process.umask(prevUmask);
  log(`control socket bind failed: ${err.message ?? err}`);
  stopChild(killTimeoutMs).finally(() => cleanupAndExit(5));
});
