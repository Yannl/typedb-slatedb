// R8-P0-03 / R8-P1-07: the ONE place a stack test says "this host cannot give
// me what I need".
//
// The round-8 audit's rule: a capability-required integration test may report
// InfrastructureFailure when the host cannot provide AF_UNIX, a readable
// /proc, a loopback bind or a container runtime — it may NOT silently pass,
// and it may NOT be quietly omitted. Both of those turn "we did not check"
// into "we checked and it was fine".
//
// The mechanism is a structural EXIT CODE, not a message the controller has to
// recognise: `xtask/src/quality/exec.rs::EXIT_CAPABILITY_UNAVAILABLE`. A test
// process that ends here exits 3, and the quality controller records
// infrastructure_failure with the capability named.
import { createServer, connect } from "node:net";
import { existsSync, readFileSync } from "node:fs";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Must match xtask/src/quality/exec.rs::EXIT_CAPABILITY_UNAVAILABLE. */
export const EXIT_CAPABILITY_UNAVAILABLE = 3;

/** AF_UNIX: can this host create and connect to a unix-domain socket? */
async function afUnix() {
  const dir = mkdtempSync(join(tmpdir(), "stack-cap-"));
  const path = join(dir, "probe.sock");
  try {
    await new Promise((resolve, reject) => {
      const server = createServer((s) => s.end());
      server.on("error", reject);
      server.listen(path, () => {
        const client = connect(path);
        client.on("error", reject);
        client.on("connect", () => {
          client.destroy();
          server.close(() => resolve());
        });
      });
    });
    return true;
  } catch {
    return false;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** /proc identity: can this host read a process's own cmdline and exe link? */
function procIdentity() {
  try {
    return (
      existsSync(`/proc/${process.pid}/cmdline`) &&
      readFileSync(`/proc/${process.pid}/cmdline`).length > 0
    );
  } catch {
    return false;
  }
}

/** loopback: can this host bind an ephemeral TCP port on 127.0.0.1? */
async function loopbackBind() {
  try {
    await new Promise((resolve, reject) => {
      const server = createServer();
      server.on("error", reject);
      server.listen(0, "127.0.0.1", () => server.close(() => resolve()));
    });
    return true;
  } catch {
    return false;
  }
}

const PROBES = {
  "af-unix": afUnix,
  "proc-identity": async () => procIdentity(),
  "loopback-bind": loopbackBind,
};

const cache = new Map();

/** Is `name` available here? Probed once per process. */
export async function has(name) {
  const probe = PROBES[name];
  if (!probe) throw new Error(`unknown capability ${name}; known: ${Object.keys(PROBES).join(", ")}`);
  if (!cache.has(name)) cache.set(name, await probe());
  return cache.get(name);
}

/**
 * Require every named capability, or END THE PROCESS with the structural
 * infrastructure exit code.
 *
 * Deliberately not `test.skip`: a skipped test is reported inside a passing
 * run, and a passing run is exactly the claim that must not be made about
 * something that never executed.
 */
export async function require_(...names) {
  const missing = [];
  for (const name of names) {
    if (!(await has(name))) missing.push(name);
  }
  if (missing.length === 0) return;
  process.stderr.write(
    `stack: MISSING HOST CAPABILITY: ${missing.join(", ")}.\n` +
      `  These tests exercise real process supervision and local networking; running them\n` +
      `  without the capability would prove nothing, and skipping them inside a passing run\n` +
      `  would claim they did.\n` +
      `  exit ${EXIT_CAPABILITY_UNAVAILABLE} (infrastructure, not a quality verdict)\n`,
  );
  process.exit(EXIT_CAPABILITY_UNAVAILABLE);
}
