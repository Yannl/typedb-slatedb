/*
 * Shared `wrangler dev` supervisor for the E2E lanes: boots workerd on a
 * named config/port with per-run vars and an isolated persistence dir,
 * waits for /health, and guarantees teardown. Test-only plumbing - the
 * protocol under proof lives in the e2e drivers, not here.
 */

import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Start `wrangler dev --local` and resolve once GET /health answers.
 * Returns { baseUrl, stop } - stop() kills the process tree and removes
 * the per-run persistence directory.
 */
export async function startWranglerDev({ configPath, port, vars = {}, timeoutMs = 120_000 }) {
  const persistTo = mkdtempSync(join(tmpdir(), "typedb-e2e-wrangler-"));
  const args = [
    "wrangler", "dev", "--local",
    "-c", configPath,
    "--port", String(port),
    "--persist-to", persistTo,
  ];
  for (const [key, value] of Object.entries(vars)) args.push("--var", `${key}:${value}`);
  const child = spawn("npx", args, {
    cwd: new URL("..", import.meta.url).pathname,
    stdio: ["ignore", "pipe", "pipe"],
    // own process group so stop() can kill the whole npx->wrangler->workerd
    // tree; an orphaned workerd would otherwise hold the stdio pipes open
    // and keep the runner's event loop alive forever
    detached: true,
    env: { ...process.env, CI: "1", WRANGLER_SEND_METRICS: "false" },
  });
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { output += chunk; });

  const baseUrl = `http://127.0.0.1:${port}`;
  const stop = () => {
    try { process.kill(-child.pid, "SIGTERM"); } catch { /* already gone */ }
    try { child.kill("SIGTERM"); } catch { /* already gone */ }
    try { rmSync(persistTo, { recursive: true, force: true }); } catch { /* best effort */ }
  };

  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (child.exitCode !== null) {
      stop();
      throw new Error(`wrangler dev exited early (code ${child.exitCode})\n${output.slice(-4000)}`);
    }
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) break;
    } catch { /* not up yet */ }
    if (Date.now() > deadline) {
      stop();
      throw new Error(`wrangler dev did not become healthy within ${timeoutMs}ms\n${output.slice(-4000)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  return { baseUrl, stop };
}
