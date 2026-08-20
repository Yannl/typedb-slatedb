/*
 * R6-CF-01 race child: one process attempting the one-time claim.
 *
 * Deliberately a separate PROCESS, not a thread: the defect this guards
 * against was a read-check-write that only real concurrent processes (and
 * the kernel's arbitration, or lack of it) can expose.
 *
 * Exit 0 = acquired the claim, 3 = correctly refused, 1 = anything else.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const [envelopePath, identityJson, startFile, stateDir] = process.argv.slice(2);
process.env.PROBE_APPROVAL_STATE_DIR = stateDir;
const { acquireRunClaim } = await import(join(dirname(fileURLToPath(import.meta.url)), "approval.ts"));
const identity = JSON.parse(readFileSync(identityJson, "utf8"));

// Barrier: wait until released, so every process is already loaded and
// enters its critical section at the same instant.
//
// Deliberately a SLEEPING wait, not a tight spin: at high process counts a
// busy-wait starves the very scheduler that has to release everyone at
// once (a 1000-process tight-spin run drove this machine's load average
// past 580 and made the race less simultaneous, not more). 1 ms of sleep
// is far below the window this test probes.
// BOUNDED: if the parent dies before releasing the barrier (or its temp
// directory disappears), an unbounded wait leaks a spinning process that
// outlives the test run — observed for real while building this. A child
// that is never released exits as an ERROR, which the test counts and
// fails on, rather than lingering.
const { setTimeout: sleep } = await import("node:timers/promises");
const deadline = Date.now() + 120_000;
while (!existsSync(startFile)) {
  if (Date.now() > deadline) process.exit(1);
  await sleep(1);
}

try {
  const outcome = acquireRunClaim(envelopePath, identity);
  process.exit(outcome.ok ? 0 : 3);
} catch {
  process.exit(1);
}
