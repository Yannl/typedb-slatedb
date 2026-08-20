/*
 * R6-CF-01: the one-time claim is arbitrated by the KERNEL, not by a
 * read-then-write the caller can lose.
 *
 * The round-6 audit released 64 barrier-synchronised processes against one
 * signed run id and 41 of them acquired it, because the round-5 journal was
 * read → check → append → rename. Atomic rename prevents a torn file; it
 * does not make the transaction exclusive. This test spawns real processes
 * (threads would not exercise the same arbitration) and requires exactly
 * one acquisition, always.
 *
 * PROBE_CLAIM_RACE_PROCESSES raises the count for a deep run; the default
 * is CI-friendly. The property does not weaken with N — O_EXCL either
 * arbitrates or it does not — and 1000-process runs are recorded in the
 * round-6 response document.
 *
 * Run: node --experimental-strip-types --no-warnings --test probes/claim-concurrency.test.ts
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { setTimeout } from "node:timers/promises";

const PROBES_DIR = dirname(fileURLToPath(import.meta.url));
const CHILD = join(PROBES_DIR, "claim-race-child.mjs");
const PROCESSES = Number(process.env.PROBE_CLAIM_RACE_PROCESSES ?? 16);

test(`R6-CF-01: ${PROCESSES} barrier-released processes yield EXACTLY ONE claim`, async () => {
  const dir = mkdtempSync(join(tmpdir(), "claim-race-"));
  try {
    const envelope = join(dir, "envelope.json");
    writeFileSync(envelope, "{}");
    const identityFile = join(dir, "identity.json");
    writeFileSync(identityFile, JSON.stringify({
      runId: "run-concurrency-check",
      envelopeBodyDigest: "a".repeat(64),
      keyFingerprint: "b".repeat(16),
    }));
    const startFile = join(dir, "GO");
    const stateDir = join(dir, "state");

    const pending = Array.from({ length: PROCESSES }, () =>
      new Promise<number>((resolve) => {
        spawn(process.execPath,
          ["--experimental-strip-types", "--no-warnings", CHILD, envelope, identityFile, startFile, stateDir],
          { stdio: "ignore" },
        ).on("exit", (code) => resolve(code ?? -1));
      }));

    // Let every child finish loading and reach the barrier, THEN release
    // them together — that simultaneity is the whole point: without it the
    // processes serialise on startup jitter and the test proves nothing.
    await setTimeout(3_000);
    writeFileSync(startFile, "go");
    const exits = await Promise.all(pending);
    const acquired = exits.filter((c) => c === 0).length;
    const refused = exits.filter((c) => c === 3).length;
    const errored = exits.filter((c) => c !== 0 && c !== 3).length;
    assert.equal(errored, 0, `no child may error (saw ${errored})`);
    assert.equal(acquired, 1, `EXACTLY one process may acquire the claim (saw ${acquired})`);
    assert.equal(refused, PROCESSES - 1);

    // and the durable state holds exactly one claim record
    const claims = readdirSync(stateDir).filter((n) => n.endsWith(".claim.json"));
    assert.equal(claims.length, 1, `one durable claim file (saw ${claims.length})`);
    const record = JSON.parse(readFileSync(join(stateDir, claims[0]), "utf8")) as Record<string, unknown>;
    assert.equal(record.schema, "probe-run-claim/v1");
    assert.equal(record.run_id, "run-concurrency-check");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("R6-CF-01: the barrier child is released only by the start file", async () => {
  // Guards the test itself: if the child did not actually wait, the race
  // above would be serialised by process startup and prove nothing.
  const source = readFileSync(CHILD, "utf8");
  assert.match(source, /while \(!existsSync\(startFile\)\) \{/,
    "the race child must spin on the barrier, or the concurrency test is vacuous");
});
