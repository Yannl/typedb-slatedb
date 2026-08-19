/*
 * R5-CF-01 mutants: the approval envelope is a SIGNED, BOUND, ONE-TIME
 * authorization artifact. Every mutant here is one of the audit's named
 * attacks: unsigned/foreign-signed/tampered envelopes, envelopes copied
 * across account/bucket/commit, expired windows, and run-id replay — each
 * must leave preflight RED with a precise reason.
 *
 * Run: node --experimental-strip-types --no-warnings --test probes/approval.test.ts
 */

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  computeProbesSourceRoot, consumedJournalPath, ENVELOPE_SCHEMA, isRunIdConsumed, markRunIdConsumed,
  signEnvelope, verifyEnvelopeSignature,
} from "./approval.ts";
import { runPreflight } from "./preflight.ts";

const PROBES_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(PROBES_DIR, "..", "..");
const HEAD = execFileSync("git", ["-C", REPO_ROOT, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const SOURCE_ROOT = computeProbesSourceRoot(PROBES_DIR, join(REPO_ROOT, "control-plane", "wrangler.probe-harness.toml"));

const owner = generateKeyPairSync("ed25519");
const OWNER_PRIVATE = owner.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const OWNER_PUBLIC = owner.publicKey.export({ type: "spki", format: "pem" }).toString();

const scratch = mkdtempSync(join(tmpdir(), "approval-test-"));
test.after(() => rmSync(scratch, { recursive: true, force: true }));

let runSeq = 0;
function draft(overrides: Record<string, unknown> = {}, bindingOverrides: Record<string, unknown> = {}) {
  runSeq += 1;
  const now = Date.now();
  return {
    schema: ENVELOPE_SCHEMA,
    approved_by: "test-owner",
    approved_at: new Date(now).toISOString(),
    valid_from: new Date(now - 60_000).toISOString(),
    valid_until: new Date(now + 3_600_000).toISOString(),
    binding: {
      release_commit: HEAD,
      probes_source_root: SOURCE_ROOT,
      cf_account_id: "acct",
      bucket: "typedb-probe-testnonce1",
      ownership_nonce: "testnonce1",
      run_id: `run-${process.pid}-${runSeq}`,
      ...bindingOverrides,
    },
    limits: {
      max_total_requests: 1000,
      max_total_bytes_written: 10_000_000,
      max_run_seconds: 900,
      max_probe_seconds: 60,
      max_request_seconds: 10,
      max_cost_usd_cents: 100,
      credential_ttl_seconds: 900,
    },
    ...overrides,
  };
}

function writeEnvelope(doc: object): string {
  const path = join(scratch, `env-${runSeq}-${Math.random().toString(36).slice(2)}.json`);
  writeFileSync(path, JSON.stringify(doc));
  return path;
}

/** A fully-populated real-mode env matching the default binding. */
function realEnv(overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    R2_ACCOUNT_ID: "acct",
    R2_ACCESS_KEY_ID: "AKIDDUMMYDUMMYDUMMY0",
    R2_SECRET_ACCESS_KEY: "dummy-secret-dummy-secret-dummy!",
    R2_PROBE_OWNERSHIP_NONCE: "testnonce1",
    R2_PROBE_BUCKET: "typedb-probe-testnonce1",
    CF_ACCOUNT_ID: "acct",
    CF_API_TOKEN: "dummy-admin-token-dummy-admin!",
    CF_RUNTIME_API_TOKEN: "dummy-runtime-token-dummy-run!",
    CF_PROBE_HARNESS_URL: "https://harness.example.com",
    CF_PROBE_HARNESS_TOKEN: "dummy-harness-token-dummy!",
    CF_PROBE_HARNESS_ALLOWED_HOSTS: "harness.example.com",
    PROBE_ENVELOPE_PUBLIC_KEY: OWNER_PUBLIC,
    ...overrides,
  };
}

function preflightWith(envelopeDoc: object, envOverrides: Record<string, string> = {}) {
  return runPreflight({ mode: "real", env: realEnv(envOverrides), envelopePath: writeEnvelope(envelopeDoc) });
}

function reasonsText(result: ReturnType<typeof runPreflight>): string {
  return result.reasons.map((r) => `${r.code}:${r.detail}`).join("\n");
}

// ---------------------------------------------------------------------------

test("a correctly signed, bound, unconsumed envelope is GREEN", () => {
  const result = preflightWith(signEnvelope(OWNER_PRIVATE, draft()));
  assert.equal(result.verdict, "GREEN", reasonsText(result));
  assert.ok(result.envelope !== null);
});

test("MUTANT: an unsigned (round-4 style) envelope grants nothing", () => {
  const result = preflightWith(draft()); // no signature at all
  assert.equal(result.verdict, "RED");
  assert.match(reasonsText(result), /signature/);
});

test("MUTANT: an envelope signed by a DIFFERENT key is refused", () => {
  const stranger = generateKeyPairSync("ed25519");
  const strangerPem = stranger.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const result = preflightWith(signEnvelope(strangerPem, draft()));
  assert.equal(result.verdict, "RED");
  assert.match(reasonsText(result), /does not verify under the trusted owner key/);
});

test("MUTANT: limits tampered AFTER signing are refused", () => {
  const signed = signEnvelope(OWNER_PRIVATE, draft()) as unknown as { limits: Record<string, number> };
  signed.limits.max_total_requests = 1_000_000_000;
  const result = preflightWith(signed as object);
  assert.equal(result.verdict, "RED");
  assert.match(reasonsText(result), /does not verify/);
});

test("MUTANT: envelope copied to another ACCOUNT is refused", () => {
  const result = preflightWith(signEnvelope(OWNER_PRIVATE, draft()), {
    CF_ACCOUNT_ID: "other-account",
    R2_ACCOUNT_ID: "other-account",
  });
  assert.equal(result.verdict, "RED");
  assert.match(reasonsText(result), /cf_account_id/);
});

test("MUTANT: envelope copied to another BUCKET is refused", () => {
  const result = preflightWith(signEnvelope(OWNER_PRIVATE, draft()), {
    R2_PROBE_BUCKET: "typedb-probe-testnonce1-other",
  });
  assert.equal(result.verdict, "RED");
  assert.match(reasonsText(result), /binding bucket/);
});

test("MUTANT: envelope signed for another COMMIT is refused", () => {
  const signed = signEnvelope(OWNER_PRIVATE, draft({}, { release_commit: "0".repeat(40) }));
  const result = preflightWith(signed);
  assert.equal(result.verdict, "RED");
  assert.match(reasonsText(result), /release_commit/);
});

test("MUTANT: envelope signed for a MODIFIED probes implementation is refused", () => {
  const signed = signEnvelope(OWNER_PRIVATE, draft({}, { probes_source_root: "f".repeat(64) }));
  const result = preflightWith(signed);
  assert.equal(result.verdict, "RED");
  assert.match(reasonsText(result), /probes_source_root/);
});

test("MUTANT: an EXPIRED envelope is refused", () => {
  const signed = signEnvelope(
    OWNER_PRIVATE,
    draft({ valid_until: new Date(Date.now() - 60_000).toISOString() }),
  );
  const result = preflightWith(signed);
  assert.equal(result.verdict, "RED");
  assert.match(reasonsText(result), /expired/);
});

test("MUTANT: a NOT-YET-VALID envelope is refused", () => {
  const signed = signEnvelope(
    OWNER_PRIVATE,
    draft({
      valid_from: new Date(Date.now() + 3_600_000).toISOString(),
      valid_until: new Date(Date.now() + 7_200_000).toISOString(),
    }),
  );
  const result = preflightWith(signed);
  assert.equal(result.verdict, "RED");
  assert.match(reasonsText(result), /not yet valid/);
});

test("MUTANT: a validity window longer than 7 days is refused", () => {
  const signed = signEnvelope(
    OWNER_PRIVATE,
    draft({ valid_until: new Date(Date.now() + 30 * 24 * 3_600_000).toISOString() }),
  );
  const result = preflightWith(signed);
  assert.equal(result.verdict, "RED");
  assert.match(reasonsText(result), /exceeds 7 days/);
});

test("MUTANT: a CONSUMED run id is refused (one-time use)", () => {
  const signed = signEnvelope(OWNER_PRIVATE, draft());
  const path = writeEnvelope(signed);
  markRunIdConsumed(path, signed.binding.run_id);
  assert.ok(isRunIdConsumed(path, signed.binding.run_id));
  const result = runPreflight({ mode: "real", env: realEnv(), envelopePath: path });
  assert.equal(result.verdict, "RED");
  assert.match(reasonsText(result), /already been consumed/);
  // double-consume throws — the journal is append-once per id
  assert.throws(() => markRunIdConsumed(path, signed.binding.run_id), /already consumed/);
});

test("MUTANT: a wrong credential TTL approval is refused", () => {
  const base = draft();
  (base.limits as Record<string, number>).credential_ttl_seconds = 3600;
  const result = preflightWith(signEnvelope(OWNER_PRIVATE, base));
  assert.equal(result.verdict, "RED");
  assert.match(reasonsText(result), /credential_ttl_seconds=3600/);
});

test("MUTANT: absent PROBE_ENVELOPE_PUBLIC_KEY means the file grants nothing", () => {
  const env = realEnv();
  delete env.PROBE_ENVELOPE_PUBLIC_KEY;
  const result = runPreflight({
    mode: "real",
    env,
    envelopePath: writeEnvelope(signEnvelope(OWNER_PRIVATE, draft())),
  });
  assert.equal(result.verdict, "RED");
  assert.match(reasonsText(result), /PROBE_ENVELOPE_PUBLIC_KEY absent/);
});

test("verifyEnvelopeSignature refuses unknown alg and non-object docs", () => {
  const signed = signEnvelope(OWNER_PRIVATE, draft()) as unknown as { signature: { alg: string } };
  signed.signature.alg = "HS256";
  assert.equal(verifyEnvelopeSignature(OWNER_PUBLIC, signed).ok, false);
  assert.equal(verifyEnvelopeSignature(OWNER_PUBLIC, "nope").ok, false);
  assert.equal(verifyEnvelopeSignature(OWNER_PUBLIC, null).ok, false);
});

test("consumed journal is a strict string array — garbage refuses, never guesses", () => {
  const signed = signEnvelope(OWNER_PRIVATE, draft());
  const path = writeEnvelope(signed);
  writeFileSync(consumedJournalPath(path), JSON.stringify({ nope: true }));
  const result = runPreflight({ mode: "real", env: realEnv(), envelopePath: path });
  assert.equal(result.verdict, "RED");
  assert.match(reasonsText(result), /consumed-run journal unreadable/);
});
