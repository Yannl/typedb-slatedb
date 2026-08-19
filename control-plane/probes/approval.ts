/*
 * Signed owner approval envelope (round-5 R5-CF-01).
 *
 * The round-4 envelope was a plain JSON file: any process able to write a
 * file could "approve" a live run by claiming an `approved_by` string. The
 * audit's requirement is that the envelope be an AUTHORIZATION ARTIFACT:
 *
 *   - SIGNED (Ed25519) by the owner; the runner verifies against a public
 *     key delivered out-of-band (PROBE_ENVELOPE_PUBLIC_KEY in the runner's
 *     environment/deployment, never inside the envelope file — the file
 *     alone grants nothing);
 *   - BOUND to the exact run it authorizes: release commit, probes source
 *     root, Cloudflare account, disposable bucket, ownership nonce,
 *     credential TTL, and ONE run id;
 *   - TIME-BOXED (valid_from / valid_until) and ONE-TIME (a consumed-run
 *     journal refuses replay of the same run id).
 *
 * The signature covers the canonical JSON of the envelope WITHOUT its
 * `signature` field; canonicalisation is recursive key-sorted JSON, the
 * same rule the control-plane token layer uses, so an envelope cannot be
 * mutated into a differently-parsed twin with the same signature.
 *
 * Owner tooling: `sign-envelope.ts` (same directory) generates keypairs
 * and signs a reviewed draft. The verifier here shares no state with it
 * beyond the format.
 */

import { createHash, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";
import { existsSync, readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const ENVELOPE_SCHEMA = "probe-run-envelope/v2";

/** Binding fields the envelope must carry — each one names an aspect of
 *  the run that a copied/replayed envelope would get wrong. */
export interface EnvelopeBinding {
  /** exact commit the runner must be executing (git HEAD, 40-hex) */
  release_commit: string;
  /** sha256 root over the probes implementation (computeProbesSourceRoot) */
  probes_source_root: string;
  /** the Cloudflare account being spent against */
  cf_account_id: string;
  /** the exact disposable bucket name */
  bucket: string;
  /** the run ownership nonce (R2_PROBE_OWNERSHIP_NONCE) */
  ownership_nonce: string;
  /** ONE run id; consumed on first authority acquisition */
  run_id: string;
}

export interface SignedEnvelope {
  schema: typeof ENVELOPE_SCHEMA;
  approved_by: string;
  approved_at: string;
  valid_from: string;
  valid_until: string;
  binding: EnvelopeBinding;
  limits: Record<string, number>;
  signature: { alg: "Ed25519"; public_key_fingerprint: string; sig: string };
}

/** Recursive key-sorted canonical JSON (same rule as the token layer). */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
    case "boolean":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw new Error("canonicalJson: non-finite number");
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
      const record = value as Record<string, unknown>;
      return `{${Object.keys(record)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
        .join(",")}}`;
    }
    default:
      throw new Error(`canonicalJson: unsupported ${typeof value}`);
  }
}

function signableBody(doc: Record<string, unknown>): Buffer {
  const { signature: _ignored, ...rest } = doc;
  return Buffer.from(canonicalJson(rest), "utf8");
}

export function publicKeyFingerprint(publicKey: KeyObject): string {
  const spki = publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(spki).digest("hex").slice(0, 16);
}

/** Owner side: sign a reviewed draft (draft must NOT already carry a
 *  signature). Returns the completed envelope object. */
export function signEnvelope(privateKeyPem: string, draft: Record<string, unknown>): SignedEnvelope {
  if ("signature" in draft) throw new Error("draft already carries a signature — sign a clean draft");
  const key = createPrivateKey(privateKeyPem);
  const publicKey = createPublicKey(key);
  // (cast: under the workers-types + node type merge, node:crypto's sign
  // return type loses its Buffer identity — the runtime value is a Buffer)
  const sigBytes = edSign(null, signableBody(draft), key) as unknown as Uint8Array;
  const sig = Buffer.from(sigBytes);
  return {
    ...(draft as Omit<SignedEnvelope, "signature">),
    signature: {
      alg: "Ed25519",
      public_key_fingerprint: publicKeyFingerprint(publicKey),
      sig: sig.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
    },
  };
}

export type EnvelopeVerification =
  | { ok: true; envelope: SignedEnvelope }
  | { ok: false; reason: string };

/** Structural + cryptographic verification. Binding-vs-run comparison is
 *  the caller's job (checkEnvelopeBinding) — this proves the OWNER said
 *  exactly these bytes. */
export function verifyEnvelopeSignature(publicKeyPem: string, doc: unknown): EnvelopeVerification {
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    return { ok: false, reason: "envelope is not a JSON object" };
  }
  const d = doc as Record<string, unknown>;
  if (d.schema !== ENVELOPE_SCHEMA) {
    return { ok: false, reason: `envelope schema is ${JSON.stringify(d.schema)} — required ${ENVELOPE_SCHEMA} (unsigned v1 envelopes are no longer authorization artifacts)` };
  }
  const sig = d.signature;
  if (typeof sig !== "object" || sig === null || Array.isArray(sig)) {
    return { ok: false, reason: "envelope carries no signature object" };
  }
  const s = sig as Record<string, unknown>;
  if (s.alg !== "Ed25519") return { ok: false, reason: `unknown signature alg ${JSON.stringify(s.alg)}` };
  if (typeof s.sig !== "string") return { ok: false, reason: "signature.sig is not a string" };
  let publicKey: KeyObject;
  try {
    publicKey = createPublicKey(publicKeyPem);
  } catch (err) {
    return { ok: false, reason: `PROBE_ENVELOPE_PUBLIC_KEY does not parse as a public key: ${String(err)}` };
  }
  let sigBytes: Buffer;
  try {
    sigBytes = Buffer.from(s.sig, "base64url");
  } catch {
    return { ok: false, reason: "signature.sig is not base64url" };
  }
  let verified = false;
  try {
    verified = edVerify(null, signableBody(d), publicKey, sigBytes);
  } catch (err) {
    return { ok: false, reason: `signature verification errored: ${String(err)}` };
  }
  if (!verified) return { ok: false, reason: "envelope signature does not verify under the trusted owner key" };
  return { ok: true, envelope: d as unknown as SignedEnvelope };
}

/**
 * Root digest over the probes implementation: sha256 of the sorted
 * (relative-path, file-sha256) list of every probe source plus the harness
 * wrangler config. An envelope signed for one probe implementation cannot
 * authorize a modified one.
 */
export function computeProbesSourceRoot(probesDir: string, harnessConfigPath: string): string {
  const entries: Array<[string, string]> = [];
  for (const name of readdirSync(probesDir).sort()) {
    if (!name.endsWith(".ts") || name.endsWith(".test.ts")) continue;
    const digest = createHash("sha256").update(readFileSync(join(probesDir, name))).digest("hex");
    entries.push([name, digest]);
  }
  if (existsSync(harnessConfigPath)) {
    const digest = createHash("sha256").update(readFileSync(harnessConfigPath)).digest("hex");
    entries.push(["wrangler.probe-harness.toml", digest]);
  }
  const rollup = createHash("sha256");
  for (const [name, digest] of entries) rollup.update(`${name}\n${digest}\n`);
  return rollup.digest("hex");
}

/** Binding comparison against the ACTUAL run parameters. Every mismatch is
 *  its own precise reason — a copied envelope names exactly what it was
 *  copied across. */
export function checkEnvelopeBinding(
  envelope: SignedEnvelope,
  actual: {
    releaseCommit: string;
    probesSourceRoot: string;
    cfAccountId: string;
    bucket: string;
    ownershipNonce: string;
    nowMs: number;
  },
): string[] {
  const reasons: string[] = [];
  const b = envelope.binding;
  if (typeof b !== "object" || b === null) return ["envelope has no binding object"];
  const expectEq = (field: keyof EnvelopeBinding, want: string, label: string) => {
    if (b[field] !== want) {
      reasons.push(`envelope binding ${field}=${JSON.stringify(b[field])} does not name the actual ${label} (${JSON.stringify(want)})`);
    }
  };
  expectEq("release_commit", actual.releaseCommit, "release commit (git HEAD)");
  expectEq("probes_source_root", actual.probesSourceRoot, "probes source root");
  expectEq("cf_account_id", actual.cfAccountId, "Cloudflare account");
  expectEq("bucket", actual.bucket, "target bucket");
  expectEq("ownership_nonce", actual.ownershipNonce, "ownership nonce");
  if (typeof b.run_id !== "string" || b.run_id.length < 8) {
    reasons.push("envelope binding run_id absent or shorter than 8 chars");
  }
  const from = Date.parse(envelope.valid_from ?? "");
  const until = Date.parse(envelope.valid_until ?? "");
  if (Number.isNaN(from) || Number.isNaN(until)) {
    reasons.push("envelope valid_from/valid_until absent or not ISO timestamps");
  } else {
    if (actual.nowMs < from) reasons.push(`envelope is not yet valid (valid_from ${envelope.valid_from})`);
    if (actual.nowMs > until) reasons.push(`envelope expired (valid_until ${envelope.valid_until})`);
    if (until - from > 7 * 24 * 3600 * 1000) reasons.push("envelope validity window exceeds 7 days — approvals are short-lived");
  }
  return reasons;
}

// ---------------------------------------------------------------------------
// One-time use: a consumed-run journal beside the envelope. Append-only,
// atomic replace; the runner marks the run id consumed at the moment it
// acquires real authority, BEFORE the first spend.
// ---------------------------------------------------------------------------

export function consumedJournalPath(envelopePath: string): string {
  return `${envelopePath}.consumed.json`;
}

function readConsumed(path: string): string[] {
  if (!existsSync(path)) return [];
  const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(parsed) || !parsed.every((x) => typeof x === "string")) {
    throw new Error(`${path} is not a JSON string array — refusing to guess consumed state`);
  }
  return parsed;
}

export function isRunIdConsumed(envelopePath: string, runId: string): boolean {
  return readConsumed(consumedJournalPath(envelopePath)).includes(runId);
}

export function markRunIdConsumed(envelopePath: string, runId: string): void {
  const path = consumedJournalPath(envelopePath);
  const consumed = readConsumed(path);
  if (consumed.includes(runId)) {
    throw new Error(`run id ${runId} already consumed — an envelope authorizes exactly one run`);
  }
  consumed.push(runId);
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify(consumed, null, 1) + "\n");
  renameSync(tmp, path);
}
