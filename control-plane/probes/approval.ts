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
 *   - TIME-BOXED (valid_from / valid_until) and ONE-TIME.
 *
 * ONE-TIME USE — round-6 R6-CF-01. The round-5 implementation was a JSON
 * array rewritten under read-check-append-rename. Atomic rename prevents a
 * TORN FILE; it does not make the read/modify/write EXCLUSIVE, so two
 * callers could both read an empty journal and both believe they held the
 * only authority (the round-6 audit released 64 barrier-synchronised
 * processes against one signed run id and 41 of them acquired it). The
 * claim is now an O_EXCL file creation — the kernel arbitrates, exactly
 * one caller can win — durably fsynced with its parent directory, keyed by
 * the digest of (schema, run id, envelope BODY, trusted key), so the claim
 * is bound to what the owner actually signed rather than to an
 * attacker-chosen run-id string.
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
import {
  closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync,
  statSync, writeFileSync, writeSync,
} from "node:fs";
import { dirname, join } from "node:path";

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
  // R6-CF-04: the displayed fingerprint is NOT covered by the signature, so
  // an attacker can set it to anything without breaking verification. It is
  // audit/rotation metadata, and metadata that lies is worse than metadata
  // that is absent — so it must equal the fingerprint DERIVED from the
  // trusted key we just verified against.
  const derived = publicKeyFingerprint(publicKey);
  if (s.public_key_fingerprint !== derived) {
    return {
      ok: false,
      reason: `envelope signature.public_key_fingerprint ${JSON.stringify(s.public_key_fingerprint)} does not `
        + `match the trusted verification key (${derived}) — the field is unsigned display metadata and must not lie`,
    };
  }
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
// One-time use (R6-CF-01): an ATOMIC, crash-durable claim.
//
// The kernel arbitrates, not the process: `open(O_CREAT|O_EXCL)` can succeed
// for exactly one caller no matter how many race. The claim record is then
// written and fsynced, and the PARENT DIRECTORY is fsynced too, so the claim
// survives a power loss rather than living only in the dentry cache.
//
// The claim is keyed by the digest of (schema, run id, the envelope BODY the
// owner signed, the trusted verification key) — not by the run-id string
// alone. Two different envelopes that both name one run id therefore cannot
// share a claim: the second is a typed BINDING CONFLICT, which is what an
// attacker-chosen run id would otherwise buy.
//
// State lives in its own 0700 directory, never beside a possibly read-only
// envelope in a deployment image.
// ---------------------------------------------------------------------------

/** Where claims live. Overridable so tests (and deployments with a
 *  read-only image) can place mutable state deliberately. */
export function claimStateDir(envelopePath: string, env: NodeJS.ProcessEnv = process.env): string {
  const override = env.PROBE_APPROVAL_STATE_DIR;
  if (typeof override === "string" && override.trim().length > 0) return override;
  return `${envelopePath}.claims.d`;
}

export interface ClaimIdentity {
  runId: string;
  /** canonical bytes of the signed body (without the signature object) */
  envelopeBodyDigest: string;
  /** fingerprint of the TRUSTED verification key, derived locally */
  keyFingerprint: string;
}

/** The identity a claim is bound to, derived from what was actually
 *  verified — never from caller-supplied display metadata. */
export function claimIdentity(envelope: SignedEnvelope, trustedPublicKeyPem: string): ClaimIdentity {
  const body = signableBody(envelope as unknown as Record<string, unknown>);
  return {
    runId: envelope.binding.run_id,
    envelopeBodyDigest: createHash("sha256").update(body).digest("hex"),
    keyFingerprint: publicKeyFingerprint(createPublicKey(trustedPublicKeyPem)),
  };
}

function claimFileName(identity: ClaimIdentity): string {
  const material = canonicalJson({
    schema: ENVELOPE_SCHEMA,
    run_id: identity.runId,
    envelope_body_sha256: identity.envelopeBodyDigest,
    key_fingerprint: identity.keyFingerprint,
  });
  return `${createHash("sha256").update(material).digest("hex")}.claim.json`;
}

export function claimPath(envelopePath: string, identity: ClaimIdentity,
                          env: NodeJS.ProcessEnv = process.env): string {
  return join(claimStateDir(envelopePath, env), claimFileName(identity));
}

/** Refuse a state directory an attacker could substitute or share:
 *  it must be a real directory (not a symlink), owned by us, and not
 *  group/world writable. */
function assertSafeStateDir(dir: string): void {
  const info = lstatSync(dir);
  if (info.isSymbolicLink()) {
    throw new Error(`approval state dir ${dir} is a symlink — refusing (claims must not be redirectable)`);
  }
  if (!info.isDirectory()) throw new Error(`approval state dir ${dir} is not a directory`);
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
    throw new Error(`approval state dir ${dir} is owned by uid ${info.uid}, not this process — refusing`);
  }
  if ((info.mode & 0o022) !== 0) {
    throw new Error(`approval state dir ${dir} is group/world writable (mode ${(info.mode & 0o777).toString(8)}) — refusing`);
  }
}

function fsyncDir(dir: string): void {
  // Directory fsync is how the NAME becomes durable; without it the claim
  // file's existence can be lost across a power failure while its contents
  // are safely on disk — exactly backwards from what we need.
  const fd = openSync(dir, "r");
  try {
    fsyncSync(fd);
  } catch {
    // some filesystems refuse directory fsync; the file fsync above still
    // stands and O_EXCL still arbitrated. Not fatal, deliberately silent.
  } finally {
    closeSync(fd);
  }
}

export interface ClaimRecord {
  schema: "probe-run-claim/v1";
  run_id: string;
  envelope_body_sha256: string;
  key_fingerprint: string;
  claimed_at: string;
  claimed_by_pid: number;
}

export type ClaimOutcome =
  | { ok: true; record: ClaimRecord }
  | { ok: false; error: "ALREADY_CLAIMED"; record: ClaimRecord | null }
  | { ok: false; error: "BINDING_CONFLICT"; detail: string }
  | { ok: false; error: "CLAIM_CORRUPT"; detail: string };

/**
 * Acquire the one-time claim. Exactly one caller can succeed, ever, for a
 * given (run id, signed body, trusted key). Called at the moment real
 * authority is acquired, BEFORE the first possible spend.
 */
export function acquireRunClaim(
  envelopePath: string, identity: ClaimIdentity, env: NodeJS.ProcessEnv = process.env,
): ClaimOutcome {
  const dir = claimStateDir(envelopePath, env);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  assertSafeStateDir(dir);

  // A DIFFERENT signed envelope naming the same run id must not be able to
  // reuse — or be blocked by — this one's claim. Scan for a claim with the
  // same run id but a different body/key binding first.
  const conflict = findBindingConflict(dir, identity);
  if (conflict !== null) return { ok: false, error: "BINDING_CONFLICT", detail: conflict };

  const path = claimPath(envelopePath, identity, env);
  const record: ClaimRecord = {
    schema: "probe-run-claim/v1",
    run_id: identity.runId,
    envelope_body_sha256: identity.envelopeBodyDigest,
    key_fingerprint: identity.keyFingerprint,
    claimed_at: new Date().toISOString(),
    claimed_by_pid: process.pid,
  };
  let fd: number;
  try {
    // THE arbitration point. O_EXCL is the whole safety property.
    fd = openSync(path, "wx", 0o600);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "EEXIST") {
      return { ok: false, error: "ALREADY_CLAIMED", record: readClaimOrNull(path) };
    }
    throw err;
  }
  try {
    writeSync(fd, canonicalJson(record as unknown as Record<string, unknown>) + "\n");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  fsyncDir(dir);
  return { ok: true, record };
}

function readClaimOrNull(path: string): ClaimRecord | null {
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (typeof parsed !== "object" || parsed === null) return null;
    const rec = parsed as Record<string, unknown>;
    if (rec.schema !== "probe-run-claim/v1") return null;
    return rec as unknown as ClaimRecord;
  } catch {
    return null;
  }
}

function findBindingConflict(dir: string, identity: ClaimIdentity): string | null {
  for (const name of readdirSync(dir)) {
    if (!name.endsWith(".claim.json")) continue;
    const existing = readClaimOrNull(join(dir, name));
    if (existing === null) {
      // A truncated or corrupt claim is NOT "absent": we cannot prove the
      // run was never authorized, so we fail closed.
      return `claim file ${name} is unreadable or malformed — refusing to assume the run was never claimed`;
    }
    if (existing.run_id !== identity.runId) continue;
    if (existing.envelope_body_sha256 !== identity.envelopeBodyDigest
        || existing.key_fingerprint !== identity.keyFingerprint) {
      return `run id ${identity.runId} is already claimed under a DIFFERENT signed envelope `
        + `(body ${existing.envelope_body_sha256.slice(0, 12)}… key ${existing.key_fingerprint}) — binding conflict`;
    }
  }
  return null;
}

/** Read-only: has this exact (run id, body, key) already been claimed?
 *  A corrupt claim answers TRUE — fail closed, never "absent". */
export function isRunClaimed(envelopePath: string, identity: ClaimIdentity,
                             env: NodeJS.ProcessEnv = process.env): boolean {
  const dir = claimStateDir(envelopePath, env);
  if (!existsSync(dir)) return false;
  const path = claimPath(envelopePath, identity, env);
  if (!existsSync(path)) {
    return findBindingConflict(dir, identity) !== null;
  }
  return true;
}
