/*
 * Q-24 / R5-SEC-01 / R5-SEC-03: fail-closed key configuration.
 *
 * The rule (directive §12.5.1): production must fail closed when qualified
 * key configuration is absent, empty, malformed, or below policy — and
 * development material must be impossible to smuggle into a managed
 * deployment, including by configuring it EXPLICITLY.
 *
 * Two named profiles, selected by `CONTROLLER_KEY_PROFILE`:
 *
 *   "managed"    the production posture. The runtime consumes EXACTLY the
 *                inputs declared in key-requirements.mjs (which the
 *                canonical stack graph re-declares and the graph checker
 *                cross-validates — R5-SEC-01):
 *
 *                  CONTROLLER_KEY_PROFILE            var   "managed"
 *                  CONTROLLER_ENVIRONMENT            var   deployment name
 *                  CONTROLLER_CAPABILITY_PUBLIC_KEYS var   Ed25519 keyring
 *                  CONTROLLER_PROVISION_PUBLIC_KEYS  var   Ed25519 keyring
 *                  CONTROLLER_JOURNAL_KEY            secret hex >= 32 bytes
 *
 *                Only PUBLIC verification keys reach the runtime: a managed
 *                worker/DO can verify capability and provision tokens but
 *                holds NO signing material of any kind (R5-SEC-03 — the
 *                private Ed25519 keys live with the issuer side). The
 *                journal key stays SYMMETRIC on purpose (R5-SEC-08): its
 *                writer and verifier are the same DatabaseControllerDO, so
 *                a signature would add a private key without removing any
 *                authority. Retired v2 HMAC inputs are refused by NAME.
 *                Anything invalid throws, which fails DO construction,
 *                which makes every route on that authority refuse. There
 *                is no downgrade path from inside the process.
 *
 *   "local-dev"  the L1 scaffolding posture. The loud committed INSECURE
 *                dev keypairs are used (and refused under managed exactly
 *                like the old dev constants), so a fresh checkout runs
 *                `wrangler dev` with zero provisioning. ONLY this profile
 *                resolves a capability SIGNING key into the runtime — the
 *                dev-lane /capability issuance route needs one; the
 *                provision signing seed is never resolved into any runtime
 *                (dev provisioning is minted by the test/e2e harness).
 *
 * An UNSET profile resolves to "managed". That direction matters: the
 * failure mode of a lost variable must be refusal, not a silent fall back
 * to development keys.
 *
 * Keyring var syntax (both scopes):
 *     "<kid>=<64 hex>[,!<kid>=<64 hex>]"
 * First entry = CURRENT key (new tokens are minted under its kid; never
 * retired). Optional second entry = PREVIOUS key for the rotation overlap
 * window; a leading "!" marks it RETIRED (recognized but refused with the
 * typed CAPABILITY_KID_RETIRED). kid syntax: "cap:<env>[/<slot>]" or
 * "prov:<env>[/<slot>]" and must name this deployment's own scope+env.
 */

import { bytesEqual, fromHex, hex, sha256, utf8 } from "./journal-crypto.ts";
import { pkcs8FromSeed } from "./ed25519.ts";
import { kidNamesScope, type VerificationKey, type VerificationKeyring } from "./capability.ts";
import {
  MANAGED_DEPLOYMENT_VARS, MANAGED_FIXED_VARS, MANAGED_RUNTIME_INPUTS, MANAGED_SECRETS,
  RETIRED_MANAGED_INPUTS,
} from "./key-requirements.mjs";

// Re-export the shared requirement lists so TypeScript consumers (tests,
// construction proofs) get them from the config module they exercise.
export { MANAGED_DEPLOYMENT_VARS, MANAGED_FIXED_VARS, MANAGED_RUNTIME_INPUTS, MANAGED_SECRETS, RETIRED_MANAGED_INPUTS };

/** The known development constants. Centralised so "is this dev material?"
 *  is a set-membership question, not a grep. */
export const DEV_JOURNAL_KEY = "dev-insecure-journal-key";
export const DEV_ISSUER_SECRET = "dev-insecure-issuer-secret";
/** R4 PR1: the local-dev environment name. Reserved: a managed deployment
 *  must name its own environment and may never claim this one. */
export const DEV_ENVIRONMENT = "local";

/*
 * R5-SEC-03 committed DEV-INSECURE Ed25519 keypairs (local-dev only).
 * Seeds are sha256 of loud strings; the public halves are precomputed and
 * PINNED here — key-config.test.ts re-derives them via WebCrypto and fails
 * on any transcription drift. A managed profile REFUSES these public keys
 * exactly as it refused the old dev HMAC constants.
 */
export const DEV_CAPABILITY_SIGNING_SEED_LABEL = "typedb-r2 DEV-INSECURE capability signing seed v3";
export const DEV_PROVISION_SIGNING_SEED_LABEL = "typedb-r2 DEV-INSECURE provision signing seed v3";
export const DEV_CAPABILITY_PUBLIC_KEY_HEX = "c65f92651a3ec9f70b12a8cd427addb8d5c407621a35b95f423f4b0572112319";
export const DEV_PROVISION_PUBLIC_KEY_HEX = "b5d190e5f8572021a7fec73ad77898c2637e77a6f24cf69626ae97a4c5d40e4d";
export const DEV_CAPABILITY_KID = `cap:${DEV_ENVIRONMENT}`;
export const DEV_PROVISION_KID = `prov:${DEV_ENVIRONMENT}`;

/** The dev capability SIGNING key (PKCS#8). Resolved into the runtime ONLY
 *  under the local-dev profile (the dev issuance route signs with it). */
export function devCapabilitySigningKey(): Uint8Array {
  return pkcs8FromSeed(sha256(utf8(DEV_CAPABILITY_SIGNING_SEED_LABEL)));
}

/** The dev provision SIGNING key (PKCS#8). NEVER resolved into any runtime
 *  — provisioning is minted by the harness/scripts (the "issuer side"),
 *  even in local-dev. Exported for tests and the local e2e drivers. */
export function devProvisionSigningKey(): Uint8Array {
  return pkcs8FromSeed(sha256(utf8(DEV_PROVISION_SIGNING_SEED_LABEL)));
}

/** Policy minima (managed profile). 32 bytes = 256-bit journal MAC key. */
export const MIN_KEY_BYTES = 32;

export interface KeyConfigEnv {
  CONTROLLER_KEY_PROFILE?: string;
  CONTROLLER_JOURNAL_KEY?: string;
  CONTROLLER_ENVIRONMENT?: string;
  CONTROLLER_CAPABILITY_PUBLIC_KEYS?: string;
  CONTROLLER_PROVISION_PUBLIC_KEYS?: string;
  /** local-dev only: the dev issuance route credential (Q-02). */
  CONTROLLER_ISSUER_SECRET?: string;
  /** RETIRED v2 HMAC inputs — refused by name under managed. */
  CONTROLLER_CAPABILITY_KEY?: string;
  CONTROLLER_PROVISION_KEY?: string;
}

export interface ResolvedKeys {
  profile: "managed" | "local-dev";
  /** Journal MAC key — SYMMETRIC by design (R5-SEC-08): writer = verifier
   *  = the same DatabaseControllerDO. */
  journalKey: Uint8Array;
  /** Ordinary-capability VERIFICATION keyring ("cap:<env>" scope). PUBLIC
   *  material only: verifying is possible, minting is not (R5-SEC-03). */
  capabilityKeyring: VerificationKeyring;
  /** PROVISION-scope verification keyring ("prov:<env>"): validates the
   *  internal provisioning capability that binds a controller DO to its
   *  registry record. Deliberately a distinct keypair. */
  provisionKeyring: VerificationKeyring;
  /** The environment this deployment serves; part of every token's binding
   *  and of the derived controller DO names. Managed requires an explicit
   *  normalized name; local-dev is always DEV_ENVIRONMENT. */
  environment: string;
  /** Credential the dev /capability issuance route requires (Q-02).
   *  LOCAL-DEV ONLY: the managed surface has no issuance route and its
   *  posture resolves no issuance credential at all. */
  issuerSecret?: string;
  /** The dev capability SIGNING key (PKCS#8). LOCAL-DEV ONLY: a managed
   *  runtime resolves NO private key, so in-worker minting is structurally
   *  impossible there (R5-SEC-03). */
  capabilitySigningKey?: Uint8Array;
}

export class KeyConfigError extends Error {
  constructor(message: string) {
    super(`KEY_CONFIG_INVALID: ${message}`);
    this.name = "KeyConfigError";
  }
}

function requireManagedJournalKey(value: string | undefined): Uint8Array {
  const name = "CONTROLLER_JOURNAL_KEY";
  if (value === undefined || value === "") {
    throw new KeyConfigError(`${name} is required under the managed profile and is absent/empty`);
  }
  if (value === DEV_JOURNAL_KEY || value === hex(utf8(DEV_JOURNAL_KEY))) {
    // an explicitly configured dev constant is refused, not merely
    // defaulted away: that is the smuggling path this module exists to cut
    throw new KeyConfigError(`${name} is a development constant; managed deployments must use provisioned keys`);
  }
  if (!/^[0-9a-fA-F]+$/.test(value) || value.length % 2 !== 0) {
    throw new KeyConfigError(`${name} is not hex-encoded key material`);
  }
  const bytes = fromHex(value.toLowerCase());
  if (bytes.length < MIN_KEY_BYTES) {
    throw new KeyConfigError(`${name} is ${bytes.length} bytes; policy minimum is ${MIN_KEY_BYTES}`);
  }
  return bytes;
}

const KEYRING_ENTRY = /^(!?)([a-z]+:[a-z0-9/-]+)=([0-9a-fA-F]+)$/;

/**
 * Parse one scope's verification keyring from its deployment var. Fail
 * closed on every malformation: wrong scope, foreign environment, retired
 * current key, more than two slots, duplicate kids, non-32-byte keys, and
 * the committed dev public keys are all refusals.
 */
export function parseVerificationKeyring(
  name: string, scope: "cap" | "prov", environment: string, text: string | undefined,
): VerificationKeyring {
  if (text === undefined || text.trim() === "") {
    throw new KeyConfigError(`${name} is required under the managed profile and is absent/empty`);
  }
  const entries = text.split(",").map((entry) => entry.trim());
  if (entries.length > 2) {
    throw new KeyConfigError(`${name} carries ${entries.length} keys; the rotation keyring is two slots (current + previous)`);
  }
  const keys: VerificationKey[] = [];
  for (const [index, entry] of entries.entries()) {
    const match = entry.match(KEYRING_ENTRY);
    if (!match) throw new KeyConfigError(`${name} entry ${index} is not "<kid>=<hex>" (optionally "!"-retired): ${JSON.stringify(entry)}`);
    const [, retiredMark, kid, keyHex] = match;
    if (!kidNamesScope(kid, scope, environment)) {
      throw new KeyConfigError(
        `${name} entry ${index} kid ${JSON.stringify(kid)} does not name this deployment's scope "${scope}:${environment}"`);
    }
    if (keyHex.length !== 64) {
      throw new KeyConfigError(`${name} entry ${index} public key must be 64 hex chars (raw Ed25519), got ${keyHex.length}`);
    }
    const lower = keyHex.toLowerCase();
    if (lower === DEV_CAPABILITY_PUBLIC_KEY_HEX || lower === DEV_PROVISION_PUBLIC_KEY_HEX) {
      throw new KeyConfigError(`${name} entry ${index} is a committed DEV-INSECURE public key; managed deployments must use provisioned keypairs`);
    }
    const retired = retiredMark === "!";
    if (index === 0 && retired) {
      throw new KeyConfigError(`${name} current key (slot 0) must not be retired — retire only the previous slot`);
    }
    if (keys.some((existing) => existing.kid === kid)) {
      throw new KeyConfigError(`${name} carries duplicate kid ${JSON.stringify(kid)}`);
    }
    keys.push({ kid, publicKey: fromHex(lower), retired });
  }
  return { scope, environment, keys };
}

export function resolveKeyConfig(env: KeyConfigEnv): ResolvedKeys {
  const profile = env.CONTROLLER_KEY_PROFILE ?? MANAGED_FIXED_VARS.CONTROLLER_KEY_PROFILE;
  if (profile !== "managed" && profile !== "local-dev") {
    throw new KeyConfigError(
      `CONTROLLER_KEY_PROFILE=${JSON.stringify(profile)} is not a known profile (managed | local-dev)`);
  }

  if (profile === "local-dev") {
    return {
      profile,
      journalKey: env.CONTROLLER_JOURNAL_KEY ? fromHex(env.CONTROLLER_JOURNAL_KEY) : utf8(DEV_JOURNAL_KEY),
      capabilityKeyring: {
        scope: "cap", environment: DEV_ENVIRONMENT,
        keys: [{ kid: DEV_CAPABILITY_KID, publicKey: fromHex(DEV_CAPABILITY_PUBLIC_KEY_HEX), retired: false }],
      },
      provisionKeyring: {
        scope: "prov", environment: DEV_ENVIRONMENT,
        keys: [{ kid: DEV_PROVISION_KID, publicKey: fromHex(DEV_PROVISION_PUBLIC_KEY_HEX), retired: false }],
      },
      // local-dev is ALWAYS the reserved dev environment: a dev stack cannot
      // dress up as a managed environment by exporting a variable
      environment: DEV_ENVIRONMENT,
      issuerSecret: env.CONTROLLER_ISSUER_SECRET ?? DEV_ISSUER_SECRET,
      capabilitySigningKey: devCapabilitySigningKey(),
    };
  }

  // --- managed: consume EXACTLY the declared inputs, refuse retired ones ---
  // The name list is the SHARED declaration (key-requirements.mjs) the
  // graph checker also enforces — presence is checked from the list itself
  // so resolver and declaration cannot skew (R5-SEC-01).
  const envRecord = env as Record<string, string | undefined>;
  for (const name of RETIRED_MANAGED_INPUTS) {
    if (envRecord[name] !== undefined) {
      throw new KeyConfigError(
        `${name} is a RETIRED symmetric (schema-v2 HMAC) input; the managed runtime holds only public`
        + ` verification keys (R5-SEC-03) — remove it and provision the asymmetric inputs instead`);
    }
  }
  for (const name of MANAGED_RUNTIME_INPUTS) {
    // the profile selector itself may be absent: unset ALREADY resolved to
    // managed above - refusal here would turn the fail-closed default into
    // a fail-broken one (the graph still declares the var explicitly)
    if (name === "CONTROLLER_KEY_PROFILE") continue;
    if (envRecord[name] === undefined || envRecord[name] === "") {
      throw new KeyConfigError(`${name} is required under the managed profile and is absent/empty`);
    }
  }
  const environment = env.CONTROLLER_ENVIRONMENT;
  if (environment === undefined || !/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(environment)) {
    throw new KeyConfigError(
      "CONTROLLER_ENVIRONMENT is required under the managed profile: a normalized bounded name" +
      " (lowercase alphanumerics/hyphens, max 64 chars)");
  }
  if (environment === DEV_ENVIRONMENT) {
    throw new KeyConfigError(
      `CONTROLLER_ENVIRONMENT=${JSON.stringify(environment)} is the reserved local-dev environment`);
  }
  const journalKey = requireManagedJournalKey(env.CONTROLLER_JOURNAL_KEY);
  const capabilityKeyring = parseVerificationKeyring(
    "CONTROLLER_CAPABILITY_PUBLIC_KEYS", "cap", environment, env.CONTROLLER_CAPABILITY_PUBLIC_KEYS);
  const provisionKeyring = parseVerificationKeyring(
    "CONTROLLER_PROVISION_PUBLIC_KEYS", "prov", environment, env.CONTROLLER_PROVISION_PUBLIC_KEYS);
  // blast-radius separation: the two scopes must not share key material
  // (one compromised... key pair must not hand over the other power), and
  // the SECRET journal key must not equal any PUBLIC key (that would mean
  // the journal key is published).
  for (const capKey of capabilityKeyring.keys) {
    for (const provKey of provisionKeyring.keys) {
      if (bytesEqual(capKey.publicKey, provKey.publicKey)) {
        throw new KeyConfigError(
          "CONTROLLER_CAPABILITY_PUBLIC_KEYS and CONTROLLER_PROVISION_PUBLIC_KEYS must be distinct keypairs");
      }
    }
  }
  for (const anyKey of [...capabilityKeyring.keys, ...provisionKeyring.keys]) {
    if (bytesEqual(anyKey.publicKey, journalKey)) {
      throw new KeyConfigError("CONTROLLER_JOURNAL_KEY equals a published verification key — it is not secret");
    }
  }
  // deliberately NO issuerSecret and NO signing key: the managed runtime
  // can verify, and can do nothing else (R5-SEC-03)
  return { profile, journalKey, capabilityKeyring, provisionKeyring, environment };
}
