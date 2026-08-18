/*
 * Q-24: fail-closed signing/capability key configuration.
 *
 * The rule (directive §12.5.1): production must fail closed when qualified
 * key configuration is absent, empty, malformed, or below policy — and
 * development fallback keys must be impossible to smuggle into a managed
 * deployment, including by configuring them EXPLICITLY.
 *
 * Two named profiles, selected by `CONTROLLER_KEY_PROFILE`:
 *
 *   "managed"    the production posture. Every key must be present, hex,
 *                at or above the minimum length, pairwise distinct, and not
 *                one of the known development constants. Anything else
 *                throws, which fails DO construction, which makes every
 *                route on that authority refuse. There is no downgrade
 *                path from inside the process.
 *
 *   "local-dev"  the L1 scaffolding posture. The loud dev constants are
 *                permitted (and are the default), so a fresh checkout runs
 *                `wrangler dev` with zero provisioning. The profile string
 *                itself is the tripwire: it is set in the DEV [vars] block
 *                of wrangler.toml, and the managed environment sets
 *                "managed", so a production deploy that somehow inherited
 *                the dev block still names itself dev in its own config.
 *
 * An UNSET profile resolves to "managed". That direction matters: the
 * failure mode of a lost variable must be refusal, not a silent fall back
 * to development keys.
 */

import { fromHex, utf8 } from "./journal-crypto.ts";

/** The known development constants. Centralised so "is this a dev key?" is
 *  a set-membership question, not a grep. */
export const DEV_JOURNAL_KEY = "dev-insecure-journal-key";
export const DEV_CAPABILITY_KEY = "dev-insecure-capability-key";
export const DEV_ISSUER_SECRET = "dev-insecure-issuer-secret";

/** Policy minima (managed profile). 32 bytes = 256-bit MAC keys; the issuer
 *  secret is a shared credential, not a MAC key, and gets a lower floor. */
export const MIN_KEY_BYTES = 32;
export const MIN_ISSUER_SECRET_BYTES = 16;

export interface KeyConfigEnv {
  CONTROLLER_KEY_PROFILE?: string;
  CONTROLLER_JOURNAL_KEY?: string;
  CONTROLLER_CAPABILITY_KEY?: string;
  CONTROLLER_ISSUER_SECRET?: string;
}

export interface ResolvedKeys {
  profile: "managed" | "local-dev";
  journalKey: Uint8Array;
  capabilityKey: Uint8Array;
  /** Credential the /capability issuance route requires (Q-02). Always
   *  present: even local-dev enforces it, so no configuration state exists
   *  in which issuance is anonymous. */
  issuerSecret: string;
}

export class KeyConfigError extends Error {
  constructor(message: string) {
    super(`KEY_CONFIG_INVALID: ${message}`);
    this.name = "KeyConfigError";
  }
}

function requireManagedKey(name: string, value: string | undefined, devConstant: string): Uint8Array {
  if (value === undefined || value === "") {
    throw new KeyConfigError(`${name} is required under the managed profile and is absent/empty`);
  }
  if (value === devConstant || value === hex(utf8(devConstant))) {
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

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function resolveKeyConfig(env: KeyConfigEnv): ResolvedKeys {
  const profile = env.CONTROLLER_KEY_PROFILE ?? "managed";
  if (profile !== "managed" && profile !== "local-dev") {
    throw new KeyConfigError(
      `CONTROLLER_KEY_PROFILE=${JSON.stringify(profile)} is not a known profile (managed | local-dev)`);
  }

  if (profile === "local-dev") {
    return {
      profile,
      journalKey: env.CONTROLLER_JOURNAL_KEY ? fromHex(env.CONTROLLER_JOURNAL_KEY) : utf8(DEV_JOURNAL_KEY),
      capabilityKey: env.CONTROLLER_CAPABILITY_KEY
        ? fromHex(env.CONTROLLER_CAPABILITY_KEY)
        : utf8(DEV_CAPABILITY_KEY),
      issuerSecret: env.CONTROLLER_ISSUER_SECRET ?? DEV_ISSUER_SECRET,
    };
  }

  const journalKey = requireManagedKey("CONTROLLER_JOURNAL_KEY", env.CONTROLLER_JOURNAL_KEY, DEV_JOURNAL_KEY);
  const capabilityKey = requireManagedKey(
    "CONTROLLER_CAPABILITY_KEY", env.CONTROLLER_CAPABILITY_KEY, DEV_CAPABILITY_KEY);
  if (hex(journalKey) === hex(capabilityKey)) {
    // one compromised surface must not hand over the other (F8 vs F9)
    throw new KeyConfigError("CONTROLLER_JOURNAL_KEY and CONTROLLER_CAPABILITY_KEY must be distinct");
  }
  const issuerSecret = env.CONTROLLER_ISSUER_SECRET;
  if (issuerSecret === undefined || issuerSecret === "" || issuerSecret === DEV_ISSUER_SECRET) {
    throw new KeyConfigError(
      "CONTROLLER_ISSUER_SECRET is required under the managed profile and must not be the development constant");
  }
  if (utf8(issuerSecret).length < MIN_ISSUER_SECRET_BYTES) {
    throw new KeyConfigError(
      `CONTROLLER_ISSUER_SECRET is below the ${MIN_ISSUER_SECRET_BYTES}-byte policy minimum`);
  }
  return { profile, journalKey, capabilityKey, issuerSecret };
}
