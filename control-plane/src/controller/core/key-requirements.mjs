// R5-SEC-01: the SINGLE declaration of what the MANAGED runtime posture
// consumes — shared verbatim by the resolver (core/key-config.ts imports
// this module) and by the canonical stack graph checker
// (stack/wrangler-check.mjs imports it too), so the runtime's requirements
// and the graph's declaration cannot skew silently: the checker compares
// the graph's declared names against THIS list, and the construction test
// (managed-construction.test.ts) proves resolveKeyConfig boots from exactly
// the graph-declared names.
//
// Plain .mjs (with key-requirements.d.mts for TypeScript) because the stack
// tooling is dependency-free node that cannot import .ts at runtime.

/** Vars with FIXED committed values (posture selectors). */
export const MANAGED_FIXED_VARS = Object.freeze({
  CONTROLLER_KEY_PROFILE: "managed",
});

/** Vars whose VALUES are deployment-specific but NOT secret (public
 *  verification material + the environment name). Supplied at deploy time
 *  (`wrangler deploy --var` / the managed E2E boot script), never baked
 *  into the committed wrangler.toml. */
export const MANAGED_DEPLOYMENT_VARS = Object.freeze([
  "CONTROLLER_ENVIRONMENT",
  "CONTROLLER_CAPABILITY_PUBLIC_KEYS",
  "CONTROLLER_PROVISION_PUBLIC_KEYS",
]);

/** Secrets (`wrangler secret put`). Exactly one: the journal MAC key stays
 *  SYMMETRIC by design (R5-SEC-08 — its writer and verifier are the same
 *  DatabaseControllerDO, so an asymmetric journal key would add a private
 *  key to the runtime without removing any authority from it). */
export const MANAGED_SECRETS = Object.freeze([
  "CONTROLLER_JOURNAL_KEY",
]);

/** Every input name the managed resolver reads — the complete boot set. */
export const MANAGED_RUNTIME_INPUTS = Object.freeze([
  ...Object.keys(MANAGED_FIXED_VARS),
  ...MANAGED_DEPLOYMENT_VARS,
  ...MANAGED_SECRETS,
]);

/** RETIRED schema-v2 (symmetric HMAC) inputs. Their presence under the
 *  managed profile is a hard refusal: symmetric verifier material could
 *  mint (round-5 audit §2.3), so a deployment still carrying these names
 *  is running an obsolete provisioning play and must fail loudly at boot,
 *  not silently ignore them. */
export const RETIRED_MANAGED_INPUTS = Object.freeze([
  "CONTROLLER_CAPABILITY_KEY",
  "CONTROLLER_PROVISION_KEY",
  "CONTROLLER_ISSUER_SECRET",
]);
