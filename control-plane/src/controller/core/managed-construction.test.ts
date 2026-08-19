/*
 * R5-SEC-01 CONSTRUCTION TEST: the managed posture boots from EXACTLY the
 * inputs the canonical stack graph declares.
 *
 * The round-5 audit's behavioral proof was that resolveKeyConfig, fed the
 * graph-declared inputs, refused first on an undeclared provision key and
 * then on an undeclared environment — the canonical graph was not an
 * executable production specification. This test closes that class:
 *
 *   1. the declared names are read PROGRAMMATICALLY from
 *      stack/graph.data.mjs (managed posture graph) — nothing is added by
 *      hand; values are per-name placeholders (fresh keys/secrets);
 *   2. resolveKeyConfig accepts exactly that set (the boot succeeds);
 *   3. dropping EACH declared input in turn refuses (no input is
 *      decorative);
 *   4. the graph declaration and the runtime requirement list
 *      (key-requirements.mjs, consumed verbatim by resolveKeyConfig) are
 *      the SAME set — the graph checker (stack/wrangler-check.mjs)
 *      enforces this too, before deployment;
 *   5. R5-SEC-03 mutant: the COMPLETE managed environment (every var and
 *      secret a runtime compromise could steal) contains no minting
 *      ability — no signing key resolves, and every resolved byte string,
 *      abused as signing material, fails to produce a verifiable token.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  MANAGED_RUNTIME_INPUTS, resolveKeyConfig, type KeyConfigEnv,
} from "./key-config.ts";
import { hex } from "./journal-crypto.ts";
import { generateEd25519KeyPair } from "./ed25519.ts";
import { mintCapabilityToken } from "./issuer.ts";
import { verifyCapabilityToken, type CapabilityPayload } from "./capability.ts";

// The canonical graph — plain data .mjs shared with the stack tooling.
// @ts-ignore: dependency-free stack module; its shape is asserted below.
import { toGraph } from "../../../../stack/graph.data.mjs";

/** Compile-time proof that every managed input NAME is a real field of the
 *  runtime env shape (KeyConfigEnv is the exact surface database-controller
 *  and worker-entry pass through) — a typo'd declaration fails tsc. */
const MANAGED_ENV_SHAPE: KeyConfigEnv = {
  CONTROLLER_KEY_PROFILE: "managed",
  CONTROLLER_ENVIRONMENT: "shape-proof",
  CONTROLLER_CAPABILITY_PUBLIC_KEYS: "shape-proof",
  CONTROLLER_PROVISION_PUBLIC_KEYS: "shape-proof",
  CONTROLLER_JOURNAL_KEY: "shape-proof",
};
void MANAGED_ENV_SHAPE;

interface ManagedGraphWorker {
  vars: Record<string, string>;
  deploymentVars: string[];
  secretSchema: string[];
}

const graph = toGraph("cloudflare-real") as { securityPosture: string; worker: ManagedGraphWorker };

// this run's "deployment": fresh issuer keypairs; the PRIVATE halves stay
// in this variable — they are exactly what the managed environment does NOT
// contain, which the minting mutant below depends on
const ENV_NAME = "managed-e2e";
const CAP_PAIR = await generateEd25519KeyPair();
const PROV_PAIR = await generateEd25519KeyPair();

/** Placeholder VALUE for one declared input name — a pure name->value map,
 *  so the NAME SET itself comes only from the graph. */
function placeholderValue(name: string): string {
  switch (name) {
    case "CONTROLLER_ENVIRONMENT": return ENV_NAME;
    case "CONTROLLER_CAPABILITY_PUBLIC_KEYS": return `cap:${ENV_NAME}/1=${hex(CAP_PAIR.publicKey)}`;
    case "CONTROLLER_PROVISION_PUBLIC_KEYS": return `prov:${ENV_NAME}/1=${hex(PROV_PAIR.publicKey)}`;
    case "CONTROLLER_JOURNAL_KEY": return hex(new Uint8Array(randomBytes(32)));
    default:
      throw new Error(`no placeholder rule for declared input ${name} — extend the graph AND this map together`);
  }
}

/** The environment built from EXACTLY the graph's declaration. */
function declaredEnv(): Record<string, string> {
  const env: Record<string, string> = { ...graph.worker.vars };
  for (const name of [...graph.worker.deploymentVars, ...graph.worker.secretSchema]) {
    env[name] = placeholderValue(name);
  }
  return env;
}

test("R5-SEC-01: the managed graph's declared inputs BOOT the key configuration", () => {
  assert.equal(graph.securityPosture, "managed");
  const resolved = resolveKeyConfig(declaredEnv());
  assert.equal(resolved.profile, "managed");
  assert.equal(resolved.environment, ENV_NAME);
  assert.equal(hex(resolved.capabilityKeyring.keys[0].publicKey), hex(CAP_PAIR.publicKey));
  assert.equal(hex(resolved.provisionKeyring.keys[0].publicKey), hex(PROV_PAIR.publicKey));
});

test("R5-SEC-01 MUTANT: dropping each graph-declared input in turn refuses the boot", () => {
  const full = declaredEnv();
  for (const name of Object.keys(full)) {
    const { [name]: _dropped, ...mutant } = full;
    if (name === "CONTROLLER_KEY_PROFILE") {
      // losing the posture selector must NOT downgrade: unset resolves to
      // managed (with the remaining declared inputs it still boots managed)
      assert.equal(resolveKeyConfig(mutant).profile, "managed",
        "a lost profile var must stay managed, never downgrade");
      continue;
    }
    assert.throws(() => resolveKeyConfig(mutant), /KEY_CONFIG_INVALID/,
      `boot without declared input ${name} must refuse`);
  }
});

test("R5-SEC-01: graph declaration == runtime requirement list (single source, no skew)", () => {
  const declared = [
    ...Object.keys(graph.worker.vars),
    ...graph.worker.deploymentVars,
    ...graph.worker.secretSchema,
  ].sort();
  assert.deepEqual(declared, [...MANAGED_RUNTIME_INPUTS].sort(),
    "the canonical graph must declare exactly the runtime's required inputs");
});

test("R5-SEC-03 MUTANT: stealing EVERY managed env var/secret yields no minting ability", async () => {
  const stolen = declaredEnv(); // everything a compromised runtime can read
  const resolved = resolveKeyConfig(stolen);
  // no private material resolves — structurally nothing to sign with
  assert.equal(resolved.capabilitySigningKey, undefined, "managed must resolve no signing key");
  assert.equal(resolved.issuerSecret, undefined, "managed must resolve no issuance credential");
  // brute the point: abuse every resolved byte string as if it were a
  // signing key; each attempt must fail to produce a token both keyrings
  // would accept
  const payload: CapabilityPayload = {
    v: 3, alg: "Ed25519", kid: resolved.capabilityKeyring.keys[0].kid,
    env: ENV_NAME, tenantId: "tenant-a", principal: "thief", databaseId: "db1",
    method: "WAL_READ", session: "s", generation: "1",
    incarnation: 1, nonce: "n-steal", expiresAtMs: 2_000_000,
  };
  const stolenBytes: Uint8Array[] = [
    resolved.journalKey,
    ...resolved.capabilityKeyring.keys.map((k) => k.publicKey),
    ...resolved.provisionKeyring.keys.map((k) => k.publicKey),
  ];
  for (const material of stolenBytes) {
    let token: string | null = null;
    try {
      token = await mintCapabilityToken(material, payload);
    } catch {
      continue; // not even importable as a signing key — the common case
    }
    const verdict = await verifyCapabilityToken(resolved.capabilityKeyring, token, {
      method: "WAL_READ", databaseId: "db1", env: ENV_NAME, nowMs: 1_000_000,
    });
    assert.equal(verdict.ok, false, "material stolen from the managed env must never sign a valid token");
  }
  // while the REAL issuer (whose private key is NOT in the env) still can:
  const genuine = await mintCapabilityToken(CAP_PAIR.privateKeyPkcs8,
    { ...payload, kid: `cap:${ENV_NAME}/1` });
  assert.ok((await verifyCapabilityToken(resolved.capabilityKeyring, genuine, {
    method: "WAL_READ", databaseId: "db1", env: ENV_NAME, nowMs: 1_000_000,
  })).ok, "the issuer-side private key remains the one minting authority");
});
