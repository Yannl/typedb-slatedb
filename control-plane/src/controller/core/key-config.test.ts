/*
 * Q-24 / R5-SEC-01 / R5-SEC-03 negative controls: fail-closed key
 * configuration.
 *
 * The properties under test: there is NO environment state in which a
 * managed deployment runs on development material; no state in which a
 * lost variable silently downgrades the posture; the managed runtime
 * resolves ONLY public verification material (verify-but-never-mint); and
 * the resolver's required-input list is the shared declaration the stack
 * graph checker also enforces.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DEV_CAPABILITY_PUBLIC_KEY_HEX, DEV_ENVIRONMENT, DEV_JOURNAL_KEY, DEV_PROVISION_PUBLIC_KEY_HEX,
  devCapabilitySigningKey, devProvisionSigningKey,
  KeyConfigError, MANAGED_DEPLOYMENT_VARS, MANAGED_RUNTIME_INPUTS, MANAGED_SECRETS, MIN_KEY_BYTES,
  parseVerificationKeyring, resolveKeyConfig, RETIRED_MANAGED_INPUTS,
} from "./key-config.ts";
import { hex } from "./journal-crypto.ts";
import { ed25519PublicKeyFromPkcs8, generateEd25519KeyPair } from "./ed25519.ts";

const CAP_PAIR = await generateEd25519KeyPair();
const PROV_PAIR = await generateEd25519KeyPair();

const GOOD_JOURNAL = "a1".repeat(MIN_KEY_BYTES);
const GOOD = {
  CONTROLLER_KEY_PROFILE: "managed",
  CONTROLLER_JOURNAL_KEY: GOOD_JOURNAL,
  CONTROLLER_ENVIRONMENT: "managed-e2e",
  CONTROLLER_CAPABILITY_PUBLIC_KEYS: `cap:managed-e2e/1=${hex(CAP_PAIR.publicKey)}`,
  CONTROLLER_PROVISION_PUBLIC_KEYS: `prov:managed-e2e/1=${hex(PROV_PAIR.publicKey)}`,
};

function refuses(env: Record<string, string | undefined>, why: string) {
  assert.throws(() => resolveKeyConfig(env), KeyConfigError, why);
}

test("Q-24: a correctly provisioned managed profile resolves - PUBLIC material only", () => {
  const keys = resolveKeyConfig(GOOD);
  assert.equal(keys.profile, "managed");
  assert.equal(keys.journalKey.length, MIN_KEY_BYTES);
  assert.equal(keys.environment, "managed-e2e");
  assert.equal(keys.capabilityKeyring.keys[0].kid, "cap:managed-e2e/1");
  assert.equal(hex(keys.capabilityKeyring.keys[0].publicKey), hex(CAP_PAIR.publicKey));
  assert.equal(keys.provisionKeyring.keys[0].kid, "prov:managed-e2e/1");
  // R5-SEC-03: verify-only - the managed posture resolves NO signing key
  // and NO issuance credential, so nothing in this process can mint
  assert.equal(keys.capabilitySigningKey, undefined);
  assert.equal(keys.issuerSecret, undefined);
});

test("Q-24: an UNSET profile is managed - a lost variable refuses, it does not downgrade", () => {
  // no profile + no keys: this is the exact state a misdeployed production
  // worker would be in, and it must refuse rather than run on dev keys
  refuses({}, "empty environment must refuse");
  // no profile + full inputs: managed semantics apply and it works
  const { CONTROLLER_KEY_PROFILE: _unused, ...withoutProfile } = GOOD;
  assert.equal(resolveKeyConfig(withoutProfile).profile, "managed");
});

test("R5-SEC-01 MUTANT: dropping EACH declared managed input in turn refuses boot", () => {
  // the drop-each-input mutant, driven off the SHARED requirement list so a
  // new requirement is automatically covered
  for (const name of MANAGED_RUNTIME_INPUTS) {
    if (name === "CONTROLLER_KEY_PROFILE") continue; // unset profile = managed; covered above
    refuses({ ...GOOD, [name]: undefined }, `absent ${name} must refuse`);
    refuses({ ...GOOD, [name]: "" }, `empty ${name} must refuse`);
  }
  // and the list is the complete boot set: exactly the declared names, with
  // placeholder values, boot (nothing undeclared is additionally required)
  const exact: Record<string, string> = {};
  for (const name of Object.keys(GOOD)) exact[name] = GOOD[name as keyof typeof GOOD];
  assert.deepEqual(Object.keys(exact).sort(), [...MANAGED_RUNTIME_INPUTS].sort(),
    "the GOOD fixture must be exactly the declared runtime inputs");
  assert.equal(resolveKeyConfig(exact).profile, "managed");
  // the declared split stays coherent
  assert.deepEqual([...MANAGED_SECRETS], ["CONTROLLER_JOURNAL_KEY"]);
  assert.ok(MANAGED_DEPLOYMENT_VARS.includes("CONTROLLER_CAPABILITY_PUBLIC_KEYS"));
});

test("R5-SEC-03: RETIRED symmetric v2 inputs are refused BY NAME under managed", () => {
  for (const name of RETIRED_MANAGED_INPUTS) {
    refuses({ ...GOOD, [name]: "b2".repeat(32) }, `${name} present must refuse`);
  }
});

test("Q-24: managed refuses malformed journal key and dev constants", () => {
  refuses({ ...GOOD, CONTROLLER_JOURNAL_KEY: "zz".repeat(MIN_KEY_BYTES) }, "non-hex");
  refuses({ ...GOOD, CONTROLLER_JOURNAL_KEY: "abc" }, "odd-length hex");
  refuses({ ...GOOD, CONTROLLER_JOURNAL_KEY: "a1".repeat(MIN_KEY_BYTES - 1) }, "below policy length");
  refuses({ ...GOOD, CONTROLLER_JOURNAL_KEY: DEV_JOURNAL_KEY }, "dev journal constant");
});

test("R5-SEC-03: managed refuses the committed DEV public keys even when configured EXPLICITLY", () => {
  // this is the smuggling path: someone sets the dev value as if it were a
  // real key. Refusal, not acceptance, is what makes the constants safe to
  // keep in the codebase at all.
  refuses({ ...GOOD, CONTROLLER_CAPABILITY_PUBLIC_KEYS: `cap:managed-e2e=${DEV_CAPABILITY_PUBLIC_KEY_HEX}` },
    "dev capability public key");
  refuses({ ...GOOD, CONTROLLER_PROVISION_PUBLIC_KEYS: `prov:managed-e2e=${DEV_PROVISION_PUBLIC_KEY_HEX}` },
    "dev provision public key");
});

test("R5-SEC-03: keyring parsing fails closed on every malformation", () => {
  const good = `cap:managed-e2e/1=${hex(CAP_PAIR.publicKey)}`;
  // wrong scope, foreign environment, junk syntax, short key, 3 slots,
  // retired current, duplicate kid
  refuses({ ...GOOD, CONTROLLER_CAPABILITY_PUBLIC_KEYS: `prov:managed-e2e=${hex(CAP_PAIR.publicKey)}` }, "wrong scope");
  refuses({ ...GOOD, CONTROLLER_CAPABILITY_PUBLIC_KEYS: `cap:other-env=${hex(CAP_PAIR.publicKey)}` }, "foreign env");
  refuses({ ...GOOD, CONTROLLER_CAPABILITY_PUBLIC_KEYS: "not-a-keyring" }, "junk");
  refuses({ ...GOOD, CONTROLLER_CAPABILITY_PUBLIC_KEYS: "cap:managed-e2e=abcd" }, "short key");
  refuses({ ...GOOD, CONTROLLER_CAPABILITY_PUBLIC_KEYS: `${good},cap:managed-e2e/2=${"b2".repeat(32)},cap:managed-e2e/3=${"c3".repeat(32)}` }, "three slots");
  refuses({ ...GOOD, CONTROLLER_CAPABILITY_PUBLIC_KEYS: `!cap:managed-e2e/1=${hex(CAP_PAIR.publicKey)}` }, "retired current");
  refuses({ ...GOOD, CONTROLLER_CAPABILITY_PUBLIC_KEYS: `${good},!${good}` }, "duplicate kid");
  // a valid two-slot ring with a retired previous parses and is marked
  const ring = parseVerificationKeyring("X", "cap", "managed-e2e",
    `cap:managed-e2e/2=${"b2".repeat(32)},!cap:managed-e2e/1=${"c3".repeat(32)}`);
  assert.equal(ring.keys.length, 2);
  assert.equal(ring.keys[0].retired, false);
  assert.equal(ring.keys[1].retired, true);
});

test("Q-24: managed refuses shared key material across scopes (blast-radius separation)", () => {
  refuses({ ...GOOD, CONTROLLER_PROVISION_PUBLIC_KEYS: `prov:managed-e2e=${hex(CAP_PAIR.publicKey)}` },
    "capability and provision scopes sharing a keypair");
  refuses({ ...GOOD, CONTROLLER_JOURNAL_KEY: hex(CAP_PAIR.publicKey) },
    "journal secret equal to a published verification key");
});

test("Q-24: an unknown profile string is a refusal, never a guess", () => {
  refuses({ ...GOOD, CONTROLLER_KEY_PROFILE: "production" }, "unknown profile");
  refuses({ ...GOOD, CONTROLLER_KEY_PROFILE: "Managed" }, "case variant");
});

test("Q-24: local-dev works with zero provisioning and stays loudly named", () => {
  const keys = resolveKeyConfig({ CONTROLLER_KEY_PROFILE: "local-dev" });
  assert.equal(keys.profile, "local-dev");
  assert.equal(keys.environment, DEV_ENVIRONMENT);
  assert.ok((keys.issuerSecret ?? "").length > 0, "issuance is credentialed even in dev (Q-02)");
  // the dev-lane issuance route needs a signing key; ONLY this profile has one
  assert.ok(keys.capabilitySigningKey !== undefined);
  assert.equal(hex(keys.capabilityKeyring.keys[0].publicKey), DEV_CAPABILITY_PUBLIC_KEY_HEX);
  assert.equal(hex(keys.provisionKeyring.keys[0].publicKey), DEV_PROVISION_PUBLIC_KEY_HEX);
});

test("R5-SEC-03: the committed dev PUBLIC constants match their committed seeds (no transcription drift)", async () => {
  assert.equal(hex(await ed25519PublicKeyFromPkcs8(devCapabilitySigningKey())), DEV_CAPABILITY_PUBLIC_KEY_HEX);
  assert.equal(hex(await ed25519PublicKeyFromPkcs8(devProvisionSigningKey())), DEV_PROVISION_PUBLIC_KEY_HEX);
  // and the two dev keypairs are distinct
  assert.notEqual(DEV_CAPABILITY_PUBLIC_KEY_HEX, DEV_PROVISION_PUBLIC_KEY_HEX);
});

test("R4 PR1: managed requires a real environment name, never the reserved dev one", () => {
  refuses({ ...GOOD, CONTROLLER_ENVIRONMENT: "Has/Bad Chars" }, "unnormalized environment");
  refuses({ ...GOOD, CONTROLLER_ENVIRONMENT: DEV_ENVIRONMENT },
    "the reserved local-dev environment name must never be a managed environment");
});
