/*
 * Q-24 negative controls: fail-closed key configuration.
 *
 * The property under test: there is NO environment state in which a managed
 * deployment runs on development keys, and no state in which a lost
 * variable silently downgrades the posture.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DEV_CAPABILITY_KEY, DEV_ISSUER_SECRET, DEV_JOURNAL_KEY, KeyConfigError,
  MIN_KEY_BYTES, resolveKeyConfig,
} from "./key-config.ts";

const GOOD_JOURNAL = "a1".repeat(MIN_KEY_BYTES);
const GOOD_CAPABILITY = "b2".repeat(MIN_KEY_BYTES);
const GOOD = {
  CONTROLLER_KEY_PROFILE: "managed",
  CONTROLLER_JOURNAL_KEY: GOOD_JOURNAL,
  CONTROLLER_CAPABILITY_KEY: GOOD_CAPABILITY,
  CONTROLLER_ISSUER_SECRET: "issuer-secret-of-adequate-length",
};

function refuses(env: Record<string, string | undefined>, why: string) {
  assert.throws(() => resolveKeyConfig(env), KeyConfigError, why);
}

test("Q-24: a correctly provisioned managed profile resolves", () => {
  const keys = resolveKeyConfig(GOOD);
  assert.equal(keys.profile, "managed");
  assert.equal(keys.journalKey.length, MIN_KEY_BYTES);
  assert.equal(keys.capabilityKey.length, MIN_KEY_BYTES);
  assert.equal(keys.issuerSecret, GOOD.CONTROLLER_ISSUER_SECRET);
});

test("Q-24: an UNSET profile is managed - a lost variable refuses, it does not downgrade", () => {
  // no profile + no keys: this is the exact state a misdeployed production
  // worker would be in, and it must refuse rather than run on dev keys
  refuses({}, "empty environment must refuse");
  // no profile + full keys: managed semantics apply and it works
  const { CONTROLLER_KEY_PROFILE: _unused, ...withoutProfile } = GOOD;
  assert.equal(resolveKeyConfig(withoutProfile).profile, "managed");
});

test("Q-24: managed refuses absent, empty, malformed and short keys", () => {
  refuses({ ...GOOD, CONTROLLER_JOURNAL_KEY: undefined }, "absent journal key");
  refuses({ ...GOOD, CONTROLLER_CAPABILITY_KEY: "" }, "empty capability key");
  refuses({ ...GOOD, CONTROLLER_JOURNAL_KEY: "zz".repeat(MIN_KEY_BYTES) }, "non-hex");
  refuses({ ...GOOD, CONTROLLER_JOURNAL_KEY: "abc" }, "odd-length hex");
  refuses({ ...GOOD, CONTROLLER_CAPABILITY_KEY: "a1".repeat(MIN_KEY_BYTES - 1) }, "below policy length");
  refuses({ ...GOOD, CONTROLLER_ISSUER_SECRET: undefined }, "absent issuer secret");
  refuses({ ...GOOD, CONTROLLER_ISSUER_SECRET: "short" }, "short issuer secret");
});

test("Q-24: managed refuses the development constants even when configured EXPLICITLY", () => {
  // this is the smuggling path: someone sets the dev value as if it were a
  // real secret. Refusal, not acceptance, is what makes the constants safe
  // to keep in the codebase at all.
  refuses({ ...GOOD, CONTROLLER_JOURNAL_KEY: DEV_JOURNAL_KEY }, "dev journal constant");
  refuses({ ...GOOD, CONTROLLER_CAPABILITY_KEY: DEV_CAPABILITY_KEY }, "dev capability constant");
  refuses({ ...GOOD, CONTROLLER_ISSUER_SECRET: DEV_ISSUER_SECRET }, "dev issuer constant");
});

test("Q-24: managed refuses journal == capability key (blast-radius separation)", () => {
  refuses({ ...GOOD, CONTROLLER_CAPABILITY_KEY: GOOD_JOURNAL }, "shared key material");
});

test("Q-24: an unknown profile string is a refusal, never a guess", () => {
  refuses({ ...GOOD, CONTROLLER_KEY_PROFILE: "production" }, "unknown profile");
  refuses({ ...GOOD, CONTROLLER_KEY_PROFILE: "Managed" }, "case variant");
});

test("Q-24: local-dev works with zero provisioning and stays loudly named", () => {
  const keys = resolveKeyConfig({ CONTROLLER_KEY_PROFILE: "local-dev" });
  assert.equal(keys.profile, "local-dev");
  assert.ok(keys.issuerSecret.length > 0, "issuance is credentialed even in dev (Q-02)");
});
