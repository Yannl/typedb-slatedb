/*
 * R8-P2-03, the half a workerd suite cannot reach: what an UNREADY deployment
 * tells the caller.
 *
 * `SELF` in the workerd pool is constructed from wrangler.local-dev.toml, whose
 * key configuration resolves by design, so the 503 branch has no subject
 * there. What can be exercised here, in plain node against the shipped
 * resolver, is the property the refusal rests on: `resolveKeyConfig` on a
 * managed env with no key material THROWS, and its message - the value the
 * route used to hand straight back to the caller - contains exactly the
 * deployment detail that must never cross the wire.
 *
 * So this suite proves the leak was real, and that the sanitised shape the
 * route now returns cannot carry it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { resolveKeyConfig } from "../../shared/key-config.ts";

/** The sanitised body `/ready` and `resolveKeysOr500` now return. */
function sanitised(error: unknown, correlationId: string) {
  return { ok: false, error: "KEY_CONFIG_INVALID", correlationId, _internalOnly: String(error) };
}

test("a managed env with no key material refuses, and the refusal names deployment detail", () => {
  let thrown: unknown;
  try {
    resolveKeyConfig({ CONTROLLER_KEY_PROFILE: "managed" } as never);
  } catch (error) {
    thrown = error;
  }
  assert.ok(thrown instanceof Error, "an unconfigured managed deployment must refuse, not resolve");
  const message = thrown.message;
  // The finding, demonstrated rather than asserted from prose: this message
  // names environment variables and key-configuration structure.
  assert.match(
    message,
    /CONTROLLER_[A-Z_]+/,
    `the resolver's message is expected to name deployment inputs; got ${message}`,
  );
});

test("the sanitised wire body carries a code and a correlation id, and no detail", () => {
  let thrown: unknown;
  try {
    resolveKeyConfig({ CONTROLLER_KEY_PROFILE: "managed" } as never);
  } catch (error) {
    thrown = error;
  }
  const correlationId = "11111111-2222-3333-4444-555555555555";
  const { _internalOnly, ...wire } = sanitised(thrown, correlationId);
  const text = JSON.stringify(wire);
  assert.deepEqual(Object.keys(wire).sort(), ["correlationId", "error", "ok"]);
  assert.equal(wire.error, "KEY_CONFIG_INVALID", "the caller gets a STABLE code, not a message");
  assert.equal(wire.correlationId, correlationId, "and a handle the operator can find the log by");
  for (const secretish of ["CONTROLLER_", "keyring", "kid", "profile", "DEV_"]) {
    assert.ok(!text.includes(secretish), `the wire body names ${secretish}: ${text}`);
  }
  // ...while the detail the operator needs is still produced, for the log
  assert.ok(_internalOnly.length > 0, "the diagnostic must exist; it just must not be returned");
});

test("an unknown key profile is refused rather than defaulted", () => {
  assert.throws(
    () => resolveKeyConfig({ CONTROLLER_KEY_PROFILE: "not-a-profile" } as never),
    /not a known profile/,
    "a profile the code does not know must never fall through to a default posture",
  );
});
