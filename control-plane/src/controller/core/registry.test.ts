/*
 * R4 PR1 / R5-SEC-03 negative controls: the opaque registry primitives and
 * the asymmetric provisioning power.
 *
 * The properties under proof:
 *  - identifiers naming tenants/databases/environments are normalized and
 *    bounded BEFORE they can reach a DO name, an object key or a token;
 *  - the PROVISION power is its own Ed25519 KEYPAIR: a holder of any
 *    verification material (capability public keys, provision public keys)
 *    cannot mint it, and a token signed by the CAPABILITY issuer key
 *    cannot provision (the audit's "verifier attempts to mint" mutant, in
 *    its asymmetric closing form);
 *  - the PROVISION token binds the exact registry triple;
 *  - the core provisioning transaction installs budgets + the journal
 *    record atomically and refuses invalid budgets.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import Database from "better-sqlite3";
import {
  capabilityKid, checkBinding, controllerDoName, provisionKid, validOpaqueId, verifyProvisionToken,
} from "../../shared/registry.ts";
import { verifyCapabilityToken, type VerificationKeyring } from "../../shared/capability.ts";
import { mintCapabilityToken, mintProvisionToken } from "./issuer.ts";
import { generateEd25519KeyPair } from "../../shared/ed25519.ts";
import { utf8 } from "../../shared/journal-crypto.ts";
import { ControllerCore } from "./procedures.ts";
import { sqlOver } from "./test-support.ts";

const BINDING = { environment: "managed-e2e", tenantId: "tenant-a", databaseId: "db-opaque-1" };
const NOW = 1_000_000;

// the run's issuer: two distinct keypairs, one per scope
const CAP_PAIR = await generateEd25519KeyPair();
const PROV_PAIR = await generateEd25519KeyPair();
const CAP_RING: VerificationKeyring = {
  scope: "cap", environment: "managed-e2e",
  keys: [{ kid: capabilityKid("managed-e2e"), publicKey: CAP_PAIR.publicKey, retired: false }],
};
const PROV_RING: VerificationKeyring = {
  scope: "prov", environment: "managed-e2e",
  keys: [{ kid: provisionKid("managed-e2e"), publicKey: PROV_PAIR.publicKey, retired: false }],
};

test("R4 PR1: identifiers are normalized and bounded - no slashes, controls, case or oversize", () => {
  for (const good of ["a", "tenant-a", "db-1", "x".repeat(64), "0abc9"]) {
    assert.ok(validOpaqueId(good), `${good} must be valid`);
  }
  const bad = [
    "", "A", "Tenant", "t/enant", "te.nant", "te_nant", "-leading", "trailing-",
    "x".repeat(65), "t enant", "тenant" /* homoglyph */, " space", 42, null, undefined,
  ];
  for (const value of bad) {
    assert.equal(validOpaqueId(value), false, `${String(value)} must be refused`);
  }
  // the wire-shape validator names the offending field, never throws
  assert.deepEqual(checkBinding({ environment: "e", tenantId: "T", databaseId: "d" }),
    { ok: false, error: "INVALID_BINDING", field: "tenantId" });
  assert.deepEqual(checkBinding({ environment: "e", tenantId: "t", databaseId: "d/b" }),
    { ok: false, error: "INVALID_BINDING", field: "databaseId" });
});

test("R4 PR1: the controller DO name derives from the FULL registry triple", () => {
  assert.equal(controllerDoName(BINDING), "ctl/managed-e2e/tenant-a/db-opaque-1");
  // same opaque database id under two tenants (or two environments) names
  // two DIFFERENT authorities - the cross-tenant collision mutant
  assert.notEqual(
    controllerDoName({ ...BINDING, tenantId: "tenant-b" }),
    controllerDoName(BINDING));
  assert.notEqual(
    controllerDoName({ ...BINDING, environment: "local" }),
    controllerDoName(BINDING));
});

test("MUTANT R5-SEC-03: no verification material can mint the PROVISION capability", async () => {
  // (a) an attacker holding EVERY public key of the runtime generates its
  // own keypair and self-signs a provision token claiming the real kid:
  // the signature cannot validate under the provisioning public key
  const attacker = await generateEd25519KeyPair();
  const selfSigned = await mintProvisionToken(attacker.privateKeyPkcs8, BINDING,
    { nonce: "n-forge", expiresAtMs: NOW + 60_000 });
  assert.deepEqual(await verifyProvisionToken(PROV_RING, selfSigned, { binding: BINDING, nowMs: NOW }),
    { ok: false, error: "CAPABILITY_SIGNATURE_INVALID" });
  // (b) the CAPABILITY issuer key (the strongest signing material outside
  // the provisioning role) still cannot provision: distinct keypairs
  const crossScope = await mintProvisionToken(CAP_PAIR.privateKeyPkcs8, BINDING,
    { nonce: "n-cross", expiresAtMs: NOW + 60_000 });
  assert.deepEqual(await verifyProvisionToken(PROV_RING, crossScope, { binding: BINDING, nowMs: NOW }),
    { ok: false, error: "CAPABILITY_SIGNATURE_INVALID" });
  // (c) and the converse: the PROVISION key cannot mint ordinary
  // capabilities that the capability keyring would accept
  const forgedCap = await mintCapabilityToken(PROV_PAIR.privateKeyPkcs8, {
    v: 3, alg: "Ed25519", kid: capabilityKid("managed-e2e"), env: "managed-e2e", tenantId: "tenant-a",
    principal: "p", databaseId: "db-opaque-1", method: "WAL_READ", session: "s", generation: "1",
    incarnation: 1, nonce: "n-2", expiresAtMs: NOW + 60_000,
  });
  assert.deepEqual(
    await verifyCapabilityToken(CAP_RING, forgedCap, {
      method: "WAL_READ", databaseId: "db-opaque-1", env: "managed-e2e", nowMs: NOW,
    }),
    { ok: false, error: "CAPABILITY_SIGNATURE_INVALID" });
  // (d) public keys are not signing material at all: attempting to "mint
  // with the verifier's key" is an import failure, not a token
  await assert.rejects(() => mintProvisionToken(PROV_RING.keys[0].publicKey, BINDING,
    { nonce: "n-pub", expiresAtMs: NOW + 60_000 }));
});

test("R4 PR1: the PROVISION token binds the exact registry triple", async () => {
  const token = await mintProvisionToken(PROV_PAIR.privateKeyPkcs8, BINDING,
    { nonce: "n-1", expiresAtMs: NOW + 60_000 });
  assert.ok((await verifyProvisionToken(PROV_RING, token, { binding: BINDING, nowMs: NOW })).ok);
  // MUTANT: a valid tenant-A provision token used against tenant B's
  // binding (same database id) refuses
  assert.deepEqual(
    await verifyProvisionToken(PROV_RING, token, { binding: { ...BINDING, tenantId: "tenant-b" }, nowMs: NOW }),
    { ok: false, error: "CAPABILITY_TENANT_MISMATCH" });
  assert.deepEqual(
    await verifyProvisionToken(PROV_RING, token, { binding: { ...BINDING, databaseId: "db-other" }, nowMs: NOW }),
    { ok: false, error: "CAPABILITY_AUDIENCE_MISMATCH" });
  // MUTANT (cross-environment): another environment's binding refuses at
  // the kid scope - the token's kid names managed-e2e, not prod-eu
  assert.deepEqual(
    await verifyProvisionToken(PROV_RING, token, { binding: { ...BINDING, environment: "prod-eu" }, nowMs: NOW }),
    { ok: false, error: "CAPABILITY_KID_MISMATCH" });
  // expiry is enforced like every capability
  assert.deepEqual(
    await verifyProvisionToken(PROV_RING, token, { binding: BINDING, nowMs: NOW + 120_000 }),
    { ok: false, error: "CAPABILITY_EXPIRED" });
});

test("R4 PR1: an ordinary route cannot accept a PROVISION token (method + kid scope both refuse)", async () => {
  const token = await mintProvisionToken(PROV_PAIR.privateKeyPkcs8, BINDING,
    { nonce: "n-1", expiresAtMs: NOW + 60_000 });
  // even if a buggy route somehow checked it under the provisioning
  // keyring, the method mismatch refuses
  assert.deepEqual(
    await verifyCapabilityToken(PROV_RING, token, {
      method: "WAL_FINALIZE", databaseId: BINDING.databaseId, env: BINDING.environment, nowMs: NOW,
    }),
    { ok: false, error: "CAPABILITY_METHOD_MISMATCH" });
  // and against the ORDINARY keyring, the kid scope refuses before any
  // signature work
  assert.deepEqual(
    await verifyCapabilityToken(CAP_RING, token, {
      method: "PROVISION", databaseId: BINDING.databaseId, env: BINDING.environment, nowMs: NOW,
    }),
    { ok: false, error: "CAPABILITY_KID_MISMATCH" });
});

test("R4 PR1: the core provisioning transaction journals the binding and installs budgets atomically", () => {
  const db = new Database(":memory:");
  const core = new ControllerCore(sqlOver(db), { journalKey: utf8("registry-test-key") });
  const ok = core.provisionDatabase(BINDING, {
    maxUnpublishedOutbox: 100, maxPayloadLength: 1_000_000, maxTailRecords: 1_000_000,
  });
  assert.ok(ok.ok);
  const journaled = db.prepare(
    `SELECT canonical_body FROM control_outbox WHERE kind='DATABASE_PROVISIONED'`).all() as
    { canonical_body: string }[];
  assert.equal(journaled.length, 1, "provisioning is a journaled authority command");
  const body = JSON.parse(journaled[0].canonical_body) as Record<string, unknown>;
  assert.equal(body.tenantId, "tenant-a");
  assert.equal(body.environment, "managed-e2e");
  assert.equal(body.budgetsInstalled, true);
  const budgets = db.prepare(`SELECT * FROM budgets WHERE database_id=?`).get(BINDING.databaseId);
  assert.ok(budgets !== undefined, "budgets installed in the provisioning transaction");
  // the journal (chain + MACs) still verifies with the provisioning row
  assert.ok(core.verifyJournal().ok);
  // an invalid budget refuses the WHOLE transaction: no journal row either
  const bad = core.provisionDatabase({ ...BINDING, databaseId: "db-2" },
    { maxUnpublishedOutbox: 1.5, maxPayloadLength: 10, maxTailRecords: 10 });
  assert.deepEqual(bad, { ok: false, error: "INVALID_BUDGET", field: "maxUnpublishedOutbox" });
  const after = db.prepare(
    `SELECT COUNT(*) AS n FROM control_outbox WHERE kind='DATABASE_PROVISIONED'`).get() as { n: number };
  assert.equal(after.n, 1, "a refused provisioning journals nothing");
});
