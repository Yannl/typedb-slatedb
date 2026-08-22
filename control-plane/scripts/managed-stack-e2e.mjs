/*
 * R4 PR1 / R5-SEC-03: PRODUCTION-SURFACE local E2E.
 *
 * Boots `wrangler dev` on the MANAGED config (wrangler.toml - the exact
 * fail-closed posture a default deploy selects: no CONTROLLER_SURFACE, so
 * every dev-only route is physically absent) with PER-RUN EPHEMERAL
 * ASYMMETRIC KEYS: this script IS the private issuer for the run
 * (scripts/issuer.mjs). It generates a fresh Ed25519 keypair per scope
 * (cap:<env>/1, prov:<env>/1), keeps the PRIVATE halves in this process,
 * and hands the runtime ONLY the public verification keyrings + the
 * journal secret + the environment name - exactly the inputs the canonical
 * graph declares (R5-SEC-01). Nothing is reused between runs, and no dev
 * constant can satisfy this surface.
 *
 * What it proves, in order:
 *   1. every dev route (capability issuer, legacy register/fence, budget
 *      admin, batch, admin bump, raw outbox/audit) answers 404 - and the
 *      subsequent bootstrap shows those probes left ZERO DO/journal state;
 *   2. the dev keypair is worthless here: the issuance route does not
 *      exist, and a token SIGNED with the committed dev capability key
 *      fails signature verification;
 *   3. the FULL bootstrap runs through the internal path only: provision
 *      (registry binding + initial budgets) under the PROVISION keypair,
 *      lifecycle admission (reserve -> attest -> activate), payload upload,
 *      WAL finalize, exact read-back - every token minted issuer-side from
 *      the run's ephemeral private keys, exactly the production
 *      authorization topology, executed locally;
 *   4. the PR1/R5 mutants hold on this surface: unprovisioned squat,
 *      forged cross-tenant token, cross-scope signing material;
 *   5. the loopback HTTP issuer (the R5-SEC-02 seam the Rust client will
 *      use) issues tokens the managed surface accepts, and refuses
 *      anonymous callers.
 *
 * Usage: node --experimental-strip-types scripts/managed-stack-e2e.mjs
 * Exit code 0 = every check passed.
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mintCapabilityToken, mintProvisionToken } from "../src/controller/core/issuer.ts";
import { devCapabilitySigningKey, DEV_ISSUER_SECRET } from "../src/shared/key-config.ts";
import { createIssuer, startIssuerServer } from "./issuer.mjs";
import { startWranglerDev } from "./wrangler-dev.mjs";

// ---- the private issuer for this run: fresh Ed25519 keypairs per scope ----
const ENV_NAME = "managed-e2e";
const TENANT = "tenant-a";
const ISSUER = await createIssuer({ environment: ENV_NAME, tenantId: TENANT });

const DB = `mdb-${Date.now()}`;
const GEN = 1;
const SESSION = "sess-managed-1";

let failures = 0;
function check(name, condition, detail = "") {
  const status = condition ? "PASS" : "FAIL";
  if (!condition) failures += 1;
  console.log(`${status}  ${name}${detail ? ` — ${detail}` : ""}`);
}

function sha256hex(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

/** The private issuer mints an ordinary capability (v3, cap:<env>/1). */
async function mint(spec) {
  return (await ISSUER.mintCapability({ principal: "managed-e2e-issuer", ...spec })).token;
}

const { baseUrl, stop } = await startWranglerDev({
  configPath: "wrangler.toml",
  port: Number(process.env.E2E_MANAGED_PORT ?? 8798),
  vars: {
    // managed posture, per-run ephemeral material - the runtime receives
    // ONLY public verification keyrings + the journal secret; the private
    // signing keys never leave this script (R5-SEC-03)
    CONTROLLER_JOURNAL_KEY: randomBytes(32).toString("hex"),
    ...ISSUER.runtimeVars(),
  },
});

async function api(method, path, { body, raw, headers = {} } = {}) {
  // See local-stack-e2e.mjs: a bodyless request omits the key entirely.
  const payload = raw ?? (body !== undefined ? JSON.stringify(body) : undefined);
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    ...(payload === undefined ? {} : { body: payload }),
    headers: raw !== undefined ? headers : { "content-type": "application/json", ...headers },
  });
  let parsed = null;
  try { parsed = await response.json(); } catch { /* non-JSON */ }
  return { status: response.status, body: parsed };
}

try {
  const health = await api("GET", "/health");
  check("managed stack is healthy", health.body?.ok === true, JSON.stringify(health.body));

  // ---- 1. the dev surface does not exist: 404, before any parsing/DO work ----
  const devProbes = [
    ["POST", "/capability", { principal: "p", databaseId: DB, method: "WAL_READ" },
      { "x-issuer-authorization": DEV_ISSUER_SECRET }],
    ["POST", "/session/register", { databaseId: DB, generation: GEN, startupSessionId: SESSION }],
    ["POST", "/session/fence", { databaseId: DB, generation: GEN, startupSessionId: SESSION }],
    ["POST", "/budgets", { databaseId: DB, maxUnpublishedOutbox: 1, maxPayloadLength: 1, maxTailRecords: 1 }],
    ["POST", "/wal/finalize-batch", { batchOperationId: "b", requests: [] }],
    ["POST", `/admin/${DB}/incarnation/bump`, {}],
    ["GET", `/outbox/${DB}?limit=10`, undefined],
    ["POST", `/outbox/${DB}/ack`, { upToControlSeq: "1" }],
    ["GET", `/wal/${DB}/${GEN}/audit`, undefined],
  ];
  for (const [method, path, body, headers] of devProbes) {
    const probe = await api(method, path, { body, headers });
    check(`dev route ${method} ${path.split("?")[0]} is absent on the managed surface`,
      probe.status === 404 && probe.body?.error === "NOT_FOUND", JSON.stringify(probe.body));
  }

  // ---- 2. dev signing material is worthless against the managed surface ----
  // (a token SIGNED with the committed dev capability key, claiming this
  // run's kid, cannot verify under the run's ephemeral public key)
  const devConstantToken = await mintCapabilityToken(devCapabilitySigningKey(), {
    v: 3, alg: "Ed25519", kid: ISSUER.capabilityKid, env: ENV_NAME, tenantId: TENANT,
    principal: "dev-smuggler", databaseId: DB, method: "WAL_READ",
    session: SESSION, generation: String(GEN),
    incarnation: 1, nonce: randomUUID(), expiresAtMs: Date.now() + 60_000,
  });
  const devConstant = await api("GET", `/wal/${DB}/${GEN}/head`,
    { raw: null, headers: { "x-capability": devConstantToken } });
  check("a token signed with the DEV capability key fails signature verification on managed",
    devConstant.status === 403 && devConstant.body?.error === "CAPABILITY_SIGNATURE_INVALID",
    JSON.stringify(devConstant.body));

  // ---- 3. squat mutant on the managed surface ----
  const preProvision = await api("GET", `/wal/${DB}/${GEN}/head`,
    { raw: null, headers: { "x-capability": await mint({ databaseId: DB, method: "WAL_READ", session: SESSION, generation: GEN }) } });
  check("an authenticated call to an unprovisioned authority fails closed (squat mutant)",
    preProvision.status === 403 && preProvision.body?.error === "DATABASE_UNPROVISIONED",
    JSON.stringify(preProvision.body));

  // cross-scope mutant: a provision token SIGNED with the capability
  // keypair (the strongest signing material outside the provisioning role;
  // the runtime itself holds NO signing material at all) binds nothing
  const forgedProvision = await api("POST", "/provision", {
    body: { tenantId: TENANT, databaseId: DB },
    headers: { "x-provision": await mintProvisionToken(ISSUER._private.capabilityPrivateKeyPkcs8,
      { environment: ENV_NAME, tenantId: TENANT, databaseId: DB },
      { nonce: randomUUID(), expiresAtMs: Date.now() + 60_000, kid: ISSUER.provisionKid }) },
  });
  check("capability-scope signing material cannot provision on managed (mint/verify separation)",
    forgedProvision.status === 403 && forgedProvision.body?.error === "CAPABILITY_SIGNATURE_INVALID",
    JSON.stringify(forgedProvision.body));

  // ---- 4. the internal bootstrap: provision -> admit -> write -> read ----
  const provisioned = await api("POST", "/provision", {
    body: {
      tenantId: TENANT, databaseId: DB,
      budgets: { maxUnpublishedOutbox: 10_000, maxPayloadLength: 1_000_000, maxTailRecords: 1_000_000 },
    },
    headers: { "x-provision": await ISSUER.mintProvision({ environment: ENV_NAME, tenantId: TENANT, databaseId: DB }) },
  });
  check("the provisioning transaction binds tenant + database + environment + budgets",
    provisioned.status === 200 && provisioned.body?.ok === true && provisioned.body?.created === true
      && provisioned.body?.binding?.tenantId === TENANT
      && provisioned.body?.binding?.environment === ENV_NAME,
    JSON.stringify(provisioned.body));

  // production lifecycle admission (the legacy one-call register is a dev
  // route and 404s here - proven above): reserve -> attest -> activate
  const reserve = await api("POST", "/session/reserve", {
    body: { databaseId: DB, generation: GEN, startupSessionId: SESSION, holder: "managed-e2e-host" },
    headers: { "x-capability": await mint({ databaseId: DB, method: "SESSION_RESERVE", session: SESSION, generation: GEN }) },
  });
  check("lifecycle: reservation via internal issuance", reserve.body?.ok === true, JSON.stringify(reserve.body));
  const attest = await api("POST", "/session/attest", {
    body: { databaseId: DB, startupSessionId: SESSION, processNonce: "pn-managed" },
    headers: { "x-capability": await mint({ databaseId: DB, method: "SESSION_ATTEST", session: SESSION }) },
  });
  check("lifecycle: attestation", attest.body?.ok === true, JSON.stringify(attest.body));
  const activate = await api("POST", "/session/activate", {
    body: { databaseId: DB, generation: GEN, startupSessionId: SESSION, processNonce: "pn-managed", leaseMs: 60_000 },
    headers: { "x-capability": await mint({ databaseId: DB, method: "SESSION_ACTIVATE", session: SESSION, generation: GEN }) },
  });
  check("lifecycle: verified activation", activate.body?.ok === true, JSON.stringify(activate.body));

  // payload through the data path (issuer-derived content-addressed key)
  const payload = Buffer.from("managed-commit-record-1");
  const digest = sha256hex(payload);
  const key = `p/${DB}/${digest}`;
  const put = await api("PUT", `/payload/${key}`, {
    raw: payload,
    headers: {
      "content-length": String(payload.length),
      "x-capability": await mint({ databaseId: DB, method: "PUT_PAYLOAD", digest, maxBytes: payload.length }),
    },
  });
  check("payload upload under an internally minted PUT_PAYLOAD capability",
    put.status === 200 && put.body?.sha256hex === digest, JSON.stringify(put.body));

  // WAL finalize (session+generation-bound token)
  const finalizeBody = {
    databaseId: DB, generation: GEN, startupSessionId: SESSION,
    operationId: "op-managed-1", sequencingKind: "SEQUENCED", recordType: 2, logicalKey: null,
    payloadKey: key, payloadDigest: digest, payloadLength: payload.length,
  };
  const finalize = await api("POST", "/wal/finalize", {
    body: finalizeBody,
    headers: { "x-capability": await mint({ databaseId: DB, method: "WAL_FINALIZE", session: SESSION, generation: GEN }) },
  });
  check("WAL finalize through the production path", finalize.body?.ok === true && finalize.body?.appendLsn === "0",
    JSON.stringify(finalize.body));

  // exact read-back
  const read = await api("GET", `/wal/${DB}/${GEN}/0`, {
    raw: null,
    headers: { "x-capability": await mint({ databaseId: DB, method: "WAL_READ", session: SESSION, generation: GEN }) },
  });
  check("exact read returns the exact payload",
    read.body?.ok === true && Buffer.from(read.body.payloadBase64, "base64").equals(payload),
    JSON.stringify({ status: read.status, error: read.body?.error }));

  // ---- 5. zero side effects from the dev probes: the journal holds ONLY
  // this bootstrap's records (provision, activation, finalize) ----
  const journal = await api("GET", `/journal/${DB}/verify`, {
    raw: null,
    headers: { "x-capability": await mint({ databaseId: DB, method: "JOURNAL_VERIFY" }) },
  });
  check("journal verifies and holds ONLY the bootstrap's 3 records (dev probes left zero state)",
    journal.body?.ok === true && journal.body?.length === 3,
    JSON.stringify(journal.body));

  // ---- 6. cross-tenant mutant on managed: a forged tenant claim reaches
  // a different (unprovisioned) authority, and the audience check kills a
  // plain wrong-database presentation at the worker frame ----
  const forgedTenant = await mint({
    databaseId: DB, method: "WAL_READ", session: SESSION, generation: GEN, tenantId: "tenant-b",
  });
  const crossTenant = await api("GET", `/wal/${DB}/${GEN}/head`,
    { raw: null, headers: { "x-capability": forgedTenant } });
  check("a forged tenant-B claim on tenant-A's database reaches only an unprovisioned authority",
    crossTenant.status === 403 && crossTenant.body?.error === "DATABASE_UNPROVISIONED",
    JSON.stringify(crossTenant.body));
  const wrongAudience = await api("GET", `/wal/${DB}/${GEN}/head`, {
    raw: null,
    headers: { "x-capability": await mint({ databaseId: "another-db", method: "WAL_READ", session: SESSION, generation: GEN }) },
  });
  check("audience framing refuses a wrong-database token at the worker",
    wrongAudience.status === 403 && wrongAudience.body?.error === "CAPABILITY_AUDIENCE_MISMATCH",
    JSON.stringify(wrongAudience.body));

  // ---- 7. the loopback HTTP issuer (R5-SEC-02 seam): tokens issued over
  // HTTP work against the managed surface; anonymous issuance refuses ----
  const bearerToken = randomBytes(24).toString("hex");
  const issuerServer = await startIssuerServer(ISSUER, { bearerToken });
  try {
    const httpIssued = await fetch(`${issuerServer.url}/issue`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${bearerToken}` },
      body: JSON.stringify({ spec: { databaseId: DB, method: "WAL_READ", session: SESSION, generation: GEN } }),
    });
    const httpToken = (await httpIssued.json()).token;
    const httpRead = await api("GET", `/wal/${DB}/${GEN}/head`,
      { raw: null, headers: { "x-capability": httpToken } });
    check("a token issued over the loopback HTTP issuer is accepted by the managed surface",
      httpIssued.status === 200 && httpRead.status === 200 && httpRead.body?.ok === true,
      JSON.stringify({ issue: httpIssued.status, read: httpRead.status, error: httpRead.body?.error }));
    const anonymousIssue = await fetch(`${issuerServer.url}/issue`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ spec: { databaseId: DB, method: "WAL_READ", session: SESSION, generation: GEN } }),
    });
    check("the loopback issuer refuses anonymous issuance",
      anonymousIssue.status === 401, String(anonymousIssue.status));
  } finally {
    await issuerServer.close();
  }

  console.log(failures === 0
    ? "\nMANAGED (PRODUCTION-SURFACE) STACK E2E: ALL PASS"
    : `\nMANAGED (PRODUCTION-SURFACE) STACK E2E: ${failures} FAILURES`);
  process.exitCode = failures === 0 ? 0 : 1;
} finally {
  stop();
}
