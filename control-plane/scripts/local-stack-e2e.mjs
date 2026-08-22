/*
 * L1 local-stack end-to-end: drives the production topology over real HTTP
 * against `wrangler dev` (workerd + local R2): capability issuance → payload
 * upload through the data path → digest verification → DO finalisation →
 * exact read-back, plus the ambiguity/idempotency, tamper, and capability
 * refusal-matrix cases from the protocol contract.
 *
 * F9: every data-path call carries a controller-issued capability
 * (audience/method/expiry/nonce/incarnation-bound; payload writes bind the
 * issuer-derived content-addressed key, the digest, and a byte budget).
 * The driver acts as the controller-side orchestrator, so local issuance
 * is open; the contract under proof is the refusal matrix.
 *
 * Usage: node scripts/local-stack-e2e.mjs [baseUrl]
 * Exit code 0 = every check passed.
 */

import { createHash } from "node:crypto";
// The script speaks the REAL token/provisioning protocol, so it imports the
// exact core modules the worker runs (node strips types; see package.json).
// R5-SEC-03: minting is ISSUER-SIDE - the dev-insecure Ed25519 SIGNING
// seeds live here (and in tests), while the local-dev runtime verifies
// under the committed dev PUBLIC keys.
import { mintCapabilityToken, mintProvisionToken } from "../src/controller/core/issuer.ts";
import {
  DEV_CAPABILITY_KID, DEV_ENVIRONMENT, DEV_PROVISION_KID,
  devCapabilitySigningKey, devProvisionSigningKey,
} from "../src/shared/key-config.ts";

const BASE = process.argv[2] ?? "http://127.0.0.1:8787";
const DB = `e2e-db-${process.pid}-${Date.now()}`;
/** R4 PR1: the local tenant every dev-issued token binds (worker default). */
const TENANT = "local";
const GEN = 1;
const SESSION = "sess-e2e";
/** The actor the script is currently acting AS. Donor A4 revalidates the
 *  session at the core for authority procedures (budgets, outbox ack,
 *  operation query), so the harness has to know which actor it is - a
 *  superseded one is refused there even with a valid capability. */
let CURRENT_SESSION = SESSION;
const PRINCIPAL = "e2e-driver";

let failures = 0;
function check(name, condition, detail = "") {
  const status = condition ? "PASS" : "FAIL";
  if (!condition) failures += 1;
  console.log(`${status}  ${name}${detail ? ` — ${detail}` : ""}`);
}

function sha256hex(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

async function rawApi(method, path, body, raw = false, headers = {}) {
  // A GET/HEAD request may not carry a body at all — not even `undefined`,
  // which some runtimes still reject. Build the init so the key is ABSENT.
  const payload = raw ? body : body !== undefined ? JSON.stringify(body) : undefined;
  const response = await fetch(`${BASE}${path}`, {
    method,
    ...(payload === undefined ? {} : { body: payload }),
    headers: raw ? headers : { "content-type": "application/json", ...headers },
  });
  return { status: response.status, body: await response.json() };
}

/** The L1 dev issuer credential (Q-02: issuance is credentialed in every
 *  posture; core/key-config.ts). */
const ISSUER_SECRET = "dev-insecure-issuer-secret";

/** Issue a capability from the controller (credentialed issuance). */
async function issueCap(spec) {
  const issued = await rawApi("POST", "/capability", { principal: PRINCIPAL, ttlMs: 60_000, ...spec },
    false, { "x-issuer-authorization": ISSUER_SECRET });
  if (!issued.body.ok) throw new Error(`capability issuance failed: ${JSON.stringify(issued.body)}`);
  return issued.body; // {token, key?, expiresAtMs, incarnation}
}

/** Which capability a route needs (mirror of the worker's guard map). */
function capSpecFor(method, rawPath, body) {
  const path = rawPath.split("?")[0]; // the audience derives from the path, never the query
  if (path === "/capability" || path === "/health") return null;
  if (path === "/budgets") {
    // donor A4: budgets are an authority mutation, so the capability names
    // the actor and the CORE revalidates that the actor is still live
    return { databaseId: body.databaseId, method: "BUDGETS_SET", session: CURRENT_SESSION };
  }
  if (path.startsWith("/session/")) {
    // R4-SEC-04: each lifecycle transition is its own exact action, bound
    // to the exact TARGET actor (token.session === body.startupSessionId)
    const action = {
      "/session/register": "SESSION_REGISTER",
      "/session/reserve": "SESSION_RESERVE",
      "/session/attest": "SESSION_ATTEST",
      "/session/activate": "SESSION_ACTIVATE",
      "/session/renew": "SESSION_RENEW",
      "/session/drain": "SESSION_DRAIN",
      "/session/revoke": "SESSION_REVOKE",
      "/session/fence": "SESSION_FENCE",
    }[path];
    if (!action) throw new Error(`no capability mapping for ${path}`);
    const spec = { databaseId: body.databaseId, method: action, session: body.startupSessionId };
    if (["SESSION_REGISTER", "SESSION_RESERVE", "SESSION_ACTIVATE"].includes(action)) {
      spec.generation = body.generation;
    }
    return spec;
  }
  // finalize capabilities are SESSION-bound (donor A3): the token carries
  // the actor identity, so a disclosed session id is not itself write authority
  if (path === "/wal/finalize") {
    // C-05: finalize tokens bind session AND generation
    return { databaseId: body.databaseId, method: "WAL_FINALIZE",
             session: body.startupSessionId, generation: body.generation };
  }
  if (path === "/wal/finalize-batch") {
    return { databaseId: body.requests[0].databaseId, method: "WAL_FINALIZE",
             session: body.requests[0].startupSessionId, generation: body.requests[0].generation };
  }
  let m = path.match(/^\/wal\/([^/]+)\/\d+\/operation\//);
  if (m) return { databaseId: m[1], method: "WAL_READ", session: CURRENT_SESSION, generation: GEN };
  m = path.match(/^\/wal\/([^/]+)\//);
  // R4-SEC-05: every runtime read token is actor-bound
  if (m) return { databaseId: m[1], method: "WAL_READ", session: CURRENT_SESSION, generation: GEN };
  m = path.match(/^\/outbox\/([^/]+)\/ack$/);
  if (m) return { databaseId: m[1], method: "OUTBOX", session: CURRENT_SESSION };
  m = path.match(/^\/outbox\/([^/]+)/);
  if (m) return { databaseId: m[1], method: "OUTBOX" };
  m = path.match(/^\/journal\/([^/]+)\/verify(-anchored)?$/);
  if (m) return { databaseId: m[1], method: "JOURNAL_VERIFY" };
  m = path.match(/^\/checkpoint\/([^/]+)\/\d+\/active$/);
  if (m) return { databaseId: m[1], method: "WAL_READ", session: CURRENT_SESSION, generation: GEN };
  m = path.match(/^\/checkpoint\/([^/]+)\/cut\/[^/]+\/activate$/);
  if (m) return { databaseId: m[1], method: "CHECKPOINT_ACTIVATE", session: CURRENT_SESSION, generation: GEN };
  m = path.match(/^\/checkpoint\/([^/]+)\//);
  if (m) return { databaseId: m[1], method: "CHECKPOINT_OPEN", session: CURRENT_SESSION, generation: GEN };
  m = path.match(/^\/admin\/([^/]+)\//);
  if (m) return { databaseId: m[1], method: "INCARNATION_BUMP" };
  throw new Error(`no capability mapping for ${method} ${path}`);
}

/** api() with automatic single-use capability acquisition. */
async function api(method, path, body, raw = false, opts = {}) {
  const headers = {};
  if (!opts.noCap) {
    const token = opts.token ?? (await issueCap(capSpecFor(method, path, body))).token;
    headers["x-capability"] = token;
  }
  return rawApi(method, path, body, raw, headers);
}

/** Upload bytes through the capability-bound payload path; returns the
 *  issuer-derived content-addressed key + receipt. */
async function uploadPayload(bytes, opts = {}) {
  const digest = sha256hex(bytes);
  const cap = await issueCap({
    databaseId: DB, method: "PUT_PAYLOAD", digest, maxBytes: bytes.length, ...opts.capOverrides,
  });
  const key = opts.key ?? cap.key;
  const response = await rawApi("PUT", `/payload/${key}`, bytes, true, { "x-capability": opts.token ?? cap.token });
  return { key, digest, length: bytes.length, response };
}

/** The three finalize payload fields, always derived from ONE upload
 *  receipt - hand-pairing a key with another payload's length was possible
 *  at every call site before this. */
function payloadFields(up) {
  return { payloadKey: up.key, payloadDigest: up.digest, payloadLength: up.length };
}

const health = await rawApi("GET", "/health");
check("health", health.body.ok === true, JSON.stringify(health.body));

// Q-02: capability issuance is credentialed - anonymous issuance was the
// audit's Q-02 finding, and the refusal must hold in every posture,
// including this local one.
const anonIssue = await rawApi("POST", "/capability",
  { principal: PRINCIPAL, databaseId: DB, method: "WAL_READ", session: CURRENT_SESSION, generation: GEN });
check("anonymous capability issuance is refused",
  anonIssue.status === 401 && anonIssue.body.error === "ISSUER_UNAUTHORIZED",
  JSON.stringify(anonIssue.body));
const wrongIssuer = await rawApi("POST", "/capability",
  { principal: PRINCIPAL, databaseId: DB, method: "WAL_READ", session: CURRENT_SESSION, generation: GEN },
  false, { "x-issuer-authorization": "not-the-issuer-secret-at-all" });
check("a wrong issuer credential is refused",
  wrongIssuer.status === 401 && wrongIssuer.body.error === "ISSUER_UNAUTHORIZED",
  JSON.stringify(wrongIssuer.body));

// ---- R4 PR1: the registry provisioning transaction gates EVERYTHING ----
// Before provisioning, the authority is unbound: issuance refuses, and an
// ordinary authenticated call (a directly minted, fully valid dev-key
// token) fails closed with no binding side effect (the squat mutant).
const preProvisionIssue = await rawApi("POST", "/capability",
  { principal: PRINCIPAL, databaseId: DB, method: "WAL_READ", session: SESSION, generation: GEN },
  false, { "x-issuer-authorization": ISSUER_SECRET });
check("issuance to an unprovisioned database is refused",
  preProvisionIssue.status === 409 && preProvisionIssue.body.error === "DATABASE_UNPROVISIONED",
  JSON.stringify(preProvisionIssue.body));
const squatToken = await mintCapabilityToken(devCapabilitySigningKey(), {
  v: 3, alg: "Ed25519", kid: DEV_CAPABILITY_KID, env: DEV_ENVIRONMENT, tenantId: TENANT,
  principal: PRINCIPAL, databaseId: DB, method: "WAL_READ", session: SESSION, generation: String(GEN),
  incarnation: 1, nonce: `n-squat-${Date.now()}`, expiresAtMs: Date.now() + 60_000,
});
const squat = await rawApi("GET", `/wal/${DB}/${GEN}/head`, undefined, false, { "x-capability": squatToken });
check("an ordinary authenticated call to an unprovisioned authority fails closed (squat mutant)",
  squat.status === 403 && squat.body.error === "DATABASE_UNPROVISIONED", JSON.stringify(squat.body));

const provisionTokenFor = (databaseId) => mintProvisionToken(devProvisionSigningKey(),
  { environment: DEV_ENVIRONMENT, tenantId: TENANT, databaseId },
  { nonce: `n-prov-${databaseId}-${Date.now()}`, expiresAtMs: Date.now() + 60_000, kid: DEV_PROVISION_KID });
// cross-scope mutant at the wire (R5-SEC-03): a provision token SIGNED
// with the ordinary CAPABILITY keypair must not bind anything - the
// signature cannot verify under the provisioning scope's public key
const forgedProvision = await mintProvisionToken(devCapabilitySigningKey(),
  { environment: DEV_ENVIRONMENT, tenantId: TENANT, databaseId: DB },
  { nonce: "n-forged", expiresAtMs: Date.now() + 60_000, kid: DEV_PROVISION_KID });
const forgedBind = await rawApi("POST", "/provision", { tenantId: TENANT, databaseId: DB },
  false, { "x-provision": forgedProvision });
check("capability-scope material cannot provision (mint/verify separation)",
  forgedBind.status === 403 && forgedBind.body.error === "CAPABILITY_SIGNATURE_INVALID",
  JSON.stringify(forgedBind.body));
const provisioned = await rawApi("POST", "/provision", { tenantId: TENANT, databaseId: DB },
  false, { "x-provision": await provisionTokenFor(DB) });
check("the internal PROVISION capability binds the authority exactly once",
  provisioned.status === 200 && provisioned.body.ok === true && provisioned.body.created === true,
  JSON.stringify(provisioned.body));
const reProvisioned = await rawApi("POST", "/provision", { tenantId: TENANT, databaseId: DB },
  false, { "x-provision": await provisionTokenFor(DB) });
check("an identical re-provision is idempotent, never a second binding",
  reProvisioned.status === 200 && reProvisioned.body.created === false,
  JSON.stringify(reProvisioned.body));
// the capability refusal-matrix section below issues a token for other-db
// (audience mutant), so that authority must exist too
const otherDb = await rawApi("POST", "/provision", { tenantId: TENANT, databaseId: "other-db" },
  false, { "x-provision": await provisionTokenFor("other-db") });
check("second database provisions independently", otherDb.status === 200, JSON.stringify(otherDb.body));

await api("POST", "/session/register", { databaseId: DB, generation: GEN, startupSessionId: SESSION });

// Q-12: a database with no validated budget row denies writes. The refusal
// is exercised first (missing budget = deny, never unlimited), then a real
// budget is installed for the rest of the run.
const preBudgetPayload = Buffer.from("pre-budget-refused");
const preBudgetUp = await uploadPayload(preBudgetPayload);
const preBudget = await api("POST", "/wal/finalize", {
  databaseId: DB, generation: GEN, startupSessionId: SESSION,
  operationId: "op-pre-budget", sequencingKind: "SEQUENCED", recordType: 2, logicalKey: null,
  ...payloadFields(preBudgetUp),
});
check("a database with no budget row denies writes",
  preBudget.status === 409 && preBudget.body.error === "ADMISSION_REJECTED_NO_BUDGET",
  JSON.stringify(preBudget.body));
const budgetInstalled = await api("POST", "/budgets", {
  databaseId: DB, maxUnpublishedOutbox: 10_000, maxPayloadLength: 1_000_000, maxTailRecords: 1_000_000,
});
check("a validated budget opens admission", budgetInstalled.body.ok === true,
  JSON.stringify(budgetInstalled.body));
const badBudget = await api("POST", "/budgets", {
  databaseId: DB, maxUnpublishedOutbox: 1.5, maxPayloadLength: 1_000_000, maxTailRecords: 1_000_000,
});
check("a fractional budget is a typed refusal, never a coercion",
  badBudget.status === 409 && badBudget.body.error === "INVALID_BUDGET"
  && badBudget.body.field === "maxUnpublishedOutbox", JSON.stringify(badBudget.body));

// 1. payload through the data path, then finalisation
const payload1 = Buffer.from("commit-record-1");
const up1 = await uploadPayload(payload1);
check("payload upload digest agrees", up1.response.body.sha256hex === up1.digest, JSON.stringify(up1.response.body));
check("payload key is issuer-derived and content-addressed",
  up1.key === `p/${DB}/${up1.digest}`, up1.key);

const finalizeRequest = {
  databaseId: DB, generation: GEN, startupSessionId: SESSION,
  operationId: "op-1",
  sequencingKind: "SEQUENCED", recordType: 2, logicalKey: null,
  ...payloadFields(up1),
};
const f1 = await api("POST", "/wal/finalize", finalizeRequest);
check("finalize allocates lsn 0", f1.body.ok === true && f1.body.appendLsn === "0" && f1.body.replayed === false,
  JSON.stringify(f1.body));

// 2. lost-response ambiguity: identical retry replays the SAME allocation
const f1retry = await api("POST", "/wal/finalize", finalizeRequest);
check("ambiguous retry replays identically",
  f1retry.body.ok === true && f1retry.body.appendLsn === "0" && f1retry.body.replayed === true);

// 3. tampered digest: the key is content-addressed (C-P0-07), so a digest
// that disagrees with the key is a NON-CANONICAL REFERENCE, refused with
// ZERO R2 I/O - strictly earlier and stronger than the old data-path 422
// (the 422 PAYLOAD_DIGEST_MISMATCH branch remains as defense in depth
// against store corruption, unreachable through the honest API)
const tampered = { ...finalizeRequest, operationId: "op-tampered", payloadDigest: "0".repeat(64) };
const ft = await api("POST", "/wal/finalize", tampered);
check("a digest disagreeing with the content-addressed key is refused pre-I/O",
  ft.status === 400 && ft.body.error === "NON_CANONICAL_PAYLOAD_KEY", JSON.stringify(ft.body));

// 3b. C-P0-07: a foreign/global object reference (a key outside this
// database's canonical namespace) is refused before any R2 GET
const crossRef = { ...finalizeRequest, operationId: "op-cross",
  payloadKey: `p/other-db/${up1.digest}` };
const fx = await api("POST", "/wal/finalize", crossRef);
check("a cross-database payload reference is refused pre-I/O",
  fx.status === 400 && fx.body.error === "NON_CANONICAL_PAYLOAD_KEY", JSON.stringify(fx.body));

// 4. a CANONICAL reference to a never-uploaded payload reaches the data
// path and is rejected there
const ghostDigest = "f".repeat(64);
const ghost = { ...finalizeRequest, operationId: "op-ghost",
  payloadKey: `p/${DB}/${ghostDigest}`, payloadDigest: ghostDigest };
const fg = await api("POST", "/wal/finalize", ghost);
check("data path rejects missing payload", fg.status === 422 && fg.body.error === "PAYLOAD_MISSING");

// 5. status singleton over HTTP
const statusPayload = Buffer.from("status-A");
const upStatus = await uploadPayload(statusPayload);
const s1 = await api("POST", "/wal/finalize", {
  ...finalizeRequest, operationId: "st-1", sequencingKind: "UNSEQUENCED",
  recordType: 1,
  logicalKey: "status:cp", ...payloadFields(upStatus),
});
check("status singleton accepted", s1.body.ok === true);

const statusB = Buffer.from("status-B-conflicting");
const upStatusB = await uploadPayload(statusB);
const s2 = await api("POST", "/wal/finalize", {
  ...finalizeRequest, operationId: "st-2", sequencingKind: "UNSEQUENCED",
  logicalKey: "status:cp", ...payloadFields(upStatusB),
});
check("conflicting status rejected", s2.status === 409 && s2.body.error === "STATUS_CONFLICT");

// 5b. Q-18: the replay/dedupe digest is derived from the canonical request,
// never asserted by the caller. A caller-supplied digest that disagrees with
// the request it claims to describe is refused - otherwise sending operation
// X's digest with body Y would hand back X's receipt for Y.
const forgedDigest = await api("POST", "/wal/finalize", {
  ...finalizeRequest, operationId: "op-forged-digest", requestDigest: "f".repeat(64),
});
check("a caller-supplied request digest that disagrees with the request is refused",
  forgedDigest.status === 400 && forgedDigest.body.error === "REQUEST_DIGEST_MISMATCH",
  JSON.stringify(forgedDigest.body));

// 6. exact read-back through the data path
const read = await api("GET", `/wal/${DB}/${GEN}/0`);
check("exact read returns the exact payload",
  read.body.ok === true && Buffer.from(read.body.payloadBase64, "base64").equals(payload1));
const miss = await api("GET", `/wal/${DB}/${GEN}/99`);
check("exact read miss is typed NOT_FOUND", miss.status === 404 && miss.body.error === "NOT_FOUND");

// 8. contiguity audit
const audit = await api("GET", `/wal/${DB}/${GEN}/audit`);
check("tail contiguous", audit.body.contiguous === true && audit.body.count === 2 && audit.body.maxLsn === "1",
  JSON.stringify(audit.body));

// 8b. payload immutability at the capability boundary: different bytes can
// never be placed at an existing key - the key/digest binding refuses
// BEFORE R2 (the conditional create underneath remains as defense in depth)
const differentBytes = Buffer.from("DIFFERENT BYTES");
const overwrite = await uploadPayload(differentBytes, { key: up1.key });
check("different bytes at an existing key are refused by the capability binding",
  overwrite.response.status === 403 && overwrite.response.body.error === "CAPABILITY_KEY_MISMATCH",
  JSON.stringify(overwrite.response.body));
const idempotentPut = await uploadPayload(payload1);
check("identical re-upload is idempotent", idempotentPut.response.status === 200
  && idempotentPut.response.body.deduplicated === true);

// 9. outbox consumer loop: at-least-once peek/ack with redelivery
const peek1 = await api("GET", `/outbox/${DB}?limit=10`);
// the bus carries the COMMAND LEDGER too (F7r): the DATABASE_PROVISIONED
// and session/budget commands ride alongside the two WAL_RECORD_FINALIZED
// events (the fence command lands after this section - the outbox must be
// drained by a LIVE actor, donor A4)
const walEvents = peek1.body.events.filter((e) => e.kind === "WAL_RECORD_FINALIZED");
check("outbox peek returns finalized + command events",
  peek1.body.ok && walEvents.length === 2 && peek1.body.events.length === 5,
  `events=${peek1.body.events?.length} wal=${walEvents.length}`);
const peek2 = await api("GET", `/outbox/${DB}?limit=10`);
check("unacked events are redelivered", peek2.body.events.length === peek1.body.events.length);
const kinds = new Set(peek1.body.events.map((e) => e.kind));
check("events carry canonical bodies", kinds.has("WAL_RECORD_FINALIZED") && kinds.has("SESSION_ACTIVATED") &&
  peek1.body.events.every((e) => JSON.parse(e.body).databaseId === DB));
// controlSeq is a decimal-string u64 on the wire (F7): compare as bigint
const maxSeq = peek1.body.events.map((e) => BigInt(e.controlSeq)).reduce((a, b) => (a > b ? a : b)).toString();
const ack = await api("POST", `/outbox/${DB}/ack`, { upToControlSeq: maxSeq });
check("ack marks events", ack.body.ok && ack.body.acked === 5, JSON.stringify(ack.body));
const peek3 = await api("GET", `/outbox/${DB}?limit=10`);
check("acked events are not redelivered", peek3.body.events.length === 0);
const ackAgain = await api("POST", `/outbox/${DB}/ack`, { upToControlSeq: maxSeq });
check("duplicate ack is idempotent", ackAgain.body.acked === 0);

// 9b. donor A4: the outbox is acked BY THE CURRENT ACTOR. A superseded actor
// holding a still-valid OUTBOX capability must not be able to mark control
// events published - that would silently drop them for its successor. The
// capability layer cannot see this: the token is MAC-valid and unexpired.
const staleAckToken = (await issueCap({ databaseId: DB, method: "OUTBOX", session: "sess-never-registered" })).token;
const staleAck = await rawApi("POST", `/outbox/${DB}/ack`, { upToControlSeq: maxSeq }, false,
  { "x-capability": staleAckToken });
check("an unregistered actor cannot ack the outbox",
  staleAck.status === 409 && staleAck.body.error === "SESSION_UNKNOWN", JSON.stringify(staleAck.body));

// 7. fencing over HTTP
await api("POST", "/session/fence", { databaseId: DB, generation: GEN, startupSessionId: SESSION });
const fenced = await api("POST", "/wal/finalize", {
  ...finalizeRequest, operationId: "op-after-fence",
});
check("fenced session rejected", fenced.status === 409 && fenced.body.error === "SESSION_FENCED");


// 9c. Q-03 / 12.4: the lifecycle over HTTP. Reservation and attestation
// grant nothing; a made-up id activates nothing; the verified activation is
// the takeover.
const lcReserve = await api("POST", "/session/reserve",
  { databaseId: DB, generation: GEN, startupSessionId: "sess-lc", holder: "e2e-host" });
check("lifecycle: reservation accepted", lcReserve.body.ok === true, JSON.stringify(lcReserve.body));
const lcEarlyActivate = await api("POST", "/session/activate",
  { databaseId: DB, generation: GEN, startupSessionId: "sess-lc", processNonce: "n-lc", leaseMs: 60000 });
check("lifecycle: activation before attestation is refused",
  lcEarlyActivate.status === 409 && lcEarlyActivate.body.error === "SESSION_NOT_ATTESTED",
  JSON.stringify(lcEarlyActivate.body));
const lcAttest = await api("POST", "/session/attest",
  { databaseId: DB, startupSessionId: "sess-lc", processNonce: "n-lc" });
check("lifecycle: attestation accepted", lcAttest.body.ok === true, JSON.stringify(lcAttest.body));
const lcWrongNonce = await api("POST", "/session/activate",
  { databaseId: DB, generation: GEN, startupSessionId: "sess-lc", processNonce: "n-imposter", leaseMs: 60000 });
check("lifecycle: activation with a hijacked nonce is refused",
  lcWrongNonce.status === 409 && lcWrongNonce.body.error === "PROCESS_NONCE_MISMATCH",
  JSON.stringify(lcWrongNonce.body));
const lcGhostActivate = await api("POST", "/session/activate",
  { databaseId: DB, generation: GEN, startupSessionId: "sess-never-reserved", processNonce: "n", leaseMs: 60000 });
check("lifecycle: a fresh random id cannot activate (or fence anyone)",
  lcGhostActivate.status === 409 && lcGhostActivate.body.error === "SESSION_NOT_RESERVED",
  JSON.stringify(lcGhostActivate.body));
const lcActivate = await api("POST", "/session/activate",
  { databaseId: DB, generation: GEN, startupSessionId: "sess-lc", processNonce: "n-lc", leaseMs: 60000 });
check("lifecycle: verified activation succeeds under a controller-time lease",
  lcActivate.body.ok === true && typeof lcActivate.body.leaseDeadlineMs === "number"
  // SESSION was already fenced in the fencing section, so this activation
  // finds no live predecessor - the takeover COUNT is exercised in the core
  // lifecycle suite; here the wire shape and the lease are under test
  && lcActivate.body.fencedPredecessors === 0, JSON.stringify(lcActivate.body));
CURRENT_SESSION = "sess-lc";
const lcRenew = await api("POST", "/session/renew",
  { databaseId: DB, startupSessionId: "sess-lc", leaseMs: 120000 });
check("lifecycle: an unexpired lease renews from controller time",
  lcRenew.body.ok === true && lcRenew.body.leaseDeadlineMs > lcActivate.body.leaseDeadlineMs,
  JSON.stringify(lcRenew.body));
const lcReuse = await api("POST", "/session/reserve",
  { databaseId: DB, generation: GEN, startupSessionId: SESSION, holder: "someone-else" });
check("lifecycle: a spent session id is a permanent refusal",
  lcReuse.status === 409 && lcReuse.body.error === "SESSION_ID_ALREADY_USED",
  JSON.stringify(lcReuse.body));

// 10. register-fences-predecessor over HTTP (takeover; three-lane pin)
await api("POST", "/session/register", { databaseId: DB, generation: GEN, startupSessionId: "sess-2" });
CURRENT_SESSION = "sess-2";
const payload2 = Buffer.from("commit-record-2");
const up2 = await uploadPayload(payload2);
const takeover = await api("POST", "/wal/finalize", {
  ...finalizeRequest, startupSessionId: "sess-2", operationId: "op-2",
  ...payloadFields(up2),
});
check("new actor appends after taking over", takeover.body.ok === true && takeover.body.appendLsn === "2");
await api("POST", "/session/register", { databaseId: DB, generation: GEN, startupSessionId: "sess-3" });
CURRENT_SESSION = "sess-3";
const fencedByRegister = await api("POST", "/wal/finalize", {
  ...finalizeRequest, startupSessionId: "sess-2", operationId: "op-2b",
  ...payloadFields(up2),
});
check("register fences the predecessor, and the refusal names no holder",
  fencedByRegister.status === 409 && fencedByRegister.body.error === "SESSION_FENCED" &&
  fencedByRegister.body.fencedBy === undefined &&
  Object.keys(fencedByRegister.body).sort().join(",") === "error,ok",
  JSON.stringify(fencedByRegister.body));
const payload3 = Buffer.from("commit-record-3");
const up3 = await uploadPayload(payload3);
const f3 = await api("POST", "/wal/finalize", {
  ...finalizeRequest, startupSessionId: "sess-3", operationId: "op-3",
  ...payloadFields(up3),
});
check("current actor appends lsn 3", f3.body.ok === true && f3.body.appendLsn === "3");

// 11. head: TypeSequence, not physical LSN (they diverge here: 4 records, 3 sequenced)
const head = await api("GET", `/wal/${DB}/${GEN}/head`);
check("head reports lsn and type sequence",
  head.body.ok === true && head.body.headLsn === "3" && head.body.headTypeSequence === "3",
  JSON.stringify(head.body));

// 12. pinned iterator + ordered scan with verified inline payloads
const iter = await api("POST", `/wal/${DB}/${GEN}/iterator`);
check("iterator pins the head and returns an opaque server-owned snapshot id",
  iter.body.ok === true && iter.body.headLsn === "3"
  && /^3\.[0-9a-f]{64}$/.test(iter.body.snapshotId ?? ""), JSON.stringify(iter.body));
const SNAP = `snapshotId=${encodeURIComponent(iter.body.snapshotId)}`;
const scan = await api("GET", `/wal/${DB}/${GEN}/scan?fromTs=1&${SNAP}&limit=100`);
check("scan replays in physical order",
  scan.body.ok === true &&
  JSON.stringify(scan.body.records.map((r) => [r.appendLsn, r.typeSequence, r.recordType])) ===
    JSON.stringify([["0", "1", 2], ["1", "1", 1], ["2", "2", 2], ["3", "3", 2]]),
  JSON.stringify(scan.body.records?.map((r) => [r.appendLsn, r.typeSequence, r.recordType])));
check("scan payloads round-trip",
  Buffer.from(scan.body.records[0].payloadBase64, "base64").equals(payload1) &&
  Buffer.from(scan.body.records[3].payloadBase64, "base64").equals(payload3));
const scanTyped = await api("GET", `/wal/${DB}/${GEN}/scan?fromTs=0&${SNAP}&recordType=1&limit=100`);
check("scan filters by record type", scanTyped.body.records.length === 1 && scanTyped.body.records[0].appendLsn === "1");
const scanUnbounded = await api("GET", `/wal/${DB}/${GEN}/scan?fromTs=0&limit=100`);
check("unbounded scan is refused (pinned snapshot is mandatory)",
  scanUnbounded.status === 400 && scanUnbounded.body.error === "MISSING_SNAPSHOT_ID",
  JSON.stringify(scanUnbounded.body));
// Q-12 / 12.6: the CUT is server-owned. A caller may not name it...
const scanCallerBound = await api("GET", `/wal/${DB}/${GEN}/scan?fromTs=0&${SNAP}&throughLsn=99`);
check("a caller-supplied scan bound is refused",
  scanCallerBound.status === 400 && scanCallerBound.body.error === "CALLER_SUPPLIED_SNAPSHOT_BOUND",
  JSON.stringify(scanCallerBound.body));
// ...and may not forge or widen one
const forgedHead = `99.${iter.body.snapshotId.split(".")[1]}`;
const scanForged = await api("GET",
  `/wal/${DB}/${GEN}/scan?fromTs=0&snapshotId=${encodeURIComponent(forgedHead)}`);
check("a snapshot id whose head was rewritten is refused",
  scanForged.status === 400 && scanForged.body.error === "INVALID_SNAPSHOT_ID",
  JSON.stringify(scanForged.body));
const scanOtherDb = await api("GET", `/wal/${DB}/${GEN + 1}/scan?fromTs=0&${SNAP}`);
check("a snapshot id from another generation is refused",
  scanOtherDb.status === 400 && scanOtherDb.body.error === "INVALID_SNAPSHOT_ID",
  JSON.stringify(scanOtherDb.body));
const scanPastEnd = await api("GET", `/wal/${DB}/${GEN}/scan?fromTs=0&fromLsn=9&${SNAP}`);
check("a continuation outside its own snapshot is a typed refusal, not an empty page",
  scanPastEnd.status === 400 && scanPastEnd.body.error === "CONTINUATION_OUTSIDE_SNAPSHOT",
  JSON.stringify(scanPastEnd.body));
const scanZeroLimit = await api("GET", `/wal/${DB}/${GEN}/scan?fromTs=0&${SNAP}&limit=0`);
check("limit=0 is clamped to one record, never a crash",
  scanZeroLimit.body.ok === true && scanZeroLimit.body.records.length === 1 && scanZeroLimit.body.nextFromLsn === "1");
const scanBadParam = await api("GET", `/wal/${DB}/${GEN}/scan?fromTs=abc&${SNAP}`);
check("non-numeric scan parameter is a typed 400",
  scanBadParam.status === 400 && scanBadParam.body.error === "INVALID_PARAMETER");
// byte budget: a budget of exactly the first record's length forces a one-record page (progress guaranteed),
// resumable exactly like a limit cut
const oneRecordBudget = payload1.length; // exactly the first record, nothing more
const scanByteCut = await api("GET", `/wal/${DB}/${GEN}/scan?fromTs=0&${SNAP}&maxBytes=${oneRecordBudget}`);
check("scan byte budget cuts the page with progress",
  scanByteCut.body.ok === true && scanByteCut.body.records.length === 1 && scanByteCut.body.nextFromLsn === "1",
  JSON.stringify({ n: scanByteCut.body.records?.length, next: scanByteCut.body.nextFromLsn }));
const scanResume = await api("GET", `/wal/${DB}/${GEN}/scan?fromTs=0&fromLsn=${scanByteCut.body.nextFromLsn}&${SNAP}&maxBytes=${statusPayload.length}`);
check("byte-cut pages resume without overlap",
  scanResume.body.records.length === 1 && scanResume.body.records[0].appendLsn === "1");
// a descriptor larger than the WHOLE page budget is refused before any
// fetch - "record zero" is not an exception (directive 12.6)
const scanTooSmall = await api("GET", `/wal/${DB}/${GEN}/scan?fromTs=0&${SNAP}&maxBytes=1`);
check("a first record larger than the page budget is refused, not admitted",
  scanTooSmall.status === 413 && scanTooSmall.body.error === "RECORD_EXCEEDS_PAGE_BUDGET",
  JSON.stringify(scanTooSmall.body));

// a finalized operation stays queryable by operation id after ITS finalizing
// session was fenced (op-1 was finalized by SESSION, since superseded). The
// READER is the current actor: donor A4 revalidates the caller's own session
// at the core, so history survives a fence but a fenced reader does not.
const opQuery = await api("GET", `/wal/${DB}/${GEN}/operation/op-1`);
check("finalized operation queryable after fencing",
  opQuery.body.ok === true && opQuery.body.record.appendLsn === "0"
  && /^[0-9a-f]{64}$/.test(opQuery.body.requestDigest), JSON.stringify(opQuery.body).slice(0, 200));
const opMiss = await api("GET", `/wal/${DB}/${GEN}/operation/op-ghost-never`);
check("operation query miss is typed NOT_FOUND", opMiss.status === 404 && opMiss.body.error === "NOT_FOUND");
// donor A4: a superseded actor reads nothing, capability or not
const staleReadToken = (await issueCap({ databaseId: DB, method: "WAL_READ", session: SESSION, generation: GEN })).token;
const staleRead = await rawApi("GET", `/wal/${DB}/${GEN}/operation/op-1`, undefined, false,
  { "x-capability": staleReadToken });
check("a fenced actor cannot read the operation surface",
  staleRead.status === 409
  && (staleRead.body.error === "SESSION_NOT_ACTIVE" || staleRead.body.error === "SESSION_FENCED"),
  JSON.stringify(staleRead.body));

// 13. last-by-type
const last = await api("GET", `/wal/${DB}/${GEN}/last?recordType=1`);
check("last-by-type finds the status record", last.body.ok === true && last.body.record.appendLsn === "1");
const lastMiss = await api("GET", `/wal/${DB}/${GEN}/last?recordType=99`);
check("last-by-type miss is typed NOT_FOUND", lastMiss.status === 404 && lastMiss.body.error === "NOT_FOUND");
const badType = await api("POST", "/wal/finalize", {
  ...finalizeRequest, startupSessionId: "sess-3", operationId: "op-bad-type", recordType: 999,
});
check("out-of-range record type is a typed 400", badType.status === 400 && badType.body.error === "INVALID_RECORD_TYPE");

// 14. batch finalize: all-or-nothing over HTTP
const batchA = Buffer.from("batch-record-A");
const batchB = Buffer.from("batch-record-B");
const upA = await uploadPayload(batchA);
const upB = await uploadPayload(batchB);
const batchOk = await api("POST", "/wal/finalize-batch", { batchOperationId: "bo-1", requests: [
  { ...finalizeRequest, startupSessionId: "sess-3", operationId: "bb-1",
    ...payloadFields(upA), },
  { ...finalizeRequest, startupSessionId: "sess-3", operationId: "bb-2",
    ...payloadFields(upB), },
]});
check("batch finalize allocates contiguously",
  batchOk.body.ok === true && JSON.stringify(batchOk.body.results.map((r) => r.appendLsn)) === JSON.stringify(["4", "5"]),
  JSON.stringify(batchOk.body));
const batchAborted = await api("POST", "/wal/finalize-batch", { batchOperationId: "bo-2", requests: [
  { ...finalizeRequest, startupSessionId: "sess-3", operationId: "bb-3",
    ...payloadFields(upA), },
  { ...finalizeRequest, startupSessionId: "sess-3", operationId: "bb-4",
    sequencingKind: "UNSEQUENCED", recordType: 1, logicalKey: "status:cp",
    ...payloadFields(upB), },
]});
check("failing member aborts the whole batch",
  batchAborted.status === 409 && batchAborted.body.error === "STATUS_CONFLICT");
const auditAfterBatch = await api("GET", `/wal/${DB}/${GEN}/audit`);
check("aborted batch allocated nothing",
  auditAfterBatch.body.contiguous === true && auditAfterBatch.body.count === 6, JSON.stringify(auditAfterBatch.body));

// 12.6: a batch without its envelope is refused, and one batch id may never
// name a different set of members
const batchUnnamed = await api("POST", "/wal/finalize-batch", { requests: [
  { ...finalizeRequest, startupSessionId: "sess-3", operationId: "bb-5",
    ...payloadFields(upA), },
] });
check("a batch without an envelope is refused",
  batchUnnamed.status === 400 && batchUnnamed.body.error === "BATCH_ENVELOPE_REQUIRED",
  JSON.stringify(batchUnnamed.body));
const batchReused = await api("POST", "/wal/finalize-batch", { batchOperationId: "bo-1", requests: [
  { ...finalizeRequest, startupSessionId: "sess-3", operationId: "bb-6",
    ...payloadFields(upA), },
] });
check("the same batch id with different members is a permanent conflict",
  batchReused.status === 409 && batchReused.body.error === "BATCH_DIGEST_CONFLICT",
  JSON.stringify(batchReused.body));

// 15. F9 capability refusal matrix - every denial is typed, nothing reaches
// the authority or the store
const noToken = await rawApi("GET", `/wal/${DB}/${GEN}/head`);
check("missing capability is a typed 401", noToken.status === 401 && noToken.body.error === "CAPABILITY_REQUIRED");

const readCap = await issueCap({ databaseId: DB, method: "WAL_READ", session: CURRENT_SESSION, generation: GEN });
const flipped = readCap.token.slice(0, -1) + (readCap.token.endsWith("0") ? "1" : "0");
const badMac = await rawApi("GET", `/wal/${DB}/${GEN}/head`, undefined, false, { "x-capability": flipped });
check("tampered signature is refused", badMac.status === 403 && badMac.body.error === "CAPABILITY_SIGNATURE_INVALID");

// C-07: reads are STATELESS - side-effect-free, so a read token records no
// durable use row and is freely replayable across different read requests.
const once = await rawApi("GET", `/wal/${DB}/${GEN}/head`, undefined, false, { "x-capability": readCap.token });
const readReplay = await rawApi("GET", `/wal/${DB}/${GEN}/0`, undefined, false, { "x-capability": readCap.token });
check("C-07: a read token is stateless and replayable (no durable use row)",
  once.status === 200 && readReplay.status === 200,
  JSON.stringify({ once: once.status, readReplay: readReplay.status }));

// C-02: a MUTATING token is single-REQUEST. Reusing one BUDGETS_SET token
// for the SAME budgets request twice must NOT apply budgets twice - the
// terminal use replays its stored response (the audit's double-BUDGETS_SET
// mutant). A DIFFERENT request under the same token is a replay refusal.
// SESSION is fenced by this point in the flow, so the underlying budgets
// call refuses - but the SINGLE-REQUEST property is what matters: whatever
// the first outcome is, the identical retry REPLAYS it byte-identically
// (same status + body) and a DIFFERENT request under the same token is a
// replay refusal. That is the double-BUDGETS_SET mutant killed.
const budgetsBody = { databaseId: DB, maxUnpublishedOutbox: 500, maxPayloadLength: 4096, maxTailRecords: 500 };
const budgetToken = (await issueCap({ databaseId: DB, method: "BUDGETS_SET", session: CURRENT_SESSION })).token;
const budgetOnce = await rawApi("POST", "/budgets", budgetsBody, false, { "x-capability": budgetToken });
const budgetRetry = await rawApi("POST", "/budgets", budgetsBody, false, { "x-capability": budgetToken });
const budgetDifferent = await rawApi("POST", "/budgets",
  { ...budgetsBody, maxTailRecords: 999 }, false, { "x-capability": budgetToken });
check("C-02: a mutating token is single-request; identical retry replays, different request refused",
  budgetOnce.status === budgetRetry.status
    && JSON.stringify(budgetOnce.body) === JSON.stringify(budgetRetry.body)
    && budgetDifferent.status === 403 && budgetDifferent.body.error === "CAPABILITY_REPLAYED",
  JSON.stringify({ once: budgetOnce.status, retry: budgetRetry.status, different: budgetDifferent.body }));

const readCap2 = await issueCap({ databaseId: DB, method: "WAL_READ", session: CURRENT_SESSION, generation: GEN });
// no caller-supplied requestDigest: a mismatching one is a 400 BEFORE the
// capability is consulted (invalid input must not burn a token), and this
// check is about the method binding refusal
const wrongMethod = await rawApi("POST", "/wal/finalize", { ...finalizeRequest, operationId: "op-wm" },
  false, { "x-capability": readCap2.token });
check("method binding: a read token cannot finalize",
  wrongMethod.status === 403 && wrongMethod.body.error === "CAPABILITY_METHOD_MISMATCH");

// session binding (donor A3): a finalize capability bound to session sess-3
// cannot authorize a finalize request that claims a DIFFERENT session, even
// though that session is a live unfenced actor. Knowing a session id is not
// write authority.
const otherSessionCap = await issueCap({ databaseId: DB, method: "WAL_FINALIZE", session: "sess-OTHER", generation: GEN });
const impersonate = await rawApi("POST", "/wal/finalize",
  { ...finalizeRequest, startupSessionId: "sess-3", operationId: "op-impersonate" },
  false, { "x-capability": otherSessionCap.token });
check("session binding: a token bound to another session cannot finalize as sess-3",
  impersonate.status === 403 && impersonate.body.error === "CAPABILITY_SESSION_MISMATCH",
  JSON.stringify(impersonate.body));

const foreignCap = await issueCap({ databaseId: "other-db", method: "WAL_READ", session: CURRENT_SESSION, generation: GEN });
const wrongAudience = await rawApi("GET", `/wal/${DB}/${GEN}/head`, undefined, false, { "x-capability": foreignCap.token });
check("audience binding: another database's token is refused",
  wrongAudience.status === 403 && wrongAudience.body.error === "CAPABILITY_AUDIENCE_MISMATCH");

// generation guard (donor A5): a 30-digit path generation passes the \d+
// route regex but is NOT an exact JS integer - Number() would round it to a
// different generation. Must be a typed 400, never a silent lookup of the
// rounded value.
const hugeGenPath = await api("GET", `/wal/${DB}/999999999999999999999999999999/head`);
check("generation guard: 30-digit path generation is a typed 400",
  hugeGenPath.status === 400 && hugeGenPath.body.error === "INVALID_GENERATION", JSON.stringify(hugeGenPath.body));
const hugeGenBody = await rawApi("POST", "/session/register",
  { databaseId: DB, generation: 1e300, startupSessionId: "sess-a5" });
check("generation guard: overflowing body generation is a typed 400",
  hugeGenBody.status === 400 && hugeGenBody.body.error === "INVALID_GENERATION", JSON.stringify(hugeGenBody.body));

const shortCap = await issueCap({ databaseId: DB, method: "WAL_READ", session: CURRENT_SESSION, generation: GEN, ttlMs: 1 });
await new Promise((resolve) => setTimeout(resolve, 25));
const expired = await rawApi("GET", `/wal/${DB}/${GEN}/head`, undefined, false, { "x-capability": shortCap.token });
check("expiry is enforced", expired.status === 403 && expired.body.error === "CAPABILITY_EXPIRED");

const budgetBytes = Buffer.from("this body exceeds its budget");
const budgetCap = await issueCap({
  databaseId: DB, method: "PUT_PAYLOAD", digest: sha256hex(budgetBytes), maxBytes: 4,
});
const overBudget = await rawApi("PUT", `/payload/${budgetCap.key}`, budgetBytes, true, { "x-capability": budgetCap.token });
check("byte budget is enforced on payload writes",
  overBudget.status === 403 && overBudget.body.error === "CAPABILITY_BUDGET_EXCEEDED");

const preBump = await issueCap({ databaseId: DB, method: "WAL_READ", session: CURRENT_SESSION, generation: GEN });
const bump = await api("POST", `/admin/${DB}/incarnation/bump`);
check("incarnation bump is a journaled admin operation", bump.body.ok === true && bump.body.incarnation === 2,
  JSON.stringify(bump.body));
const stale = await rawApi("GET", `/wal/${DB}/${GEN}/head`, undefined, false, { "x-capability": preBump.token });
check("stale-incarnation tokens die with their controller",
  stale.status === 403 && stale.body.error === "CAPABILITY_STALE_INCARNATION");

// 16. F6r CheckpointCut lifecycle over HTTP. The incarnation bump above
// transactionally revoked EVERY live actor (audit C-P0-04), and checkpoint
// transitions revalidate the acting session's LIVE authority at use time
// (R4-SEC-04/06) - so a fresh checkpoint operator is admitted first.
await api("POST", "/session/register", { databaseId: DB, generation: GEN, startupSessionId: "sess-cp" });
CURRENT_SESSION = "sess-cp";
const cutOpen = await api("POST", `/checkpoint/${DB}/${GEN}/cut`, { cutId: "e2e-cut-1" });
check("checkpoint cut opens with head + journal anchor",
  cutOpen.body.ok === true && cutOpen.body.headLsn === "5" && Number(cutOpen.body.journalLength) > 0,
  JSON.stringify(cutOpen.body));
const cutDup = await api("POST", `/checkpoint/${DB}/${GEN}/cut`, { cutId: "e2e-cut-1" });
check("duplicate cut id is refused", cutDup.status === 409 && cutDup.body.error === "CUT_EXISTS");
const HEX64 = "e".repeat(64);
const restoreManifest = (cutId, walHead, over = {}) => ({
  schema: "checkpoint-restore-evidence/v2",
  cutId,
  walHead,
  keyspaceRoots: [{ keyspace: "default", rootDigest: HEX64 }],
  logicalDigest: HEX64,
  scratchRestore: { verifier: "e2e-scratch-restore", verifiedAtMs: 1 },
  materializations: ["m-e2e-1"],
  ...over,
});
const noEvidence = await api("POST", `/checkpoint/${DB}/cut/e2e-cut-1/activate`, { materializations: [], logicalDigest: "" });
check("activation without restore evidence fails closed",
  noEvidence.status === 409 && noEvidence.body.error === "CUT_EVIDENCE_INVALID",
  JSON.stringify(noEvidence.body));
// R4-SEC-06 negative controls: wrong cut id / wrong WAL head inside a
// well-formed manifest must refuse and leave no active cut behind
const wrongCut = await api("POST", `/checkpoint/${DB}/cut/e2e-cut-1/activate`,
  restoreManifest("cut-other", cutOpen.body.headLsn));
check("activation manifest naming another cut is refused",
  wrongCut.status === 409 && wrongCut.body.error === "CUT_EVIDENCE_INVALID", JSON.stringify(wrongCut.body));
const wrongHead = await api("POST", `/checkpoint/${DB}/cut/e2e-cut-1/activate`,
  restoreManifest("e2e-cut-1", "999999"));
check("activation manifest with a wrong WAL head is refused",
  wrongHead.status === 409 && wrongHead.body.error === "CUT_EVIDENCE_INVALID", JSON.stringify(wrongHead.body));
const activate = await api("POST", `/checkpoint/${DB}/cut/e2e-cut-1/activate`,
  restoreManifest("e2e-cut-1", cutOpen.body.headLsn));
check("activation with evidence succeeds", activate.body.ok === true && activate.body.superseded === null);
const activeCut = await api("GET", `/checkpoint/${DB}/${GEN}/active`);
check("active cut is readable", activeCut.body.ok === true && activeCut.body.cutId === "e2e-cut-1"
  && activeCut.body.logicalDigest === HEX64, JSON.stringify(activeCut.body));

// F8+F6r: the authenticated journal verifies end-to-end, INCLUDING the
// command ledger (sessions, budgets-free run: 4 session commands), the
// incarnation bump, and the cut events, against the newest cut anchor
const journal = await api("GET", `/journal/${DB}/verify`);
check("authenticated journal verifies (chain + MACs)",
  journal.body.ok === true && journal.body.length === 18 && /^[0-9a-f]{64}$/.test(journal.body.headHash),
  JSON.stringify(journal.body));
const anchored = await api("GET", `/journal/${DB}/verify-anchored`);
check("journal verifies against the cut anchor",
  anchored.body.ok === true && anchored.body.anchor !== null
  && Number(anchored.body.anchor.length) > 0,
  JSON.stringify(anchored.body));

console.log(failures === 0 ? "\nL1 LOCAL STACK E2E: ALL PASS" : `\nL1 LOCAL STACK E2E: ${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
