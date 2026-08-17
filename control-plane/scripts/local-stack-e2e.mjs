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

const BASE = process.argv[2] ?? "http://127.0.0.1:8787";
const DB = `e2e-db-${process.pid}-${Date.now()}`;
const GEN = 1;
const SESSION = "sess-e2e";
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
  const response = await fetch(`${BASE}${path}`, {
    method,
    body: raw ? body : body !== undefined ? JSON.stringify(body) : undefined,
    headers: raw ? headers : { "content-type": "application/json", ...headers },
  });
  return { status: response.status, body: await response.json() };
}

/** Issue a capability from the controller (open local issuance). */
async function issueCap(spec) {
  const issued = await rawApi("POST", "/capability", { principal: PRINCIPAL, ttlMs: 60_000, ...spec });
  if (!issued.body.ok) throw new Error(`capability issuance failed: ${JSON.stringify(issued.body)}`);
  return issued.body; // {token, key?, expiresAtMs, incarnation}
}

/** Which capability a route needs (mirror of the worker's guard map). */
function capSpecFor(method, rawPath, body) {
  const path = rawPath.split("?")[0]; // the audience derives from the path, never the query
  if (path === "/capability" || path === "/health") return null;
  if (path.startsWith("/session/") || path === "/budgets") {
    return { databaseId: body.databaseId, method: "SESSION_ADMIN" };
  }
  if (path === "/wal/finalize") return { databaseId: body.databaseId, method: "WAL_FINALIZE" };
  if (path === "/wal/finalize-batch") return { databaseId: body.requests[0].databaseId, method: "WAL_FINALIZE" };
  let m = path.match(/^\/wal\/([^/]+)\//);
  if (m) return { databaseId: m[1], method: "WAL_READ" };
  m = path.match(/^\/outbox\/([^/]+)/);
  if (m) return { databaseId: m[1], method: "OUTBOX" };
  m = path.match(/^\/journal\/([^/]+)\/verify$/);
  if (m) return { databaseId: m[1], method: "JOURNAL_VERIFY" };
  m = path.match(/^\/admin\/([^/]+)\//);
  if (m) return { databaseId: m[1], method: "SESSION_ADMIN" };
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

const health = await rawApi("GET", "/health");
check("health", health.body.ok === true, JSON.stringify(health.body));

await api("POST", "/session/register", { databaseId: DB, generation: GEN, startupSessionId: SESSION });

// 1. payload through the data path, then finalisation
const payload1 = Buffer.from("commit-record-1");
const up1 = await uploadPayload(payload1);
check("payload upload digest agrees", up1.response.body.sha256hex === up1.digest, JSON.stringify(up1.response.body));
check("payload key is issuer-derived and content-addressed",
  up1.key === `p/${DB}/${up1.digest}`, up1.key);

const finalizeRequest = {
  databaseId: DB, generation: GEN, startupSessionId: SESSION,
  operationId: "op-1", requestDigest: "rd-1",
  sequencingKind: "SEQUENCED", recordType: 2, logicalKey: null,
  payloadKey: up1.key, payloadDigest: up1.digest, payloadLength: payload1.length,
};
const f1 = await api("POST", "/wal/finalize", finalizeRequest);
check("finalize allocates lsn 0", f1.body.ok === true && f1.body.appendLsn === "0" && f1.body.replayed === false,
  JSON.stringify(f1.body));

// 2. lost-response ambiguity: identical retry replays the SAME allocation
const f1retry = await api("POST", "/wal/finalize", finalizeRequest);
check("ambiguous retry replays identically",
  f1retry.body.ok === true && f1retry.body.appendLsn === "0" && f1retry.body.replayed === true);

// 3. tampered digest is rejected by the DATA PATH before the controller
const tampered = { ...finalizeRequest, operationId: "op-tampered", requestDigest: "rd-t", payloadDigest: "0".repeat(64) };
const ft = await api("POST", "/wal/finalize", tampered);
check("data path rejects digest mismatch", ft.status === 422 && ft.body.error === "PAYLOAD_DIGEST_MISMATCH");

// 4. finalize referencing a never-uploaded payload is rejected
const ghost = { ...finalizeRequest, operationId: "op-ghost", requestDigest: "rd-g", payloadKey: `p/${DB}/${"f".repeat(64)}` };
const fg = await api("POST", "/wal/finalize", ghost);
check("data path rejects missing payload", fg.status === 422 && fg.body.error === "PAYLOAD_MISSING");

// 5. status singleton over HTTP
const statusPayload = Buffer.from("status-A");
const upStatus = await uploadPayload(statusPayload);
const s1 = await api("POST", "/wal/finalize", {
  ...finalizeRequest, operationId: "st-1", requestDigest: "rd-s1", sequencingKind: "UNSEQUENCED",
  recordType: 1,
  logicalKey: "status:cp", payloadKey: upStatus.key, payloadDigest: upStatus.digest, payloadLength: statusPayload.length,
});
check("status singleton accepted", s1.body.ok === true);

const statusB = Buffer.from("status-B-conflicting");
const upStatusB = await uploadPayload(statusB);
const s2 = await api("POST", "/wal/finalize", {
  ...finalizeRequest, operationId: "st-2", requestDigest: "rd-s2", sequencingKind: "UNSEQUENCED",
  logicalKey: "status:cp", payloadKey: upStatusB.key, payloadDigest: upStatusB.digest, payloadLength: statusB.length,
});
check("conflicting status rejected", s2.status === 409 && s2.body.error === "STATUS_CONFLICT");

// 6. exact read-back through the data path
const read = await api("GET", `/wal/${DB}/${GEN}/0`);
check("exact read returns the exact payload",
  read.body.ok === true && Buffer.from(read.body.payloadBase64, "base64").equals(payload1));
const miss = await api("GET", `/wal/${DB}/${GEN}/99`);
check("exact read miss is typed NOT_FOUND", miss.status === 404 && miss.body.error === "NOT_FOUND");

// 7. fencing over HTTP
await api("POST", "/session/fence", { databaseId: DB, generation: GEN, startupSessionId: SESSION });
const fenced = await api("POST", "/wal/finalize", {
  ...finalizeRequest, operationId: "op-after-fence", requestDigest: "rd-f",
});
check("fenced session rejected", fenced.status === 409 && fenced.body.error === "SESSION_FENCED");

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
check("outbox peek returns finalized events", peek1.body.ok && peek1.body.events.length === 2,
  `events=${peek1.body.events?.length}`);
const peek2 = await api("GET", `/outbox/${DB}?limit=10`);
check("unacked events are redelivered", peek2.body.events.length === peek1.body.events.length);
const kinds = new Set(peek1.body.events.map((e) => e.kind));
check("events carry canonical bodies", kinds.has("WAL_RECORD_FINALIZED") &&
  peek1.body.events.every((e) => JSON.parse(e.body).databaseId === DB));
// controlSeq is a decimal-string u64 on the wire (F7): compare as bigint
const maxSeq = peek1.body.events.map((e) => BigInt(e.controlSeq)).reduce((a, b) => (a > b ? a : b)).toString();
const ack = await api("POST", `/outbox/${DB}/ack`, { upToControlSeq: maxSeq });
check("ack marks events", ack.body.ok && ack.body.acked === 2, JSON.stringify(ack.body));
const peek3 = await api("GET", `/outbox/${DB}?limit=10`);
check("acked events are not redelivered", peek3.body.events.length === 0);
const ackAgain = await api("POST", `/outbox/${DB}/ack`, { upToControlSeq: maxSeq });
check("duplicate ack is idempotent", ackAgain.body.acked === 0);

// 10. register-fences-predecessor over HTTP (takeover; three-lane pin)
await api("POST", "/session/register", { databaseId: DB, generation: GEN, startupSessionId: "sess-2" });
const payload2 = Buffer.from("commit-record-2");
const up2 = await uploadPayload(payload2);
const takeover = await api("POST", "/wal/finalize", {
  ...finalizeRequest, startupSessionId: "sess-2", operationId: "op-2", requestDigest: "rd-2",
  payloadKey: up2.key, payloadDigest: up2.digest, payloadLength: payload2.length,
});
check("new actor appends after taking over", takeover.body.ok === true && takeover.body.appendLsn === "2");
await api("POST", "/session/register", { databaseId: DB, generation: GEN, startupSessionId: "sess-3" });
const fencedByRegister = await api("POST", "/wal/finalize", {
  ...finalizeRequest, startupSessionId: "sess-2", operationId: "op-2b", requestDigest: "rd-2b",
  payloadKey: up2.key, payloadDigest: up2.digest, payloadLength: payload2.length,
});
check("register fences the predecessor, with attribution",
  fencedByRegister.status === 409 && fencedByRegister.body.error === "SESSION_FENCED" &&
  fencedByRegister.body.fencedBy === "sess-3");
const payload3 = Buffer.from("commit-record-3");
const up3 = await uploadPayload(payload3);
const f3 = await api("POST", "/wal/finalize", {
  ...finalizeRequest, startupSessionId: "sess-3", operationId: "op-3", requestDigest: "rd-3",
  payloadKey: up3.key, payloadDigest: up3.digest, payloadLength: payload3.length,
});
check("current actor appends lsn 3", f3.body.ok === true && f3.body.appendLsn === "3");

// 11. head: TypeSequence, not physical LSN (they diverge here: 4 records, 3 sequenced)
const head = await api("GET", `/wal/${DB}/${GEN}/head`);
check("head reports lsn and type sequence",
  head.body.ok === true && head.body.headLsn === "3" && head.body.headTypeSequence === "3",
  JSON.stringify(head.body));

// 12. pinned iterator + ordered scan with verified inline payloads
const iter = await api("POST", `/wal/${DB}/${GEN}/iterator`);
check("iterator pins the head", iter.body.ok === true && iter.body.headLsn === "3");
const scan = await api("GET", `/wal/${DB}/${GEN}/scan?fromTs=1&throughLsn=${iter.body.headLsn}&limit=100`);
check("scan replays in physical order",
  scan.body.ok === true &&
  JSON.stringify(scan.body.records.map((r) => [r.appendLsn, r.typeSequence, r.recordType])) ===
    JSON.stringify([["0", "1", 2], ["1", "1", 1], ["2", "2", 2], ["3", "3", 2]]),
  JSON.stringify(scan.body.records?.map((r) => [r.appendLsn, r.typeSequence, r.recordType])));
check("scan payloads round-trip",
  Buffer.from(scan.body.records[0].payloadBase64, "base64").equals(payload1) &&
  Buffer.from(scan.body.records[3].payloadBase64, "base64").equals(payload3));
const scanTyped = await api("GET", `/wal/${DB}/${GEN}/scan?fromTs=0&throughLsn=${iter.body.headLsn}&recordType=1&limit=100`);
check("scan filters by record type", scanTyped.body.records.length === 1 && scanTyped.body.records[0].appendLsn === "1");
const scanUnbounded = await api("GET", `/wal/${DB}/${GEN}/scan?fromTs=0&limit=100`);
check("unbounded scan is refused (pinned snapshot is mandatory)",
  scanUnbounded.status === 400 && scanUnbounded.body.error === "MISSING_THROUGH_LSN");
const scanZeroLimit = await api("GET", `/wal/${DB}/${GEN}/scan?fromTs=0&throughLsn=${iter.body.headLsn}&limit=0`);
check("limit=0 is clamped to one record, never a crash",
  scanZeroLimit.body.ok === true && scanZeroLimit.body.records.length === 1 && scanZeroLimit.body.nextFromLsn === "1");
const scanBadParam = await api("GET", `/wal/${DB}/${GEN}/scan?fromTs=abc&throughLsn=${iter.body.headLsn}`);
check("non-numeric scan parameter is a typed 400",
  scanBadParam.status === 400 && scanBadParam.body.error === "INVALID_PARAMETER");
// byte budget: maxBytes=1 forces a one-record page (progress guaranteed),
// resumable exactly like a limit cut
const scanByteCut = await api("GET", `/wal/${DB}/${GEN}/scan?fromTs=0&throughLsn=${iter.body.headLsn}&maxBytes=1`);
check("scan byte budget cuts the page with progress",
  scanByteCut.body.ok === true && scanByteCut.body.records.length === 1 && scanByteCut.body.nextFromLsn === "1",
  JSON.stringify({ n: scanByteCut.body.records?.length, next: scanByteCut.body.nextFromLsn }));
const scanResume = await api("GET", `/wal/${DB}/${GEN}/scan?fromTs=0&fromLsn=${scanByteCut.body.nextFromLsn}&throughLsn=${iter.body.headLsn}&maxBytes=1`);
check("byte-cut pages resume without overlap",
  scanResume.body.records.length === 1 && scanResume.body.records[0].appendLsn === "1");

// a finalized operation stays queryable by operation id after its session was
// fenced (op-1 was finalized by SESSION, fenced in step 7)
const opQuery = await api("GET", `/wal/${DB}/${GEN}/operation/op-1`);
check("finalized operation queryable after fencing",
  opQuery.body.ok === true && opQuery.body.record.appendLsn === "0" && opQuery.body.requestDigest === "rd-1");
const opMiss = await api("GET", `/wal/${DB}/${GEN}/operation/op-ghost-never`);
check("operation query miss is typed NOT_FOUND", opMiss.status === 404 && opMiss.body.error === "NOT_FOUND");

// 13. last-by-type
const last = await api("GET", `/wal/${DB}/${GEN}/last?recordType=1`);
check("last-by-type finds the status record", last.body.ok === true && last.body.record.appendLsn === "1");
const lastMiss = await api("GET", `/wal/${DB}/${GEN}/last?recordType=99`);
check("last-by-type miss is typed NOT_FOUND", lastMiss.status === 404 && lastMiss.body.error === "NOT_FOUND");
const badType = await api("POST", "/wal/finalize", {
  ...finalizeRequest, startupSessionId: "sess-3", operationId: "op-bad-type", requestDigest: "rd-bt", recordType: 999,
});
check("out-of-range record type is a typed 400", badType.status === 400 && badType.body.error === "INVALID_RECORD_TYPE");

// 14. batch finalize: all-or-nothing over HTTP
const batchA = Buffer.from("batch-record-A");
const batchB = Buffer.from("batch-record-B");
const upA = await uploadPayload(batchA);
const upB = await uploadPayload(batchB);
const batchOk = await api("POST", "/wal/finalize-batch", { requests: [
  { ...finalizeRequest, startupSessionId: "sess-3", operationId: "bb-1", requestDigest: "rd-bb1",
    payloadKey: upA.key, payloadDigest: upA.digest, payloadLength: batchA.length },
  { ...finalizeRequest, startupSessionId: "sess-3", operationId: "bb-2", requestDigest: "rd-bb2",
    payloadKey: upB.key, payloadDigest: upB.digest, payloadLength: batchB.length },
]});
check("batch finalize allocates contiguously",
  batchOk.body.ok === true && JSON.stringify(batchOk.body.results.map((r) => r.appendLsn)) === JSON.stringify(["4", "5"]),
  JSON.stringify(batchOk.body));
const batchAborted = await api("POST", "/wal/finalize-batch", { requests: [
  { ...finalizeRequest, startupSessionId: "sess-3", operationId: "bb-3", requestDigest: "rd-bb3",
    payloadKey: upA.key, payloadDigest: upA.digest, payloadLength: batchA.length },
  { ...finalizeRequest, startupSessionId: "sess-3", operationId: "bb-4", requestDigest: "rd-bb4",
    sequencingKind: "UNSEQUENCED", recordType: 1, logicalKey: "status:cp",
    payloadKey: upB.key, payloadDigest: upB.digest, payloadLength: batchB.length },
]});
check("failing member aborts the whole batch",
  batchAborted.status === 409 && batchAborted.body.error === "STATUS_CONFLICT");
const auditAfterBatch = await api("GET", `/wal/${DB}/${GEN}/audit`);
check("aborted batch allocated nothing",
  auditAfterBatch.body.contiguous === true && auditAfterBatch.body.count === 6, JSON.stringify(auditAfterBatch.body));

// 15. F9 capability refusal matrix - every denial is typed, nothing reaches
// the authority or the store
const noToken = await rawApi("GET", `/wal/${DB}/${GEN}/head`);
check("missing capability is a typed 401", noToken.status === 401 && noToken.body.error === "CAPABILITY_REQUIRED");

const readCap = await issueCap({ databaseId: DB, method: "WAL_READ" });
const flipped = readCap.token.slice(0, -1) + (readCap.token.endsWith("0") ? "1" : "0");
const badMac = await rawApi("GET", `/wal/${DB}/${GEN}/head`, undefined, false, { "x-capability": flipped });
check("tampered MAC is refused", badMac.status === 403 && badMac.body.error === "CAPABILITY_MAC_INVALID");

const once = await rawApi("GET", `/wal/${DB}/${GEN}/head`, undefined, false, { "x-capability": readCap.token });
const replayed = await rawApi("GET", `/wal/${DB}/${GEN}/head`, undefined, false, { "x-capability": readCap.token });
check("nonce is single-use: replay is refused",
  once.status === 200 && replayed.status === 403 && replayed.body.error === "CAPABILITY_REPLAYED",
  JSON.stringify(replayed.body));

const readCap2 = await issueCap({ databaseId: DB, method: "WAL_READ" });
const wrongMethod = await rawApi("POST", "/wal/finalize", { ...finalizeRequest, operationId: "op-wm", requestDigest: "rd-wm" },
  false, { "x-capability": readCap2.token });
check("method binding: a read token cannot finalize",
  wrongMethod.status === 403 && wrongMethod.body.error === "CAPABILITY_METHOD_MISMATCH");

const foreignCap = await issueCap({ databaseId: "other-db", method: "WAL_READ" });
const wrongAudience = await rawApi("GET", `/wal/${DB}/${GEN}/head`, undefined, false, { "x-capability": foreignCap.token });
check("audience binding: another database's token is refused",
  wrongAudience.status === 403 && wrongAudience.body.error === "CAPABILITY_AUDIENCE_MISMATCH");

const shortCap = await issueCap({ databaseId: DB, method: "WAL_READ", ttlMs: 1 });
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

const preBump = await issueCap({ databaseId: DB, method: "WAL_READ" });
const bump = await api("POST", `/admin/${DB}/incarnation/bump`);
check("incarnation bump is a journaled admin operation", bump.body.ok === true && bump.body.incarnation === 2,
  JSON.stringify(bump.body));
const stale = await rawApi("GET", `/wal/${DB}/${GEN}/head`, undefined, false, { "x-capability": preBump.token });
check("stale-incarnation tokens die with their controller",
  stale.status === 403 && stale.body.error === "CAPABILITY_STALE_INCARNATION");

// F8: the authenticated journal verifies end-to-end over the whole run
// (6 WAL finalisations + the journaled incarnation bump)
const journal = await api("GET", `/journal/${DB}/verify`);
check("authenticated journal verifies (chain + MACs)",
  journal.body.ok === true && journal.body.length === 7 && /^[0-9a-f]{64}$/.test(journal.body.headHash),
  JSON.stringify(journal.body));

console.log(failures === 0 ? "\nL1 LOCAL STACK E2E: ALL PASS" : `\nL1 LOCAL STACK E2E: ${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
