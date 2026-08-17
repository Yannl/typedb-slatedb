/*
 * L1 local-stack end-to-end: drives the production topology over real HTTP
 * against `wrangler dev` (workerd + local R2): payload upload → data-path
 * digest verification → DO finalisation → exact read-back, plus the
 * ambiguity/idempotency and tamper cases from the protocol contract.
 *
 * Usage: node scripts/local-stack-e2e.mjs [baseUrl]
 * Exit code 0 = every check passed.
 */

import { createHash } from "node:crypto";

const BASE = process.argv[2] ?? "http://127.0.0.1:8787";
const DB = `e2e-db-${process.pid}-${Date.now()}`;
const GEN = 1;
const SESSION = "sess-e2e";

let failures = 0;
function check(name, condition, detail = "") {
  const status = condition ? "PASS" : "FAIL";
  if (!condition) failures += 1;
  console.log(`${status}  ${name}${detail ? ` — ${detail}` : ""}`);
}

async function api(method, path, body, raw = false) {
  const response = await fetch(`${BASE}${path}`, {
    method,
    body: raw ? body : body !== undefined ? JSON.stringify(body) : undefined,
    headers: raw ? {} : { "content-type": "application/json" },
  });
  return { status: response.status, body: await response.json() };
}

function sha256hex(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

const health = await api("GET", "/health");
check("health", health.body.ok === true, JSON.stringify(health.body));

await api("POST", "/session/register", { databaseId: DB, generation: GEN, startupSessionId: SESSION });

// 1. payload through the data path, then finalisation
const payload1 = Buffer.from("commit-record-1");
const digest1 = sha256hex(payload1);
const up1 = await api("PUT", `/payload/${DB}/g1/p1`, payload1, true);
check("payload upload digest agrees", up1.body.sha256hex === digest1);

const finalizeRequest = {
  databaseId: DB, generation: GEN, startupSessionId: SESSION,
  operationId: "op-1", requestDigest: "rd-1",
  sequencingKind: "SEQUENCED", recordType: 2, logicalKey: null,
  payloadKey: `${DB}/g1/p1`, payloadDigest: digest1, payloadLength: payload1.length,
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
const ghost = { ...finalizeRequest, operationId: "op-ghost", requestDigest: "rd-g", payloadKey: `${DB}/g1/ghost` };
const fg = await api("POST", "/wal/finalize", ghost);
check("data path rejects missing payload", fg.status === 422 && fg.body.error === "PAYLOAD_MISSING");

// 5. status singleton over HTTP
const statusPayload = Buffer.from("status-A");
const statusDigest = sha256hex(statusPayload);
await api("PUT", `/payload/${DB}/g1/status-a`, statusPayload, true);
const s1 = await api("POST", "/wal/finalize", {
  ...finalizeRequest, operationId: "st-1", requestDigest: "rd-s1", sequencingKind: "UNSEQUENCED",
  recordType: 1,
  logicalKey: "status:cp", payloadKey: `${DB}/g1/status-a`, payloadDigest: statusDigest, payloadLength: statusPayload.length,
});
check("status singleton accepted", s1.body.ok === true);

const statusB = Buffer.from("status-B-conflicting");
await api("PUT", `/payload/${DB}/g1/status-b`, statusB, true);
const s2 = await api("POST", "/wal/finalize", {
  ...finalizeRequest, operationId: "st-2", requestDigest: "rd-s2", sequencingKind: "UNSEQUENCED",
  logicalKey: "status:cp", payloadKey: `${DB}/g1/status-b`, payloadDigest: sha256hex(statusB), payloadLength: statusB.length,
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
check("tail contiguous", audit.body.contiguous === true && audit.body.count === 2 && audit.body.maxLsn === "1", JSON.stringify(audit.body));

// 8b. payload immutability on the data path
const overwrite = await api("PUT", `/payload/${DB}/g1/p1`, Buffer.from("DIFFERENT BYTES"), true);
check("payload overwrite with different bytes rejected",
  overwrite.status === 409 && overwrite.body.error === "PAYLOAD_IMMUTABILITY_VIOLATION");
const idempotentPut = await api("PUT", `/payload/${DB}/g1/p1`, payload1, true);
check("identical re-upload is idempotent", idempotentPut.status === 200 && idempotentPut.body.deduplicated === true);

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
await api("PUT", `/payload/${DB}/g1/p2`, payload2, true);
const takeover = await api("POST", "/wal/finalize", {
  ...finalizeRequest, startupSessionId: "sess-2", operationId: "op-2", requestDigest: "rd-2",
  payloadKey: `${DB}/g1/p2`, payloadDigest: sha256hex(payload2), payloadLength: payload2.length,
});
check("new actor appends after taking over", takeover.body.ok === true && takeover.body.appendLsn === "2");
await api("POST", "/session/register", { databaseId: DB, generation: GEN, startupSessionId: "sess-3" });
const fencedByRegister = await api("POST", "/wal/finalize", {
  ...finalizeRequest, startupSessionId: "sess-2", operationId: "op-2b", requestDigest: "rd-2b",
  payloadKey: `${DB}/g1/p2`, payloadDigest: sha256hex(payload2), payloadLength: payload2.length,
});
check("register fences the predecessor, with attribution",
  fencedByRegister.status === 409 && fencedByRegister.body.error === "SESSION_FENCED" &&
  fencedByRegister.body.fencedBy === "sess-3");
const payload3 = Buffer.from("commit-record-3");
await api("PUT", `/payload/${DB}/g1/p3`, payload3, true);
const f3 = await api("POST", "/wal/finalize", {
  ...finalizeRequest, startupSessionId: "sess-3", operationId: "op-3", requestDigest: "rd-3",
  payloadKey: `${DB}/g1/p3`, payloadDigest: sha256hex(payload3), payloadLength: payload3.length,
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
await api("PUT", `/payload/${DB}/g1/ba`, batchA, true);
await api("PUT", `/payload/${DB}/g1/bb`, batchB, true);
const batchOk = await api("POST", "/wal/finalize-batch", { requests: [
  { ...finalizeRequest, startupSessionId: "sess-3", operationId: "bb-1", requestDigest: "rd-bb1",
    payloadKey: `${DB}/g1/ba`, payloadDigest: sha256hex(batchA), payloadLength: batchA.length },
  { ...finalizeRequest, startupSessionId: "sess-3", operationId: "bb-2", requestDigest: "rd-bb2",
    payloadKey: `${DB}/g1/bb`, payloadDigest: sha256hex(batchB), payloadLength: batchB.length },
]});
check("batch finalize allocates contiguously",
  batchOk.body.ok === true && JSON.stringify(batchOk.body.results.map((r) => r.appendLsn)) === JSON.stringify(["4", "5"]),
  JSON.stringify(batchOk.body));
const batchAborted = await api("POST", "/wal/finalize-batch", { requests: [
  { ...finalizeRequest, startupSessionId: "sess-3", operationId: "bb-3", requestDigest: "rd-bb3",
    payloadKey: `${DB}/g1/ba`, payloadDigest: sha256hex(batchA), payloadLength: batchA.length },
  { ...finalizeRequest, startupSessionId: "sess-3", operationId: "bb-4", requestDigest: "rd-bb4",
    sequencingKind: "UNSEQUENCED", recordType: 1, logicalKey: "status:cp",
    payloadKey: `${DB}/g1/bb`, payloadDigest: sha256hex(batchB), payloadLength: batchB.length },
]});
check("failing member aborts the whole batch",
  batchAborted.status === 409 && batchAborted.body.error === "STATUS_CONFLICT");
const auditAfterBatch = await api("GET", `/wal/${DB}/${GEN}/audit`);
check("aborted batch allocated nothing",
  auditAfterBatch.body.contiguous === true && auditAfterBatch.body.count === 6, JSON.stringify(auditAfterBatch.body));

console.log(failures === 0 ? "\nL1 LOCAL STACK E2E: ALL PASS" : `\nL1 LOCAL STACK E2E: ${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
