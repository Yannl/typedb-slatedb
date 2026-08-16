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
  sequencingKind: "SEQUENCED", logicalKey: null,
  payloadKey: `${DB}/g1/p1`, payloadDigest: digest1, payloadLength: payload1.length,
};
const f1 = await api("POST", "/wal/finalize", finalizeRequest);
check("finalize allocates lsn 0", f1.body.ok === true && f1.body.appendLsn === 0 && f1.body.replayed === false,
  JSON.stringify(f1.body));

// 2. lost-response ambiguity: identical retry replays the SAME allocation
const f1retry = await api("POST", "/wal/finalize", finalizeRequest);
check("ambiguous retry replays identically",
  f1retry.body.ok === true && f1retry.body.appendLsn === 0 && f1retry.body.replayed === true);

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
check("tail contiguous", audit.body.contiguous === true && audit.body.count === 2, JSON.stringify(audit.body));

// 9. outbox consumer loop: at-least-once peek/ack with redelivery
const peek1 = await api("GET", `/outbox/${DB}?limit=10`);
check("outbox peek returns finalized events", peek1.body.ok && peek1.body.events.length === 2,
  `events=${peek1.body.events?.length}`);
const peek2 = await api("GET", `/outbox/${DB}?limit=10`);
check("unacked events are redelivered", peek2.body.events.length === peek1.body.events.length);
const kinds = new Set(peek1.body.events.map((e) => e.kind));
check("events carry canonical bodies", kinds.has("WAL_RECORD_FINALIZED") &&
  peek1.body.events.every((e) => JSON.parse(e.body).databaseId === DB));
const maxSeq = Math.max(...peek1.body.events.map((e) => e.controlSeq));
const ack = await api("POST", `/outbox/${DB}/ack`, { upToControlSeq: maxSeq });
check("ack marks events", ack.body.ok && ack.body.acked === 2, JSON.stringify(ack.body));
const peek3 = await api("GET", `/outbox/${DB}?limit=10`);
check("acked events are not redelivered", peek3.body.events.length === 0);
const ackAgain = await api("POST", `/outbox/${DB}/ack`, { upToControlSeq: maxSeq });
check("duplicate ack is idempotent", ackAgain.body.acked === 0);

console.log(failures === 0 ? "\nL1 LOCAL STACK E2E: ALL PASS" : `\nL1 LOCAL STACK E2E: ${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
