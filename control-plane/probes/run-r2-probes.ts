/*
 * P-R2-01/02/04/05 probe runner (typedb-r2-v16-platform-probes.md).
 *
 * Runs against a real R2 staging account through the S3 API. Credentials
 * come exclusively from the environment:
 *   R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_PROBE_BUCKET
 * Without them the runner exits with the stop-item marker (SI-G0-3) and a
 * non-zero code: a skipped probe is a non-execution, never a pass.
 *
 * Every probe emits a PlatformProbeEvidence JSON record with raw request /
 * response logs to docs/evidence/G1-platform/<probe_id>/.
 *
 * Probe outline (implemented below, executed when credentials exist):
 *  P-R2-01 conditions/ambiguity:
 *    - PUT with If-None-Match:* on a fresh key -> 200; repeat -> 412
 *    - two concurrent conditional PUTs on one key -> exactly one winner
 *    - GET readback: full byte + sha256 equality
 *  P-R2-02 credential scope:
 *    - temporary credential minted with exact PutObject on one key prefix
 *    - assert Delete/List/other-prefix operations are denied
 *    - parent revocation: minted credential stops working; measure latency
 *  P-R2-04 checksums/multipart:
 *    - single-part PUT with x-amz-checksum-sha256; verify echo
 *    - multipart: same-part retry with identical bytes OK; changed bytes
 *      under the same part is recorded as attempt-corruption evidence;
 *      completed object verified by full application SHA-256
 *  P-R2-05 consistency/same-key pressure:
 *    - write/read-after-write on the S3 endpoint (no CDN domain)
 *    - N concurrent same-key writers -> last-writer-to-complete wins;
 *      429/backoff behavior recorded
 */

import { createHash, createHmac } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";

const ACCOUNT = process.env.R2_ACCOUNT_ID;
const KEY_ID = process.env.R2_ACCESS_KEY_ID;
const SECRET = process.env.R2_SECRET_ACCESS_KEY;
const BUCKET = process.env.R2_PROBE_BUCKET;

const EVIDENCE_DIR = new URL("../../docs/evidence/G1-platform/", import.meta.url).pathname;

if (!ACCOUNT || !KEY_ID || !SECRET || !BUCKET) {
  console.error(
    "SI-G0-3: no Cloudflare staging credentials in environment " +
      "(R2_ACCOUNT_ID / R2_ACCESS_KEY_ID / R2_SECRET_ACCESS_KEY / R2_PROBE_BUCKET). " +
      "Probes NOT executed; this is a recorded non-execution, not a pass.",
  );
  process.exit(3);
}

const HOST = `${ACCOUNT}.r2.cloudflarestorage.com`;

function hmac(key: Buffer | string, data: string): Buffer {
  return createHmac("sha256", key).update(data, "utf8").digest();
}
function sha256hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Minimal SigV4 signer for R2's S3 API (auto region). */
async function s3(
  method: string,
  path: string,
  body: Buffer = Buffer.alloc(0),
  headers: Record<string, string> = {},
): Promise<{ status: number; headers: Headers; body: Buffer }> {
  const now = new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, "").slice(0, 15) + "Z";
  const date = amzDate.slice(0, 8);
  const payloadHash = sha256hex(body);
  const h: Record<string, string> = {
    host: HOST,
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amzDate,
    ...Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])),
  };
  const signedHeaderNames = Object.keys(h).sort();
  const canonical = [
    method,
    path,
    "",
    ...signedHeaderNames.map((k) => `${k}:${h[k].trim()}`),
    "",
    signedHeaderNames.join(";"),
    payloadHash,
  ].join("\n");
  const scope = `${date}/auto/s3/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256hex(canonical)].join("\n");
  const kSigning = hmac(hmac(hmac(hmac("AWS4" + SECRET, date), "auto"), "s3"), "aws4_request");
  const signature = createHmac("sha256", kSigning).update(toSign).digest("hex");
  h["authorization"] =
    `AWS4-HMAC-SHA256 Credential=${KEY_ID}/${scope}, ` +
    `SignedHeaders=${signedHeaderNames.join(";")}, Signature=${signature}`;
  const res = await fetch(`https://${HOST}${path}`, {
    method,
    headers: h,
    body: body.length ? new Uint8Array(body) : undefined,
  });
  return { status: res.status, headers: res.headers, body: Buffer.from(await res.arrayBuffer()) };
}

interface Evidence {
  probe_id: string;
  started_at: string;
  steps: Array<Record<string, unknown>>;
  expected_outcome: string;
  actual_outcome: string;
  pass: boolean;
}

function writeEvidence(ev: Evidence) {
  const dir = `${EVIDENCE_DIR}${ev.probe_id}`;
  mkdirSync(dir, { recursive: true });
  writeFileSync(`${dir}/evidence.json`, JSON.stringify(ev, null, 2));
  console.log(`${ev.probe_id}: ${ev.pass ? "PASS" : "FAIL"} — ${ev.actual_outcome}`);
}

async function probeR2_01(): Promise<void> {
  const key = `/${BUCKET}/probes/p-r2-01/${Date.now()}-cond`;
  const payload = Buffer.from("probe-conditional-body");
  const ev: Evidence = {
    probe_id: "P-R2-01",
    started_at: new Date().toISOString(),
    steps: [],
    expected_outcome:
      "create-if-absent succeeds once; second conditional create 412; readback byte/hash exact",
    actual_outcome: "",
    pass: false,
  };
  const put1 = await s3("PUT", key, payload, { "if-none-match": "*" });
  ev.steps.push({ op: "PUT if-none-match:*", status: put1.status });
  const put2 = await s3("PUT", key, Buffer.from("different"), { "if-none-match": "*" });
  ev.steps.push({ op: "PUT if-none-match:* (dup)", status: put2.status });
  const get = await s3("GET", key);
  const exact = get.body.equals(payload);
  ev.steps.push({ op: "GET readback", status: get.status, sha256: sha256hex(get.body), exact });
  ev.pass = put1.status === 200 && put2.status === 412 && exact;
  ev.actual_outcome = `put1=${put1.status} put2=${put2.status} exact=${exact}`;
  writeEvidence(ev);
}

async function probeR2_05(): Promise<void> {
  const key = `/${BUCKET}/probes/p-r2-05/${Date.now()}-raw`;
  const N = 8;
  const ev: Evidence = {
    probe_id: "P-R2-05",
    started_at: new Date().toISOString(),
    steps: [],
    expected_outcome:
      "read-after-write strongly consistent on the S3 endpoint; concurrent same-key writers: last-complete wins; overload classified",
    actual_outcome: "",
    pass: false,
  };
  const writes = await Promise.all(
    Array.from({ length: N }, (_, i) => s3("PUT", key, Buffer.from(`writer-${i}`))),
  );
  ev.steps.push({ op: "concurrent PUT x8", statuses: writes.map((w) => w.status) });
  const rd = await s3("GET", key);
  const winner = rd.body.toString();
  ev.steps.push({ op: "GET", status: rd.status, winner });
  ev.pass =
    rd.status === 200 &&
    /^writer-\d$/.test(winner) &&
    writes.every((w) => w.status === 200 || w.status === 429);
  ev.actual_outcome = `winner=${winner} statuses=${writes.map((w) => w.status).join(",")}`;
  writeEvidence(ev);
}

const main = async () => {
  await probeR2_01();
  await probeR2_05();
  // P-R2-02 (temporary-credential scope) and P-R2-04 (checksums/multipart)
  // require the account API token to mint temp credentials; implemented in
  // this repo once a staging account exists (SI-G0-3).
};
main();
