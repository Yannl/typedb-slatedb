// Native-fidelity product lane (round-4 PR3 / R4-STACK-03).
//
// Runs the EXACT TypeDB server binary (the staged fork build) against a
// real native S3 backend through the deterministic fault proxy, and
// closes four feedback loops the unit suites cannot:
//
//   1. product path      the official HTTP surface (signin, one-shot
//                        query) drives schema + writes + reads — no test
//                        shims between the client and the server binary;
//   2. S3-path witness   every S3 byte transits fault-proxy.mjs, whose
//                        connection report is the nonzero-S3-path counter
//                        (a stack that silently fell back to a local
//                        store shows ZERO connections and FAILS);
//   3. crash realism     kill -9 the server mid-life, restart over the
//                        same data dir + prefix, and require the data
//                        back byte-for-byte through the same HTTP path;
//   4. fault realism     a named connection gets a named fault (reset)
//                        and the workload must still converge — the
//                        object_store retry path is exercised on the
//                        REAL data path, not a mock.
//
// Also proves parallel isolation: two full stacks (distinct ports, data
// dirs, prefixes) run the workload concurrently against ONE S3 server
// and must never see each other's data.
//
// Provider selection is the SHARED one (round-6 R6-LOCAL-01): this lane no
// longer carries its own `if (provider === "minio") ... else ...` spawn
// code. It resolves the provider through local-parity.mjs (same resolution
// `stack up` and the canonical graph use) and builds the spawn spec from
// the s3-provider.mjs descriptor, so binary resolution, argv, env,
// data-directory creation and readiness are identical in every lane. The
// descriptor is also what encodes that RustFS refuses to start without an
// existing volume directory while MinIO creates its own.
//
// Usage:
//   node stack/native-fidelity.mjs                 # agent-local default
//   S3_PROVIDER=minio node stack/native-fidelity.mjs   # comparator
//   node stack/native-fidelity.mjs --provider minio
//   TYPEDB_SERVER_BIN=/path/to/bin node stack/native-fidelity.mjs
//
// Exit 0 only when every phase passes.

import { spawn, execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { startFaultProxy } from "./fault-proxy.mjs";
import { formatGate, resolveProvider } from "./local-parity.mjs";
import { providerSpawnSpec } from "./s3-provider.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..");
const LOOPBACK = "127.0.0.1";
const S3OP = path.join(REPO, "tools", "s3-cert-corpus", "s3op.py");

function log(msg) {
  console.log(`native-fidelity: ${msg}`);
}

// Source-locked artifact resolution (materialization + digest refusal)
// lives in s3-provider.mjs and is shared by every lane — a lane verdict may
// only ever cite the exact pinned artifact, and there must be exactly one
// implementation of that rule.

const children = new Set();
function spawnChild(cmd, args, opts) {
  const child = spawn(cmd, args, { ...opts, detached: true });
  children.add(child);
  child.on("exit", () => children.delete(child));
  return child;
}
function kill9(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  try {
    process.kill(-child.pid, "SIGKILL");
  } catch {
    try { child.kill("SIGKILL"); } catch { /* already gone */ }
  }
}
process.on("exit", () => { for (const c of children) kill9(c); });
process.on("SIGINT", () => process.exit(130));
process.on("SIGTERM", () => process.exit(143));

// ---------------------------------------------------------------------------
// S3 backend
// ---------------------------------------------------------------------------

/**
 * Start the S3 backend from the SHARED provider descriptor. The only
 * provider-specific knowledge left in this file is the provider's NAME:
 * binary resolution + digest refusal, argv, env, and data-directory
 * creation all come from s3-provider.mjs.
 */
async function startS3({ provider, port, runDir, logFile, access, secret }) {
  const spec = await providerSpawnSpec({
    provider,
    runDir,
    port,
    consolePort: 0,
    credentials: { accessKey: access, secretKey: secret },
  });
  const out = fs.openSync(logFile, "a");
  const child = spawnChild(spec.command, spec.args, {
    env: { ...process.env, ...spec.env },
    stdio: ["ignore", out, out],
  });
  child.spec = spec;
  // readiness = an AUTHENTICATED S3 operation (R4-LOCAL-01), never /health
  for (let i = 0; i < 60; i++) {
    try {
      execFileSync("python3", [S3OP, `http://${LOOPBACK}:${port}`, "list-buckets"], {
        env: { ...process.env, AWS_ACCESS_KEY_ID: access, AWS_SECRET_ACCESS_KEY: secret },
        stdio: "ignore",
        timeout: 15000,
      });
      return child;
    } catch {
      await delay(1000);
    }
  }
  throw new Error(`${provider} never became S3-ready; see ${logFile}`);
}

function createBucket({ port, bucket, access, secret }) {
  execFileSync("python3", [S3OP, `http://${LOOPBACK}:${port}`, "create-bucket", bucket], {
    env: { ...process.env, AWS_ACCESS_KEY_ID: access, AWS_SECRET_ACCESS_KEY: secret },
    stdio: "ignore",
    timeout: 15000,
  });
}

// ---------------------------------------------------------------------------
// TypeDB server
// ---------------------------------------------------------------------------

function serverBinary() {
  const bin = process.env.TYPEDB_SERVER_BIN ?? path.join(REPO, "sources", "typedb", "target", "debug", "typedb_server_bin");
  if (!fs.existsSync(bin)) {
    throw new Error(`typedb server binary absent at ${bin} — build it (cargo build -p typedb_server_bin in sources/typedb) or set TYPEDB_SERVER_BIN`);
  }
  return bin;
}

async function startTypeDB({ name, grpcPort, httpPort, dataDir, logDir, s3Port, prefix, access, secret, profile }) {
  const bin = serverBinary();
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(logDir, { recursive: true });
  const env = {
    ...process.env,
    TYPEDB_STORAGE_PROFILE: profile,
    TYPEDB_S3_ENDPOINT: `http://${LOOPBACK}:${s3Port}`,
    TYPEDB_S3_BUCKET: "native-fidelity",
    TYPEDB_S3_REGION: "auto",
    TYPEDB_S3_ACCESS_KEY_ID: access,
    TYPEDB_S3_SECRET_ACCESS_KEY: secret,
    TYPEDB_S3_PREFIX: prefix,
  };
  const out = fs.openSync(path.join(logDir, "stdout.log"), "a");
  const child = spawnChild(
    bin,
    [
      "--config", path.join(REPO, "sources", "typedb", "server", "config.yml"),
      "--storage.data-directory", dataDir,
      "--server.listen-address", `${LOOPBACK}:${grpcPort}`,
      "--server.http.enabled", "true",
      "--server.http.listen-address", `${LOOPBACK}:${httpPort}`,
      "--diagnostics.reporting.errors", "false",
      "--diagnostics.reporting.metrics", "false",
      "--diagnostics.monitoring.enabled", "false",
      "--logging.directory", logDir,
    ],
    { env, stdio: ["ignore", out, out] },
  );
  for (let i = 0; i < 120; i++) {
    if (child.exitCode !== null) {
      throw new Error(`${name}: typedb server exited rc=${child.exitCode} before ready; see ${logDir}/stdout.log`);
    }
    try {
      const res = await fetch(`http://${LOOPBACK}:${httpPort}/health`, { signal: AbortSignal.timeout(3000) });
      if (res.ok) return child;
    } catch { /* not up yet */ }
    await delay(1000);
  }
  throw new Error(`${name}: typedb server never became healthy; see ${logDir}/stdout.log`);
}

// ---------------------------------------------------------------------------
// Official-HTTP-surface workload
// ---------------------------------------------------------------------------

async function http(base, token, method, route, body) {
  const res = await fetch(`${base}${route}`, {
    method,
    headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(120000),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${route} -> ${res.status}: ${text.slice(0, 300)}`);
  return text ? JSON.parse(text) : null;
}

async function signin(base) {
  const { token } = await http(base, null, "POST", "/v1/signin", { username: "admin", password: "password" });
  return token;
}

async function oneShot(base, token, database, transactionType, query, commit) {
  return http(base, token, "POST", "/v1/query", {
    databaseName: database,
    transactionType,
    query,
    ...(commit ? { commit: true } : {}),
  });
}

/// Define a schema, insert `marker`, and return the read-back names.
async function writeWorkload(base, token, database, marker) {
  await http(base, token, "POST", `/v1/databases/${database}`);
  await oneShot(base, token, database, "schema", "define entity witness, owns tag; attribute tag, value string;", true);
  await oneShot(base, token, database, "write", `insert $w isa witness, has tag "${marker}";`, true);
  return readWorkload(base, token, database);
}

async function readWorkload(base, token, database) {
  const res = await oneShot(base, token, database, "read", "match $w isa witness, has tag $t; select $t;");
  const rows = res?.answers ?? [];
  return rows
    .map((row) => row?.data?.t?.value)
    .filter((v) => typeof v === "string")
    .sort();
}

// ---------------------------------------------------------------------------
// Lane phases
// ---------------------------------------------------------------------------

const results = [];
function phase(name, ok, detail = "") {
  results.push({ name, ok, detail });
  log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) {
    finish();
  }
}

function finish() {
  const failed = results.filter((r) => !r.ok);
  console.log(
    failed.length === 0
      ? `NATIVE-FIDELITY: ALL ${results.length} PHASES PASS`
      : `NATIVE-FIDELITY: ${failed.length} FAILURES`,
  );
  process.exit(failed.length === 0 ? 0 : 1);
}

const providerFlagIndex = process.argv.indexOf("--provider");
const selection = resolveProvider({
  requested: providerFlagIndex >= 0 ? process.argv[providerFlagIndex + 1] : null,
});
const provider = selection.provider;
const basePort = Number(process.env.NATIVE_FIDELITY_BASE_PORT ?? 39400);
const work = fs.mkdtempSync(path.join(os.tmpdir(), "native-fidelity-"));
fs.chmodSync(work, 0o700);
const access = `nf-${crypto.randomBytes(8).toString("hex")}`;
const secret = `nf-${crypto.randomBytes(16).toString("hex")}`;
const runNonce = crypto.randomBytes(4).toString("hex");

log(`provider=${provider} [${selection.selection}] work=${work}`);
// structured, never prose: this lane never implies the promotion gate is
// green, it prints exactly which required lanes have executed and passed
for (const line of formatGate(selection.gate).split("\n")) log(line);

// One S3 server for the whole lane; every stack gets its own proxy+prefix.
const s3Port = basePort;
const s3RunDir = path.join(work, "s3-run");
fs.mkdirSync(s3RunDir, { recursive: true, mode: 0o700 });
const s3 = await startS3({
  provider,
  port: s3Port,
  runDir: s3RunDir,
  logFile: path.join(work, "s3.log"),
  access,
  secret,
});
createBucket({ port: s3Port, bucket: "native-fidelity", access, secret });
log(`s3 up (${provider}) on :${s3Port}`);

async function startStack(name, { grpcPort, httpPort, schedule = [], profile = "U2S3", dataDir }) {
  const proxy = await startFaultProxy({ upstreamPort: s3Port, schedule });
  const stack = {
    name,
    proxy,
    base: `http://${LOOPBACK}:${httpPort}`,
    grpcPort,
    httpPort,
    dataDir: dataDir ?? path.join(work, `${name}-data`),
    logDir: path.join(work, `${name}-logs`),
    prefix: `nf-${runNonce}-${name}`,
    profile,
    server: null,
  };
  stack.server = await startTypeDB({
    name,
    grpcPort,
    httpPort,
    dataDir: stack.dataDir,
    logDir: stack.logDir,
    s3Port: proxy.port,
    prefix: stack.prefix,
    access,
    secret,
    profile,
  });
  return stack;
}

// --- Phase 1: product workload over the real S3 path --------------------
const alpha = await startStack("alpha", { grpcPort: basePort + 10, httpPort: basePort + 11 });
let token = await signin(alpha.base);
const seen = await writeWorkload(alpha.base, token, "nfdb", "alpha-1");
phase("workload-write-read", seen.length === 1 && seen[0] === "alpha-1", JSON.stringify(seen));

const s3Connections = alpha.proxy.report().length;
phase("s3-path-witness-nonzero", s3Connections > 0, `${s3Connections} S3 connections through the proxy`);

// --- Phase 2: kill -9 + restart over same data dir + prefix -------------
kill9(alpha.server);
await delay(1500);
alpha.server = await startTypeDB({
  name: "alpha-restarted",
  grpcPort: basePort + 10,
  httpPort: basePort + 11,
  dataDir: alpha.dataDir,
  logDir: alpha.logDir,
  s3Port: alpha.proxy.port,
  prefix: alpha.prefix,
  access,
  secret,
  profile: "U2S3",
});
token = await signin(alpha.base);
const afterCrash = await readWorkload(alpha.base, token, "nfdb");
phase("crash-restart-recovery", afterCrash.length === 1 && afterCrash[0] === "alpha-1", JSON.stringify(afterCrash));

// --- Phase 3: parallel isolation ----------------------------------------
const beta = await startStack("beta", { grpcPort: basePort + 20, httpPort: basePort + 21 });
const gamma = await startStack("gamma", { grpcPort: basePort + 30, httpPort: basePort + 31 });
const [betaToken, gammaToken] = await Promise.all([signin(beta.base), signin(gamma.base)]);
const [betaSeen, gammaSeen] = await Promise.all([
  writeWorkload(beta.base, betaToken, "nfdb", "beta-only"),
  writeWorkload(gamma.base, gammaToken, "nfdb", "gamma-only"),
]);
phase(
  "parallel-isolation",
  betaSeen.length === 1 && betaSeen[0] === "beta-only" && gammaSeen.length === 1 && gammaSeen[0] === "gamma-only",
  JSON.stringify({ beta: betaSeen, gamma: gammaSeen }),
);
kill9(beta.server);
kill9(gamma.server);
await Promise.all([beta.proxy.close(), gamma.proxy.close()]);

// --- Phase 4: deterministic fault on the live data path ------------------
// A named early connection gets RST; the workload must still converge
// (object_store retries) and the proxy report must show the fault applied.
kill9(alpha.server);
await delay(1000);
const faulted = await startStack("faulted", {
  grpcPort: basePort + 40,
  httpPort: basePort + 41,
  schedule: [{ connection: 3, action: "reset" }],
});
const faultToken = await signin(faulted.base);
const faultSeen = await writeWorkload(faulted.base, faultToken, "nfdb", "fault-survivor");
const applied = faulted.proxy.report().find((r) => r.connection === 3);
phase(
  "fault-injection-survival",
  faultSeen.length === 1 && faultSeen[0] === "fault-survivor" && applied?.action === "reset" && applied?.applied === true,
  JSON.stringify({ seen: faultSeen, fault: applied }),
);
kill9(faulted.server);
await faulted.proxy.close();

// --- Phase 5: witness validity mutant ------------------------------------
// Run the DEFAULT (U1 rocks/file-WAL) profile through a proxy: the S3
// witness must read ZERO connections. This proves the phase-1 counter is
// a real detector — a stack that silently avoided S3 cannot pass it.
const mutant = await startStack("mutant-u1", {
  grpcPort: basePort + 50,
  httpPort: basePort + 51,
  profile: "U1",
});
const mutantToken = await signin(mutant.base);
const mutantSeen = await writeWorkload(mutant.base, mutantToken, "nfdb", "mutant-local");
const mutantConnections = mutant.proxy.report().length;
phase(
  "witness-detects-local-fallback",
  mutantSeen.length === 1 && mutantConnections === 0,
  `local-profile stack made ${mutantConnections} S3 connections (must be 0)`,
);
kill9(mutant.server);
await mutant.proxy.close();

kill9(alpha.server);
await alpha.proxy.close();
kill9(s3);
try { fs.rmSync(work, { recursive: true, force: true }); } catch { /* best effort */ }
finish();
