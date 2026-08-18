// Source-locked native MinIO: fetch, verify, supervise, tear down.
//
// The TypeDB/SlateDB half of the stack consumes a real S3 endpoint
// (object_store AmazonS3Builder: SigV4, XML API, conditional puts,
// multipart). Alchemy's local R2 has no S3 listener (audit §6.3), so this
// module runs the pinned native MinIO from source-lock node MINIO:
//
//   - the binary is downloaded from the EXACT locked URL and verified
//     against the locked sha256 — always, including cache hits; a mismatch
//     is a refusal, never a warning (the tampered file is quarantined);
//   - it starts on loopback with RANDOM per-run credentials and a unique
//     per-run data directory; nothing is shared between runs;
//   - readiness is a REAL S3 API probe (SigV4-signed ListBuckets must
//     return the ListAllMyBucketsResult document), not a sleep;
//   - the run manifest records pid/pgid/port/credentials/data dir/binary
//     digest; teardown kills the whole process group and verifies the
//     port is actually released.

import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  createWriteStream,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { fileURLToPath } from "node:url";

const STACK_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(STACK_DIR, "..");
const LOCK_FILE = path.join(REPO_ROOT, "source-lock", "source-lock.json");

export const MINIO_NODE_ID = "MINIO";
// uncommitted cache (sources/ is gitignored; materialized on demand)
export const CACHE_DIR = path.join(REPO_ROOT, "sources", "minio");

export function runRoot() {
  return process.env.STACK_RUN_ROOT ?? path.join(os.tmpdir(), "typedb-r2-stack");
}

// ---------------------------------------------------------------------------
// lock node + fetch/verify
// ---------------------------------------------------------------------------

export function minioLockNode(lockFile = LOCK_FILE) {
  const lock = JSON.parse(readFileSync(lockFile, "utf8"));
  const node = lock.nodes.find((n) => n.id === MINIO_NODE_ID);
  if (!node) throw new Error(`source-lock has no ${MINIO_NODE_ID} node`);
  for (const field of ["url", "sha256", "version", "license"]) {
    if (!node[field]) throw new Error(`source-lock ${MINIO_NODE_ID} node missing ${field}`);
  }
  return node;
}

export function sha256File(file) {
  const h = createHash("sha256");
  h.update(readFileSync(file));
  return h.digest("hex");
}

export function cachedBinaryPath(node, cacheDir = CACHE_DIR) {
  return path.join(cacheDir, `minio-RELEASE.${node.version}`);
}

/**
 * Ensure the locked MinIO binary is present and verified. Returns its
 * path. Every call re-verifies the digest — a tampered cache entry is
 * moved aside as *.quarantine and the call fails (mutant lane: tamper the
 * hash in a lock copy, or the cached bytes, and this must refuse).
 */
export async function fetchMinio({ lockFile = LOCK_FILE, cacheDir = CACHE_DIR, fetchImpl = fetch } = {}) {
  const node = minioLockNode(lockFile);
  const bin = cachedBinaryPath(node, cacheDir);
  if (!existsSync(bin)) {
    mkdirSync(cacheDir, { recursive: true });
    const tmp = `${bin}.download.${process.pid}`;
    const res = await fetchImpl(node.url, { redirect: "follow" });
    if (!res.ok || !res.body) {
      throw new Error(`MinIO download failed: ${res.status} ${res.statusText} from ${node.url}`);
    }
    await pipeline(Readable.fromWeb(res.body), createWriteStream(tmp, { mode: 0o755 }));
    const got = sha256File(tmp);
    if (got !== node.sha256) {
      renameSync(tmp, `${bin}.quarantine`);
      throw new Error(
        `MinIO digest mismatch on download: locked ${node.sha256}, got ${got} — refusing (quarantined ${bin}.quarantine)`,
      );
    }
    renameSync(tmp, bin);
  }
  const got = sha256File(bin);
  if (got !== node.sha256) {
    renameSync(bin, `${bin}.quarantine`);
    throw new Error(
      `MinIO digest mismatch in cache: locked ${node.sha256}, got ${got} — refusing (quarantined ${bin}.quarantine)`,
    );
  }
  chmodSync(bin, 0o755);
  return { binary: bin, node };
}

// ---------------------------------------------------------------------------
// start / readiness / teardown
// ---------------------------------------------------------------------------

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

export function portInUse(port, host = "127.0.0.1") {
  return new Promise((resolve) => {
    const sock = net.connect({ port, host });
    const done = (v) => {
      sock.destroy();
      resolve(v);
    };
    sock.once("connect", () => done(true));
    sock.once("error", () => done(false));
    sock.setTimeout(1000, () => done(false));
  });
}

/** SigV4-signed ListBuckets — a real S3 API probe, not a TCP check. */
export async function s3ListBuckets({ endpoint, accessKey, secretKey }) {
  // aws4fetch is already pinned in this workspace (alchemy dependency)
  const { AwsClient } = await import("aws4fetch");
  const client = new AwsClient({
    accessKeyId: accessKey,
    secretAccessKey: secretKey,
    service: "s3",
    region: "us-east-1",
  });
  const res = await client.fetch(`${endpoint}/`, { method: "GET" });
  const body = await res.text();
  if (res.status !== 200 || !body.includes("ListAllMyBucketsResult")) {
    throw new Error(`S3 probe failed: HTTP ${res.status}: ${body.slice(0, 200)}`);
  }
  return true;
}

/**
 * Start a supervised per-run MinIO. Returns the manifest fragment (also
 * written to `<runDir>/minio.json`).
 */
export async function startMinio({ runDir, lockFile = LOCK_FILE, cacheDir = CACHE_DIR, readyTimeoutMs = 30_000 } = {}) {
  const { binary, node } = await fetchMinio({ lockFile, cacheDir });
  if (!runDir) {
    runDir = path.join(runRoot(), `run-${new Date().toISOString().replace(/[:.]/g, "-")}-${randomBytes(3).toString("hex")}`);
  }
  const dataDir = path.join(runDir, "minio-data");
  mkdirSync(dataDir, { recursive: true });

  const port = await freePort();
  const consolePort = await freePort();
  const accessKey = `dev-${randomBytes(9).toString("hex")}`;
  const secretKey = randomBytes(24).toString("hex");
  const endpoint = `http://127.0.0.1:${port}`;

  const child = spawn(
    binary,
    ["server", dataDir, "--address", `127.0.0.1:${port}`, "--console-address", `127.0.0.1:${consolePort}`],
    {
      detached: true, // own process group → teardown kills the whole group
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        // minimal, no ambient credential inheritance
        PATH: process.env.PATH,
        HOME: runDir,
        MINIO_ROOT_USER: accessKey,
        MINIO_ROOT_PASSWORD: secretKey,
        MINIO_BROWSER: "off",
        MINIO_UPDATE: "off",
      },
    },
  );
  const logPath = path.join(runDir, "minio.log");
  const log = createWriteStream(logPath, { flags: "a" });
  child.stdout.pipe(log);
  child.stderr.pipe(log);
  child.unref();

  const startedAt = new Date().toISOString();
  let exited = null;
  child.on("exit", (code, signal) => {
    exited = { code, signal };
  });

  // readiness: real S3 API round-trip
  const deadline = Date.now() + readyTimeoutMs;
  let lastErr;
  for (;;) {
    if (exited) {
      throw new Error(
        `MinIO exited before ready (code=${exited.code} signal=${exited.signal}); log: ${logPath}`,
      );
    }
    try {
      await s3ListBuckets({ endpoint, accessKey, secretKey });
      break;
    } catch (err) {
      lastErr = err;
      if (Date.now() > deadline) {
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {}
        throw new Error(`MinIO not ready within ${readyTimeoutMs}ms: ${lastErr}`);
      }
      await new Promise((r) => setTimeout(r, 200));
    }
  }

  const manifest = {
    component: "minio",
    version: node.version,
    binary,
    binarySha256: node.sha256,
    url: node.url,
    pid: child.pid,
    pgid: child.pid, // detached → leader of its own group
    endpoint,
    port,
    consolePort,
    credentials: { accessKey, secretKey },
    dataDir,
    logPath,
    startedAt,
  };
  writeFileSync(path.join(runDir, "minio.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  return { manifest, runDir };
}

export function processAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/**
 * Kill the MinIO process group and verify the port is released. Returns a
 * teardown report; throws if the process or port survives.
 */
export async function stopMinio(manifest, { killTimeoutMs = 10_000 } = {}) {
  const { pgid, port } = manifest;
  try {
    process.kill(-pgid, "SIGTERM");
  } catch {} // already gone
  const deadline = Date.now() + killTimeoutMs;
  while (processAlive(manifest.pid) && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 100));
  }
  if (processAlive(manifest.pid)) {
    try {
      process.kill(-pgid, "SIGKILL");
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  if (processAlive(manifest.pid)) {
    throw new Error(`MinIO pid ${manifest.pid} survived SIGTERM+SIGKILL`);
  }
  // port release can lag the process by a beat
  const portDeadline = Date.now() + 5_000;
  while ((await portInUse(port)) && Date.now() < portDeadline) {
    await new Promise((r) => setTimeout(r, 100));
  }
  if (await portInUse(port)) {
    throw new Error(`MinIO port ${port} still accepting connections after teardown`);
  }
  return { pid: manifest.pid, port, stoppedAt: new Date().toISOString(), portReleased: true };
}

// ---------------------------------------------------------------------------
// CLI: node minio.mjs fetch|start|stop <runDir>
// ---------------------------------------------------------------------------

const invokedDirectly =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  const cmd = process.argv[2];
  if (cmd === "fetch") {
    const { binary, node } = await fetchMinio();
    console.log(`MinIO ${node.version} verified at ${binary} (sha256 ${node.sha256})`);
  } else if (cmd === "start") {
    const { manifest, runDir } = await startMinio({ runDir: process.argv[3] });
    console.log(JSON.stringify({ runDir, ...manifest }, null, 2));
  } else if (cmd === "stop") {
    const manifest = JSON.parse(readFileSync(path.join(process.argv[3], "minio.json"), "utf8"));
    console.log(JSON.stringify(await stopMinio(manifest), null, 2));
  } else {
    console.error("usage: node minio.mjs fetch | start [runDir] | stop <runDir>");
    process.exit(2);
  }
}
