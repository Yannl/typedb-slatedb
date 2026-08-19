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
//   - the download path is serialized: a process-local singleflight map
//     plus an inter-process `${bin}.lock` lockfile (R4-LOCAL-05); bytes
//     stream into an O_CREAT|O_EXCL|O_NOFOLLOW random temp with an
//     incremental sha256 and a hard byte ceiling, then fsync + atomic
//     rename + directory fsync; redirects are followed only to https
//     URLs on pinned hosts;
//   - it starts on loopback with RANDOM per-run credentials and a unique
//     per-run data directory; nothing is shared between runs; the run
//     root and run dirs are 0700 and uid-checked, and the credentials
//     file (minio.json) is 0600 (R4-LOCAL-06);
//   - readiness is a REAL S3 API probe (SigV4-signed ListBuckets must
//     return the ListAllMyBucketsResult document), not a sleep;
//   - the run manifest records pid/pgid/port/data dir/binary digest PLUS
//     the process start time (/proc/<pid>/stat field 22) and executable
//     path, so teardown can prove it is signaling the process it started
//     and not a recycled pid (R4-STACK-05); teardown kills the whole
//     process group only after that identity check and verifies the port
//     is actually released.

import { execFileSync, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  createReadStream,
  createWriteStream,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const STACK_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(STACK_DIR, "..");
const LOCK_FILE = path.join(REPO_ROOT, "source-lock", "source-lock.json");

export const MINIO_NODE_ID = "MINIO";
// uncommitted cache (sources/ is gitignored; materialized on demand)
export const CACHE_DIR = path.join(REPO_ROOT, "sources", "minio");

// Hard download ceiling (R4-LOCAL-05): comfortably above the locked
// 110,989,496-byte artifact, small enough that a runaway/poisoned stream
// cannot fill the disk.
export const MAX_DOWNLOAD_BYTES = 150 * 1024 * 1024;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// typed errors
// ---------------------------------------------------------------------------

export class UnsupportedPlatformError extends Error {
  constructor(message) {
    super(message);
    this.name = "UnsupportedPlatformError";
    this.code = "UNSUPPORTED_PLATFORM";
  }
}

export class DownloadTooLargeError extends Error {
  constructor(message) {
    super(message);
    this.name = "DownloadTooLargeError";
    this.code = "DOWNLOAD_BYTE_CEILING_EXCEEDED";
  }
}

/**
 * R4-LOCAL-07: the source lock pins exactly ONE artifact
 * (minio-linux-amd64). Any other platform/arch must fail early and
 * honestly instead of downloading a binary that cannot run — locking
 * additional artifacts is a deliberate future change, not a fallback.
 */
export function assertSupportedPlatform() {
  const { platform, arch } = process;
  if (platform === "linux" && arch === "x64") return;
  throw new UnsupportedPlatformError(
    `unsupported platform ${platform}/${arch}: the source lock pins exactly one MinIO artifact ` +
      `(minio-linux-amd64, node ${MINIO_NODE_ID}) and this stack currently runs only on linux/x64 — ` +
      `refusing early rather than fetching an incompatible binary (R4-LOCAL-07)`,
  );
}

// ---------------------------------------------------------------------------
// run root (R4-LOCAL-06): per-uid, 0700, ownership-verified
// ---------------------------------------------------------------------------

export function runRoot() {
  if (process.env.STACK_RUN_ROOT) return process.env.STACK_RUN_ROOT;
  const uid = typeof process.getuid === "function" ? process.getuid() : "nouid";
  // uid in the path: two users on one machine can never collide on the
  // run root or the current-run pointer inside it
  return path.join(os.tmpdir(), `typedb-r2-stack-${uid}`);
}

/**
 * Create (or validate) the run root: mode 0700 (chmod after mkdir — umask
 * masks mkdirSync's mode bits), owned by this uid. A pre-existing root
 * owned by another uid is refused; a wider mode is tightened to 0700 and
 * refused if the tightening does not stick.
 */
export function ensureRunRoot(root = runRoot()) {
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const st = statSync(root);
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  if (uid !== undefined && st.uid !== uid) {
    throw new Error(
      `refusing run root ${root}: owned by uid ${st.uid}, not this process's uid ${uid}`,
    );
  }
  if ((st.mode & 0o077) !== 0) chmodSync(root, 0o700);
  const st2 = statSync(root);
  if ((st2.mode & 0o077) !== 0) {
    throw new Error(
      `refusing run root ${root}: mode ${(st2.mode & 0o777).toString(8)} is wider than 0700 and could not be tightened`,
    );
  }
  return root;
}

// ---------------------------------------------------------------------------
// durable file writes (R4-STACK-05): create-new temp + fsync + atomic
// rename + directory fsync
// ---------------------------------------------------------------------------

export function writeFileAtomic(file, data, { mode = 0o644 } = {}) {
  const dir = path.dirname(file);
  const tmp = path.join(dir, `.${path.basename(file)}.tmp.${randomBytes(6).toString("hex")}`);
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const fd = openSync(tmp, "wx", mode);
  try {
    let off = 0;
    while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
    fsyncSync(fd);
  } catch (err) {
    try {
      closeSync(fd);
    } catch {}
    try {
      unlinkSync(tmp);
    } catch {}
    throw err;
  }
  closeSync(fd);
  try {
    renameSync(tmp, file);
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {}
    throw err;
  }
  const dfd = openSync(dir, "r");
  try {
    fsyncSync(dfd);
  } finally {
    closeSync(dfd);
  }
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

/** Stream-hash a file (R4-LOCAL-05: never readFileSync whole artifacts). */
export function sha256File(file) {
  return new Promise((resolve, reject) => {
    const h = createHash("sha256");
    const s = createReadStream(file);
    s.on("data", (chunk) => h.update(chunk));
    s.on("error", reject);
    s.on("end", () => resolve(h.digest("hex")));
  });
}

export function cachedBinaryPath(node, cacheDir = CACHE_DIR) {
  return path.join(cacheDir, `minio-RELEASE.${node.version}`);
}

// --- inter-process download lock (R4-LOCAL-05) -----------------------------

const LOCK_STALE_MS = 10 * 60 * 1000;

async function acquireDownloadLock(lockPath, { waitMs = 120_000 } = {}) {
  const deadline = Date.now() + waitMs;
  let backoff = 50;
  for (;;) {
    try {
      const fd = openSync(lockPath, "wx", 0o600);
      try {
        const info = Buffer.from(JSON.stringify({ pid: process.pid, at: new Date().toISOString() }));
        writeSync(fd, info);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      return;
    } catch (err) {
      if (err.code !== "EEXIST") throw err;
      // a stale lock (older than 10 min) may be broken only after
      // verifying the pid it recorded is dead
      try {
        const st = statSync(lockPath);
        if (Date.now() - st.mtimeMs > LOCK_STALE_MS) {
          let holderDead = true;
          try {
            const info = JSON.parse(readFileSync(lockPath, "utf8"));
            if (info.pid && processAlive(info.pid)) holderDead = false;
          } catch {} // unreadable/corrupt lock past the stale window → treat holder as dead
          if (holderDead) {
            try {
              unlinkSync(lockPath);
            } catch {}
            continue;
          }
        }
      } catch {} // lock vanished between EEXIST and stat → just retry
      if (Date.now() > deadline) {
        throw new Error(`timed out after ${waitMs}ms waiting for download lock ${lockPath}`);
      }
      await sleep(backoff);
      backoff = Math.min(backoff * 2, 1000);
    }
  }
}

// --- pinned-redirect fetch (R4-LOCAL-05) -----------------------------------

/**
 * Hosts a redirect may land on, per download URL. dl.min.io's canonical
 * archive path redirects to the github.com/minio/minio release asset,
 * which GitHub serves from its *.githubusercontent.com asset CDN — those
 * are the ONLY legitimate hops for the locked artifact.
 */
export function allowedRedirectHosts(url) {
  const first = new URL(url).hostname;
  const hosts = new Set([first]);
  if (first === "dl.min.io") {
    hosts.add("github.com");
    hosts.add("objects.githubusercontent.com");
    hosts.add("release-assets.githubusercontent.com");
  }
  return hosts;
}

async function fetchPinned(url, fetchImpl, { maxRedirects = 5 } = {}) {
  const allowed = allowedRedirectHosts(url);
  let current = url;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    const res = await fetchImpl(current, { redirect: "manual" });
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (!loc) throw new Error(`redirect (${res.status}) without Location from ${current}`);
      const next = new URL(loc, current);
      if (next.protocol !== "https:") {
        throw new Error(`refusing redirect to non-https URL ${next.href} (from ${current})`);
      }
      if (!allowed.has(next.hostname)) {
        throw new Error(
          `refusing redirect to unpinned host ${next.hostname} (from ${current}; allowed: ${[...allowed].join(", ")})`,
        );
      }
      try {
        await res.body?.cancel();
      } catch {}
      current = next.href;
      continue;
    }
    return res;
  }
  throw new Error(`too many redirects (> ${maxRedirects}) fetching ${url}`);
}

// --- streamed, ceilinged, incremental-hash download ------------------------

async function downloadVerified(node, bin, fetchImpl) {
  const tmp = `${bin}.download.${randomBytes(8).toString("hex")}`;
  const openFlags =
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW;
  const fd = openSync(tmp, openFlags, 0o755);
  let fdOpen = true;
  let tmpGone = false;
  try {
    const res = await fetchPinned(node.url, fetchImpl);
    if (!res.ok || !res.body) {
      throw new Error(`MinIO download failed: ${res.status} ${res.statusText} from ${node.url}`);
    }
    const hash = createHash("sha256");
    let total = 0;
    for await (const chunk of res.body) {
      const buf = Buffer.from(chunk);
      total += buf.length;
      if (total > MAX_DOWNLOAD_BYTES) {
        // throwing aborts the for-await, which cancels the stream
        throw new DownloadTooLargeError(
          `MinIO download exceeded the ${MAX_DOWNLOAD_BYTES}-byte ceiling after ${total} bytes — aborting (locked artifact is 110,989,496 bytes)`,
        );
      }
      hash.update(buf); // incremental: the artifact is never held in memory
      let off = 0;
      while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
    }
    const got = hash.digest("hex");
    fsyncSync(fd);
    closeSync(fd);
    fdOpen = false;
    if (got !== node.sha256) {
      renameSync(tmp, `${bin}.quarantine`);
      tmpGone = true;
      throw new Error(
        `MinIO digest mismatch on download: locked ${node.sha256}, got ${got} — refusing (quarantined ${bin}.quarantine)`,
      );
    }
    renameSync(tmp, bin);
    tmpGone = true;
    const dfd = openSync(path.dirname(bin), "r");
    try {
      fsyncSync(dfd);
    } finally {
      closeSync(dfd);
    }
  } finally {
    if (fdOpen) {
      try {
        closeSync(fd);
      } catch {}
    }
    if (!tmpGone) {
      try {
        unlinkSync(tmp);
      } catch {}
    }
  }
}

// process-local singleflight (R4-LOCAL-05): one download per binary path
// per process, no matter how many concurrent ensure/fetch calls
const inflightDownloads = new Map();

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
    if (!inflightDownloads.has(bin)) {
      const flight = (async () => {
        mkdirSync(cacheDir, { recursive: true });
        const lockPath = `${bin}.lock`;
        await acquireDownloadLock(lockPath);
        try {
          // recheck under the lock: another PROCESS may have finished
          if (!existsSync(bin)) await downloadVerified(node, bin, fetchImpl);
        } finally {
          try {
            unlinkSync(lockPath);
          } catch {}
        }
      })();
      inflightDownloads.set(
        bin,
        flight.finally(() => inflightDownloads.delete(bin)),
      );
    }
    await inflightDownloads.get(bin);
  }
  const got = await sha256File(bin);
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
// process identity (R4-STACK-05): a pid is only "our child" if the
// cmdline names the recorded executable AND (on Linux) the /proc start
// time matches what we recorded at spawn — a recycled pid fails both.
// ---------------------------------------------------------------------------

/** /proc/<pid>/stat field 22 (starttime, clock ticks); null off-Linux. */
export function procStartTimeTicks(pid) {
  if (process.platform !== "linux") return null;
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    // comm (field 2) may contain spaces/parens: split after the LAST ')'
    const rest = stat.slice(stat.lastIndexOf(")") + 1).trim().split(/\s+/);
    // rest[0] is field 3 (state) → field 22 is rest[19]
    const ticks = Number(rest[19]);
    return Number.isFinite(ticks) ? ticks : null;
  } catch {
    return null;
  }
}

/** Full command line for a pid (/proc on Linux, `ps` fallback elsewhere). */
export function procCmdline(pid) {
  if (process.platform === "linux") {
    try {
      return readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0").filter(Boolean).join(" ");
    } catch {
      return null;
    }
  }
  try {
    const out = execFileSync("ps", ["-o", "command=", "-p", String(pid)], { encoding: "utf8" }).trim();
    return out || null;
  } catch {
    return null;
  }
}

/**
 * Verify a manifest-recorded process before signaling it.
 * Returns { alive, ok, reason }: ok=true only when the live process's
 * cmdline contains the recorded executable AND, on Linux, its start time
 * matches the recorded ticks. Unverifiable ⇒ ok=false (refuse to signal).
 */
export function verifyRecordedProcess({ pid, startTimeTicks, executable }) {
  if (!pid || !processAlive(pid)) return { alive: false, ok: false, reason: `pid ${pid} is not alive` };
  if (!executable) {
    return { alive: true, ok: false, reason: `manifest records no executable for pid ${pid} — refusing to signal an unverifiable process` };
  }
  const cmdline = procCmdline(pid);
  if (cmdline === null) {
    return { alive: true, ok: false, reason: `cannot read the command line of pid ${pid} — refusing to signal an unverifiable process` };
  }
  if (!cmdline.includes(executable)) {
    return {
      alive: true,
      ok: false,
      reason: `pid ${pid} cmdline ${JSON.stringify(cmdline.slice(0, 160))} does not name recorded executable ${executable} (recycled pid?)`,
    };
  }
  if (process.platform === "linux") {
    const now = procStartTimeTicks(pid);
    if (startTimeTicks == null || now == null || now !== startTimeTicks) {
      return {
        alive: true,
        ok: false,
        reason: `pid ${pid} start time ${now} does not match recorded ${startTimeTicks} (recycled pid?)`,
      };
    }
  }
  return { alive: true, ok: true };
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
 * written to `<runDir>/minio.json` — the 0600 CREDENTIALS file; the
 * ordinary run manifest must reference its path, never its contents).
 */
export async function startMinio({ runDir, lockFile = LOCK_FILE, cacheDir = CACHE_DIR, readyTimeoutMs = 30_000 } = {}) {
  const { binary, node } = await fetchMinio({ lockFile, cacheDir });
  if (!runDir) {
    const root = ensureRunRoot();
    runDir = path.join(root, `run-${new Date().toISOString().replace(/[:.]/g, "-")}-${randomBytes(3).toString("hex")}`);
  }
  mkdirSync(runDir, { recursive: true, mode: 0o700 });
  chmodSync(runDir, 0o700); // umask may have masked mkdir's mode bits
  const dataDir = path.join(runDir, "minio-data");
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  chmodSync(dataDir, 0o700);

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
  // R4-STACK-05: identity recorded at spawn so teardown can verify it is
  // signaling THIS process, not a later occupant of a recycled pid
  const startTimeTicks = procStartTimeTicks(child.pid);
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
      await sleep(200);
    }
  }

  const manifest = {
    component: "minio",
    version: node.version,
    binary,
    executable: binary,
    binarySha256: node.sha256,
    url: node.url,
    pid: child.pid,
    pgid: child.pid, // detached → leader of its own group
    startTimeTicks,
    endpoint,
    port,
    consolePort,
    credentials: { accessKey, secretKey },
    dataDir,
    logPath,
    startedAt,
  };
  // R4-LOCAL-06: this file carries the root credentials — 0600, atomic,
  // durable. The ordinary run manifest records only its PATH.
  writeFileAtomic(path.join(runDir, "minio.json"), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
  return { manifest, runDir, child };
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
 * Kill the MinIO process group and verify the port is released. Signals
 * are sent only after verifyRecordedProcess() proves the recorded pid is
 * still the process we spawned (R4-STACK-05). Returns a teardown report;
 * throws if identity cannot be verified or the process/port survives.
 */
export async function stopMinio(manifest, { killTimeoutMs = 10_000 } = {}) {
  const { pid, pgid, port } = manifest;
  const identity = {
    pid,
    startTimeTicks: manifest.startTimeTicks,
    executable: manifest.executable ?? manifest.binary,
  };
  const check = verifyRecordedProcess(identity);
  if (check.alive && !check.ok) {
    throw new Error(`refusing to signal MinIO pid ${pid}: ${check.reason}`);
  }
  if (check.ok) {
    try {
      process.kill(-pgid, "SIGTERM");
    } catch {} // already gone
    const deadline = Date.now() + killTimeoutMs;
    while (processAlive(pid) && Date.now() < deadline) {
      await sleep(100);
    }
    if (processAlive(pid)) {
      // re-verify before escalating: the pid must still be ours
      const again = verifyRecordedProcess(identity);
      if (again.ok) {
        try {
          process.kill(-pgid, "SIGKILL");
        } catch {}
        await sleep(500);
      }
    }
    if (processAlive(pid) && verifyRecordedProcess(identity).ok) {
      throw new Error(`MinIO pid ${pid} survived SIGTERM+SIGKILL`);
    }
  }
  // port release can lag the process by a beat
  const portDeadline = Date.now() + 5_000;
  while ((await portInUse(port)) && Date.now() < portDeadline) {
    await sleep(100);
  }
  if (await portInUse(port)) {
    throw new Error(`MinIO port ${port} still accepting connections after teardown`);
  }
  return { pid, port, stoppedAt: new Date().toISOString(), portReleased: true };
}

// ---------------------------------------------------------------------------
// CLI: node minio.mjs fetch|start|stop <runDir>
// ---------------------------------------------------------------------------

const invokedDirectly =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  assertSupportedPlatform();
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
