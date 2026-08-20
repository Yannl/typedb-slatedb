// Provider-neutral native S3 backend descriptors (round-6 R6-LOCAL-01).
//
// Before round 6 the stack had ONE supervisor and it was MinIO-shaped:
// MinIO's argv, MinIO's env, MinIO's data-dir behaviour and MinIO's
// readiness were welded into stack/minio.mjs, and only native-fidelity.mjs
// had an S3_PROVIDER switch (implemented by a second, duplicated spawn
// path). The audit's requirement is not "add a RustFS supervisor" — that
// would be the same mistake twice — but to describe a provider as DATA and
// drive every provider through one supervision code path.
//
// A provider descriptor answers exactly six questions:
//
//   1. lockNodeId       which source-lock node pins the binary;
//   2. resolveBinary    how the binary is materialized and digest-verified;
//   3. dataDir          where its data lives and WHO CREATES IT — RustFS
//                       refuses to start when its volume is missing, MinIO
//                       creates its own; this is a real behavioural
//                       difference and it belongs in the descriptor, not in
//                       an `if (provider === ...)` inside the supervisor;
//   4. argv             the command line for a loopback, per-run instance;
//   5. env              the credential/environment shape;
//   6. readiness        an AUTHENTICATED S3 round-trip (never a TCP poke,
//                       never a sleep) + the unauthenticated health route
//                       for diagnostics only.
//
// MinIO stays a fully supported comparator (R6-LOCAL-01 explicitly says do
// not delete it). A provider that cannot start on this host is reported as
// a typed comparator-unavailable result, not silently skipped and not a
// test failure.

import { createHash } from "node:crypto";
import { createReadStream, existsSync, mkdirSync, chmodSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { fetchMinio, s3ListBuckets } from "./minio.mjs";

export const STACK_DIR = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(STACK_DIR, "..");
export const LOCK_FILE = path.join(REPO_ROOT, "source-lock", "source-lock.json");
export const LOOPBACK = "127.0.0.1";

export class ProviderBinaryAbsentError extends Error {
  constructor(message, detail) {
    super(message);
    this.name = "ProviderBinaryAbsentError";
    this.code = "PROVIDER_BINARY_ABSENT";
    this.detail = detail;
  }
}

export class ProviderDigestMismatchError extends Error {
  constructor(message, detail) {
    super(message);
    this.name = "ProviderDigestMismatchError";
    this.code = "PROVIDER_DIGEST_MISMATCH";
    this.detail = detail;
  }
}

export class UnknownProviderError extends Error {
  constructor(message) {
    super(message);
    this.name = "UnknownProviderError";
    this.code = "UNKNOWN_PROVIDER";
  }
}

export function lockNode(nodeId, lockFile = LOCK_FILE) {
  const lock = JSON.parse(readFileSync(lockFile, "utf8"));
  const node = lock.nodes.find((n) => n.id === nodeId);
  if (!node) throw new Error(`source-lock has no node ${nodeId}`);
  for (const field of ["sha256", "version", "license"]) {
    if (!node[field]) throw new Error(`source-lock ${nodeId} node missing ${field}`);
  }
  return node;
}

export function sha256File(file) {
  return new Promise((resolve, reject) => {
    const h = createHash("sha256");
    const s = createReadStream(file);
    s.on("data", (c) => h.update(c));
    s.on("error", reject);
    s.on("end", () => resolve(h.digest("hex")));
  });
}

/**
 * A locked artifact that is materialized on demand into its gitignored
 * cache_path. The digest is re-verified on EVERY use (cache hits included):
 * a lane verdict may only ever cite the exact pinned bytes.
 */
async function resolveCachedArtifact(nodeId, { lockFile = LOCK_FILE, repoRoot = REPO_ROOT } = {}) {
  const node = lockNode(nodeId, lockFile);
  if (!node.cache_path) throw new Error(`source-lock ${nodeId} node has no cache_path`);
  const file = path.join(repoRoot, node.cache_path);
  if (!existsSync(file)) {
    throw new ProviderBinaryAbsentError(
      `${nodeId} binary absent at ${node.cache_path} — materialize it first (see the lock node's note); ` +
        "refusing rather than substituting another binary",
      { nodeId, expected: file, sha256: node.sha256 },
    );
  }
  const got = await sha256File(file);
  if (got !== node.sha256) {
    throw new ProviderDigestMismatchError(
      `${nodeId} digest mismatch: locked ${node.sha256}, got ${got} — refusing (pinned-artifact rule)`,
      { nodeId, file, want: node.sha256, got },
    );
  }
  chmodSync(file, 0o755);
  return { binary: file, node };
}

// ---------------------------------------------------------------------------
// descriptors
// ---------------------------------------------------------------------------

/** Shared: an authenticated ListBuckets round trip against the endpoint. */
async function s3Readiness({ endpoint, credentials }) {
  await s3ListBuckets({
    endpoint,
    accessKey: credentials.accessKey,
    secretKey: credentials.secretKey,
  });
  return true;
}

export const PROVIDERS = Object.freeze({
  minio: Object.freeze({
    id: "minio",
    lockNodeId: "MINIO",
    role: "comparator",
    note: "mature provider-diversity comparator (R6-LOCAL-01: keep, do not delete)",
    // MinIO creates its own data directory; we still pre-create it so the
    // 0700 mode is OURS and not the umask's.
    createsOwnDataDir: true,
    dataDirName: "minio-data",
    async resolveBinary({ lockFile = LOCK_FILE, cacheDir } = {}) {
      // MinIO is a single locked URL, so it can be fetched on demand.
      const { binary, node } = await fetchMinio({ lockFile, ...(cacheDir ? { cacheDir } : {}) });
      return { binary, node };
    },
    argv({ dataDir, port, consolePort }) {
      return [
        "server",
        dataDir,
        "--address",
        `${LOOPBACK}:${port}`,
        "--console-address",
        `${LOOPBACK}:${consolePort ?? 0}`,
      ];
    },
    env({ credentials, runDir }) {
      return {
        PATH: process.env.PATH,
        HOME: runDir,
        MINIO_ROOT_USER: credentials.accessKey,
        MINIO_ROOT_PASSWORD: credentials.secretKey,
        MINIO_BROWSER: "off",
        MINIO_UPDATE: "off",
      };
    },
    healthPath: "/minio/health/live",
    readiness: s3Readiness,
  }),

  rustfs: Object.freeze({
    id: "rustfs",
    lockNodeId: "RUSTFS",
    role: "agent-local-default-candidate",
    note: "R6-LOCAL-01 promotion candidate; promotion is gated by local-parity.mjs, never asserted here",
    // RustFS REFUSES to start when its volume directory does not exist.
    // This is the concrete reason the descriptor owns data-dir creation.
    createsOwnDataDir: false,
    dataDirName: "rustfs-data",
    async resolveBinary({ lockFile = LOCK_FILE, repoRoot = REPO_ROOT } = {}) {
      return resolveCachedArtifact("RUSTFS", { lockFile, repoRoot });
    },
    argv({ dataDir, port }) {
      return ["server", "--address", `${LOOPBACK}:${port}`, dataDir];
    },
    env({ credentials, runDir }) {
      return {
        PATH: process.env.PATH,
        HOME: runDir,
        RUSTFS_ACCESS_KEY: credentials.accessKey,
        RUSTFS_SECRET_KEY: credentials.secretKey,
        // keep the console off the loopback surface: this is a storage
        // backend for tests, not an operator UI
        RUSTFS_CONSOLE_ENABLE: "false",
      };
    },
    healthPath: "/health",
    readiness: s3Readiness,
  }),
});

export function providerDescriptor(id) {
  const d = PROVIDERS[id];
  if (!d) {
    throw new UnknownProviderError(
      `unknown S3 provider ${JSON.stringify(id)} — known providers: ${Object.keys(PROVIDERS).join(", ")}`,
    );
  }
  return d;
}

export function providerIds() {
  return Object.keys(PROVIDERS);
}

/**
 * Create the provider's data directory according to its descriptor.
 * Returns { dataDir, createdByUs }. Always 0700: a per-run data dir with
 * a umask-widened mode would leak object bytes to other local users.
 */
export function prepareDataDir(descriptor, runDir) {
  const dataDir = path.join(runDir, descriptor.dataDirName);
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  chmodSync(dataDir, 0o700);
  return { dataDir, createdByUs: true, providerWouldCreateItself: descriptor.createsOwnDataDir };
}

/**
 * Everything the provider-neutral supervisor needs to spawn this provider.
 * No provider name appears in the supervisor — only this shape does.
 */
export async function providerSpawnSpec({
  provider,
  runDir,
  port,
  consolePort,
  credentials,
  lockFile = LOCK_FILE,
  repoRoot = REPO_ROOT,
  cacheDir,
}) {
  const descriptor = providerDescriptor(provider);
  const { binary, node } = await descriptor.resolveBinary({ lockFile, repoRoot, cacheDir });
  const { dataDir, providerWouldCreateItself } = prepareDataDir(descriptor, runDir);
  const endpoint = `http://${LOOPBACK}:${port}`;
  return {
    provider,
    descriptor,
    node,
    command: binary,
    args: descriptor.argv({ dataDir, port, consolePort }),
    env: descriptor.env({ credentials, runDir, dataDir, port }),
    dataDir,
    providerWouldCreateItself,
    endpoint,
    healthUrl: `${endpoint}${descriptor.healthPath}`,
    readiness: () => descriptor.readiness({ endpoint, credentials }),
  };
}

export { s3ListBuckets };
