// The combined managed-local topology: one start, one verified teardown
// (round-6 PR6 / R6-LOCAL-01 + R6-LOCAL-02).
//
// This is the glue an LLM agent actually needs:
//
//     node stack/cli.mjs up   --provider rustfs [--s3-only]
//     ... work happens in OTHER process invocations ...
//     node stack/cli.mjs down --verify-clean
//
// The middle step is the whole point. `up` exits; the supervisor owner does
// not. A later, completely separate `down` invocation reaches the owner
// through its 0600 socket with the per-run nonce and gets an authoritative
// answer about the child, instead of trying to re-identify a pid on a host
// where /proc may be restricted.
//
// Nothing here knows what "minio" or "rustfs" mean: it takes a provider
// descriptor (s3-provider.mjs) and drives it through the provider-neutral
// supervisor (supervisor.mjs). Adding a third provider is a descriptor, not
// a code path.

import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { writeFileAtomic } from "./minio.mjs";
import { providerDescriptor, providerSpawnSpec } from "./s3-provider.mjs";
import {
  probeSupervisionCapabilities,
  startSupervised,
  stopSupervised,
  supervisedStatus,
} from "./supervisor.mjs";

export const S3_MANIFEST_SCHEMA = "typedb-r2-stack/s3-backend@1";
/** The 0600 file that carries per-run S3 credentials. */
export const S3_MANIFEST_NAME = "s3.json";
export const S3_COMPONENT = "s3";

export function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

export function s3ManifestPath(runDir) {
  return path.join(runDir, S3_MANIFEST_NAME);
}

export function loadS3Manifest(runDir) {
  const file = s3ManifestPath(runDir);
  if (!existsSync(file)) return null;
  return JSON.parse(readFileSync(file, "utf8"));
}

/**
 * Start a source-locked native S3 backend under owner supervision.
 *
 * Readiness is an AUTHENTICATED S3 round-trip supplied by the descriptor —
 * a TCP connect or a health route would accept a half-started server, and
 * a sleep would accept anything.
 */
export async function startS3Backend({
  provider,
  runDir,
  port,
  consolePort,
  credentials,
  readyTimeoutMs = 60_000,
  lockFile,
  repoRoot,
  cacheDir,
  probe,
} = {}) {
  if (!runDir) throw new Error("startS3Backend requires runDir");
  // the run dir must exist (0700) BEFORE the capability probe: the AF_UNIX
  // probe binds a real socket inside it
  mkdirSync(runDir, { recursive: true, mode: 0o700 });
  chmodSync(runDir, 0o700);
  const descriptor = providerDescriptor(provider);
  const resolvedPort = port ?? (await freePort());
  const resolvedConsolePort = consolePort ?? (await freePort());
  const creds = credentials ?? {
    accessKey: `dev-${randomBytes(9).toString("hex")}`,
    secretKey: randomBytes(24).toString("hex"),
  };

  // capability probe BEFORE any binary resolution or child spawn
  const caps = probe ?? (await probeSupervisionCapabilities({ runDir }));

  const spec = await providerSpawnSpec({
    provider,
    runDir,
    port: resolvedPort,
    consolePort: resolvedConsolePort,
    credentials: creds,
    lockFile,
    repoRoot,
    cacheDir,
  });

  const { record } = await startSupervised({
    runDir,
    component: S3_COMPONENT,
    command: spec.command,
    args: spec.args,
    env: spec.env,
    cwd: runDir,
    logPath: path.join(runDir, `${provider}.log`),
    readiness: spec.readiness,
    readyTimeoutMs,
    port: resolvedPort,
    probe: caps,
    extra: { provider },
  });

  const manifest = {
    schema: S3_MANIFEST_SCHEMA,
    component: S3_COMPONENT,
    provider,
    providerRole: descriptor.role,
    version: spec.node.version,
    binary: spec.command,
    executable: spec.command,
    binarySha256: spec.node.sha256,
    lockNodeId: descriptor.lockNodeId,
    endpoint: spec.endpoint,
    healthUrl: spec.healthUrl,
    port: resolvedPort,
    consolePort: resolvedConsolePort,
    dataDir: spec.dataDir,
    dataDirPreCreated: !spec.providerWouldCreateItself,
    credentials: creds,
    supervision: record,
    supervisionProbe: {
      mechanisms: caps.mechanisms,
      preferred: caps.preferred,
      socketOwner: caps.socketOwner,
      procIdentity: caps.procIdentity,
    },
    startedAt: record.startedAt,
  };
  // 0600: this file carries the per-run root credentials. The ordinary run
  // manifest records only its PATH.
  writeFileAtomic(s3ManifestPath(runDir), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
  const mode = statSync(s3ManifestPath(runDir)).mode & 0o777;
  if (mode !== 0o600) throw new Error(`${S3_MANIFEST_NAME} is mode ${mode.toString(8)}, must be 0600`);
  return { manifest, record, spec };
}

export async function s3BackendStatus(manifest) {
  return supervisedStatus(manifest.supervision);
}

/** Stop the S3 backend and return the typed teardown report. */
export async function stopS3Backend(manifest, opts = {}) {
  const record = manifest.supervision ?? {
    // legacy pre-round-6 minio.json: no supervision block, proc identity only
    schema: "typedb-r2-stack/supervised@1",
    component: manifest.component ?? "minio",
    mechanism: "proc-identity",
    runDir: path.dirname(manifest.dataDir ?? "."),
    pid: manifest.pid,
    pgid: manifest.pgid ?? manifest.pid,
    startTimeTicks: manifest.startTimeTicks,
    executable: manifest.executable ?? manifest.binary,
    port: manifest.port,
    logPath: manifest.logPath ?? null,
  };
  const report = await stopSupervised(record, opts);
  return { ...report, provider: manifest.provider ?? "minio" };
}

// ---------------------------------------------------------------------------
// comparator availability (R6-LOCAL-01)
// ---------------------------------------------------------------------------

/**
 * Try to bring a provider up and straight back down, and report the result
 * as DATA. MinIO cannot start in some agent sandboxes (its host-address
 * discovery hits a denied netlink operation); that is a fact about the
 * host, not a defect in this repo, so it is a typed
 * COMPARATOR_UNAVAILABLE result — never a silent skip and never a test
 * failure. A provider that DOES start reports COMPARATOR_AVAILABLE with
 * the exact locked digest that ran.
 */
export async function probeProvider({ provider, runDir, readyTimeoutMs = 45_000, ...rest }) {
  const startedAt = new Date().toISOString();
  let manifest = null;
  try {
    const started = await startS3Backend({ provider, runDir, readyTimeoutMs, ...rest });
    manifest = started.manifest;
  } catch (err) {
    return {
      schema: "typedb-r2-stack/provider-probe@1",
      provider,
      code: err.code === "PROVIDER_BINARY_ABSENT" ? "COMPARATOR_BINARY_ABSENT" : "COMPARATOR_UNAVAILABLE",
      available: false,
      reason: String(err.message ?? err),
      errorCode: err.code ?? null,
      startedAt,
      checkedAt: new Date().toISOString(),
    };
  }
  const teardown = await stopS3Backend(manifest);
  return {
    schema: "typedb-r2-stack/provider-probe@1",
    provider,
    code: "COMPARATOR_AVAILABLE",
    available: true,
    endpoint: manifest.endpoint,
    binarySha256: manifest.binarySha256,
    version: manifest.version,
    teardown,
    startedAt,
    checkedAt: new Date().toISOString(),
  };
}
