#!/usr/bin/env node
// One-command supervised local stack (audit PR2/PR3 local half; round-6 PR6).
//
//   node cli.mjs up|dev [--mode native] [--provider rustfs|minio]
//                       [--s3-only] [--allow-degraded]
//                       [--require-qualified-provider]
//       ONE command for the combined managed-local topology: platform check
//       → no-cloud guard → wrangler consistency → source-locked native S3
//       provider under OWNER supervision (S3 half) → `alchemy dev`
//       (Worker/DO/local-R2 half) → Worker /health probe → dev: identity
//       assertion → run-identity manifest.
//       --provider: which source-locked native S3 backend to run. Omitted,
//       the agent-local default (graph.data.mjs LOCAL_S3_PROVIDER_DEFAULT)
//       is used and the run manifest carries the STRUCTURED promotion gate
//       from local-parity.mjs — a lane that has not executed in this
//       session is reported NOT_EXECUTED, never assumed green.
//       --s3-only: bring up only the S3 half (the lane native tests and the
//       Rust/TypeDB suites consume); the Alchemy half is skipped, not
//       silently failed — the manifest records mode "s3-only".
//       --allow-degraded: DIAGNOSTIC mode — if the Alchemy half fails, keep
//       the S3 half up for debugging, write a manifest with "degraded":
//       true (never a ready/qualified marker) and exit 2. A degraded run is
//       never a success: exit 0 fully up, 2 degraded-diagnostic, 1 failed.
//   node cli.mjs down [--verify-clean] [--json] [runDir]
//       ONE verified teardown, idempotent, with a TYPED result (never a
//       bare exit code): every supervised component is stopped through its
//       owner socket (or, on hosts without AF_UNIX, through the retained
//       PID+start-time identity check), then teardown is VERIFIED — child
//       gone, owner gone, port released, control socket removed, run-dir
//       control material revoked. Reports TEARDOWN_CLEAN /
//       TEARDOWN_ALREADY_CLEAN / TEARDOWN_INCOMPLETE.
//   node cli.mjs status [--json] [runDir]
//       ask the OWNER what it holds (no pid re-discovery).
//   node cli.mjs lane-status [--provider p] [--json]
//       the executable promotion gate: which required lanes have actually
//       executed and passed in this session.
//   node cli.mjs record-lane --lane L --provider P --status pass|fail
//                            --command "..." [--binary-sha256 H] [--detail D]
//       append a REAL lane result to the session ledger.
//   node cli.mjs provider-probe [--provider p]
//       start+stop each provider once and report typed availability; a
//       provider that cannot run on this host is COMPARATOR_UNAVAILABLE,
//       which is data, not a failure.
//   node cli.mjs graph [variant] [--provider p]
//       emit the normalized desired graph as canonical JSON.
//   node cli.mjs check-wrangler
//       verify control-plane/wrangler.toml against the canonical graph.
//
// Modes: `native` is the only mode implemented here (Alchemy workerd local
// providers + a native source-locked S3 provider). `container`
// (ContainerDO via Docker) and `cloudflare-real` are later PRs; naming them
// is an error, not a silent fallback.

import { execSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  LOCAL_S3_PROVIDERS,
  REPO_ROOT,
  STACK_DIR,
  canonicalJson,
  graphDigest,
  toGraph,
} from "./graph.data.mjs";
import {
  assertDevIdentities,
  assertNoCloudCredentials,
  LOCAL_SYNTHETIC_ACCOUNT_ID,
  LOCAL_SYNTHETIC_API_TOKEN,
  sanitizedEnv,
  staticScan,
} from "./no-cloud-guard.mjs";
import { checkWrangler, WRANGLER_TOML } from "./wrangler-check.mjs";
import {
  assertSupportedPlatform,
  ensureRunRoot,
  portInUse,
  processAlive,
  runRoot,
  verifyRecordedProcess,
  writeFileAtomic,
} from "./minio.mjs";
import {
  loadS3Manifest,
  probeProvider,
  s3BackendStatus,
  s3ManifestPath,
  startS3Backend,
  stopS3Backend,
} from "./managed-local.mjs";
import {
  DEFAULT_PROVIDER,
  evaluateGate,
  formatGate,
  recordLaneResult,
  resolveProvider,
} from "./local-parity.mjs";
import { lockNode, providerDescriptor, providerIds } from "./s3-provider.mjs";
import {
  probeSupervisionCapabilities,
  startSupervised,
  stopSupervised,
  supervisedStatus,
} from "./supervisor.mjs";

const GRAPH_FILE = path.join(STACK_DIR, "alchemy.run.ts");
// resource state rows only (.alchemy also holds logs/local blob data)
const STATE_DIR = path.join(STACK_DIR, ".alchemy", "state");
// pointer lives INSIDE the per-uid 0700 run root (R4-LOCAL-06): two users
// on one machine cannot collide on it
const CURRENT_RUN_POINTER = () => path.join(runRoot(), "current-run");

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");
const fileDigest = (p) => sha256(readFileSync(p));

function fail(msg) {
  console.error(`stack: ${msg}`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// guards shared by dev
// ---------------------------------------------------------------------------

function runGuards() {
  // 0. R4-LOCAL-07: the source lock pins exactly one artifact
  //    (minio-linux-amd64) — refuse any other platform/arch early
  assertSupportedPlatform();

  // 1. credentials must be absent — a local run may never be able to reach
  //    a real Cloudflare account, so a set credential is a refusal
  assertNoCloudCredentials(process.env);

  // 2. static no-cloud scan of the canonical graph file — transitive over
  //    every reachable relative import (R4-STACK-06)
  const violations = staticScan(GRAPH_FILE);
  if (violations.length > 0) {
    fail(
      `no-cloud guard refused ${path.relative(REPO_ROOT, GRAPH_FILE)}:\n  - ${violations.join("\n  - ")}`,
    );
  }

  // 3. the committed wrangler.toml must match the canonical graph
  const drift = checkWrangler();
  if (drift.length > 0) {
    fail(`wrangler.toml drifted from the canonical graph:\n  - ${drift.join("\n  - ")}`);
  }
}

// ---------------------------------------------------------------------------
// run identity (R4-STACK-09)
// ---------------------------------------------------------------------------

function gitInfo() {
  try {
    const head = execSync("git rev-parse HEAD", { cwd: REPO_ROOT, encoding: "utf8" }).trim();
    const dirty = execSync("git status --porcelain", { cwd: REPO_ROOT, encoding: "utf8" })
      .split("\n")
      .filter((l) => l.trim().length > 0).length;
    return { head, dirtyPathCount: dirty };
  } catch (err) {
    return { head: null, dirtyPathCount: null, error: String(err.message ?? err) };
  }
}

/** Digest over a source tree: files sorted by relative path, each hashed
 *  as path NUL content NUL — renames, additions and edits all move it. */
function treeDigest(root) {
  const files = [];
  (function walk(dir) {
    for (const name of readdirSync(dir).sort()) {
      const p = path.join(dir, name);
      const st = statSync(p);
      if (st.isDirectory()) walk(p);
      else if (st.isFile()) files.push(p);
    }
  })(root);
  files.sort();
  const h = createHash("sha256");
  for (const f of files) {
    h.update(path.relative(root, f));
    h.update("\0");
    h.update(readFileSync(f));
    h.update("\0");
  }
  return h.digest("hex");
}

export function buildRunIdentity(graph, s3Node, provider) {
  const git = gitInfo();
  const identity = {
    // pre-R4 fields (kept for compatibility)
    graphDigest: graphDigest(graph),
    graphFileSha256: fileDigest(GRAPH_FILE),
    graphDataSha256: fileDigest(path.join(STACK_DIR, "graph.data.mjs")),
    wranglerTomlSha256: fileDigest(WRANGLER_TOML),
    packageLockSha256: fileDigest(path.join(STACK_DIR, "package-lock.json")),
    // R6-LOCAL-01: provider-neutral. The identity names WHICH provider ran
    // and pins its exact locked digest — an evidence bundle that cites a
    // provider must be able to prove which binary produced it.
    s3Provider: provider,
    s3BinarySha256: s3Node.sha256,
    s3Version: s3Node.version,
    // R4-STACK-09: outer commit + dirty state, source/workspace locks,
    // Worker/controller source tree, actual node version
    gitHead: git.head,
    gitDirtyPathCount: git.dirtyPathCount,
    sourceLockSha256: fileDigest(path.join(REPO_ROOT, "source-lock", "source-lock.json")),
    workspaceLockSha256: fileDigest(path.join(REPO_ROOT, "source-lock", "workspace-lock.json")),
    controlPlaneSrcDigest: treeDigest(path.join(REPO_ROOT, "control-plane", "src")),
    nodeVersion: process.version,
    // R4-STACK-09: the TypeDB fork build and the OCI image are not
    // materialized locally yet — recorded as null (not omitted) until an
    // artifact exists to hash; a QUALIFIED verdict must treat null here
    // as "identity incomplete".
    typedbArtifactSha256: null,
    ociImageDigest: null,
  };
  // one root digest over every input above (canonical key order)
  const canonical = JSON.stringify(
    Object.fromEntries(Object.entries(identity).sort(([a], [b]) => (a < b ? -1 : 1))),
  );
  identity.release_input_root = sha256(canonical);
  return identity;
}

// ---------------------------------------------------------------------------
// dev
// ---------------------------------------------------------------------------

async function cmdDev(args) {
  const mode = argValue(args, "--mode") ?? "native";
  if (mode !== "native") {
    fail(`mode ${JSON.stringify(mode)} is not implemented in this PR (only "native"); refusing rather than silently substituting another mode`);
  }
  const allowDegraded = args.includes("--allow-degraded");
  const s3Only = args.includes("--s3-only");
  const requestedProvider = argValue(args, "--provider") ?? null;
  const requireQualified =
    args.includes("--require-qualified-provider") || process.env.STACK_REQUIRE_QUALIFIED_PROVIDER === "1";

  runGuards();

  // R6-LOCAL-01: provider selection is explicit and its WORTH is measured.
  let selection;
  try {
    selection = resolveProvider({ requested: requestedProvider, requireQualified });
  } catch (err) {
    fail(`${err.code ?? "PROVIDER_SELECTION_FAILED"}: ${String(err.message ?? err)}`);
    return;
  }
  const provider = selection.provider;

  const root = ensureRunRoot(); // 0700, per-uid, ownership-verified
  const runDir = path.join(
    root,
    `run-${new Date().toISOString().replace(/[:.]/g, "-")}-${randomBytes(3).toString("hex")}`,
  );
  mkdirSync(runDir, { recursive: true, mode: 0o700 });
  chmodSync(runDir, 0o700); // umask masks mkdir's mode bits

  // R6-LOCAL-02: probe the host's supervision capabilities BEFORE any child
  // exists. If neither the owner socket nor /proc identity works, refuse
  // here — a started child we could never verifiably stop is worse than no
  // stack at all.
  const probe = await probeSupervisionCapabilities({ runDir });
  if (!probe.usable) {
    console.error(`stack: SUPERVISION_UNSUPPORTED — nothing was started.`);
    console.error(`  owner socket:   ${probe.socketOwner.reason}`);
    console.error(`  /proc identity: ${probe.procIdentity.reason}`);
    process.exit(1);
  }
  console.log(`stack: supervision mechanisms available: ${probe.mechanisms.join(", ")} (using ${probe.preferred})`);
  console.log(
    `stack: S3 provider ${provider} [${selection.selection}] — promotion gate ${selection.gate.state}` +
      (selection.gate.missing.length ? ` (lanes not passed in this session: ${selection.gate.missing.join(", ")})` : ""),
  );

  const graph = toGraph("local-native", REPO_ROOT, { s3Provider: provider });
  const s3Node = lockNode(providerDescriptor(provider).lockNodeId);
  const manifest = {
    schema: "typedb-r2-stack/run@1",
    mode: s3Only ? "native-s3-only" : mode,
    provider,
    // structured, never prose: what we selected, why, and what the audit's
    // required lanes have ACTUALLY done in this session
    providerSelection: {
      provider,
      selection: selection.selection,
      requestedBy: selection.requestedBy,
      comparator: selection.comparator,
    },
    providerGate: selection.gate,
    supervision: {
      mechanisms: probe.mechanisms,
      preferred: probe.preferred,
      socketOwner: probe.socketOwner,
      procIdentity: probe.procIdentity,
    },
    startedAt: new Date().toISOString(),
    runDir,
    repoRoot: REPO_ROOT,
    // run identity: digests of every config/input the run depends on
    identity: buildRunIdentity(graph, s3Node, provider),
    components: {},
  };
  writeFileAtomic(path.join(runDir, "graph.json"), canonicalJson(graph));

  // R4-STACK-05: every child started below is torn down in the catch arm
  // if any later step fails — we hold the exact objects we spawned, so
  // teardown identity is certain here.
  let s3 = null;
  let alchemyRecord = null;
  try {
    // ---- S3 half: source-locked native provider under owner supervision --
    console.log(`stack: starting source-locked ${provider} (S3 half) under owner supervision...`);
    const started = await startS3Backend({ provider, runDir, probe });
    s3 = started.manifest;
    // R4-LOCAL-06: the run manifest must NEVER contain the credentials —
    // they live only in the 0600 s3.json; record its path.
    const { credentials: _creds, ...s3Redacted } = s3;
    manifest.components.s3 = { ...s3Redacted, credentialsFile: s3ManifestPath(runDir) };
    console.log(
      `stack: ${provider} ready on ${s3.endpoint} (child pid ${s3.supervision.pid}, owner pid ${s3.supervision.ownerPid ?? "n/a"}, mechanism ${s3.supervision.mechanism})`,
    );

    // ---- Cloudflare-facing half: alchemy dev ----------------------------
    if (s3Only) {
      // NOT a degraded run and NOT a silent partial: an explicitly narrowed
      // topology, named in the manifest, that the native/Rust lanes consume.
      manifest.components.alchemy = {
        status: "not-started",
        reason: "--s3-only: the Worker/DO/local-R2 half was not requested",
      };
      manifest.readyAt = new Date().toISOString();
      writeFileAtomic(path.join(runDir, "run.json"), `${JSON.stringify(manifest, null, 2)}\n`);
      writeFileAtomic(CURRENT_RUN_POINTER(), `${runDir}\n`);
      console.log(`stack: up (s3-only). run manifest: ${path.join(runDir, "run.json")}`);
      console.log(`stack: S3 endpoint ${s3.endpoint}; credentials: ${s3ManifestPath(runDir)} (0600)`);
      console.log(`stack: tear down with: node cli.mjs down --verify-clean`);
      return;
    }

    console.log("stack: starting alchemy dev (Worker/DO/local-R2 half) under owner supervision...");
    const alchemy = await startAlchemyDev(runDir, probe);
    alchemyRecord = alchemy.supervision ?? null;
    manifest.components.alchemy = alchemy;

    if (alchemy.status !== "running") {
      if (!allowDegraded) {
        throw new Error(
          `alchemy dev did not reach ready (${alchemy.status}: ${alchemy.reason}); ` +
            `rerun with --allow-degraded to keep the S3 half up for diagnosis (exits 2, never a success)`,
        );
      }
      // R4-STACK-04: --allow-degraded is a distinct DIAGNOSTIC outcome —
      // nonzero exit, "degraded": true, and no ready/qualified marker.
      manifest.degraded = true;
      writeFileAtomic(path.join(runDir, "run.json"), `${JSON.stringify(manifest, null, 2)}\n`);
      writeFileAtomic(CURRENT_RUN_POINTER(), `${runDir}\n`);
      console.error(`stack: DEGRADED (diagnostic only) — alchemy half not running: ${alchemy.reason}`);
      console.error(`stack: degraded manifest: ${path.join(runDir, "run.json")} — this run is NOT ready and can never be QUALIFIED`);
      console.error(`stack: tear down with: node cli.mjs down --verify-clean`);
      process.exit(2);
    }

    // every emulated resource id must be dev: — no state at all is also a
    // failure once alchemy claimed to be running
    const idViolations = assertDevIdentities(STATE_DIR, { allowMissing: false });
    if (idViolations.length > 0) {
      throw new Error(`dev: identity assertion failed:\n  - ${idViolations.join("\n  - ")}`);
    }
    manifest.components.alchemy.devIdentityCheck = "pass";

    manifest.readyAt = new Date().toISOString();
    writeFileAtomic(path.join(runDir, "run.json"), `${JSON.stringify(manifest, null, 2)}\n`);
    writeFileAtomic(CURRENT_RUN_POINTER(), `${runDir}\n`);
    console.log(`stack: up. run manifest: ${path.join(runDir, "run.json")}`);
    console.log(`stack: tear down with: node cli.mjs down --verify-clean`);
  } catch (err) {
    // fail closed: tear down every child this invocation started, through
    // the same owner-verified path a later `down` would use
    if (alchemyRecord) await stopSupervised(alchemyRecord).catch(() => {});
    if (s3) await stopS3Backend(s3).catch(() => {});
    fail(String(err.message ?? err));
  }
}

/**
 * The Alchemy dev child goes through the SAME provider-neutral supervisor
 * as the S3 provider: one owner, one 0600 socket, one nonce, one teardown
 * path. Readiness is unchanged in substance (R4-STACK-04) — a loopback URL
 * in the log is only a candidate; ready means the Worker answers /health
 * with the L1 body — but the log is now the owner-written file rather than
 * a pipe this process holds, which is exactly what lets a LATER invocation
 * stop this child.
 */
async function startAlchemyDev(runDir, probe) {
  const logPath = path.join(runDir, "alchemy.log");
  const env = {
    ...sanitizedEnv(process.env),
    CI: "1", // suppress interactive ink UI where supported
    ALCHEMY_STAGE: "dev",
    // R4-STACK-02 handshake: alchemy.run.ts refuses to load unless this
    // exact acknowledgement is present, and `cli.mjs dev` is the ONLY
    // invoker that may set it. It also refuses if any CLOUDFLARE_*/CF_*
    // credential variable is set — sanitizedEnv() above already strips
    // them all (and assertNoCloudCredentials() refused the run outright
    // if they were present), so the child env stays credential-free.
    ALCHEMY_LOCAL_ONLY_ACK: "stack-cli-dev",
    // Alchemy's LOCAL providers resolve the full credential chain even
    // though nothing leaves the machine; inject the SYNTHETIC pair (the
    // only values alchemy.run.ts's assertion and the guard accept). The
    // token is self-evidently fake and can never authenticate.
    CLOUDFLARE_ACCOUNT_ID: LOCAL_SYNTHETIC_ACCOUNT_ID,
    CLOUDFLARE_API_TOKEN: LOCAL_SYNTHETIC_API_TOKEN,
  };
  const timeoutMs = Number(process.env.STACK_ALCHEMY_READY_TIMEOUT_MS ?? 180_000);
  const urlRe = /https?:\/\/(?:localhost|127\.0\.0\.1):\d+/;
  let url = null;
  let lastHealth = null;

  const readiness = async () => {
    const logText = existsSync(logPath) ? readFileSync(logPath, "utf8") : "";
    const m = logText.match(urlRe);
    if (!m) throw new Error("no candidate loopback URL in the alchemy log yet");
    const health = await probeWorkerHealth(`${m[0]}/health`);
    lastHealth = health;
    if (!health.ok) throw new Error(health.reason ?? "worker /health not ready");
    url = m[0];
  };

  try {
    const { record } = await startSupervised({
      runDir,
      component: "alchemy",
      command: process.execPath,
      args: [path.join(STACK_DIR, "node_modules", "alchemy", "bin", "cli.js"), "dev", "--stage", "dev", GRAPH_FILE],
      env,
      cwd: STACK_DIR,
      logPath,
      readiness,
      readyTimeoutMs: timeoutMs,
      probe,
    });
    // the Worker's port is only known once readiness resolved it from the
    // log; record it so teardown VERIFIES the port is released too
    if (url) record.port = Number(new URL(url).port);
    return {
      status: "running",
      supervision: record,
      pid: record.pid,
      pgid: record.pgid,
      startTimeTicks: record.startTimeTicks,
      executable: record.executable,
      url,
      healthCheck: lastHealth,
      logPath,
      credentials:
        "synthetic placeholders only (real Cloudflare credentials are refused and stripped; see no-cloud guard)",
    };
  } catch (err) {
    // typed, not swallowed: the caller decides whether a non-running
    // alchemy half is fatal or a diagnostic --allow-degraded run
    return {
      status: err.code === "CHILD_EXITED_BEFORE_READY" ? "failed" : err.code === "READINESS_TIMEOUT" ? "timeout" : "failed",
      reason: String(err.message ?? err),
      errorCode: err.code ?? null,
      logPath,
      healthCheck: lastHealth,
    };
  }
}

/**
 * R4-STACK-04: semantic health probe against the local Worker's /health
 * (control-plane/src/controller/worker-entry.ts). Ready requires HTTP 200
 * AND the expected L1 body — a stray loopback URL from an unrelated
 * process/log line will not answer this shape. The full result is
 * recorded in the run manifest.
 */
async function probeWorkerHealth(url) {
  const checkedAt = new Date().toISOString();
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(3_000) });
    const text = await res.text();
    let body = null;
    try {
      body = JSON.parse(text);
    } catch {}
    const ok = res.status === 200 && body?.ok === true && body?.stack === "L1-local";
    return {
      url,
      status: res.status,
      body: body ?? text.slice(0, 200),
      ok,
      checkedAt,
      ...(ok ? {} : { reason: `expected HTTP 200 with {ok:true, stack:"L1-local"}, got HTTP ${res.status}: ${text.slice(0, 200)}` }),
    };
  } catch (err) {
    return { url, status: null, ok: false, checkedAt, reason: String(err.message ?? err) };
  }
}

// ---------------------------------------------------------------------------
// down
// ---------------------------------------------------------------------------

/**
 * Stop every supervised component of a run and VERIFY it. Each component
 * goes through stopSupervised(), which prefers the owner socket (works on
 * hosts with a restricted /proc) and falls back to the retained PID +
 * start-time identity check. Nothing is ever signalled blind.
 */
async function stopStack(manifest) {
  const components = [];
  const runDir = manifest.runDir;

  const alchemy = manifest.components?.alchemy;
  if (alchemy?.supervision) {
    components.push(await stopSupervised(alchemy.supervision));
  } else if (alchemy?.pid) {
    // legacy manifest (pre-round-6): proc-identity record reconstructed
    components.push(
      await stopSupervised({
        schema: "typedb-r2-stack/supervised@1",
        component: "alchemy",
        mechanism: "proc-identity",
        runDir,
        pid: alchemy.pid,
        pgid: alchemy.pgid ?? alchemy.pid,
        startTimeTicks: alchemy.startTimeTicks,
        executable: alchemy.executable,
        port: alchemy.url ? Number(new URL(alchemy.url).port) : undefined,
        logPath: alchemy.logPath ?? null,
      }),
    );
  }

  // s3.json (round-6, provider-neutral) or a legacy minio.json
  const s3 = loadS3Manifest(runDir);
  if (s3) {
    components.push(await stopS3Backend(s3));
  } else {
    const legacy = path.join(runDir, "minio.json");
    if (existsSync(legacy)) {
      components.push(await stopS3Backend(JSON.parse(readFileSync(legacy, "utf8"))));
    }
  }
  return components;
}

/**
 * Scan every recorded run under the run root for survivors. A pid counts
 * as a survivor only when it can still be POSITIVELY identified as ours —
 * either an owner still answers on its socket, or the recorded /proc
 * identity still matches. An unverifiable pid is never assumed dead and
 * never signalled.
 */
async function scanForSurvivors() {
  const problems = [];
  const root = runRoot();
  for (const entry of existsSync(root) ? readdirSync(root) : []) {
    if (!entry.startsWith("run-")) continue;
    const dir = path.join(root, entry);
    const records = [];
    for (const name of ["run.json", "s3.json", "minio.json"]) {
      const file = path.join(dir, name);
      if (!existsSync(file)) continue;
      let doc;
      try {
        doc = JSON.parse(readFileSync(file, "utf8"));
      } catch {
        continue;
      }
      if (doc.supervision) records.push(doc.supervision);
      if (doc.components?.alchemy?.supervision) records.push(doc.components.alchemy.supervision);
      if (doc.components?.s3?.supervision) records.push(doc.components.s3.supervision);
      if (!doc.supervision && doc.pid) {
        records.push({
          component: doc.component ?? "minio",
          mechanism: "proc-identity",
          runDir: dir,
          pid: doc.pid,
          startTimeTicks: doc.startTimeTicks,
          executable: doc.executable ?? doc.binary,
          port: doc.port,
        });
      }
    }
    for (const record of records) {
      if (record.mechanism === "owner-socket" && record.socketPath && existsSync(record.socketPath)) {
        problems.push(`surviving ${record.component} supervisor owner still serving ${record.socketPath} (from ${entry})`);
        continue;
      }
      if (
        record.pid &&
        processAlive(record.pid) &&
        verifyRecordedProcess({
          pid: record.pid,
          startTimeTicks: record.startTimeTicks,
          executable: record.executable,
        }).ok
      ) {
        problems.push(`surviving ${record.component} process pid ${record.pid} from ${entry}`);
      }
      if (record.port && (await portInUse(record.port))) {
        problems.push(`surviving ${record.component} port ${record.port} from ${entry}`);
      }
    }
  }
  return problems;
}

async function cmdDown(args) {
  const verifyClean = args.includes("--verify-clean");
  const asJson = args.includes("--json");
  const explicit = args.find((x) => !x.startsWith("--"));
  let runDir = explicit;
  if (!runDir) {
    const ptr = CURRENT_RUN_POINTER();
    if (!existsSync(ptr)) fail("no current run pointer and no runDir argument");
    runDir = readFileSync(ptr, "utf8").trim();
  }
  const runJson = path.join(runDir, "run.json");
  if (!existsSync(runJson)) fail(`no run manifest at ${runJson}`);
  const manifest = JSON.parse(readFileSync(runJson, "utf8"));

  const components = await stopStack(manifest);
  const problems = components.flatMap((c) => c.problems.map((p) => `${c.component}: ${p}`));
  const survivors = verifyClean ? await scanForSurvivors() : [];
  problems.push(...survivors);

  const ok = problems.length === 0;
  const allAlreadyClean = components.length > 0 && components.every((c) => c.code === "TEARDOWN_ALREADY_CLEAN");
  const report = {
    schema: "typedb-r2-stack/stack-teardown@1",
    // TYPED, not a bare exit code (R6-LOCAL-02 / PR6 exit criterion)
    code: ok ? (allAlreadyClean ? "TEARDOWN_ALREADY_CLEAN" : "TEARDOWN_CLEAN") : "TEARDOWN_INCOMPLETE",
    ok,
    runDir,
    provider: manifest.provider ?? null,
    stoppedAt: new Date().toISOString(),
    verifyClean,
    components,
    survivors,
    problems,
  };
  writeFileAtomic(path.join(runDir, "down.json"), `${JSON.stringify(report, null, 2)}\n`);

  // R6-LOCAL-01 lane evidence: a clean, VERIFIED start->teardown cycle is
  // exactly the "one-command supervisor start/readiness/teardown path"
  // lane. It is recorded here because it just executed - never in advance.
  if (ok && verifyClean && manifest.provider && manifest.components?.s3?.binarySha256) {
    try {
      recordLaneResult({
        lane: "supervision",
        provider: manifest.provider,
        status: "pass",
        binarySha256: manifest.components.s3.binarySha256,
        command: "node cli.mjs up ... (separate invocation) node cli.mjs down --verify-clean",
        detail: `run ${path.basename(runDir)}: ${components.map((c) => `${c.component}=${c.code}`).join(" ")}`,
      });
    } catch (err) {
      console.error(`stack down: lane result not recorded: ${String(err.message ?? err)}`);
    }
  }

  if (asJson) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!ok) {
    console.error(`stack down: ${report.code}`);
    for (const p of problems) console.error(`  - ${p}`);
    process.exit(1);
  }
  if (!asJson) {
    console.log(`stack down: ${report.code}`);
    for (const c of components) {
      console.log(
        `  ${c.component} (${c.provider ?? "-"}) via ${c.via}: ${c.checks.map((x) => `${x.name}=${x.ok ? "ok" : "FAIL"}`).join(" ")}`,
      );
    }
    console.log(`  report: ${path.join(runDir, "down.json")}`);
  }
}

// ---------------------------------------------------------------------------
// status / lane-status / record-lane / provider-probe (R6-LOCAL-01/02)
// ---------------------------------------------------------------------------

function resolveRunDir(args) {
  const explicit = args.find((x) => !x.startsWith("--"));
  if (explicit) return explicit;
  const ptr = CURRENT_RUN_POINTER();
  if (!existsSync(ptr)) fail("no current run pointer and no runDir argument");
  return readFileSync(ptr, "utf8").trim();
}

/** Ask the OWNER. No pid re-discovery anywhere in this path. */
async function cmdStatus(args) {
  const runDir = resolveRunDir(args);
  const runJson = path.join(runDir, "run.json");
  if (!existsSync(runJson)) fail(`no run manifest at ${runJson}`);
  const manifest = JSON.parse(readFileSync(runJson, "utf8"));
  const out = {
    schema: "typedb-r2-stack/run-status@1",
    runDir,
    mode: manifest.mode,
    provider: manifest.provider ?? null,
    providerSelection: manifest.providerSelection ?? null,
    providerGate: manifest.providerGate
      ? { state: manifest.providerGate.state, missing: manifest.providerGate.missing }
      : null,
    components: {},
  };
  const s3 = loadS3Manifest(runDir);
  if (s3) {
    out.components.s3 = {
      endpoint: s3.endpoint,
      provider: s3.provider,
      ...(await s3BackendStatus(s3).catch((e) => ({ error: e.code ?? "ERROR", reason: String(e.message ?? e) }))),
    };
  }
  const alchemy = manifest.components?.alchemy;
  if (alchemy?.supervision) {
    out.components.alchemy = {
      url: alchemy.url ?? null,
      ...(await supervisedStatus(alchemy.supervision).catch((e) => ({
        error: e.code ?? "ERROR",
        reason: String(e.message ?? e),
      }))),
    };
  }
  process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
}

function cmdLaneStatus(args) {
  const provider = argValue(args, "--provider") ?? DEFAULT_PROVIDER;
  const gate = evaluateGate({ provider });
  if (args.includes("--json")) {
    process.stdout.write(`${JSON.stringify(gate, null, 2)}\n`);
  } else {
    console.log(formatGate(gate));
  }
  // exit 0: reporting an OPEN gate is a successful REPORT. --require-green
  // makes an open gate a failure for callers (CI/release) that need one.
  if (args.includes("--require-green") && gate.state !== "GREEN") process.exit(1);
}

function cmdRecordLane(args) {
  const lane = argValue(args, "--lane");
  const provider = argValue(args, "--provider") ?? DEFAULT_PROVIDER;
  const status = argValue(args, "--status");
  const command = argValue(args, "--command");
  if (!lane || !status || !command) {
    fail("record-lane requires --lane, --status pass|fail and --command (the exact command that produced the result)");
  }
  const entry = recordLaneResult({
    lane,
    provider,
    status,
    command,
    binarySha256: argValue(args, "--binary-sha256") ?? null,
    detail: argValue(args, "--detail") ?? null,
  });
  process.stdout.write(`${JSON.stringify(entry, null, 2)}\n`);
}

/**
 * Start and stop each provider once and report typed availability. A
 * provider that cannot run on this host (MinIO's host-address discovery
 * hits a denied netlink operation in some agent sandboxes) is
 * COMPARATOR_UNAVAILABLE - a fact about the host, recorded as data.
 */
async function cmdProviderProbe(args) {
  const only = argValue(args, "--provider");
  const providers = only ? [only] : providerIds();
  const root = ensureRunRoot();
  const results = [];
  for (const provider of providers) {
    const runDir = path.join(root, `probe-${provider}-${randomBytes(3).toString("hex")}`);
    mkdirSync(runDir, { recursive: true, mode: 0o700 });
    chmodSync(runDir, 0o700);
    results.push(await probeProvider({ provider, runDir, readyTimeoutMs: 45_000 }));
  }
  process.stdout.write(
    `${JSON.stringify(
      { schema: "typedb-r2-stack/provider-probe-set@1", checkedAt: new Date().toISOString(), results },
      null,
      2,
    )}\n`,
  );
  // an unavailable comparator is DATA, not a failure; only a provider that
  // was explicitly asked for and could not start is an error
  if (only && !results[0].available) process.exit(1);
}

// ---------------------------------------------------------------------------
// graph / check-wrangler
// ---------------------------------------------------------------------------

function cmdGraph(args) {
  const variant = args.find((x) => !x.startsWith("--")) ?? "local-native";
  // R6-LOCAL-01: the graph is provider-parameterized like everything else.
  // With no --provider the agent-local default is used, exactly as `up`
  // would use it, so `stack graph` and a real run cannot disagree.
  const requested = argValue(args, "--provider");
  if (requested && !LOCAL_S3_PROVIDERS.includes(requested)) {
    fail(`unknown local S3 provider ${JSON.stringify(requested)} — known: ${LOCAL_S3_PROVIDERS.join(", ")}`);
  }
  const s3Provider = requested ?? resolveProvider({}).provider;
  process.stdout.write(canonicalJson(toGraph(variant, REPO_ROOT, { s3Provider })));
}

function cmdCheckWrangler() {
  const findings = checkWrangler();
  if (findings.length > 0) {
    console.error("WRANGLER CONSISTENCY: FAIL");
    for (const f of findings) console.error(`  - ${f}`);
    process.exit(1);
  }
  console.log("WRANGLER CONSISTENCY: PASS (control-plane/wrangler.toml matches the canonical graph)");
}

// ---------------------------------------------------------------------------

function argValue(args, flag) {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

const [cmd, ...rest] = process.argv.slice(2);
switch (cmd) {
  // `up` is the round-6 name for the ONE command that brings up the
  // combined managed-local topology; `dev` is kept as its alias so no
  // existing script or npm alias breaks.
  case "up":
  case "dev":
    await cmdDev(rest);
    break;
  case "down":
  case "teardown":
    await cmdDown(rest);
    break;
  case "status":
    await cmdStatus(rest);
    break;
  case "lane-status":
    cmdLaneStatus(rest);
    break;
  case "record-lane":
    cmdRecordLane(rest);
    break;
  case "provider-probe":
    await cmdProviderProbe(rest);
    break;
  case "graph":
    cmdGraph(rest);
    break;
  case "check-wrangler":
    cmdCheckWrangler();
    break;
  default:
    console.error(
      [
        "usage:",
        "  cli.mjs up|dev [--mode native] [--provider rustfs|minio] [--s3-only]",
        "                 [--allow-degraded (diagnostic: exit 2, never success)]",
        "                 [--require-qualified-provider]",
        "  cli.mjs down|teardown [--verify-clean] [--json] [runDir]",
        "  cli.mjs status [runDir]",
        "  cli.mjs lane-status [--provider p] [--json] [--require-green]",
        "  cli.mjs record-lane --lane L --status pass|fail --command C [--provider p] [--binary-sha256 H] [--detail D]",
        "  cli.mjs provider-probe [--provider p]",
        "  cli.mjs graph [variant] [--provider p]",
        "  cli.mjs check-wrangler",
      ].join("\n"),
    );
    process.exit(2);
}
