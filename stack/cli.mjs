#!/usr/bin/env node
// One-command supervised local stack (audit PR2/PR3, local half).
//
//   node cli.mjs dev [--mode native] [--allow-degraded]
//       zero-cloud-risk local bring-up: platform check → no-cloud guard →
//       wrangler consistency → pinned MinIO (S3 half) → `alchemy dev`
//       (Worker/DO/local-R2 half) → Worker /health probe → dev: identity
//       assertion → run-identity manifest.
//       --allow-degraded: DIAGNOSTIC mode — if the Alchemy half fails,
//       keep the MinIO half up for debugging, write a manifest with
//       "degraded": true (never a ready/qualified marker) and exit 2.
//       A degraded run is never a success: exit 0 means fully up, exit 2
//       means degraded-diagnostic, exit 1 means failed.
//   node cli.mjs down [--verify-clean] [runDir]
//       teardown: verify recorded process identity (start time +
//       executable) before signaling, kill recorded process groups,
//       verify ports released and no surviving processes/state
//       collisions; nonzero if any remain.
//   node cli.mjs graph [variant]
//       emit the normalized desired graph as canonical JSON.
//   node cli.mjs check-wrangler
//       verify control-plane/wrangler.toml against the canonical graph.
//
// Modes: `native` is the only mode implemented here (Alchemy workerd local
// providers + native MinIO). `container` (ContainerDO via Docker) and
// `cloudflare-real` are later PRs; naming them is an error, not a silent
// fallback.

import { spawn, execSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  createWriteStream,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
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
  minioLockNode,
  portInUse,
  procStartTimeTicks,
  processAlive,
  runRoot,
  startMinio,
  stopMinio,
  verifyRecordedProcess,
  writeFileAtomic,
} from "./minio.mjs";

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

export function buildRunIdentity(graph, minioNode) {
  const git = gitInfo();
  const identity = {
    // pre-R4 fields (kept for compatibility)
    graphDigest: graphDigest(graph),
    graphFileSha256: fileDigest(GRAPH_FILE),
    graphDataSha256: fileDigest(path.join(STACK_DIR, "graph.data.mjs")),
    wranglerTomlSha256: fileDigest(WRANGLER_TOML),
    packageLockSha256: fileDigest(path.join(STACK_DIR, "package-lock.json")),
    minioBinarySha256: minioNode.sha256,
    minioVersion: minioNode.version,
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

  runGuards();

  const root = ensureRunRoot(); // 0700, per-uid, ownership-verified
  const runDir = path.join(
    root,
    `run-${new Date().toISOString().replace(/[:.]/g, "-")}-${randomBytes(3).toString("hex")}`,
  );
  mkdirSync(runDir, { recursive: true, mode: 0o700 });
  chmodSync(runDir, 0o700); // umask masks mkdir's mode bits

  const graph = toGraph("local-native");
  const minioNode = minioLockNode();
  const manifest = {
    schema: "typedb-r2-stack/run@1",
    mode,
    startedAt: new Date().toISOString(),
    runDir,
    repoRoot: REPO_ROOT,
    // run identity: digests of every config/input the run depends on
    identity: buildRunIdentity(graph, minioNode),
    components: {},
  };
  writeFileAtomic(path.join(runDir, "graph.json"), canonicalJson(graph));

  // R4-STACK-05: every child started below is torn down in the catch arm
  // if any later step fails — we hold the exact objects we spawned, so
  // teardown identity is certain here.
  let minio = null;
  let alchemyChild = null;
  try {
    // ---- S3 half: pinned native MinIO -----------------------------------
    console.log("stack: starting source-locked MinIO (S3 half)...");
    const started = await startMinio({ runDir });
    minio = started.manifest;
    // R4-LOCAL-06: the run manifest must NEVER contain the credentials —
    // they live only in the 0600 minio.json; record its path.
    const { credentials: _creds, ...minioRedacted } = minio;
    manifest.components.minio = {
      ...minioRedacted,
      credentialsFile: path.join(runDir, "minio.json"),
    };
    console.log(`stack: MinIO ready on ${minio.endpoint} (pid ${minio.pid})`);

    // ---- Cloudflare-facing half: alchemy dev ----------------------------
    console.log("stack: starting alchemy dev (Worker/DO/local-R2 half)...");
    const alchemy = await startAlchemyDev(runDir);
    alchemyChild = alchemy.child;
    delete alchemy.child; // ChildProcess handle is not manifest material
    manifest.components.alchemy = alchemy;

    if (alchemy.status !== "running") {
      if (!allowDegraded) {
        throw new Error(
          `alchemy dev did not reach ready (${alchemy.status}: ${alchemy.reason}); ` +
            `rerun with --allow-degraded to keep the MinIO half up for diagnosis (exits 2, never a success)`,
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
    // fail closed: tear down every child this invocation started, using
    // the exact handles we hold (no pid-recycling ambiguity possible)
    if (alchemyChild?.pid) {
      try {
        process.kill(-alchemyChild.pid, "SIGKILL");
      } catch {
        try {
          alchemyChild.kill("SIGKILL");
        } catch {}
      }
    }
    if (minio) await stopMinio(minio).catch(() => {});
    fail(String(err.message ?? err));
  }
}

async function startAlchemyDev(runDir) {
  const logPath = path.join(runDir, "alchemy.log");
  const log = createWriteStream(logPath, { flags: "a" });
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
  const child = spawn(
    process.execPath,
    [path.join(STACK_DIR, "node_modules", "alchemy", "bin", "cli.js"), "dev", "--stage", "dev", GRAPH_FILE],
    { cwd: STACK_DIR, env, detached: true, stdio: ["ignore", "pipe", "pipe"] },
  );
  let logText = "";
  const onData = (d) => {
    logText += d.toString();
    log.write(d);
  };
  child.stdout.on("data", onData);
  child.stderr.on("data", onData);
  child.unref();

  // R4-STACK-05: identity recorded at spawn for verified teardown
  const startTimeTicks = procStartTimeTicks(child.pid);

  let exited = null;
  child.on("exit", (code, signal) => {
    exited = { code, signal };
  });

  const timeoutMs = Number(process.env.STACK_ALCHEMY_READY_TIMEOUT_MS ?? 180_000);
  const deadline = Date.now() + timeoutMs;
  const urlRe = /https?:\/\/(?:localhost|127\.0\.0\.1):\d+/;
  let lastHealth = null;
  for (;;) {
    // R4-STACK-04: a loopback URL in the logs is only a CANDIDATE — ready
    // means the expected Worker answers its /health endpoint with HTTP
    // 200 and the L1 body ({ok:true, stack:"L1-local"}). A documentation
    // or error line containing a URL can never satisfy this.
    const m = logText.match(urlRe);
    if (m) {
      const health = await probeWorkerHealth(`${m[0]}/health`);
      lastHealth = health;
      if (health.ok) {
        return {
          status: "running",
          pid: child.pid,
          pgid: child.pid,
          startTimeTicks,
          executable: process.execPath,
          url: m[0],
          healthCheck: health,
          logPath,
          credentials:
            "synthetic placeholders only (real Cloudflare credentials are refused and stripped; see no-cloud guard)",
          child,
        };
      }
    }
    if (exited) {
      return {
        status: "failed",
        reason: `alchemy dev exited (code=${exited.code} signal=${exited.signal}); log tail: ${logText.slice(-2000)}`,
        logPath,
        healthCheck: lastHealth,
        child,
      };
    }
    if (Date.now() > deadline) {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {}
      const healthNote = lastHealth
        ? `; last /health probe: ${JSON.stringify(lastHealth)}`
        : "; no candidate URL appeared in the logs";
      return {
        status: "timeout",
        reason: `no healthy Worker within ${timeoutMs}ms${healthNote}; log tail: ${logText.slice(-2000)}`,
        logPath,
        healthCheck: lastHealth,
        child,
      };
    }
    await new Promise((r) => setTimeout(r, 250));
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

async function stopStack(manifest) {
  const problems = [];
  const a = manifest.components?.alchemy;
  if (a?.pid) {
    // R4-STACK-05: never signal a manifest-recorded pid without proving
    // it is still the process we spawned (start time + executable)
    const identity = { pid: a.pid, startTimeTicks: a.startTimeTicks, executable: a.executable };
    const check = verifyRecordedProcess(identity);
    if (check.alive && !check.ok) {
      problems.push(`refusing to signal alchemy pid ${a.pid}: ${check.reason}`);
    } else if (check.ok) {
      try {
        process.kill(-a.pgid, "SIGTERM");
      } catch {}
      const deadline = Date.now() + 10_000;
      while (processAlive(a.pid) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 100));
      if (processAlive(a.pid) && verifyRecordedProcess(identity).ok) {
        try {
          process.kill(-a.pgid, "SIGKILL");
        } catch {}
        await new Promise((r) => setTimeout(r, 500));
      }
      if (processAlive(a.pid) && verifyRecordedProcess(identity).ok) {
        problems.push(`alchemy pid ${a.pid} survived SIGTERM+SIGKILL`);
      }
    }
    if (a.url) {
      const port = Number(new URL(a.url).port);
      const deadline2 = Date.now() + 5_000;
      while ((await portInUse(port)) && Date.now() < deadline2) await new Promise((r) => setTimeout(r, 100));
      if (await portInUse(port)) problems.push(`alchemy port ${port} still accepting connections`);
    }
  }
  const minioManifestPath = path.join(manifest.runDir, "minio.json");
  if (existsSync(minioManifestPath)) {
    const minio = JSON.parse(readFileSync(minioManifestPath, "utf8"));
    try {
      await stopMinio(minio); // verifies recorded identity itself
    } catch (err) {
      problems.push(String(err.message ?? err));
    }
  }
  return problems;
}

async function cmdDown(args) {
  const verifyClean = args.includes("--verify-clean");
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

  const problems = await stopStack(manifest);

  if (verifyClean) {
    // no survivor from ANY recorded run may remain (state collisions):
    // scan every run manifest under the run root for live pids/ports.
    // A pid counts as a survivor only when its recorded identity still
    // matches (R4-STACK-05: a recycled pid is not our survivor).
    const root = runRoot();
    for (const entry of existsSync(root) ? readdirSync(root) : []) {
      if (!entry.startsWith("run-")) continue;
      for (const name of ["run.json", "minio.json"]) {
        const p = path.join(root, entry, name);
        if (!existsSync(p)) continue;
        const doc = JSON.parse(readFileSync(p, "utf8"));
        const procs = [];
        if (doc.pid) {
          procs.push(["minio", { pid: doc.pid, startTimeTicks: doc.startTimeTicks, executable: doc.executable ?? doc.binary }, doc.port]);
        }
        const al = doc.components?.alchemy;
        if (al?.pid) {
          procs.push(["alchemy", { pid: al.pid, startTimeTicks: al.startTimeTicks, executable: al.executable }, undefined]);
        }
        for (const [what, identity, port] of procs) {
          if (verifyRecordedProcess(identity).ok) {
            problems.push(`surviving ${what} process pid ${identity.pid} from ${entry}`);
          }
          if (port && (await portInUse(port))) problems.push(`surviving ${what} port ${port} from ${entry}`);
        }
      }
    }
  }

  const report = {
    runDir,
    stoppedAt: new Date().toISOString(),
    verifyClean,
    problems,
  };
  writeFileAtomic(path.join(runDir, "down.json"), `${JSON.stringify(report, null, 2)}\n`);
  if (problems.length > 0) {
    console.error("stack down: NOT CLEAN");
    for (const p of problems) console.error(`  - ${p}`);
    process.exit(1);
  }
  console.log("stack down: clean (processes gone, ports released)");
}

// ---------------------------------------------------------------------------
// graph / check-wrangler
// ---------------------------------------------------------------------------

function cmdGraph(args) {
  const variant = args.find((x) => !x.startsWith("--")) ?? "local-native";
  process.stdout.write(canonicalJson(toGraph(variant)));
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
  case "dev":
    await cmdDev(rest);
    break;
  case "down":
    await cmdDown(rest);
    break;
  case "graph":
    cmdGraph(rest);
    break;
  case "check-wrangler":
    cmdCheckWrangler();
    break;
  default:
    console.error(
      "usage: cli.mjs dev [--mode native] [--allow-degraded (diagnostic: exit 2, never success)] | down [--verify-clean] [runDir] | graph [variant] | check-wrangler",
    );
    process.exit(2);
}
