#!/usr/bin/env node
// One-command supervised local stack (audit PR2/PR3, local half).
//
//   node cli.mjs dev [--mode native] [--allow-degraded]
//       zero-cloud-risk local bring-up: no-cloud guard → wrangler
//       consistency → pinned MinIO (S3 half) → `alchemy dev` (Worker/DO/
//       local-R2 half) → dev: identity assertion → run-identity manifest.
//   node cli.mjs down [--verify-clean] [runDir]
//       teardown: kill recorded process groups, verify ports released and
//       no surviving processes/state collisions; nonzero if any remain.
//   node cli.mjs graph [variant]
//       emit the normalized desired graph as canonical JSON.
//   node cli.mjs check-wrangler
//       verify control-plane/wrangler.toml against the canonical graph.
//
// Modes: `native` is the only mode implemented here (Alchemy workerd local
// providers + native MinIO). `container` (ContainerDO via Docker) and
// `cloudflare-real` are later PRs; naming them is an error, not a silent
// fallback.

import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  createWriteStream,
  readFileSync,
  readdirSync,
  writeFileSync,
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
  sanitizedEnv,
  staticScan,
} from "./no-cloud-guard.mjs";
import { checkWrangler, WRANGLER_TOML } from "./wrangler-check.mjs";
import { minioLockNode, portInUse, processAlive, runRoot, startMinio, stopMinio } from "./minio.mjs";

const GRAPH_FILE = path.join(STACK_DIR, "alchemy.run.ts");
// resource state rows only (.alchemy also holds logs/local blob data)
const STATE_DIR = path.join(STACK_DIR, ".alchemy", "state");
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
  // 1. credentials must be absent — a local run may never be able to reach
  //    a real Cloudflare account, so a set credential is a refusal
  assertNoCloudCredentials(process.env);

  // 2. static no-cloud scan of the canonical graph file
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
// dev
// ---------------------------------------------------------------------------

async function cmdDev(args) {
  const mode = argValue(args, "--mode") ?? "native";
  if (mode !== "native") {
    fail(`mode ${JSON.stringify(mode)} is not implemented in this PR (only "native"); refusing rather than silently substituting another mode`);
  }
  const allowDegraded = args.includes("--allow-degraded");

  runGuards();

  const runDir = path.join(
    runRoot(),
    `run-${new Date().toISOString().replace(/[:.]/g, "-")}-${randomBytes(3).toString("hex")}`,
  );
  mkdirSync(runDir, { recursive: true });

  const graph = toGraph("local-native");
  const minioNode = minioLockNode();
  const manifest = {
    schema: "typedb-r2-stack/run@1",
    mode,
    startedAt: new Date().toISOString(),
    runDir,
    repoRoot: REPO_ROOT,
    // run identity: digests of every config the run depends on
    identity: {
      graphDigest: graphDigest(graph),
      graphFileSha256: fileDigest(GRAPH_FILE),
      graphDataSha256: fileDigest(path.join(STACK_DIR, "graph.data.mjs")),
      wranglerTomlSha256: fileDigest(WRANGLER_TOML),
      packageLockSha256: fileDigest(path.join(STACK_DIR, "package-lock.json")),
      minioBinarySha256: minioNode.sha256,
      minioVersion: minioNode.version,
    },
    components: {},
  };
  writeFileSync(path.join(runDir, "graph.json"), canonicalJson(graph));

  // ---- S3 half: pinned native MinIO -------------------------------------
  console.log("stack: starting source-locked MinIO (S3 half)...");
  const { manifest: minio } = await startMinio({ runDir });
  manifest.components.minio = { ...minio, credentials: "see minio.json (per-run random)" };
  console.log(`stack: MinIO ready on ${minio.endpoint} (pid ${minio.pid})`);

  // ---- Cloudflare-facing half: alchemy dev ------------------------------
  console.log("stack: starting alchemy dev (Worker/DO/local-R2 half)...");
  const alchemy = await startAlchemyDev(runDir);
  manifest.components.alchemy = alchemy;
  if (alchemy.status !== "running") {
    if (!allowDegraded) {
      // fail closed: tear the S3 half back down before exiting
      await stopMinio(minio).catch(() => {});
      fail(
        `alchemy dev did not reach ready (${alchemy.status}: ${alchemy.reason}); ` +
          `rerun with --allow-degraded to keep the MinIO half up and record the degradation honestly`,
      );
    }
    console.error(`stack: DEGRADED — alchemy half not running: ${alchemy.reason}`);
  } else {
    // every emulated resource id must be dev: — no state at all is also a
    // failure once alchemy claimed to be running
    const idViolations = assertDevIdentities(STATE_DIR, { allowMissing: false });
    if (idViolations.length > 0) {
      await stopStack(manifest).catch(() => {});
      fail(`dev: identity assertion failed:\n  - ${idViolations.join("\n  - ")}`);
    }
    manifest.components.alchemy.devIdentityCheck = "pass";
  }

  manifest.readyAt = new Date().toISOString();
  writeFileSync(path.join(runDir, "run.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(CURRENT_RUN_POINTER(), `${runDir}\n`);
  console.log(`stack: up. run manifest: ${path.join(runDir, "run.json")}`);
  console.log(`stack: tear down with: node cli.mjs down --verify-clean`);
}

async function startAlchemyDev(runDir) {
  const logPath = path.join(runDir, "alchemy.log");
  const log = createWriteStream(logPath, { flags: "a" });
  const env = {
    ...sanitizedEnv(process.env),
    CI: "1", // suppress interactive ink UI where supported
    ALCHEMY_STAGE: "dev",
    // SYNTHETIC NON-CREDENTIALS. alchemy 2.0.0-beta.72 resolves the full
    // Cloudflare credential chain even for purely-LOCAL providers (the
    // local R2/Worker providers stamp an accountId into state:
    // Cloudflare/R2/Bucket.ts ProviderLocal -> CloudflareEnvironment), so
    // `alchemy dev` refuses to start with nothing set. Real credentials
    // were already refused by assertNoCloudCredentials() and stripped by
    // sanitizedEnv() above; these constants are self-evidently fake, can
    // never authenticate, and make any accidental live API call fail
    // closed with an auth error instead of touching an account.
    CLOUDFLARE_ACCOUNT_ID: "00000000000000000000000000000000",
    CLOUDFLARE_API_TOKEN: "alchemy-local-placeholder-never-a-real-token",
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

  let exited = null;
  child.on("exit", (code, signal) => {
    exited = { code, signal };
  });

  const timeoutMs = Number(process.env.STACK_ALCHEMY_READY_TIMEOUT_MS ?? 180_000);
  const deadline = Date.now() + timeoutMs;
  const urlRe = /https?:\/\/(?:localhost|127\.0\.0\.1):\d+/;
  for (;;) {
    const m = logText.match(urlRe);
    if (m) {
      return {
        status: "running",
        pid: child.pid,
        pgid: child.pid,
        url: m[0],
        logPath,
        credentials:
          "synthetic placeholders only (real Cloudflare credentials are refused and stripped; see no-cloud guard)",
      };
    }
    if (exited) {
      return {
        status: "failed",
        reason: `alchemy dev exited (code=${exited.code} signal=${exited.signal}); log tail: ${logText.slice(-2000)}`,
        logPath,
      };
    }
    if (Date.now() > deadline) {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {}
      return {
        status: "timeout",
        reason: `no local URL within ${timeoutMs}ms; log tail: ${logText.slice(-2000)}`,
        logPath,
      };
    }
    await new Promise((r) => setTimeout(r, 250));
  }
}

// ---------------------------------------------------------------------------
// down
// ---------------------------------------------------------------------------

async function stopStack(manifest) {
  const problems = [];
  const a = manifest.components?.alchemy;
  if (a?.pid) {
    try {
      process.kill(-a.pgid, "SIGTERM");
    } catch {}
    const deadline = Date.now() + 10_000;
    while (processAlive(a.pid) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 100));
    if (processAlive(a.pid)) {
      try {
        process.kill(-a.pgid, "SIGKILL");
      } catch {}
      await new Promise((r) => setTimeout(r, 500));
    }
    if (processAlive(a.pid)) problems.push(`alchemy pid ${a.pid} survived SIGTERM+SIGKILL`);
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
      await stopMinio(minio);
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
    // scan every run manifest under the run root for live pids/ports
    const root = runRoot();
    for (const entry of existsSync(root) ? readdirSync(root) : []) {
      if (!entry.startsWith("run-")) continue;
      for (const name of ["run.json", "minio.json"]) {
        const p = path.join(root, entry, name);
        if (!existsSync(p)) continue;
        const doc = JSON.parse(readFileSync(p, "utf8"));
        const pids = [];
        if (doc.pid) pids.push(["minio", doc.pid, doc.port]);
        if (doc.components?.alchemy?.pid) pids.push(["alchemy", doc.components.alchemy.pid, undefined]);
        for (const [what, pid, port] of pids) {
          if (processAlive(pid)) problems.push(`surviving ${what} process pid ${pid} from ${entry}`);
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
  writeFileSync(path.join(runDir, "down.json"), `${JSON.stringify(report, null, 2)}\n`);
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
    console.error("usage: cli.mjs dev [--mode native] [--allow-degraded] | down [--verify-clean] [runDir] | graph [variant] | check-wrangler");
    process.exit(2);
}
