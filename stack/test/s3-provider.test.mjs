// Provider-neutral S3 backends (round-6 R6-LOCAL-01).
//
// The claim under test is NOT "RustFS works". It is that ONE code path
// drives every provider: the same startS3Backend()/stopS3Backend() pair,
// the same supervisor, the same readiness contract, differing only by a
// descriptor. Duplicated per-provider supervisors are exactly what the
// audit told us to stop doing, and a test that exercises only the default
// provider would not notice a regression back into that shape.
//
// MinIO is a comparator, not a requirement: on hosts where it cannot start
// (its host-address discovery hits a denied netlink operation in some agent
// sandboxes) the result is the typed COMPARATOR_UNAVAILABLE — recorded as
// data. It is never a silent skip and never a test failure.

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  LOCK_FILE,
  PROVIDERS,
  lockNode,
  prepareDataDir,
  providerDescriptor,
  providerIds,
  providerSpawnSpec,
  sha256File,
} from "../s3-provider.mjs";
import { loadS3Manifest, probeProvider, startS3Backend, stopS3Backend } from "../managed-local.mjs";
import { s3ListBuckets } from "../minio.mjs";

const tmp = (p) => mkdtempSync(path.join(os.tmpdir(), p));
function newRunDir(tag) {
  const dir = path.join(tmp(tag), "run-1");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

test("every provider descriptor answers the same six questions", () => {
  assert.deepEqual(providerIds().sort(), ["minio", "rustfs"]);
  for (const id of providerIds()) {
    const d = providerDescriptor(id);
    assert.equal(d.id, id);
    assert.ok(d.lockNodeId, `${id}: lockNodeId`);
    assert.equal(typeof d.resolveBinary, "function", `${id}: resolveBinary`);
    assert.equal(typeof d.argv, "function", `${id}: argv`);
    assert.equal(typeof d.env, "function", `${id}: env`);
    assert.equal(typeof d.readiness, "function", `${id}: readiness`);
    assert.equal(typeof d.createsOwnDataDir, "boolean", `${id}: data-dir behaviour is declared`);
    assert.ok(d.dataDirName, `${id}: dataDirName`);
    assert.ok(d.healthPath.startsWith("/"), `${id}: healthPath`);
    // the lock node the descriptor names must really exist and be pinned
    const node = lockNode(d.lockNodeId);
    assert.match(node.sha256, /^[0-9a-f]{64}$/, `${id}: locked digest`);
  }
});

test("unknown providers are a typed refusal, not a default", () => {
  assert.throws(
    () => providerDescriptor("ceph"),
    (err) => {
      assert.equal(err.code, "UNKNOWN_PROVIDER");
      assert.match(err.message, /known providers: /);
      return true;
    },
  );
});

test("the descriptor owns data-dir creation because providers differ (RustFS refuses a missing volume)", () => {
  // This is the concrete behavioural difference R6-LOCAL-01 calls out.
  assert.equal(PROVIDERS.rustfs.createsOwnDataDir, false, "RustFS needs its volume to exist");
  assert.equal(PROVIDERS.minio.createsOwnDataDir, true, "MinIO creates its own");
  for (const id of providerIds()) {
    const runDir = newRunDir(`dd-${id}-`);
    const { dataDir } = prepareDataDir(providerDescriptor(id), runDir);
    assert.equal(existsSync(dataDir), true, `${id}: data dir created by the supervisor path`);
    assert.equal(statSync(dataDir).mode & 0o777, 0o700, `${id}: data dir must be 0700`);
    assert.equal(path.dirname(dataDir), runDir, `${id}: data dir is inside the run dir`);
  }
});

test("spawn specs are built from the descriptor, and name the loopback + per-run data dir", async () => {
  for (const id of providerIds()) {
    const runDir = newRunDir(`spec-${id}-`);
    const spec = await providerSpawnSpec({
      provider: id,
      runDir,
      port: 12345,
      consolePort: 12346,
      credentials: { accessKey: "ak", secretKey: "sk" },
    });
    assert.equal(spec.provider, id);
    assert.equal(spec.endpoint, "http://127.0.0.1:12345");
    assert.ok(spec.args.includes(spec.dataDir), `${id}: the data dir is on the command line`);
    assert.ok(
      spec.args.some((a) => a.includes("127.0.0.1:12345")),
      `${id}: binds loopback only`,
    );
    // per-run credentials reach the child through env, never argv (a
    // command line is world-readable on many hosts)
    const envValues = Object.values(spec.env);
    assert.ok(envValues.includes("ak") && envValues.includes("sk"), `${id}: credentials in env`);
    assert.ok(!spec.args.some((a) => a.includes("sk")), `${id}: secret must not appear in argv`);
    // the resolved binary is the exact locked artifact
    const node = lockNode(providerDescriptor(id).lockNodeId);
    assert.equal(await sha256File(spec.command), node.sha256, `${id}: locked digest`);
  }
});

test("a digest mismatch in the lock is a typed refusal (no substituted binary ever runs)", async () => {
  const lock = JSON.parse(readFileSync(LOCK_FILE, "utf8"));
  lock.nodes.find((n) => n.id === "RUSTFS").sha256 = "0".repeat(64);
  const lockFile = path.join(tmp("forged-lock-"), "source-lock.json");
  writeFileSync(lockFile, JSON.stringify(lock));
  const runDir = newRunDir("mismatch-");
  await assert.rejects(
    providerSpawnSpec({
      provider: "rustfs",
      runDir,
      port: 1,
      credentials: { accessKey: "a", secretKey: "b" },
      lockFile,
    }),
    (err) => {
      assert.equal(err.code, "PROVIDER_DIGEST_MISMATCH");
      assert.match(err.message, /refusing \(pinned-artifact rule\)/);
      return true;
    },
  );
});

test("an unmaterialized locked binary is a typed PROVIDER_BINARY_ABSENT, not a crash", async () => {
  const lock = JSON.parse(readFileSync(LOCK_FILE, "utf8"));
  lock.nodes.find((n) => n.id === "RUSTFS").cache_path = "sources/rustfs/definitely-not-here";
  const lockFile = path.join(tmp("absent-lock-"), "source-lock.json");
  writeFileSync(lockFile, JSON.stringify(lock));
  await assert.rejects(
    providerSpawnSpec({
      provider: "rustfs",
      runDir: newRunDir("absent-"),
      port: 1,
      credentials: { accessKey: "a", secretKey: "b" },
      lockFile,
    }),
    (err) => {
      assert.equal(err.code, "PROVIDER_BINARY_ABSENT");
      assert.match(err.message, /materialize it first/);
      return true;
    },
  );
});

test("RustFS starts from the source-locked binary, serves authenticated S3, and tears down cleanly", async (t) => {
  const runDir = newRunDir("rustfs-live-");
  const { manifest } = await startS3Backend({ provider: "rustfs", runDir, readyTimeoutMs: 60_000 });
  t.after(async () => {
    await stopS3Backend(manifest).catch(() => {});
  });

  const node = lockNode("RUSTFS");
  assert.equal(manifest.provider, "rustfs");
  assert.equal(manifest.binarySha256, node.sha256, "the exact locked digest ran");
  assert.equal(await sha256File(manifest.binary), node.sha256);
  assert.ok(manifest.endpoint.startsWith("http://127.0.0.1:"), "loopback only");
  assert.equal(manifest.dataDirPreCreated, true, "RustFS's volume was created for it");
  assert.equal(statSync(path.join(runDir, "s3.json")).mode & 0o777, 0o600, "credentials file is 0600");

  // readiness is a REAL authenticated S3 round trip — prove it independently
  await s3ListBuckets({
    endpoint: manifest.endpoint,
    accessKey: manifest.credentials.accessKey,
    secretKey: manifest.credentials.secretKey,
  });
  // ...and that it is a real auth surface
  await assert.rejects(
    s3ListBuckets({ endpoint: manifest.endpoint, accessKey: "nope", secretKey: "x".repeat(40) }),
    /S3 probe failed/,
  );

  // the manifest a later invocation would load is on disk and complete
  const reloaded = loadS3Manifest(runDir);
  assert.equal(reloaded.supervision.pid, manifest.supervision.pid);

  const report = await stopS3Backend(manifest);
  assert.equal(report.code, "TEARDOWN_CLEAN", JSON.stringify(report.problems));
  assert.equal(report.provider, "rustfs");
});

test("PROVIDER NEUTRALITY: the same code path drives every descriptor; an unavailable comparator is typed data", async () => {
  // Both providers go through startS3Backend/stopS3Backend. Whatever this
  // host can run must produce the SAME record shape; whatever it cannot
  // must produce a typed unavailability, never a failure and never silence.
  const results = {};
  for (const provider of providerIds()) {
    const runDir = newRunDir(`neutral-${provider}-`);
    results[provider] = await probeProvider({ provider, runDir, readyTimeoutMs: 60_000 });
  }

  const codes = new Set(Object.values(results).map((r) => r.code));
  for (const code of codes) {
    assert.ok(
      ["COMPARATOR_AVAILABLE", "COMPARATOR_UNAVAILABLE", "COMPARATOR_BINARY_ABSENT"].includes(code),
      `unexpected probe code ${code}`,
    );
  }

  // the agent-local default must actually work here; a comparator need not
  assert.equal(
    results.rustfs.code,
    "COMPARATOR_AVAILABLE",
    `rustfs must run on this host: ${results.rustfs.reason ?? ""}`,
  );

  const available = Object.values(results).filter((r) => r.available);
  for (const r of available) {
    assert.equal(r.teardown.code, "TEARDOWN_CLEAN", `${r.provider}: ${JSON.stringify(r.teardown.problems)}`);
    // identical verification shape across providers = one code path
    assert.deepEqual(
      r.teardown.checks.map((c) => c.name).sort(),
      available[0].teardown.checks.map((c) => c.name).sort(),
      "every provider must be verified by the same checks",
    );
    assert.match(r.binarySha256, /^[0-9a-f]{64}$/);
  }

  if (!results.minio.available) {
    // documented, structured, and explicitly not a failure
    assert.ok(results.minio.reason.length > 0, "an unavailable comparator must say why");
    console.log(`comparator minio unavailable on this host: ${results.minio.code}: ${results.minio.reason}`);
  }
});
