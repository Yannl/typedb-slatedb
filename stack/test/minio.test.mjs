// MinIO supervision end-to-end (start → real S3 readiness → teardown →
// port released) + executed mutant (c): tampered binary hash → fetcher
// refuses. Uses the source-locked binary from the sources/minio cache
// (fetched+verified on demand; the full download happens once per machine).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import {
  fetchMinio,
  minioLockNode,
  portInUse,
  s3ListBuckets,
  sha256File,
  startMinio,
  stopMinio,
} from "../minio.mjs";

const tmp = (p) => mkdtempSync(path.join(os.tmpdir(), p));

test("lock node is well-formed and the fetcher verifies the cached binary", async () => {
  const node = minioLockNode();
  assert.match(node.sha256, /^[0-9a-f]{64}$/);
  assert.ok(node.url.startsWith("https://dl.min.io/"));
  const { binary } = await fetchMinio();
  assert.equal(sha256File(binary), node.sha256);
});

test("MUTANT c1: tampered lock hash makes the fetcher refuse the cache", async () => {
  // real binary bytes in a scratch cache, lock forged to a different hash
  const cacheDir = tmp("minio-cache-");
  const real = await fetchMinio();
  const node = minioLockNode();
  writeFileSync(path.join(cacheDir, `minio-RELEASE.${node.version}`), readFileSync(real.binary));
  const lock = JSON.parse(readFileSync(path.join(path.dirname(real.binary), "..", "..", "source-lock", "source-lock.json"), "utf8"));
  lock.nodes.find((n) => n.id === "MINIO").sha256 = "0".repeat(64);
  const lockFile = path.join(tmp("minio-lock-"), "source-lock.json");
  writeFileSync(lockFile, JSON.stringify(lock));
  await assert.rejects(
    fetchMinio({ lockFile, cacheDir }),
    /digest mismatch in cache.*refusing/s,
  );
  // the tampered-per-lock binary was quarantined, not executed
  assert.ok(existsSync(path.join(cacheDir, `minio-RELEASE.${node.version}.quarantine`)));
});

test("MUTANT c2: tampered download bytes are refused and quarantined", async () => {
  // serve wrong bytes from a loopback server at the locked hash's URL
  const server = http.createServer((req, res) => res.end("not the binary"));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  try {
    const lock = JSON.parse(
      readFileSync(new URL("../../source-lock/source-lock.json", import.meta.url), "utf8"),
    );
    lock.nodes.find((n) => n.id === "MINIO").url = `https://127.0.0.1:${port}/minio`;
    const lockFile = path.join(tmp("minio-lock2-"), "source-lock.json");
    writeFileSync(lockFile, JSON.stringify(lock));
    const cacheDir = tmp("minio-cache2-");
    // fetchImpl bridges to the loopback http server (the lock schema pins
    // https; the test impl only swaps the transport, not the verification)
    const fetchImpl = (url, opts) => fetch(url.replace("https://", "http://"), opts);
    await assert.rejects(
      fetchMinio({ lockFile, cacheDir, fetchImpl }),
      /digest mismatch on download.*refusing/s,
    );
    const node = minioLockNode(lockFile);
    assert.ok(existsSync(path.join(cacheDir, `minio-RELEASE.${node.version}.quarantine`)));
  } finally {
    server.close();
  }
});

test("supervision: start → S3-API ready → teardown → port released", async (t) => {
  const runDir = path.join(tmp("minio-run-"), "run-1");
  const { manifest } = await startMinio({ runDir, readyTimeoutMs: 60_000 });
  t.after(async () => {
    // idempotent cleanup if an assertion fails mid-flight
    try {
      await stopMinio(manifest);
    } catch {}
  });

  // manifest completeness
  for (const k of ["pid", "pgid", "port", "endpoint", "dataDir", "binarySha256", "startedAt"]) {
    assert.ok(manifest[k], `manifest.${k} recorded`);
  }
  assert.match(manifest.credentials.accessKey, /^dev-[0-9a-f]{18}$/, "random per-run access key");
  assert.equal(manifest.credentials.secretKey.length, 48, "random per-run secret");
  assert.ok(manifest.endpoint.startsWith("http://127.0.0.1:"), "loopback only");
  assert.ok(manifest.dataDir.startsWith(runDir), "per-run data dir");
  assert.ok(existsSync(path.join(runDir, "minio.json")), "manifest persisted");

  // readiness really is the S3 API (probe again, independently)
  await s3ListBuckets({
    endpoint: manifest.endpoint,
    accessKey: manifest.credentials.accessKey,
    secretKey: manifest.credentials.secretKey,
  });

  // wrong credentials must NOT pass the probe (it is a real auth surface)
  await assert.rejects(
    s3ListBuckets({ endpoint: manifest.endpoint, accessKey: "dev-x", secretKey: "y".repeat(40) }),
    /S3 probe failed/,
  );

  assert.equal(await portInUse(manifest.port), true, "port serving before teardown");
  const report = await stopMinio(manifest);
  assert.equal(report.portReleased, true);
  assert.equal(await portInUse(manifest.port), false, "port released after teardown");
  // process group is gone
  assert.throws(() => process.kill(manifest.pid, 0), "pid must be gone");
});
