// MinIO supervision end-to-end (start → real S3 readiness → teardown →
// port released) + executed mutant (c): tampered binary hash → fetcher
// refuses. Uses the source-locked binary from the sources/minio cache
// (fetched+verified on demand; the full download happens once per machine).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync, existsSync } from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import {
  assertSupportedPlatform,
  ensureRunRoot,
  fetchMinio,
  minioLockNode,
  portInUse,
  procStartTimeTicks,
  s3ListBuckets,
  sha256File,
  startMinio,
  stopMinio,
  verifyRecordedProcess,
} from "../minio.mjs";

const tmp = (p) => mkdtempSync(path.join(os.tmpdir(), p));

/** Forge a lock copy whose MINIO node points at a test URL/digest. */
function forgeLock({ url, sha256 }) {
  const lock = JSON.parse(
    readFileSync(new URL("../../source-lock/source-lock.json", import.meta.url), "utf8"),
  );
  const node = lock.nodes.find((n) => n.id === "MINIO");
  if (url) node.url = url;
  if (sha256) node.sha256 = sha256;
  const lockFile = path.join(tmp("minio-forged-lock-"), "source-lock.json");
  writeFileSync(lockFile, JSON.stringify(lock));
  return { lockFile, node };
}

const strayDownloadArtifacts = (cacheDir) =>
  readdirSync(cacheDir).filter((n) => n.includes(".download.") || n.endsWith(".lock"));

test("lock node is well-formed and the fetcher verifies the cached binary", async () => {
  const node = minioLockNode();
  assert.match(node.sha256, /^[0-9a-f]{64}$/);
  assert.ok(node.url.startsWith("https://dl.min.io/"));
  const { binary } = await fetchMinio();
  assert.equal(await sha256File(binary), node.sha256);
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

test("R4-LOCAL-05: concurrent fetches singleflight into ONE download, no stray temps", async () => {
  const cacheDir = tmp("minio-sf-");
  const payload = Buffer.from("fake-minio-binary-for-singleflight");
  const digest = createHash("sha256").update(payload).digest("hex");
  const { lockFile } = forgeLock({ url: "https://dl.min.io/fake/minio", sha256: digest });
  let fetches = 0;
  const fetchImpl = async () => {
    fetches += 1;
    await new Promise((r) => setTimeout(r, 100)); // hold the flight open
    return new Response(payload, { status: 200 });
  };
  const [a, b] = await Promise.all([
    fetchMinio({ lockFile, cacheDir, fetchImpl }),
    fetchMinio({ lockFile, cacheDir, fetchImpl }),
  ]);
  assert.equal(fetches, 1, "two parallel ensure calls must share one download");
  assert.equal(a.binary, b.binary);
  assert.equal(await sha256File(a.binary), digest);
  assert.deepEqual(strayDownloadArtifacts(cacheDir), [], "no temp/lock files may survive");
});

test("R4-LOCAL-05: byte ceiling aborts a runaway download with a typed error and cleans temps", async () => {
  const cacheDir = tmp("minio-ceiling-");
  const { lockFile } = forgeLock({ url: "https://dl.min.io/fake/minio", sha256: "0".repeat(64) });
  const chunk = new Uint8Array(8 * 1024 * 1024);
  const fetchImpl = async () =>
    new Response(
      new ReadableStream({
        pull(c) {
          c.enqueue(chunk); // endless: only the ceiling can stop this
        },
      }),
      { status: 200 },
    );
  await assert.rejects(
    fetchMinio({ lockFile, cacheDir, fetchImpl }),
    (err) => err.code === "DOWNLOAD_BYTE_CEILING_EXCEEDED" && /ceiling/.test(err.message),
  );
  assert.deepEqual(strayDownloadArtifacts(cacheDir), [], "aborted temp and lock must be removed");
});

test("R4-LOCAL-05: digest mismatch via injected fetch quarantines, leaves no temp/lock", async () => {
  const cacheDir = tmp("minio-mismatch-");
  const { lockFile, node } = forgeLock({ url: "https://dl.min.io/fake/minio", sha256: "1".repeat(64) });
  const fetchImpl = async () => new Response(Buffer.from("wrong bytes"), { status: 200 });
  await assert.rejects(
    fetchMinio({ lockFile, cacheDir, fetchImpl }),
    /digest mismatch on download.*refusing/s,
  );
  assert.ok(existsSync(path.join(cacheDir, `minio-RELEASE.${node.version}.quarantine`)));
  assert.deepEqual(strayDownloadArtifacts(cacheDir), [], "temp renamed to quarantine, lock removed");
});

test("R4-LOCAL-05: redirects to non-https or unpinned hosts are refused", async () => {
  const cacheDir = tmp("minio-redirect-");
  const { lockFile } = forgeLock({ url: "https://dl.min.io/fake/minio", sha256: "2".repeat(64) });
  const redirectTo = (location) => async () =>
    new Response(null, { status: 302, headers: { location } });
  await assert.rejects(
    fetchMinio({ lockFile, cacheDir, fetchImpl: redirectTo("http://dl.min.io/downgraded") }),
    /non-https/,
  );
  await assert.rejects(
    fetchMinio({ lockFile, cacheDir, fetchImpl: redirectTo("https://attacker.example/minio") }),
    /unpinned host/,
  );
  assert.deepEqual(strayDownloadArtifacts(cacheDir), []);
});

test("R4-LOCAL-06: run root is 0700 and a wider pre-existing mode is tightened", () => {
  const parent = tmp("minio-root-");
  const fresh = path.join(parent, "root-a");
  ensureRunRoot(fresh);
  assert.equal(statSync(fresh).mode & 0o777, 0o700, "fresh run root must be 0700");
  const wide = path.join(parent, "root-b");
  mkdirSync(wide, { mode: 0o755 });
  chmodSync(wide, 0o755);
  ensureRunRoot(wide);
  assert.equal(statSync(wide).mode & 0o777, 0o700, "pre-existing wide root must be tightened");
});

test("R4-LOCAL-07: unsupported platform is a typed early refusal naming the locked artifact", () => {
  for (const [prop, value] of [
    ["platform", "darwin"],
    ["arch", "arm64"],
  ]) {
    const orig = Object.getOwnPropertyDescriptor(process, prop);
    Object.defineProperty(process, prop, { value, configurable: true });
    try {
      assert.throws(
        () => assertSupportedPlatform(),
        (err) =>
          err.code === "UNSUPPORTED_PLATFORM" &&
          err.message.includes(value) &&
          err.message.includes("minio-linux-amd64"),
        `${prop}=${value} must be refused with the typed error`,
      );
    } finally {
      Object.defineProperty(process, prop, orig);
    }
  }
  assert.doesNotThrow(() => assertSupportedPlatform(), "linux/x64 must pass");
});

test("R4-STACK-05: verifyRecordedProcess refuses recycled/mismatched pids", () => {
  // our own process with its REAL identity → ok
  const honest = verifyRecordedProcess({
    pid: process.pid,
    startTimeTicks: procStartTimeTicks(process.pid),
    executable: process.execPath,
  });
  assert.equal(honest.ok, true, honest.reason);
  if (process.platform === "linux") {
    // recorded start time missing or different → recycled-pid suspicion → refuse
    const noTicks = verifyRecordedProcess({ pid: process.pid, executable: process.execPath });
    assert.equal(noTicks.ok, false, "missing recorded start time must refuse");
    const wrongTicks = verifyRecordedProcess({
      pid: process.pid,
      startTimeTicks: (procStartTimeTicks(process.pid) ?? 0) + 12345,
      executable: process.execPath,
    });
    assert.equal(wrongTicks.ok, false, "mismatched start time must refuse");
  }
  // wrong executable → refuse even though the pid is alive
  const wrongExe = verifyRecordedProcess({
    pid: process.pid,
    startTimeTicks: 1,
    executable: "/definitely/not/this/binary",
  });
  assert.equal(wrongExe.ok, false);
  assert.match(wrongExe.reason, /does not name recorded executable|cannot read/);
  // dead pid → not alive, refuse
  const dead = verifyRecordedProcess({ pid: 2 ** 22 - 3, startTimeTicks: 1, executable: "x" });
  assert.equal(dead.ok, false);
  assert.equal(dead.alive, false);
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

  // manifest completeness (executable + startTimeTicks: R4-STACK-05
  // teardown identity)
  for (const k of ["pid", "pgid", "port", "endpoint", "dataDir", "binarySha256", "startedAt", "executable"]) {
    assert.ok(manifest[k], `manifest.${k} recorded`);
  }
  if (process.platform === "linux") {
    assert.ok(Number.isFinite(manifest.startTimeTicks), "process start time recorded at spawn");
  }
  assert.match(manifest.credentials.accessKey, /^dev-[0-9a-f]{18}$/, "random per-run access key");
  assert.equal(manifest.credentials.secretKey.length, 48, "random per-run secret");
  assert.ok(manifest.endpoint.startsWith("http://127.0.0.1:"), "loopback only");
  assert.ok(manifest.dataDir.startsWith(runDir), "per-run data dir");
  assert.ok(existsSync(path.join(runDir, "minio.json")), "manifest persisted");
  // R4-LOCAL-06: credentials file 0600, run dir 0700
  assert.equal(statSync(path.join(runDir, "minio.json")).mode & 0o777, 0o600, "credentials file must be 0600");
  assert.equal(statSync(runDir).mode & 0o777, 0o700, "run dir must be 0700");
  // R4-STACK-05: the recorded identity verifies against the live child
  const idCheck = verifyRecordedProcess({
    pid: manifest.pid,
    startTimeTicks: manifest.startTimeTicks,
    executable: manifest.executable,
  });
  assert.equal(idCheck.ok, true, idCheck.reason);

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
