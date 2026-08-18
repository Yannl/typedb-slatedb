// No-cloud guard tests + executed mutant (a): inject Alchemy.remote() into
// a copy of the graph → the guard must refuse.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  assertDevIdentities,
  assertNoCloudCredentials,
  sanitizedEnv,
  staticScan,
  staticScanSource,
} from "../no-cloud-guard.mjs";
import { STACK_DIR } from "../graph.data.mjs";

const GRAPH_FILE = path.join(STACK_DIR, "alchemy.run.ts");
const tmp = () => mkdtempSync(path.join(os.tmpdir(), "guard-test-"));

test("the real alchemy.run.ts passes the static no-cloud scan", () => {
  assert.deepEqual(staticScan(GRAPH_FILE), []);
});

test("MUTANT a: remote() injected into a graph copy is refused", () => {
  const src = readFileSync(GRAPH_FILE, "utf8");
  const mutated = src.replace(
    "export const Payloads = Cloudflare.R2.Bucket(",
    'import { remote } from "alchemy";\nexport const Payloads = remote(() => Cloudflare.R2.Bucket(',
  );
  assert.notEqual(mutated, src, "mutation must apply");
  const file = path.join(tmp(), "alchemy.run.ts");
  writeFileSync(file, mutated);
  const violations = staticScan(file);
  assert.ok(violations.length > 0, "guard must refuse the mutant");
  assert.ok(
    violations.some((v) => v.includes("remote")),
    `a violation must name remote(): ${violations.join("; ")}`,
  );
});

test("Alchemy.remote spelled through the namespace is refused", () => {
  const violations = staticScanSource(
    'import * as Alchemy from "alchemy";\nAlchemy.ProviderMode.remote();\n',
  );
  assert.ok(violations.some((v) => v.includes("remote")));
});

test("resource kinds without a local provider are refused", () => {
  const violations = staticScanSource(
    'import * as Cloudflare from "alchemy/Cloudflare";\n' +
      'const z = Cloudflare.DNS.Record("z", {});\n',
  );
  assert.ok(
    violations.some((v) => v.includes("Cloudflare.DNS.Record") && v.includes("allowlist")),
    violations.join("; "),
  );
});

test("live/bridge imports are refused", () => {
  for (const spec of ["alchemy/Cloudflare/Live", "alchemy/Cloudflare/Bridge"]) {
    const violations = staticScanSource(`import * as X from "${spec}";\n`);
    assert.ok(violations.length > 0, `${spec} must be refused`);
  }
});

test("credential guard refuses CLOUDFLARE_API_TOKEN / ACCOUNT_ID", () => {
  assert.throws(
    () => assertNoCloudCredentials({ CLOUDFLARE_API_TOKEN: "tok" }),
    /CLOUDFLARE_API_TOKEN/,
  );
  assert.throws(
    () => assertNoCloudCredentials({ CLOUDFLARE_ACCOUNT_ID: "acct" }),
    /CLOUDFLARE_ACCOUNT_ID/,
  );
  assert.doesNotThrow(() => assertNoCloudCredentials({ PATH: "/bin" }));
});

test("sanitizedEnv strips every cloud credential for child spawns", () => {
  const env = sanitizedEnv({
    PATH: "/bin",
    CLOUDFLARE_API_TOKEN: "tok",
    CLOUDFLARE_ACCOUNT_ID: "acct",
    CF_API_TOKEN: "tok2",
  });
  assert.equal(env.PATH, "/bin");
  assert.equal(env.CLOUDFLARE_API_TOKEN, undefined);
  assert.equal(env.CLOUDFLARE_ACCOUNT_ID, undefined);
  assert.equal(env.CF_API_TOKEN, undefined);
});

test("dev: identity assertion — local state passes, live markers fail", () => {
  const dir = tmp();
  writeFileSync(
    path.join(dir, "worker.json"),
    JSON.stringify({ providerMode: "local", attributes: { bucketName: "dev:payloads" } }),
  );
  assert.deepEqual(assertDevIdentities(dir), []);

  const dir2 = tmp();
  writeFileSync(
    path.join(dir2, "worker.json"),
    JSON.stringify({ providerMode: "live", attributes: { bucketName: "typedb-payloads" } }),
  );
  const violations = assertDevIdentities(dir2);
  assert.ok(violations.some((v) => v.includes('providerMode = "live"')));
  assert.ok(violations.some((v) => v.includes("dev:")));
});

test("dev: identity assertion — missing/empty state cannot fake a pass", () => {
  assert.ok(assertDevIdentities(path.join(tmp(), "nope")).length > 0);
  assert.ok(assertDevIdentities(tmp()).length > 0); // empty dir
  assert.deepEqual(assertDevIdentities(path.join(tmp(), "nope"), { allowMissing: true }), []);
});
