// No-cloud guard tests + executed mutants: remote() injected into a copy
// of the graph, a relative-import module caught TRANSITIVELY, namespace
// aliasing, computed member access, and runtime state-schema rejection of
// live-looking resources decorated with stray "dev:" strings (R4-STACK-06).
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

test("MUTANT (transitive): Alchemy.remote in a relative-import module is caught", () => {
  const dir = tmp();
  // extensionless specifier exercises the .ts resolution path
  writeFileSync(
    path.join(dir, "root.ts"),
    'import * as Cloudflare from "alchemy/Cloudflare";\nimport { helper } from "./dep";\nexport const w = Cloudflare.Worker("w", {});\n',
  );
  writeFileSync(
    path.join(dir, "dep.ts"),
    'import * as Alchemy from "alchemy";\nexport const helper = Alchemy.remote(() => {});\n',
  );
  const violations = staticScan(path.join(dir, "root.ts"));
  assert.ok(
    violations.some((v) => v.includes("dep.ts") && v.includes("remote")),
    `the imported module's remote() must be a violation of the root: ${violations.join("; ")}`,
  );
});

test("unresolvable relative imports are refused, not skipped", () => {
  const dir = tmp();
  writeFileSync(path.join(dir, "root.ts"), 'import { x } from "./missing.mjs";\n');
  const violations = staticScan(path.join(dir, "root.ts"));
  assert.ok(
    violations.some((v) => v.includes("unresolvable relative import")),
    violations.join("; "),
  );
});

test("MUTANT (alias): const X = Alchemy; X.remote(...) is refused", () => {
  const violations = staticScanSource(
    'import * as Alchemy from "alchemy";\nconst X = Alchemy;\nX.remote(() => {});\n',
  );
  assert.ok(
    violations.some((v) => v.includes("alias") && v.includes("Alchemy")),
    `aliasing must be refused: ${violations.join("; ")}`,
  );
});

test("MUTANT (alias): const X = Cloudflare; X.DNS.Record(...) is refused", () => {
  const violations = staticScanSource(
    'import * as Cloudflare from "alchemy/Cloudflare";\nconst X = Cloudflare;\nconst z = X.DNS.Record("z", {});\n',
  );
  assert.ok(
    violations.some((v) => v.includes("alias") && v.includes("Cloudflare")),
    `namespace aliasing must be refused even without the word remote: ${violations.join("; ")}`,
  );
});

test("MUTANT (computed): Alchemy['remote'] / Cloudflare[...] access is refused", () => {
  const v1 = staticScanSource(
    'import * as Alchemy from "alchemy";\nAlchemy["remote"](() => {});\n',
  );
  assert.ok(v1.some((v) => v.includes("computed member access")), v1.join("; "));
  const v2 = staticScanSource(
    'import * as Cloudflare from "alchemy/Cloudflare";\nconst k = "DNS";\nconst z = Cloudflare[k].Record("z", {});\n',
  );
  assert.ok(v2.some((v) => v.includes("computed member access")), v2.join("; "));
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

test("dev: identity assertion — exact local schema passes, live markers fail", () => {
  const dir = tmp();
  writeFileSync(
    path.join(dir, "PAYLOADS.json"),
    JSON.stringify({
      resourceType: "Cloudflare.R2.Bucket",
      providerMode: "local",
      attr: { bucketName: "dev:9f152307-c2c6-47ce-becc-5a28e8d43b0c" },
    }),
  );
  writeFileSync(
    path.join(dir, "worker.json"),
    JSON.stringify({
      resourceType: "Cloudflare.Worker",
      providerMode: "local",
      props: { workersDev: false },
      attr: { workerId: "typedb-r2-control-plane", url: "http://localhost:1337", urls: ["http://localhost:1337"] },
    }),
  );
  assert.deepEqual(assertDevIdentities(dir), []);

  const dir2 = tmp();
  writeFileSync(
    path.join(dir2, "bucket.json"),
    JSON.stringify({
      resourceType: "Cloudflare.R2.Bucket",
      providerMode: "live",
      attr: { bucketName: "typedb-payloads" },
    }),
  );
  const violations = assertDevIdentities(dir2);
  assert.ok(violations.some((v) => v.includes('providerMode = "live"')), violations.join("; "));
  assert.ok(violations.some((v) => v.includes("bucketName")), violations.join("; "));
});

test("R4-STACK-06: a stray nested 'dev: ...' string cannot bless a live-looking resource", () => {
  const dir = tmp();
  // providerMode claims local but the KIND's identity field is a real
  // (non-dev:) bucket name; a decorative "dev: innocent text" string in
  // an unrelated field must not rescue it
  writeFileSync(
    path.join(dir, "bucket.json"),
    JSON.stringify({
      resourceType: "Cloudflare.R2.Bucket",
      providerMode: "local",
      attr: { bucketName: "typedb-payloads" },
      note: "dev: innocent text",
    }),
  );
  const violations = assertDevIdentities(dir);
  assert.ok(
    violations.some((v) => v.includes("bucketName") && v.includes('"typedb-payloads"')),
    `the exact schema must reject the unblessed identity: ${violations.join("; ")}`,
  );
});

test("dev: identity assertion — non-loopback worker URL and unknown kinds are refused", () => {
  const dir = tmp();
  writeFileSync(
    path.join(dir, "worker.json"),
    JSON.stringify({
      resourceType: "Cloudflare.Worker",
      providerMode: "local",
      attr: { workerId: "w", url: "https://w.example.workers.dev" },
    }),
  );
  const v1 = assertDevIdentities(dir);
  assert.ok(v1.some((v) => v.includes("not a loopback")), v1.join("; "));

  const dir2 = tmp();
  writeFileSync(
    path.join(dir2, "dns.json"),
    JSON.stringify({ resourceType: "Cloudflare.DNS.Record", providerMode: "local", attr: { name: "dev:x" } }),
  );
  const v2 = assertDevIdentities(dir2);
  assert.ok(v2.some((v) => v.includes("not on the local-provider allowlist")), v2.join("; "));
});

test("dev: identity assertion — missing/empty state cannot fake a pass", () => {
  assert.ok(assertDevIdentities(path.join(tmp(), "nope")).length > 0);
  assert.ok(assertDevIdentities(tmp()).length > 0); // empty dir
  assert.deepEqual(assertDevIdentities(path.join(tmp(), "nope"), { allowMissing: true }), []);
});
