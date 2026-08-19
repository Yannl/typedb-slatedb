// Wrangler consistency tests (R4-STACK-01/10 two-file posture split):
// BOTH committed configs must match the canonical graph NOW, tampered
// copies must fail, and the migration ledger is order/tag-immutable.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  checkWrangler,
  parseToml,
  WRANGLER_LOCAL_DEV_TOML,
  WRANGLER_TOML,
} from "../wrangler-check.mjs";

const managed = () => readFileSync(WRANGLER_TOML, "utf8");
const localDev = () => readFileSync(WRANGLER_LOCAL_DEV_TOML, "utf8");

test("both committed wrangler configs match the canonical graph", () => {
  assert.deepEqual(checkWrangler(), []);
});

test("parser handles the committed files' tables and arrays", () => {
  const m = parseToml(managed());
  assert.equal(m.name, "typedb-r2-control-plane");
  assert.equal(m.durable_objects.bindings[0].class_name, "DatabaseControllerDO");
  assert.deepEqual(m.migrations[0].new_sqlite_classes, ["DatabaseControllerDO"]);
  assert.equal(m.vars.CONTROLLER_KEY_PROFILE, "managed");
  assert.equal(m.workers_dev, false);
  const l = parseToml(localDev());
  assert.equal(l.vars.CONTROLLER_SURFACE, "local-dev");
});

test("R4-STACK-01: the DEFAULT config is the managed fail-closed posture", () => {
  const m = parseToml(managed());
  assert.equal(m.vars.CONTROLLER_KEY_PROFILE, "managed", "default deploy must be managed");
  assert.ok(!("CONTROLLER_SURFACE" in m.vars), "default config must not open dev routes");
  assert.equal(m.workers_dev, false, "no implicit public route");
  assert.equal(m.preview_urls, false, "no preview URLs");
  assert.equal(m.r2_buckets[0].bucket_name, "typedb-payloads");
  assert.equal(m.env, undefined, "no embedded env escape hatch");
});

test("renamed R2 binding in a managed copy fails", () => {
  const tampered = managed().replace('binding = "PAYLOADS"', 'binding = "PAYLOADZ"');
  const findings = checkWrangler({ managedText: tampered });
  assert.ok(findings.some((f) => f.includes("r2_buckets")), findings.join("; "));
});

test("changed compatibility date in a local-dev copy fails", () => {
  const tampered = localDev().replace(
    'compatibility_date = "2025-11-01"',
    'compatibility_date = "2026-02-02"',
  );
  const findings = checkWrangler({ localDevText: tampered });
  assert.ok(findings.some((f) => f.includes("compatibility_date")), findings.join("; "));
});

test("changed DO class name in a managed copy fails", () => {
  const tampered = managed().replaceAll("DatabaseControllerDO", "RenamedDO");
  const findings = checkWrangler({ managedText: tampered });
  assert.ok(findings.some((f) => f.includes("class") || f.includes("ledger")), findings.join("; "));
});

test("MUTANT R4-STACK-01: managed config gaining CONTROLLER_SURFACE fails", () => {
  const tampered = managed().replace(
    'CONTROLLER_KEY_PROFILE = "managed"',
    'CONTROLLER_KEY_PROFILE = "managed"\nCONTROLLER_SURFACE = "local-dev"',
  );
  assert.notEqual(tampered, managed(), "tamper must apply");
  const findings = checkWrangler({ managedText: tampered });
  assert.ok(findings.some((f) => f.includes("must NOT set CONTROLLER_SURFACE")), findings.join("; "));
});

test("MUTANT R4-STACK-01: managed config downgraded to local-dev keys fails", () => {
  const tampered = managed().replace(
    'CONTROLLER_KEY_PROFILE = "managed"',
    'CONTROLLER_KEY_PROFILE = "local-dev"',
  );
  const findings = checkWrangler({ managedText: tampered });
  assert.ok(findings.some((f) => f.includes("CONTROLLER_KEY_PROFILE")), findings.join("; "));
});

test("MUTANT: workers_dev exposure re-enabled fails", () => {
  const tampered = managed().replace("workers_dev = false", "workers_dev = true");
  const findings = checkWrangler({ managedText: tampered });
  assert.ok(findings.some((f) => f.includes("workers_dev")), findings.join("; "));
});

test("dropped local var fails", () => {
  const tampered = localDev().replace('CONTROLLER_SURFACE = "local-dev"\n', "");
  const findings = checkWrangler({ localDevText: tampered });
  assert.ok(findings.some((f) => f.includes("[vars]")), findings.join("; "));
});

test("extra unreviewed var fails (exact allowlist, not denylist)", () => {
  const tampered = managed().replace(
    'CONTROLLER_KEY_PROFILE = "managed"',
    'CONTROLLER_KEY_PROFILE = "managed"\nEXTRA_KNOB = "surprise"',
  );
  const findings = checkWrangler({ managedText: tampered });
  assert.ok(findings.some((f) => f.includes("unexpected EXTRA_KNOB")), findings.join("; "));
});

// --- R4-STACK-10: migration ledger immutability ---------------------------

test("MUTANT R4-STACK-10: reordered migrations fail (ledger order is history)", () => {
  const reordered = managed()
    .replace(
      /\[\[migrations\]\]\ntag = "v1"\nnew_sqlite_classes = \["DatabaseControllerDO"\]\n\n\[\[migrations\]\]\ntag = "v2"\nnew_sqlite_classes = \["DatabaseContainerDO"\]/,
      '[[migrations]]\ntag = "v2"\nnew_sqlite_classes = ["DatabaseContainerDO"]\n\n[[migrations]]\ntag = "v1"\nnew_sqlite_classes = ["DatabaseControllerDO"]',
    );
  assert.notEqual(reordered, managed(), "tamper must apply");
  const findings = checkWrangler({ managedText: reordered });
  assert.ok(findings.some((f) => f.includes("append-only") || f.includes("tag")), findings.join("; "));
});

test("MUTANT R4-STACK-10: retagged historical migration fails", () => {
  const tampered = managed().replace('tag = "v1"', 'tag = "v1-renamed"');
  const findings = checkWrangler({ managedText: tampered });
  assert.ok(findings.some((f) => f.includes("tag")), findings.join("; "));
});

test("MUTANT R4-STACK-10: removed historical migration fails", () => {
  const tampered = managed().replace(
    '[[migrations]]\ntag = "v1"\nnew_sqlite_classes = ["DatabaseControllerDO"]\n\n',
    "",
  );
  assert.notEqual(tampered, managed(), "tamper must apply");
  const findings = checkWrangler({ managedText: tampered });
  assert.ok(findings.length > 0, "removed migration must be detected");
});

test("MUTANT: embedded [env.*] section fails (postures are separate files)", () => {
  const tampered = managed() + '\n[env.sneaky]\n[env.sneaky.vars]\nCONTROLLER_SURFACE = "local-dev"\n';
  const findings = checkWrangler({ managedText: tampered });
  assert.ok(findings.some((f) => f.includes("[env.*]")), findings.join("; "));
});

test("unparseable constructs fail closed", () => {
  const findings = checkWrangler({ managedText: 'name = { weird = "inline table" }\n' });
  assert.ok(findings.some((f) => f.includes("unparseable")), findings.join("; "));
});

// --- R5-SEC-01: managed BOOTABILITY (graph declaration == runtime need) ----
// The runtime requirement list is the SHARED module
// control-plane/src/controller/core/key-requirements.mjs; the checker must
// fail BEFORE deployment whenever the graph's declared inputs skew from it.

test("R5-SEC-01: the committed graph declaration is bootable (no findings)", async () => {
  const { bootabilityFindings } = await import("../wrangler-check.mjs");
  const { toGraph, toWranglerView } = await import("../graph.data.mjs");
  const view = toWranglerView();
  const findings = bootabilityFindings({
    fixedVars: view.managed.vars,
    deploymentVars: view.managed.deployment_vars,
    secrets: toGraph("cloudflare-real").worker.secretSchema,
  });
  assert.deepEqual(findings, []);
});

test("MUTANT R5-SEC-01: dropping EACH required managed input in turn fails the graph checker", async () => {
  const { bootabilityFindings } = await import("../wrangler-check.mjs");
  const { toGraph, toWranglerView } = await import("../graph.data.mjs");
  const { MANAGED_DEPLOYMENT_VARS, MANAGED_SECRETS } =
    await import("../../control-plane/src/controller/core/key-requirements.mjs");
  const view = toWranglerView();
  const healthy = {
    fixedVars: view.managed.vars,
    deploymentVars: view.managed.deployment_vars,
    secrets: toGraph("cloudflare-real").worker.secretSchema,
  };
  for (const name of MANAGED_DEPLOYMENT_VARS) {
    const findings = bootabilityFindings({
      ...healthy, deploymentVars: healthy.deploymentVars.filter((v) => v !== name),
    });
    assert.ok(findings.some((f) => f.includes(name) && f.includes("cannot boot")),
      `dropping deployment var ${name} must fail: ${findings.join("; ")}`);
  }
  for (const name of MANAGED_SECRETS) {
    const findings = bootabilityFindings({
      ...healthy, secrets: healthy.secrets.filter((s) => s !== name),
    });
    assert.ok(findings.some((f) => f.includes(name) && f.includes("cannot boot")),
      `dropping secret ${name} must fail: ${findings.join("; ")}`);
  }
  // the fixed posture selector cannot silently change value either
  const findings = bootabilityFindings({ ...healthy, fixedVars: { CONTROLLER_KEY_PROFILE: "local-dev" } });
  assert.ok(findings.some((f) => f.includes("CONTROLLER_KEY_PROFILE")), findings.join("; "));
});

test("MUTANT R5-SEC-01: an UNDECLARED extra runtime input fails the graph checker (unreviewed input)", async () => {
  const { bootabilityFindings } = await import("../wrangler-check.mjs");
  const { toGraph, toWranglerView } = await import("../graph.data.mjs");
  const view = toWranglerView();
  const findings = bootabilityFindings({
    fixedVars: view.managed.vars,
    deploymentVars: [...view.managed.deployment_vars, "CONTROLLER_EXTRA_BACKDOOR"],
    secrets: toGraph("cloudflare-real").worker.secretSchema,
  });
  assert.ok(findings.some((f) => f.includes("CONTROLLER_EXTRA_BACKDOOR") && f.includes("unreviewed")),
    findings.join("; "));
});

test("R5-SEC-01: a managed graph missing a deployment var fails its posture invariant", async () => {
  const { toGraph } = await import("../graph.data.mjs");
  const { assertPostureInvariants } = await import("../graph-diff.mjs");
  const mutant = JSON.parse(JSON.stringify(toGraph("cloudflare-real")));
  mutant.worker.deploymentVars = mutant.worker.deploymentVars.filter(
    (v) => v !== "CONTROLLER_PROVISION_PUBLIC_KEYS");
  const violations = assertPostureInvariants(mutant);
  assert.ok(violations.some((v) => v.path === "worker.deploymentVars"), JSON.stringify(violations));
});
