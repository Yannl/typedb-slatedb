// Wrangler consistency tests: the committed control-plane/wrangler.toml
// must match the canonical graph NOW, and tampered copies must fail.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { checkWrangler, parseToml, WRANGLER_TOML } from "../wrangler-check.mjs";

const committed = () => readFileSync(WRANGLER_TOML, "utf8");

test("the committed wrangler.toml matches the canonical graph", () => {
  assert.deepEqual(checkWrangler(), []);
});

test("parser handles the committed file's tables and arrays", () => {
  const toml = parseToml(committed());
  assert.equal(toml.name, "typedb-r2-control-plane");
  assert.equal(toml.durable_objects.bindings[0].class_name, "DatabaseControllerDO");
  assert.deepEqual(toml.migrations[0].new_sqlite_classes, ["DatabaseControllerDO"]);
  assert.equal(toml.env.production.vars.CONTROLLER_KEY_PROFILE, "managed");
});

test("renamed R2 binding in a toml copy fails", () => {
  const tampered = committed().replace('binding = "PAYLOADS"', 'binding = "PAYLOADZ"');
  const findings = checkWrangler({ tomlText: tampered });
  assert.ok(findings.length > 0, "tamper must be detected");
  assert.ok(findings.some((f) => f.includes("r2_buckets")), findings.join("; "));
});

test("changed compatibility date in a toml copy fails", () => {
  const tampered = committed().replace(
    'compatibility_date = "2025-11-01"',
    'compatibility_date = "2026-02-02"',
  );
  const findings = checkWrangler({ tomlText: tampered });
  assert.ok(findings.some((f) => f.includes("compatibility_date")), findings.join("; "));
});

test("changed DO class name in a toml copy fails", () => {
  const tampered = committed().replaceAll("DatabaseControllerDO", "RenamedDO");
  const findings = checkWrangler({ tomlText: tampered });
  assert.ok(findings.some((f) => f.includes("class")), findings.join("; "));
});

test("production env gaining CONTROLLER_SURFACE fails (fail-closed posture)", () => {
  const tampered = committed().replace(
    '[env.production.vars]\nCONTROLLER_KEY_PROFILE = "managed"',
    '[env.production.vars]\nCONTROLLER_KEY_PROFILE = "managed"\nCONTROLLER_SURFACE = "local-dev"',
  );
  assert.notEqual(tampered, committed(), "tamper must apply");
  const findings = checkWrangler({ tomlText: tampered });
  assert.ok(
    findings.some((f) => f.includes("must NOT set CONTROLLER_SURFACE")),
    findings.join("; "),
  );
});

test("dropped local var fails", () => {
  const tampered = committed().replace('CONTROLLER_SURFACE = "local-dev"\n', "");
  const findings = checkWrangler({ tomlText: tampered });
  assert.ok(findings.some((f) => f.includes("[vars]")), findings.join("; "));
});

test("unparseable constructs fail closed", () => {
  const findings = checkWrangler({ tomlText: 'name = { weird = "inline table" }\n' });
  assert.ok(findings.some((f) => f.includes("unparseable")), findings.join("; "));
});
