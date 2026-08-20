/*
 * R6-CTRL-01: THE ROUTE / EFFECT MATRIX, AS A TEST.
 *
 * The round-6 audit's first control-plane finding was that three
 * authoritative effect queries (`WAL_FINALIZE_BATCH`, `CHECKPOINT_OPEN`,
 * `CHECKPOINT_ACTIVATE`) were implemented and unreachable, because the
 * routes that should have bound them relied on `withMutation`'s default
 * fifth argument and stored `{kind:"IDEMPOTENT_REEXECUTE"}` instead. Prose
 * cannot hold that closed: the defect was invisible precisely because
 * nothing had to be written down when a route was added.
 *
 * So the matrix is executable, and it is a SOURCE-LEVEL check on purpose.
 * A type-level check cannot fail for a route that passes an explicit but
 * WRONG effect, and it cannot notice a route that was never declared. This
 * suite reads `worker-entry.ts` and `procedures.ts` and requires:
 *
 *   1. every mutation route declared in MUTATION_ROUTES has exactly one
 *      `withMutation({...})` call, and every call names a declared route;
 *   2. the route -> effect binding equals the matrix declared HERE, so
 *      adding a route (or changing its ambiguity policy) fails until a
 *      human states the new policy in this file;
 *   3. every `CapabilityEffect` variant is constructed by at least one
 *      route - no variant is dead code again;
 *   4. every `ReceiptMethod` is bound by at least one route;
 *   5. no mutation API carries a DEFAULT effect (the exact defect), and no
 *      route constructs the retired generic effect;
 *   6. the effect reducer is exhaustive at compile time, so a new variant
 *      cannot be added without an authoritative query.
 *
 * Run: node --experimental-strip-types --test src/controller/core/route-effects.test.ts
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const read = (relative: string) => readFileSync(join(HERE, relative), "utf8");
const WORKER = read("../worker-entry.ts");
const CORE = read("./procedures.ts");
const DO = read("../database-controller.ts");

/**
 * THE MATRIX. Route id (MUTATION_ROUTES) -> the `CapabilityEffect` variant
 * that decides what a lost response to it meant. `effectTest` names the
 * suite that drives the four ambiguity cuts for that route, so the matrix
 * also records where the evidence lives.
 */
const MATRIX: Record<string, { effect: string; effectTest: string }> = {
  INCARNATION_BUMP: { effect: "INCARNATION_BUMP", effectTest: "ambiguity-cuts: INCARNATION_BUMP" },
  PAYLOAD_PUT: { effect: "OPERATION_RECEIPT", effectTest: "mutation-cuts.workerd: PUT_PAYLOAD cuts (a)/(b)/(b')/(c)/(d)" },
  SESSION_REGISTER: { effect: "OPERATION_RECEIPT", effectTest: "ambiguity-cuts: SESSION_REGISTER" },
  SESSION_RESERVE: { effect: "OPERATION_RECEIPT", effectTest: "ambiguity-cuts: SESSION_RESERVE" },
  SESSION_ATTEST: { effect: "OPERATION_RECEIPT", effectTest: "ambiguity-cuts: SESSION_ATTEST" },
  SESSION_ACTIVATE: { effect: "OPERATION_RECEIPT", effectTest: "ambiguity-cuts: SESSION_ACTIVATE" },
  SESSION_RENEW: { effect: "OPERATION_RECEIPT", effectTest: "ambiguity-cuts: SESSION_RENEW" },
  SESSION_DRAIN: { effect: "OPERATION_RECEIPT", effectTest: "ambiguity-cuts: SESSION_DRAIN" },
  SESSION_REVOKE: { effect: "OPERATION_RECEIPT", effectTest: "ambiguity-cuts: SESSION_REVOKE" },
  SESSION_FENCE: { effect: "OPERATION_RECEIPT", effectTest: "ambiguity-cuts: SESSION_FENCE" },
  BUDGETS_SET: { effect: "BUDGETS_SET", effectTest: "ambiguity-cuts: BUDGETS_SET" },
  WAL_FINALIZE: { effect: "WAL_FINALIZE", effectTest: "ambiguity-cuts: WAL_FINALIZE" },
  WAL_FINALIZE_BATCH: { effect: "WAL_FINALIZE_BATCH", effectTest: "ambiguity-cuts: WAL_FINALIZE_BATCH" },
  OUTBOX_ACK: { effect: "OPERATION_RECEIPT", effectTest: "ambiguity-cuts: OUTBOX_ACK" },
  CHECKPOINT_OPEN: { effect: "CHECKPOINT_OPEN", effectTest: "ambiguity-cuts: CHECKPOINT_OPEN" },
  CHECKPOINT_ACTIVATE: { effect: "CHECKPOINT_ACTIVATE", effectTest: "ambiguity-cuts: CHECKPOINT_ACTIVATE" },
};

/** The `{ ... }` starting at `open`, by brace balance, ignoring braces
 *  inside string literals, template literals and line comments. */
function balancedBlock(source: string, open: number): string {
  let depth = 0;
  let index = open;
  while (index < source.length) {
    const char = source[index];
    if (char === "/" && source[index + 1] === "/") {
      index = source.indexOf("\n", index);
      if (index === -1) break;
      continue;
    }
    if (char === '"' || char === "'" || char === "`") {
      const quote = char;
      index += 1;
      while (index < source.length && source[index] !== quote) {
        index += source[index] === "\\" ? 2 : 1;
      }
    } else if (char === "{") {
      depth += 1;
    } else if (char === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(open, index + 1);
    }
    index += 1;
  }
  throw new Error(`unbalanced block at offset ${open}`);
}

/** Every `withMutation({ ... })` call in the worker, as (route, effect kind,
 *  receipt method) triples read from the source itself. */
function parseMutationCalls(): { route: string; effect: string; receiptMethod: string | null }[] {
  const calls: { route: string; effect: string; receiptMethod: string | null }[] = [];
  const marker = "withMutation({";
  for (let at = WORKER.indexOf(marker); at !== -1; at = WORKER.indexOf(marker, at + 1)) {
    const block = balancedBlock(WORKER, at + marker.length - 1);
    const route = /\n\s*route:\s*"([A-Z_]+)"/.exec(block);
    assert.ok(route, `a withMutation call carries no route id:\n${block.slice(0, 200)}`);
    const effectAt = block.indexOf("effect:");
    assert.notEqual(effectAt, -1, `route ${route[1]} passes no effect`);
    const effectBlock = balancedBlock(block, block.indexOf("{", effectAt));
    const kind = /kind:\s*"([A-Z_]+)"/.exec(effectBlock);
    assert.ok(kind, `route ${route[1]} passes an effect with no kind`);
    const method = /method:\s*"([A-Z_]+)"/.exec(effectBlock);
    calls.push({ route: route[1], effect: kind[1], receiptMethod: method ? method[1] : null });
  }
  return calls;
}

/** The route ids the worker declares. */
function declaredRoutes(): string[] {
  const at = WORKER.indexOf("export const MUTATION_ROUTES = {");
  assert.notEqual(at, -1, "MUTATION_ROUTES is gone: the route table is the matrix's anchor");
  const block = balancedBlock(WORKER, WORKER.indexOf("{", at));
  return [...block.matchAll(/\n\s*([A-Z_]+):\s*"/g)].map((m) => m[1]);
}

/** The variants of the `CapabilityEffect` union, from its declaration. */
function unionVariants(): string[] {
  const at = CORE.indexOf("export type CapabilityEffect =");
  assert.notEqual(at, -1, "CapabilityEffect is gone");
  const end = CORE.indexOf(";", CORE.indexOf("OPERATION_RECEIPT", at));
  return [...CORE.slice(at, end).matchAll(/\{ kind: "([A-Z_]+)"/g)].map((m) => m[1]);
}

/** The receipt methods the core declares. */
function receiptMethods(): string[] {
  const at = CORE.indexOf("export const RECEIPT_METHODS = [");
  assert.notEqual(at, -1, "RECEIPT_METHODS is gone");
  const end = CORE.indexOf("] as const;", at);
  return [...CORE.slice(at, end).matchAll(/"([A-Z_]+)"/g)].map((m) => m[1]);
}

test("every declared mutation route has exactly one withMutation call, and vice versa", () => {
  const calls = parseMutationCalls();
  const called = calls.map((c) => c.route).sort();
  const declared = declaredRoutes().sort();
  assert.deepEqual(called, declared,
    "MUTATION_ROUTES and the withMutation call sites disagree: a mutation route "
    + "must be declared once and bound once");
  assert.equal(new Set(called).size, called.length, "a route id is used by two withMutation calls");
});

test("MUTANT: the route -> effect matrix in the source equals the matrix declared here", () => {
  const calls = parseMutationCalls();
  const fromSource = Object.fromEntries(calls.map((c) => [c.route, c.effect]));
  const fromMatrix = Object.fromEntries(Object.entries(MATRIX).map(([k, v]) => [k, v.effect]));
  assert.deepEqual(fromSource, fromMatrix,
    "a mutation route's ambiguity policy changed (or a route was added) without updating "
    + "the matrix. State what a lost response to it means, then update MATRIX.");
  // and the matrix records where the four ambiguity cuts are proven
  for (const [route, entry] of Object.entries(MATRIX)) {
    assert.ok(entry.effectTest.length > 0, `route ${route} names no cut suite`);
  }
});

test("MUTANT: every CapabilityEffect variant is constructed by at least one route", () => {
  const constructed = new Set(parseMutationCalls().map((c) => c.effect));
  const unused = unionVariants().filter((variant) => !constructed.has(variant));
  assert.deepEqual(unused, [],
    "a CapabilityEffect variant is implemented but no route binds it - exactly the "
    + "R6-CTRL-01 defect (WAL_FINALIZE_BATCH / CHECKPOINT_OPEN / CHECKPOINT_ACTIVATE "
    + "were dead reducer branches for a whole release).");
});

test("MUTANT: every receipt method is bound by at least one route", () => {
  const bound = new Set(parseMutationCalls().map((c) => c.receiptMethod).filter((m) => m !== null));
  const unused = receiptMethods().filter((method) => !bound.has(method));
  assert.deepEqual(unused, [], "a ReceiptMethod exists that no route records receipts under");
});

test("MUTANT: no mutation API carries a DEFAULT effect", () => {
  // the exact round-5 defect: `effect: CapabilityEffect = { kind: ... }`
  for (const [name, source] of [["worker-entry.ts", WORKER], ["database-controller.ts", DO]] as const) {
    assert.equal(/effect:\s*CapabilityEffect\s*=/.test(source), false,
      `${name} gives \`effect\` a default; a mutation must not be able to inherit an `
      + "ambiguity policy it never stated");
    assert.ok(/effect:\s*CapabilityEffect[,;)\n]/.test(source),
      `${name} no longer takes an effect at all`);
  }
});

test("MUTANT: no route can construct the retired generic effect", () => {
  // the string still appears in the comment that records WHY the default
  // was removed; what must never reappear is a route CONSTRUCTING it
  const generic = parseMutationCalls().filter((c) => c.effect === "IDEMPOTENT_REEXECUTE");
  assert.deepEqual(generic, [],
    "a route constructs the retired generic effect; convergence-by-identity is no "
    + "longer something a route may claim without an authoritative query");
  assert.equal(unionVariants().includes("IDEMPOTENT_REEXECUTE"), false,
    "IDEMPOTENT_REEXECUTE is back in CapabilityEffect: it is a legacy ROW value only");
  // ...and the legacy value is still understood, so pre-R6 rows resolve
  assert.ok(CORE.includes('export const LEGACY_REEXECUTE_EFFECT = "IDEMPOTENT_REEXECUTE"'),
    "rows written by a pre-R6 build must still be interpretable");
});

test("MUTANT: the effect reducer is exhaustive at compile time", () => {
  const at = CORE.indexOf("private deriveEffectOutcome(");
  assert.notEqual(at, -1, "deriveEffectOutcome is gone");
  const end = CORE.indexOf("\n  private quarantineNow(", at);
  assert.notEqual(end, -1, "deriveEffectOutcome's end marker moved");
  const body = CORE.slice(at, end);
  assert.ok(/const unhandled:\s*never\s*=\s*effect;/.test(body),
    "deriveEffectOutcome lost its `never` exhaustiveness guard: a new CapabilityEffect "
    + "variant could be added with no authoritative query and still compile");
  // every variant has a case arm
  for (const variant of unionVariants()) {
    assert.ok(body.includes(`case "${variant}"`), `deriveEffectOutcome has no arm for ${variant}`);
  }
});

test("the mutation wrapper claims the effect BEFORE it executes anything", () => {
  const at = WORKER.indexOf("const withMutation = async (spec: {");
  assert.notEqual(at, -1, "withMutation is no longer the single mutation wrapper");
  const body = WORKER.slice(at, WORKER.indexOf("\n    };", at));
  const claim = body.indexOf("verifyCapability(databaseId, expect, useDigest, effect)");
  const execute = body.indexOf("await execute(");
  assert.ok(claim !== -1 && execute !== -1 && claim < execute,
    "the effect must be recorded with the claim, before the route body runs");
});
