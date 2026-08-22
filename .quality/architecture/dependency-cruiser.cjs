// TypeScript architecture invariants for the control plane (spec §8).
//
// PROTECTED FILE: "Architecture rule files are protected quality policy."
//
// Invoked by `cargo xtask quality` as:
//   (cd control-plane && npx --no-install depcruise \
//       --config ../.quality/architecture/dependency-cruiser.cjs src)
//
// R8-P1-03. Two corrections, and the second matters as much as the first.
//
// 1. THE BOUNDARY IS REAL AGAIN. `src/container/database-container.ts`
//    imported `controller/core/{registry,key-config,capability}.ts` directly.
//    DatabaseContainerDO and DatabaseControllerDO are separate Durable
//    Objects; a production import across them collapses the boundary the rule
//    below exists to protect. The fix is not an exception — it is a real
//    contract layer, `src/shared/`, holding what BOTH sides genuinely need:
//    identifier syntax and the registry binding shape, the capability wire
//    types and their Ed25519 verification, the key-config resolver, and the
//    crypto primitives underneath. Nothing in `src/shared/` knows about a
//    Durable Object, a route or a storage layout: it is contracts and
//    verification, which is why both a controller and a container may hold it
//    without either depending on the other.
//
// 2. TESTS ARE JUDGED BY TEST RULES, NOT IGNORED. The audited configuration
//    classified `*.test.ts` and `*.workerd.test.ts` as production, so every
//    vitest import was a `no-dev-dep-in-production` error — sixteen of the
//    twenty-one violations were tests being told they were production. The
//    answer is not `exclude: tests`: that would stop checking them entirely,
//    and a test file importing the probe harness or the stack tooling is a
//    real finding. So production-only rules now carry `pathNot: TEST`, and
//    tests get their OWN rules below.
//
// The one thing no rule may do is get quieter. Every relaxation here is paired
// with a rule that keeps the same property under the correct classification.

// Test and test-support modules. `*-test-support.ts` is production-shaped code
// that exists only to build fixtures, so it belongs on the test side of every
// production-only rule and on the strict side of the test rules.
const TEST = [
  '\\.test\\.ts$',
  '\\.test\\.mts$',
  '\\.test\\.mjs$',
  '-test-support\\.ts$',
  '(^|/)test-support\\.ts$',
  '(^|/)workerd-test-support\\.ts$',
];

module.exports = {
  forbidden: [
    {
      name: 'no-circular',
      severity: 'error',
      comment: 'Cyclic dependencies between control-plane modules.',
      from: {},
      to: { circular: true },
    },
    {
      name: 'no-orphans',
      severity: 'error',
      comment: 'A module nothing imports and that imports nothing is dead weight.',
      // `.d.mts` is an ambient declaration for a sibling `.mjs`: the compiler
      // consumes it, no module imports it, and that is correct — the same
      // reason `.d.ts` was already exempt.
      from: { orphan: true, pathNot: ['\\.d\\.ts$', '\\.d\\.mts$', '(^|/)index\\.ts$'] },
      to: {},
    },
    {
      name: 'production-must-not-import-probes',
      severity: 'error',
      comment:
        'control-plane/src is the real Worker + Durable Object control plane. It must never import the probe harness, which is test tooling.',
      from: { path: '^src/', pathNot: TEST },
      to: { path: '^probes/' },
    },
    {
      name: 'production-must-not-import-stack-tooling',
      severity: 'error',
      comment: 'The deployed control plane must not depend on local orchestration tooling.',
      from: { path: '^src/', pathNot: TEST },
      to: { path: '^\\.\\./stack/' },
    },
    {
      name: 'no-dev-dep-in-production',
      severity: 'error',
      comment: 'A devDependency must not leak into deployed control-plane code.',
      from: { path: '^src/', pathNot: TEST },
      to: { dependencyTypes: ['npm-dev'] },
    },
    {
      name: 'container-must-not-import-controller-internals',
      severity: 'error',
      comment:
        'DatabaseContainerDO and DatabaseControllerDO are separate Durable Objects (CF-P1). Cross-imports of internals collapse that boundary. What both genuinely share lives in src/shared/ as contracts and verification, not as controller implementation.',
      from: { path: '^src/container/', pathNot: TEST },
      to: { path: '^src/controller/' },
    },
    {
      name: 'controller-must-not-import-container-internals',
      severity: 'error',
      comment:
        'The boundary is symmetric: the controller may not reach into the container either. Without this rule the previous one only stopped the violation that happened to occur first. The single exemption is the WORKER ENTRY module, and it is a platform constraint rather than a convenience: the Workers runtime binds a Durable Object by a class EXPORTED FROM THE ENTRY MODULE, so the entry must name both classes or the container DO cannot be bound at all. The next rule bounds exactly what that exemption may reach.',
      from: { path: '^src/controller/', pathNot: [...TEST, '(^|/)worker-entry\\.ts$'] },
      to: { path: '^src/container/' },
    },
    {
      name: 'worker-entry-may-only-import-the-container-do-class',
      severity: 'error',
      comment:
        'The entry module exists to satisfy the runtime binding, not to become a second route across the boundary: it may import the container Durable Object CLASS and nothing else from src/container/.',
      from: { path: '(^|/)worker-entry\\.ts$' },
      to: { path: '^src/container/', pathNot: ['^src/container/database-container\\.ts$'] },
    },
    {
      name: 'shared-must-stay-a-contract-layer',
      severity: 'error',
      comment:
        'src/shared/ is what both Durable Objects may hold: identifier syntax, wire shapes, capability verification, key configuration, crypto primitives. The moment it imports controller or container code it stops being shared and becomes a laundering route for the boundary above.',
      from: { path: '^src/shared/' },
      to: { path: '^src/(controller|container)/' },
    },
    // ---------------------------------------------------------------- tests
    {
      name: 'test-must-not-be-imported-by-production',
      severity: 'error',
      comment:
        'The replacement for classifying tests as production: production code may not import a test or test-support module. That is the property the misclassification was accidentally enforcing, stated correctly.',
      from: { path: '^src/', pathNot: TEST },
      to: { path: TEST },
    },
    {
      name: 'test-must-not-import-probes',
      severity: 'error',
      comment:
        'Tests are checked by their own rule rather than exempted: the probe harness is a separate credentialed surface and no unit test may pull it in.',
      from: { path: TEST },
      to: { path: '^probes/' },
    },
  ],
  options: {
    doNotFollow: { path: 'node_modules' },
    tsPreCompilationDeps: true,
    tsConfig: { fileName: 'tsconfig.json' },
    reporterOptions: { text: { highlightFocused: true } },
  },
};
