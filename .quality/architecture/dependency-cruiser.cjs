// TypeScript architecture invariants for the control plane (spec §8).
//
// PROTECTED FILE: "Architecture rule files are protected quality policy."
//
// Invoked by `cargo xtask quality` as:
//   (cd control-plane && npx --no-install depcruise \
//       --config ../.quality/architecture/dependency-cruiser.cjs src)

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
      from: { orphan: true, pathNot: ['\\.d\\.ts$', '(^|/)index\\.ts$'] },
      to: {},
    },
    {
      name: 'production-must-not-import-probes',
      severity: 'error',
      comment:
        'control-plane/src is the real Worker + Durable Object control plane. It must never import the probe harness, which is test tooling.',
      from: { path: '^src/' },
      to: { path: '^probes/' },
    },
    {
      name: 'production-must-not-import-stack-tooling',
      severity: 'error',
      comment: 'The deployed control plane must not depend on local orchestration tooling.',
      from: { path: '^src/' },
      to: { path: '^\\.\\./stack/' },
    },
    {
      name: 'no-dev-dep-in-production',
      severity: 'error',
      comment: 'A devDependency must not leak into deployed control-plane code.',
      from: { path: '^src/' },
      to: { dependencyTypes: ['npm-dev'] },
    },
    {
      name: 'container-must-not-import-controller-internals',
      severity: 'error',
      comment:
        'DatabaseContainerDO and DatabaseControllerDO are separate Durable Objects (CF-P1). Cross-imports of internals collapse that boundary.',
      from: { path: '^src/container/' },
      to: { path: '^src/controller/core/' },
    },
  ],
  options: {
    doNotFollow: { path: 'node_modules' },
    tsPreCompilationDeps: true,
    tsConfig: { fileName: 'tsconfig.json' },
    reporterOptions: { text: { highlightFocused: true } },
  },
};
