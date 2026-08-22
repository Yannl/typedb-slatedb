# Why `knip.json` says what it says (R8-P1-03)

R8-P1-03: knip findings resolved DELIBERATELY, not by widening `ignore`.

Three classes of finding existed, and each gets the treatment its cause
deserves rather than a blanket exclusion:

1. ENTRY POINTS knip could not know about. The Worker entry is named in
   wrangler.toml, the probe CLIs are invoked by npm scripts and by the
   probe self-test shell script, and the workerd suites are collected by
   vitest. Declaring them here is stating a fact about how this project
   is run - it is not suppressing a finding.
2. VIRTUAL CLOUDFLARE MODULES. `cloudflare:workers` and `cloudflare:test`
   are provided by the workerd runtime, not by any package. They are
   declared as ignored dependencies for exactly that reason.
3. GENUINELY UNUSED code and exports were REMOVED (see the commit), not
   listed here.

Nothing in this file may hide an unused source file or an unused export:
the `ignore`/`ignoreExportsUsedInFile` escape hatches are deliberately
absent, so a new dead export fails the gate.

## The three `ignore*` lists, and why each entry is a fact rather than a suppression

* `ignoreDependencies`
  * `dependency-cruiser`, `oxlint` — TOOLS the quality controller runs through
    `npx --no-install`, committed as exact devDependencies precisely so that
    `npm ci` makes them findable without a network fallback (R8-P0-04). No
    module imports them, and none should.
  * `cloudflare` — knip resolves the runtime-provided `cloudflare:workers` and
    `cloudflare:test` specifiers to a package of this name. Those modules are
    supplied by workerd itself; there is no package to install.
  * `@cloudflare/containers` — the Container binding's type/runtime surface,
    referenced from wrangler configuration rather than from source.
* `ignore: **/*.d.mts` — an ambient declaration file is consumed by the
  TypeScript compiler for its sibling `.mjs`; nothing imports it, and that is
  the correct shape. `.d.ts` was already treated this way by the architecture
  rules for the same reason.

Deliberately absent: any entry that would hide an unused source file or an
unused export. Those were resolved by removing the export, so a new dead export
still fails this gate.

  * `@stryker-mutator/core`, `jscpd` — the same shape as dependency-cruiser and
    oxlint: TOOLS the controller runs, committed as exact devDependencies so a
    clean `npm ci` can run the tier-C campaigns at all (R8-P0-04/R8-P0-05). No
    module imports them.
  * `@stryker-mutator/command-runner` — named in `stryker.conf.json`, which
    knip reads as a source of dependency references; Stryker resolves the
    command runner itself from its own package.
