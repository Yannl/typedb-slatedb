/*
 * DEPRECATED wrapper — kept only so existing entry points
 * (package.json "probes:r2", docs/handoff-live-validation.md) keep
 * working. The pre-audit implementation that lived here was proved
 * false-green by the external audit (finding C-P0-10): probes printed
 * FAIL while main() never aggregated verdicts, so the process exited 0,
 * and only 2 of the 14 normative probes existed.
 *
 * All probe execution now goes through run-platform-probes.ts, which
 * carries the manifest completeness gate, fail-closed verdict
 * aggregation, and sealed evidence bundles. This wrapper forwards argv
 * verbatim and propagates the aggregated exit code unchanged.
 */

import { main } from "./run-platform-probes.ts";

console.error(
  "run-r2-probes.ts is a deprecated wrapper; forwarding to run-platform-probes.ts " +
    "(all 14 normative probes, fail-closed aggregation).",
);

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error("platform-probes: runner crashed:", err);
    process.exitCode = 1;
  },
);
