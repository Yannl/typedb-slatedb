/*
 * Owner tooling for the signed approval envelope (R5-CF-01).
 *
 * This is the ISSUER side of the approval artifact: it runs on the owner's
 * machine, never inside the probe runner. Two operations:
 *
 *   keygen:  node --experimental-strip-types probes/sign-envelope.ts \
 *              --keygen <out-prefix>
 *            writes <out-prefix>.private.pem (0600) and <out-prefix>.public.pem.
 *            The PUBLIC key is what the runner's deployment receives as
 *            PROBE_ENVELOPE_PUBLIC_KEY; the private key never leaves the
 *            owner's custody.
 *
 *   sign:    node --experimental-strip-types probes/sign-envelope.ts \
 *              --sign <draft.json> --key <private.pem> --out <envelope.json>
 *            Completes computable binding fields (release_commit from git
 *            HEAD, probes_source_root from the working tree) IF the draft
 *            left them empty — the owner still reviews the completed draft
 *            printed before signing. Refuses a draft whose computable
 *            fields disagree with the tree it is signed from.
 */

import { generateKeyPairSync } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { computeProbesSourceRoot, ENVELOPE_SCHEMA, signEnvelope } from "./approval.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..");

function gitHead(): string {
  return execFileSync("git", ["-C", REPO_ROOT, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
}

function keygen(prefix: string): number {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  writeFileSync(`${prefix}.private.pem`, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  writeFileSync(`${prefix}.public.pem`, publicKey.export({ type: "spki", format: "pem" }));
  console.log(`wrote ${prefix}.private.pem (keep private) and ${prefix}.public.pem (deploy as PROBE_ENVELOPE_PUBLIC_KEY)`);
  return 0;
}

function signCmd(draftPath: string, keyPath: string, outPath: string): number {
  const draft = JSON.parse(readFileSync(draftPath, "utf8")) as Record<string, unknown>;
  if (draft.schema !== ENVELOPE_SCHEMA) {
    console.error(`draft schema must be ${ENVELOPE_SCHEMA}`);
    return 2;
  }
  const binding = (draft.binding ?? {}) as Record<string, unknown>;
  const head = gitHead();
  const sourceRoot = computeProbesSourceRoot(HERE, join(REPO_ROOT, "control-plane", "wrangler.probe-harness.toml"));
  for (const [field, computed] of [
    ["release_commit", head],
    ["probes_source_root", sourceRoot],
  ] as const) {
    if (binding[field] === undefined || binding[field] === "") binding[field] = computed;
    else if (binding[field] !== computed) {
      console.error(
        `draft binding.${field}=${JSON.stringify(binding[field])} disagrees with this tree (${computed}) — ` +
          "sign from the exact tree the envelope authorizes",
      );
      return 2;
    }
  }
  draft.binding = binding;
  console.log("signing this exact envelope body:");
  console.log(JSON.stringify(draft, null, 2));
  const signed = signEnvelope(readFileSync(keyPath, "utf8"), draft);
  writeFileSync(outPath, JSON.stringify(signed, null, 2) + "\n");
  console.log(`wrote ${outPath} (fingerprint ${signed.signature.public_key_fingerprint})`);
  return 0;
}

export function cli(argv: string[]): number {
  if (argv[0] === "--keygen" && argv[1]) return keygen(argv[1]);
  if (argv[0] === "--sign" && argv[1]) {
    const keyIdx = argv.indexOf("--key");
    const outIdx = argv.indexOf("--out");
    if (keyIdx === -1 || outIdx === -1 || !argv[keyIdx + 1] || !argv[outIdx + 1]) {
      console.error("usage: --sign <draft.json> --key <private.pem> --out <envelope.json>");
      return 2;
    }
    return signCmd(argv[1], argv[keyIdx + 1], argv[outIdx + 1]);
  }
  console.error("usage: sign-envelope.ts --keygen <prefix> | --sign <draft> --key <pem> --out <path>");
  return 2;
}

const invokedDirectly = (() => {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(entry)).href;
  } catch {
    return false;
  }
})();

if (invokedDirectly) process.exitCode = cli(process.argv.slice(2));
