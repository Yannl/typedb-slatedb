// R6-PORT-01 - the release identity, resolvable in every source posture.
//
// The round-6 audit materialised this repository with `git archive` (no
// `.git`) and two probe controls failed: `control-plane/probes/approval.test.ts`
// and `runner-safety.test.ts` call `execFileSync("git", ["rev-parse", "HEAD"])`
// at module scope, and `preflight.ts` records PREREQUISITE_MISSING when that
// call throws. The approval envelope is BOUND to the release commit, so a
// source release without `.git` could not validate an approval at all.
//
// This module is the single resolution point. It is the exact behavioural twin
// of tools/release/release_identity.py - the same four postures, the same
// precedence, the same refusal - so the Python CI gate and the TypeScript
// probes can never disagree about which commit is being approved.
//
//   git checkout  -> `git rev-parse HEAD`                 (authoritative)
//   git archive   -> RELEASE-IDENTITY.json, `$Format:%H$` expanded by git's
//                    `export-subst` at export time        (verified: false)
//   release/installed -> RELEASE-IDENTITY.json written by
//                    `tools/release/release_identity.py --generate`, carrying
//                    an identity_digest over its own canonical body, which the
//                    release artifact manifest records  (verified: true)
//   none of the above -> throw SourceIdentityUnavailable  (REFUSE, never guess)
//
// Refusing is the point. The pre-fix behaviour of `evidence.ts` -
// `return "UNKNOWN (git rev-parse HEAD failed)"` - lets a run continue and
// produce evidence with no provenance; that is worse than stopping.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

export const RELEASE_IDENTITY_SCHEMA = "typedb-r2/release-identity@1";
export const IDENTITY_FILENAME = "RELEASE-IDENTITY.json";

const SHA1_RE = /^[0-9a-f]{40}$/;
const PLACEHOLDER_RE = /^\$Format:.*\$$/;
/** Excluded from the digest: itself, and prose that may be reworded. */
const DIGEST_EXCLUDED = new Set(["identity_digest", "note"]);

export type ReleaseIdentityPosture =
  | "git-checkout"
  | "git-archive-export-subst"
  | "release-artifact";

export interface ReleaseIdentity {
  releaseCommit: string;
  posture: ReleaseIdentityPosture | string;
  /** true when git itself vouches for it, or an identity_digest re-verified. */
  verified: boolean;
  /** Only a checkout can answer this; null in every archive posture. */
  dirtyPaths: number | null;
  detail: string;
}

export class SourceIdentityUnavailable extends Error {
  readonly code = "SOURCE_IDENTITY_UNAVAILABLE";
  constructor(message: string) {
    super(message);
    this.name = "SourceIdentityUnavailable";
  }
}

/** sha256 over the canonical body: compact JSON, sorted keys, digest+note removed. */
export function canonicalIdentityDigest(body: Record<string, unknown>): string {
  const payload: Record<string, unknown> = {};
  for (const key of Object.keys(body).sort()) {
    if (!DIGEST_EXCLUDED.has(key)) payload[key] = body[key];
  }
  return createHash("sha256").update(JSON.stringify(payload), "utf8").digest("hex");
}

function gitHead(repoRoot: string): string | null {
  try {
    const out = execFileSync("git", ["-C", repoRoot, "rev-parse", "HEAD"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return SHA1_RE.test(out) ? out : null;
  } catch {
    return null;
  }
}

function gitDirtyCount(repoRoot: string): number | null {
  try {
    const out = execFileSync("git", ["-C", repoRoot, "status", "--porcelain"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    return out.split("\n").filter((l) => l.trim().length > 0).length;
  } catch {
    return null;
  }
}

/**
 * Resolve the release identity, or throw SourceIdentityUnavailable.
 *
 * This is the function probes should call instead of shelling out to git.
 */
export function resolveReleaseIdentity(repoRoot: string): ReleaseIdentity {
  const head = gitHead(repoRoot);
  if (head !== null) {
    return {
      releaseCommit: head,
      posture: "git-checkout",
      verified: true,
      dirtyPaths: gitDirtyCount(repoRoot),
      detail: "resolved from git HEAD in a working checkout",
    };
  }

  let raw: string;
  try {
    raw = readFileSync(join(repoRoot, IDENTITY_FILENAME), "utf8");
  } catch {
    throw new SourceIdentityUnavailable(
      `no .git and no ${IDENTITY_FILENAME}: this materialisation cannot prove which commit it is. ` +
        `Use a checkout, a \`git archive\` export (which expands the identity file), or a release ` +
        `artifact built by \`tools/release/release_identity.py --generate\`.`,
    );
  }

  let body: Record<string, unknown>;
  try {
    body = JSON.parse(raw) as Record<string, unknown>;
  } catch (err) {
    throw new SourceIdentityUnavailable(`${IDENTITY_FILENAME} is not valid JSON: ${(err as Error).message}`);
  }

  if (body.schema !== RELEASE_IDENTITY_SCHEMA) {
    throw new SourceIdentityUnavailable(
      `${IDENTITY_FILENAME} schema is ${JSON.stringify(body.schema)}, expected ${RELEASE_IDENTITY_SCHEMA}`,
    );
  }

  const commit = body.release_commit;
  if (typeof commit === "string" && PLACEHOLDER_RE.test(commit)) {
    throw new SourceIdentityUnavailable(
      `${IDENTITY_FILENAME} still carries the unexpanded ${commit} placeholder and there is no .git to ` +
        `fall back to. This tree was COPIED out of a checkout rather than exported; \`git archive\` ` +
        `would have expanded it (see .gitattributes export-subst).`,
    );
  }
  if (typeof commit !== "string" || !SHA1_RE.test(commit)) {
    throw new SourceIdentityUnavailable(
      `${IDENTITY_FILENAME} release_commit is not a 40-hex commit: ${JSON.stringify(commit)}`,
    );
  }

  const digest = body.identity_digest;
  if (digest === null || digest === undefined) {
    return {
      releaseCommit: commit,
      posture: (body.provenance as string) ?? "git-archive-export-subst",
      verified: false,
      dirtyPaths: null,
      detail: "expanded by git at archive-export time; no identity_digest to re-verify",
    };
  }

  const recomputed = canonicalIdentityDigest(body);
  if (recomputed !== digest) {
    throw new SourceIdentityUnavailable(
      `${IDENTITY_FILENAME} identity_digest does not match its own body ` +
        `(recorded ${String(digest)}, recomputed ${recomputed}) - the identity file has been altered`,
    );
  }
  return {
    releaseCommit: commit,
    posture: (body.provenance as string) ?? "release-artifact",
    verified: true,
    dirtyPaths: typeof body.dirty_paths === "object" && Array.isArray(body.dirty_paths) ? body.dirty_paths.length : null,
    detail: "identity_digest recomputed from the file's canonical body and matched",
  };
}

/**
 * The commit alone, for call sites that only need the binding value.
 *
 * This is the one-line drop-in for the probe sites that currently call
 * `execFileSync("git", ["-C", REPO_ROOT, "rev-parse", "HEAD"], ...)`.
 */
export function resolveReleaseCommit(repoRoot: string): string {
  return resolveReleaseIdentity(repoRoot).releaseCommit;
}
