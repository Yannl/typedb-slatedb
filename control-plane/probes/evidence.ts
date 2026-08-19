/*
 * Evidence bundle writer for the platform probe harness —
 * PlatformRunBundle v2 (round-3 audit findings P-01, P-04, P-05).
 *
 * Every run gets a UNIQUE content-addressed directory under
 * docs/evidence/G1-platform/runs/<timestamp>-<random>/ — never reused,
 * never merged. Bundle layout (v2):
 *
 *   <run>/run.json          run id, mode, source identity (git HEAD +
 *                           dirty state), lock digests, toolchain, argv,
 *                           fault schedule (the deterministic "seed"),
 *                           observed verdicts and the policy verdict;
 *   <run>/plan.json         EVERY assertion id of every manifest probe
 *                           with its required_in modes — the plan exists
 *                           before results, so a missing assertion is
 *                           visible, and a probe 'note' can never satisfy
 *                           a required assertion (it is not in the plan's
 *                           satisfiable vocabulary at all);
 *   <run>/probes/<id>.json  one evidence record per probe: typed
 *                           assertion results plus REDACTED exchanges;
 *   <run>/cleanup.json      cleanup obligations and the actions actually
 *                           taken (written from the runner's finally);
 *   <run>/artifacts.json    path/digest/bytes/media type/producer/
 *                           redaction class for every artifact;
 *   <run>/VERDICT.json      deterministic coverage + policy result;
 *   <run>/COMPLETE          written LAST: sha256 root over the sorted
 *                           (path, sha256) list of every other artifact.
 *
 * A bundle without COMPLETE is an aborted run and must never be treated
 * as evidence; a bundle whose root does not recompute is tampered.
 *
 * P-01: nothing reaches this file unredacted — headers pass the strict
 * allowlist, bodies pass the recursive semantic redactor, and
 * credential-route bodies get no preview at all (see redact.ts).
 *
 * P-04: the RecordingProvider records the sanitized INTENT of every
 * exchange BEFORE dispatch and always finalizes a typed outcome
 * (success/error/abort) with end time and duration in a finally — a
 * thrown timeout after a possible server commit leaves a complete
 * intent+outcome pair, never a silent hole.
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import type { ProbeVerdict } from "./manifest.ts";
import type { PlatformProvider, SeamRequest, SeamResponse } from "./provider.ts";
import { randomHex, sha256hex } from "./provider.ts";
import type { RedactionClass } from "./redact.ts";
import {
  classifyRoute,
  findSecretLeaks,
  redactedBodyPreview,
  redactEvidenceValue,
  redactHeaders,
  redactText,
} from "./redact.ts";

// ---------------------------------------------------------------------------
// Exchange records (P-01 + P-04).
// ---------------------------------------------------------------------------

export type ExchangeOutcome =
  | { type: "pending" }
  | { type: "success"; status: number }
  | { type: "error"; message: string }
  | { type: "abort"; message: string };

/** One request/response pair; every string in it has passed redaction. */
export interface ExchangeRecord {
  seq: number;
  started_at: string;
  finished_at: string | null;
  duration_ms: number | null;
  redaction_class: RedactionClass;
  request: {
    service: string;
    method: string;
    path: string;
    headers: Record<string, string>;
    redacted_header_names: string[];
    // Credentials never land in evidence — not even the key id (AWS-style
    // key ids are canary-shaped); only its sha256 for correlation.
    credential_key_id_sha256?: string;
    body_length: number;
    body_sha256: string;
    body_preview: string;
  };
  request_sha256: string;
  outcome: ExchangeOutcome;
  response: {
    status: number;
    headers: Record<string, string>;
    redacted_header_names: string[];
    body_length: number;
    body_sha256: string;
    body_preview: string;
  } | null;
  response_sha256: string | null;
}

/** One assertion result; the id must be declared in the probe's plan. */
export interface CheckRecord {
  assertion_id: string;
  ok: boolean;
  detail: string;
}

export interface ProbeEvidence {
  probe_id: string;
  title: string;
  spec_section: string;
  mode: "real" | "mock";
  injected_fault: string | null;
  started_at: string;
  finished_at: string;
  verdict: ProbeVerdict;
  expected_outcome: string;
  actual_outcome: string;
  checks: CheckRecord[];
  /** Declared-but-unexercised required assertion ids (any => FAIL). */
  unsatisfied_required_assertions: string[];
  exchanges: ExchangeRecord[];
  notes: string[];
}

/** Error thrown when a recorded exchange exceeds its deadline (P-04). */
export class ExchangeDeadlineError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = "ExchangeDeadlineError";
  }
}

/**
 * Wraps a provider so every exchange a probe makes is recorded, with
 * sanitized intent BEFORE dispatch and a typed outcome finalized in a
 * finally. Probes cannot opt out: this wrapper is the only fetch they see.
 */
export class RecordingProvider {
  private seq = 0;
  readonly exchanges: ExchangeRecord[] = [];
  private readonly inner: PlatformProvider;
  private readonly requestDeadlineMs: number;
  private closedReason: string | null = null;

  constructor(inner: PlatformProvider, requestDeadlineMs = 30_000) {
    this.inner = inner;
    this.requestDeadlineMs = requestDeadlineMs;
  }

  get mode(): "real" | "mock" {
    return this.inner.mode;
  }

  /**
   * R4-CF-01: after close(), every further fetch is a typed refusal
   * recorded as an exchange. The runner closes the recorder the moment a
   * probe's deadline fires, so the raced-out async task cannot keep
   * making provider calls while the runner moves on to cleanup.
   */
  close(reason: string): void {
    if (this.closedReason === null) this.closedReason = reason;
  }

  async fetch(req: SeamRequest): Promise<SeamResponse> {
    if (this.closedReason !== null) {
      throw new ExchangeDeadlineError(
        `provider closed (${this.closedReason}); post-deadline probe calls are refused before dispatch`,
      );
    }
    const cls = classifyRoute(req.service, req.path);
    const reqBody = req.body ?? new Uint8Array(0);
    const reqHeaders = redactHeaders(req.headers ?? {});
    const reqRecord: ExchangeRecord["request"] = {
      service: req.service,
      method: req.method,
      path: redactText(req.path),
      headers: reqHeaders.headers,
      redacted_header_names: reqHeaders.redacted_header_names,
      body_length: reqBody.length,
      body_sha256: sha256hex(reqBody),
      body_preview: redactedBodyPreview(reqBody, cls),
    };
    if (req.credentials) reqRecord.credential_key_id_sha256 = sha256hex(req.credentials.keyId);
    const startedMs = Date.now();
    // --- P-04: intent is recorded BEFORE dispatch ---
    const record: ExchangeRecord = {
      seq: ++this.seq,
      started_at: new Date(startedMs).toISOString(),
      finished_at: null,
      duration_ms: null,
      redaction_class: cls,
      request: reqRecord,
      request_sha256: sha256hex(JSON.stringify(reqRecord)),
      outcome: { type: "pending" },
      response: null,
      response_sha256: null,
    };
    this.exchanges.push(record);

    const effectiveDeadline = req.deadlineMs ?? this.requestDeadlineMs;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      // The deadline is enforced HERE as well as inside the real provider's
      // AbortSignal: even a never-resolving inner fetch (or a mock bug)
      // yields a typed abort outcome instead of a hung run.
      const deadline = new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new ExchangeDeadlineError(`exchange deadline ${effectiveDeadline}ms exceeded`)),
          effectiveDeadline,
        );
      });
      const res = await Promise.race([this.inner.fetch({ ...req, deadlineMs: effectiveDeadline }), deadline]);
      const resHeaders = redactHeaders(res.headers);
      const resRecord: NonNullable<ExchangeRecord["response"]> = {
        status: res.status,
        headers: resHeaders.headers,
        redacted_header_names: resHeaders.redacted_header_names,
        body_length: res.body.length,
        body_sha256: sha256hex(res.body),
        body_preview: redactedBodyPreview(res.body, cls),
      };
      record.response = resRecord;
      record.response_sha256 = sha256hex(JSON.stringify(resRecord));
      record.outcome = { type: "success", status: res.status };
      return res;
    } catch (err) {
      const message = redactText(err instanceof Error ? `${err.name}: ${err.message}` : String(err));
      const aborted =
        err instanceof ExchangeDeadlineError ||
        (err instanceof Error && (err.name === "AbortError" || err.name === "TimeoutError"));
      record.outcome = aborted ? { type: "abort", message } : { type: "error", message };
      throw err;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      // Always: end time and duration, whatever happened above.
      record.finished_at = new Date().toISOString();
      record.duration_ms = Date.now() - startedMs;
    }
  }
}

// ---------------------------------------------------------------------------
// Source identity.
// ---------------------------------------------------------------------------

/** Source identity: git HEAD of the working tree the probes ran from. */
export function gitHead(repoRoot: string): string {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], { cwd: repoRoot, encoding: "utf8" }).trim();
  } catch {
    // Recorded, not hidden: evidence without provenance says so explicitly.
    return "UNKNOWN (git rev-parse HEAD failed)";
  }
}

/** Number of dirty paths in the working tree ("0" is a claim, so record it). */
export function gitDirtyCount(repoRoot: string): number | null {
  try {
    const out = execFileSync("git", ["status", "--porcelain"], { cwd: repoRoot, encoding: "utf8" });
    return out.split("\n").filter((l) => l.trim().length > 0).length;
  } catch {
    return null;
  }
}

/** sha256 of a repo file, or null when absent (recorded, not hidden). */
export function fileSha256(path: string): string | null {
  try {
    return sha256hex(new Uint8Array(readFileSync(path)));
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// PlatformRunBundle v2.
// ---------------------------------------------------------------------------

export interface ArtifactEntry {
  path: string;
  sha256: string;
  bytes: number;
  media_type: string;
  producer: string;
  redaction_class: "redacted-exchanges" | "none";
}

function mediaTypeFor(name: string): string {
  if (name.endsWith(".json")) return "application/json";
  return "text/plain";
}

export class EvidenceBundle {
  readonly runDir: string;
  readonly runId: string;
  private sealed = false;

  constructor(evidenceRoot: string) {
    // Unique per run: timestamp for humans, random suffix so two runs in
    // the same millisecond can never collide or merge.
    this.runId = `${new Date().toISOString().replace(/[:.]/g, "-")}-${randomHex(4)}`;
    this.runDir = join(evidenceRoot, this.runId);
    mkdirSync(evidenceRoot, { recursive: true });
    // recursive:false on the run directory itself: if the unique name ever
    // collides, fail loudly instead of merging into an existing bundle.
    mkdirSync(this.runDir, { recursive: false });
    mkdirSync(join(this.runDir, "probes"));
  }

  private write(rel: string, value: unknown): void {
    if (this.sealed) throw new Error("evidence bundle already sealed");
    // R4-CF-03: the redactor is a SERIALIZATION invariant — every value
    // (assertion detail, notes, thrown errors, preflight reasons, cleanup
    // detail, run record, verdict) passes the deep redactor here, at the
    // single point where evidence becomes bytes. Nothing is written that
    // did not pass it.
    writeFileSync(join(this.runDir, rel), JSON.stringify(redactEvidenceValue(value), null, 2) + "\n");
  }

  writeProbeEvidence(ev: ProbeEvidence): void {
    this.write(join("probes", `${ev.probe_id}.json`), ev);
  }

  writePlan(plan: Record<string, unknown>): void {
    this.write("plan.json", plan);
  }

  writeRunRecord(record: Record<string, unknown>): void {
    this.write("run.json", record);
  }

  writeCleanupRecord(record: Record<string, unknown>): void {
    this.write("cleanup.json", record);
  }

  writeVerdict(record: Record<string, unknown>): void {
    this.write("VERDICT.json", record);
  }

  /** Every file currently in the bundle, as run-relative sorted paths. */
  private files(): string[] {
    const out: string[] = [];
    const walk = (dir: string): void => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, e.name);
        if (e.isDirectory()) walk(p);
        else if (e.isFile()) out.push(relative(this.runDir, p));
      }
    };
    walk(this.runDir);
    return out.sort();
  }

  /**
   * Seal the bundle: FIRST scan every artifact byte (filenames included)
   * for secret leaks — a hit throws SealViolationError and COMPLETE is
   * never written (R4-CF-03: the scanner is the second gate behind the
   * write-time redactor, and it also catches files placed in the bundle
   * directory outside the writer). Then write artifacts.json (manifest
   * of every artifact, excluding itself and COMPLETE), compute the root
   * hash over the sorted (path, sha256) list of EVERY file —
   * artifacts.json included — and write COMPLETE last. Returns the root.
   *
   * `knownSecrets` are the run's actual configured credential values;
   * their exact bytes must appear nowhere in the bundle.
   */
  seal(knownSecrets: ReadonlyArray<string> = []): string {
    if (this.sealed) throw new Error("evidence bundle already sealed");
    const leaks: string[] = [];
    for (const rel of this.files()) {
      const nameLeaks = findSecretLeaks(rel, knownSecrets);
      for (const l of nameLeaks) leaks.push(`${rel} (filename): ${l}`);
      const content = readFileSync(join(this.runDir, rel), "utf8");
      for (const l of findSecretLeaks(content, knownSecrets)) leaks.push(`${rel}: ${l}`);
    }
    if (leaks.length > 0) {
      // No COMPLETE, no root: a leaking bundle is an aborted run.
      throw new SealViolationError(leaks);
    }
    const manifest: ArtifactEntry[] = this.files()
      .filter((rel) => rel !== "COMPLETE" && rel !== "artifacts.json")
      .map((rel) => {
        const bytes = new Uint8Array(readFileSync(join(this.runDir, rel)));
        return {
          path: rel,
          sha256: sha256hex(bytes),
          bytes: bytes.length,
          media_type: mediaTypeFor(rel),
          producer: "control-plane/probes/run-platform-probes.ts",
          redaction_class: rel.startsWith("probes/") ? ("redacted-exchanges" as const) : ("none" as const),
        };
      });
    this.write("artifacts.json", { artifacts: manifest });
    const entries = this.files()
      .filter((rel) => rel !== "COMPLETE")
      .map((rel) => `${rel}\n${sha256hex(new Uint8Array(readFileSync(join(this.runDir, rel))))}\n`);
    const root = sha256hex(entries.join(""));
    writeFileSync(join(this.runDir, "COMPLETE"), root + "\n");
    this.sealed = true;
    return root;
  }
}

/** Thrown by seal() on any secret leak; the bundle stays un-COMPLETE. */
export class SealViolationError extends Error {
  readonly leaks: ReadonlyArray<string>;
  constructor(leaks: ReadonlyArray<string>) {
    // The leak list names files and leak CLASSES only — never the
    // leaking content itself (that would move the leak into logs).
    super(`evidence seal refused: ${leaks.length} secret leak(s) detected: ${leaks.join("; ")}`);
    this.name = "SealViolationError";
    this.leaks = leaks;
  }
}
