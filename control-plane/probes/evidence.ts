/*
 * Evidence bundle writer for the platform probe harness.
 *
 * Every run gets a UNIQUE content-addressed directory under
 * docs/evidence/G1-platform/runs/<timestamp>-<random>/ — never reused,
 * never merged, so no later run can silently overwrite the record of an
 * earlier one. The bundle is sealed fail-closed:
 *
 *   <run>/<probe-id>.json   one PlatformProbeEvidence record per probe,
 *                           embedding every raw request/response exchange
 *                           with its sha256;
 *   <run>/run.json          source identity (git HEAD), config, argv,
 *                           timestamps, verdict table, exit code;
 *   <run>/COMPLETE          written LAST, containing the bundle root:
 *                           sha256 over the sorted (path, sha256) list of
 *                           every other artifact in the bundle.
 *
 * A bundle without COMPLETE is an aborted run and must never be treated
 * as evidence; a bundle whose root does not recompute is tampered.
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { ProbeVerdict } from "./manifest.ts";
import type { PlatformProvider, SeamRequest, SeamResponse } from "./provider.ts";
import { randomHex, sha256hex, text } from "./provider.ts";

/** One raw request/response pair, hash-addressed for the evidence record. */
export interface ExchangeRecord {
  seq: number;
  at: string;
  request: {
    service: string;
    method: string;
    path: string;
    headers: Record<string, string>;
    // Credentials never land in evidence in signing form; only the key id.
    credential_key_id?: string;
    body_length: number;
    body_sha256: string;
    body_preview: string;
  };
  request_sha256: string;
  response: {
    status: number;
    headers: Record<string, string>;
    body_length: number;
    body_sha256: string;
    body_preview: string;
  };
  response_sha256: string;
}

/** Assertion outcome; every probe check lands here, pass or fail. */
export interface CheckRecord {
  label: string;
  ok: boolean;
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
  exchanges: ExchangeRecord[];
  notes: string[];
}

function preview(body: Uint8Array): string {
  const s = text(body.subarray(0, 256));
  // Keep evidence JSON printable; raw bytes are represented by the sha256.
  return s.replace(/[^\x20-\x7e\n\t]/g, "?");
}

/**
 * Wraps a provider so every exchange a probe makes is recorded, with
 * sha256 hashes over the canonical JSON serialization of request and
 * response. Probes cannot opt out: this wrapper is the only fetch they see.
 */
export class RecordingProvider {
  private seq = 0;
  readonly exchanges: ExchangeRecord[] = [];
  private readonly inner: PlatformProvider;

  constructor(inner: PlatformProvider) {
    this.inner = inner;
  }

  get mode(): "real" | "mock" {
    return this.inner.mode;
  }

  async fetch(req: SeamRequest): Promise<SeamResponse> {
    const res = await this.inner.fetch(req);
    const reqRecord: ExchangeRecord["request"] = {
      service: req.service,
      method: req.method,
      path: req.path,
      headers: req.headers ?? {},
      body_length: req.body?.length ?? 0,
      body_sha256: sha256hex(req.body ?? new Uint8Array(0)),
      body_preview: preview(req.body ?? new Uint8Array(0)),
    };
    if (req.credentials) reqRecord.credential_key_id = req.credentials.keyId;
    const resRecord: ExchangeRecord["response"] = {
      status: res.status,
      headers: res.headers,
      body_length: res.body.length,
      body_sha256: sha256hex(res.body),
      body_preview: preview(res.body),
    };
    this.exchanges.push({
      seq: ++this.seq,
      at: new Date().toISOString(),
      request: reqRecord,
      request_sha256: sha256hex(JSON.stringify(reqRecord)),
      response: resRecord,
      response_sha256: sha256hex(JSON.stringify(resRecord)),
    });
    return res;
  }
}

/** Source identity: git HEAD of the working tree the probes ran from. */
export function gitHead(repoRoot: string): string {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], { cwd: repoRoot, encoding: "utf8" }).trim();
  } catch {
    // Recorded, not hidden: evidence without provenance says so explicitly.
    return "UNKNOWN (git rev-parse HEAD failed)";
  }
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
  }

  writeProbeEvidence(ev: ProbeEvidence): void {
    if (this.sealed) throw new Error("evidence bundle already sealed");
    writeFileSync(join(this.runDir, `${ev.probe_id}.json`), JSON.stringify(ev, null, 2) + "\n");
  }

  writeRunRecord(record: Record<string, unknown>): void {
    if (this.sealed) throw new Error("evidence bundle already sealed");
    writeFileSync(join(this.runDir, "run.json"), JSON.stringify(record, null, 2) + "\n");
  }

  /**
   * Seal the bundle: compute the root hash over the sorted
   * (path, sha256) list of every artifact, then write COMPLETE last.
   * Returns the bundle root.
   */
  seal(): string {
    if (this.sealed) throw new Error("evidence bundle already sealed");
    const entries = readdirSync(this.runDir, { withFileTypes: true })
      .filter((e) => e.isFile() && e.name !== "COMPLETE")
      .map((e) => e.name)
      .sort()
      .map((name) => `${name}\n${sha256hex(new Uint8Array(readFileSync(join(this.runDir, name))))}\n`);
    const root = sha256hex(entries.join(""));
    writeFileSync(join(this.runDir, "COMPLETE"), root + "\n");
    this.sealed = true;
    return root;
  }
}
