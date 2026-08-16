/*
 * Worker entry: local-stack (L1) HTTP facade over the control plane.
 *
 * The same topology as production — gateway Worker → R2 data path →
 * DatabaseControllerDO finalisation — served locally by workerd via
 * `wrangler dev` (or vitest-pool-workers). Payload bytes travel through R2
 * (local simulator in dev, real R2 in staging/production); the controller
 * only ever sees keys/digests, and digest verification happens in the data
 * path BEFORE the DO's synchronous finalisation (inv. 151).
 *
 * Endpoints (JSON unless noted):
 *   GET  /health
 *   PUT  /payload/{key}            raw body → R2; returns {key, sha256hex, length}
 *   POST /session/register         {databaseId, generation, startupSessionId}
 *   POST /session/fence            {databaseId, generation, startupSessionId}
 *   POST /budgets                  {databaseId, maxUnpublishedOutbox, maxPayloadLength, maxTailRecords}
 *   POST /wal/finalize             FinalizeRequest → FinalizeResult (verifies R2 object + digest first)
 *   GET  /wal/{db}/{generation}/{lsn}  exact lookup; returns record metadata + payload bytes (base64)
 *   GET  /wal/{db}/{generation}/audit  contiguity audit
 *   GET  /outbox/{db}?limit=N      peek unpublished control events (no marking)
 *   POST /outbox/{db}/ack          {upToControlSeq} - ack after durable processing
 */

export { DatabaseControllerDO } from "./database-controller.ts";

interface Env {
  CONTROLLER: DurableObjectNamespace;
  PAYLOADS: R2Bucket;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

async function sha256hex(bytes: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "GET" && path === "/health") {
      return json({ ok: true, runtime: "workerd", stack: "L1-local" });
    }

    if (request.method === "PUT" && path.startsWith("/payload/")) {
      const key = decodeURIComponent(path.slice("/payload/".length));
      const bytes = await request.arrayBuffer();
      const digest = await sha256hex(bytes);
      // payload immutability: puts are create-or-identical, never overwrite.
      // The create is a CONDITIONAL put (If-None-Match: *), not get-then-put:
      // two concurrent puts of different bytes must never both succeed, and a
      // read-then-write window would allow exactly that (last-writer-wins over
      // a digest another client may already have receipt-verified). On
      // precondition failure the existing object is compared by digest.
      // (In production the same contract is enforced by object-store
      // conditions/credential policy; the facade upholds it locally.)
      for (let attempt = 0; attempt < 3; attempt++) {
        const created = await env.PAYLOADS.put(key, bytes, {
          onlyIf: new Headers({ "if-none-match": "*" }),
        });
        if (created !== null) {
          return json({ key, sha256hex: digest, length: bytes.byteLength });
        }
        const existing = await env.PAYLOADS.get(key);
        if (existing === null) continue; // lost a delete/create race; retry the conditional create
        const existingDigest = await sha256hex(await existing.arrayBuffer());
        if (existingDigest !== digest) {
          return json({ ok: false, error: "PAYLOAD_IMMUTABILITY_VIOLATION", key, existing: existingDigest }, 409);
        }
        return json({ key, sha256hex: digest, length: bytes.byteLength, deduplicated: true });
      }
      return json({ ok: false, error: "PAYLOAD_RACE_UNRESOLVED", key }, 503);
    }

    // controller routing: one DO per database
    const stubFor = (databaseId: string) =>
      env.CONTROLLER.get(env.CONTROLLER.idFromName(databaseId)) as unknown as {
        registerSession(db: string, generation: number, session: string): Promise<void>;
        fenceSession(db: string, generation: number, session: string): Promise<void>;
        setBudgets(db: string, budgets: object): Promise<void>;
        finalizeWalRecord(req: object): Promise<Record<string, unknown>>;
        exactLookup(db: string, generation: number, lsn: number): Promise<Record<string, unknown>>;
        auditContiguity(db: string, generation: number): Promise<Record<string, unknown>>;
      };

    if (request.method === "POST" && path === "/session/register") {
      const b = (await request.json()) as { databaseId: string; generation: number; startupSessionId: string };
      await stubFor(b.databaseId).registerSession(b.databaseId, b.generation, b.startupSessionId);
      return json({ ok: true });
    }

    if (request.method === "POST" && path === "/session/fence") {
      const b = (await request.json()) as { databaseId: string; generation: number; startupSessionId: string };
      await stubFor(b.databaseId).fenceSession(b.databaseId, b.generation, b.startupSessionId);
      return json({ ok: true });
    }

    if (request.method === "POST" && path === "/budgets") {
      const b = (await request.json()) as {
        databaseId: string; maxUnpublishedOutbox: number; maxPayloadLength: number; maxTailRecords: number;
      };
      await stubFor(b.databaseId).setBudgets(b.databaseId, {
        maxUnpublishedOutbox: b.maxUnpublishedOutbox,
        maxPayloadLength: b.maxPayloadLength,
        maxTailRecords: b.maxTailRecords,
      });
      return json({ ok: true });
    }

    if (request.method === "POST" && path === "/wal/finalize") {
      const req = (await request.json()) as {
        databaseId: string; payloadKey: string; payloadDigest: string; payloadLength: number;
      } & Record<string, unknown>;
      // data-path receipt verification BEFORE the DO's synchronous
      // finalisation: the object must exist and match digest + length
      const object = await env.PAYLOADS.get(req.payloadKey);
      if (object === null) {
        return json({ ok: false, error: "PAYLOAD_MISSING" }, 422);
      }
      const bytes = await object.arrayBuffer();
      const digest = await sha256hex(bytes);
      if (digest !== req.payloadDigest || bytes.byteLength !== req.payloadLength) {
        return json({ ok: false, error: "PAYLOAD_DIGEST_MISMATCH", observed: digest, length: bytes.byteLength }, 422);
      }
      const result = await stubFor(req.databaseId).finalizeWalRecord(req);
      return json(result, result.ok ? 200 : 409);
    }

    const walRead = path.match(/^\/wal\/([^/]+)\/(\d+)\/(\d+)$/);
    if (request.method === "GET" && walRead) {
      const [, db, generation, lsn] = walRead;
      const record = await stubFor(db).exactLookup(db, Number(generation), Number(lsn));
      if (!record.ok) return json(record, 404);
      const object = await env.PAYLOADS.get(String(record.payloadKey));
      if (object === null) {
        // a catalogued record whose payload is missing is a hard integrity
        // error - never EOF (§exact-index rules)
        return json({ ok: false, error: "PAYLOAD_MISSING_FOR_CATALOGUED_RECORD", record }, 500);
      }
      const buffer = await object.arrayBuffer();
      // exact reads re-verify bytes against the catalogued digest: serving
      // corrupted payload under valid metadata is worse than failing
      const observedDigest = await sha256hex(buffer);
      if (observedDigest !== String(record.payloadDigest)) {
        return json(
          { ok: false, error: "PAYLOAD_INTEGRITY_VIOLATION", record, observed: observedDigest },
          500,
        );
      }
      const bytes = new Uint8Array(buffer);
      let binary = "";
      for (const b of bytes) binary += String.fromCharCode(b);
      return json({ ...record, payloadBase64: btoa(binary) });
    }

    const outboxPeek = path.match(/^\/outbox\/([^/]+)$/);
    if (request.method === "GET" && outboxPeek) {
      const limit = Number(url.searchParams.get("limit") ?? "100");
      const stub = stubFor(outboxPeek[1]) as unknown as { outboxPeek(limit: number): Promise<unknown[]> };
      return json({ ok: true, events: await stub.outboxPeek(limit) });
    }

    const outboxAck = path.match(/^\/outbox\/([^/]+)\/ack$/);
    if (request.method === "POST" && outboxAck) {
      const b = (await request.json()) as { upToControlSeq: number };
      const stub = stubFor(outboxAck[1]) as unknown as { outboxAck(seq: number): Promise<number> };
      return json({ ok: true, acked: await stub.outboxAck(b.upToControlSeq) });
    }

    const walAudit = path.match(/^\/wal\/([^/]+)\/(\d+)\/audit$/);
    if (request.method === "GET" && walAudit) {
      const [, db, generation] = walAudit;
      return json(await stubFor(db).auditContiguity(db, Number(generation)));
    }

    return json({ ok: false, error: "NOT_FOUND" }, 404);
  },
};
