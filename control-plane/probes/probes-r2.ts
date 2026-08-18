/*
 * P-R2-01 .. P-R2-05 (contract/typedb-r2-v16-platform-probes.md).
 *
 * All five probes run identically against the real R2 S3 API (SigV4,
 * region "auto") and against the deterministic mock provider; steps that
 * require mock-only controllability (forced timeout-after-commit, virtual
 * rate-limit windows, application-layer UploadAttemptId enforcement) are
 * gated on ctx.mode and recorded as such in evidence — a real run never
 * fabricates them and a mock run never skips them.
 */

import type { ProbeContext, ProbeImpl } from "./probe.ts";
import { asJson, patternBytes, r2Delete, r2Get, r2Key, r2Put } from "./probe.ts";
import type { SeamCredentials } from "./provider.ts";
import { sha256hex, utf8 } from "./provider.ts";

function b64sha256(body: Uint8Array): string {
  return Buffer.from(sha256hex(body), "hex").toString("base64");
}

// ---------------------------------------------------------------------------
// P-R2-01 — Conditions and ambiguity.
// ---------------------------------------------------------------------------

const pR2_01: ProbeImpl = {
  id: "P-R2-01",
  expected:
    "exact success/conflict/ambiguous classification; concurrent conditional " +
    "PUTs produce exactly one winner; no unconditional downgrade; " +
    "byte/hash-exact readback",
  async run(ctx: ProbeContext): Promise<void> {
    // --- create-if-absent, then duplicate conditional create ---
    const key = r2Key(ctx, "p-r2-01/cond");
    const payload = utf8("p-r2-01 conditional body");
    const put1 = await r2Put(ctx, key, payload, { "if-none-match": "*" });
    ctx.check(put1.status === 200, `initial PUT if-none-match:* succeeds (got ${put1.status})`);
    const put2 = await r2Put(ctx, key, utf8("different"), { "if-none-match": "*" });
    ctx.check(put2.status === 412, `duplicate conditional create is 412, not a downgrade (got ${put2.status})`);

    // --- if-match: correct and wrong expected version ---
    const etag = put1.headers["etag"] ?? "";
    const put3 = await r2Put(ctx, key, utf8("updated-via-if-match"), { "if-match": etag });
    ctx.check(put3.status === 200, `PUT if-match with current etag succeeds (got ${put3.status})`);
    const put4 = await r2Put(ctx, key, utf8("must-not-land"), { "if-match": '"bogus-version"' });
    ctx.check(put4.status === 412, `PUT if-match with wrong expected version is 412 (got ${put4.status})`);

    // --- byte/hash-exact readback ---
    const rd = await r2Get(ctx, key);
    const expectBytes = utf8("updated-via-if-match");
    ctx.check(rd.status === 200, `readback GET succeeds (got ${rd.status})`);
    ctx.check(
      Buffer.from(rd.body).equals(Buffer.from(expectBytes)) &&
        sha256hex(rd.body) === sha256hex(expectBytes),
      "readback is byte- and sha256-exact",
    );

    // --- concurrency: two conditional creates on one fresh key ---
    // The normative case the pre-audit runner never exercised: exactly one
    // of two concurrent If-None-Match:* writers may win.
    const raceKey = r2Key(ctx, "p-r2-01/race");
    const bodyA = utf8("concurrent-writer-A");
    const bodyB = utf8("concurrent-writer-B");
    const [ra, rb] = await Promise.all([
      r2Put(ctx, raceKey, bodyA, { "if-none-match": "*" }),
      r2Put(ctx, raceKey, bodyB, { "if-none-match": "*" }),
    ]);
    const winners = [ra, rb].filter((r) => r.status === 200);
    const losers = [ra, rb].filter((r) => r.status === 412);
    ctx.check(
      winners.length === 1 && losers.length === 1,
      `exactly one concurrent conditional writer wins (statuses ${ra.status},${rb.status})`,
    );
    const raceRead = await r2Get(ctx, raceKey);
    const winnerBody = ra.status === 200 ? bodyA : bodyB;
    ctx.check(
      raceRead.status === 200 && Buffer.from(raceRead.body).equals(Buffer.from(winnerBody)),
      "stored bytes are exactly the single winner's bytes",
    );

    // --- ambiguity: timeout after server commit (mock-controlled) ---
    if (ctx.mode === "mock") {
      const ambKey = r2Key(ctx, "p-r2-01/ambiguous");
      const ambBody = utf8("ambiguous-commit-body");
      const amb = await r2Put(ctx, ambKey, ambBody, {
        "if-none-match": "*",
        "x-mock-simulate": "commit-then-timeout",
      });
      ctx.check(amb.status === 599, `client observes network failure after server commit (got ${amb.status})`);
      // Resolution of the SAME operation, still conditional — never an
      // unconditional retry that would grant duplicate authority.
      const retry = await r2Put(ctx, ambKey, ambBody, { "if-none-match": "*" });
      ctx.check(retry.status === 412, `conditional retry classifies ambiguity as already-committed (got ${retry.status})`);
      const ambRead = await r2Get(ctx, ambKey);
      ctx.check(
        ambRead.status === 200 && Buffer.from(ambRead.body).equals(Buffer.from(ambBody)),
        "readback proves the ambiguous operation committed exactly once",
      );
    } else {
      ctx.note("real mode: forced timeout-after-commit not injectable against live R2; covered in mock");
    }
  },
};

// ---------------------------------------------------------------------------
// P-R2-02 — Temporary credential action and path scope.
// ---------------------------------------------------------------------------

const pR2_02: ProbeImpl = {
  id: "P-R2-02",
  expected:
    "temporary credentials work only for their exact actions and prefixes; " +
    "every forbidden action denied; parent revocation kills minted credentials",
  async run(ctx: ProbeContext): Promise<void> {
    const allowedPrefix = `probes/${ctx.runNonce}/p-r2-02/allowed/`;
    const allowedKey = `/${ctx.bucket}/${allowedPrefix}obj`;
    const outsideKey = r2Key(ctx, "p-r2-02/outside/obj");

    // Mint a credential scoped to put+get on exactly one prefix.
    const mint = await ctx.fetch({
      service: "cfapi",
      method: "POST",
      path: "/r2/temp-access-credentials",
      body: utf8(JSON.stringify({ bucket: ctx.bucket, prefixes: [allowedPrefix], permissions: ["put", "get"] })),
    });
    ctx.check(mint.status === 200, `temp credential mint succeeds (got ${mint.status})`);
    const minted = asJson(mint);
    const creds: SeamCredentials = {
      keyId: String(minted.keyId),
      secret: String(minted.secret),
      sessionToken: String(minted.sessionToken),
    };

    // In-scope actions must work.
    const body = utf8("scoped-write");
    const putOk = await r2Put(ctx, allowedKey, body, {}, creds);
    ctx.check(putOk.status === 200, `in-scope PUT allowed (got ${putOk.status})`);
    const getOk = await r2Get(ctx, allowedKey, creds);
    ctx.check(
      getOk.status === 200 && Buffer.from(getOk.body).equals(Buffer.from(body)),
      "in-scope GET allowed and byte-exact",
    );

    // Forbidden action inside scope: delete was never granted.
    const delDenied = await r2Delete(ctx, allowedKey, creds);
    ctx.check(delDenied.status === 403, `DELETE with put/get-only credential denied (got ${delDenied.status})`);

    // Forbidden path outside scope, both write and read.
    const putOutside = await r2Put(ctx, outsideKey, utf8("must-not-land"), {}, creds);
    ctx.check(putOutside.status === 403, `PUT outside credential prefix denied (got ${putOutside.status})`);
    const seeded = await r2Put(ctx, outsideKey, utf8("parent-data"));
    ctx.check(seeded.status === 200, `parent credential seeds outside object (got ${seeded.status})`);
    const getOutside = await r2Get(ctx, outsideKey, creds);
    ctx.check(getOutside.status === 403, `GET outside credential prefix denied (got ${getOutside.status})`);

    // Parent revocation: minted credentials must die with the parent.
    const revoke = await ctx.fetch({
      service: "cfapi",
      method: "POST",
      path: "/r2/temp-access-credentials/revoke-parent",
    });
    ctx.check(revoke.status === 200, `parent revocation accepted (got ${revoke.status})`);
    const afterRevoke = await r2Put(ctx, allowedKey, utf8("post-revocation"), {}, creds);
    ctx.check(afterRevoke.status === 403, `minted credential dead after parent revocation (got ${afterRevoke.status})`);
  },
};

// ---------------------------------------------------------------------------
// P-R2-03 — Bucket Locks.
// ---------------------------------------------------------------------------

const pR2_03: ProbeImpl = {
  id: "P-R2-03",
  expected:
    "locked mutations fail as documented; lock policy machine-verifiable; " +
    "runtime principals cannot alter policy",
  async run(ctx: ProbeContext): Promise<void> {
    const lockedPrefix = `probes/${ctx.runNonce}/p-r2-03/locked/`;
    const lockedKey = `/${ctx.bucket}/${lockedPrefix}a`;
    const freeKey = r2Key(ctx, "p-r2-03/free/b");
    const rules = [{ prefix: lockedPrefix, allowOverwrite: false, allowDelete: false }];

    // Seed an object, then lock its prefix from the admin plane.
    const seed = await r2Put(ctx, lockedKey, utf8("locked-object-v1"));
    ctx.check(seed.status === 200, `seed object created (got ${seed.status})`);
    const lockSet = await ctx.fetch({
      service: "cfapi",
      method: "PUT",
      path: `/r2/buckets/${ctx.bucket}/lock`,
      headers: { "x-cf-authz": "admin" },
      body: utf8(JSON.stringify({ rules })),
    });
    ctx.check(lockSet.status === 200, `admin lock configuration accepted (got ${lockSet.status})`);

    // Locked mutations must fail; the bytes must survive.
    const overwrite = await r2Put(ctx, lockedKey, utf8("must-not-overwrite"));
    ctx.check(overwrite.status === 403, `overwrite of locked object denied (got ${overwrite.status})`);
    const del = await r2Delete(ctx, lockedKey);
    ctx.check(del.status === 403, `delete of locked object denied (got ${del.status})`);
    const survived = await r2Get(ctx, lockedKey);
    ctx.check(
      survived.status === 200 && Buffer.from(survived.body).equals(Buffer.from(utf8("locked-object-v1"))),
      "locked bytes unchanged after denied mutations",
    );

    // New objects under the locked prefix may be created, then are locked.
    const newUnder = await r2Put(ctx, `/${ctx.bucket}/${lockedPrefix}new`, utf8("new-under-lock"));
    ctx.check(newUnder.status === 200, `new object under locked prefix creatable (got ${newUnder.status})`);
    const delNew = await r2Delete(ctx, `/${ctx.bucket}/${lockedPrefix}new`);
    ctx.check(delNew.status === 403, `new object immediately covered by lock (got ${delNew.status})`);

    // Outside the rule the bucket behaves normally.
    await r2Put(ctx, freeKey, utf8("free"));
    const delFree = await r2Delete(ctx, freeKey);
    ctx.check(delFree.status === 204, `delete outside lock rules allowed (got ${delFree.status})`);

    // Policy is continuously machine-verifiable...
    const policy = await ctx.fetch({ service: "cfapi", method: "GET", path: `/r2/buckets/${ctx.bucket}/lock` });
    const gotRules = JSON.stringify((asJson(policy) as { rules?: unknown }).rules);
    ctx.check(
      policy.status === 200 && gotRules === JSON.stringify(rules),
      "retrieved lock policy is exactly the configured policy",
    );

    // ...and runtime principals cannot mutate it.
    const runtimeMutate = await ctx.fetch({
      service: "cfapi",
      method: "PUT",
      path: `/r2/buckets/${ctx.bucket}/lock`,
      body: utf8(JSON.stringify({ rules: [] })),
    });
    ctx.check(runtimeMutate.status === 403, `runtime principal lock mutation denied (got ${runtimeMutate.status})`);
    const policy2 = await ctx.fetch({ service: "cfapi", method: "GET", path: `/r2/buckets/${ctx.bucket}/lock` });
    ctx.check(
      JSON.stringify((asJson(policy2) as { rules?: unknown }).rules) === JSON.stringify(rules),
      "lock policy unchanged after denied mutation attempt",
    );
  },
};

// ---------------------------------------------------------------------------
// P-R2-04 — Checksums and multipart identity.
// ---------------------------------------------------------------------------

const pR2_04: ProbeImpl = {
  id: "P-R2-04",
  expected:
    "checksum headers verified and echoed, never substituting the application " +
    "SHA-256; identical-byte part retry idempotent; changed bytes require a " +
    "new UploadAttemptId; completed bytes match the application manifest",
  async run(ctx: ProbeContext): Promise<void> {
    // --- single-part checksum echo ---
    const singleKey = r2Key(ctx, "p-r2-04/single");
    const single = utf8("p-r2-04 single-part body");
    const checksum = b64sha256(single);
    const put = await r2Put(ctx, singleKey, single, { "x-amz-checksum-sha256": checksum });
    ctx.check(put.status === 200, `checksummed PUT accepted (got ${put.status})`);
    const rd = await r2Get(ctx, singleKey);
    ctx.check(
      rd.headers["x-amz-checksum-sha256"] === checksum,
      "provider echoes the stored sha256 checksum on read",
    );
    // The application SHA-256 is computed over the bytes we hold — the
    // provider's echo corroborates it but never replaces it.
    ctx.check(
      rd.status === 200 && sha256hex(rd.body) === sha256hex(single),
      "application SHA-256 over readback matches the manifest value",
    );

    // --- multipart attempt identity ---
    const mpKey = r2Key(ctx, "p-r2-04/multipart");
    // Real R2 requires >=5MiB for non-final parts; the mock keeps runs fast.
    const partSize = ctx.mode === "mock" ? 1024 : 5 * 1024 * 1024;
    const part1v1 = patternBytes("part-one.", partSize);
    const part1v2 = patternBytes("PART-ONE!", partSize); // changed bytes, same size
    const part2 = patternBytes("part-two.", 512);

    const create = await ctx.fetch({ service: "r2", method: "POST", path: `${mpKey}?uploads` });
    ctx.check(create.status === 200, `multipart create accepted (got ${create.status})`);
    // Mock returns JSON {uploadId}; real R2 returns XML — extract either way.
    const createText = new TextDecoder().decode(create.body);
    const uploadId =
      ctx.mode === "mock"
        ? String(asJson(create).uploadId)
        : (/<UploadId>([^<]+)<\/UploadId>/.exec(createText)?.[1] ?? "");
    ctx.check(uploadId.length > 0, "uploadId extracted");

    const putPart = (n: number, bytes: Uint8Array, attemptId: string) =>
      ctx.fetch({
        service: "r2",
        method: "PUT",
        path: `${mpKey}?uploadId=${encodeURIComponent(uploadId)}&partNumber=${n}`,
        headers: { "x-upload-attempt-id": attemptId },
        body: bytes,
      });

    const p1 = await putPart(1, part1v1, "attempt-1");
    ctx.check(p1.status === 200, `part 1 upload accepted (got ${p1.status})`);
    const p1retry = await putPart(1, part1v1, "attempt-1");
    ctx.check(
      p1retry.status === 200 && p1retry.headers["etag"] === p1.headers["etag"],
      "byte-identical retry under the same UploadAttemptId is idempotent",
    );

    // Changed bytes under the SAME attempt id: the platform contract makes
    // the ADAPTER refuse this (attempt corruption). The mock enforces it;
    // raw R2 does not, which is recorded as evidence for why the adapter
    // must gate on UploadAttemptId.
    const p1changed = await putPart(1, part1v2, "attempt-1");
    if (ctx.mode === "mock") {
      ctx.check(
        p1changed.status === 409,
        `changed bytes under same UploadAttemptId refused (got ${p1changed.status})`,
      );
    } else {
      ctx.note(
        `raw R2 response to changed-byte same-attempt retry: ${p1changed.status} — ` +
          "adapter-level UploadAttemptId gate is mandatory (see mock enforcement)",
      );
    }

    // Replacement is legal under a NEW attempt id.
    const p1v2 = await putPart(1, part1v2, "attempt-2");
    ctx.check(p1v2.status === 200, `changed bytes under new UploadAttemptId accepted (got ${p1v2.status})`);
    const p2 = await putPart(2, part2, "attempt-1");
    ctx.check(p2.status === 200, `part 2 upload accepted (got ${p2.status})`);

    const completeXml =
      "<CompleteMultipartUpload>" +
      `<Part><PartNumber>1</PartNumber><ETag>${p1v2.headers["etag"] ?? ""}</ETag></Part>` +
      `<Part><PartNumber>2</PartNumber><ETag>${p2.headers["etag"] ?? ""}</ETag></Part>` +
      "</CompleteMultipartUpload>";
    const complete = await ctx.fetch({
      service: "r2",
      method: "POST",
      path: `${mpKey}?uploadId=${encodeURIComponent(uploadId)}`,
      body: utf8(completeXml),
    });
    ctx.check(complete.status === 200, `multipart completion accepted (got ${complete.status})`);

    // Final bytes must equal the application manifest: part1v2 + part2.
    const manifestSha = sha256hex(Buffer.concat([Buffer.from(part1v2), Buffer.from(part2)]));
    const final = await r2Get(ctx, mpKey);
    ctx.check(
      final.status === 200 && sha256hex(final.body) === manifestSha,
      "completed object application SHA-256 matches the part manifest",
    );

    // Abort: an abandoned upload is dead, not silently completable.
    const create2 = await ctx.fetch({ service: "r2", method: "POST", path: `${mpKey}-abort?uploads` });
    const abortText = new TextDecoder().decode(create2.body);
    const abortId =
      ctx.mode === "mock"
        ? String(asJson(create2).uploadId)
        : (/<UploadId>([^<]+)<\/UploadId>/.exec(abortText)?.[1] ?? "");
    const abort = await ctx.fetch({
      service: "r2",
      method: "DELETE",
      path: `${mpKey}-abort?uploadId=${encodeURIComponent(abortId)}`,
    });
    ctx.check(abort.status === 204, `multipart abort accepted (got ${abort.status})`);
    const afterAbort = await ctx.fetch({
      service: "r2",
      method: "PUT",
      path: `${mpKey}-abort?uploadId=${encodeURIComponent(abortId)}&partNumber=1`,
      headers: { "x-upload-attempt-id": "attempt-1" },
      body: utf8("late"),
    });
    ctx.check(afterAbort.status === 404, `part upload after abort refused (got ${afterAbort.status})`);
  },
};

// ---------------------------------------------------------------------------
// P-R2-05 — Consistency and same-key pressure.
// ---------------------------------------------------------------------------

const pR2_05: ProbeImpl = {
  id: "P-R2-05",
  expected:
    "read-after-write consistent on the S3 endpoint; concurrent same-key " +
    "writers resolve by completion order to one winner; 429 pressure is " +
    "bounded, retried with bounded backoff, and never an incorrect success",
  async run(ctx: ProbeContext): Promise<void> {
    // --- read-after-write on the S3 endpoint (no CDN involved) ---
    const rawKey = r2Key(ctx, "p-r2-05/raw");
    const rawBody = utf8("read-after-write-body");
    const put = await r2Put(ctx, rawKey, rawBody);
    ctx.check(put.status === 200, `write accepted (got ${put.status})`);
    const rd = await r2Get(ctx, rawKey);
    ctx.check(
      rd.status === 200 && Buffer.from(rd.body).equals(Buffer.from(rawBody)),
      "immediate readback returns the committed bytes (read-after-write)",
    );

    // --- concurrent same-key writers under deliberate rate pressure ---
    const key = r2Key(ctx, "p-r2-05/pressure");
    const N = 8;
    const bodies = Array.from({ length: N }, (_, i) => utf8(`writer-${i}`));
    const burst = await Promise.all(
      bodies.map((b) => r2Put(ctx, key, b, { "x-mock-rate-limited": "1" })),
    );
    ctx.check(
      burst.every((r) => r.status === 200 || r.status === 429),
      `every burst response is exactly 200 or 429 (got ${burst.map((r) => r.status).join(",")})`,
    );
    const accepted = burst
      .map((r, i) => ({ r, i }))
      .filter(({ r }) => r.status === 200);
    const rejected = burst
      .map((r, i) => ({ r, i }))
      .filter(({ r }) => r.status === 429);
    ctx.check(accepted.length >= 1, "at least one burst writer is accepted");
    if (ctx.mode === "mock") {
      // Deterministic fake: 4 writes per key per window.
      ctx.check(rejected.length === N - 4, `mock rate limit sheds exactly ${N - 4} writers (got ${rejected.length})`);
    }

    // Overload must never create an incorrect success: the visible bytes
    // must belong to a writer that received 200 — never to a 429'd writer.
    const mid = await r2Get(ctx, key);
    const midBody = Buffer.from(mid.body);
    ctx.check(
      accepted.some(({ i }) => midBody.equals(Buffer.from(bodies[i]))),
      "visible bytes after burst belong to an acknowledged (200) writer",
    );
    if (ctx.mode === "mock") {
      // Completion order: the winner is the accepted write that COMMITTED
      // last (highest commit sequence), not merely the last issued.
      const maxSeq = Math.max(...accepted.map(({ r }) => Number(r.headers["x-mock-commit-seq"])));
      const lastCommitted = accepted.find(({ r }) => Number(r.headers["x-mock-commit-seq"]) === maxSeq);
      ctx.check(
        lastCommitted !== undefined && midBody.equals(Buffer.from(bodies[lastCommitted.i])),
        "winner is exactly the last-completed acknowledged write",
      );
    }

    // --- bounded-backoff retry of the shed writers ---
    const MAX_ATTEMPTS = 3; // bound; exceeding it is a probe failure
    let outstanding = rejected.map(({ i }) => i);
    let attempts = 0;
    while (outstanding.length > 0 && attempts < MAX_ATTEMPTS) {
      attempts += 1;
      if (ctx.mode === "mock") {
        // Virtual time: backoff = advancing the rate-limit window.
        await ctx.fetch({ service: "r2", method: "POST", path: "/__mock/advance-window" });
      } else {
        // Real backoff: capped exponential, no unbounded spin.
        await new Promise((r) => setTimeout(r, Math.min(200 * 2 ** attempts, 1000)));
      }
      const retries = await Promise.all(
        outstanding.map((i) => r2Put(ctx, key, bodies[i], { "x-mock-rate-limited": "1" })),
      );
      outstanding = outstanding.filter((_, k) => retries[k].status !== 200);
      ctx.check(
        retries.every((r) => r.status === 200 || r.status === 429),
        `retry round ${attempts} responses are exactly 200 or 429`,
      );
    }
    ctx.check(
      outstanding.length === 0,
      `all shed writers complete within the backoff bound of ${MAX_ATTEMPTS} attempts (used ${attempts})`,
    );
    ctx.check(attempts <= MAX_ATTEMPTS, "backoff attempts stayed within the bound");
    if (ctx.mode === "mock") {
      // Deterministic fake: one extra window admits all shed writers.
      ctx.check(attempts === 1, `mock retries complete in exactly one bounded round (got ${attempts})`);
    }

    // Final winner must still be an acknowledged write.
    const finalRead = await r2Get(ctx, key);
    ctx.check(
      finalRead.status === 200 && /^writer-\d$/.test(new TextDecoder().decode(finalRead.body)),
      "final visible bytes are a complete single writer's bytes",
    );
  },
};

export const R2_PROBES: ReadonlyArray<ProbeImpl> = [pR2_01, pR2_02, pR2_03, pR2_04, pR2_05];
