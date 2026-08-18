/*
 * P-R2-01 .. P-R2-05 (contract/typedb-r2-v16-platform-probes.md).
 *
 * All five probes run identically against the real R2 S3 API (SigV4,
 * region "auto") and against the deterministic mock provider. Every
 * assertion is declared up front with the modes it is required in
 * (round-3 P-05): steps that need mock-only controllability (forced
 * timeout-after-commit, virtual rate-limit windows, application-layer
 * UploadAttemptId enforcement) declare required_in:["mock"], so a real
 * run shows them explicitly uncovered instead of silently noting them.
 *
 * The Cloudflare account-API calls use the CURRENT official wire shapes
 * (round-3 P-02), typed and runtime-validated in cfapi-dto.ts; the mock
 * serves exactly those shapes.
 */

import type { ProbeContext, ProbeImpl } from "./probe.ts";
import { asJson, BOTH, MOCK_ONLY, patternBytes, r2Delete, r2Get, r2Key, r2Put } from "./probe.ts";
import type { SeamCredentials } from "./provider.ts";
import { sha256hex, utf8 } from "./provider.ts";
import { validateBucketLockGetResponse, validateTempCredentialsResponse } from "./cfapi-dto.ts";
import type { BucketLockRule } from "./cfapi-dto.ts";

function b64sha256(body: Uint8Array): string {
  return Buffer.from(sha256hex(body), "hex").toString("base64");
}

/** Key-order-independent canonical form of a lock-rule list. */
function canonicalRules(rules: ReadonlyArray<BucketLockRule>): string {
  return JSON.stringify(
    rules.map((r) => ({
      id: r.id,
      enabled: r.enabled,
      prefix: r.prefix ?? null,
      condition_type: r.condition.type,
      condition_max_age: r.condition.type === "Age" ? r.condition.maxAgeSeconds : null,
      condition_date: r.condition.type === "Date" ? r.condition.date : null,
    })),
  );
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
  assertions: [
    { id: "create-if-absent-succeeds", title: "initial PUT if-none-match:* succeeds", required_in: BOTH },
    { id: "duplicate-create-412", title: "duplicate conditional create is 412, not a downgrade", required_in: BOTH },
    { id: "if-match-current-succeeds", title: "PUT if-match with current etag succeeds", required_in: BOTH },
    { id: "if-match-wrong-412", title: "PUT if-match with wrong expected version is 412", required_in: BOTH },
    { id: "readback-200", title: "readback GET succeeds", required_in: BOTH },
    { id: "readback-byte-exact", title: "readback is byte- and sha256-exact", required_in: BOTH },
    { id: "race-single-winner", title: "exactly one concurrent conditional writer wins", required_in: BOTH },
    { id: "race-winner-bytes", title: "stored bytes are exactly the single winner's bytes", required_in: BOTH },
    { id: "ambiguous-observed", title: "client observes network failure after server commit", required_in: MOCK_ONLY },
    { id: "ambiguous-retry-classified", title: "conditional retry classifies ambiguity as already-committed", required_in: MOCK_ONLY },
    { id: "ambiguous-committed-once", title: "readback proves the ambiguous operation committed exactly once", required_in: MOCK_ONLY },
  ],
  async run(ctx: ProbeContext): Promise<void> {
    // --- create-if-absent, then duplicate conditional create ---
    const key = r2Key(ctx, "p-r2-01/cond");
    const payload = utf8("p-r2-01 conditional body");
    const put1 = await r2Put(ctx, key, payload, { "if-none-match": "*" });
    ctx.check("create-if-absent-succeeds", put1.status === 200, `got ${put1.status}`);
    const put2 = await r2Put(ctx, key, utf8("different"), { "if-none-match": "*" });
    ctx.check("duplicate-create-412", put2.status === 412, `got ${put2.status}`);

    // --- if-match: correct and wrong expected version ---
    const etag = put1.headers["etag"] ?? "";
    const put3 = await r2Put(ctx, key, utf8("updated-via-if-match"), { "if-match": etag });
    ctx.check("if-match-current-succeeds", put3.status === 200, `got ${put3.status}`);
    const put4 = await r2Put(ctx, key, utf8("must-not-land"), { "if-match": '"bogus-version"' });
    ctx.check("if-match-wrong-412", put4.status === 412, `got ${put4.status}`);

    // --- byte/hash-exact readback ---
    const rd = await r2Get(ctx, key);
    const expectBytes = utf8("updated-via-if-match");
    ctx.check("readback-200", rd.status === 200, `got ${rd.status}`);
    ctx.check(
      "readback-byte-exact",
      Buffer.from(rd.body).equals(Buffer.from(expectBytes)) && sha256hex(rd.body) === sha256hex(expectBytes),
      "compared bytes and sha256",
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
      "race-single-winner",
      winners.length === 1 && losers.length === 1,
      `statuses ${ra.status},${rb.status}`,
    );
    const raceRead = await r2Get(ctx, raceKey);
    const winnerBody = ra.status === 200 ? bodyA : bodyB;
    ctx.check(
      "race-winner-bytes",
      raceRead.status === 200 && Buffer.from(raceRead.body).equals(Buffer.from(winnerBody)),
      "readback compared against the acknowledged winner",
    );

    // --- ambiguity: timeout after server commit (mock-controlled) ---
    if (ctx.mode === "mock") {
      const ambKey = r2Key(ctx, "p-r2-01/ambiguous");
      const ambBody = utf8("ambiguous-commit-body");
      const amb = await r2Put(ctx, ambKey, ambBody, {
        "if-none-match": "*",
        "x-mock-simulate": "commit-then-timeout",
      });
      ctx.check("ambiguous-observed", amb.status === 599, `got ${amb.status}`);
      // Resolution of the SAME operation, still conditional — never an
      // unconditional retry that would grant duplicate authority.
      const retry = await r2Put(ctx, ambKey, ambBody, { "if-none-match": "*" });
      ctx.check("ambiguous-retry-classified", retry.status === 412, `got ${retry.status}`);
      const ambRead = await r2Get(ctx, ambKey);
      ctx.check(
        "ambiguous-committed-once",
        ambRead.status === 200 && Buffer.from(ambRead.body).equals(Buffer.from(ambBody)),
        "readback matches the single committed body",
      );
    }
  },
};

// ---------------------------------------------------------------------------
// P-R2-02 — Temporary credential action and path scope.
// ---------------------------------------------------------------------------

const pR2_02: ProbeImpl = {
  id: "P-R2-02",
  expected:
    "temp credentials mint via the official DTO (parentAccessKeyId, singular " +
    "permission enum, ttlSeconds, result envelope); read-write scope works only " +
    "inside its prefix; read-only cannot write; malformed mint requests are " +
    "refused; the permission presets cannot express put+get-without-delete " +
    "(no-delete must come from bucket locks or a mediating gateway)",
  assertions: [
    { id: "mint-malformed-refused", title: "mint without parentAccessKeyId/singular permission is refused", required_in: BOTH },
    { id: "mint-envelope-valid", title: "mint response validates against the official result envelope", required_in: BOTH },
    { id: "rw-put-in-scope", title: "object-read-write PUT inside the prefix allowed", required_in: BOTH },
    { id: "rw-get-in-scope", title: "object-read-write GET inside the prefix allowed and byte-exact", required_in: BOTH },
    { id: "rw-put-outside-denied", title: "PUT outside credential prefix denied", required_in: BOTH },
    { id: "seed-outside-with-parent", title: "parent credential seeds an outside object", required_in: BOTH },
    { id: "rw-get-outside-denied", title: "GET outside credential prefix denied", required_in: BOTH },
    { id: "ro-envelope-valid", title: "read-only mint response validates", required_in: BOTH },
    { id: "ro-get-allowed", title: "object-read-only GET inside the prefix allowed", required_in: BOTH },
    { id: "ro-put-denied", title: "object-read-only PUT denied (forbidden action)", required_in: BOTH },
    {
      id: "rw-delete-in-scope-allowed",
      title:
        "object-read-write DELETE inside the prefix is ALLOWED by the platform — " +
        "the preset enum cannot express put+get-without-delete, so no-delete must " +
        "be enforced above the credential layer (bucket locks / gateway)",
      required_in: BOTH,
    },
  ],
  async run(ctx: ProbeContext): Promise<void> {
    const allowedPrefix = `probes/${ctx.runNonce}/p-r2-02/allowed/`;
    const allowedKey = `/${ctx.bucket}/${allowedPrefix}obj`;
    const outsideKey = r2Key(ctx, "p-r2-02/outside/obj");

    const mintBody = (permission: string): Uint8Array =>
      utf8(
        JSON.stringify({
          bucket: ctx.bucket,
          parentAccessKeyId: ctx.parentAccessKeyId,
          permission,
          ttlSeconds: 900,
          prefixes: [allowedPrefix],
        }),
      );

    // Malformed mint (the PRE-FIX wire shape): plural permissions array and
    // no parentAccessKeyId. The platform must refuse it — this pins the
    // probe to the current API and would catch a silent schema rollback.
    const badMint = await ctx.fetch({
      service: "cfapi",
      method: "POST",
      path: "/r2/temp-access-credentials",
      body: utf8(JSON.stringify({ bucket: ctx.bucket, prefixes: [allowedPrefix], permissions: ["put", "get"] })),
    });
    ctx.check("mint-malformed-refused", badMint.status === 400, `got ${badMint.status}`);

    // Mint an object-read-write credential scoped to exactly one prefix.
    const mint = await ctx.fetch({
      service: "cfapi",
      method: "POST",
      path: "/r2/temp-access-credentials",
      body: mintBody("object-read-write"),
    });
    let creds: SeamCredentials | null = null;
    try {
      const envelope = validateTempCredentialsResponse(asJson(mint));
      creds = {
        keyId: envelope.result.accessKeyId,
        secret: envelope.result.secretAccessKey,
        sessionToken: envelope.result.sessionToken,
      };
      ctx.check("mint-envelope-valid", mint.status === 200 && envelope.success, `status ${mint.status}`);
    } catch (err) {
      ctx.check("mint-envelope-valid", false, `DTO validation failed: ${err instanceof Error ? err.message : String(err)}`);
      return; // no credential => the scope assertions cannot run; they stay unsatisfied => FAIL
    }

    // In-scope actions must work.
    const body = utf8("scoped-write");
    const putOk = await r2Put(ctx, allowedKey, body, {}, creds);
    ctx.check("rw-put-in-scope", putOk.status === 200, `got ${putOk.status}`);
    const getOk = await r2Get(ctx, allowedKey, creds);
    ctx.check(
      "rw-get-in-scope",
      getOk.status === 200 && Buffer.from(getOk.body).equals(Buffer.from(body)),
      `got ${getOk.status}`,
    );

    // Forbidden path outside scope, both write and read.
    const putOutside = await r2Put(ctx, outsideKey, utf8("must-not-land"), {}, creds);
    ctx.check("rw-put-outside-denied", putOutside.status === 403, `got ${putOutside.status}`);
    const seeded = await r2Put(ctx, outsideKey, utf8("parent-data"));
    ctx.check("seed-outside-with-parent", seeded.status === 200, `got ${seeded.status}`);
    const getOutside = await r2Get(ctx, outsideKey, creds);
    ctx.check("rw-get-outside-denied", getOutside.status === 403, `got ${getOutside.status}`);

    // Read-only credential: reads work, writes are the forbidden action.
    const roMint = await ctx.fetch({
      service: "cfapi",
      method: "POST",
      path: "/r2/temp-access-credentials",
      body: mintBody("object-read-only"),
    });
    let roCreds: SeamCredentials | null = null;
    try {
      const envelope = validateTempCredentialsResponse(asJson(roMint));
      roCreds = {
        keyId: envelope.result.accessKeyId,
        secret: envelope.result.secretAccessKey,
        sessionToken: envelope.result.sessionToken,
      };
      ctx.check("ro-envelope-valid", roMint.status === 200 && envelope.success, `status ${roMint.status}`);
    } catch (err) {
      ctx.check("ro-envelope-valid", false, `DTO validation failed: ${err instanceof Error ? err.message : String(err)}`);
      return;
    }
    const roGet = await r2Get(ctx, allowedKey, roCreds);
    ctx.check("ro-get-allowed", roGet.status === 200, `got ${roGet.status}`);
    const roPut = await r2Put(ctx, allowedKey, utf8("must-not-land-ro"), {}, roCreds);
    ctx.check("ro-put-denied", roPut.status === 403, `got ${roPut.status}`);

    // The preset enum has NO put+get-without-delete member: an
    // object-read-write credential CAN delete inside its prefix. This is
    // asserted (not noted) so the record that "exact Put+Get/no Delete
    // needs enforcement above the credential layer" is machine-checked.
    const delAllowed = await r2Delete(ctx, allowedKey, creds);
    ctx.check("rw-delete-in-scope-allowed", delAllowed.status === 204, `got ${delAllowed.status}`);
  },
};

// ---------------------------------------------------------------------------
// P-R2-03 — Bucket Locks.
// ---------------------------------------------------------------------------

const pR2_03: ProbeImpl = {
  id: "P-R2-03",
  expected:
    "lock rules use the official {id, enabled, prefix, condition} shape; " +
    "locked mutations fail as documented; lock policy machine-verifiable via " +
    "the result envelope; the runtime principal cannot alter policy",
  assertions: [
    { id: "seed-created", title: "seed object created before the lock", required_in: BOTH },
    { id: "legacy-rule-shape-refused", title: "the pre-fix {prefix,allowOverwrite,allowDelete} rule shape is refused", required_in: BOTH },
    { id: "admin-lock-accepted", title: "admin-principal lock configuration accepted", required_in: BOTH },
    { id: "locked-overwrite-denied", title: "overwrite of locked object denied", required_in: BOTH },
    { id: "locked-delete-denied", title: "delete of locked object denied", required_in: BOTH },
    { id: "locked-bytes-survive", title: "locked bytes unchanged after denied mutations", required_in: BOTH },
    { id: "new-under-lock-creatable", title: "new object under locked prefix creatable", required_in: BOTH },
    { id: "new-under-lock-covered", title: "new object immediately covered by the lock", required_in: BOTH },
    { id: "outside-rules-normal", title: "delete outside lock rules allowed", required_in: BOTH },
    { id: "policy-readback-exact", title: "retrieved lock policy (result envelope) is exactly the configured policy", required_in: BOTH },
    { id: "runtime-mutation-denied", title: "runtime principal lock mutation denied", required_in: BOTH },
    { id: "policy-unchanged-after-denial", title: "lock policy unchanged after denied mutation attempt", required_in: BOTH },
  ],
  async run(ctx: ProbeContext): Promise<void> {
    const lockedPrefix = `probes/${ctx.runNonce}/p-r2-03/locked/`;
    const lockedKey = `/${ctx.bucket}/${lockedPrefix}a`;
    const freeKey = r2Key(ctx, "p-r2-03/free/b");
    // Official rule shape: {id, enabled, prefix, condition} — condition
    // Indefinite locks matching objects until the rule is removed.
    const rules: BucketLockRule[] = [
      {
        id: `probe-lock-${ctx.runNonce}`,
        enabled: true,
        prefix: lockedPrefix,
        condition: { type: "Indefinite" },
      },
    ];

    // Seed an object, then lock its prefix from the admin plane.
    const seed = await r2Put(ctx, lockedKey, utf8("locked-object-v1"));
    ctx.check("seed-created", seed.status === 200, `got ${seed.status}`);

    // The PRE-FIX rule shape must be refused — catches schema drift.
    const legacySet = await ctx.fetch({
      service: "cfapi",
      method: "PUT",
      path: `/r2/buckets/${ctx.bucket}/lock`,
      principal: "admin",
      body: utf8(JSON.stringify({ rules: [{ prefix: lockedPrefix, allowOverwrite: false, allowDelete: false }] })),
    });
    ctx.check("legacy-rule-shape-refused", legacySet.status === 400, `got ${legacySet.status}`);

    const lockSet = await ctx.fetch({
      service: "cfapi",
      method: "PUT",
      path: `/r2/buckets/${ctx.bucket}/lock`,
      principal: "admin",
      body: utf8(JSON.stringify({ rules })),
    });
    ctx.check("admin-lock-accepted", lockSet.status === 200, `got ${lockSet.status}`);

    // Locked mutations must fail; the bytes must survive.
    const overwrite = await r2Put(ctx, lockedKey, utf8("must-not-overwrite"));
    ctx.check("locked-overwrite-denied", overwrite.status === 403, `got ${overwrite.status}`);
    const del = await r2Delete(ctx, lockedKey);
    ctx.check("locked-delete-denied", del.status === 403, `got ${del.status}`);
    const survived = await r2Get(ctx, lockedKey);
    ctx.check(
      "locked-bytes-survive",
      survived.status === 200 && Buffer.from(survived.body).equals(Buffer.from(utf8("locked-object-v1"))),
      `got ${survived.status}`,
    );

    // New objects under the locked prefix may be created, then are locked.
    const newUnder = await r2Put(ctx, `/${ctx.bucket}/${lockedPrefix}new`, utf8("new-under-lock"));
    ctx.check("new-under-lock-creatable", newUnder.status === 200, `got ${newUnder.status}`);
    const delNew = await r2Delete(ctx, `/${ctx.bucket}/${lockedPrefix}new`);
    ctx.check("new-under-lock-covered", delNew.status === 403, `got ${delNew.status}`);

    // Outside the rule the bucket behaves normally.
    await r2Put(ctx, freeKey, utf8("free"));
    const delFree = await r2Delete(ctx, freeKey);
    ctx.check("outside-rules-normal", delFree.status === 204, `got ${delFree.status}`);

    // Policy is continuously machine-verifiable via the result envelope...
    const policy = await ctx.fetch({ service: "cfapi", method: "GET", path: `/r2/buckets/${ctx.bucket}/lock` });
    try {
      const envelope = validateBucketLockGetResponse(asJson(policy));
      ctx.check(
        "policy-readback-exact",
        policy.status === 200 && canonicalRules(envelope.result.rules) === canonicalRules(rules),
        `status ${policy.status}`,
      );
    } catch (err) {
      ctx.check("policy-readback-exact", false, `DTO validation failed: ${err instanceof Error ? err.message : String(err)}`);
    }

    // ...and the RUNTIME principal (a genuinely separate credential in
    // real mode, not a spoofable header) cannot mutate it.
    const runtimeMutate = await ctx.fetch({
      service: "cfapi",
      method: "PUT",
      path: `/r2/buckets/${ctx.bucket}/lock`,
      principal: "runtime",
      body: utf8(JSON.stringify({ rules: [] })),
    });
    ctx.check("runtime-mutation-denied", runtimeMutate.status === 403, `got ${runtimeMutate.status}`);
    const policy2 = await ctx.fetch({ service: "cfapi", method: "GET", path: `/r2/buckets/${ctx.bucket}/lock` });
    try {
      const envelope2 = validateBucketLockGetResponse(asJson(policy2));
      ctx.check(
        "policy-unchanged-after-denial",
        canonicalRules(envelope2.result.rules) === canonicalRules(rules),
        "policy re-read compared",
      );
    } catch (err) {
      ctx.check("policy-unchanged-after-denial", false, `DTO validation failed: ${err instanceof Error ? err.message : String(err)}`);
    }
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
  assertions: [
    { id: "checksummed-put-accepted", title: "checksummed PUT accepted", required_in: BOTH },
    { id: "checksum-echoed", title: "provider echoes the stored sha256 checksum on read", required_in: BOTH },
    { id: "app-sha256-authoritative", title: "application SHA-256 over readback matches the manifest value", required_in: BOTH },
    { id: "mp-create-accepted", title: "multipart create accepted", required_in: BOTH },
    { id: "mp-upload-id", title: "uploadId extracted", required_in: BOTH },
    { id: "mp-part1-accepted", title: "part 1 upload accepted", required_in: BOTH },
    { id: "mp-identical-retry-idempotent", title: "byte-identical retry under the same UploadAttemptId is idempotent", required_in: BOTH },
    { id: "mp-changed-bytes-refused", title: "changed bytes under same UploadAttemptId refused (adapter contract)", required_in: MOCK_ONLY },
    { id: "mp-new-attempt-accepted", title: "changed bytes under a NEW UploadAttemptId accepted", required_in: BOTH },
    { id: "mp-part2-accepted", title: "part 2 upload accepted", required_in: BOTH },
    { id: "mp-complete-accepted", title: "multipart completion accepted", required_in: BOTH },
    { id: "mp-final-bytes-match-manifest", title: "completed object application SHA-256 matches the part manifest", required_in: BOTH },
    { id: "mp-abort-accepted", title: "multipart abort accepted", required_in: BOTH },
    { id: "mp-after-abort-refused", title: "part upload after abort refused", required_in: BOTH },
  ],
  async run(ctx: ProbeContext): Promise<void> {
    // --- single-part checksum echo ---
    const singleKey = r2Key(ctx, "p-r2-04/single");
    const single = utf8("p-r2-04 single-part body");
    const checksum = b64sha256(single);
    const put = await r2Put(ctx, singleKey, single, { "x-amz-checksum-sha256": checksum });
    ctx.check("checksummed-put-accepted", put.status === 200, `got ${put.status}`);
    const rd = await r2Get(ctx, singleKey);
    ctx.check("checksum-echoed", rd.headers["x-amz-checksum-sha256"] === checksum, "echo compared");
    // The application SHA-256 is computed over the bytes we hold — the
    // provider's echo corroborates it but never replaces it.
    ctx.check(
      "app-sha256-authoritative",
      rd.status === 200 && sha256hex(rd.body) === sha256hex(single),
      `got ${rd.status}`,
    );

    // --- multipart attempt identity ---
    const mpKey = r2Key(ctx, "p-r2-04/multipart");
    // Real R2 requires >=5MiB for non-final parts; the mock keeps runs fast.
    const partSize = ctx.mode === "mock" ? 1024 : 5 * 1024 * 1024;
    const part1v1 = patternBytes("part-one.", partSize);
    const part1v2 = patternBytes("PART-ONE!", partSize); // changed bytes, same size
    const part2 = patternBytes("part-two.", 512);

    const create = await ctx.fetch({ service: "r2", method: "POST", path: `${mpKey}?uploads` });
    ctx.check("mp-create-accepted", create.status === 200, `got ${create.status}`);
    // Mock returns JSON {uploadId}; real R2 returns XML — extract either way.
    const createText = new TextDecoder().decode(create.body);
    const uploadId =
      ctx.mode === "mock"
        ? String(asJson(create).uploadId)
        : (/<UploadId>([^<]+)<\/UploadId>/.exec(createText)?.[1] ?? "");
    ctx.check("mp-upload-id", uploadId.length > 0, `length ${uploadId.length}`);

    const putPart = (n: number, bytes: Uint8Array, attemptId: string) =>
      ctx.fetch({
        service: "r2",
        method: "PUT",
        path: `${mpKey}?uploadId=${encodeURIComponent(uploadId)}&partNumber=${n}`,
        headers: { "x-upload-attempt-id": attemptId },
        body: bytes,
      });

    const p1 = await putPart(1, part1v1, "attempt-1");
    ctx.check("mp-part1-accepted", p1.status === 200, `got ${p1.status}`);
    const p1retry = await putPart(1, part1v1, "attempt-1");
    ctx.check(
      "mp-identical-retry-idempotent",
      p1retry.status === 200 && p1retry.headers["etag"] === p1.headers["etag"],
      `got ${p1retry.status}, etag match ${p1retry.headers["etag"] === p1.headers["etag"]}`,
    );

    // Changed bytes under the SAME attempt id: the platform contract makes
    // the ADAPTER refuse this (attempt corruption). The mock enforces it;
    // raw R2 does not, which is recorded as evidence for why the adapter
    // must gate on UploadAttemptId.
    const p1changed = await putPart(1, part1v2, "attempt-1");
    if (ctx.mode === "mock") {
      ctx.check("mp-changed-bytes-refused", p1changed.status === 409, `got ${p1changed.status}`);
    } else {
      ctx.note(
        `raw R2 response to changed-byte same-attempt retry: ${p1changed.status} — ` +
          "adapter-level UploadAttemptId gate is mandatory (see mock enforcement)",
      );
    }

    // Replacement is legal under a NEW attempt id.
    const p1v2 = await putPart(1, part1v2, "attempt-2");
    ctx.check("mp-new-attempt-accepted", p1v2.status === 200, `got ${p1v2.status}`);
    const p2 = await putPart(2, part2, "attempt-1");
    ctx.check("mp-part2-accepted", p2.status === 200, `got ${p2.status}`);

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
    ctx.check("mp-complete-accepted", complete.status === 200, `got ${complete.status}`);

    // Final bytes must equal the application manifest: part1v2 + part2.
    const manifestSha = sha256hex(Buffer.concat([Buffer.from(part1v2), Buffer.from(part2)]));
    const final = await r2Get(ctx, mpKey);
    ctx.check(
      "mp-final-bytes-match-manifest",
      final.status === 200 && sha256hex(final.body) === manifestSha,
      `got ${final.status}`,
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
    ctx.check("mp-abort-accepted", abort.status === 204, `got ${abort.status}`);
    const afterAbort = await ctx.fetch({
      service: "r2",
      method: "PUT",
      path: `${mpKey}-abort?uploadId=${encodeURIComponent(abortId)}&partNumber=1`,
      headers: { "x-upload-attempt-id": "attempt-1" },
      body: utf8("late"),
    });
    ctx.check("mp-after-abort-refused", afterAbort.status === 404, `got ${afterAbort.status}`);
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
  assertions: [
    { id: "write-accepted", title: "write accepted", required_in: BOTH },
    { id: "read-after-write", title: "immediate readback returns the committed bytes", required_in: BOTH },
    { id: "burst-statuses-exact", title: "every burst response is exactly 200 or 429", required_in: BOTH },
    { id: "burst-some-accepted", title: "at least one burst writer is accepted", required_in: BOTH },
    { id: "burst-shed-exact", title: "mock rate limit sheds exactly the excess writers", required_in: MOCK_ONLY },
    { id: "visible-bytes-acknowledged", title: "visible bytes after burst belong to an acknowledged (200) writer", required_in: BOTH },
    { id: "winner-last-committed", title: "winner is exactly the last-completed acknowledged write", required_in: MOCK_ONLY },
    { id: "retry-statuses-exact", title: "every retry-round response is exactly 200 or 429", required_in: BOTH },
    { id: "shed-writers-complete", title: "all shed writers complete within the backoff bound", required_in: BOTH },
    { id: "backoff-bounded", title: "backoff attempts stayed within the bound", required_in: BOTH },
    { id: "mock-single-retry-round", title: "mock retries complete in exactly one bounded round", required_in: MOCK_ONLY },
    { id: "final-winner-complete", title: "final visible bytes are a complete single writer's bytes", required_in: BOTH },
  ],
  async run(ctx: ProbeContext): Promise<void> {
    // --- read-after-write on the S3 endpoint (no CDN involved) ---
    const rawKey = r2Key(ctx, "p-r2-05/raw");
    const rawBody = utf8("read-after-write-body");
    const put = await r2Put(ctx, rawKey, rawBody);
    ctx.check("write-accepted", put.status === 200, `got ${put.status}`);
    const rd = await r2Get(ctx, rawKey);
    ctx.check(
      "read-after-write",
      rd.status === 200 && Buffer.from(rd.body).equals(Buffer.from(rawBody)),
      `got ${rd.status}`,
    );

    // --- concurrent same-key writers under deliberate rate pressure ---
    const key = r2Key(ctx, "p-r2-05/pressure");
    const N = 8;
    const bodies = Array.from({ length: N }, (_, i) => utf8(`writer-${i}`));
    const burst = await Promise.all(
      bodies.map((b) => r2Put(ctx, key, b, { "x-mock-rate-limited": "1" })),
    );
    ctx.check(
      "burst-statuses-exact",
      burst.every((r) => r.status === 200 || r.status === 429),
      `got ${burst.map((r) => r.status).join(",")}`,
    );
    const accepted = burst
      .map((r, i) => ({ r, i }))
      .filter(({ r }) => r.status === 200);
    const rejected = burst
      .map((r, i) => ({ r, i }))
      .filter(({ r }) => r.status === 429);
    ctx.check("burst-some-accepted", accepted.length >= 1, `accepted ${accepted.length}`);
    if (ctx.mode === "mock") {
      // Deterministic fake: 4 writes per key per window.
      ctx.check("burst-shed-exact", rejected.length === N - 4, `shed ${rejected.length}, expected ${N - 4}`);
    }

    // Overload must never create an incorrect success: the visible bytes
    // must belong to a writer that received 200 — never to a 429'd writer.
    const mid = await r2Get(ctx, key);
    const midBody = Buffer.from(mid.body);
    ctx.check(
      "visible-bytes-acknowledged",
      accepted.some(({ i }) => midBody.equals(Buffer.from(bodies[i]))),
      "visible bytes compared against acknowledged writers",
    );
    if (ctx.mode === "mock") {
      // Completion order: the winner is the accepted write that COMMITTED
      // last (highest commit sequence), not merely the last issued.
      const maxSeq = Math.max(...accepted.map(({ r }) => Number(r.headers["x-mock-commit-seq"])));
      const lastCommitted = accepted.find(({ r }) => Number(r.headers["x-mock-commit-seq"]) === maxSeq);
      ctx.check(
        "winner-last-committed",
        lastCommitted !== undefined && midBody.equals(Buffer.from(bodies[lastCommitted.i])),
        "compared against the highest commit sequence",
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
        "retry-statuses-exact",
        retries.every((r) => r.status === 200 || r.status === 429),
        `round ${attempts}: ${retries.map((r) => r.status).join(",")}`,
      );
    }
    ctx.check(
      "shed-writers-complete",
      outstanding.length === 0,
      `bound ${MAX_ATTEMPTS}, used ${attempts}, outstanding ${outstanding.length}`,
    );
    ctx.check("backoff-bounded", attempts <= MAX_ATTEMPTS, `used ${attempts}`);
    if (ctx.mode === "mock") {
      // Deterministic fake: one extra window admits all shed writers.
      ctx.check("mock-single-retry-round", attempts === 1, `got ${attempts}`);
    }

    // Final winner must still be an acknowledged write.
    const finalRead = await r2Get(ctx, key);
    ctx.check(
      "final-winner-complete",
      finalRead.status === 200 && /^writer-\d$/.test(new TextDecoder().decode(finalRead.body)),
      `got ${finalRead.status}`,
    );
  },
};

export const R2_PROBES: ReadonlyArray<ProbeImpl> = [pR2_01, pR2_02, pR2_03, pR2_04, pR2_05];
