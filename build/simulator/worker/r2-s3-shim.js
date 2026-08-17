/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// An S3 façade over a real R2 binding, running on workerd.
//
// # Why this exists alongside MinIO
//
// The two tiers of the simulator test different things, and neither substitutes for the other.
//
// MinIO is a faithful S3 *protocol* implementation: real SigV4, real header handling, real
// error shapes. It proves the `AmazonS3Builder` configuration this project ships is correct —
// region, endpoint style, conditional-put mode — because a mistake there fails against MinIO
// exactly as it would against any S3 service.
//
// What MinIO cannot tell you is how *R2* behaves, because R2 is not MinIO. The behaviour that
// matters is conditional put: SlateDB commits every manifest version with a compare-and-swap,
// and the entire single-writer guarantee rests on that CAS being atomic. `object_store`
// implements it over `If-Match`/`If-None-Match`, and R2 implements those headers with its own
// semantics. This worker routes those headers to R2's native `onlyIf` so the CAS is evaluated
// by R2's implementation rather than a re-implementation of it.
//
// # What is deliberately not implemented
//
// Signature verification. Every request is accepted whatever it carries in `Authorization`.
// That is not laziness about fidelity: signing is precisely what the MinIO tier covers, and
// re-implementing SigV4 here would mean testing this file's understanding of the algorithm
// rather than R2's understanding of conditional writes. Each tier tests the thing it is
// authoritative for.

const XML_HEADER = '<?xml version="1.0" encoding="UTF-8"?>';

function xmlEscape(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function s3Error(code, message, status) {
  const body = `${XML_HEADER}<Error><Code>${code}</Code><Message>${xmlEscape(message)}</Message></Error>`;
  return new Response(body, { status, headers: { "content-type": "application/xml" } });
}

/// R2 quotes etags on the way out of `httpEtag` but not on `etag`; S3 clients expect the quoted
/// form, and `object_store` compares the string it was given verbatim when it later sends an
/// `If-Match`. Normalising in one place keeps a put and the subsequent conditional put agreeing.
function quoteEtag(etag) {
  if (!etag) return undefined;
  return etag.startsWith('"') ? etag : `"${etag}"`;
}

function objectHeaders(object) {
  const headers = new Headers();
  headers.set("etag", quoteEtag(object.httpEtag ?? object.etag));
  headers.set("content-length", String(object.size));
  headers.set("last-modified", new Date(object.uploaded).toUTCString());
  headers.set("accept-ranges", "bytes");
  return headers;
}

/// Translate S3's conditional headers into R2's `onlyIf`.
///
/// `If-None-Match: *` means "create only if absent" and `If-Match: <etag>` means "replace only
/// if unchanged". Together they are exactly the compare-and-swap SlateDB's manifest commit
/// needs, which is why this function is the most load-bearing part of the file.
function conditionFrom(request) {
  const ifNoneMatch = request.headers.get("if-none-match");
  const ifMatch = request.headers.get("if-match");

  if (ifNoneMatch === "*") return { etagDoesNotMatch: "*" };
  if (ifNoneMatch) return { etagDoesNotMatch: ifNoneMatch.replaceAll('"', "") };
  if (ifMatch) return { etagMatches: ifMatch.replaceAll('"', "") };
  return undefined;
}

/// Split `/bucket/some/key` into its bucket and key.
///
/// Path style, because that is how R2 is addressed: the endpoint is account-scoped
/// (`<account>.r2.cloudflarestorage.com`) and the bucket is the first path segment. A
/// virtual-hosted client would arrive here with no bucket in the path at all, so getting this
/// wrong surfaces as every key being prefixed with the bucket name rather than as an error.
function splitPath(pathname) {
  const segments = pathname.split("/").filter((segment) => segment.length > 0);
  if (segments.length === 0) return { bucket: undefined, key: "" };
  return { bucket: segments[0], key: segments.slice(1).map(decodeURIComponent).join("/") };
}

async function handleList(bucket, url) {
  const prefix = url.searchParams.get("prefix") ?? undefined;
  const delimiter = url.searchParams.get("delimiter") ?? undefined;
  const cursor = url.searchParams.get("continuation-token") ?? undefined;
  const maxKeys = Number(url.searchParams.get("max-keys") ?? 1000);

  const listing = await bucket.list({ prefix, delimiter, cursor, limit: Math.min(maxKeys, 1000) });

  const contents = listing.objects
    .map(
      (object) =>
        `<Contents><Key>${xmlEscape(object.key)}</Key>` +
        `<LastModified>${new Date(object.uploaded).toISOString()}</LastModified>` +
        `<ETag>${xmlEscape(quoteEtag(object.httpEtag ?? object.etag))}</ETag>` +
        `<Size>${object.size}</Size>` +
        `<StorageClass>STANDARD</StorageClass></Contents>`,
    )
    .join("");

  const commonPrefixes = (listing.delimitedPrefixes ?? [])
    .map((value) => `<CommonPrefixes><Prefix>${xmlEscape(value)}</Prefix></CommonPrefixes>`)
    .join("");

  const truncated = listing.truncated === true;
  const nextToken = truncated && listing.cursor
    ? `<NextContinuationToken>${xmlEscape(listing.cursor)}</NextContinuationToken>`
    : "";

  const body =
    `${XML_HEADER}<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
    `<Name>bucket</Name>` +
    `<Prefix>${xmlEscape(prefix ?? "")}</Prefix>` +
    `<KeyCount>${listing.objects.length}</KeyCount>` +
    `<MaxKeys>${maxKeys}</MaxKeys>` +
    `<IsTruncated>${truncated}</IsTruncated>` +
    nextToken +
    contents +
    commonPrefixes +
    `</ListBucketResult>`;

  return new Response(body, { status: 200, headers: { "content-type": "application/xml" } });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { bucket: bucketName, key } = splitPath(url.pathname);
    const bucket = env.BUCKET;

    if (!bucketName) return s3Error("NoSuchBucket", "bucket missing from path", 404);

    // A GET at the bucket root, or one carrying list parameters, is a listing rather than a
    // fetch of a key literally named "".
    const isList = key === "" && (request.method === "GET" || request.method === "HEAD");

    try {
      if (isList) return await handleList(bucket, url);

      if (request.method === "HEAD") {
        const object = await bucket.head(key);
        if (!object) return new Response(null, { status: 404 });
        return new Response(null, { status: 200, headers: objectHeaders(object) });
      }

      if (request.method === "GET") {
        const range = request.headers.get("range");
        let options = {};
        if (range) {
          // `bytes=<start>-<end>` inclusive, which is also R2's convention, but R2 wants a
          // length rather than an end offset.
          const match = /^bytes=(\d+)-(\d*)$/.exec(range);
          if (match) {
            const offset = Number(match[1]);
            options = match[2]
              ? { range: { offset, length: Number(match[2]) - offset + 1 } }
              : { range: { offset } };
          }
        }

        const object = await bucket.get(key, options);
        if (!object) return s3Error("NoSuchKey", `no such key: ${key}`, 404);

        const headers = objectHeaders(object);
        if (range && object.range) {
          const start = object.range.offset ?? 0;
          const length = object.range.length ?? object.size - start;
          headers.set("content-range", `bytes ${start}-${start + length - 1}/${object.size}`);
          headers.set("content-length", String(length));
          return new Response(object.body, { status: 206, headers });
        }
        return new Response(object.body, { status: 200, headers });
      }

      if (request.method === "PUT") {
        const onlyIf = conditionFrom(request);
        const body = await request.arrayBuffer();
        const object = await bucket.put(key, body, onlyIf ? { onlyIf } : undefined);

        // R2 signals a failed precondition by returning null rather than throwing. S3 clients
        // — `object_store` among them — expect 412, and treating this as success is the bug
        // that would let two writers both believe they won the manifest CAS.
        if (!object) {
          return s3Error("PreconditionFailed", "the condition was not met", 412);
        }

        const headers = new Headers();
        headers.set("etag", quoteEtag(object.httpEtag ?? object.etag));
        return new Response(null, { status: 200, headers });
      }

      if (request.method === "DELETE") {
        await bucket.delete(key);
        return new Response(null, { status: 204 });
      }

      return s3Error("MethodNotAllowed", `${request.method} is not implemented`, 405);
    } catch (error) {
      return s3Error("InternalError", error?.message ?? String(error), 500);
    }
  },
};
