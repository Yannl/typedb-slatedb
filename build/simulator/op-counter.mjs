/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// A transparent reverse proxy that counts object-store operations the way R2 bills them.
//
// The point is to make cost claims testable. "One commit is one Class A operation" and "the
// diagnostics poll does no I/O" are the kind of assertions that hold when written and rot
// silently afterwards, because nothing in an ordinary test suite can see the difference between
// an implementation that issues one request and one that issues forty. This sits in front of the
// object store and counts, so a test can assert on the bill.
//
// It forwards verbatim, and that constraint drives the one subtle piece of the implementation:
// SigV4 signs the Host header, so the request must reach the backend carrying the Host the
// client signed, not the backend's own address. Rewriting it — the reflex when proxying —
// produces a signature mismatch that reads like a credentials problem.

import http from "node:http";

const LISTEN_PORT = Number(process.env.OP_COUNTER_PORT ?? 9100);
const BACKEND_HOST = process.env.OP_COUNTER_BACKEND_HOST ?? "127.0.0.1";
const BACKEND_PORT = Number(process.env.OP_COUNTER_BACKEND_PORT ?? 9000);

// R2's billing classes. Cloudflare groups operations by cost, not by HTTP verb, and the mapping
// is not quite the obvious one: a bucket LIST is a *write-priced* Class A operation even though
// it reads nothing, and DELETE is free even though it mutates. Getting this table right is the
// whole value of the tool, so each line names the R2 operation it stands for.
//
//   Class A  $4.50/M   PutObject, CopyObject, ListObjects, CreateMultipartUpload,
//                      UploadPart, CompleteMultipartUpload
//   Class B  $0.36/M   GetObject, HeadObject
//   Free     $0.00     DeleteObject, DeleteObjects
function classify(method, url) {
  const [path, query = ""] = url.split("?");
  const params = new URLSearchParams(query);

  if (method === "DELETE") return { klass: "free", op: "DeleteObject" };
  if (method === "HEAD") return { klass: "B", op: "HeadObject" };

  if (method === "POST") {
    if (params.has("uploads")) return { klass: "A", op: "CreateMultipartUpload" };
    if (params.has("uploadId")) return { klass: "A", op: "CompleteMultipartUpload" };
    if (params.has("delete")) return { klass: "free", op: "DeleteObjects" };
    return { klass: "A", op: "PostObject" };
  }

  if (method === "PUT") {
    if (params.has("partNumber")) return { klass: "A", op: "UploadPart" };
    // A copy is distinguished only by a header, which the caller passes in separately.
    return { klass: "A", op: "PutObject" };
  }

  if (method === "GET") {
    // A listing is a GET whose target is the bucket rather than a key. `list-type=2` marks
    // ListObjectsV2 explicitly; the older form is a GET at the bucket root with a prefix.
    if (params.has("list-type") || params.has("prefix") || params.has("delimiter")) {
      return { klass: "A", op: "ListObjects" };
    }
    const segments = path.split("/").filter(Boolean);
    if (segments.length <= 1) return { klass: "A", op: "ListObjects" };
    return { klass: "B", op: "GetObject" };
  }

  return { klass: "other", op: `${method} ${path}` };
}

const emptyTally = () => ({
  A: 0,
  B: 0,
  free: 0,
  other: 0,
  bytesIn: 0,
  bytesOut: 0,
  byOp: {},
  since: new Date().toISOString(),
});

let tally = emptyTally();

// R2's published prices, so the tool can report a bill rather than a count. A count is hard to
// reason about; a number in dollars is immediately comparable to the alternative design.
const PRICE_PER_MILLION = { A: 4.5, B: 0.36, free: 0, other: 0 };

function summary() {
  const cost = (["A", "B", "free"]).reduce(
    (total, klass) => total + (tally[klass] / 1e6) * PRICE_PER_MILLION[klass],
    0,
  );
  return {
    ...tally,
    total: tally.A + tally.B + tally.free + tally.other,
    estimatedCostUsd: Number(cost.toFixed(9)),
    pricePerMillion: PRICE_PER_MILLION,
  };
}

const server = http.createServer((clientReq, clientRes) => {
  // The control plane is served here rather than on a second port so a test needs exactly one
  // address to talk to. These paths are not valid S3 keys, so they cannot collide with traffic.
  if (clientReq.url === "/__ops") {
    clientRes.writeHead(200, { "content-type": "application/json" });
    clientRes.end(JSON.stringify(summary(), null, 2));
    return;
  }
  if (clientReq.url === "/__ops/reset") {
    tally = emptyTally();
    clientRes.writeHead(200, { "content-type": "application/json" });
    clientRes.end(JSON.stringify({ reset: true }));
    return;
  }

  const isCopy = Boolean(clientReq.headers["x-amz-copy-source"]);
  const { klass, op } = isCopy
    ? { klass: "A", op: "CopyObject" }
    : classify(clientReq.method, clientReq.url);

  tally[klass] += 1;
  tally.byOp[op] = (tally.byOp[op] ?? 0) + 1;

  const proxyReq = http.request(
    {
      host: BACKEND_HOST,
      port: BACKEND_PORT,
      method: clientReq.method,
      path: clientReq.url,
      // Verbatim, Host included. SigV4 covers the Host header, so rewriting it here would
      // invalidate every signed request — and it would fail as an authentication error, which
      // points at the credentials rather than at the proxy.
      headers: clientReq.headers,
    },
    (backendRes) => {
      clientRes.writeHead(backendRes.statusCode ?? 502, backendRes.headers);
      backendRes.on("data", (chunk) => {
        tally.bytesOut += chunk.length;
      });
      backendRes.pipe(clientRes);
    },
  );

  clientReq.on("data", (chunk) => {
    tally.bytesIn += chunk.length;
  });
  clientReq.pipe(proxyReq);

  proxyReq.on("error", (error) => {
    if (!clientRes.headersSent) clientRes.writeHead(502, { "content-type": "text/plain" });
    clientRes.end(`op-counter could not reach the object store: ${error.message}`);
  });
});

server.listen(LISTEN_PORT, "127.0.0.1", () => {
  process.stdout.write(
    `op-counter listening on 127.0.0.1:${LISTEN_PORT} -> ${BACKEND_HOST}:${BACKEND_PORT}\n`,
  );
});
