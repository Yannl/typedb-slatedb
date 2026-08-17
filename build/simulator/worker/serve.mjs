/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// Runs `r2-s3-shim.js` on workerd with a real R2 binding, via Miniflare.
//
// Miniflare is the supported way to get an R2 binding outside Cloudflare's network: it drives
// workerd — the same runtime that serves Workers in production — and backs `env.BUCKET` with
// R2's own storage simulator. That is what makes this tier worth having over a hand-written
// fake: the conditional-put semantics under test are R2's, not ours.

import { Miniflare } from "miniflare";
import { readFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.WORKERD_PORT ?? 9200);
const persistTo = process.env.WORKERD_PERSIST ?? join(here, "..", "data", "workerd");

mkdirSync(persistTo, { recursive: true });

const miniflare = new Miniflare({
  script: readFileSync(join(here, "r2-s3-shim.js"), "utf8"),
  modules: true,
  r2Buckets: { BUCKET: "typedb" },
  r2Persist: persistTo,
  host: "127.0.0.1",
  port,
});

await miniflare.ready;
process.stdout.write(`workerd R2 shim listening on http://127.0.0.1:${port}\n`);

const shutdown = async () => {
  await miniflare.dispose();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
