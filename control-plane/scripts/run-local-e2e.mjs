/*
 * One-command local E2E lane: boots `wrangler dev` on the EXPLICIT
 * developer-convenience config (wrangler.local-dev.toml, R4-STACK-01), runs
 * scripts/local-stack-e2e.mjs against it, and tears the stack down.
 * Exit code is the driver's.
 */

import { spawn } from "node:child_process";
import { startWranglerDev } from "./wrangler-dev.mjs";

const PORT = Number(process.env.E2E_PORT ?? 8797);
const { baseUrl, stop } = await startWranglerDev({ configPath: "wrangler.local-dev.toml", port: PORT });
try {
  const code = await new Promise((resolve) => {
    const driver = spawn(process.execPath,
      ["--experimental-strip-types", "--disable-warning=ExperimentalWarning",
        new URL("./local-stack-e2e.mjs", import.meta.url).pathname, baseUrl],
      { stdio: "inherit" });
    driver.on("exit", (exitCode) => resolve(exitCode ?? 1));
  });
  process.exitCode = code;
} finally {
  stop();
}
