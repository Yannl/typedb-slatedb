import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

export default defineConfig({
  // R4-STACK-01: tests exercise the EXPLICIT local-dev config; the default
  // wrangler.toml is the managed fail-closed posture and must never be
  // selected implicitly by a dev lane.
  plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.local-dev.toml" } })],
  test: {
    include: ["src/**/*.workerd.test.ts"],
  },
});
