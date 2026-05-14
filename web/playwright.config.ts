import { defineConfig, devices } from "@playwright/test";

// E2E tests drive the embedded React UI against a real, isolated daemon
// (not Electron — the daemon serves the SPA itself). `globalSetup` provisions
// the tmpdir + config, the `webServer` block launches the binary, and tests
// connect to baseURL below.
//
// Port 18548 keeps these tests off the developer's interactive daemon on
// 8548. The binary at ../remote-signer is expected to exist; `pretest:e2e`
// in package.json runs the Go build first.

const PORT = Number(process.env.E2E_PORT ?? 18548);

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: false, // one daemon, shared SQLite state
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: "list",
  globalSetup: "./tests/e2e/global-setup.ts",
  globalTeardown: "./tests/e2e/global-teardown.ts",

  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },

  // No `webServer` block: globalSetup spawns the daemon directly so we can
  // hold onto the tmp REMOTE_SIGNER_HOME and tear it down deterministically.
  // Playwright's webServer wrapper restarts the process per test file which
  // breaks state-sensitive specs (e.g. audit records seeded by login).

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
