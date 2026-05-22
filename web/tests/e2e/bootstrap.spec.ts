import { spawn, type ChildProcessByStdio } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

// __dirname for ESM context.
const __dirname = dirname(fileURLToPath(import.meta.url));

// These tests need a daemon that is in a *different state* from the one
// global-setup spawns (the shared daemon there bootstraps admin at
// startup via REMOTE_SIGNER_KEYSTORE_PASSWORD). We launch our own
// per-test daemon on a distinct port, with an empty home and NO env-var
// password, so the soft-start flow is the path under exercise.
//
// Cost: each test pays for a ~500ms daemon start. Worth it: we need to
// observe the daemon in two different lifecycle states (pre-bootstrap
// and post-bootstrap), and globalSetup's shared instance only ever
// shows the post-bootstrap state.

let daemon: ChildProcessByStdio<null, Readable, Readable> | undefined;
let baseURL: string;

const BOOTSTRAP_TEST_PORT = Number(process.env.E2E_BOOTSTRAP_PORT ?? 19548);
const PASSWORD = "BootstrapE2E-Test-2026!";

async function waitForHealth(url: string, timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(url);
      if (r.ok) return;
    } catch (err) {
      lastErr = err;
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`daemon never became healthy on ${url}: ${String(lastErr)}`);
}

test.beforeEach(async () => {
  // Fresh tempdir per test so soft-start always observes an empty
  // api_keys table. Sharing a home across the two tests would leak the
  // first test's admin row into the second.
  const home = mkdtempSync(join(tmpdir(), "remote-signer-bootstrap-e2e-"));
  const binary = resolve(__dirname, "../../../remote-signer");
  const rulesDir = resolve(__dirname, "../../../rules");

  if (!existsSync(binary)) {
    throw new Error(
      `binary not found at ${binary} — run \`make build-embed\` first`,
    );
  }

  const cfg = `
server:
  host: 127.0.0.1
  port: ${BOOTSTRAP_TEST_PORT}
  read_timeout: 30s
  write_timeout: 30s
  tls:
    enabled: false

database:
  dsn: "file:${home}/remote-signer.db?_journal_mode=WAL&_busy_timeout=5000"

logger:
  level: warn
  pretty: false

chains:
  evm:
    enabled: true
    keystore_dir: "${home}/keystores"
    hd_wallet_dir: "${home}/hd-wallets"

templates_dir: "${rulesDir}/templates"
presets:
  dir: "${rulesDir}/presets"
`;
  writeFileSync(join(home, "config.yaml"), cfg.trimStart());

  // The key difference from global-setup: we deliberately do NOT set
  // REMOTE_SIGNER_KEYSTORE_PASSWORD so the daemon stops short of
  // creating an admin keystore. It serves HTTP, responds to
  // /api/v1/bootstrap/status with needs_bootstrap=true, and waits for
  // either this spec's POST or for the user to walk through the UI
  // (which is what the second test exercises).
  daemon = spawn(binary, ["server", "start"], {
    env: { ...process.env, REMOTE_SIGNER_HOME: home },
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (process.env.E2E_DEBUG) {
    daemon.stdout.on("data", (b) =>
      process.stdout.write(`[bootstrap-daemon] ${b}`),
    );
    daemon.stderr.on("data", (b) =>
      process.stderr.write(`[bootstrap-daemon] ${b}`),
    );
  } else {
    daemon.stdout.on("data", () => undefined);
    daemon.stderr.on("data", () => undefined);
  }

  baseURL = `http://127.0.0.1:${BOOTSTRAP_TEST_PORT}`;
  await waitForHealth(`${baseURL}/health`);
});

test.afterEach(async () => {
  if (daemon && !daemon.killed) {
    daemon.kill("SIGTERM");
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        daemon?.kill("SIGKILL");
        resolve();
      }, 3000);
      daemon?.once("exit", () => {
        clearTimeout(timer);
        resolve();
      });
    });
  }
});

test.describe("first-run bootstrap", () => {
  test("daemon reports needs_bootstrap=true before setup", async () => {
    // Sanity guard: if this fails the entire flow under test is
    // bypassed (the UI would skip straight to login because the daemon
    // claimed it didn't need bootstrap). Worth pinning explicitly.
    const status = await fetch(`${baseURL}/api/v1/bootstrap/status`).then(
      (r) => r.json(),
    );
    expect(status.needs_bootstrap).toBe(true);
  });

  test("operator completes bootstrap via the web UI and lands logged in", async ({
    page,
  }) => {
    // Drive the daemon's HTML directly — Playwright's `page.goto`
    // hits its `webServer` baseURL by default, which points at the
    // shared globalSetup daemon. Here we want our soft-start daemon,
    // so go absolute.
    await page.goto(`${baseURL}/`);

    // The App.tsx route guard should detect needs_bootstrap=true on
    // mount and route to /bootstrap automatically, regardless of any
    // stale auth state in localStorage.
    await expect(
      page.getByRole("heading", { name: "First-run setup" }),
    ).toBeVisible({ timeout: 5_000 });

    // The button stays disabled until the password meets the strength
    // check AND the confirmation matches. Test that path before
    // submitting the happy case — otherwise a typo'd password would
    // race the submit silently.
    const submitBtn = page.getByRole("button", {
      name: /Create admin & continue/,
    });
    await expect(submitBtn).toBeDisabled();

    await page
      .getByLabel("New admin password", { exact: true })
      .fill(PASSWORD);
    await expect(submitBtn).toBeDisabled(); // confirm still empty
    await page
      .getByLabel("Confirm password", { exact: true })
      .fill(PASSWORD);
    await expect(submitBtn).toBeEnabled();

    await submitBtn.click();

    // After a successful bootstrap the page navigates to "/" and the
    // dashboard heading shows up. (We're explicitly NOT testing for
    // the Login page — the bootstrap flow short-circuits straight to
    // logged-in by unlocking the just-issued keystore.)
    //
    // The "Dashboard" heading is the canonical landed-state marker
    // used across other specs in this suite.
    await expect(
      page.getByRole("heading", { name: /Dashboard/i }),
    ).toBeVisible({ timeout: 10_000 });

    // Cross-check via the public HTTP surface: the daemon should now
    // report bootstrap is done.
    const status = await fetch(`${baseURL}/api/v1/bootstrap/status`).then(
      (r) => r.json(),
    );
    expect(status.needs_bootstrap).toBe(false);
  });

  test("second bootstrap POST is rejected with 410 Gone", async () => {
    // Race-safety: once admin exists, the bootstrap endpoint must
    // refuse subsequent calls, otherwise an attacker who learns the
    // daemon URL during the setup window could overwrite the just-
    // configured admin row.
    const ok = await fetch(`${baseURL}/api/v1/bootstrap/admin`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: PASSWORD }),
    });
    expect(ok.status).toBe(200);

    const second = await fetch(`${baseURL}/api/v1/bootstrap/admin`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: "different-password" }),
    });
    expect(second.status).toBe(410);
    const body = await second.json();
    expect(body.code).toBe("admin_already_exists");
  });
});
