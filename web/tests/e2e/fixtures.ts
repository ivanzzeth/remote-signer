import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test as base, expect } from "@playwright/test";
import { RemoteSignerClient } from "remote-signer-client";
import { decryptKeystore } from "../../src/lib/keystore";
import { getState } from "./global-setup";

// The daemon's bootstrap sets this — see global-setup.ts. We reuse it in
// the auth fixture because, post-cleanup, the daemon no longer exports
// an admin.key.priv PEM and the web UI's onboarding flow takes the
// keystore JSON directly with this same password.
export const KEYSTORE_PASSWORD = "e2e-test-password";

/**
 * Reads the bootstrap admin keystore JSON from the test daemon's home
 * directory. Resolves the actual file path by following the ptr file
 * the daemon writes during bootstrap (the keystore's filename is hash-
 * derived from the public key, so we can't hardcode it).
 */
export function readAdminKeystoreJSON(): string {
  const state = getState();
  const ptrPath = join(state.home, "apikeys", "admin.key.keystore");
  const keystorePath = readFileSync(ptrPath, "utf8").trim();
  return readFileSync(keystorePath, "utf8");
}

let cachedAdminSeed: Uint8Array | null = null;

/**
 * Returns a `RemoteSignerClient` authenticated as admin. Used by specs
 * that need to seed daemon state out-of-band (e.g. create a rule, then
 * drive UI to toggle it). Decrypts the daemon's admin keystore once per
 * worker and caches the seed — scrypt(N=2^18) is the slow step we want
 * to amortise across tests.
 *
 * Lives here (not in a per-spec helper) so the migration off the
 * now-removed admin.key.priv PEM is a single grep target rather than 6.
 */
export async function adminSDKClient(): Promise<RemoteSignerClient> {
  if (!cachedAdminSeed) {
    const json = readAdminKeystoreJSON();
    const { seed } = await decryptKeystore(json, KEYSTORE_PASSWORD);
    cachedAdminSeed = seed;
  }
  return new RemoteSignerClient({
    baseURL: `http://127.0.0.1:${process.env.E2E_PORT ?? 18548}`,
    apiKeyID: "admin",
    privateKey: cachedAdminSeed,
  });
}

// Auth fixture: arrives logged in as the bootstrap admin. Each test gets a
// fresh page in a fresh storage state, so credentials don't leak across
// specs (the SPA only keeps them in memory anyway).
//
// Post-cleanup the daemon ships the admin key as an encrypted keystore
// JSON only — the web UI's onboarding auto-detects this shape and
// switches to a single-password flow (the keystore's own password is
// the password we type here). The localStorage value is the keystore
// JSON as-is, so the on-disk and in-browser representations match
// byte-for-byte.

export const test = base.extend<{ authedPage: import("@playwright/test").Page }>({
  authedPage: async ({ page }, use) => {
    const keystoreJSON = readAdminKeystoreJSON();

    await page.goto("/");
    // Unauthed root bounces to /login. Wipe localStorage so we land on the
    // onboarding form (not the returning-user unlock screen) even if a
    // previous spec left a keystore behind.
    await expect(page).toHaveURL(/\/login$/);
    await page.evaluate(() => localStorage.clear());
    await page.reload();

    await page.fill('[data-testid="onboard-api-key-id"]', "admin");
    await page.fill('[data-testid="onboard-key-input"]', keystoreJSON);
    await page.fill('[data-testid="onboard-password"]', KEYSTORE_PASSWORD);
    // Keystore mode hides the confirm field — no need to fill it.
    await page.click('[data-testid="onboard-submit"]');

    // Decrypt (scrypt N=2^18) takes a couple of seconds. The Dashboard
    // heading is the "logged in" marker — Layout + Dashboard render once
    // setCredentials() succeeds AND the SPA navigates to "/".
    await expect(
      page.getByRole("heading", { name: "Dashboard" }),
    ).toBeVisible({ timeout: 30_000 });

    await use(page);
  },
});

export { expect };
