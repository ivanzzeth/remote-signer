import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test as base, expect } from "@playwright/test";
import { getState } from "./global-setup";

// Auth fixture: arrives logged in as the bootstrap admin. Each test gets a
// fresh page in a fresh storage state, so credentials don't leak across
// specs (the SPA only keeps them in memory anyway).
//
// The post-keystore login flow takes 3 inputs: api-key-id, PEM/hex, plus a
// strong password (we use the same throwaway across all e2e specs since
// the keystore is wiped in beforeEach). The encrypted-keystore write to
// localStorage is incidental — the daemon doesn't see it and tests don't
// need to inspect it unless they're explicitly testing the unlock flow.
const FIXTURE_PASSWORD = "Correct-Horse-9!";

export const test = base.extend<{ authedPage: import("@playwright/test").Page }>({
  authedPage: async ({ page }, use) => {
    const state = getState();
    const pem = readFileSync(
      join(state.home, "apikeys", "admin.key.priv"),
      "utf8",
    );

    await page.goto("/");
    // Unauthed root bounces to /login. Wipe localStorage so we land on the
    // onboarding form (not the returning-user unlock screen) even if a
    // previous spec left a keystore behind.
    await expect(page).toHaveURL(/\/login$/);
    await page.evaluate(() => localStorage.clear());
    // Re-load so the React state reflects the cleared localStorage.
    await page.reload();

    await page.fill('[data-testid="onboard-api-key-id"]', "admin");
    await page.fill('[data-testid="onboard-key-input"]', pem);
    await page.fill('[data-testid="onboard-password"]', FIXTURE_PASSWORD);
    await page.fill(
      '[data-testid="onboard-password-confirm"]',
      FIXTURE_PASSWORD,
    );
    await page.click('[data-testid="onboard-submit"]');

    // Encrypting (scrypt N=2^18) takes a couple of seconds. The Dashboard
    // heading is the "logged in" marker — Layout + Dashboard render once
    // setCredentials() succeeds AND the SPA navigates to "/".
    await expect(
      page.getByRole("heading", { name: "Dashboard" }),
    ).toBeVisible({ timeout: 30_000 });

    await use(page);
  },
});

export { expect };
