import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test as base, expect } from "@playwright/test";
import { getState } from "./global-setup";

// Auth fixture: arrives logged in as the bootstrap admin. Each test gets a
// fresh page in a fresh storage state, so credentials don't leak across
// specs (the SPA only keeps them in memory anyway).
export const test = base.extend<{ authedPage: import("@playwright/test").Page }>({
  authedPage: async ({ page }, use) => {
    const state = getState();
    const pem = readFileSync(
      join(state.home, "apikeys", "admin.key.priv"),
      "utf8",
    );

    await page.goto("/");
    // Unauthed root bounces to /login.
    await expect(page).toHaveURL(/\/login$/);

    await page.fill("#api-key-id", "admin");
    await page.fill("#key-input", pem);
    await page.click("button[type=submit]");

    // Login navigates to /, where the Layout + Dashboard render. We use the
    // Dashboard heading as the "logged in" marker rather than waiting on
    // load events — the SPA is client-rendered and load fires before React.
    await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();

    await use(page);
  },
});

export { expect };
