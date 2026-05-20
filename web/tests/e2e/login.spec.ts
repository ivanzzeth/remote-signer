import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "@playwright/test";
import { getState } from "./global-setup";

const STRONG_PASSWORD = "Correct-Horse-9!";

// Each test starts with a clean slate — clear localStorage so we deterministically
// land in onboarding mode rather than inheriting state from a prior test.
test.beforeEach(async ({ page }) => {
  await page.goto("/login");
  await page.evaluate(() => localStorage.clear());
});

test("unauthenticated root redirects to /login (onboarding)", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
  await expect(
    page.getByRole("heading", { name: "Import API key" }),
  ).toBeVisible();
});

test("onboarding flow: import key + set password lands on Dashboard", async ({
  page,
}) => {
  const state = getState();
  const pem = readFileSync(
    join(state.home, "apikeys", "admin.key.priv"),
    "utf8",
  );

  await page.goto("/login");
  await page.fill('[data-testid="onboard-api-key-id"]', "admin");
  await page.fill('[data-testid="onboard-key-input"]', pem);
  await page.fill('[data-testid="onboard-password"]', STRONG_PASSWORD);
  await page.fill('[data-testid="onboard-password-confirm"]', STRONG_PASSWORD);
  await page.click('[data-testid="onboard-submit"]');

  // Encrypting + verifying takes a couple of seconds (scrypt N=2^18).
  await expect(
    page.getByRole("heading", { name: "Dashboard" }),
  ).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText("Daemon", { exact: true })).toBeVisible();
});

test("returning user: persisted keystore prompts for password only", async ({
  page,
}) => {
  const state = getState();
  const pem = readFileSync(
    join(state.home, "apikeys", "admin.key.priv"),
    "utf8",
  );

  // First, onboard so the keystore lands in localStorage.
  await page.goto("/login");
  await page.fill('[data-testid="onboard-api-key-id"]', "admin");
  await page.fill('[data-testid="onboard-key-input"]', pem);
  await page.fill('[data-testid="onboard-password"]', STRONG_PASSWORD);
  await page.fill('[data-testid="onboard-password-confirm"]', STRONG_PASSWORD);
  await page.click('[data-testid="onboard-submit"]');
  await expect(
    page.getByRole("heading", { name: "Dashboard" }),
  ).toBeVisible({ timeout: 30_000 });

  // Sign out (keeps the encrypted keystore in localStorage).
  await page.click('[data-testid="sign-out"]');
  await expect(page).toHaveURL(/\/login$/);
  // We should be in unlock mode, not onboarding.
  await expect(page.getByRole("heading", { name: "Unlock" })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Import API key" }),
  ).toHaveCount(0);

  // Unlock with the same password.
  await page.fill('[data-testid="unlock-password"]', STRONG_PASSWORD);
  await page.click('[data-testid="unlock-submit"]');
  await expect(
    page.getByRole("heading", { name: "Dashboard" }),
  ).toBeVisible({ timeout: 30_000 });
});

test("returning user: wrong password surfaces a clear error", async ({
  page,
}) => {
  const state = getState();
  const pem = readFileSync(
    join(state.home, "apikeys", "admin.key.priv"),
    "utf8",
  );

  await page.goto("/login");
  await page.fill('[data-testid="onboard-api-key-id"]', "admin");
  await page.fill('[data-testid="onboard-key-input"]', pem);
  await page.fill('[data-testid="onboard-password"]', STRONG_PASSWORD);
  await page.fill('[data-testid="onboard-password-confirm"]', STRONG_PASSWORD);
  await page.click('[data-testid="onboard-submit"]');
  await expect(
    page.getByRole("heading", { name: "Dashboard" }),
  ).toBeVisible({ timeout: 30_000 });
  await page.click('[data-testid="sign-out"]');

  await page.fill('[data-testid="unlock-password"]', "WrongPassword-9!");
  await page.click('[data-testid="unlock-submit"]');
  await expect(page.locator('[data-testid="unlock-error"]')).toContainText(
    "Wrong password",
    { timeout: 30_000 },
  );
  // Still on /login — wrong password doesn't navigate.
  await expect(page).toHaveURL(/\/login$/);
});

test("Forget encrypted key resets back to onboarding", async ({ page }) => {
  const state = getState();
  const pem = readFileSync(
    join(state.home, "apikeys", "admin.key.priv"),
    "utf8",
  );

  // Onboard first.
  await page.goto("/login");
  await page.fill('[data-testid="onboard-api-key-id"]', "admin");
  await page.fill('[data-testid="onboard-key-input"]', pem);
  await page.fill('[data-testid="onboard-password"]', STRONG_PASSWORD);
  await page.fill('[data-testid="onboard-password-confirm"]', STRONG_PASSWORD);
  await page.click('[data-testid="onboard-submit"]');
  await expect(
    page.getByRole("heading", { name: "Dashboard" }),
  ).toBeVisible({ timeout: 30_000 });

  // Click "Forget encrypted key" and accept the confirm dialog.
  page.once("dialog", (d) => d.accept());
  await page.click('[data-testid="forget-key"]');

  // Should land back on /login in onboarding mode.
  await expect(page).toHaveURL(/\/login$/);
  await expect(
    page.getByRole("heading", { name: "Import API key" }),
  ).toBeVisible();
  // localStorage should be cleared.
  const stored = await page.evaluate(() =>
    localStorage.getItem("remote-signer:web:keystore"),
  );
  expect(stored).toBeNull();
});

test("onboarding rejects a weak password", async ({ page }) => {
  await page.goto("/login");
  await page.fill('[data-testid="onboard-api-key-id"]', "admin");
  await page.fill(
    '[data-testid="onboard-key-input"]',
    // any non-empty value — the password check fires before key parse
    "deadbeef",
  );
  await page.fill('[data-testid="onboard-password"]', "weakpass");
  // The submit button stays disabled while the password fails validation.
  // Real-time help text should mention "at least 10".
  await expect(
    page.locator('[data-testid="onboard-password-help"]'),
  ).toContainText("at least 10");
  await expect(page.locator('[data-testid="onboard-submit"]')).toBeDisabled();
});

test("onboarding rejects mismatched confirm password", async ({ page }) => {
  await page.goto("/login");
  await page.fill('[data-testid="onboard-api-key-id"]', "admin");
  await page.fill('[data-testid="onboard-key-input"]', "deadbeef");
  await page.fill('[data-testid="onboard-password"]', STRONG_PASSWORD);
  await page.fill(
    '[data-testid="onboard-password-confirm"]',
    "Different-Pass-9!",
  );
  // Mismatch banner appears under confirm field; submit stays disabled.
  await expect(page.getByText("Passwords don't match")).toBeVisible();
  await expect(page.locator('[data-testid="onboard-submit"]')).toBeDisabled();
});

test("garbage key input surfaces a parse error", async ({ page }) => {
  await page.goto("/login");
  await page.fill('[data-testid="onboard-api-key-id"]', "admin");
  await page.fill('[data-testid="onboard-key-input"]', "this is not a pem");
  await page.fill('[data-testid="onboard-password"]', STRONG_PASSWORD);
  await page.fill('[data-testid="onboard-password-confirm"]', STRONG_PASSWORD);
  await page.click('[data-testid="onboard-submit"]');
  await expect(page.locator('[data-testid="onboard-error"]')).toContainText(
    "expected hex or PKCS#8 PEM input",
    { timeout: 30_000 },
  );
});
