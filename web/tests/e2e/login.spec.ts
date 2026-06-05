import { expect, test } from "@playwright/test";
import { readAdminKeystoreJSON } from "./fixtures";

// Post-cleanup the daemon ships the admin private key only as an
// encrypted keystore JSON; there's no admin.key.priv PEM on disk. Both
// onboarding flows (keystore JSON vs PEM/hex) are exercised — the
// keystore path uses the daemon's own password, the PEM path uses a
// throwaway strong password and a synthetic key.
const KEYSTORE_PASSWORD = "e2e-test-password";
const STRONG_PASSWORD = "Correct-Horse-9!";

// Throwaway PEM for the PEM-mode path. Generated from the Ed25519 zero
// seed (key bytes deliberately all-zero so the test pins the
// "encrypt-then-decrypt" round trip without depending on daemon state).
// It's NOT registered with the daemon, so the daemon will reject the
// signed-API-call setCredentials() does — that's expected and asserted
// downstream where relevant.
const ZERO_SEED_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END PRIVATE KEY-----`;

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

test("onboarding via keystore JSON lands on Dashboard", async ({ page }) => {
  const keystoreJSON = readAdminKeystoreJSON();

  await page.goto("/login");
  await page.fill('[data-testid="onboard-api-key-id"]', "admin");
  await page.fill('[data-testid="onboard-key-input"]', keystoreJSON);
  // Keystore detection should flip the form into single-password mode.
  await expect(
    page.locator('[data-testid="onboard-keystore-detected"]'),
  ).toBeVisible();
  // Confirm-password field should be hidden in keystore mode.
  await expect(
    page.locator('[data-testid="onboard-password-confirm"]'),
  ).toHaveCount(0);
  await page.fill('[data-testid="onboard-password"]', KEYSTORE_PASSWORD);
  await page.click('[data-testid="onboard-submit"]');

  await expect(
    page.getByRole("heading", { name: "Dashboard" }),
  ).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText("Daemon", { exact: true })).toBeVisible();
});

test("returning user: persisted keystore prompts for password only", async ({
  page,
}) => {
  const keystoreJSON = readAdminKeystoreJSON();

  // First, onboard so the keystore lands in localStorage.
  await page.goto("/login");
  await page.fill('[data-testid="onboard-api-key-id"]', "admin");
  await page.fill('[data-testid="onboard-key-input"]', keystoreJSON);
  await page.fill('[data-testid="onboard-password"]', KEYSTORE_PASSWORD);
  await page.click('[data-testid="onboard-submit"]');
  await expect(
    page.getByRole("heading", { name: "Dashboard" }),
  ).toBeVisible({ timeout: 30_000 });

  // Sign out (keeps the encrypted keystore in localStorage).
  await page.click('[data-testid="sign-out"]');
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("heading", { name: "Unlock" })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Import API key" }),
  ).toHaveCount(0);

  // Unlock with the same keystore password.
  await page.fill('[data-testid="unlock-password"]', KEYSTORE_PASSWORD);
  await page.click('[data-testid="unlock-submit"]');
  await expect(
    page.getByRole("heading", { name: "Dashboard" }),
  ).toBeVisible({ timeout: 30_000 });
});

test("returning user: wrong password surfaces a clear error", async ({
  page,
}) => {
  const keystoreJSON = readAdminKeystoreJSON();

  await page.goto("/login");
  await page.fill('[data-testid="onboard-api-key-id"]', "admin");
  await page.fill('[data-testid="onboard-key-input"]', keystoreJSON);
  await page.fill('[data-testid="onboard-password"]', KEYSTORE_PASSWORD);
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
  await expect(page).toHaveURL(/\/login$/);
});

test("Forget encrypted key resets back to onboarding", async ({ page }) => {
  const keystoreJSON = readAdminKeystoreJSON();

  await page.goto("/login");
  await page.fill('[data-testid="onboard-api-key-id"]', "admin");
  await page.fill('[data-testid="onboard-key-input"]', keystoreJSON);
  await page.fill('[data-testid="onboard-password"]', KEYSTORE_PASSWORD);
  await page.click('[data-testid="onboard-submit"]');
  await expect(
    page.getByRole("heading", { name: "Dashboard" }),
  ).toBeVisible({ timeout: 30_000 });

  await page.click('[data-testid="forget-key"]');
  await page.getByTestId("confirm-dialog-confirm").click();

  await expect(page).toHaveURL(/\/login$/);
  await expect(
    page.getByRole("heading", { name: "Import API key" }),
  ).toBeVisible();
  const stored = await page.evaluate(() =>
    localStorage.getItem("remote-signer:web:keystore"),
  );
  expect(stored).toBeNull();
});

test("PEM-mode onboarding shows the confirm field + strong-password gate", async ({
  page,
}) => {
  await page.goto("/login");
  await page.fill('[data-testid="onboard-api-key-id"]', "admin");
  await page.fill('[data-testid="onboard-key-input"]', ZERO_SEED_PEM);
  // PEM mode → confirm field visible, password help text visible.
  await expect(
    page.locator('[data-testid="onboard-password-confirm"]'),
  ).toBeVisible();
  await expect(
    page.locator('[data-testid="onboard-password-help"]'),
  ).toBeVisible();
  // Weak password → submit disabled, help text reflects the requirement.
  await page.fill('[data-testid="onboard-password"]', "weak");
  await expect(
    page.locator('[data-testid="onboard-password-help"]'),
  ).toContainText("at least 10");
  await expect(page.locator('[data-testid="onboard-submit"]')).toBeDisabled();
  // Strong password but mismatched confirm → still disabled.
  await page.fill('[data-testid="onboard-password"]', STRONG_PASSWORD);
  await page.fill(
    '[data-testid="onboard-password-confirm"]',
    "Different-Pass-9!",
  );
  await expect(page.getByText("Passwords don't match")).toBeVisible();
  await expect(page.locator('[data-testid="onboard-submit"]')).toBeDisabled();
});

test("keystore-mode onboarding hides the confirm field", async ({ page }) => {
  const keystoreJSON = readAdminKeystoreJSON();

  await page.goto("/login");
  await page.fill('[data-testid="onboard-api-key-id"]', "admin");
  await page.fill('[data-testid="onboard-key-input"]', keystoreJSON);
  // Confirm + strong-password help should NOT be rendered when the input
  // is recognised as a keystore — the operator can't change the
  // keystore's password from this form.
  await expect(
    page.locator('[data-testid="onboard-password-confirm"]'),
  ).toHaveCount(0);
  await expect(
    page.locator('[data-testid="onboard-password-help"]'),
  ).toHaveCount(0);
  // A short password should NOT trigger the strong-password gate (the
  // gate doesn't apply to keystore mode).
  await page.fill('[data-testid="onboard-password"]', "short");
  await expect(page.locator('[data-testid="onboard-submit"]')).toBeEnabled();
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
