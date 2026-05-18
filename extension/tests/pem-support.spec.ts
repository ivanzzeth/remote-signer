/**
 * PEM private-key input coverage.
 *
 * The remote-signer server hands operators a PEM file (the TUI's
 * -api-key-file flag takes the same format). The extension must accept it as
 * a paste so operators don't have to run openssl to extract the seed.
 */
import { test, expect } from "./fixtures";

// PEM produced by `openssl genpkey -algorithm Ed25519` (32-byte seed
// 6ef73b243b8d323e8ffeaa592966ded0a5ecf84f71665705d4734dd7a806e00a).
// Used here as a deterministic value the test can verify hex-encodes to.
const PEM_FIXTURE = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIG73OyQ7jTI+j/6qWSlm3tCl7PhPcWZXBdRzTdeoBuAK
-----END PRIVATE KEY-----`;
const PEM_EXPECTED_HEX =
  "6ef73b243b8d323e8ffeaa592966ded0a5ecf84f71665705d4734dd7a806e00a";

test.describe("PEM private key support (@integration)", () => {
  test("PEM input is stored as 32-byte hex seed", async ({ popup, serverInfo }) => {
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();

    await popup.fill("#inputUrl", serverInfo.base_url);
    await popup.fill("#inputKeyId", "anything");
    await popup.fill("#inputPrivateKey", PEM_FIXTURE);

    await popup.click("#saveConfigBtn");
    // Save flips us out of settings — wait for it.
    await expect(popup.locator("#settingsView")).toHaveClass(/hidden/, { timeout: 10_000 });

    // Re-open settings to verify the input was normalised.
    const settingsBtn = popup.locator("#settingsBtn");
    const disconnectedBtn = popup.locator("#disconnectedSettingsBtn");
    if (await settingsBtn.isVisible().catch(() => false)) {
      await settingsBtn.click();
    } else {
      await disconnectedBtn.click();
    }
    await expect(popup.locator("#settingsView")).toBeVisible({ timeout: 5_000 });
    await expect(popup.locator("#inputPrivateKey")).toHaveValue(PEM_EXPECTED_HEX);
  });

  test("malformed PEM produces a clear error", async ({ popup, serverInfo }) => {
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();

    await popup.fill("#inputUrl", serverInfo.base_url);
    await popup.fill("#inputKeyId", "anything");
    await popup.fill(
      "#inputPrivateKey",
      "-----BEGIN PRIVATE KEY-----\nthis-is-not-base64\n-----END PRIVATE KEY-----"
    );

    await popup.click("#saveConfigBtn");

    await expect(popup.locator("#connectionError")).toBeVisible({ timeout: 5_000 });
    await expect(popup.locator("#connectionError")).toContainText(/Invalid configuration/i);
    // The button comes back so the user can fix and retry.
    await expect(popup.locator("#saveConfigBtn")).toBeEnabled();
  });

  test("hex private key path still works (backwards compatible)", async ({ popup, serverInfo }) => {
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();

    await popup.fill("#inputUrl", serverInfo.base_url);
    await popup.fill("#inputKeyId", serverInfo.admin_api_key_id);
    await popup.fill("#inputPrivateKey", serverInfo.admin_api_key_hex);

    await popup.click("#saveConfigBtn");
    await expect(popup.locator("#settingsView")).toHaveClass(/hidden/, { timeout: 10_000 });

    // No error banner.
    await expect(popup.locator("#connectionError")).toHaveClass(/hidden/);
  });
});
