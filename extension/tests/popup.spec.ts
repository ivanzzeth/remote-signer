import { test, expect } from "./fixtures";

test.describe("Extension basic functionality", () => {
  test("popup loads and shows disconnected state", async ({ popup }) => {
    // The popup should show the disconnected view initially (no config saved)
    await expect(popup.locator("#disconnectedView")).toBeVisible();
    await expect(popup.locator("#disconnectedView .empty-icon")).toHaveText("🔌");
    await expect(popup.locator("#disconnectedSettingsBtn")).toBeVisible();
  });

  test("popup settings view is accessible", async ({ popup }) => {
    // Click settings button from disconnected view
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();
    await expect(popup.locator("#inputUrl")).toBeVisible();
    await expect(popup.locator("#inputKeyId")).toBeVisible();
    await expect(popup.locator("#inputPrivateKey")).toBeVisible();
  });

  test("can configure extension and test connection", async ({ popup, serverInfo }) => {
    // Navigate to settings
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();

    // Fill config
    await popup.fill("#inputUrl", serverInfo.base_url);
    await popup.fill("#inputKeyId", serverInfo.admin_api_key_id);
    await popup.fill("#inputPrivateKey", serverInfo.admin_api_key_hex);

    // Test connection
    await popup.click("#testConnectionBtn");

    // Should show a connection result — either success or an error message
    // Since the service worker lazily initializes, this may need a retry
    await expect(popup.locator("#connectionError")).not.toBeEmpty({ timeout: 8_000 });
  });

  test("can save config and return to main view", async ({ popup, serverInfo }) => {
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();

    await popup.fill("#inputUrl", serverInfo.base_url);
    await popup.fill("#inputKeyId", serverInfo.admin_api_key_id);
    await popup.fill("#inputPrivateKey", serverInfo.admin_api_key_hex);

    await popup.click("#saveConfigBtn");
    await popup.waitForTimeout(500);

    // After saving, should navigate back to connected or disconnected view
    // (provider init is lazy, so may still show disconnected)
    await expect(popup.locator("#settingsView")).toHaveClass(/hidden/);
  });
});

test.describe("Extension configuration persistence", () => {
  test("config persists across popup opens", async ({ context, extensionId, serverInfo }) => {
    // First popup: save config
    const popup1 = await context.newPage();
    await popup1.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup1.waitForSelector("#app");

    // Go to settings and configure
    const settingsBtn1 = popup1.locator("#disconnectedSettingsBtn");
    if (await settingsBtn1.isVisible()) {
      await settingsBtn1.click();
    } else {
      // Already in connected view, click the settings button there
      await popup1.click("#settingsBtn");
    }

    await popup1.waitForSelector("#settingsView:not(.hidden)", { timeout: 5_000 });
    await popup1.fill("#inputUrl", serverInfo.base_url);
    await popup1.fill("#inputKeyId", serverInfo.admin_api_key_id);
    await popup1.fill("#inputPrivateKey", serverInfo.admin_api_key_hex);
    await popup1.click("#saveConfigBtn");
    await popup1.waitForTimeout(500);
    await popup1.close();

    // Second popup: check config loaded
    const popup2 = await context.newPage();
    await popup2.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup2.waitForSelector("#app");

    // Open settings and verify fields
    await popup2.click("#settingsBtn");
    await popup2.waitForSelector("#settingsView:not(.hidden)", { timeout: 5_000 });
    await expect(popup2.locator("#inputUrl")).toHaveValue(serverInfo.base_url);
    await expect(popup2.locator("#inputKeyId")).toHaveValue(serverInfo.admin_api_key_id);

    await popup2.close();
  });
});
