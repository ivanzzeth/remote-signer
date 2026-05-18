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

  test("Test Connection succeeds with valid credentials and shows success banner", async ({ popup, serverInfo }) => {
    // Reproduces the bug "Test Connection button has no reaction" — clicking
    // must produce visible feedback (success banner OR error message).
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();

    await popup.fill("#inputUrl", serverInfo.base_url);
    await popup.fill("#inputKeyId", serverInfo.admin_api_key_id);
    await popup.fill("#inputPrivateKey", serverInfo.admin_api_key_hex);

    await popup.click("#testConnectionBtn");

    // Button must transition through "Testing…" then back to "Test Connection".
    await expect(popup.locator("#testConnectionBtn")).toHaveText("Test Connection", { timeout: 10_000 });

    // Either success banner is shown (server reachable + auth OK) or error banner is shown.
    const successVisible = await popup.locator("#connectionSuccess:not(.hidden)").isVisible().catch(() => false);
    const errorVisible = await popup.locator("#connectionError:not(.hidden)").isVisible().catch(() => false);
    expect(successVisible || errorVisible).toBe(true);

    // With valid e2e credentials we expect success.
    await expect(popup.locator("#connectionSuccess")).toBeVisible({ timeout: 10_000 });
    await expect(popup.locator("#connectionSuccess")).toContainText(/Connection successful/i);
  });

  test("Test Connection surfaces a clear error for an invalid API key", async ({ popup, serverInfo }) => {
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();

    await popup.fill("#inputUrl", serverInfo.base_url);
    await popup.fill("#inputKeyId", "definitely-not-a-real-key");
    // 64-byte hex (Go-style) so we exercise the SDK-signing path, not a malformed-key short-circuit.
    await popup.fill("#inputPrivateKey", "00".repeat(64));

    await popup.click("#testConnectionBtn");

    await expect(popup.locator("#connectionError")).toBeVisible({ timeout: 10_000 });
    await expect(popup.locator("#connectionError")).toContainText(/(Connection failed|Auth failed|Error)/i);
    // Crucially: button is re-enabled and reset to "Test Connection" — never stuck on "Testing…".
    await expect(popup.locator("#testConnectionBtn")).toBeEnabled();
    await expect(popup.locator("#testConnectionBtn")).toHaveText("Test Connection");
  });

  test("Test Connection reports a clear error when the URL is unreachable", async ({ popup, serverInfo }) => {
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();

    // Pick a port nothing is listening on.
    await popup.fill("#inputUrl", "http://127.0.0.1:1");
    await popup.fill("#inputKeyId", serverInfo.admin_api_key_id);
    await popup.fill("#inputPrivateKey", serverInfo.admin_api_key_hex);

    await popup.click("#testConnectionBtn");

    await expect(popup.locator("#connectionError")).toBeVisible({ timeout: 15_000 });
    await expect(popup.locator("#connectionError")).toContainText(/(Cannot reach server|Connection failed|Error)/i);
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
