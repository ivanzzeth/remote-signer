/**
 * Popup state-model tests — real backend.
 *
 * Pins the rule: "connection state is decoupled from signer presence."
 * - Not configured: disconnected, no error.
 * - Configured + unreachable: disconnected with reachability error.
 * - Configured + auth fails: disconnected with auth error.
 * - Configured + reachable + auth OK: connected, even if signer mix isn't healthy.
 */
import { test, expect } from "./fixtures";
import { injectStorageConfig } from "./helpers";

async function open(context: any, extensionId: string) {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/popup/popup.html`);
  await page.waitForSelector("#app");
  return page;
}

test.describe("Popup state model (real backend) (@integration)", () => {
  test("unconfigured popup shows disconnected without an error reason", async ({ context, extensionId }) => {
    const popup = await open(context, extensionId);
    // Make sure storage really is empty.
    await popup.evaluate(() =>
      new Promise<void>((resolve) =>
        chrome.storage.local.remove("remoteSignerConfig", () => resolve())
      )
    );
    await popup.reload();
    await popup.waitForSelector("#app");
    await expect(popup.locator("#disconnectedView")).toBeVisible();
    await expect(popup.locator("#disconnectedReason")).toHaveText("Configure your connection in Settings");
    await popup.close();
  });

  test("configured + unreachable URL surfaces a 'Cannot reach' message", async ({ context, extensionId, serverInfo }) => {
    const popup = await open(context, extensionId);
    await injectStorageConfig(popup, {
      remoteSignerUrl: "http://127.0.0.1:1",
      apiKeyId: serverInfo.admin_api_key_id,
      apiKeyPrivateKey: serverInfo.admin_api_key_hex,
    });
    await popup.reload();
    await popup.waitForSelector("#app");
    await expect(popup.locator("#disconnectedView")).toBeVisible({ timeout: 15_000 });
    await expect(popup.locator("#disconnectedReason")).toContainText(/Cannot reach server/i);
    await popup.close();
  });

  test("configured + bogus API key surfaces an auth-failed message", async ({ context, extensionId, serverInfo }) => {
    const popup = await open(context, extensionId);
    await injectStorageConfig(popup, {
      remoteSignerUrl: serverInfo.base_url,
      apiKeyId: "not-a-real-key",
      apiKeyPrivateKey: "00".repeat(32),
    });
    await popup.reload();
    await popup.waitForSelector("#app");
    await expect(popup.locator("#disconnectedView")).toBeVisible({ timeout: 15_000 });
    await expect(popup.locator("#disconnectedReason")).toContainText(/Auth failed|signature|unauthorized/i);
    await popup.close();
  });

  test("configured + valid creds reaches the connected view (signer present)", async ({ context, extensionId, serverInfo }) => {
    const popup = await open(context, extensionId);
    await injectStorageConfig(popup, {
      remoteSignerUrl: serverInfo.base_url,
      apiKeyId: serverInfo.admin_api_key_id,
      apiKeyPrivateKey: serverInfo.admin_api_key_hex,
    });
    await popup.reload();
    await popup.waitForSelector("#app");
    await expect(popup.locator("#connectedView")).toBeVisible({ timeout: 15_000 });
    // At least one usable signer present → no banner.
    await expect(popup.locator("#signerBanner")).toHaveClass(/hidden/);
    // Status dot is green.
    await expect(popup.locator("#connectionDot")).toHaveClass(/connected/);
    await popup.close();
  });
});
