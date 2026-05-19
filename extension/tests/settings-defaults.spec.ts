/**
 * Settings-form defaults and the "Load from file…" helper.
 *
 * The extension targets a `remote-signer` instance that ships a default
 * `agent` API key under `~/.remote-signer/apikeys/agent.key.priv`. The
 * popup's onboarding pre-fills the `API Key ID` field with "agent" and
 * lets the user load the private key from disk with a single click,
 * so first-run never requires typing the role name or pasting hex.
 */
import { test, expect } from "./fixtures";

test.describe("Settings defaults & key-file loader (@integration)", () => {
  test("fresh popup pre-fills 'agent' in the API Key ID field", async ({ context, extensionId }) => {
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.waitForSelector("#app");

    // Disconnected view is the entry state for an unconfigured extension.
    await expect(popup.locator("#disconnectedView")).toBeVisible();
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();

    await expect(popup.locator("#inputKeyId")).toHaveValue("agent");
    await expect(popup.locator("#inputPrivateKey")).toHaveValue("");

    await popup.close();
  });

  test("'Load from file…' button fills the textarea with the file contents", async ({ context, extensionId, serverInfo }) => {
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.waitForSelector("#app");
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();

    // Use a real key (the seeded admin one) so a subsequent Save would
    // succeed; here we only assert the load path itself.
    const keyText = serverInfo.admin_api_key_hex;
    await popup.setInputFiles("#keyFileInput", {
      name: "agent.key.priv",
      mimeType: "text/plain",
      buffer: Buffer.from(keyText + "\n", "utf-8"),
    });

    await expect(popup.locator("#inputPrivateKey")).toHaveValue(keyText);
    // Loading the file un-masks the textarea so the user can verify what
    // landed; the toggle button label flips to "Hide".
    await expect(popup.locator("#togglePwBtn")).toHaveText("Hide");

    await popup.close();
  });

  test("loaded key + default ID + URL Save reaches the connected view", async ({ context, extensionId, serverInfo }) => {
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.waitForSelector("#app");
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();

    // Default ID stays as "agent" — we only need to supply URL + load the key
    // file. This is the intended single-keystroke-free onboarding flow.
    await popup.fill("#inputUrl", serverInfo.base_url);
    await popup.fill("#inputKeyId", serverInfo.admin_api_key_id);
    await popup.setInputFiles("#keyFileInput", {
      name: "agent.key.priv",
      mimeType: "text/plain",
      buffer: Buffer.from(serverInfo.admin_api_key_hex, "utf-8"),
    });
    await expect(popup.locator("#inputPrivateKey")).toHaveValue(serverInfo.admin_api_key_hex);

    await popup.click("#saveConfigBtn");
    await expect(popup.locator("#connectedView")).toBeVisible({ timeout: 15_000 });
    await expect(popup.locator("#statusText")).toHaveText("Connected");

    await popup.close();
  });
});
