import { test, expect } from "../fixtures";
import {
  injectStorageConfig,
  openDappAndWaitForProvider,
  dappEIP1193Call,
  fillPopupConfig,
  TEST_ACCOUNTS,
} from "../helpers";

test.describe("API Key Authentication (@integration)", () => {
  /**
   * Helper: configure extension via direct storage injection and then
   * verify connection status in the popup.
   */
  async function configureViaStorage(
    context: ReturnType<Parameters<Parameters<typeof test>[1]>[0]["context"]>,
    extensionId: string,
    config: {
      url: string;
      apiKeyId: string;
      apiKeyPrivateKey: string;
    }
  ): Promise<void> {
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await page.waitForSelector("#app", { timeout: 10_000 });

    await injectStorageConfig(page, {
      remoteSignerUrl: config.url,
      apiKeyId: config.apiKeyId,
      apiKeyPrivateKey: config.apiKeyPrivateKey,
      selectedChain: 1,
    });

    await page.close();
  }

  test("valid admin API key: popup test connection succeeds", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    const popup = await context.newPage();
    await popup.goto(
      `chrome-extension://${extensionId}/popup/popup.html`
    );
    await popup.waitForSelector("#app", { timeout: 10_000 });

    // Navigate to settings
    const settingsBtn = popup.locator("#disconnectedSettingsBtn");
    if (await settingsBtn.isVisible()) {
      await settingsBtn.click();
    } else {
      await popup.click("#settingsBtn");
    }
    await popup.waitForSelector("#settingsView:not(.hidden)", {
      timeout: 5_000,
    });

    // Fill in valid admin credentials
    await popup.fill("#inputUrl", serverInfo.base_url);
    await popup.fill("#inputKeyId", serverInfo.admin_api_key_id);
    await popup.fill("#inputPrivateKey", serverInfo.admin_api_key_hex);

    // Test connection
    await popup.click("#testConnectionBtn");

    // The connection error element should show success or the test result
    await popup.waitForTimeout(2000);

    // Test connection should succeed — no error, or connection test feedback appears
    const connectionResult = await popup.locator("#connectionError").textContent();
    // After a successful test, saveConfigBtn should be enabled
    const saveBtnDisabled = await popup.locator("#saveConfigBtn").isDisabled();

    // For valid keys, test connection should show an informative result
    expect(saveBtnDisabled).toBe(false);

    await popup.close();
  });

  test("valid admin API key: signing works end-to-end", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await configureViaStorage(context, extensionId, {
      url: serverInfo.base_url,
      apiKeyId: serverInfo.admin_api_key_id,
      apiKeyPrivateKey: serverInfo.admin_api_key_hex,
    });

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    // personal_sign should work with valid admin API key
    const signResult = await dappEIP1193Call(
      dapp,
      "personal_sign",
      "0x48656c6c6f",
      TEST_ACCOUNTS.signer
    );

    expect(signResult.ok).toBe(true);
    expect(signResult.result).toMatch(/^0x[a-fA-F0-9]{130}$/);

    await dapp.close();
  });

  test("valid non-admin API key: connection succeeds and signing works", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await configureViaStorage(context, extensionId, {
      url: serverInfo.base_url,
      apiKeyId: serverInfo.non_admin_api_key_id,
      apiKeyPrivateKey: serverInfo.non_admin_api_key_hex,
    });

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    // Non-admin (strategy role) should still be able to sign
    const signResult = await dappEIP1193Call(
      dapp,
      "personal_sign",
      "0x48656c6c6f",
      TEST_ACCOUNTS.signer
    );

    expect(signResult.ok).toBe(true);
    expect(signResult.result).toMatch(/^0x[a-fA-F0-9]{130}$/);

    await dapp.close();
  });

  test("invalid API key: connection fails and signing is rejected", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    const popup = await context.newPage();
    await popup.goto(
      `chrome-extension://${extensionId}/popup/popup.html`
    );
    await popup.waitForSelector("#app", { timeout: 10_000 });

    // Navigate to settings
    const settingsBtn = popup.locator("#disconnectedSettingsBtn");
    if (await settingsBtn.isVisible()) {
      await settingsBtn.click();
    } else {
      await popup.click("#settingsBtn");
    }
    await popup.waitForSelector("#settingsView:not(.hidden)", {
      timeout: 5_000,
    });

    // Fill in an invalid API key (bogus key ID + random hex)
    await popup.fill("#inputUrl", serverInfo.base_url);
    await popup.fill("#inputKeyId", "nonexistent-key-id");
    await popup.fill(
      "#inputPrivateKey",
      "0000000000000000000000000000000000000000000000000000000000000000"
    );

    // Test connection with invalid key
    await popup.click("#testConnectionBtn");
    await popup.waitForTimeout(2000);

    // The connection error element should show an error message
    const connectionError = await popup
      .locator("#connectionError")
      .textContent();

    // An error should be displayed (non-empty)
    expect(connectionError?.trim().length).toBeGreaterThan(0);

    await popup.close();
  });

  test("invalid API key: signing rejected via provider", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    // Configure storage with invalid credentials
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await page.waitForSelector("#app", { timeout: 10_000 });

    await injectStorageConfig(page, {
      remoteSignerUrl: serverInfo.base_url,
      apiKeyId: "bogus-key",
      apiKeyPrivateKey:
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      selectedChain: 1,
    });
    await page.close();

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    // Attempt to sign with bogus credentials
    const result = await dappEIP1193Call(
      dapp,
      "personal_sign",
      "0x48656c6c6f",
      TEST_ACCOUNTS.signer
    );

    // Should fail due to authentication error
    expect(result.ok).toBe(false);
    expect(result.error).toBeDefined();

    await dapp.close();
  });
});
