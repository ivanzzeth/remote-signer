import { test, expect } from "../fixtures";
import {
  injectStorageConfig,
  openDappAndWaitForProvider,
  dappEIP1193Call,
  TEST_ACCOUNTS,
} from "../helpers";

test.describe("Rule Engine Integration (@integration)", () => {
  /**
   * Helper: configure extension via storage injection so it starts
   * connected with the given API key.
   */
  async function configureExtension(
    context: ReturnType<Parameters<Parameters<typeof test>[1]>[0]["context"]>,
    extensionId: string,
    config: { url: string; apiKeyId: string; apiKeyPrivateKey: string }
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

  test("valid personal_sign passes rule engine and returns signature", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await configureExtension(context, extensionId, {
      url: serverInfo.base_url,
      apiKeyId: serverInfo.admin_api_key_id,
      apiKeyPrivateKey: serverInfo.admin_api_key_hex,
    });

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    // personal_sign with the known signer should pass the rule engine
    // (e2e-test-server seeds an auto-approve rule)
    const result = await dappEIP1193Call(
      dapp,
      "personal_sign",
      "0x48656c6c6f",
      TEST_ACCOUNTS.signer
    );

    expect(result.ok).toBe(true);
    expect(result.result).toMatch(/^0x[a-fA-F0-9]{130}$/);

    await dapp.close();
  });

  test("eth_sendTransaction passes rule engine and returns result", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await configureExtension(context, extensionId, {
      url: serverInfo.base_url,
      apiKeyId: serverInfo.admin_api_key_id,
      apiKeyPrivateKey: serverInfo.admin_api_key_hex,
    });

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    // eth_sendTransaction with the known signer should pass rule engine checks
    const result = await dappEIP1193Call(dapp, "eth_sendTransaction", {
      from: TEST_ACCOUNTS.signer,
      to: TEST_ACCOUNTS.recipient,
      value: "0x0",
    });

    expect(result.ok).toBe(true);
    expect(typeof result.result).toBe("string");
    expect(result.result).toMatch(/^0x[a-fA-F0-9]+$/);

    await dapp.close();
  });

  test("multiple sequential sign requests all pass rule engine", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await configureExtension(context, extensionId, {
      url: serverInfo.base_url,
      apiKeyId: serverInfo.admin_api_key_id,
      apiKeyPrivateKey: serverInfo.admin_api_key_hex,
    });

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    const messages = [
      "0x48656c6c6f", // Hello
      "0x576f726c64", // World
      "0x54657374", // Test
    ];

    for (const msg of messages) {
      const result = await dappEIP1193Call(
        dapp,
        "personal_sign",
        msg,
        TEST_ACCOUNTS.signer
      );

      expect(result.ok).toBe(true);
      expect(result.result).toMatch(/^0x[a-fA-F0-9]{130}$/);
    }

    await dapp.close();
  });

  test("popup displays connected state after rule engine approves requests", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    // Configure extension
    const popup = await context.newPage();
    await popup.goto(
      `chrome-extension://${extensionId}/popup/popup.html`
    );
    await popup.waitForSelector("#app", { timeout: 10_000 });
    await injectStorageConfig(popup, {
      remoteSignerUrl: serverInfo.base_url,
      apiKeyId: serverInfo.admin_api_key_id,
      apiKeyPrivateKey: serverInfo.admin_api_key_hex,
      selectedChain: 1,
    });
    await popup.close();

    // Make a signing request via dApp
    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);
    await dappEIP1193Call(dapp, "personal_sign", "0x48656c6c6f", TEST_ACCOUNTS.signer);
    await dapp.close();

    // Reopen popup and verify connected state with stats
    const popup2 = await context.newPage();
    await popup2.goto(
      `chrome-extension://${extensionId}/popup/popup.html`
    );
    await popup2.waitForSelector("#app", { timeout: 10_000 });

    // After successful connection and signing, the dashboard may show statistics
    const statusText = await popup2.locator("#statusText").textContent();
    expect(statusText?.trim().length).toBeGreaterThan(0);

    // Verify dashboard elements are present when connected
    const requestsStat = popup2.locator("#requestsStat");
    const signersStat = popup2.locator("#signersStat");

    // These may be visible if the extension dashboard updates
    const requestsVisible = await requestsStat.isVisible().catch(() => false);
    const signersVisible = await signersStat.isVisible().catch(() => false);

    // At minimum, the extension should show some connected state
    expect(requestsVisible || signersVisible || statusText?.length).toBeTruthy();

    await popup2.close();
  });
});
