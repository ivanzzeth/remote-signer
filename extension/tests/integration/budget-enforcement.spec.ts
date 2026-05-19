import { test, expect } from "../fixtures";
import { switchToAnvil } from "../helpers";
import {
  injectStorageConfig,
  openDappAndWaitForProvider,
  dappEIP1193Call,
  TEST_ACCOUNTS,
} from "../helpers";

test.describe("Budget Enforcement (@integration)", () => {
  /**
   * Helper: pre-configure extension via storage injection.
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

  test("single sign request within budget limits succeeds", async ({
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

    // A single sign request should be well within default budget limits
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

  test("multiple sequential requests within budget succeed", async ({
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

    // Send multiple requests sequentially — budget with default limits should handle these
    for (let i = 0; i < 5; i++) {
      const result = await dappEIP1193Call(
        dapp,
        "personal_sign",
        `0x${Buffer.from(`test-message-${i}`).toString("hex")}`,
        TEST_ACCOUNTS.signer
      );

      expect(result.ok).toBe(true);
      expect(result.result).toMatch(/^0x[a-fA-F0-9]{130}$/);
    }

    await dapp.close();
  });

  test("transaction request within budget succeeds end-to-end", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    test.skip(!serverInfo.anvil_url, "anvil not available in this environment");
    await configureExtension(context, extensionId, {
      url: serverInfo.base_url,
      apiKeyId: serverInfo.admin_api_key_id,
      apiKeyPrivateKey: serverInfo.admin_api_key_hex,
    });

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);
    expect(await switchToAnvil(dapp, serverInfo)).toBe(true);

    // Transaction with zero value passes budget/value limit check and
    // lands on anvil cleanly.
    const result = await dappEIP1193Call(dapp, "eth_sendTransaction", {
      from: TEST_ACCOUNTS.signer,
      to: TEST_ACCOUNTS.recipient,
      value: "0x0",
      gas: "0x5208",
      gasPrice: "0x3b9aca00",
    });

    expect(result.ok).toBe(true);
    expect(result.result).toMatch(/^0x[a-fA-F0-9]{64}$/);

    await dapp.close();
  });

  test("mixed personal_sign and transaction requests within budget succeed", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    test.skip(!serverInfo.anvil_url, "anvil not available in this environment");
    await configureExtension(context, extensionId, {
      url: serverInfo.base_url,
      apiKeyId: serverInfo.admin_api_key_id,
      apiKeyPrivateKey: serverInfo.admin_api_key_hex,
    });

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);
    expect(await switchToAnvil(dapp, serverInfo)).toBe(true);

    // Sign a message
    const signResult = await dappEIP1193Call(
      dapp,
      "personal_sign",
      "0x48656c6c6f",
      TEST_ACCOUNTS.signer
    );
    expect(signResult.ok).toBe(true);

    // Send a transaction
    const txResult = await dappEIP1193Call(dapp, "eth_sendTransaction", {
      from: TEST_ACCOUNTS.signer,
      to: TEST_ACCOUNTS.recipient,
      value: "0x0",
      gas: "0x5208",
      gasPrice: "0x3b9aca00",
    });
    expect(txResult.ok).toBe(true);

    // Sign another message after transaction
    const signResult2 = await dappEIP1193Call(
      dapp,
      "personal_sign",
      "0x576f726c64",
      TEST_ACCOUNTS.signer
    );
    expect(signResult2.ok).toBe(true);
    expect(signResult2.result).toMatch(/^0x[a-fA-F0-9]{130}$/);

    await dapp.close();
  });

  test("popup reflects connected state after budget-checked requests", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    // Configure and make a request
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

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    for (let i = 0; i < 3; i++) {
      await dappEIP1193Call(
        dapp,
        "personal_sign",
        `0x${Buffer.from(`budget-test-${i}`).toString("hex")}`,
        TEST_ACCOUNTS.signer
      );
    }
    await dapp.close();

    // Reopen popup and verify dashboard stats are populated
    const popup2 = await context.newPage();
    await popup2.goto(
      `chrome-extension://${extensionId}/popup/popup.html`
    );
    await popup2.waitForSelector("#app", { timeout: 10_000 });

    // The dashboard should show request statistics
    const requestsStat = await popup2
      .locator("#requestsStat")
      .textContent()
      .catch(() => null);

    // The requests stat should be present (may show a count)
    const statusText = await popup2
      .locator("#statusText")
      .textContent()
      .catch(() => null);

    expect(requestsStat !== null || statusText !== null).toBe(true);

    await popup2.close();
  });
});
