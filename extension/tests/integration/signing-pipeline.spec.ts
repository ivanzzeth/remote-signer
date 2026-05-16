import { test, expect } from "../fixtures";
import {
  injectStorageConfig,
  openDappAndWaitForProvider,
  dappEIP1193Call,
  TEST_ACCOUNTS,
} from "../helpers";

test.describe("Signing Pipeline (@integration)", () => {
  /**
   * Pre-configure the extension using injectStorageConfig via an extension page.
   * The config is written to chrome.storage.local so the service worker picks it up.
   */
  async function preConfigureExtension(
    context: ReturnType<test["info"]> extends { config: any }
      ? never
      : ReturnType<Parameters<Parameters<typeof test>[1]>[0]["context"]>,
    extensionId: string,
    serverInfo: { base_url: string; admin_api_key_id: string; admin_api_key_hex: string }
  ): Promise<void> {
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
  }

  test("full signing pipeline: personal_sign via extension returns valid signature", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await preConfigureExtension(context, extensionId, serverInfo);

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    const message = "0x48656c6c6f"; // "Hello" in hex
    const result = await dappEIP1193Call(
      dapp,
      "personal_sign",
      message,
      TEST_ACCOUNTS.signer
    );

    expect(result.ok).toBe(true);
    // Signature format: 0x + 130 hex chars (r=64, s=64, v=2)
    expect(result.result).toMatch(/^0x[a-fA-F0-9]{130}$/);

    await dapp.close();
  });

  test("provider returns correct chain ID via extension pipeline", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await preConfigureExtension(context, extensionId, serverInfo);

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    const result = await dappEIP1193Call(dapp, "eth_chainId");

    expect(result.ok).toBe(true);
    expect(result.result).toBe("0x1");

    await dapp.close();
  });

  test("eth_sendTransaction returns valid tx hash through pipeline", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await preConfigureExtension(context, extensionId, serverInfo);

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    const result = await dappEIP1193Call(dapp, "eth_sendTransaction", {
      from: TEST_ACCOUNTS.signer,
      to: TEST_ACCOUNTS.recipient,
      value: "0x0",
    });

    expect(result.ok).toBe(true);
    // Response should be a hex-prefixed hash or signed raw transaction
    expect(typeof result.result).toBe("string");
    expect(result.result).toMatch(/^0x[a-fA-F0-9]+$/);

    await dapp.close();
  });

  test("eth_accounts exposes the signer address", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await preConfigureExtension(context, extensionId, serverInfo);

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    const result = await dappEIP1193Call(dapp, "eth_accounts");

    expect(result.ok).toBe(true);
    expect(Array.isArray(result.result)).toBe(true);
    expect(result.result.length).toBeGreaterThanOrEqual(1);

    // The returned address should be a valid Ethereum address
    expect(result.result[0]).toMatch(/^0x[a-fA-F0-9]{40}$/);

    await dapp.close();
  });
});
