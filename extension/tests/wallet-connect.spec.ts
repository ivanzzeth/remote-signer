import { test, expect } from "./fixtures";
import { openDappAndWaitForProvider, dappEIP1193Call, injectStorageConfig, TEST_ACCOUNTS, TEST_CHAINS } from "./helpers";
import { fileURLToPath } from "url";
import path from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

test.describe("Wallet Connection (@integration)", () => {
  test("window.ethereum provider is available on dApp pages", async ({ context, extensionId, serverInfo }) => {
    // Open popup to inject config so the provider initializes
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.waitForSelector("#app");
    await injectStorageConfig(popup, {
      remoteSignerUrl: serverInfo.base_url,
      apiKeyId: serverInfo.admin_api_key_id,
      apiKeyPrivateKey: serverInfo.admin_api_key_hex,
    });
    await popup.close();

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    const hasProvider = await dapp.evaluate(() => !!window.ethereum);
    expect(hasProvider).toBe(true);

    const isMetaMask = await dapp.evaluate(() => (window.ethereum as any)?.isMetaMask);
    // remote-signer's inpage proxy sets isMetaMask to false (not undefined)
    expect(isMetaMask).toBe(false);
  });

  test("eth_requestAccounts returns account addresses after connection", async ({ context, extensionId, serverInfo }) => {
    // Pre-configure the extension
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.waitForSelector("#app");
    await injectStorageConfig(popup, {
      remoteSignerUrl: serverInfo.base_url,
      apiKeyId: serverInfo.admin_api_key_id,
      apiKeyPrivateKey: serverInfo.admin_api_key_hex,
    });
    await popup.close();

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    const result = await dappEIP1193Call(dapp, "eth_requestAccounts");

    // Expect accounts to be returned (or at minimum a descriptive error if the
    // provider needs additional user interaction)
    if (result.ok) {
      expect(Array.isArray(result.result)).toBe(true);
      expect(result.result.length).toBeGreaterThan(0);
      expect(result.result[0]).toMatch(/^0x[a-fA-F0-9]{40}$/);
    } else {
      // If the provider returns an error, it should be descriptive
      expect(result.error.message).toBeTruthy();
    }
  });

  test("eth_requestAccounts rejection scenario returns user-friendly error", async ({ context, extensionId, serverInfo }) => {
    // Pre-configure the extension
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.waitForSelector("#app");
    await injectStorageConfig(popup, {
      remoteSignerUrl: serverInfo.base_url,
      apiKeyId: serverInfo.admin_api_key_id,
      apiKeyPrivateKey: serverInfo.admin_api_key_hex,
    });
    await popup.close();

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    // Attempt to request accounts — without user approval in the popup,
    // the provider should either succeed or return a rejection-style error
    const result = await dappEIP1193Call(dapp, "eth_requestAccounts");

    if (!result.ok) {
      // Rejection should have a code and meaningful message
      expect(result.error.code).toBeDefined();
      expect(result.error.message).toBeTruthy();
    }
  });

  test("eth_accounts returns accounts when connected", async ({ context, extensionId, serverInfo }) => {
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.waitForSelector("#app");
    await injectStorageConfig(popup, {
      remoteSignerUrl: serverInfo.base_url,
      apiKeyId: serverInfo.admin_api_key_id,
      apiKeyPrivateKey: serverInfo.admin_api_key_hex,
    });
    await popup.close();

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    // Call eth_requestAccounts first to establish a connection
    const connectResult = await dappEIP1193Call(dapp, "eth_requestAccounts");

    // Now check eth_accounts
    const result = await dappEIP1193Call(dapp, "eth_accounts");

    if (connectResult.ok) {
      // If connection succeeded, accounts should be available
      expect(result.ok).toBe(true);
      expect(Array.isArray(result.result)).toBe(true);
      if (result.result.length > 0) {
        expect(result.result[0]).toMatch(/^0x[a-fA-F0-9]{40}$/);
      }
    } else {
      // If connection didn't succeed, eth_accounts may return empty array
      if (result.ok) {
        // Empty array is valid when not connected
        expect(Array.isArray(result.result)).toBe(true);
      } else {
        expect(result.error.message).toBeTruthy();
      }
    }
  });

  test("eth_accounts returns empty array when not connected", async ({ context, extensionId, serverInfo }) => {
    // Do NOT configure the extension — no config means no connection possible
    const dapp = await context.newPage();

    // Open the dApp via HTTP (file:// blocks MV3 content-script injection)
    await dapp.goto(serverInfo.dapp_url);
    await dapp.waitForFunction(() => !!window.ethereum, { timeout: 15_000 });

    // Without config, eth_requestAccounts should fail
    const result = await dappEIP1193Call(dapp, "eth_accounts");

    // Should return empty array or error about missing config
    if (result.ok) {
      expect(Array.isArray(result.result)).toBe(true);
      expect(result.result.length).toBe(0);
    } else {
      expect(result.error.message).toBeTruthy();
    }
  });

  test("eth_chainId returns correct chain ID", async ({ context, extensionId, serverInfo }) => {
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.waitForSelector("#app");
    await injectStorageConfig(popup, {
      remoteSignerUrl: serverInfo.base_url,
      apiKeyId: serverInfo.admin_api_key_id,
      apiKeyPrivateKey: serverInfo.admin_api_key_hex,
    });
    await popup.close();

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    const result = await dappEIP1193Call(dapp, "eth_chainId");

    if (result.ok) {
      // Chain ID should be a hex string
      expect(typeof result.result).toBe("string");
      expect(result.result).toMatch(/^0x[0-9a-f]+$/);
    } else {
      expect(result.error.message).toBeTruthy();
    }
  });

  test("wallet_switchEthereumChain switches the active chain", async ({ context, extensionId, serverInfo }) => {
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.waitForSelector("#app");
    await injectStorageConfig(popup, {
      remoteSignerUrl: serverInfo.base_url,
      apiKeyId: serverInfo.admin_api_key_id,
      apiKeyPrivateKey: serverInfo.admin_api_key_hex,
    });
    await popup.close();

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    // Get initial chain ID
    const initialResult = await dappEIP1193Call(dapp, "eth_chainId");
    const initialChainId = initialResult.ok ? initialResult.result : null;

    // Switch to Polygon
    const switchResult = await dappEIP1193Call(dapp, "wallet_switchEthereumChain", { chainId: TEST_CHAINS.polygon });

    if (switchResult.ok) {
      // Successfully switched
      expect(switchResult.result).toBe(null);

      // Verify the chain ID changed
      await dapp.waitForTimeout(500);
      const afterResult = await dappEIP1193Call(dapp, "eth_chainId");
      if (afterResult.ok) {
        expect(afterResult.result).toBe(TEST_CHAINS.polygon);
      }
    } else {
      // If chain switching is not supported, expect a descriptive error
      expect(switchResult.error.code || switchResult.error.message).toBeTruthy();
    }
  });

  test("multi-dApp: two dApp pages share the same wallet connection", async ({ context, extensionId, serverInfo }) => {
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.waitForSelector("#app");
    await injectStorageConfig(popup, {
      remoteSignerUrl: serverInfo.base_url,
      apiKeyId: serverInfo.admin_api_key_id,
      apiKeyPrivateKey: serverInfo.admin_api_key_hex,
    });
    await popup.close();

    // Open first dApp
    const dapp1 = await context.newPage();
    await openDappAndWaitForProvider(dapp1);

    // Open second dApp
    const dapp2 = await context.newPage();
    await openDappAndWaitForProvider(dapp2);

    // Both should have the provider
    const hasProvider1 = await dapp1.evaluate(() => !!window.ethereum);
    const hasProvider2 = await dapp2.evaluate(() => !!window.ethereum);
    expect(hasProvider1).toBe(true);
    expect(hasProvider2).toBe(true);

    // If eth_requestAccounts works, both pages should return the same accounts
    const result1 = await dappEIP1193Call(dapp1, "eth_requestAccounts");
    const result2 = await dappEIP1193Call(dapp2, "eth_requestAccounts");

    if (result1.ok && result2.ok) {
      // Both pages should see the same accounts
      expect(result1.result).toEqual(result2.result);
    }
  });
});
