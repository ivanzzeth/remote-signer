/**
 * Chain persistence regression.
 *
 * The user-reported "Polymarket Request Cancelled after manual approval"
 * was actually a wagmi ConnectorChainMismatchError: Polymarket cached the
 * session expecting chain 137 (Polygon) but our extension was still
 * reporting chain 1 because chain switches weren't persisted across
 * MV3 service-worker suspensions.
 *
 * This test locks the behaviour: any wallet_switchEthereumChain call
 * MUST write the new chain id to chrome.storage.local so the next SW
 * boot reads it back. We approximate the SW restart by closing all
 * pages and reopening the popup — the popup reads selectedChain from
 * storage and shows the persisted value.
 */
import { test, expect, type BrowserContext } from "./fixtures";
import {
  injectStorageConfig,
  openDappAndWaitForProvider,
  dappEIP1193Call,
  TEST_CHAINS,
} from "./helpers";

async function setupContext(context: BrowserContext, extensionId: string, serverInfo: any) {
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
  await popup.waitForSelector("#app");
  await injectStorageConfig(popup, {
    remoteSignerUrl: serverInfo.base_url,
    apiKeyId: serverInfo.admin_api_key_id,
    apiKeyPrivateKey: serverInfo.admin_api_key_hex,
  });
  await popup.close();
}

test.describe("Chain persistence across SW restart (@integration)", () => {
  test("wallet_switchEthereumChain to Polygon persists into chrome.storage.local", async ({ context, extensionId, serverInfo }) => {
    await setupContext(context, extensionId, serverInfo);

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    // Sanity: initial chain matches the seeded default (1 = Ethereum).
    const initial = await dappEIP1193Call(dapp, "eth_chainId");
    expect(initial.ok).toBe(true);
    expect(initial.result).toBe(TEST_CHAINS.ethereum);

    // dApp triggers a switch (this is what Polymarket does).
    const switched = await dappEIP1193Call(dapp, "wallet_switchEthereumChain", { chainId: TEST_CHAINS.polygon });
    expect(switched.ok, `switch failed: ${!switched.ok ? switched.error.message : ""}`).toBe(true);

    // The chainChanged listener writes back asynchronously — give it a tick.
    await dapp.waitForTimeout(500);

    // Read straight from chrome.storage.local from the dApp page; the
    // popup origin shares the same extension-storage namespace, but
    // popup-side storage access from a content-script page is denied,
    // so we re-open the popup to inspect.
    const popup2 = await context.newPage();
    await popup2.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup2.waitForSelector("#app");
    const storedChain = await popup2.evaluate(() =>
      new Promise<number>((resolve) =>
        chrome.storage.local.get("remoteSignerConfig", (r) => resolve(r.remoteSignerConfig?.selectedChain))
      )
    );
    expect(storedChain).toBe(137);
    await popup2.close();
    await dapp.close();
  });

  test("after a popup reopen, the persisted chain is the one queried over EIP-1193", async ({ context, extensionId, serverInfo }) => {
    await setupContext(context, extensionId, serverInfo);

    // Switch first.
    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);
    const switched = await dappEIP1193Call(dapp, "wallet_switchEthereumChain", { chainId: TEST_CHAINS.polygon });
    expect(switched.ok).toBe(true);
    await dapp.waitForTimeout(500);
    await dapp.close();

    // Open a fresh dApp tab — the inpage proxy syncs state from the SW
    // via the initial getState round-trip. If persistence works, this
    // page should see chainId = 137 from the very first eth_chainId.
    const dapp2 = await context.newPage();
    await openDappAndWaitForProvider(dapp2);
    const after = await dappEIP1193Call(dapp2, "eth_chainId");
    expect(after.ok).toBe(true);
    expect(after.result).toBe(TEST_CHAINS.polygon);
    await dapp2.close();
  });
});
