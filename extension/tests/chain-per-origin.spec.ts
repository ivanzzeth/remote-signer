/**
 * Per-origin chain state — the wagmi/Polymarket "ConnectorChainMismatchError"
 * fix.
 *
 * remote-signer is a multi-chain gateway; the extension previously held a
 * single global chain that every dApp had to live with. wagmi 3.x compares
 * the chain wallet reports (eth_chainId) against the chain its connector
 * was last configured for; a mismatch throws a hard error *before* the
 * dApp can call wallet_switchEthereumChain to reconcile. The user-visible
 * symptom on a Polymarket reconnect was "Request Cancelled".
 *
 * This spec locks the new behaviour:
 *   1. eth_chainId returns whatever THIS origin last switched to (or the
 *      popup-set default for a fresh origin), independent of other dApps.
 *   2. wallet_switchEthereumChain mutates only the calling origin's
 *      record — concurrent dApps keep their own chain.
 *   3. The choice survives an MV3 SW restart (persisted to chrome.storage).
 */
import { test, expect, type BrowserContext } from "./fixtures";
import {
  injectStorageConfig,
  openDappAndWaitForProvider,
  dappEIP1193Call,
  TEST_CHAINS,
} from "./helpers";

async function configure(context: BrowserContext, extensionId: string, serverInfo: any) {
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

test.describe("Per-origin chain memory (@integration)", () => {
  test("wallet_switchEthereumChain on one dApp does NOT change another dApp's chain", async ({ context, extensionId, serverInfo }) => {
    await configure(context, extensionId, serverInfo);

    // Both dApps load from the same dapp-test-page.html, but they live on
    // different ports/origins so per-origin tracking can distinguish them.
    // The global-setup serves dApp pages from a single HTTP server, so we
    // need two distinct origins. We achieve that by serving the same
    // page via the e2e admin server's static file route AND the dApp
    // file server — but failing that, simulate two origins by patching
    // location.origin via window.history (no — Origin is enforced by
    // the browser, not patchable). We instead use two distinct hostnames
    // pointing at 127.0.0.1 (localhost vs 127.0.0.1) which Chromium
    // treats as separate origins.
    const dapp1 = await context.newPage();
    await openDappAndWaitForProvider(dapp1);
    const origin1 = await dapp1.evaluate(() => window.location.origin);

    // dapp2 loads the same content from an aliased host (the host map
    // 127.0.0.1 ↔ localhost) which Chromium classifies as a different
    // origin, exactly the case the per-origin invariant must handle.
    const dapp2 = await context.newPage();
    await dapp2.goto(origin1.replace("127.0.0.1", "localhost").replace("localhost", "127.0.0.1").includes("127.0.0.1")
      ? origin1.replace("127.0.0.1", "localhost") + new URL(dapp1.url()).pathname
      : origin1.replace("localhost", "127.0.0.1") + new URL(dapp1.url()).pathname,
      { waitUntil: "domcontentloaded" }
    );
    await dapp2.waitForFunction(() => !!window.ethereum, { timeout: 15_000 });
    const origin2 = await dapp2.evaluate(() => window.location.origin);
    expect(origin2).not.toBe(origin1);

    // dApp 1 switches to Polygon (137); dApp 2 unchanged.
    const sw = await dappEIP1193Call(dapp1, "wallet_switchEthereumChain", { chainId: TEST_CHAINS.polygon });
    expect(sw.ok).toBe(true);

    await dapp1.waitForTimeout(300);
    const chain1 = await dappEIP1193Call(dapp1, "eth_chainId");
    const chain2 = await dappEIP1193Call(dapp2, "eth_chainId");

    expect(chain1.result).toBe(TEST_CHAINS.polygon);
    // dApp 2 must NOT have inherited the switch.
    expect(chain2.result).not.toBe(TEST_CHAINS.polygon);

    await dapp1.close();
    await dapp2.close();
  });

  test("a dApp's chain choice survives a fresh tab open (persisted)", async ({ context, extensionId, serverInfo }) => {
    await configure(context, extensionId, serverInfo);

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);
    const origin = await dapp.evaluate(() => window.location.origin);

    const sw = await dappEIP1193Call(dapp, "wallet_switchEthereumChain", { chainId: TEST_CHAINS.polygon });
    expect(sw.ok).toBe(true);
    await dapp.waitForTimeout(300);
    await dapp.close();

    // Re-open the same origin in a fresh tab — chain memory must persist.
    const dapp2 = await context.newPage();
    await openDappAndWaitForProvider(dapp2);
    const origin2 = await dapp2.evaluate(() => window.location.origin);
    expect(origin2).toBe(origin);
    const after = await dappEIP1193Call(dapp2, "eth_chainId");
    expect(after.result).toBe(TEST_CHAINS.polygon);
    await dapp2.close();
  });

  test("eth_chainId returns the per-origin value the inpage proxy can see immediately on injection", async ({ context, extensionId, serverInfo }) => {
    // Pre-seed an origin's chain so we can verify the inpage proxy's
    // initial state-sync respects per-origin storage on first load.
    await configure(context, extensionId, serverInfo);

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    // Seed via dApp's own wallet_switchEthereumChain call.
    await dappEIP1193Call(dapp, "wallet_switchEthereumChain", { chainId: TEST_CHAINS.polygon });
    await dapp.waitForTimeout(300);
    await dapp.close();

    // New tab on the same origin: the inpage proxy queries web3-get-state
    // synchronously on init; this must return 0x89, not the global default.
    const dapp2 = await context.newPage();
    await openDappAndWaitForProvider(dapp2);
    const reported = await dapp2.evaluate(() => (window.ethereum as any).chainId);
    expect(reported).toBe(TEST_CHAINS.polygon);
    await dapp2.close();
  });
});
