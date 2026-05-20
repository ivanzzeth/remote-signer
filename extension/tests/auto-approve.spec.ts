/**
 * Auto-approve mode (the production default).
 *
 * Power-users want zero per-site prompts — they trust the dApps they
 * visit and just want the wallet to hand over the active signer + the
 * chain they've set in the popup chip. autoApproveConnections=true is
 * the DEFAULT_CONFIG default, so a fresh install of the extension just
 * works without ever showing the Connect popup.
 *
 * These specs lock that behaviour: no chrome.windows.create fires
 * during eth_requestAccounts, the permission record IS still written
 * (so subsequent reads + revocation still work), and the chain comes
 * from the popup's selected default.
 */
import { test, expect, type BrowserContext } from "./fixtures";
import {
  openDappWithoutPermission,
  dappEIP1193Call,
  TEST_CHAINS,
} from "./helpers";

async function configureAutoApprove(
  context: BrowserContext,
  extensionId: string,
  serverInfo: any,
  opts: { selectedChain?: number } = {}
) {
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
  await popup.waitForSelector("#app");
  await popup.evaluate((cfg) => {
    return new Promise<void>((resolve) =>
      chrome.storage.local.set({ remoteSignerConfig: cfg }, () => resolve())
    );
  }, {
    remoteSignerUrl: serverInfo.base_url,
    apiKeyId: serverInfo.admin_api_key_id,
    apiKeyPrivateKey: serverInfo.admin_api_key_hex,
    selectedChain: opts.selectedChain ?? 1,
    autoApproveConnections: true,
  });
  // Wipe any prior permission record so we're testing the
  // first-time-grant code path.
  await popup.evaluate(() => {
    return new Promise<void>((resolve) =>
      chrome.storage.local.remove("remote-signer:permittedOrigins", () => resolve())
    );
  });
  await popup.evaluate(() => {
    return new Promise<void>((resolve) =>
      chrome.storage.local.remove("remote-signer:chainByOrigin", () => resolve())
    );
  });
  await popup.close();
}

test.describe("Auto-approve mode (@integration)", () => {
  test.describe.configure({ mode: "serial" });

  test("eth_requestAccounts grants immediately — no Connect popup spawned", async ({ context, extensionId, serverInfo }) => {
    await configureAutoApprove(context, extensionId, serverInfo, { selectedChain: 1 });

    const dapp = await context.newPage();
    await openDappWithoutPermission(dapp);

    // Watch the context for new pages. If autoApprove is on we must
    // see NONE — the eth_requestAccounts call should settle without
    // ever opening the Connect window.
    const newPages: string[] = [];
    const onPage = (p: any) => newPages.push(p.url());
    context.on("page", onPage);

    const accounts = await dappEIP1193Call(dapp, "eth_requestAccounts");
    await dapp.waitForTimeout(200);
    context.off("page", onPage);

    expect(accounts.ok).toBe(true);
    expect((accounts.result as string[]).length).toBeGreaterThan(0);
    expect((accounts.result as string[])[0].toLowerCase()).toBe(serverInfo.signer_address.toLowerCase());
    const connectWindows = newPages.filter((u) => u.includes("/popup/connect.html"));
    expect(connectWindows).toEqual([]);

    await dapp.close();
  });

  test("granted chain matches the popup's selectedChain at the moment of approval", async ({ context, extensionId, serverInfo }) => {
    // Pre-set the popup's default to Polygon and expect any new origin
    // to come up on 137 — same UX as MetaMask-on-Polygon -> Polymarket.
    await configureAutoApprove(context, extensionId, serverInfo, {
      selectedChain: parseInt(TEST_CHAINS.polygon, 16),
    });

    const dapp = await context.newPage();
    await openDappWithoutPermission(dapp);
    await dappEIP1193Call(dapp, "eth_requestAccounts");
    await dapp.waitForTimeout(200);

    const chain = await dappEIP1193Call(dapp, "eth_chainId");
    expect(chain.ok).toBe(true);
    expect(chain.result).toBe(TEST_CHAINS.polygon);
    await dapp.close();
  });

  test("turning auto-approve off reinstates the Connect prompt", async ({ context, extensionId, serverInfo }) => {
    test.setTimeout(60_000);
    // Persist autoApproveConnections=false directly. Toggling via the
    // popup UI is exercised end-to-end in popup-ui.spec.ts; here we
    // just need the wire-level effect.
    const setup = await context.newPage();
    await setup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await setup.waitForSelector("#app");
    await setup.evaluate((cfg) => {
      return new Promise<void>((resolve) =>
        chrome.storage.local.set({ remoteSignerConfig: cfg }, () => resolve())
      );
    }, {
      remoteSignerUrl: serverInfo.base_url,
      apiKeyId: serverInfo.admin_api_key_id,
      apiKeyPrivateKey: serverInfo.admin_api_key_hex,
      selectedChain: 1,
      autoApproveConnections: false,
    });
    await setup.evaluate(() => {
      return new Promise<void>((resolve) =>
        chrome.storage.local.remove("remote-signer:permittedOrigins", () => resolve())
      );
    });
    await setup.close();

    const dapp = await context.newPage();
    await openDappWithoutPermission(dapp);

    // With autoApprove=false, eth_requestAccounts blocks on the Connect
    // popup. The popup-type chrome.windows.create surface is visible to
    // Playwright via context.pages() (occasionally racing with `page`
    // events, so we poll-then-assert instead of waitForEvent).
    void dapp.evaluate(() =>
      window.ethereum!.request({ method: "eth_requestAccounts" }).catch(() => {})
    );
    let connectPage: import("@playwright/test").Page | undefined;
    for (let i = 0; i < 30 && !connectPage; i++) {
      await dapp.waitForTimeout(500);
      connectPage = context.pages().find((p) => p.url().includes("/popup/connect.html"));
    }
    expect(connectPage, "Connect popup never appeared in context.pages()").toBeTruthy();
    expect(connectPage!.url()).toContain("/popup/connect.html");

    // Cancel to clean up the dApp's hanging RPC promise. Use Promise.race
    // so the test never blocks indefinitely if the popup or dApp tab
    // misbehaves.
    await Promise.race([
      (async () => {
        await connectPage!.locator("#cancelBtn").click().catch(() => {});
        await connectPage!.waitForEvent("close", { timeout: 3000 }).catch(() => {});
      })(),
      new Promise<void>((r) => setTimeout(r, 5000)),
    ]);
    await dapp.close().catch(() => {});
  });
});
