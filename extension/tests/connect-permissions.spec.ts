/**
 * EIP-2255 permission system + Connect popup window.
 *
 * Before this change our extension auto-granted account access to every
 * page that asked, which bypassed the connect-time chain selection
 * MetaMask 12+ exposes. The Polymarket failure mode was downstream of
 * that: the dApp never had a chance to drive the wallet onto chain 137
 * so the SIWE text baked in chain 1 and Polymarket's auth API 401'd.
 *
 * These specs pin the new semantics:
 *   1. A fresh origin sees [] from eth_accounts (no permission yet).
 *   2. eth_requestAccounts spawns a Connect popup window owned by the
 *      service worker. Approving it grants accounts AND records the
 *      chain the user picked. Subsequent eth_chainId on that origin
 *      returns the chosen chain.
 *   3. Cancelling the popup rejects the RPC with EIP-1193 code 4001.
 *   4. wallet_revokePermissions clears the record so a later
 *      eth_accounts reverts to [].
 */
import { test, expect, type BrowserContext, type Page } from "./fixtures";
import {
  openDappWithoutPermission,
  dappEIP1193Call,
  TEST_CHAINS,
} from "./helpers";

async function preConfigureWithoutGrant(
  context: BrowserContext,
  extensionId: string,
  serverInfo: any
) {
  // Disable auto-approve AND skip the helper's pre-grant so the Connect
  // popup actually fires for these specs. Production default is
  // autoApproveConnections=true (no popup) — that path is exercised by
  // the auto-approve specs further down.
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
    selectedChain: 1,
    autoApproveConnections: false,
  });
  await popup.evaluate(() => {
    return new Promise<void>((resolve) =>
      chrome.storage.local.remove("remote-signer:permittedOrigins", () => resolve())
    );
  });
  await popup.close();
}

test.describe("EIP-2255 permissions + Connect popup (@integration)", () => {
  test.describe.configure({ mode: "serial" });

  test("a fresh origin sees an empty eth_accounts", async ({ context, extensionId, serverInfo }) => {
    await preConfigureWithoutGrant(context, extensionId, serverInfo);

    const dapp = await context.newPage();
    await openDappWithoutPermission(dapp);

    const r = await dappEIP1193Call(dapp, "eth_accounts");
    expect(r.ok).toBe(true);
    expect(r.result).toEqual([]);

    await dapp.close();
  });

  test("eth_requestAccounts opens Connect popup; approving grants accounts + records chain", async ({ context, extensionId, serverInfo }) => {
    await preConfigureWithoutGrant(context, extensionId, serverInfo);
    const dapp = await context.newPage();
    await openDappWithoutPermission(dapp);

    // Capture the Connect popup window the SW spawns. Don't await the
    // dApp's RPC — it blocks until the popup resolves.
    const popupPromise = context.waitForEvent("page", { timeout: 15_000 });
    void dapp.evaluate(() =>
      window.ethereum!.request({ method: "eth_requestAccounts" }).catch(() => {})
    );

    const connectPopup = await popupPromise;
    await connectPopup.waitForLoadState("domcontentloaded");
    const url = new URL(connectPopup.url());
    expect(url.pathname).toMatch(/\/popup\/connect\.html$/);
    expect(url.searchParams.get("origin")).toBeTruthy();

    // The default-checked signer + a chain dropdown are visible.
    await expect(connectPopup.locator("#signerList .signer-item input:checked")).toHaveCount(1);
    await connectPopup.locator("#chainSelect").selectOption(String(parseInt(TEST_CHAINS.polygon, 16)));
    await expect(connectPopup.locator("#connectBtn")).toBeEnabled();
    await connectPopup.locator("#connectBtn").click();
    await connectPopup.waitForEvent("close", { timeout: 5_000 }).catch(() => {});

    // After approval the dApp's eth_accounts now returns the granted
    // signer and eth_chainId returns the chosen chain (137).
    await dapp.waitForTimeout(300);
    const accounts = await dappEIP1193Call(dapp, "eth_accounts");
    expect(accounts.ok).toBe(true);
    expect((accounts.result as string[]).length).toBeGreaterThan(0);
    expect((accounts.result as string[])[0].toLowerCase()).toBe(serverInfo.signer_address.toLowerCase());

    const chainId = await dappEIP1193Call(dapp, "eth_chainId");
    expect(chainId.ok).toBe(true);
    expect(chainId.result).toBe(TEST_CHAINS.polygon);

    await dapp.close();
  });

  test("cancelling the Connect popup rejects eth_requestAccounts with code 4001", async ({ context, extensionId, serverInfo }) => {
    await preConfigureWithoutGrant(context, extensionId, serverInfo);
    const dapp = await context.newPage();
    await openDappWithoutPermission(dapp);

    const popupPromise = context.waitForEvent("page", { timeout: 15_000 });
    const rpcPromise = dapp.evaluate(() =>
      window.ethereum!
        .request({ method: "eth_requestAccounts" })
        .then((r) => ({ ok: true, result: r }))
        .catch((e: any) => ({ ok: false, error: { code: e?.code, message: e?.message ?? String(e) } }))
    );

    const connectPopup = await popupPromise;
    await connectPopup.waitForLoadState("domcontentloaded");
    await connectPopup.locator("#cancelBtn").click();
    await connectPopup.waitForEvent("close", { timeout: 5_000 }).catch(() => {});

    const rpc = await rpcPromise;
    expect(rpc.ok).toBe(false);
    expect((rpc as any).error.code).toBe(4001);

    // eth_accounts still returns [] — Cancel must NOT have leaked a permission record.
    const accounts = await dappEIP1193Call(dapp, "eth_accounts");
    expect(accounts.ok).toBe(true);
    expect(accounts.result).toEqual([]);

    await dapp.close();
  });

  test("wallet_revokePermissions clears the grant and re-empties eth_accounts", async ({ context, extensionId, serverInfo }) => {
    await preConfigureWithoutGrant(context, extensionId, serverInfo);
    const dapp = await context.newPage();
    await openDappWithoutPermission(dapp);

    // First grant via the popup so we have something to revoke.
    const popupPromise = context.waitForEvent("page", { timeout: 15_000 });
    void dapp.evaluate(() =>
      window.ethereum!.request({ method: "eth_requestAccounts" }).catch(() => {})
    );
    const connectPopup = await popupPromise;
    await connectPopup.waitForLoadState("domcontentloaded");
    await connectPopup.locator("#connectBtn").click();
    await connectPopup.waitForEvent("close", { timeout: 5_000 }).catch(() => {});
    await dapp.waitForTimeout(200);
    const before = await dappEIP1193Call(dapp, "eth_accounts");
    expect((before.result as string[]).length).toBeGreaterThan(0);

    // Revoke. EIP-2255 / MIP-2 wire shape accepts an array of permissions.
    const rev = await dappEIP1193Call(dapp, "wallet_revokePermissions", { eth_accounts: {} });
    expect(rev.ok).toBe(true);
    await dapp.waitForTimeout(200);
    const after = await dappEIP1193Call(dapp, "eth_accounts");
    expect(after.result).toEqual([]);
    await dapp.close();
  });
});
