/**
 * Pending-approval popup window — opens when a sign request needs
 * manual approval, lets the user jump to the management page, and
 * auto-closes once an operator approves (or rejects) the request.
 *
 * Reproduction strategy: create a fresh keystore signer at test time.
 * It's NOT covered by the seeded auto-approve whitelist (which only
 * targets the original test signer), so a personal_sign from this new
 * signer falls into the manual-approval queue. From there we can
 * observe the SW spawning a popup window, drive the admin approval,
 * and watch the window auto-close.
 */
import { test, expect, type Page, type BrowserContext } from "./fixtures";
import {
  injectStorageConfig,
  openDappAndWaitForProvider,
  adminClient,
  dappEIP1193Call,
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

async function switchActiveSigner(context: BrowserContext, extensionId: string, address: string) {
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
  await popup.waitForSelector("#app");
  await expect(popup.locator("#connectedView")).toBeVisible({ timeout: 15_000 });
  await popup.locator(`.account-item[data-address="${address}"]`).click();
  await expect(popup.locator(`.account-item[data-address="${address}"]`)).toHaveClass(/account-item--active/, { timeout: 10_000 });
  await popup.close();
}

test.describe("Pending-approval popup window (@integration)", () => {
  test.describe.configure({ mode: "serial" });

  // A fresh keystore signer that no rule covers — so its sign requests
  // land in the manual-approval queue, which is exactly the scenario
  // this UX exists for.
  let unmatchedAddr = "";
  test.beforeAll(async ({ serverInfo }) => {
    const admin = adminClient(serverInfo);
    const created = await admin.evm.signers.create({
      type: "keystore",
      keystore: { password: "pending-approval-test" },
    });
    unmatchedAddr = (created as any).address;
  });

  test.afterAll(async ({ serverInfo }) => {
    if (!unmatchedAddr) return;
    const admin = adminClient(serverInfo);
    await admin.evm.signers.deleteSigner(unmatchedAddr).catch(() => {});
  });

  test("opens a popup window when a sign request lands in the manual-approval queue", async ({ context, extensionId, serverInfo }) => {
    test.setTimeout(60_000);
    await configure(context, extensionId, serverInfo);
    await switchActiveSigner(context, extensionId, unmatchedAddr);

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);

    // Confirm the dApp sees the unmatched signer as active — otherwise
    // the personal_sign would still go through the seeded auto-approve
    // path and never trigger the manual-approval queue.
    const accounts = await dappEIP1193Call(dapp, "eth_requestAccounts");
    expect(accounts.ok).toBe(true);
    expect((accounts.result as string[])[0].toLowerCase()).toBe(unmatchedAddr.toLowerCase());

    // Catch the next new Page (= chrome.windows.create popup) BEFORE we
    // trigger the sign. Don't await the personal_sign — it blocks on
    // the SDK's poll loop while we drive the approval below.
    const newPagePromise = context.waitForEvent("page", { timeout: 30_000 });
    void dapp.evaluate(
      ({ message, address }) =>
        window.ethereum!.request({ method: "personal_sign", params: [message, address] }),
      {
        message: "0x" + Buffer.from("Manual approval e2e", "utf-8").toString("hex"),
        address: unmatchedAddr,
      }
    ).catch(() => { /* dApp call resolves only after admin approves */ });

    const pending = await newPagePromise;
    await pending.waitForLoadState("domcontentloaded");

    // The popup URL carries the request id + summary metadata.
    const url = new URL(pending.url());
    expect(url.pathname).toMatch(/\/popup\/pending\.html$/);
    const requestId = url.searchParams.get("requestId");
    expect(requestId, "popup must carry the request id").toBeTruthy();
    expect(url.searchParams.get("signType")).toBe("personal");
    expect(url.searchParams.get("signerAddress")?.toLowerCase()).toBe(
      unmatchedAddr.toLowerCase()
    );

    await expect(pending.locator("#pendingStatusText")).toHaveText(/manual approval/i);
    await expect(pending.locator("#detailSignType")).toHaveText("personal");
    await expect(pending.locator("#openMgmtBtn")).toBeVisible();

    // Approve via the admin SDK — mimics the operator clicking Approve.
    const admin = adminClient(serverInfo);
    await admin.evm.requests.approve(requestId!, { approved: true });

    // The pending window polls every 2s; give it a generous window to
    // observe the transition and auto-close.
    await expect.poll(async () => {
      if (pending.isClosed()) return "closed";
      try {
        return await pending.locator("#pendingStatusText").textContent();
      } catch {
        return "closed";
      }
    }, { timeout: 15_000 }).toMatch(/approved|signature delivered|closed/i);

    await dapp.close();
    if (!pending.isClosed()) await pending.close();
  });

  test("Go to manual approval button asks the SW to open the admin page", async ({ context, extensionId, serverInfo }) => {
    test.setTimeout(60_000);
    await configure(context, extensionId, serverInfo);
    await switchActiveSigner(context, extensionId, unmatchedAddr);

    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);
    await dappEIP1193Call(dapp, "eth_requestAccounts");

    const pagePromise = context.waitForEvent("page", { timeout: 30_000 });
    void dapp.evaluate(
      ({ message, address }) =>
        window.ethereum!.request({ method: "personal_sign", params: [message, address] }),
      {
        message: "0x" + Buffer.from("admin-link-test", "utf-8").toString("hex"),
        address: unmatchedAddr,
      }
    ).catch(() => {});
    const pending = await pagePromise;
    await pending.waitForLoadState("domcontentloaded");

    // Clicking "Go to manual approval" triggers the SW to open the
    // backend URL in a new tab. Wait for the new tab.
    const adminTabPromise = context.waitForEvent("page", { timeout: 10_000 });
    await pending.locator("#openMgmtBtn").click();
    const adminTab = await adminTabPromise;
    await adminTab.waitForLoadState("domcontentloaded").catch(() => {});

    // The tab navigates to the backend root — e2e-test-server might 404
    // there, which is fine. What matters is the URL points at the right host.
    const adminUrl = new URL(adminTab.url());
    const expectedUrl = new URL(serverInfo.base_url);
    expect(adminUrl.host).toBe(expectedUrl.host);

    await adminTab.close().catch(() => {});

    // Approve from admin so the dApp's poll loop doesn't leak into the
    // next test.
    const admin = adminClient(serverInfo);
    const list = await admin.evm.requests.list({}).catch(() => ({ requests: [] } as any));
    const pendingReq = ((list as any).requests || []).find(
      (r: any) => r.sign_type === "personal" && (r.status === "pending" || r.status === "authorizing")
    );
    if (pendingReq) {
      await admin.evm.requests.approve(pendingReq.id, { approved: true }).catch(() => {});
    }
    if (!pending.isClosed()) await pending.close();
    await dapp.close();
  });
});
