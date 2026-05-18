/**
 * Account switcher UX — real popup against the real backend.
 *
 * The e2e server seeds a single private-key signer. Multi-signer state is
 * created at test time via the admin API: a keystore signer is added in
 * beforeAll so the popup sees two signers, and the locked-greyed-out test
 * temporarily locks that keystore via admin.signers.lock(). Cleanup happens
 * in afterAll so subsequent specs see the original single-signer state.
 */
import { test, expect, type BrowserContext, type Page } from "./fixtures";
import { injectStorageConfig, adminClient } from "./helpers";

async function openConfiguredPopup(context: BrowserContext, extensionId: string, serverInfo: any): Promise<Page> {
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
  await popup.waitForSelector("#app");
  await injectStorageConfig(popup, {
    remoteSignerUrl: serverInfo.base_url,
    apiKeyId: serverInfo.admin_api_key_id,
    apiKeyPrivateKey: serverInfo.admin_api_key_hex,
  });
  await popup.reload();
  await popup.waitForSelector("#app");
  await expect(popup.locator("#connectedView")).toBeVisible({ timeout: 15_000 });
  return popup;
}

test.describe("Account switcher (real backend) (@integration)", () => {
  // Sub-suite creates+disposes a second keystore signer so the multi-signer
  // UI surface has something to render. Lives in a nested describe so the
  // setup/teardown doesn't run for tests that only need the single seeded
  // signer (none here today, but kept structured this way for clarity).
  test.describe.configure({ mode: "serial" });

  let keystoreAddr = "";

  test.beforeAll(async ({ serverInfo }) => {
    const admin = adminClient(serverInfo);
    const created = await admin.evm.signers.create({
      type: "keystore",
      keystore: { password: "switcher-test-pw" },
    });
    keystoreAddr = (created as any).address;

    // The seeded whitelist rule only mentions the seeded private-key signer;
    // create a permissive whitelist for the new keystore so the popup can
    // exercise it without the rule engine rejecting later signing requests.
    await admin.evm.rules.create({
      name: "e2e-keystore-allow",
      type: "signer_restriction",
      mode: "whitelist",
      chain_type: "evm",
      config: { allowed_signers: [keystoreAddr] },
      enabled: true,
    } as any);
  });

  test.afterAll(async ({ serverInfo }) => {
    if (!keystoreAddr) return;
    const admin = adminClient(serverInfo);
    await admin.evm.signers.unlock(keystoreAddr, { password: "switcher-test-pw" }).catch(() => {});
    await admin.evm.signers.deleteSigner(keystoreAddr).catch(() => {});
  });

  test("renders both signers and marks one active", async ({ context, extensionId, serverInfo }) => {
    const popup = await openConfiguredPopup(context, extensionId, serverInfo);

    const rows = popup.locator(".account-item");
    await expect(rows).toHaveCount(2);

    await expect(popup.locator(`.account-item[data-address="${serverInfo.signer_address}"]`)).not.toHaveClass(/account-item--disabled/);
    await expect(popup.locator(`.account-item[data-address="${keystoreAddr}"]`)).not.toHaveClass(/account-item--disabled/);

    await expect(popup.locator(".account-item--active")).toHaveCount(1);
    await expect(popup.locator("#accountCount")).toHaveText("2");

    await popup.close();
  });

  test("clicking the non-active usable row switches the active signer", async ({ context, extensionId, serverInfo }) => {
    const popup = await openConfiguredPopup(context, extensionId, serverInfo);

    const activeBefore = await popup.locator(".account-item--active").getAttribute("data-address");
    const target = activeBefore?.toLowerCase() === serverInfo.signer_address.toLowerCase()
      ? keystoreAddr
      : serverInfo.signer_address;

    await popup.locator(`.account-item[data-address="${target}"]`).click();
    await expect(popup.locator(`.account-item[data-address="${target}"]`)).toHaveClass(/account-item--active/, { timeout: 10_000 });

    const stored = await popup.evaluate(() =>
      new Promise<any>((resolve) =>
        chrome.storage.local.get("remoteSignerConfig", (r) => resolve(r.remoteSignerConfig))
      )
    );
    expect(stored?.activeSignerAddress?.toLowerCase()).toBe(target.toLowerCase());

    await popup.close();
  });

  test("locked signer is greyed out, shows 🔒, and clicks are no-ops", async ({ context, extensionId, serverInfo }) => {
    const admin = adminClient(serverInfo);
    await admin.evm.signers.lock(keystoreAddr);

    try {
      const popup = await openConfiguredPopup(context, extensionId, serverInfo);

      const lockedRow = popup.locator(`.account-item[data-address="${keystoreAddr}"]`);
      await expect(lockedRow).toHaveClass(/account-item--disabled/);
      await expect(lockedRow.locator(".account-status")).toHaveText("🔒");

      const activeBefore = await popup.locator(".account-item--active").getAttribute("data-address");
      await lockedRow.click({ force: true });
      await popup.waitForTimeout(400);

      const activeAfter = await popup.locator(".account-item--active").getAttribute("data-address");
      expect(activeAfter).toBe(activeBefore);

      await expect(popup.locator("#accountCount")).toHaveText("1");

      await popup.close();
    } finally {
      await admin.evm.signers.unlock(keystoreAddr, { password: "switcher-test-pw" }).catch(() => {});
    }
  });

  test("copy button does not trigger a switch", async ({ context, extensionId, serverInfo }) => {
    const popup = await openConfiguredPopup(context, extensionId, serverInfo);

    const activeBefore = await popup.locator(".account-item--active").getAttribute("data-address");
    await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: `chrome-extension://${extensionId}` }).catch(() => {});

    const targetAddr = activeBefore?.toLowerCase() === serverInfo.signer_address.toLowerCase()
      ? keystoreAddr
      : serverInfo.signer_address;
    await popup.locator(`.account-item[data-address="${targetAddr}"] .account-copy`).click();
    await popup.waitForTimeout(300);

    const activeAfter = await popup.locator(".account-item--active").getAttribute("data-address");
    expect(activeAfter?.toLowerCase()).toBe(activeBefore?.toLowerCase());
    await popup.close();
  });

  test("active signer choice persists across popup reopen", async ({ context, extensionId, serverInfo }) => {
    const popup = await openConfiguredPopup(context, extensionId, serverInfo);

    const activeBefore = await popup.locator(".account-item--active").getAttribute("data-address");
    const target = activeBefore?.toLowerCase() === serverInfo.signer_address.toLowerCase()
      ? keystoreAddr
      : serverInfo.signer_address;

    await popup.locator(`.account-item[data-address="${target}"]`).click();
    await expect(popup.locator(`.account-item[data-address="${target}"]`)).toHaveClass(/account-item--active/, { timeout: 10_000 });
    await popup.close();

    const popup2 = await context.newPage();
    await popup2.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup2.waitForSelector("#app");
    await expect(popup2.locator("#connectedView")).toBeVisible({ timeout: 15_000 });
    await expect(popup2.locator(`.account-item[data-address="${target}"]`)).toHaveClass(/account-item--active/);
    await popup2.close();
  });
});
