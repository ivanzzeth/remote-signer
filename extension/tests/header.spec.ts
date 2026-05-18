/**
 * Header chips (chain + signer) + role badge — real popup, real backend.
 *
 * Tests that depend on multi-signer state create a second keystore signer
 * via the admin API at the start of their sub-suite, and dispose of it
 * afterwards. The e2e server seed itself is single-signer.
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
    selectedChain: 1,
  });
  await popup.reload();
  await popup.waitForSelector("#app");
  await expect(popup.locator("#connectedView")).toBeVisible({ timeout: 15_000 });
  return popup;
}

// ── Single-signer subset (uses only the seeded signer) ────────────────────

test.describe("AppBar header — single-signer (real backend) (@integration)", () => {
  test("subtitle reads 'Policy-controlled signing'", async ({ context, extensionId, serverInfo }) => {
    const popup = await openConfiguredPopup(context, extensionId, serverInfo);
    await expect(popup.locator(".logo-subtitle")).toHaveText("Policy-controlled signing");
    await popup.close();
  });

  test("chain chip shows current chain label", async ({ context, extensionId, serverInfo }) => {
    const popup = await openConfiguredPopup(context, extensionId, serverInfo);
    await expect(popup.locator("#appbarChainBtn")).toBeVisible();
    await expect(popup.locator("#appbarChainLabel")).toHaveText("Ethereum");
    await popup.close();
  });

  test("chain chip opens dropdown; the active chain has the ✓ marker", async ({ context, extensionId, serverInfo }) => {
    const popup = await openConfiguredPopup(context, extensionId, serverInfo);
    await popup.locator("#appbarChainBtn").click();
    await expect(popup.locator("#chainDropdown")).toBeVisible();
    const activeItem = popup.locator("#chainDropdown .appbar-dropdown-item--active");
    await expect(activeItem).toHaveCount(1);
    await expect(activeItem).toContainText("Ethereum");
    await popup.close();
  });

  test("picking another chain updates the chip label and persists the choice", async ({ context, extensionId, serverInfo }) => {
    const popup = await openConfiguredPopup(context, extensionId, serverInfo);
    await popup.locator("#appbarChainBtn").click();
    await popup.locator("#chainDropdown .appbar-dropdown-item:has-text('Polygon')").click();
    await expect(popup.locator("#appbarChainLabel")).toHaveText("Polygon");

    const stored = await popup.evaluate(() =>
      new Promise<any>((resolve) =>
        chrome.storage.local.get("remoteSignerConfig", (r) => resolve(r.remoteSignerConfig))
      )
    );
    expect(stored?.selectedChain).toBe(137);
    await popup.close();
  });

  test("role badge reflects the API key role", async ({ context, extensionId, serverInfo }) => {
    const popup = await openConfiguredPopup(context, extensionId, serverInfo);
    await expect(popup.locator("#roleBadge")).toBeVisible({ timeout: 10_000 });
    const text = (await popup.locator("#roleBadge").textContent())?.trim();
    expect(["admin", "agent"]).toContain(text);
    await popup.close();
  });

  test("clicking outside the dropdown dismisses it", async ({ context, extensionId, serverInfo }) => {
    const popup = await openConfiguredPopup(context, extensionId, serverInfo);
    await popup.locator("#appbarChainBtn").click();
    await expect(popup.locator("#chainDropdown")).toBeVisible();
    await popup.locator(".logo-text").click();
    await expect(popup.locator("#chainDropdown")).toHaveClass(/hidden/, { timeout: 2_000 });
    await popup.close();
  });
});

// ── Multi-signer subset (provisions an extra keystore signer) ─────────────

test.describe("AppBar header — multi-signer (real backend) (@integration)", () => {
  test.describe.configure({ mode: "serial" });

  let keystoreAddr = "";

  test.beforeAll(async ({ serverInfo }) => {
    const admin = adminClient(serverInfo);
    const created = await admin.evm.signers.create({
      type: "keystore",
      keystore: { password: "header-test-pw" },
    });
    keystoreAddr = (created as any).address;
    await admin.evm.rules.create({
      name: "e2e-header-keystore-allow",
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
    await admin.evm.signers.unlock(keystoreAddr, { password: "header-test-pw" }).catch(() => {});
    await admin.evm.signers.deleteSigner(keystoreAddr).catch(() => {});
  });

  test("signer chip shows the active address and opens a dropdown with both signers", async ({ context, extensionId, serverInfo }) => {
    const popup = await openConfiguredPopup(context, extensionId, serverInfo);
    await expect(popup.locator("#appbarSignerBtn")).toBeVisible();
    const label = (await popup.locator("#appbarSignerLabel").textContent()) || "";
    expect(label.length).toBeGreaterThan(0);
    expect(label.startsWith("0x")).toBe(true);

    await popup.locator("#appbarSignerBtn").click();
    await expect(popup.locator("#signerDropdown")).toBeVisible();
    await expect(popup.locator("#signerDropdown .appbar-dropdown-item")).toHaveCount(2);
    await expect(popup.locator("#signerDropdown .appbar-dropdown-item--active")).toHaveCount(1);
    await popup.close();
  });

  test("picking another signer from the dropdown switches the active account", async ({ context, extensionId, serverInfo }) => {
    const popup = await openConfiguredPopup(context, extensionId, serverInfo);
    const activeBefore = await popup.locator(".account-item--active").getAttribute("data-address");
    const target = activeBefore?.toLowerCase() === serverInfo.signer_address.toLowerCase()
      ? keystoreAddr
      : serverInfo.signer_address;

    await popup.locator("#appbarSignerBtn").click();
    const shortTarget = target.slice(0, 6) + "..." + target.slice(-4);
    await popup.locator(`#signerDropdown .appbar-dropdown-item:has-text("${shortTarget}")`).click();

    await expect(popup.locator(`.account-item[data-address="${target}"]`)).toHaveClass(/account-item--active/, { timeout: 10_000 });
    const stored = await popup.evaluate(() =>
      new Promise<any>((resolve) =>
        chrome.storage.local.get("remoteSignerConfig", (r) => resolve(r.remoteSignerConfig))
      )
    );
    expect(stored?.activeSignerAddress?.toLowerCase()).toBe(target.toLowerCase());
    await popup.close();
  });

  test("locked signer in the dropdown is non-clickable and shows 🔒", async ({ context, extensionId, serverInfo }) => {
    const admin = adminClient(serverInfo);
    await admin.evm.signers.lock(keystoreAddr);

    try {
      const popup = await openConfiguredPopup(context, extensionId, serverInfo);
      const activeBefore = await popup.locator(".account-item--active").getAttribute("data-address");

      await popup.locator("#appbarSignerBtn").click();
      const lockedRow = popup.locator("#signerDropdown .appbar-dropdown-item--disabled");
      await expect(lockedRow).toHaveCount(1);
      await expect(lockedRow).toContainText("🔒");
      await lockedRow.click({ force: true });
      await popup.waitForTimeout(400);

      const activeAfter = await popup.locator(".account-item--active").getAttribute("data-address");
      expect(activeAfter).toBe(activeBefore);
      await popup.close();
    } finally {
      await admin.evm.signers.unlock(keystoreAddr, { password: "header-test-pw" }).catch(() => {});
    }
  });
});
