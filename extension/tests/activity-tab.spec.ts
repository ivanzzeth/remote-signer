/**
 * Activity tab — real popup against real backend.
 *
 * We drive personal_sign requests through a dApp page to populate the
 * audit/request log, then open the popup and assert the Activity tab
 * surfaces them.
 */
import { test, expect } from "./fixtures";
import {
  injectStorageConfig,
  openDappAndWaitForProvider,
  dappEIP1193Call,
  TEST_ACCOUNTS,
} from "./helpers";

async function seedExtensionConfig(context: any, extensionId: string, serverInfo: any) {
  const seed = await context.newPage();
  await seed.goto(`chrome-extension://${extensionId}/popup/popup.html`);
  await seed.waitForSelector("#app");
  await injectStorageConfig(seed, {
    remoteSignerUrl: serverInfo.base_url,
    apiKeyId: serverInfo.admin_api_key_id,
    apiKeyPrivateKey: serverInfo.admin_api_key_hex,
  });
  await seed.reload();
  await seed.waitForSelector("#app");
  await seed.close();
}

async function generateSignedRequest(context: any, message: string) {
  const page = await context.newPage();
  await openDappAndWaitForProvider(page);
  const r = await dappEIP1193Call(
    page,
    "personal_sign",
    "0x" + Buffer.from(message).toString("hex"),
    TEST_ACCOUNTS.signer
  );
  await page.close();
  return r;
}

async function openConnectedPopup(context: any, extensionId: string) {
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
  await popup.waitForSelector("#app");
  await expect(popup.locator("#connectedView")).toBeVisible({ timeout: 15_000 });
  return popup;
}

test.describe("Activity tab (real backend) (@integration)", () => {
  test("tab switches to Activity and renders the signed requests", async ({ context, extensionId, serverInfo }) => {
    await seedExtensionConfig(context, extensionId, serverInfo);

    // Produce 2 signed requests so the list has something to show.
    const r1 = await generateSignedRequest(context, "activity-test-1");
    const r2 = await generateSignedRequest(context, "activity-test-2");
    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(true);

    const popup = await openConnectedPopup(context, extensionId);

    // Default tab.
    await expect(popup.locator("#tabAccounts")).toBeVisible();
    await expect(popup.locator("#tabActivity")).toHaveClass(/hidden/);

    await popup.locator("#tabActivityBtn").click();
    await expect(popup.locator("#tabActivity")).toBeVisible();

    // At least the two we just produced are present.
    const items = popup.locator(".activity-item");
    await expect.poll(async () => items.count(), { timeout: 10_000 }).toBeGreaterThanOrEqual(2);

    // Each visible row has a status pill.
    const first = items.first();
    await expect(first.locator(".activity-status")).toBeVisible();
    const statusText = (await first.locator(".activity-status").textContent())?.toLowerCase().trim();
    expect(["completed", "rejected", "failed", "pending", "authorizing", "signing"]).toContain(statusText ?? "");

    await popup.close();
  });

  test("clicking a request opens the detail drawer with payload + rule match", async ({ context, extensionId, serverInfo }) => {
    await seedExtensionConfig(context, extensionId, serverInfo);
    const r = await generateSignedRequest(context, "activity-detail");
    expect(r.ok).toBe(true);

    const popup = await openConnectedPopup(context, extensionId);
    await popup.locator("#tabActivityBtn").click();

    const items = popup.locator(".activity-item");
    await expect.poll(async () => items.count(), { timeout: 10_000 }).toBeGreaterThanOrEqual(1);

    await items.first().click();
    await expect(popup.locator("#requestDrawer")).toBeVisible();

    // Drawer body should mention the sign type and chain id row labels.
    const body = popup.locator("#drawerBody");
    await expect(body).toContainText(/Sign type/i);
    await expect(body).toContainText(/Chain/i);
    // The seeded auto-approve rule's id should appear under "Rule matched".
    await expect(body).toContainText(/e2e-test-rule/);
    // Payload block renders the JSON-stringified payload.
    await expect(popup.locator(".drawer-payload")).toBeVisible();

    await popup.locator("#drawerCloseBtn").click();
    await expect(popup.locator("#requestDrawer")).toHaveClass(/hidden/);
    await popup.close();
  });

  test("refresh button re-fetches", async ({ context, extensionId, serverInfo }) => {
    await seedExtensionConfig(context, extensionId, serverInfo);
    await generateSignedRequest(context, "before-refresh");

    const popup = await openConnectedPopup(context, extensionId);
    await popup.locator("#tabActivityBtn").click();
    const countBefore = await popup.locator(".activity-item").count();

    // Produce one more after the popup opened, then refresh.
    await generateSignedRequest(context, "after-refresh");
    await popup.locator("#activityRefreshBtn").click();
    await expect.poll(async () => popup.locator(".activity-item").count(), { timeout: 10_000 }).toBeGreaterThan(countBefore);

    await popup.close();
  });
});
