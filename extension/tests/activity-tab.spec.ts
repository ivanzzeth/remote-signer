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
    // Payload block renders the JSON-stringified payload (now under a
    // collapsed <details> labelled "Raw payload"). After the decoded-
    // message addition there are TWO .drawer-payload nodes (decoded +
    // raw); both should be present.
    await expect(popup.locator(".drawer-payload")).toHaveCount(2);
    // Decoded message preview: the hex-encoded payload we seeded should
    // surface as readable UTF-8 in the drawer.
    await expect(body).toContainText("activity-detail");

    await popup.locator("#drawerCloseBtn").click();
    await expect(popup.locator("#requestDrawer")).toHaveClass(/hidden/);
    await popup.close();
  });

  test("activity drawer flags Chain-ID mismatch in decoded SIWE", async ({ context, extensionId, serverInfo }) => {
    await seedExtensionConfig(context, extensionId, serverInfo);

    // Craft a SIWE-shaped message whose internal "Chain ID: 137" line
    // disagrees with the request's chain_id (which defaults to 1 on a
    // fresh origin). This is exactly the Polymarket failure mode — a
    // dApp on Polygon receives a signature over a SIWE that says Chain
    // ID: 1 and rejects it with 401.
    const siweText =
      "polymarket.com wants you to sign in with your Ethereum account:\n" +
      TEST_ACCOUNTS.signer +
      "\n\nWelcome.\n\nURI: https://polymarket.com\nVersion: 1\nChain ID: 137\nNonce: e2e-mismatch\nIssued At: 2026-05-19T00:00:00.000Z";
    const dapp = await context.newPage();
    await openDappAndWaitForProvider(dapp);
    const r = await dappEIP1193Call(
      dapp,
      "personal_sign",
      "0x" + Buffer.from(siweText, "utf-8").toString("hex"),
      TEST_ACCOUNTS.signer
    );
    expect(r.ok).toBe(true);
    await dapp.close();

    const popup = await openConnectedPopup(context, extensionId);
    await popup.locator("#tabActivityBtn").click();
    const items = popup.locator(".activity-item");
    await expect.poll(async () => items.count(), { timeout: 10_000 }).toBeGreaterThanOrEqual(1);
    await items.first().click();
    await expect(popup.locator("#requestDrawer")).toBeVisible();

    const body = popup.locator("#drawerBody");
    // Decoded SIWE text should be visible as-is.
    await expect(body).toContainText(/Chain ID: 137/);
    await expect(body).toContainText("Welcome.");
    // Warning banner appears because chain in message (137) differs
    // from the request's chain_id (1, the default for new origins).
    await expect(body.locator(".drawer-warning")).toBeVisible();
    await expect(body.locator(".drawer-warning")).toContainText(/Chain ID 137/);

    await popup.locator("#drawerCloseBtn").click();
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
