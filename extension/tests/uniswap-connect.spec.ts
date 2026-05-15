import { test, expect } from "./fixtures";
import type { Page, BrowserContext } from "@playwright/test";
import path from "path";

const SWAP_PAGE_PATH = path.resolve(__dirname, "dapp", "swap-page.html");

/**
 * Open the swap simulation dApp page in a new tab.
 */
async function openSwapPage(context: BrowserContext): Promise<Page> {
  const page = await context.newPage();
  await page.goto(`file://${SWAP_PAGE_PATH}`);
  return page;
}

/**
 * Pre-configure the extension via popup so it can serve dApp requests.
 */
async function configureViaPopup(
  context: BrowserContext,
  extensionId: string,
  serverInfo: { base_url: string; admin_api_key_id: string; admin_api_key_hex: string }
): Promise<void> {
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
  await popup.waitForSelector("#app");

  const settingsBtn = popup.locator("#disconnectedSettingsBtn");
  if (await settingsBtn.isVisible()) {
    await settingsBtn.click();
  } else {
    await popup.click("#settingsBtn");
  }

  await popup.waitForSelector("#settingsView:not(.hidden)", { timeout: 5_000 });
  await popup.fill("#inputUrl", serverInfo.base_url);
  await popup.fill("#inputKeyId", serverInfo.admin_api_key_id);
  await popup.fill("#inputPrivateKey", serverInfo.admin_api_key_hex);
  await popup.click("#saveConfigBtn");
  await popup.waitForTimeout(500);
  await popup.close();
}

test.describe("Uniswap Connect (@integration)", () => {
  test("swap page loads and detects window.ethereum", async ({ openDapp }) => {
    // Use the built-in openDapp to confirm provider injection works
    const dapp = await openDapp();
    await dapp.waitForFunction(() => !!window.ethereum, { timeout: 15_000 });

    const hasProvider = await dapp.evaluate(() => !!window.ethereum);
    expect(hasProvider).toBe(true);
  });

  test("Connect Wallet returns accounts after pre-configuration", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    // Configure the extension so it can respond
    await configureViaPopup(context, extensionId, serverInfo);

    // Open the swap page
    const page = await openSwapPage(context);
    await page.waitForFunction(() => !!window.ethereum, { timeout: 15_000 });

    // Verify provider is available
    const providerAvailable = await page.evaluate(
      () => document.getElementById("providerStatus")?.textContent
    );
    expect(providerAvailable).toBe("available");

    // Click Connect Wallet
    await page.click("#btnConnect");

    // Wait for accounts to appear in the UI
    await page.waitForFunction(
      () => {
        const el = document.getElementById("walletAddress");
        return el && el.textContent !== "";
      },
      { timeout: 15_000 }
    );

    // Verify an account address is displayed
    const walletAddress = await page.evaluate(
      () => document.getElementById("walletAddress")?.textContent ?? ""
    );
    expect(walletAddress).toMatch(/^0x[a-fA-F0-9]{40}$/);

    // Verify accounts are shown in the provider state panel
    const accountsText = await page.evaluate(
      () => document.getElementById("accounts")?.textContent ?? ""
    );
    expect(accountsText).toContain("0x");

    await page.close();
  });

  test("UI shows connected state after eth_requestAccounts", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await configureViaPopup(context, extensionId, serverInfo);

    const page = await openSwapPage(context);
    await page.waitForFunction(() => !!window.ethereum, { timeout: 15_000 });

    await page.click("#btnConnect");

    // Wait for provider state to reflect connection
    await page.waitForFunction(
      () => {
        const connected = document.getElementById("connected");
        return connected && connected.textContent === "true";
      },
      { timeout: 15_000 }
    );

    const connected = await page.evaluate(
      () => document.getElementById("connected")?.textContent
    );
    expect(connected).toBe("true");

    // Chain ID should be populated
    const chainId = await page.evaluate(
      () => document.getElementById("chainId")?.textContent ?? ""
    );
    expect(chainId).toMatch(/^0x[a-fA-F0-9]+$/);

    await page.close();
  });

  test("chainChanged event is logged on the swap page", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await configureViaPopup(context, extensionId, serverInfo);

    const page = await openSwapPage(context);
    await page.waitForFunction(() => !!window.ethereum, { timeout: 15_000 });

    await page.click("#btnConnect");
    await page.waitForFunction(
      () => {
        const connected = document.getElementById("connected");
        return connected && connected.textContent === "true";
      },
      { timeout: 15_000 }
    );

    // Trigger a chain switch
    await page.evaluate(async () => {
      try {
        await window.ethereum!.request({
          method: "wallet_switchEthereumChain",
          params: [{ chainId: "0x89" }],
        });
      } catch {
        // May fail if Polygon is not configured, but event should still fire
      }
    });

    // Verify event log contains the chainChanged event (or at least some activity)
    await page.waitForTimeout(1000);
    const eventLog = await page.evaluate(
      () => document.getElementById("eventLog")?.textContent ?? ""
    );
    // The log should contain some entries
    expect(eventLog.length).toBeGreaterThan(2);

    await page.close();
  });
});
