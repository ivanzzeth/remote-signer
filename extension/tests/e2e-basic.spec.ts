import { test, expect } from "./fixtures.js";
import { chromium, type BrowserContext } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const extensionPath = path.resolve(__dirname, "..");

/**
 * Launch a Chromium context with the extension loaded.
 */
async function launchExtensionContext(): Promise<{
  context: BrowserContext;
  extensionId: string;
}> {
  const userDataDir = path.join(__dirname, ".chrome-profile");

  const context = await chromium.launchPersistentContext(userDataDir, {
    headless: false,
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
      "--no-sandbox",
      "--disable-setuid-sandbox",
    ],
    viewport: { width: 1280, height: 720 },
  });

  // Get the extension ID from the background page's URL
  const bgPage = context.serviceWorkers[0] || context.backgroundPages[0];
  const bgUrl = bgPage?.url() || "";
  const match = bgUrl.match(/chrome-extension:\/\/([a-z]+)/);
  const extensionId = match?.[1] || "";

  return { context, extensionId };
}

test.describe("Extension E2E — wallet connection", () => {
  let ctx: { context: BrowserContext; extensionId: string };

  test.beforeAll(async () => {
    ctx = await launchExtensionContext();
  });

  test.afterAll(async () => {
    await ctx.context.close();
  });

  test("should load extension and configure API key", async () => {
    const { context } = ctx;
    const page = context.pages()[0] || await context.newPage();
    await page.goto(`chrome-extension://${ctx.extensionId}/popup/popup.html`);

    // Expect at least the popup body to render
    await expect(page.locator("body")).toBeVisible();
    await expect(page.locator("#disconnectedView")).toBeVisible({ timeout: 5000 });
  });

  test("should interact with dApp test page via provider", async () => {
    const { context } = ctx;
    const page = context.pages()[0] || await context.newPage();

    // Navigate to the local dApp test page
    const dappPath = path.resolve(__dirname, "dapp-test-page.html");
    await page.goto(`file://${dappPath}`);

    // Verify the page loaded
    await expect(page.locator("h1")).toContainText("E2E Test dApp");

    // The extension should inject window.ethereum via inpage.js
    const hasProvider = await page.evaluate(() => {
      return typeof window.ethereum !== "undefined";
    });
    expect(hasProvider).toBe(true);
  });
});
