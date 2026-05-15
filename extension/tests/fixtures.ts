import { test as base, type Page, type BrowserContext } from "@playwright/test";
import * as path from "path";
import * as fs from "fs";

// ── Types ────────────────────────────────────────────────────────────────────

export interface E2EServerInfo {
  base_url: string;
  admin_api_key_id: string;
  admin_api_key_hex: string;
  non_admin_api_key_id: string;
  non_admin_api_key_hex: string;
  signer_address: string;
}

export interface ExtensionFixtures {
  /** Server info loaded from global-setup */
  serverInfo: E2EServerInfo;
  /** Extension ID (auto-detected) */
  extensionId: string;
  /** Popup page handle */
  popup: Page;
  /** Open the extension popup in a new tab and return it */
  openPopup: (ctx: BrowserContext) => Promise<Page>;
  /** Open a dApp test page tab */
  openDapp: () => Promise<Page>;
  /** Configure the extension via popup */
  configureExtension: (page: Page, overrides?: Partial<{ url: string; apiKeyId: string; apiKeyPrivateKey: string }>) => Promise<void>;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function loadServerInfo(): E2EServerInfo {
  const statePath = path.resolve(__dirname, ".e2e-state", "server.json");
  return JSON.parse(fs.readFileSync(statePath, "utf-8"));
}

async function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

/** Detect the extension ID for an unpacked Chrome extension */
export async function detectExtensionId(context: BrowserContext): Promise<string> {
  const page = await context.newPage();
  await page.goto("about:blank");

  // Method 1: Check registered service workers (MV3)
  const sws = context.serviceWorkers();
  for (const sw of sws) {
    const m = sw.url().match(/^chrome-extension:\/\/([a-p]{32})\//);
    if (m) { await page.close(); return m[1]; }
  }

  // Method 2: Check background pages (MV2)
  const bgPages = context.backgroundPages();
  for (const bg of bgPages) {
    const m = bg.url().match(/^chrome-extension:\/\/([a-p]{32})\//);
    if (m) { await page.close(); return m[1]; }
  }

  // Method 3: Check injected scripts on the page
  const extId = await page.evaluate(() => {
    const scripts = document.querySelectorAll("script");
    for (const s of scripts) {
      const m = s.src.match(/^chrome-extension:\/\/([a-p]{32})\//);
      if (m) return m[1];
    }
    return null;
  });

  await page.close();
  if (extId) return extId;

  throw new Error(
    "Could not detect extension ID. Ensure the extension is loaded. " +
    "Run the extension build first: npm run build"
  );
}

/** Open the extension popup by navigating to chrome-extension://<id>/popup/popup.html */
export async function openPopupPage(context: BrowserContext, extensionId: string): Promise<Page> {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/popup/popup.html`);
  // Wait for the popup to initialize
  await page.waitForSelector("#app", { timeout: 10_000 });
  return page;
}

// ── Extended Test ─────────────────────────────────────────────────────────────

export const test = base.extend<ExtensionFixtures>({
  serverInfo: async ({}, use) => {
    const info = loadServerInfo();
    await use(info);
  },

  extensionId: async ({ context }: { context: BrowserContext }, use) => {
    const extId = await detectExtensionId(context);
    await use(extId);
  },

  openPopup: async ({ context, extensionId }: { context: BrowserContext; extensionId: string }, use) => {
    await use(async () => openPopupPage(context, extensionId as string));
  },

  popup: async ({ context, extensionId }: { context: BrowserContext; extensionId: string }, use) => {
    const page = await openPopupPage(context, extensionId as string);
    await use(page);
    await page.close();
  },

  openDapp: async ({ context }: { context: BrowserContext }, use) => {
    const dappPath = path.resolve(__dirname, ".e2e-state", "dapp-test-page.html");
    await use(async () => {
      const page = await context.newPage();
      await page.goto(`file://${dappPath}`);
      return page;
    });
  },

  configureExtension: async ({ serverInfo }: { serverInfo: E2EServerInfo }, use) => {
    await use(async (page: Page, overrides?: Partial<{ url: string; apiKeyId: string; apiKeyPrivateKey: string }>) => {
      await page.click("#settingsBtn");
      await page.fill("#inputUrl", overrides?.url ?? serverInfo.base_url);
      await page.fill("#inputKeyId", overrides?.apiKeyId ?? serverInfo.admin_api_key_id);
      await page.fill("#inputPrivateKey", overrides?.apiKeyPrivateKey ?? serverInfo.admin_api_key_hex);
      await page.click("#testConnectionBtn");

      // Wait for test result
      await sleep(500);
      await page.click("#saveConfigBtn");
      await sleep(300);
    });
  },
});

export { expect } from "@playwright/test";
