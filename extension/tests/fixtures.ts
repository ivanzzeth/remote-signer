import { test as base, chromium, type Page, type BrowserContext } from "@playwright/test";
import { fileURLToPath } from "url";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ── Types ────────────────────────────────────────────────────────────────────

export interface E2EServerInfo {
  base_url: string;
  dapp_url: string;
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

/** Detect the extension ID for an unpacked Chrome extension (MV3) */
export async function detectExtensionId(context: BrowserContext): Promise<string> {
  const page = await context.newPage();
  await page.goto("about:blank");

  // Method 1: Wait for and check service workers (MV3) — retry since SW may not be ready immediately
  for (let i = 0; i < 30; i++) {
    const sws = context.serviceWorkers();
    for (const sw of sws) {
      const m = sw.url().match(/^chrome-extension:\/\/([a-p]{32})\//);
      if (m) { await page.close(); return m[1]; }
    }
    // Listen for newly registered service workers
    const swFromEvent = await new Promise<string | null>((resolve) => {
      const handler = (sw: any) => {
        const m = sw.url().match(/^chrome-extension:\/\/([a-p]{32})\//);
        if (m) resolve(m[1]);
      };
      context.on("serviceworker", handler);
      setTimeout(() => {
        context.off("serviceworker", handler);
        resolve(null);
      }, 200);
    });
    if (swFromEvent) { await page.close(); return swFromEvent; }
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

const EXTENSION_PATH = path.resolve(__dirname, "..");

export const test = base.extend<ExtensionFixtures>({
  serverInfo: async ({}, use) => {
    const info = loadServerInfo();
    await use(info);
  },

  /**
   * Override Playwright's default context with chromium.launchPersistentContext.
   *
   * REQUIRED for Chrome extension testing: Playwright's default test runner
   * provides an ephemeral context (via browser.newContext()), and Chrome
   * refuses to load unpacked extensions into ephemeral contexts — even with
   * --load-extension on the launch command. The extension's service worker
   * silently never registers, so detectExtensionId loops out.
   *
   * The original fix for this lived in commit 6aba3ee but was dropped when
   * fixtures.ts was rewritten for v0.3.4 — re-applying it here.
   */
  context: async ({}, use) => {
    const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "rs-e2e-"));
    const persistentContext = await chromium.launchPersistentContext(userDataDir, {
      args: [
        `--disable-extensions-except=${EXTENSION_PATH}`,
        `--load-extension=${EXTENSION_PATH}`,
      ],
    });
    await use(persistentContext);
    await persistentContext.close();
    fs.rmSync(userDataDir, { recursive: true, force: true });
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

  openDapp: async ({ context, serverInfo }: { context: BrowserContext; serverInfo: E2EServerInfo }, use) => {
    await use(async () => {
      const page = await context.newPage();
      await page.goto(serverInfo.dapp_url + "/");
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
