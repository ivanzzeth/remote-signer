import { test as base, type Page, type BrowserContext, chromium } from "@playwright/test";
import { fileURLToPath } from "url";
import * as path from "path";
import * as fs from "fs";
import { createHash } from "crypto";
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
  /** Extension ID (deterministically derived from extension path) */
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

/** Derive the deterministic extension ID for an unpacked MV3 extension.

Chrome derives unpacked extension IDs from the SHA-256 hash of the absolute
extension path. Each byte of the first 16 hash bytes produces 2 characters (one
from the high nibble, one from the low nibble), mapped to [a-p], yielding a 32-
character ID.

Playwright's `context.serviceWorkers()` does not enumerate MV3 service workers,
so we compute the ID deterministically instead of at runtime.
 */
export function deriveExtensionId(extensionPath: string): string {
  const hash = createHash("sha256").update(extensionPath).digest();
  const chars = "abcdefghijklmnop";
  let id = "";
  for (let i = 0; i < 16; i++) {
    id += chars[(hash[i] >> 4) & 0x0f];
    id += chars[hash[i] & 0x0f];
  }
  return id;
}

const EXTENSION_PATH = path.resolve(__dirname, "..");

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
  // Override the built-in context fixture with launchPersistentContext.
  // Standard browser contexts block chrome-extension:// navigation (ERR_BLOCKED_BY_CLIENT);
  // persistent contexts tied to a profile directory allow extension access.
  context: async ({}, use) => {
    const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "pw-ext-"));
    const context = await chromium.launchPersistentContext(userDataDir, {
      headless: false, // required for extension loading
      args: [
        `--disable-extensions-except=${EXTENSION_PATH}`,
        `--load-extension=${EXTENSION_PATH}`,
      ],
    });
    await use(context);
    await context.close();
  },

  serverInfo: async ({}, use) => {
    const info = loadServerInfo();
    await use(info);
  },

  extensionId: async ({ }, use) => {
    const extId = deriveExtensionId(EXTENSION_PATH);
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
