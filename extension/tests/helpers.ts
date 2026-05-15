import type { Page } from "@playwright/test";
import { fileURLToPath } from "url";
import path from "path";
import fs from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ── Storage helpers ──────────────────────────────────────────────────────────

/**
 * Inject config into chrome.storage.local for the extension.
 * Call this before opening the popup so it starts pre-configured.
 */
export async function injectStorageConfig(
  page: Page,
  config: {
    remoteSignerUrl: string;
    apiKeyId: string;
    apiKeyPrivateKey: string;
    selectedChain?: number;
  }
): Promise<void> {
  await page.evaluate((cfg) => {
    return new Promise<void>((resolve, reject) => {
      chrome.storage.local.set({ remoteSignerConfig: cfg }, () => {
        if (chrome.runtime.lastError) {
          reject(chrome.runtime.lastError.message);
        } else {
          resolve();
        }
      });
    });
  }, config);
}

// ── Popup Interactions ───────────────────────────────────────────────────────

/** Navigate to the popup and wait for a specific view */
export async function openPopupAndWaitForView(
  extensionId: string,
  context: any,
  viewSelector: string,
  timeout = 10_000
): Promise<Page> {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/popup/popup.html`);
  await page.waitForSelector(viewSelector, { timeout });
  return page;
}

/** Get the text content of an element by ID */
export async function getPopupElementText(page: Page, elementId: string): Promise<string> {
  return page.locator(`#${elementId}`).textContent() ?? "";
}

/** Switch to settings view and fill configuration */
export async function fillPopupConfig(
  page: Page,
  config: { url?: string; apiKeyId?: string; apiKeyPrivateKey?: string }
): Promise<void> {
  // Click Settings button to switch to settings view
  await page.click("#settingsBtn");
  await page.waitForSelector("#settingsView:not(.hidden)", { timeout: 5_000 });

  if (config.url != null) {
    await page.fill("#inputUrl", config.url);
  }
  if (config.apiKeyId != null) {
    await page.fill("#inputKeyId", config.apiKeyId);
  }
  if (config.apiKeyPrivateKey != null) {
    await page.fill("#inputPrivateKey", config.apiKeyPrivateKey);
  }
}

// ── dApp Page Interactions ───────────────────────────────────────────────────

/** Navigate to the dApp test page and wait for window.ethereum to be injected */
export async function openDappAndWaitForProvider(page: Page, timeout = 15_000): Promise<void> {
  const dappPath = path.resolve(__dirname, ".e2e-state", "dapp-test-page.html");
  await page.goto(`file://${dappPath}`);

  await page.waitForFunction(() => !!window.ethereum, { timeout });
}

/** Call an EIP-1193 method on the dApp page and return the result */
export async function dappEIP1193Call(
  page: Page,
  method: string,
  ...params: any[]
): Promise<{ ok: boolean; result?: any; error?: any }> {
  return page.evaluate(
    async ({ method, params }: { method: string; params: any[] }) => {
      try {
        const result = await window.ethereum!.request({ method, params });
        return { ok: true, result };
      } catch (err: any) {
        return { ok: false, error: { code: err.code, message: err.message } };
      }
    },
    { method, params }
  );
}

// ── Wallet Helpers ───────────────────────────────────────────────────────────

/** ABI-encode a simple ERC-20 transfer for test transactions */
export function encodeERC20Transfer(to: string, amount: string): string {
  // transfer(address to, uint256 value) — 4-byte selector a9059cbb
  const selector = "a9059cbb";
  const toPadded = to.replace("0x", "").padStart(64, "0");
  const amountPadded = BigInt(amount).toString(16).padStart(64, "0");
  return "0x" + selector + toPadded + amountPadded;
}

// ── Test Data ────────────────────────────────────────────────────────────────

export const TEST_ACCOUNTS = {
  signer: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  recipient: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  burn: "0x000000000000000000000000000000000000dEaD",
  treasury: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
} as const;

export const TEST_CHAINS = {
  ethereum: "0x1",
  polygon: "0x89",
  sepolia: "0xaa36a7",
} as const;
