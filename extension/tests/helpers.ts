import type { Page } from "@playwright/test";
import { fileURLToPath } from "url";
import path from "path";
import fs from "fs";
import { RemoteSignerClient } from "remote-signer-client";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ── Admin client (runtime state manipulation) ────────────────────────────────

/**
 * Build a RemoteSignerClient using the admin API key from the running e2e
 * server. Tests use this when they need to transition backend state into a
 * configuration the static seed doesn't ship (e.g. locking a signer to
 * exercise the greyed-out UI path).
 */
export function adminClient(serverInfo: {
  base_url: string;
  admin_api_key_id: string;
  admin_api_key_hex: string;
}): RemoteSignerClient {
  return new RemoteSignerClient({
    baseURL: serverInfo.base_url,
    apiKeyID: serverInfo.admin_api_key_id,
    privateKey: serverInfo.admin_api_key_hex,
    httpClient: { fetch: fetch.bind(globalThis) },
  });
}

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

/** Navigate to the dApp test page (served via HTTP to support MV3 content-script injection) and wait for window.ethereum */
export async function openDappAndWaitForProvider(page: Page, timeout = 15_000): Promise<void> {
  const statePath = path.resolve(__dirname, ".e2e-state", "server.json");
  const info = JSON.parse(fs.readFileSync(statePath, "utf-8"));
  const dappUrl = info.dapp_url || `file://${path.resolve(__dirname, ".e2e-state", "dapp-test-page.html")}`;
  await page.goto(dappUrl);

  // Wait until the dApp page has both: (a) window.ethereum injected by the
  // content script's async <script src=inpage.js>, and (b) the page's own
  // listeners attached. Without the second condition, tests that fire
  // eth_requestAccounts immediately race the page's "attachListeners"
  // setup and lose the connect/accountsChanged event.
  await page.waitForFunction(
    () =>
      !!window.ethereum &&
      document.getElementById("providerStatus")?.textContent === "available",
    { timeout }
  );
}

/**
 * Add + switch the active chain to the local anvil instance started by
 * global-setup. Tests that broadcast transactions call this after opening
 * the dApp so eth_sendTransaction lands on a real-but-local RPC instead of
 * the public default (which would rate-limit / reject for lack of funds).
 *
 * Returns false when global-setup didn't find anvil on PATH — callers can
 * use that to skip themselves rather than fail with "no RPC".
 */
export async function switchToAnvil(page: Page, serverInfo: {
  anvil_url?: string;
  anvil_chain_id?: number;
}): Promise<boolean> {
  if (!serverInfo.anvil_url) return false;
  // Reset anvil state first so each test starts from a clean nonce/block
  // height — otherwise tests bleed into each other ("nonce too low") as
  // soon as more than one of them broadcasts.
  await fetch(serverInfo.anvil_url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "anvil_reset", params: [] }),
  }).catch(() => {});

  const chainIdHex = "0x" + (serverInfo.anvil_chain_id ?? 31337).toString(16);
  await dappEIP1193Call(page, "wallet_addEthereumChain", {
    chainId: chainIdHex,
    chainName: "Anvil",
    rpcUrls: [serverInfo.anvil_url],
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  });
  const switched = await dappEIP1193Call(page, "wallet_switchEthereumChain", {
    chainId: chainIdHex,
  });
  return switched.ok === true;
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
