import type { Page } from "@playwright/test";
import { expect } from "./fixtures.js";

/**
 * E2E test helpers for Remote Signer extension tests.
 */

/** Extension ID — determined at runtime by Playwright's chrome-extension loading */
export function getExtensionId(page: Page): string {
  const url = page.url();
  const match = url.match(/^chrome-extension:\/\/([a-z]+)/);
  if (!match) throw new Error("Not on a chrome-extension page");
  return match[1];
}

/** Get the extension URL for a given relative path */
export function extensionUrl(page: Page, relPath: string): string {
  return `chrome-extension://${getExtensionId(page)}/${relPath.replace(/^\//, "")}`;
}

/** Set extension config via chrome.storage.local from the service worker's context */
export async function setExtensionConfig(
  page: Page,
  config: {
    remoteSignerUrl: string;
    apiKeyId: string;
    apiKeyPrivateKey: string;
    selectedChain?: number;
  }
) {
  // Evaluate in the service worker through the popup save mechanism.
  // The popup sends a popup:saveConfig message to background.js which
  // writes to chrome.storage.local.
  await page.evaluate(
    (cfg) =>
      chrome.runtime.sendMessage({ type: "popup:saveConfig", config: cfg }),
    { ...config, selectedChain: config.selectedChain ?? 1 }
  );
}

/** Connect wallet on the dApp test page and verify connection state */
export async function connectWallet(page: Page): Promise<string[]> {
  // Click connect button
  await page.click('[data-testid="connect"]');
  // Wait for account to appear
  await page.waitForFunction(() => {
    const el = document.querySelector('[data-testid="accountDisplay"]');
    return el && el.textContent !== "Not connected";
  });
  const text = await page.textContent('[data-testid="accountDisplay"]');
  expect(text).toContain("Account: 0x");
  const match = text?.match(/0x[a-fA-F0-9]{40}/);
  return match ? [match[0]] : [];
}

/** Perform personal_sign and return the signature */
export async function personalSign(
  page: Page,
  message?: string
): Promise<string> {
  if (message) {
    await page.fill('[data-testid="personalSignInput"]', message);
  }
  await page.click('[data-testid="personalSign"]');
  await page.waitForFunction(() => {
    const el = document.querySelector('[data-testid="personalSignResult"]');
    return el && el.textContent !== "" && !el.textContent?.startsWith("Error");
  });
  const text = await page.textContent('[data-testid="personalSignResult"]');
  expect(text).toMatch(/Signature: 0x/);
  return text!.replace("Signature: ", "");
}

/** Perform eth_signTypedData and return the signature */
export async function signTypedData(page: Page): Promise<string> {
  await page.click('[data-testid="typedDataSign"]');
  await page.waitForFunction(() => {
    const el = document.querySelector('[data-testid="typedDataResult"]');
    return el && el.textContent !== "" && !el.textContent?.startsWith("Error");
  });
  const text = await page.textContent('[data-testid="typedDataResult"]');
  expect(text).toMatch(/Signature: 0x/);
  return text!.replace("Signature: ", "");
}

/** Perform eth_sendTransaction and return the tx hash */
export async function sendTransaction(page: Page): Promise<string> {
  await page.click('[data-testid="sendTransaction"]');
  await page.waitForFunction(() => {
    const el = document.querySelector('[data-testid="sendTxResult"]');
    return el && el.textContent !== "" && !el.textContent?.startsWith("Error");
  });
  const text = await page.textContent('[data-testid="sendTxResult"]');
  expect(text).toMatch(/Tx Hash: 0x/);
  return text!.replace("Tx Hash: ", "");
}
