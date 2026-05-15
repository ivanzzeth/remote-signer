import { test as base, expect } from "@playwright/test";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Extension info stored by globalSetup */
export interface ServerConfig {
  baseURL: string;
  signerAddress: string;
  adminAPIKeyID: string;
  adminAPIKeyHex: string;
  nonAdminAPIKeyID: string;
  nonAdminAPIKeyHex: string;
}

/** Load the server config written by globalSetup */
export function loadServerConfig(): ServerConfig {
  const configPath = path.join(__dirname, ".server-config.json");
  return JSON.parse(fs.readFileSync(configPath, "utf-8"));
}

export interface ExtensionFixtures {
  /** Remote-signer server base URL */
  serverURL: string;

  /** Admin API key ID */
  adminAPIKeyID: string;

  /** Admin API key (Ed25519 hex) */
  adminAPIKeyHex: string;

  /** Non-admin API key ID */
  nonAdminAPIKeyID: string;

  /** Non-admin API key (Ed25519 hex) */
  nonAdminAPIKeyHex: string;

  /** Signer address from test server */
  signerAddress: string;

  /** Open the extension popup page */
  openPopup: () => Promise<void>;

  /** Navigate to the local dApp test page */
  openDApp: () => Promise<void>;
}

export const test = base.extend<ExtensionFixtures>({
  serverURL: async ({}, use) => {
    const cfg = loadServerConfig();
    await use(cfg.baseURL);
  },

  adminAPIKeyID: async ({}, use) => {
    const cfg = loadServerConfig();
    await use(cfg.adminAPIKeyID);
  },

  adminAPIKeyHex: async ({}, use) => {
    const cfg = loadServerConfig();
    await use(cfg.adminAPIKeyHex);
  },

  nonAdminAPIKeyID: async ({}, use) => {
    const cfg = loadServerConfig();
    await use(cfg.nonAdminAPIKeyID);
  },

  nonAdminAPIKeyHex: async ({}, use) => {
    const cfg = loadServerConfig();
    await use(cfg.nonAdminAPIKeyHex);
  },

  signerAddress: async ({}, use) => {
    const cfg = loadServerConfig();
    await use(cfg.signerAddress);
  },

  openPopup: async ({ context }, use) => {
    await use(async () => {
      // The extension popup URL is chrome-extension://<id>/popup/popup.html
      // We need to find it from the service worker or by iterating background pages.
      // Instead, open the extension via its popup action click programmatically.
      await context.pages()[0]?.bringToFront();
    });
  },

  openDApp: async ({ page }, use) => {
    await use(async () => {
      const dappPath = path.resolve(__dirname, "dapp-test-page.html");
      await page.goto(`file://${dappPath}`);
    });
  },
});

export { expect } from "@playwright/test";
