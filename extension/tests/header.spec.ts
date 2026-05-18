/**
 * MetaMask-style header — chain dropdown, signer chip, role badge,
 * "Policy-controlled signing" tagline.
 */
import { test, expect, type Page } from "./fixtures";

async function openMockedPopup(
  context: any,
  extensionId: string,
  opts: {
    signers?: Array<{ address: string; type: string; enabled: boolean; locked: boolean }>;
    activeAddress?: string | null;
    chainIdHex?: string;
    apiKeyRole?: string;
  }
): Promise<{ page: Page; switchCalls: () => Promise<string[]>; chainCalls: () => Promise<number[]> }> {
  const page = await context.newPage();
  await page.addInitScript(
    ({ opts }: { opts: any }) => {
      const switchHistory: string[] = [];
      const chainHistory: number[] = [];
      let liveActive = opts.activeAddress ?? null;
      let liveChain = opts.chainIdHex || "0x1";

      const responder = (msg: any): any => {
        if (msg.type === "popup:getConfig") {
          return {
            type: "popup:config",
            config: {
              remoteSignerUrl: "http://x",
              apiKeyId: "k",
              apiKeyPrivateKey: "0".repeat(64),
              selectedChain: parseInt(liveChain, 16) || 1,
            },
          };
        }
        if (msg.type === "popup:getState") {
          const signers = opts.signers || [];
          const usable = signers.filter((s: any) => s.enabled && !s.locked);
          return {
            type: "popup:state",
            connected: true,
            configured: true,
            accounts: usable.map((s: any) => s.address),
            activeAddress: liveActive,
            signers,
            chainId: liveChain,
            error: null,
            signerStatus: {
              total: signers.length,
              usable: usable.length,
              locked: signers.filter((s: any) => s.locked).length,
              disabled: signers.filter((s: any) => !s.enabled).length,
            },
          };
        }
        if (msg.type === "popup:getDashboard") {
          return {
            type: "popup:dashboard",
            signers: [],
            signerCount: (opts.signers || []).length,
            ruleCount: 0,
            requestCount: 0,
            apiKeyRole: opts.apiKeyRole || "agent",
          };
        }
        if (msg.type === "popup:saveConfig") {
          if (msg.config && typeof msg.config.selectedChain === "number") {
            liveChain = "0x" + msg.config.selectedChain.toString(16);
            chainHistory.push(msg.config.selectedChain);
          }
          return { type: "popup:configSaved", ok: true };
        }
        if (msg.type === "popup:switchAccount") {
          switchHistory.push(msg.address);
          liveActive = msg.address;
          return { type: "popup:accountSwitched", ok: true, address: msg.address };
        }
        if (msg.type === "popup:getActivity") {
          return { type: "popup:activity", ok: true, requests: [], total: 0, hasMore: false };
        }
        return {};
      };

      (window as any).__switchHistory = switchHistory;
      (window as any).__chainHistory = chainHistory;
      const realChrome = (window as any).chrome;
      Object.defineProperty(window, "chrome", {
        value: {
          ...(realChrome || {}),
          runtime: {
            ...((realChrome && realChrome.runtime) || {}),
            lastError: null,
            sendMessage: (msg: any, cb: (resp: any) => void) =>
              setTimeout(() => cb(responder(msg)), 0),
          },
          storage: {
            local: {
              get: (_k: any, cb: (o: any) => void) => setTimeout(() => cb({}), 0),
              set: (_o: any, cb?: () => void) => setTimeout(() => cb?.(), 0),
            },
          },
          tabs: { create: () => {} },
        },
        writable: true,
        configurable: true,
      });
    },
    { opts }
  );

  await page.goto(`chrome-extension://${extensionId}/popup/popup.html`);
  await page.waitForSelector("#app");
  await expect(page.locator("#connectedView")).toBeVisible();
  return {
    page,
    switchCalls: async () => page.evaluate(() => (window as any).__switchHistory as string[]),
    chainCalls: async () => page.evaluate(() => (window as any).__chainHistory as number[]),
  };
}

const A1 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const A2 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

test.describe("MetaMask-style header (@integration)", () => {
  test("tagline reads 'Policy-controlled signing'", async ({ context, extensionId }) => {
    const { page } = await openMockedPopup(context, extensionId, {
      signers: [{ address: A1, type: "keystore", enabled: true, locked: false }],
      activeAddress: A1,
    });
    await expect(page.locator(".logo-subtitle")).toHaveText("Policy-controlled signing");
    await page.close();
  });

  test("header chain chip shows current chain and opens the dropdown", async ({ context, extensionId }) => {
    const { page } = await openMockedPopup(context, extensionId, {
      signers: [{ address: A1, type: "keystore", enabled: true, locked: false }],
      activeAddress: A1,
      chainIdHex: "0x1",
    });
    await expect(page.locator("#appbarChainBtn")).toBeVisible();
    await expect(page.locator("#appbarChainLabel")).toHaveText("Ethereum");

    await page.locator("#appbarChainBtn").click();
    await expect(page.locator("#chainDropdown")).toBeVisible();
    // Active chain has the ✓ marker.
    const activeItem = page.locator("#chainDropdown .appbar-dropdown-item--active");
    await expect(activeItem).toHaveCount(1);
    await expect(activeItem).toContainText("Ethereum");

    await page.close();
  });

  test("picking a chain from the dropdown updates the chip and fires saveConfig", async ({ context, extensionId }) => {
    const { page, chainCalls } = await openMockedPopup(context, extensionId, {
      signers: [{ address: A1, type: "keystore", enabled: true, locked: false }],
      activeAddress: A1,
      chainIdHex: "0x1",
    });
    await page.locator("#appbarChainBtn").click();
    // Polygon row.
    await page.locator("#chainDropdown .appbar-dropdown-item:has-text('Polygon')").click();
    await expect(page.locator("#appbarChainLabel")).toHaveText("Polygon");
    expect(await chainCalls()).toContain(137);
    await page.close();
  });

  test("signer chip shows shortened active address and opens the signer dropdown", async ({ context, extensionId }) => {
    const { page } = await openMockedPopup(context, extensionId, {
      signers: [
        { address: A1, type: "keystore", enabled: true, locked: false },
        { address: A2, type: "keystore", enabled: true, locked: false },
      ],
      activeAddress: A1,
    });
    await expect(page.locator("#appbarSignerBtn")).toBeVisible();
    await expect(page.locator("#appbarSignerLabel")).toContainText("0xf39");

    await page.locator("#appbarSignerBtn").click();
    await expect(page.locator("#signerDropdown")).toBeVisible();
    await expect(page.locator("#signerDropdown .appbar-dropdown-item")).toHaveCount(2);
    await expect(page.locator("#signerDropdown .appbar-dropdown-item--active")).toHaveCount(1);
    await page.close();
  });

  test("clicking another signer in the dropdown switches the active account", async ({ context, extensionId }) => {
    const { page, switchCalls } = await openMockedPopup(context, extensionId, {
      signers: [
        { address: A1, type: "keystore", enabled: true, locked: false },
        { address: A2, type: "keystore", enabled: true, locked: false },
      ],
      activeAddress: A1,
    });
    await page.locator("#appbarSignerBtn").click();
    // The item that isn't currently active.
    await page.locator(`#signerDropdown .appbar-dropdown-item:not(.appbar-dropdown-item--active)`).first().click();
    await expect(page.locator("#appbarSignerLabel")).toContainText("0x709", { timeout: 5_000 });
    expect(await switchCalls()).toEqual([A2]);
    await page.close();
  });

  test("locked signer is disabled in the dropdown", async ({ context, extensionId }) => {
    const { page, switchCalls } = await openMockedPopup(context, extensionId, {
      signers: [
        { address: A1, type: "keystore", enabled: true, locked: false },
        { address: A2, type: "keystore", enabled: true, locked: true },
      ],
      activeAddress: A1,
    });
    await page.locator("#appbarSignerBtn").click();
    const lockedRow = page.locator("#signerDropdown .appbar-dropdown-item--disabled");
    await expect(lockedRow).toHaveCount(1);
    await expect(lockedRow).toContainText("🔒");
    // Clicking the locked row does not fire a switch.
    await lockedRow.click({ force: true });
    await page.waitForTimeout(150);
    expect(await switchCalls()).toEqual([]);
    await page.close();
  });

  test("role badge reflects the apiKeyRole from dashboard", async ({ context, extensionId }) => {
    const { page } = await openMockedPopup(context, extensionId, {
      signers: [{ address: A1, type: "keystore", enabled: true, locked: false }],
      activeAddress: A1,
      apiKeyRole: "admin",
    });
    await expect(page.locator("#roleBadge")).toBeVisible();
    await expect(page.locator("#roleBadge")).toHaveText("admin");
    await expect(page.locator("#roleBadge")).toHaveClass(/role-badge--admin/);
    await page.close();
  });

  test("clicking outside the dropdown dismisses it", async ({ context, extensionId }) => {
    const { page } = await openMockedPopup(context, extensionId, {
      signers: [{ address: A1, type: "keystore", enabled: true, locked: false }],
      activeAddress: A1,
    });
    await page.locator("#appbarChainBtn").click();
    await expect(page.locator("#chainDropdown")).toBeVisible();
    // Click on something far away.
    await page.locator(".logo-text").click();
    await expect(page.locator("#chainDropdown")).toHaveClass(/hidden/, { timeout: 2_000 });
    await page.close();
  });
});
