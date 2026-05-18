/**
 * Account switcher UX.
 *
 * Uses chrome.runtime stubbing so we can drive every signer-status
 * combination (active+usable, locked, disabled) without needing the backend
 * to be in that state.
 */
import { test, expect, type Page } from "./fixtures";

interface MockSigner {
  address: string;
  type: string;
  enabled: boolean;
  locked: boolean;
}

async function openPopupWithSigners(
  context: any,
  extensionId: string,
  signers: MockSigner[],
  activeAddress: string | null
): Promise<{ page: Page; switchCalls: () => Promise<string[]> }> {
  const page = await context.newPage();
  await page.addInitScript(
    ({ signers, activeAddress }: { signers: MockSigner[]; activeAddress: string | null }) => {
      const switchHistory: string[] = [];
      let liveActive = activeAddress;
      let liveSigners = signers;

      const responder = (msg: any): any => {
        if (msg.type === "popup:getConfig") {
          return {
            type: "popup:config",
            config: {
              remoteSignerUrl: "http://x",
              apiKeyId: "k",
              apiKeyPrivateKey: "0".repeat(64),
              selectedChain: 1,
            },
          };
        }
        if (msg.type === "popup:getState") {
          const usable = liveSigners.filter((s) => s.enabled && !s.locked);
          return {
            type: "popup:state",
            connected: true,
            configured: true,
            accounts: usable.map((s) => s.address),
            activeAddress: liveActive,
            signers: liveSigners,
            chainId: "0x1",
            error: null,
            signerStatus: {
              total: liveSigners.length,
              usable: usable.length,
              locked: liveSigners.filter((s) => s.locked).length,
              disabled: liveSigners.filter((s) => !s.enabled).length,
            },
          };
        }
        if (msg.type === "popup:getDashboard") {
          return {
            type: "popup:dashboard",
            signers: liveSigners.filter((s) => s.enabled && !s.locked).map((s) => s.address),
            signerCount: liveSigners.length,
            ruleCount: 0,
            requestCount: 0,
            apiKeyRole: "agent",
          };
        }
        if (msg.type === "popup:switchAccount") {
          switchHistory.push(msg.address);
          liveActive = msg.address;
          return { type: "popup:accountSwitched", ok: true, address: msg.address };
        }
        return {};
      };

      (window as any).__switchHistory = switchHistory;
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
    { signers, activeAddress }
  );

  await page.goto(`chrome-extension://${extensionId}/popup/popup.html`);
  await page.waitForSelector("#app");
  return {
    page,
    switchCalls: async () => page.evaluate(() => (window as any).__switchHistory as string[]),
  };
}

const A1 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const A2 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const A3 = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";

test.describe("Account switcher (@integration)", () => {
  test("renders all signers; only the active one is marked", async ({ context, extensionId }) => {
    const { page } = await openPopupWithSigners(
      context,
      extensionId,
      [
        { address: A1, type: "keystore", enabled: true, locked: false },
        { address: A2, type: "keystore", enabled: true, locked: false },
      ],
      A1
    );
    await expect(page.locator("#connectedView")).toBeVisible();
    const rows = page.locator(".account-item");
    await expect(rows).toHaveCount(2);
    // Active row shows the ✓ marker.
    await expect(page.locator(`.account-item[data-address="${A1}"] .account-marker`)).toHaveText("✓");
    await expect(page.locator(`.account-item[data-address="${A2}"] .account-marker`)).toHaveText("");
    await expect(page.locator(`.account-item[data-address="${A1}"]`)).toHaveClass(/account-item--active/);
    // Account count badge shows usable count.
    await expect(page.locator("#accountCount")).toHaveText("2");
    await page.close();
  });

  test("clicking a non-active usable row calls switchAccount", async ({ context, extensionId }) => {
    const { page, switchCalls } = await openPopupWithSigners(
      context,
      extensionId,
      [
        { address: A1, type: "keystore", enabled: true, locked: false },
        { address: A2, type: "keystore", enabled: true, locked: false },
      ],
      A1
    );
    await expect(page.locator("#connectedView")).toBeVisible();
    await page.locator(`.account-item[data-address="${A2}"]`).click();

    // Wait for re-init to mark A2 as active.
    await expect(page.locator(`.account-item[data-address="${A2}"]`)).toHaveClass(/account-item--active/, { timeout: 5_000 });
    await expect(page.locator(`.account-item[data-address="${A1}"]`)).not.toHaveClass(/account-item--active/);

    const history = await switchCalls();
    expect(history).toEqual([A2]);
    await page.close();
  });

  test("locked signer is greyed out and non-clickable", async ({ context, extensionId }) => {
    const { page, switchCalls } = await openPopupWithSigners(
      context,
      extensionId,
      [
        { address: A1, type: "keystore", enabled: true, locked: false },
        { address: A2, type: "keystore", enabled: true, locked: true }, // locked
        { address: A3, type: "keystore", enabled: false, locked: false }, // disabled
      ],
      A1
    );
    await expect(page.locator("#connectedView")).toBeVisible();

    // Both non-usable rows have the disabled modifier.
    await expect(page.locator(`.account-item[data-address="${A2}"]`)).toHaveClass(/account-item--disabled/);
    await expect(page.locator(`.account-item[data-address="${A3}"]`)).toHaveClass(/account-item--disabled/);

    // Lock + disable status icons render.
    await expect(page.locator(`.account-item[data-address="${A2}"] .account-status`)).toHaveText("🔒");
    await expect(page.locator(`.account-item[data-address="${A3}"] .account-status`)).toHaveText("⛔");

    // Clicking them does nothing — no switch IPC.
    await page.locator(`.account-item[data-address="${A2}"]`).click({ force: true });
    await page.locator(`.account-item[data-address="${A3}"]`).click({ force: true });
    await page.waitForTimeout(200);
    expect(await switchCalls()).toEqual([]);

    // Usable count only counts the unlocked-enabled ones.
    await expect(page.locator("#accountCount")).toHaveText("1");
    await page.close();
  });

  test("clicking the already-active row does nothing", async ({ context, extensionId }) => {
    const { page, switchCalls } = await openPopupWithSigners(
      context,
      extensionId,
      [{ address: A1, type: "keystore", enabled: true, locked: false }],
      A1
    );
    await page.locator(`.account-item[data-address="${A1}"]`).click();
    await page.waitForTimeout(200);
    expect(await switchCalls()).toEqual([]);
    await page.close();
  });

  test("copy button does not trigger a switch", async ({ context, extensionId }) => {
    const { page, switchCalls } = await openPopupWithSigners(
      context,
      extensionId,
      [
        { address: A1, type: "keystore", enabled: true, locked: false },
        { address: A2, type: "keystore", enabled: true, locked: false },
      ],
      A1
    );
    await page.locator(`.account-item[data-address="${A2}"] .account-copy`).click();
    await page.waitForTimeout(200);
    expect(await switchCalls()).toEqual([]);
    await page.close();
  });
});
