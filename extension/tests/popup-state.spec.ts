/**
 * Popup state-model tests.
 *
 * The popup IPC schema is small enough that we can stub
 * chrome.runtime.sendMessage and feed the popup canned background responses.
 * This lets us exercise rare-but-important paths the e2e server can't easily
 * produce (e.g. "server reachable but every signer is locked") without
 * modifying the Go test server.
 *
 * The whole point of these tests is to lock down the rule "connection state
 * MUST be decoupled from signer presence" — that misdesign is exactly what
 * confused the user originally.
 */
import { test, expect, type Page } from "./fixtures";

interface MockState {
  configured?: boolean;
  connected?: boolean;
  accounts?: string[];
  chainId?: string;
  error?: string | null;
  signerStatus?: {
    total: number;
    usable: number;
    locked: number;
    disabled: number;
  } | null;
}

async function openPopupWithMockedState(
  context: any,
  extensionId: string,
  state: MockState,
  config = {
    remoteSignerUrl: "http://example.invalid",
    apiKeyId: "k",
    apiKeyPrivateKey: "0".repeat(64),
    selectedChain: 1,
  }
): Promise<Page> {
  const page = await context.newPage();
  // addInitScript runs before popup.js. We swap in a stub of
  // chrome.runtime.sendMessage that resolves with canned data based on the
  // outgoing message type.
  await page.addInitScript(
    ({ state, config }: { state: MockState; config: any }) => {
      const canned: Record<string, any> = {
        "popup:getConfig": { type: "popup:config", config },
        "popup:getState": {
          type: "popup:state",
          configured: state.configured ?? true,
          connected: state.connected ?? false,
          accounts: state.accounts ?? [],
          chainId: state.chainId ?? "0x1",
          error: state.error ?? null,
          signerStatus: state.signerStatus ?? null,
        },
        "popup:saveConfig": { type: "popup:configSaved", ok: true },
        "popup:testConnection": { type: "popup:connectionResult", ok: true, version: "test", signerCount: 0 },
        "popup:getDashboard": {
          type: "popup:dashboard",
          signers: state.accounts ?? [],
          signerCount: state.signerStatus?.total ?? 0,
          ruleCount: 0,
          requestCount: 0,
          apiKeyRole: "agent",
        },
        "popup:openManagement": { type: "popup:managementOpened" },
      };
      // @ts-ignore — overwrite the chrome.runtime API surface popup.js uses.
      const realChrome = (window as any).chrome;
      const stub = {
        ...(realChrome || {}),
        runtime: {
          ...((realChrome && realChrome.runtime) || {}),
          lastError: null,
          sendMessage: (msg: any, cb: (resp: any) => void) => {
            const resp = canned[msg.type];
            // Mimic chrome's async callback semantics.
            setTimeout(() => cb(resp ?? {}), 0);
          },
        },
        storage: {
          local: {
            get: (_k: any, cb: (o: any) => void) => setTimeout(() => cb({}), 0),
            set: (_o: any, cb?: () => void) => setTimeout(() => cb?.(), 0),
          },
        },
        tabs: { create: (_o: any) => {} },
      };
      Object.defineProperty(window, "chrome", { value: stub, writable: true, configurable: true });
    },
    { state, config }
  );

  await page.goto(`chrome-extension://${extensionId}/popup/popup.html`);
  await page.waitForSelector("#app");
  return page;
}

test.describe("Popup state model (@integration)", () => {
  test("connected + 0 usable signers stays on connected view and shows the signer banner", async ({ context, extensionId }) => {
    const popup = await openPopupWithMockedState(context, extensionId, {
      connected: true,
      configured: true,
      accounts: [],
      chainId: "0x1",
      error: null,
      signerStatus: { total: 2, usable: 0, locked: 2, disabled: 0 },
    });

    // Critically: we are NOT on the disconnected view.
    await expect(popup.locator("#connectedView")).toBeVisible();
    await expect(popup.locator("#disconnectedView")).toHaveClass(/hidden/);

    // The signer banner is shown with an actionable message.
    await expect(popup.locator("#signerBanner")).toBeVisible();
    await expect(popup.locator("#signerBannerText")).toContainText(/locked/i);

    // Header dot stays green (we ARE connected to the server).
    await expect(popup.locator("#connectionDot")).toHaveClass(/connected/);
    await expect(popup.locator("#statusText")).toHaveText("Connected");

    await popup.close();
  });

  test("connected + 0 signers total shows 'no signers' banner, not disconnected", async ({ context, extensionId }) => {
    const popup = await openPopupWithMockedState(context, extensionId, {
      connected: true,
      configured: true,
      accounts: [],
      signerStatus: { total: 0, usable: 0, locked: 0, disabled: 0 },
    });

    await expect(popup.locator("#connectedView")).toBeVisible();
    await expect(popup.locator("#signerBanner")).toBeVisible();
    await expect(popup.locator("#signerBannerText")).toContainText(/no signers/i);

    await popup.close();
  });

  test("connected + at least one usable signer hides the banner", async ({ context, extensionId }) => {
    const popup = await openPopupWithMockedState(context, extensionId, {
      connected: true,
      configured: true,
      accounts: ["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"],
      signerStatus: { total: 1, usable: 1, locked: 0, disabled: 0 },
    });

    await expect(popup.locator("#connectedView")).toBeVisible();
    await expect(popup.locator("#signerBanner")).toHaveClass(/hidden/);

    await popup.close();
  });

  test("not configured shows disconnected without an error reason", async ({ context, extensionId }) => {
    const popup = await openPopupWithMockedState(
      context,
      extensionId,
      { configured: false, connected: false },
      { remoteSignerUrl: "", apiKeyId: "", apiKeyPrivateKey: "", selectedChain: 1 }
    );

    await expect(popup.locator("#disconnectedView")).toBeVisible();
    await expect(popup.locator("#disconnectedReason")).toHaveText("Configure your connection in Settings");

    await popup.close();
  });

  test("configured + server unreachable shows disconnected with the actual error", async ({ context, extensionId }) => {
    const popup = await openPopupWithMockedState(context, extensionId, {
      configured: true,
      connected: false,
      error: "Cannot reach server: connect ECONNREFUSED 127.0.0.1:1",
      signerStatus: null,
    });

    await expect(popup.locator("#disconnectedView")).toBeVisible();
    await expect(popup.locator("#disconnectedReason")).toContainText(/Cannot reach server/);

    await popup.close();
  });

  test("configured + auth failure shows disconnected with the actual error", async ({ context, extensionId }) => {
    const popup = await openPopupWithMockedState(context, extensionId, {
      configured: true,
      connected: false,
      error: "Auth failed (HTTP 401): signature mismatch",
      signerStatus: null,
    });

    await expect(popup.locator("#disconnectedView")).toBeVisible();
    await expect(popup.locator("#disconnectedReason")).toContainText(/Auth failed/);

    await popup.close();
  });
});
