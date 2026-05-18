/**
 * Activity tab — read-only view of client.evm.requests.list/get.
 *
 * Drives the popup with a stubbed chrome.runtime so we don't depend on the
 * e2e server having a specific request history.
 */
import { test, expect, type Page } from "./fixtures";

interface MockRequest {
  id: string;
  status: string;
  sign_type: string;
  chain_id: string;
  signer_address: string;
  created_at: string;
  rule_matched_id?: string;
  signature?: string;
  error_message?: string;
  approved_by?: string;
  approved_at?: string;
  completed_at?: string;
  payload?: any;
}

async function openPopupWithActivity(
  context: any,
  extensionId: string,
  requests: MockRequest[],
  options: { activityFails?: string; requestFails?: string } = {}
): Promise<Page> {
  const page = await context.newPage();
  await page.addInitScript(
    ({ requests, options }: { requests: MockRequest[]; options: any }) => {
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
          return {
            type: "popup:state",
            connected: true,
            configured: true,
            accounts: ["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"],
            activeAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            signers: [
              {
                address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
                type: "keystore",
                enabled: true,
                locked: false,
              },
            ],
            chainId: "0x1",
            error: null,
            signerStatus: { total: 1, usable: 1, locked: 0, disabled: 0 },
          };
        }
        if (msg.type === "popup:getDashboard") {
          return { type: "popup:dashboard", signers: [], signerCount: 1, ruleCount: 0, requestCount: requests.length, apiKeyRole: "agent" };
        }
        if (msg.type === "popup:getActivity") {
          if (options.activityFails) {
            return { type: "popup:activity", ok: false, error: options.activityFails, requests: [] };
          }
          return { type: "popup:activity", ok: true, requests, total: requests.length, hasMore: false };
        }
        if (msg.type === "popup:getRequest") {
          if (options.requestFails) {
            return { type: "popup:request", ok: false, error: options.requestFails };
          }
          const r = requests.find((x) => x.id === msg.requestId);
          return { type: "popup:request", ok: true, request: r };
        }
        return {};
      };

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
    { requests, options }
  );

  await page.goto(`chrome-extension://${extensionId}/popup/popup.html`);
  await page.waitForSelector("#app");
  await expect(page.locator("#connectedView")).toBeVisible();
  return page;
}

const SAMPLE_REQUESTS: MockRequest[] = [
  {
    id: "req-1",
    status: "completed",
    sign_type: "personal",
    chain_id: "1",
    signer_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    created_at: new Date(Date.now() - 30_000).toISOString(),
    rule_matched_id: "rule-allow-personal",
    signature: "0x" + "ab".repeat(65),
    payload: { message: "hello" },
  },
  {
    id: "req-2",
    status: "rejected",
    sign_type: "transaction",
    chain_id: "137",
    signer_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    created_at: new Date(Date.now() - 60_000 * 10).toISOString(),
    error_message: "blocklist rule matched",
    payload: { transaction: { to: "0xdead", value: "0x1" } },
  },
  {
    id: "req-3",
    status: "pending",
    sign_type: "typed_data",
    chain_id: "1",
    signer_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    created_at: new Date(Date.now() - 60_000 * 60).toISOString(),
    payload: { typed_data: { primaryType: "Permit" } },
  },
];

test.describe("Activity tab (@integration)", () => {
  test("tab switches and renders requests with status badges", async ({ context, extensionId }) => {
    const page = await openPopupWithActivity(context, extensionId, SAMPLE_REQUESTS);

    // Default tab is Accounts.
    await expect(page.locator("#tabAccounts")).toBeVisible();
    await expect(page.locator("#tabActivity")).toHaveClass(/hidden/);

    await page.locator("#tabActivityBtn").click();
    await expect(page.locator("#tabActivity")).toBeVisible();
    await expect(page.locator("#tabAccounts")).toHaveClass(/hidden/);

    const items = page.locator(".activity-item");
    await expect(items).toHaveCount(3);

    await expect(page.locator(".activity-item[data-request-id='req-1'] .activity-status")).toHaveClass(/activity-status--completed/);
    await expect(page.locator(".activity-item[data-request-id='req-2'] .activity-status")).toHaveClass(/activity-status--rejected/);
    await expect(page.locator(".activity-item[data-request-id='req-3'] .activity-status")).toHaveClass(/activity-status--pending/);

    await page.close();
  });

  test("clicking a request opens the detail drawer with full fields", async ({ context, extensionId }) => {
    const page = await openPopupWithActivity(context, extensionId, SAMPLE_REQUESTS);
    await page.locator("#tabActivityBtn").click();
    await page.locator(".activity-item[data-request-id='req-1']").click();

    await expect(page.locator("#requestDrawer")).toBeVisible();
    await expect(page.locator("#drawerBody")).toContainText("req-1");
    await expect(page.locator("#drawerBody")).toContainText("rule-allow-personal");
    await expect(page.locator("#drawerBody")).toContainText("personal");
    await expect(page.locator("#drawerBody")).toContainText("hello"); // payload pretty-print

    await page.locator("#drawerCloseBtn").click();
    await expect(page.locator("#requestDrawer")).toHaveClass(/hidden/);
    await page.close();
  });

  test("rejected request detail shows the error message", async ({ context, extensionId }) => {
    const page = await openPopupWithActivity(context, extensionId, SAMPLE_REQUESTS);
    await page.locator("#tabActivityBtn").click();
    await page.locator(".activity-item[data-request-id='req-2']").click();

    await expect(page.locator("#requestDrawer")).toBeVisible();
    await expect(page.locator("#drawerBody")).toContainText("blocklist rule matched");
    await page.close();
  });

  test("empty list shows an empty-state message", async ({ context, extensionId }) => {
    const page = await openPopupWithActivity(context, extensionId, []);
    await page.locator("#tabActivityBtn").click();
    await expect(page.locator(".activity-empty")).toContainText(/No requests/i);
    await page.close();
  });

  test("activity fetch failure shows an error banner", async ({ context, extensionId }) => {
    const page = await openPopupWithActivity(context, extensionId, [], { activityFails: "Auth failed" });
    await page.locator("#tabActivityBtn").click();
    await expect(page.locator(".activity-error")).toContainText(/Auth failed/);
    await page.close();
  });

  test("refresh button re-fetches", async ({ context, extensionId }) => {
    const page = await openPopupWithActivity(context, extensionId, SAMPLE_REQUESTS);
    await page.locator("#tabActivityBtn").click();
    await expect(page.locator(".activity-item")).toHaveCount(3);
    // Refresh should not blow up.
    await page.locator("#activityRefreshBtn").click();
    await expect(page.locator(".activity-item")).toHaveCount(3);
    await page.close();
  });
});
