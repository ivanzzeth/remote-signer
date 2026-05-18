/**
 * Live-dApp end-to-end tests.
 *
 * These hit real production sites (Uniswap, Polymarket, DeBank) and exercise
 * the provider's connect + sign + chain-switch surface without touching any
 * dApp UI. The goal is to catch regressions in how our EIP-1193 + EIP-6963
 * provider interacts with dApps that ship the latest connector libraries
 * (wagmi, RainbowKit, Web3-React, etc.).
 *
 * Opt-in only: skipped unless LIVE_DAPP_E2E=1 is in the environment.
 * Default CI must stay hermetic — third-party sites are flaky and rate-limit.
 *
 * Flows covered (read-only, no on-chain transactions):
 *  - EIP-6963 announce / provider injection
 *  - eth_requestAccounts
 *  - eth_chainId / eth_accounts after connect
 *  - personal_sign (SIWE-style signing)
 *  - wallet_switchEthereumChain (Uniswap → Polygon, Polymarket → Polygon)
 *
 * Run:
 *   LIVE_DAPP_E2E=1 npm run test:e2e -- live-dapps.spec.ts
 *
 * Skipping:
 *   tests are .skip'd automatically when LIVE_DAPP_E2E isn't set, so they
 *   appear in the test report as "skipped" rather than passing silently.
 */
import { test, expect, type Page } from "./fixtures";
import { injectStorageConfig } from "./helpers";

const LIVE = process.env.LIVE_DAPP_E2E === "1";

// Each dApp gets its own timeout because cold-loading these pages is heavy.
const NAV_TIMEOUT = 60_000;
const PROVIDER_TIMEOUT = 30_000;
const RPC_TIMEOUT = 45_000;

// ── Helpers ──────────────────────────────────────────────────────────────────

async function waitForInjectedProvider(page: Page, timeout = PROVIDER_TIMEOUT) {
  // EIP-6963 fires "eip6963:announceProvider" once the inpage script loads,
  // but most dApps also set window.ethereum. Wait for whichever lands first.
  await page.waitForFunction(
    () => {
      const eth = (window as any).ethereum;
      return !!eth && typeof eth.request === "function";
    },
    { timeout }
  );
}

async function rpc<T = unknown>(page: Page, method: string, params: unknown[] = []) {
  return page.evaluate(
    async ({ method, params, timeoutMs }: { method: string; params: unknown[]; timeoutMs: number }) => {
      const provider = (window as any).ethereum!;
      const timeout = new Promise<{ ok: false; error: { code?: number; message: string } }>(
        (resolve) =>
          setTimeout(
            () => resolve({ ok: false, error: { message: `Timed out after ${timeoutMs}ms` } }),
            timeoutMs
          )
      );
      const call = (async () => {
        try {
          const result = await provider.request({ method, params });
          return { ok: true as const, result };
        } catch (err: any) {
          return { ok: false as const, error: { code: err?.code, message: err?.message ?? String(err) } };
        }
      })();
      return (await Promise.race([call, timeout])) as
        | { ok: true; result: T }
        | { ok: false; error: { code?: number; message: string } };
    },
    { method, params, timeoutMs: RPC_TIMEOUT }
  );
}

async function verifyEip6963Announce(page: Page) {
  // EIP-6963 says wallets dispatch "eip6963:announceProvider" both proactively
  // and in response to "eip6963:requestProvider". Listen for one within 5s
  // of explicitly requesting.
  return page.evaluate(async () => {
    const detail = await new Promise<any | null>((resolve) => {
      const listener = (ev: any) => {
        window.removeEventListener("eip6963:announceProvider", listener as any);
        resolve(ev.detail ?? null);
      };
      window.addEventListener("eip6963:announceProvider", listener as any);
      window.dispatchEvent(new Event("eip6963:requestProvider"));
      setTimeout(() => {
        window.removeEventListener("eip6963:announceProvider", listener as any);
        resolve(null);
      }, 5000);
    });
    if (!detail) return { announced: false };
    return {
      announced: true,
      uuid: detail.info?.uuid,
      name: detail.info?.name,
      rdns: detail.info?.rdns,
      hasProvider: typeof detail.provider?.request === "function",
    };
  });
}

// ── Suite gate ───────────────────────────────────────────────────────────────

test.describe("Live dApp provider integration (@live)", () => {
  test.skip(!LIVE, "Set LIVE_DAPP_E2E=1 to run live-dApp tests");
  test.describe.configure({ mode: "serial", retries: 1 });

  test.beforeEach(async ({ context, extensionId, serverInfo }) => {
    // Pre-configure the extension so the provider initialises on first use.
    const seed = await context.newPage();
    await seed.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await seed.waitForSelector("#app");
    await injectStorageConfig(seed, {
      remoteSignerUrl: serverInfo.base_url,
      apiKeyId: serverInfo.admin_api_key_id,
      apiKeyPrivateKey: serverInfo.admin_api_key_hex,
    });
    await seed.close();
  });

  // ── Uniswap (Ethereum mainnet → Polygon switch) ──────────────────────────

  test("Uniswap: EIP-6963 + eth_requestAccounts + personal_sign", async ({ context }) => {
    const page = await context.newPage();
    page.setDefaultTimeout(NAV_TIMEOUT);
    await page.goto("https://app.uniswap.org/", { waitUntil: "domcontentloaded" });
    await waitForInjectedProvider(page);

    const announce = await verifyEip6963Announce(page);
    expect(announce.announced).toBe(true);
    expect(announce.hasProvider).toBe(true);

    const accounts = await rpc<string[]>(page, "eth_requestAccounts");
    expect(accounts.ok, `eth_requestAccounts failed: ${!accounts.ok ? accounts.error.message : ""}`).toBe(true);
    if (accounts.ok) {
      expect(accounts.result.length).toBeGreaterThan(0);
      expect(accounts.result[0]).toMatch(/^0x[a-fA-F0-9]{40}$/);
    }

    const chainId = await rpc<string>(page, "eth_chainId");
    expect(chainId.ok).toBe(true);
    if (chainId.ok) expect(chainId.result).toMatch(/^0x[0-9a-f]+$/);

    if (accounts.ok) {
      const messageHex = "0x" + Buffer.from("SIWE: Uniswap test").toString("hex");
      const sig = await rpc<string>(page, "personal_sign", [messageHex, accounts.result[0]]);
      expect(sig.ok, `personal_sign failed: ${!sig.ok ? sig.error.message : ""}`).toBe(true);
      if (sig.ok) {
        expect(sig.result).toMatch(/^0x[a-fA-F0-9]{130}$/);
      }
    }
    await page.close();
  });

  test("Uniswap: wallet_switchEthereumChain to Polygon (137)", async ({ context }) => {
    const page = await context.newPage();
    page.setDefaultTimeout(NAV_TIMEOUT);
    await page.goto("https://app.uniswap.org/", { waitUntil: "domcontentloaded" });
    await waitForInjectedProvider(page);

    // 137 is in the default chain registry.
    const sw = await rpc(page, "wallet_switchEthereumChain", [{ chainId: "0x89" }]);
    expect(sw.ok, `switch failed: ${!sw.ok ? sw.error.message : ""}`).toBe(true);

    const chainId = await rpc<string>(page, "eth_chainId");
    expect(chainId.ok).toBe(true);
    if (chainId.ok) expect(chainId.result.toLowerCase()).toBe("0x89");

    await page.close();
  });

  // ── Polymarket (Polygon) ─────────────────────────────────────────────────

  test("Polymarket: provider injection, requestAccounts, personal_sign on Polygon", async ({ context }) => {
    const page = await context.newPage();
    page.setDefaultTimeout(NAV_TIMEOUT);
    await page.goto("https://polymarket.com/", { waitUntil: "domcontentloaded" });
    await waitForInjectedProvider(page);

    const announce = await verifyEip6963Announce(page);
    expect(announce.announced).toBe(true);

    // Polymarket runs on Polygon — switch up front. If the cold load already
    // arrived on Polygon, the switch is a no-op.
    const sw = await rpc(page, "wallet_switchEthereumChain", [{ chainId: "0x89" }]);
    expect(sw.ok, `switch failed: ${!sw.ok ? sw.error.message : ""}`).toBe(true);

    const accounts = await rpc<string[]>(page, "eth_requestAccounts");
    expect(accounts.ok).toBe(true);

    if (accounts.ok) {
      const messageHex = "0x" + Buffer.from("SIWE: Polymarket test").toString("hex");
      const sig = await rpc<string>(page, "personal_sign", [messageHex, accounts.result[0]]);
      expect(sig.ok, `personal_sign failed: ${!sig.ok ? sig.error.message : ""}`).toBe(true);
      if (sig.ok) expect(sig.result).toMatch(/^0x[a-fA-F0-9]{130}$/);
    }
    await page.close();
  });

  // ── DeBank (multi-chain reads) ───────────────────────────────────────────

  test("DeBank: provider injection + eth_chainId + eth_blockNumber via RPC", async ({ context }) => {
    const page = await context.newPage();
    page.setDefaultTimeout(NAV_TIMEOUT);
    await page.goto("https://debank.com/", { waitUntil: "domcontentloaded" });
    await waitForInjectedProvider(page);

    const announce = await verifyEip6963Announce(page);
    expect(announce.announced).toBe(true);

    const chainId = await rpc<string>(page, "eth_chainId");
    expect(chainId.ok).toBe(true);

    // Exercises the rpcOverrides path we just wired up — without a registry
    // entry for chain 1 this throws "No RPC URL configured for chain 1".
    const bn = await rpc<string>(page, "eth_blockNumber");
    expect(bn.ok, `eth_blockNumber failed: ${!bn.ok ? bn.error.message : ""}`).toBe(true);
    if (bn.ok) expect(bn.result).toMatch(/^0x[0-9a-f]+$/i);

    await page.close();
  });

  test("DeBank: eth_requestAccounts + personal_sign", async ({ context }) => {
    const page = await context.newPage();
    page.setDefaultTimeout(NAV_TIMEOUT);
    await page.goto("https://debank.com/", { waitUntil: "domcontentloaded" });
    await waitForInjectedProvider(page);

    const accounts = await rpc<string[]>(page, "eth_requestAccounts");
    expect(accounts.ok, `eth_requestAccounts failed: ${!accounts.ok ? accounts.error.message : ""}`).toBe(true);

    if (accounts.ok) {
      const messageHex = "0x" + Buffer.from("SIWE: DeBank test").toString("hex");
      const sig = await rpc<string>(page, "personal_sign", [messageHex, accounts.result[0]]);
      expect(sig.ok, `personal_sign failed: ${!sig.ok ? sig.error.message : ""}`).toBe(true);
      if (sig.ok) expect(sig.result).toMatch(/^0x[a-fA-F0-9]{130}$/);
    }
    await page.close();
  });
});
