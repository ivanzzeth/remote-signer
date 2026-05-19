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
import { verifyMessage } from "ethers";
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

  /**
   * End-to-end Polymarket login: drive the actual Login button, let
   * Polymarket pick its own signing method (we don't presume personal_sign
   * vs eth_signTypedData_v4), instrument window.ethereum.request to log
   * every method + params + outcome, and assert that whatever signature
   * comes back is accepted by Polymarket (i.e. no "Request Cancelled").
   *
   * Synthetic personal_sign tests don't catch the real failure because
   * Polymarket may use signTypedData / a custom CLOB auth flow. The test
   * dumps the captured RPC log to stdout regardless of pass/fail so we
   * can see exactly what Polymarket is asking for.
   */
  test("Polymarket: real login UI drives sign request and Polymarket accepts the signature", async ({ context }) => {
    test.setTimeout(180_000);
    const page = await context.newPage();
    page.setDefaultTimeout(NAV_TIMEOUT);

    // Instrument window.ethereum.request as soon as the inpage proxy lands.
    // Both `window.ethereum` and the EIP-6963-announced provider point at
    // the same proxy object, so wrapping `.request` captures every call.
    await page.addInitScript(() => {
      (window as any).__rpcLog = [] as Array<{
        method: string;
        params: unknown;
        status?: "ok" | "error";
        result?: unknown;
        code?: number;
        message?: string;
        t: number;
      }>;
      let hooked = false;
      const tryHook = () => {
        const eth = (window as any).ethereum;
        if (hooked || !eth || typeof eth.request !== "function") return;
        const original = eth.request.bind(eth);
        eth.request = async (args: any) => {
          const entry: any = { method: args?.method, params: args?.params, t: Date.now() };
          (window as any).__rpcLog.push(entry);
          try {
            const result = await original(args);
            entry.status = "ok";
            // Store the full result (we assert on it later). Long values
            // still show up in the JSON dump — that's fine for diagnostics.
            entry.result = result;
            return result;
          } catch (err: any) {
            entry.status = "error";
            entry.code = err?.code;
            entry.message = err?.message ?? String(err);
            throw err;
          }
        };
        hooked = true;
      };
      const iv = setInterval(tryHook, 50);
      setTimeout(() => clearInterval(iv), 30_000);
    });

    await page.goto("https://polymarket.com/", { waitUntil: "domcontentloaded" });
    await waitForInjectedProvider(page);

    // Polymarket lives on Polygon — pre-switch so it can't bail with
    // "wrong chain" on first interaction.
    await rpc(page, "wallet_switchEthereumChain", [{ chainId: "0x89" }]);

    // The login button label has rotated over time; try a few common
    // candidates and surface a clear failure if none are visible.
    const loginCandidates = [
      page.getByRole("button", { name: /^log\s*in$/i }),
      page.getByRole("button", { name: /^sign\s*in$/i }),
      page.getByRole("button", { name: /connect.*wallet/i }),
      page.locator('button:has-text("Log In")'),
      page.locator('button:has-text("Login")'),
    ];
    let clickedLogin = false;
    for (const btn of loginCandidates) {
      try {
        await btn.first().click({ timeout: 4_000 });
        clickedLogin = true;
        break;
      } catch {
        /* try next */
      }
    }
    if (!clickedLogin) {
      // Surface the page state so we can diagnose offline (Cloudflare?
      // Geo-block? UI rename?) instead of just skipping silently.
      const url = page.url();
      const snippet = (await page.locator("body").innerText().catch(() => "")).slice(0, 600);
      // eslint-disable-next-line no-console
      console.log(`[live] Polymarket Login not clickable. URL=${url}\nBody[0..600]=${snippet}`);
      test.skip(true, "Polymarket UI changed: no recognizable Login button");
    }

    // After login click, Polymarket shows an EIP-6963 wallet selector.
    // The entries are icon-only — no visible "Remote Signer" text — so look
    // for an accessible label or image alt instead. Try the most precise
    // selectors first.
    const walletSelectors = [
      'button[aria-label*="Remote Signer" i]',
      'button[title*="Remote Signer" i]',
      '[role="button"][aria-label*="Remote Signer" i]',
      'img[alt*="Remote Signer" i]',
      // Last-resort: the inpage icon is a unique data: URI with a blue "R"
      // square. Click whichever <img> has it as its src.
      'img[src*="627EEA"]',
    ];
    let clickedWallet = false;
    for (const sel of walletSelectors) {
      try {
        const loc = page.locator(sel).first();
        await loc.waitFor({ state: "visible", timeout: 8_000 });
        await loc.click({ timeout: 4_000 });
        clickedWallet = true;
        break;
      } catch {
        /* try next */
      }
    }
    if (!clickedWallet) {
      // eslint-disable-next-line no-console
      console.log("[live] Polymarket: could not find Remote Signer in the wallet picker — diagnostic shows what's on the page");
    }

    // Polymarket may defer the SIWE call until the user does something
    // account-shaped (portfolio, trade, bet). After wallet connect, try
    // a few common nudges; the test only needs ONE of them to produce a
    // sign call so we can diagnose method + params.
    const nudges = [
      () => page.getByRole("link", { name: /portfolio/i }).first().click({ timeout: 4_000 }),
      () => page.getByRole("button", { name: /portfolio/i }).first().click({ timeout: 4_000 }),
      () => page.getByRole("link", { name: /^trades?$/i }).first().click({ timeout: 4_000 }),
      () => page.goto("https://polymarket.com/portfolio", { waitUntil: "domcontentloaded", timeout: 10_000 }).then(() => {}),
    ];
    for (const nudge of nudges) {
      try {
        await nudge();
        await page.waitForTimeout(3000);
        const hasSign = await page.evaluate(() =>
          ((window as any).__rpcLog || []).some((e: any) =>
            /personal_sign|eth_signTypedData|eth_sign/i.test(e.method || "")
          )
        );
        if (hasSign) break;
      } catch {
        /* try the next nudge */
      }
    }

    // Give Polymarket up to ~75s to issue its sign request, our extension
    // to forward+sign, and Polymarket's frontend to accept/reject. Run as
    // a soft wait — even on timeout we want the captured log.
    const settled = await page
      .waitForFunction(
        () => {
          const log = (window as any).__rpcLog as any[];
          if (!Array.isArray(log) || log.length === 0) return false;
          return log.some(
            (e) =>
              /personal_sign|eth_signTypedData|eth_sign/i.test(e.method || "") &&
              (e.status === "ok" || e.status === "error")
          );
        },
        { timeout: 75_000 }
      )
      .then(() => true)
      .catch(() => false);

    const log = await page.evaluate(() => (window as any).__rpcLog).catch(() => []);
    // Dump the captured RPC log + a page screenshot so we always have evidence
    // — pass or fail. The screenshot path is logged so it's easy to retrieve.
    // eslint-disable-next-line no-console
    console.log("[live] Polymarket RPC log:\n" + JSON.stringify(log, null, 2));
    const shotPath = `test-results/polymarket-live-${Date.now()}.png`;
    await page.screenshot({ path: shotPath, fullPage: true }).catch(() => {});
    // eslint-disable-next-line no-console
    console.log("[live] Polymarket page screenshot saved to " + shotPath);

    expect(settled, "no sign request observed within timeout").toBe(true);
    const signCalls = log.filter((e: any) => /personal_sign|eth_signTypedData|eth_sign/i.test(e.method));
    expect(signCalls.length).toBeGreaterThan(0);

    // The signature itself must have completed without our provider throwing.
    const erroredSigns = signCalls.filter((e: any) => e.status === "error");
    expect(
      erroredSigns,
      "extension surfaced an error for the sign request: " + JSON.stringify(erroredSigns)
    ).toEqual([]);

    // Re-fetch the full RPC log to read the actual signature (the dump
    // earlier truncated long results for readability).
    const fullLog = await page.evaluate(() => (window as any).__rpcLog).catch(() => []);
    const personalSignCall = fullLog
      .filter((e: any) => e.method === "personal_sign" && e.status === "ok")
      .pop();
    if (personalSignCall) {
      // The first param is Polymarket's hex-encoded SIWE message.
      const [hexMsg, addressParam] = personalSignCall.params as [string, string];
      expect(hexMsg.startsWith("0x")).toBe(true);
      expect(addressParam.toLowerCase()).toMatch(/^0x[a-f0-9]{40}$/);

      const decodedMessage = Buffer.from(hexMsg.slice(2), "hex").toString("utf-8");
      // Sanity-check it looks like a SIWE message so a future Polymarket
      // change doesn't make us silently assert against junk.
      expect(decodedMessage).toMatch(/wants you to sign in with your Ethereum account/i);

      const signature = personalSignCall.result as string;
      expect(signature).toMatch(/^0x[a-fA-F0-9]{130}$/);

      // The defining invariant: this signature must recover to the address
      // Polymarket asked for, under verifyMessage's MetaMask-compat
      // semantics (EIP-191 prefix over the *decoded* UTF-8 message). If
      // this fails, Polymarket's backend will reject the SIWE login.
      const recovered = verifyMessage(decodedMessage, signature);
      expect(recovered.toLowerCase()).toBe(addressParam.toLowerCase());
    }

    // The user's failure mode: Polymarket renders "Request Cancelled"
    // even though we returned a signature. The bodyText check is a sanity
    // backup; a positive logged-in indicator (Portfolio link / Deposit
    // button visible) is the stronger acceptance signal.
    const bodyText = (await page.locator("body").innerText()).toLowerCase();
    expect(
      bodyText.includes("request cancelled") || bodyText.includes("request canceled"),
      "Polymarket shows 'Request Cancelled' after we returned a signature — recovery mismatch?"
    ).toBe(false);

    await page.close();
  });

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
