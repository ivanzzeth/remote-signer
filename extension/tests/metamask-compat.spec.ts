/**
 * MetaMask-compatibility surface tests.
 *
 * These cover the EIP-1193 methods the SDK provider doesn't enumerate on its
 * own — the ones that real dApps (Uniswap, Polymarket, DeBank) reach for
 * during connect, chain-switch, and SIWE login flows. They run against the
 * locally-served dApp page from global-setup, so no external network access
 * is required.
 */
import { test, expect } from "./fixtures";
import { injectStorageConfig } from "./helpers";

test.describe("MetaMask-compat methods (@integration)", () => {
  test.beforeEach(async ({ context, extensionId, serverInfo }) => {
    // Pre-configure the extension so provider init succeeds.
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

  async function callRpc(page: any, method: string, params: unknown[] = []) {
    return page.evaluate(
      async ({ method, params }: { method: string; params: unknown[] }) => {
        try {
          const result = await (window as any).ethereum!.request({ method, params });
          return { ok: true, result };
        } catch (err: any) {
          return { ok: false, error: { code: err?.code, message: err?.message } };
        }
      },
      { method, params }
    );
  }

  test("web3_clientVersion returns RemoteSigner identifier", async ({ openDapp }) => {
    const dapp = await openDapp();
    await dapp.waitForFunction(() => !!(window as any).ethereum, { timeout: 15_000 });
    const r = await callRpc(dapp, "web3_clientVersion");
    expect(r.ok).toBe(true);
    expect(typeof r.result).toBe("string");
    expect(r.result).toMatch(/RemoteSigner\//);
  });

  test("net_listening returns true", async ({ openDapp }) => {
    const dapp = await openDapp();
    await dapp.waitForFunction(() => !!(window as any).ethereum, { timeout: 15_000 });
    const r = await callRpc(dapp, "net_listening");
    expect(r.ok).toBe(true);
    expect(r.result).toBe(true);
  });

  test("wallet_getPermissions reports the eth_accounts capability", async ({ openDapp }) => {
    const dapp = await openDapp();
    await dapp.waitForFunction(() => !!(window as any).ethereum, { timeout: 15_000 });
    const r = await callRpc(dapp, "wallet_getPermissions");
    expect(r.ok).toBe(true);
    expect(Array.isArray(r.result)).toBe(true);
    expect(r.result[0]).toMatchObject({ parentCapability: "eth_accounts" });
  });

  test("wallet_watchAsset accepts ERC-20 metadata and returns true", async ({ openDapp }) => {
    const dapp = await openDapp();
    await dapp.waitForFunction(() => !!(window as any).ethereum, { timeout: 15_000 });
    // Per EIP-747, wallet_watchAsset takes a single object, not an array.
    const r = await dapp.evaluate(async () => {
      try {
        const result = await (window as any).ethereum!.request({
          method: "wallet_watchAsset",
          params: {
            type: "ERC20",
            options: {
              address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
              symbol: "USDC",
              decimals: 6,
            },
          } as any,
        });
        return { ok: true, result };
      } catch (err: any) {
        return { ok: false, error: { code: err?.code, message: err?.message } };
      }
    });
    expect(r.ok).toBe(true);
    expect(r.result).toBe(true);
  });

  test("wallet_getCapabilities returns an object", async ({ openDapp }) => {
    const dapp = await openDapp();
    await dapp.waitForFunction(() => !!(window as any).ethereum, { timeout: 15_000 });
    const r = await callRpc(dapp, "wallet_getCapabilities", ["0x0000000000000000000000000000000000000000"]);
    expect(r.ok).toBe(true);
    expect(typeof r.result).toBe("object");
  });

  test("wallet_switchEthereumChain rejects an unknown chain with code 4902", async ({ openDapp }) => {
    const dapp = await openDapp();
    await dapp.waitForFunction(() => !!(window as any).ethereum, { timeout: 15_000 });
    // Cosmos-style chain ID definitely not in the default registry.
    const r = await callRpc(dapp, "wallet_switchEthereumChain", [{ chainId: "0xdeadbeef" }]);
    expect(r.ok).toBe(false);
    expect(r.error?.code).toBe(4902);
  });

  test("wallet_addEthereumChain then wallet_switchEthereumChain succeeds", async ({ openDapp }) => {
    const dapp = await openDapp();
    await dapp.waitForFunction(() => !!(window as any).ethereum, { timeout: 15_000 });

    // Use a clearly-not-default chain id (Reya = 1729) with a fake RPC URL —
    // we're only testing registration + chainChanged emission, not actual reads.
    const addr = await dapp.evaluate(async () => {
      try {
        const r1 = await (window as any).ethereum!.request({
          method: "wallet_addEthereumChain",
          params: [
            {
              chainId: "0x6c1",
              chainName: "Reya",
              rpcUrls: ["https://rpc.example.invalid"],
              nativeCurrency: { name: "Reya", symbol: "RYA", decimals: 18 },
            },
          ],
        });
        const r2 = await (window as any).ethereum!.request({
          method: "wallet_switchEthereumChain",
          params: [{ chainId: "0x6c1" }],
        });
        const chainId = await (window as any).ethereum!.request({ method: "eth_chainId" });
        return { ok: true, r1, r2, chainId };
      } catch (err: any) {
        return { ok: false, error: { code: err?.code, message: err?.message } };
      }
    });

    expect(addr.ok).toBe(true);
    expect(addr.chainId).toBe("0x6c1");
  });

  test("wallet_addEthereumChain rejects malformed chainId", async ({ openDapp }) => {
    const dapp = await openDapp();
    await dapp.waitForFunction(() => !!(window as any).ethereum, { timeout: 15_000 });
    const r = await callRpc(dapp, "wallet_addEthereumChain", [{ chainId: "not-hex", rpcUrls: ["https://x"] }]);
    expect(r.ok).toBe(false);
    expect(r.error?.code).toBe(-32602);
  });

  test("wallet_revokePermissions returns null and emits accountsChanged([])", async ({ openDapp }) => {
    const dapp = await openDapp();
    await dapp.waitForFunction(() => !!(window as any).ethereum, { timeout: 15_000 });
    const r = await dapp.evaluate(async () => {
      const events: any[] = [];
      (window as any).ethereum!.on("accountsChanged", (accts: any) => events.push(accts));
      try {
        const result = await (window as any).ethereum!.request({
          method: "wallet_revokePermissions",
          params: [{ eth_accounts: {} }],
        });
        await new Promise((r) => setTimeout(r, 200));
        return { ok: true, result, events };
      } catch (err: any) {
        return { ok: false, error: { code: err?.code, message: err?.message } };
      }
    });
    expect(r.ok).toBe(true);
    expect(r.result).toBeNull();
    expect(r.events?.[0]).toEqual([]);
  });
});
