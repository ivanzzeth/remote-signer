import { adminSDKClient, expect, test } from "./fixtures";

// End-to-end coverage of the wallet RPC proxy: SDK client → real
// daemon → upstream RPC.
//
// The deterministic check is the allowlist: a sign method is
// guaranteed to be rejected by the daemon regardless of upstream
// health, so it pins the *route registration* + *auth* + *server
// allowlist* in one assertion that doesn't depend on network
// reachability. The upstream-call case is best-effort — if the
// upstream is reachable the result rounds-trip; if not, the
// failure surfaces with a wrapped "daemon rpc proxy: ..." error
// instead of a cryptic JSON parser hiccup, which is itself the
// regression-guard for the original Uniswap bug.
test.describe("EVM wallet RPC proxy (/api/v1/evm/rpc/{chainId})", () => {
  test("rejects sign methods via the server-side allowlist", async () => {
    const sdk = await adminSDKClient();
    await expect(
      sdk.evm.rpcProxy.call(1, "personal_sign", [
        "0xdeadbeef",
        "0x0000000000000000000000000000000000000000",
      ]),
    ).rejects.toThrow(/not allowed via the wallet proxy/i);
  });

  test("rejects another sign method (eth_sendTransaction) — defence in depth", async () => {
    // eth_sendTransaction (unsigned) MUST be blocked here. Unlike
    // eth_sendRawTransaction (signed bytes broadcast) which is
    // allowed, the unsigned variant would require server-side key
    // material — that path goes through /api/v1/evm/sign where the
    // rule engine + budget tracking apply.
    const sdk = await adminSDKClient();
    await expect(
      sdk.evm.rpcProxy.call(1, "eth_sendTransaction", [{ to: "0xdead", value: "0x1" }]),
    ).rejects.toThrow(/not allowed via the wallet proxy/i);
  });

  test("forwards an allow-listed read method (eth_blockNumber) and wraps upstream errors", async () => {
    // Best-effort: the e2e daemon uses the default rpc_gateway
    // (https://evm.web3gate.xyz/evm). If it's reachable, we get a
    // 0x-prefixed hex block number; if not, we get a wrapped
    // "daemon rpc proxy: <reason>" error — which is exactly the
    // contract the Uniswap regression was missing.
    const sdk = await adminSDKClient();
    try {
      const block = (await sdk.evm.rpcProxy.call(1, "eth_blockNumber", [])) as string;
      expect(block).toMatch(/^0x[0-9a-fA-F]+$/);
    } catch (err: any) {
      // Upstream unreachable / rate-limited: the error MUST carry
      // the "daemon rpc proxy" prefix so dApp-side bug reports
      // identify the failing layer.
      expect(String(err?.message ?? err)).toMatch(/daemon rpc proxy/i);
    }
  });

  test("a malformed chain id is rejected by the SSRF validator (defence in depth)", async () => {
    // RPCProvider's chainID validator only accepts numeric strings.
    // A non-numeric value gets rejected before any URL gets built,
    // so this case is deterministic — doesn't depend on the
    // upstream's behavior for unknown numeric chains (which is
    // implementation-specific).
    const sdk = await adminSDKClient();
    await expect(
      sdk.evm.rpcProxy.call("not-a-number", "eth_blockNumber", []),
    ).rejects.toThrow(/chain_id/i);
  });
});
