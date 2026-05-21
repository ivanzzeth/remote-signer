import { test, expect } from "./fixtures";
import {
  RemoteSignerClient,
} from "remote-signer-client";
import {
  injectStorageConfig,
  openDappAndWaitForProvider,
  dappEIP1193Call,
  switchToAnvil,
  TEST_ACCOUNTS,
} from "./helpers";

// Full broadcast → tracking loop:
//
//   eth_sendTransaction
//     → SDK signs via daemon
//     → SDK broadcasts via daemon's wallet RPC proxy (POST /rpc/{chain})
//     → proxy records the signed bytes into the transactions table
//     → sign_requests.transaction_id back-ref is set
//     → background poller observes anvil's receipt (instant on anvil)
//     → tx.status flips to mined, receipt_status / block_number land
//
// Pre-tracking the operator's only visibility into post-broadcast
// state was the daemon log. This spec pins the end-to-end so a
// future refactor can't silently break any of the four hops.
test.describe("on-chain transaction tracking (@integration)", () => {
  async function setupSigningContext(
    context: any,
    extensionId: string,
    serverInfo: any,
  ) {
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.waitForSelector("#app");
    await injectStorageConfig(popup, {
      remoteSignerUrl: serverInfo.base_url,
      apiKeyId: serverInfo.admin_api_key_id,
      apiKeyPrivateKey: serverInfo.admin_api_key_hex,
    });
    await popup.reload();
    await popup.waitForSelector("#app");
    await popup.close();
  }

  test("eth_sendTransaction populates the daemon's transactions table and the sign_request back-ref", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    test.skip(!serverInfo.anvil_url, "anvil not available in this environment");

    await setupSigningContext(context, extensionId, serverInfo);
    const page = await context.newPage();
    await openDappAndWaitForProvider(page);
    expect(await switchToAnvil(page, serverInfo)).toBe(true);

    // 1. Broadcast a tx through the extension → daemon. Returns the
    //    tx hash on success; failure here would short-circuit the
    //    spec before the tracking assertions run.
    // tx.chainId is what the wallet RPC proxy routes against —
    // wallet_addEthereumChain pre-registers anvil but doesn't flip
    // the SDK's global, so without an explicit chainId per request
    // the proxy URL would still target the popup's default (1) and
    // the broadcast lands under the wrong chain.
    const anvilChainHex = "0x" + (serverInfo.anvil_chain_id ?? 31337).toString(16);
    const tx = {
      from: TEST_ACCOUNTS.signer,
      to: TEST_ACCOUNTS.recipient,
      value: "0x0",
      gas: "0x5208",
      gasPrice: "0x3b9aca00",
      chainId: anvilChainHex,
    };
    const result = await dappEIP1193Call(page, "eth_sendTransaction", tx);
    expect(result.ok).toBe(true);
    const txHash = (result.result as string).toLowerCase();
    expect(txHash).toMatch(/^0x[a-f0-9]{64}$/);

    // 2. Build an SDK client to query the daemon's read API
    //    directly — same auth path the web UI uses.
    const admin = new RemoteSignerClient({
      baseURL: serverInfo.base_url,
      apiKeyID: serverInfo.admin_api_key_id,
      privateKey: serverInfo.admin_api_key_hex,
    });

    // 3. The transactions list must include our hash. The proxy
    //    records on a goroutine, so poll briefly until it lands.
    let recorded: any = null;
    for (let i = 0; i < 40; i++) {
      const resp = await admin.evm.transactions.list({ limit: 100 });
      recorded = resp.transactions.find(
        (t: any) => t.tx_hash.toLowerCase() === txHash,
      );
      if (recorded) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    expect(recorded, "transaction never landed in the daemon's table").not.toBeNull();
    expect(recorded.chain_id).toBe(String(serverInfo.anvil_chain_id ?? 31337));
    expect(recorded.from_address.toLowerCase()).toBe(
      TEST_ACCOUNTS.signer.toLowerCase(),
    );
    // sign_request_id back-link is set (the proxy matched the
    // signed bytes to the request that produced them).
    expect(recorded.sign_request_id).toBeTruthy();

    // 4. The poller (10s ticker by default, but PollPending can also
    //    be invoked via the next chain query) eventually flips the
    //    row to mined on anvil. Anvil mines on every tx so the
    //    receipt is available immediately; poll for up to 15s to
    //    cover one full poller cycle.
    let mined: any = null;
    for (let i = 0; i < 150; i++) {
      const resp = await admin.evm.transactions.get(recorded.id);
      if (resp.status === "mined") {
        mined = resp;
        break;
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    expect(mined, "poller never moved tx to mined").not.toBeNull();
    expect(mined.receipt_status).toBe(1); // success
    expect(mined.block_number).toBeGreaterThan(0);

    // 5. The sign_request that produced the signed bytes carries
    //    the FK — the Requests UI's "On-chain" column relies on
    //    this being populated.
    const req = await admin.evm.requests.get(recorded.sign_request_id);
    expect(req.transaction_id).toBe(recorded.id);
  });

  test("visibility: non-admin can't peek at other keys' transactions", async ({
    serverInfo,
  }) => {
    // The handler scope-enforces per-key visibility — verify via
    // SDK directly so the spec doesn't depend on which dApp
    // broadcasted what. The non-admin key may pass api_key_id as
    // their own (no-op), but a different key value triggers 403.
    const nonAdmin = new RemoteSignerClient({
      baseURL: serverInfo.base_url,
      apiKeyID: serverInfo.non_admin_api_key_id,
      privateKey: serverInfo.non_admin_api_key_hex,
    });
    // Own-key passthrough must succeed (200 + possibly empty list).
    await expect(
      nonAdmin.evm.transactions.list({
        api_key_id: serverInfo.non_admin_api_key_id,
      }),
    ).resolves.toBeDefined();
    // Cross-key probe must be rejected with the standard 403 message.
    await expect(
      nonAdmin.evm.transactions.list({
        api_key_id: serverInfo.admin_api_key_id,
      }),
    ).rejects.toThrow(/forbidden/i);
  });
});
