import { test, expect } from "./fixtures";
import {
  injectStorageConfig,
  openDappAndWaitForProvider,
  dappEIP1193Call,
  switchToAnvil,
  TEST_ACCOUNTS,
} from "./helpers";

test.describe("eth_signTransaction (@integration)", () => {
  async function setupSigningContext(
    context: any,
    extensionId: string,
    serverInfo: any
  ) {
    const popup = await context.newPage();
    await popup.goto(
      `chrome-extension://${extensionId}/popup/popup.html`
    );
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

  test("signs legacy transaction and returns valid signed tx hex", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    const tx = {
      from: TEST_ACCOUNTS.signer,
      to: TEST_ACCOUNTS.recipient,
      value: "0x1", // 1 wei
      gas: "0x5208", // 21000
      gasPrice: "0x3b9aca00", // 1 gwei
    };

    const result = await dappEIP1193Call(
      page,
      "eth_signTransaction",
      tx
    );

    expect(result.ok).toBe(true);
    // Signed transaction is an RLP-encoded hex string
    expect(result.result).toMatch(/^0x[a-fA-F0-9]+$/);
    // Minimum length: nonce + gasPrice + gas + to + value + data + v + r + s
    expect(result.result.length).toBeGreaterThan(200);
  });

  test("signs EIP-1559 transaction with maxFeePerGas", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    const tx = {
      from: TEST_ACCOUNTS.signer,
      to: TEST_ACCOUNTS.recipient,
      value: "0x1",
      gas: "0x5208",
      maxFeePerGas: "0x3b9aca00",
      maxPriorityFeePerGas: "0x59682f00",
    };

    const result = await dappEIP1193Call(
      page,
      "eth_signTransaction",
      tx
    );

    expect(result.ok).toBe(true);
    expect(result.result).toMatch(/^0x[a-fA-F0-9]+$/);
    expect(result.result.length).toBeGreaterThan(200);
  });

  test("signs 0-value transaction", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    const tx = {
      from: TEST_ACCOUNTS.signer,
      to: TEST_ACCOUNTS.recipient,
      value: "0x0",
      gas: "0x5208",
      gasPrice: "0x3b9aca00",
    };

    const result = await dappEIP1193Call(
      page,
    "eth_signTransaction",
    tx
    );

    expect(result.ok).toBe(true);
    expect(result.result).toMatch(/^0x[a-fA-F0-9]+$/);
    expect(result.result.length).toBeGreaterThan(200);
  });

  test("eth_sendTransaction signs and broadcasts to anvil", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    test.skip(!serverInfo.anvil_url, "anvil not available in this environment");

    await setupSigningContext(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);
    expect(await switchToAnvil(page, serverInfo)).toBe(true);

    const tx = {
      from: TEST_ACCOUNTS.signer,
      to: TEST_ACCOUNTS.recipient,
      value: "0x0",
      gas: "0x5208",
      gasPrice: "0x3b9aca00",
    };

    const result = await dappEIP1193Call(page, "eth_sendTransaction", tx);
    expect(result.ok).toBe(true);
    // Returns a 32-byte tx hash.
    expect(result.result).toMatch(/^0x[a-fA-F0-9]{64}$/);

    // Confirm the tx is actually on the chain by querying anvil.
    const receipt = await dappEIP1193Call(page, "eth_getTransactionReceipt", result.result);
    expect(receipt.ok).toBe(true);
    expect((receipt.result as any)?.transactionHash).toBe(result.result);
  });

  test("rejects transaction with unauthorized 'from' address", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    const tx = {
      from: TEST_ACCOUNTS.recipient, // not the signer
      to: TEST_ACCOUNTS.burn,
      value: "0x1",
      gas: "0x5208",
      gasPrice: "0x3b9aca00",
    };

    const result = await dappEIP1193Call(
      page,
      "eth_signTransaction",
      tx
    );

    expect(result.ok).toBe(false);
    expect(result.error.code).toBe(4100); // unauthorized
  });
});
