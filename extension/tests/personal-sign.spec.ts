import { test, expect } from "./fixtures";
import {
  injectStorageConfig,
  openDappAndWaitForProvider,
  dappEIP1193Call,
  TEST_ACCOUNTS,
} from "./helpers";

test.describe("personal_sign (@integration)", () => {
  /**
   * Configure the extension so the provider is ready before opening the dApp.
   */
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

  test("signs 'Hello, World' message and returns valid signature", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    const message = "0x" + Buffer.from("Hello, World").toString("hex");
    const result = await dappEIP1193Call(
      page,
      "personal_sign",
      message,
      TEST_ACCOUNTS.signer
    );

    expect(result.ok).toBe(true);
    // EIP-191 personal_sign returns 65-byte signature: r(32) + s(32) + v(1)
    // = 130 hex chars + 0x prefix
    expect(result.result).toMatch(/^0x[a-fA-F0-9]{130}$/);
  });

  test("signs empty message", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    const emptyMessage = "0x";
    const result = await dappEIP1193Call(
      page,
      "personal_sign",
      emptyMessage,
      TEST_ACCOUNTS.signer
    );

    expect(result.ok).toBe(true);
    expect(result.result).toMatch(/^0x[a-fA-F0-9]{130}$/);
  });

  test("rejects signature request for wrong address", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    const message = "0xdeadbeef";
    const result = await dappEIP1193Call(
      page,
      "personal_sign",
      message,
      TEST_ACCOUNTS.recipient
    );

    expect(result.ok).toBe(false);
    expect(result.error.code).toBe(4100); // unauthorized
  });

  test("produces different signatures for different messages", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    const r1 = await dappEIP1193Call(
      page,
      "personal_sign",
      "0x" + Buffer.from("msg-1").toString("hex"),
      TEST_ACCOUNTS.signer
    );
    const r2 = await dappEIP1193Call(
      page,
      "personal_sign",
      "0x" + Buffer.from("msg-2").toString("hex"),
      TEST_ACCOUNTS.signer
    );

    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(true);
    expect(r1.result).not.toBe(r2.result);
  });
});
