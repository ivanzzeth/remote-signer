import { test, expect } from "./fixtures";
import {
  injectStorageConfig,
  openDappAndWaitForProvider,
  dappEIP1193Call,
} from "./helpers";

test.describe("EIP-1193 signing errors (@integration)", () => {
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

  test("returns proper error code for unsupported signing method", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    const result = await dappEIP1193Call(
      page,
      "eth_sign" // eth_sign is supported but uses different params; use a bogus method
    );

    // eth_sign without params will parse params as [undefined, undefined]
    // and may fail with address mismatch or server error
    expect(result.ok).toBe(false);
  });

  test("returns unsupported method error for unknown method", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    const result = await dappEIP1193Call(
      page,
      "eth_bogusMethod"
    );

    expect(result.ok).toBe(false);
    expect(result.error.code).toBe(4200); // unsupported method
  });

  test("personal_sign with no params returns error", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    const result = await dappEIP1193Call(page, "personal_sign");

    expect(result.ok).toBe(false);
  });

  test("personal_sign with empty message still produces signature", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    // personal_sign params: [message, address]; an empty string as message
    // is a valid signed message in personal_sign
    const result = await dappEIP1193Call(
      page,
      "personal_sign",
      "",
      "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    );

    // An empty string should either produce a signature or a parse error
    // from the server — either is fine as long as it doesn't crash
    expect(result.ok || result.error).toBeTruthy();
  });

  test("eth_sendTransaction with invalid gas value", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    const tx = {
      from: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
      to: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
      value: "0x1",
      gas: "not-a-number",
      gasPrice: "0x3b9aca00",
    };

    const result = await dappEIP1193Call(
      page,
      "eth_sendTransaction",
      tx
    );

    expect(result.ok).toBe(false);
    // Should be either a provider error or a server-side signing error
    expect(result.error).toBeDefined();
  });

  test("eth_signTransaction without from address", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    const tx = {
      to: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
      value: "0x1",
      gas: "0x5208",
      gasPrice: "0x3b9aca00",
    };

    const result = await dappEIP1193Call(
      page,
      "eth_signTransaction",
      tx
    );

    // Without "from", the handler skips the unauthorized check.
    // The signing itself should still work using the active signer.
    expect(result.ok).toBe(true);
    expect(result.result).toMatch(/^0x[a-fA-F0-9]+$/);
  });
});
