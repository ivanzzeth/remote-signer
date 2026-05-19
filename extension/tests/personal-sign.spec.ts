import { test, expect } from "./fixtures";
import { verifyMessage } from "ethers";
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

  /**
   * Polymarket/SIWE regression: viem/wagmi-based dApps (Polymarket, Uniswap,
   * etc.) hex-encode the UTF-8 SIWE message before calling personal_sign.
   * The wallet must sign the *decoded* bytes — signing the literal hex
   * string produces a signature that recovers to the wrong address, which
   * Polymarket surfaces as "Request Cancelled". Verify the returned
   * signature recovers to the seeded signer when verified against the
   * original UTF-8 message.
   */
  test("hex-encoded SIWE message: recovered address matches the signer (Polymarket regression)", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);
    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    const utf8Message =
      "example.com wants you to sign in with your Ethereum account:\n" +
      TEST_ACCOUNTS.signer +
      "\n\nSign-in nonce: e2e-polymarket-regression";
    const hexMessage = "0x" + Buffer.from(utf8Message, "utf-8").toString("hex");

    const result = await dappEIP1193Call(
      page,
      "personal_sign",
      hexMessage,
      TEST_ACCOUNTS.signer
    );
    expect(result.ok, `personal_sign failed: ${result.ok ? "" : result.error?.message}`).toBe(true);
    expect(result.result).toMatch(/^0x[a-fA-F0-9]{130}$/);

    // ethers.verifyMessage applies the standard EIP-191 prefix over the
    // UTF-8 bytes and recovers the signer address. If the wallet had
    // signed the literal "0x..." hex string instead of the decoded bytes,
    // recovery would return a different address.
    const recovered = verifyMessage(utf8Message, result.result);
    expect(recovered.toLowerCase()).toBe(TEST_ACCOUNTS.signer.toLowerCase());
  });

  /**
   * Companion to the above: the same UTF-8 message passed unencoded must
   * produce a signature that *also* recovers to the signer — and ideally
   * the *same* signature, since both encodings represent the same payload.
   */
  test("plain UTF-8 and hex-encoded forms produce equivalent recoverable signatures", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);
    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    const msg = "Hello Polymarket";

    const plain = await dappEIP1193Call(
      page,
      "personal_sign",
      msg,
      TEST_ACCOUNTS.signer
    );
    expect(plain.ok).toBe(true);

    const hexed = await dappEIP1193Call(
      page,
      "personal_sign",
      "0x" + Buffer.from(msg, "utf-8").toString("hex"),
      TEST_ACCOUNTS.signer
    );
    expect(hexed.ok).toBe(true);

    expect(verifyMessage(msg, plain.result).toLowerCase()).toBe(
      TEST_ACCOUNTS.signer.toLowerCase()
    );
    expect(verifyMessage(msg, hexed.result).toLowerCase()).toBe(
      TEST_ACCOUNTS.signer.toLowerCase()
    );
    // Deterministic signers (incl. the seeded private-key signer) must
    // produce byte-identical signatures for the same payload.
    expect(plain.result).toBe(hexed.result);
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
