import { test, expect } from "./fixtures";
import {
  injectStorageConfig,
  openDappAndWaitForProvider,
  dappEIP1193Call,
  TEST_ACCOUNTS,
} from "./helpers";

/**
 * A minimal EIP-712 Permit typed data payload for signature testing.
 */
const PERMIT_TYPED_DATA = {
  types: {
    EIP712Domain: [
      { name: "name", type: "string" },
      { name: "version", type: "string" },
      { name: "chainId", type: "uint256" },
      { name: "verifyingContract", type: "address" },
    ],
    Permit: [
      { name: "owner", type: "address" },
      { name: "spender", type: "address" },
      { name: "value", type: "uint256" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  },
  domain: {
    name: "Test Token",
    version: "1",
    chainId: 31337,
    verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
  },
  primaryType: "Permit",
  message: {
    owner: TEST_ACCOUNTS.signer,
    spender: TEST_ACCOUNTS.recipient,
    value: 1000,
    nonce: 0,
    deadline: 9999999999,
  },
} as const;

test.describe("eth_signTypedData_v4 (@integration)", () => {
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

  test("signs EIP-712 Permit typed data and returns valid signature", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    const result = await dappEIP1193Call(
      page,
      "eth_signTypedData_v4",
      TEST_ACCOUNTS.signer,
      PERMIT_TYPED_DATA
    );

    expect(result.ok).toBe(true);
    // ECDSA signature: 65 bytes = 130 hex chars + 0x
    expect(result.result).toMatch(/^0x[a-fA-F0-9]{130}$/);
  });

  test("verifies domain fields present in typed data", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    // Sign with an incorrect chainId domain — should still produce a signature
    // but the contract verification would fail. We just test server acceptance.
    const modifiedData = {
      ...PERMIT_TYPED_DATA,
      domain: {
        ...PERMIT_TYPED_DATA.domain,
        chainId: 1,
      },
    };

    const result = await dappEIP1193Call(
      page,
      "eth_signTypedData_v4",
      TEST_ACCOUNTS.signer,
      modifiedData
    );

    expect(result.ok).toBe(true);
    expect(result.result).toMatch(/^0x[a-fA-F0-9]{130}$/);
  });

  test("rejects typed data signing for unauthorized address", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    const result = await dappEIP1193Call(
      page,
      "eth_signTypedData_v4",
      TEST_ACCOUNTS.recipient, // wrong address
      PERMIT_TYPED_DATA
    );

    expect(result.ok).toBe(false);
    expect(result.error.code).toBe(4100);
  });

  test("signatures are deterministic for same typed data", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await setupSigningContext(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    const r1 = await dappEIP1193Call(
      page,
      "eth_signTypedData_v4",
      TEST_ACCOUNTS.signer,
      PERMIT_TYPED_DATA
    );
    const r2 = await dappEIP1193Call(
      page,
      "eth_signTypedData_v4",
      TEST_ACCOUNTS.signer,
      PERMIT_TYPED_DATA
    );

    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(true);
    expect(r1.result).toBe(r2.result);
  });
});
