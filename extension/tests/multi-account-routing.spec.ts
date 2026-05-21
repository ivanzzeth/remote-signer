import { test, expect } from "./fixtures";
import {
  injectStorageConfig,
  openDappAndWaitForProvider,
  dappEIP1193Call,
  TEST_ACCOUNTS,
} from "./helpers";

test.describe("EIP1193 multi-account routing (@integration)", () => {
  // Regression guard for the Uniswap "Token approval failed / network
  // or connection issue" symptom: pre-fix the EIP1193Provider always
  // called `_getActiveSigner()` and rejected anything else as
  // "Address mismatch", so a dApp that asked for a non-active signer
  // (the user-selected account on a multi-account wallet) failed
  // locally before the request ever reached the daemon. Post-fix the
  // provider resolves by the address in the request — active for
  // omit, an exact match for explicit values, unauthorized for
  // unknown addresses.

  async function configurePopup(
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
      // Pin the active signer to #1 so the test always exercises the
      // "ask for the non-active account" path regardless of whichever
      // address the daemon returns first from signers.list.
      activeSignerAddress: TEST_ACCOUNTS.signer,
    });
    await popup.reload();
    await popup.waitForSelector("#app");
    await popup.close();
  }

  test("personal_sign routes to the non-active signer when the dApp asks for one", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    expect(serverInfo.signer_address_2).toBeTruthy();
    await configurePopup(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    const message = "0x" + Buffer.from("multi-account test").toString("hex");

    // Sign with the non-active second signer — pre-fix this threw
    // "Address mismatch" client-side, no POST ever reached the daemon.
    const result = await dappEIP1193Call(
      page,
      "personal_sign",
      message,
      serverInfo.signer_address_2,
    );

    expect(
      result.ok,
      `personal_sign on non-active signer failed: ${result.error?.message}`,
    ).toBe(true);
    expect(result.result).toMatch(/^0x[a-fA-F0-9]{130}$/);

    // The active signer keeps working too (regression guard against
    // a fix that broke the "no `from` provided" path).
    const activeResult = await dappEIP1193Call(
      page,
      "personal_sign",
      message,
      TEST_ACCOUNTS.signer,
    );
    expect(activeResult.ok).toBe(true);
  });

  test("personal_sign rejects an address not in the provider's signer set", async ({
    context,
    extensionId,
    serverInfo,
  }) => {
    await configurePopup(context, extensionId, serverInfo);

    const page = await context.newPage();
    await openDappAndWaitForProvider(page);

    // The fix mustn't widen the auth surface — an address the
    // provider doesn't know about must still error. Use the burn
    // address as a guaranteed-unknown target.
    const result = await dappEIP1193Call(
      page,
      "personal_sign",
      "0x" + Buffer.from("nope").toString("hex"),
      "0x0000000000000000000000000000000000000000",
    );

    expect(result.ok).toBe(false);
    expect(result.error?.message ?? "").toMatch(
      /not available in this provider/i,
    );
  });
});
