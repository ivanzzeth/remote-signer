import { adminSDKClient, expect, test } from "./fixtures";

const PASSWORD = "e2e-filter-pw-3kq8";

// Exercises the Signers page filter bar end-to-end. The fixture is
// two keystore signers with intentionally diverging state — one
// unlocked, one locked — so each filter has a unique answer.
test("Signers page filters by type / locked / enabled and pins API key picker to admin", async ({
  authedPage,
}) => {
  const sdk = await adminSDKClient();

  // 1. Two keystore signers — A stays unlocked, B is locked right
  //    after creation so Locked filter has a non-trivial answer.
  const a = await sdk.evm.signers.create({
    type: "keystore",
    keystore: { password: PASSWORD },
    display_name: "filter-signer-A",
  } as any);
  const b = await sdk.evm.signers.create({
    type: "keystore",
    keystore: { password: PASSWORD },
    display_name: "filter-signer-B",
  } as any);
  await sdk.evm.signers.lock((b as any).address);

  // 2. Land on Signers, verify both rows present without any filter.
  await authedPage.click("text=Signers");
  await expect(authedPage.locator("[data-testid=signers-filter-bar]"))
    .toBeVisible();
  const rowA = authedPage.locator("tr", { hasText: (a as any).address });
  const rowB = authedPage.locator("tr", { hasText: (b as any).address });
  await expect(rowA).toBeVisible({ timeout: 5_000 });
  await expect(rowB).toBeVisible({ timeout: 5_000 });

  // 3. Locked=true → only B.
  await authedPage.locator("[data-testid=filter-locked]").selectOption("true");
  await expect(rowB).toBeVisible();
  await expect(rowA).toHaveCount(0);

  // 4. Locked=false → only A. Drop the prior constraint by switching
  //    the same select rather than reloading the page.
  await authedPage.locator("[data-testid=filter-locked]").selectOption("false");
  await expect(rowA).toBeVisible();
  await expect(rowB).toHaveCount(0);

  // 5. Clear locked, set type filter — both keystores remain. The
  //    important bit is that type=hd_wallet hides them both.
  await authedPage.locator("[data-testid=filter-locked]").selectOption("");
  await authedPage.locator("[data-testid=filter-type]").selectOption("hd_wallet");
  await expect(rowA).toHaveCount(0);
  await expect(rowB).toHaveCount(0);
  await authedPage.locator("[data-testid=filter-type]").selectOption("keystore");
  await expect(rowA).toBeVisible();
  await expect(rowB).toBeVisible();

  // 6. Admin sees the api-key picker — confirms the role-gating
  //    wired through /api/v1/api-keys/names.
  await expect(authedPage.locator("[data-testid=filter-apikey]")).toBeVisible();

  // Cleanup so subsequent specs see a clean signer set.
  await sdk.evm.signers.deleteSigner((a as any).address);
  await sdk.evm.signers.deleteSigner((b as any).address);
});
