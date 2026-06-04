import { adminSDKClient, expect, test } from "./fixtures";

const HD_PASSWORD = "e2e-hd-primary-badge-4m8k";

test("Signers page shows primary badge for HD wallet root address", async ({
  authedPage,
}) => {
  const client = await adminSDKClient();

  const created = await client.evm.hdWallets.create({
    password: HD_PASSWORD,
  } as any);
  const primaryAddr: string = (created as any).primary_address;
  expect(primaryAddr).toMatch(/^0x[0-9a-fA-F]{40}$/);

  const derived = await client.evm.hdWallets.deriveAddress(primaryAddr, {
    index: 2,
  });
  const derivedAddr: string = derived.derived[0].address;
  expect(derivedAddr.toLowerCase()).not.toBe(primaryAddr.toLowerCase());

  await authedPage.click("text=Signers");

  const primaryRow = authedPage.locator("tr", { hasText: primaryAddr }).first();
  await expect(primaryRow).toBeVisible({ timeout: 5_000 });
  await expect(primaryRow.locator("[data-testid=hd-primary-badge]")).toContainText(
    "primary",
  );

  const derivedRow = authedPage.locator("tr", { hasText: derivedAddr }).first();
  await expect(derivedRow).toBeVisible();
  await expect(derivedRow.locator("[data-testid=hd-primary-badge]")).toHaveCount(
    0,
  );
});
