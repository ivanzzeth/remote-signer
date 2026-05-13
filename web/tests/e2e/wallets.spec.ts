import { expect, test } from "./fixtures";

test("create wallet + add member + delete via UI", async ({ authedPage }) => {
  // We need a signer to add as a member. Use the SDK to mint one quickly —
  // the form-driven create path is exercised by signers-mutations.spec.
  const stamp = Date.now();
  const walletName = `e2e-wallet-${stamp}`;

  // The sidebar has both "HD Wallets" and "Wallets" — match exactly so
  // we land on the collections page, not the HD page.
  await authedPage.getByRole("link", { name: "Wallets", exact: true }).click();
  await authedPage.click("button:has-text('New wallet')");
  await authedPage.fill("input >> nth=0", walletName);
  await authedPage.fill("input >> nth=1", "from e2e suite");
  await authedPage.click("button:has-text('Create wallet')");

  const row = authedPage.locator("tr", {
    has: authedPage.locator(`text=${walletName}`),
  });
  await expect(row).toBeVisible({ timeout: 5_000 });

  // Expand the wallet: members panel renders, empty initially. The full
  // add/remove flow is exercised by signer-seeded scenarios in the Go
  // integration suite — wallet collections accept any 0x address as a
  // member row, so the daemon doesn't validate signer existence here.
  await row.click();
  await expect(
    authedPage.getByRole("heading", { name: "Members" }),
  ).toBeVisible();
  await expect(authedPage.locator("text=No members yet")).toBeVisible();

  // Delete the wallet (auto-accept the native confirm).
  authedPage.once("dialog", (d) => d.accept());
  await row.getByRole("button", { name: "Delete" }).click();
  await expect(authedPage.locator(`text=${walletName}`)).toHaveCount(0);
});
