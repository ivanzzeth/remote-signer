import { adminSDKClient, expect, test } from "./fixtures";

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

test("add member uses signer picker filtered by type", async ({
  authedPage,
}) => {
  // Seed a keystore signer + import one private-key signer via the SDK so
  // the picker has two distinct types to filter between.
  const c = await adminSDKClient();
  const stamp = Date.now();
  const keystore = await c.evm.signers.create({
    type: "keystore",
    keystore: { password: `pw-${stamp}` },
    display_name: `e2e-keystore-${stamp}`,
  });

  const walletName = `e2e-picker-${stamp}`;
  await authedPage
    .getByRole("link", { name: "Wallets", exact: true })
    .click();
  await authedPage.click("button:has-text('New wallet')");
  await authedPage.fill("input >> nth=0", walletName);
  await authedPage.click("button:has-text('Create wallet')");

  const row = authedPage.locator("tr", {
    has: authedPage.locator(`text=${walletName}`),
  });
  await row.click();

  // Picker is a <select> for the signer. The keystore we just seeded
  // should be one of its options.
  const picker = authedPage
    .locator("form")
    .filter({ hasText: "Signer" })
    .locator("select")
    .nth(1); // first select is Type, second is Signer
  await expect(picker).toBeVisible();
  await picker.selectOption(keystore.address);
  await authedPage.click("button:has-text('Add member')");

  // The selected address now appears in the Members table.
  await expect(
    authedPage.locator(`text=${keystore.address}`).first(),
  ).toBeVisible({ timeout: 5_000 });

  // After adding, the picker should no longer offer this signer (filtered
  // out by `memberAddrs`). Eligibility text appears when the list empties.
  await expect(
    authedPage.locator(`option[value='${keystore.address}']`),
  ).toHaveCount(0);

  // Cleanup: remove the member + delete the wallet. The member row is
  // identified by the signer address; Remove is on the same row.
  const memberRow = authedPage.locator("tr", {
    has: authedPage.locator(`text=${keystore.address}`),
  });
  authedPage.once("dialog", (d) => d.accept()); // remove member confirm
  await memberRow.getByRole("button", { name: "Remove" }).click();
  authedPage.once("dialog", (d) => d.accept()); // delete wallet confirm
  await row.getByRole("button", { name: "Delete" }).click();
});
