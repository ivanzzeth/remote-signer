import { expect, test } from "./fixtures";

const PASSWORD = "e2e-signer-pw-9k7g";

test("create + lock + unlock + delete via the UI", async ({ authedPage }) => {
  await authedPage.click("text=Signers");
  await authedPage.click("button:has-text('New signer')");

  // Two password fields, then display_name, then tags.
  await authedPage.fill("input[type=password] >> nth=0", PASSWORD);
  await authedPage.fill("input[type=password] >> nth=1", PASSWORD);
  await authedPage.fill("input[type=text] >> nth=0", "e2e-signer");
  await authedPage.click("button:has-text('Create signer')");

  // Newly created signer lands in the table. The exact address is random
  // so locate by display name.
  const row = authedPage.locator("tr", {
    has: authedPage.locator("text=e2e-signer"),
  });
  await expect(row).toBeVisible({ timeout: 5_000 });
  // Freshly created signers are unlocked by default — the create call
  // unlocks them in-memory so the very next sign request works without
  // a separate Unlock click.
  await expect(row.getByText("unlocked")).toBeVisible();

  // Lock it.
  await row.getByRole("button", { name: "Lock" }).click();
  await expect(row.getByText("locked")).toBeVisible();

  // Unlock dialog.
  await row.getByRole("button", { name: "Unlock" }).click();
  const dialog = authedPage.locator("text=Unlock signer").locator("..");
  await expect(dialog).toBeVisible();
  await authedPage.fill("input[type=password]", PASSWORD);
  await authedPage.locator("button:has-text('Unlock')").last().click();
  await expect(row.getByText("unlocked")).toBeVisible();

  // Delete (auto-accept the native confirm).
  authedPage.once("dialog", (d) => d.accept());
  await row.getByRole("button", { name: "Delete" }).click();
  await expect(authedPage.locator("text=e2e-signer")).toHaveCount(0);
});

test("password mismatch in create form is caught client-side", async ({
  authedPage,
}) => {
  await authedPage.click("text=Signers");
  await authedPage.click("button:has-text('New signer')");

  await authedPage.fill("input[type=password] >> nth=0", "password-123");
  await authedPage.fill("input[type=password] >> nth=1", "password-456");
  await authedPage.click("button:has-text('Create signer')");

  await expect(
    authedPage.locator("text=passwords do not match"),
  ).toBeVisible();
});
