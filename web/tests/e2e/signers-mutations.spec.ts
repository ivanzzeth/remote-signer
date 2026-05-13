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

test("import existing private key produces the expected EVM address", async ({
  authedPage,
}) => {
  // Well-known test key: privkey 0x0000…0001 → address 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
  const PRIV = "0x0000000000000000000000000000000000000000000000000000000000000001";
  const EXPECTED_ADDR = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";

  await authedPage.click("text=Signers");
  await authedPage.click("button:has-text('New signer')");
  await authedPage.click("button:has-text('Import private key')");

  // Mode-toggle reveals the hex field; first input is now the key, then
  // two password fields, then display_name, then tags.
  await authedPage.fill("input[type=password] >> nth=0", PRIV);
  await authedPage.fill("input[type=password] >> nth=1", PASSWORD);
  await authedPage.fill("input[type=password] >> nth=2", PASSWORD);
  await authedPage.fill("input[type=text] >> nth=0", "e2e-import");
  await authedPage.click("button:has-text('Import signer')");

  // Imported signer lands at the well-known address.
  const row = authedPage.locator("tr", {
    has: authedPage.locator(`text=${EXPECTED_ADDR}`),
  });
  await expect(row).toBeVisible({ timeout: 5_000 });
  await expect(row.getByText("unlocked")).toBeVisible();

  // Clean up so subsequent specs don't see this signer.
  authedPage.once("dialog", (d) => d.accept());
  await row.getByRole("button", { name: "Delete" }).click();
});

test("import with malformed hex shows a client-side error", async ({
  authedPage,
}) => {
  await authedPage.click("text=Signers");
  await authedPage.click("button:has-text('New signer')");
  await authedPage.click("button:has-text('Import private key')");

  await authedPage.fill("input[type=password] >> nth=0", "not-hex");
  await authedPage.fill("input[type=password] >> nth=1", PASSWORD);
  await authedPage.fill("input[type=password] >> nth=2", PASSWORD);
  await authedPage.click("button:has-text('Import signer')");

  await expect(
    authedPage.locator("text=private key must be 64 hex chars"),
  ).toBeVisible();
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
