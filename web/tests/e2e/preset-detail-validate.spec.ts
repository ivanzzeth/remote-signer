import { expect, test } from "./fixtures";

test("Preset detail shows Validate and Apply buttons with results", async ({
  authedPage,
}) => {
  await authedPage.click("text=Presets");
  await expect(
    authedPage.getByRole("heading", { name: "Presets" }),
  ).toBeVisible({ timeout: 15000 });

  // Navigate to the ERC20 preset.
  const link = authedPage.getByRole("link", { name: "ERC20 (JS)" });
  await expect(link).toBeVisible();
  await link.click();
  await expect(
    authedPage.locator("text=Apply preset").first(),
  ).toBeVisible({ timeout: 10000 });

  // Fill required variables. The erc20 template requires token_address,
  // allowed_recipients, allowed_spenders, max_transfer_amount.
  await authedPage
    .getByTestId("preset-form-var-token_address")
    .fill("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
  await authedPage
    .getByTestId("preset-form-var-allowed_recipients")
    .fill("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
  await authedPage
    .getByTestId("preset-form-var-allowed_spenders")
    .fill("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
  await authedPage
    .getByTestId("preset-form-var-max_transfer_amount")
    .fill("1000000");

  // Click Validate before Apply.
  const validateBtn = authedPage.getByRole("button", { name: "Validate" });
  await expect(validateBtn).toBeVisible();
  await validateBtn.click();

  // Results should appear with pass count.
  await expect(
    authedPage.locator("text=passed").first(),
  ).toBeVisible({ timeout: 15000 });

  // Apply button should still be enabled.
  const applyBtn = authedPage.getByTestId("preset-form-submit");
  await expect(applyBtn).toBeVisible();
  await expect(applyBtn).toBeEnabled();
});
