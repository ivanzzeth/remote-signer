import { expect, test } from "./fixtures";

test("Presets page lists built-in presets and routes to detail", async ({
  authedPage,
}) => {
  await authedPage.click("text=Presets");
  await expect(
    authedPage.getByRole("heading", { name: "Presets" }),
  ).toBeVisible();

  // Presets ship under rules/presets in the bootstrap config; assert
  // the erc20 preset shows up by filename.
  const erc20Row = authedPage.locator("tr", {
    has: authedPage.locator("text=erc20.preset"),
  });
  await expect(erc20Row.first()).toBeVisible();

  // Click into detail.
  await erc20Row.first().getByRole("link", { name: /erc20.preset/i }).first().click();
  await expect(authedPage.locator("text=Apply preset").first()).toBeVisible();
});

test("Preset detail page renders override-hint fields", async ({ authedPage }) => {
  // erc20.preset.js.yaml declares override_hints including
  // token_address, max_transfer_amount, allowed_recipients, etc. The
  // page must render at least one of them as an input.
  //
  // Stay within the SPA — page.goto() reloads and dumps credentials.
  await authedPage.click("text=Presets");
  const row = authedPage.locator("tr", {
    has: authedPage.locator("text=erc20.preset"),
  });
  await row.first().getByRole("link", { name: /erc20.preset/i }).first().click();

  await expect(
    authedPage.getByTestId("preset-form-var-token_address"),
  ).toBeVisible();
});
