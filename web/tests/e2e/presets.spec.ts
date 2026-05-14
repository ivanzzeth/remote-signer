import { expect, test } from "./fixtures";

test("Presets page lists built-in presets and routes to detail", async ({
  authedPage,
}) => {
  await authedPage.click("text=Presets");
  await expect(
    authedPage.getByRole("heading", { name: "Presets" }),
  ).toBeVisible();

  // The erc20 preset's YAML declares name: "ERC20 (JS)" — the list
  // surfaces the friendly name as the link, with the filename in a
  // smaller font below. Click the link by its friendly text.
  const link = authedPage.getByRole("link", { name: "ERC20 (JS)" });
  await expect(link).toBeVisible();
  await link.click();
  await expect(authedPage.locator("text=Apply preset").first()).toBeVisible();
});

test("Preset detail page renders override-hint fields", async ({ authedPage }) => {
  // erc20.preset.js.yaml declares override_hints including
  // token_address, max_transfer_amount, allowed_recipients, etc. The
  // page must render each as an input with the joined description
  // from the referenced template.
  //
  // Stay within the SPA — page.goto() reloads and dumps credentials.
  await authedPage.click("text=Presets");
  await authedPage.getByRole("link", { name: "ERC20 (JS)" }).click();

  await expect(
    authedPage.getByTestId("preset-form-var-token_address"),
  ).toBeVisible();
  // Description text from the template should leak into the help
  // line — confirms the variable join is wired.
  await expect(
    authedPage.locator("text=ERC20 token contract address").first(),
  ).toBeVisible();
});
