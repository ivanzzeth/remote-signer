import { expect, test } from "./fixtures";

test("Templates page lists built-in templates and routes to detail", async ({
  authedPage,
}) => {
  await authedPage.click("text=Templates");
  await expect(
    authedPage.getByRole("heading", { name: "Templates" }),
  ).toBeVisible({ timeout: 10000 });

  // Template entries are identified by their YAML `name:` field. The
  // ERC20 template emits "ERC20 transfer/transferFrom limit" — use that
  // as the link text to click into its detail page.
  const link = authedPage.getByRole("link", { name: "ERC20 transfer/transferFrom limit", exact: true });
  await expect(link).toBeVisible({ timeout: 15000 });
  await link.click();
  await expect(
    authedPage.getByRole("heading", { name: "ERC20 transfer/transferFrom limit" }),
  ).toBeVisible();
  await expect(authedPage.locator("text=Metadata")).toBeVisible();
  await expect(authedPage.locator("text=Instantiate as rule")).toBeVisible();
});

test("Template detail page shows variable form for required fields", async ({
  authedPage,
}) => {
  // erc20 template declares required: token_address, allowed_recipients,
  // allowed_spenders. The form must surface them.
  //
  // Stay within the SPA — page.goto() reloads, which discards the
  // module-scoped credentials and bounces back to /login.
  await authedPage.click("text=Templates");
  await expect(
    authedPage.getByRole("heading", { name: "Templates" }),
  ).toBeVisible({ timeout: 15000 });

  const link = authedPage.getByRole("link", { name: "ERC20 transfer/transferFrom limit", exact: true });
  await expect(link).toBeVisible({ timeout: 15000 });
  await link.click();
  await expect(
    authedPage.getByRole("heading", { name: "ERC20 transfer/transferFrom limit" }),
  ).toBeVisible({ timeout: 10000 });

  // Required vars from the erc20 template
  await expect(
    authedPage.getByTestId("template-form-var-token_address"),
  ).toBeVisible();
  await expect(
    authedPage.getByTestId("template-form-var-allowed_recipients"),
  ).toBeVisible();
});
