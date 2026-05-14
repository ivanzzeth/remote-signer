import { expect, test } from "./fixtures";

test("Templates page lists built-in templates and routes to detail", async ({
  authedPage,
}) => {
  await authedPage.click("text=Templates");
  await expect(
    authedPage.getByRole("heading", { name: "Templates" }),
  ).toBeVisible();

  // The bootstrap config wires templates_dir to rules/templates, which
  // ships 30+ files. Don't pin an exact count (the catalogue is
  // expected to grow); assert exactly the "erc20" template (not its
  // family — erc20_permit, etc. — those share the prefix).
  const link = authedPage.getByRole("link", { name: "erc20", exact: true });
  await expect(link).toBeVisible();
  await link.click();
  await expect(
    authedPage.getByRole("heading", { name: "erc20", exact: true }),
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
  // Exact name match — without it "erc20" matches erc20_permit,
  // erc20_dynamic_blocklist, etc., and locator().first() lands on
  // whichever sorted first.
  const link = authedPage.getByRole("link", { name: "erc20", exact: true });
  await link.click();
  await expect(
    authedPage.getByRole("heading", { name: "erc20", exact: true }),
  ).toBeVisible();

  // Required vars from the erc20 template
  await expect(
    authedPage.getByTestId("template-form-var-token_address"),
  ).toBeVisible();
  await expect(
    authedPage.getByTestId("template-form-var-allowed_recipients"),
  ).toBeVisible();
});
