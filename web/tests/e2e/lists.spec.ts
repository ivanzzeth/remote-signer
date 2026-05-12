import { expect, test } from "./fixtures";

test("Signers page renders empty state on a fresh daemon", async ({
  authedPage,
}) => {
  await authedPage.click("text=Signers");
  await expect(
    authedPage.getByRole("heading", { name: "Signers" }),
  ).toBeVisible();
  await expect(authedPage.locator("text=No signers configured")).toBeVisible();
});

test("Rules page renders empty state", async ({ authedPage }) => {
  await authedPage.click("text=Rules");
  await expect(
    authedPage.getByRole("heading", { name: "Rules" }),
  ).toBeVisible();
  await expect(authedPage.locator("text=No rules defined")).toBeVisible();
});

test("API Keys page lists the bootstrap admin", async ({ authedPage }) => {
  await authedPage.click("text=API Keys");
  await expect(
    authedPage.getByRole("heading", { name: "API Keys" }),
  ).toBeVisible();
  // The admin key always exists post-bootstrap; its role is "admin".
  const row = authedPage.locator("tr", { has: authedPage.locator("text=admin") }).first();
  await expect(row).toBeVisible();
  await expect(authedPage.locator("text=enabled").first()).toBeVisible();
});
