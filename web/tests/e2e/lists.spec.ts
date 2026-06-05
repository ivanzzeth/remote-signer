import { expect, test } from "./fixtures";

// The e2e suite shares one daemon across specs; by the time these run other
// specs may have seeded signers/rules. Assert only that the page heading +
// table headings render — content is exercised by the mutation specs.
test("Signers page renders", async ({ authedPage }) => {
  await authedPage.click("text=Signers");
  await expect(
    authedPage.getByRole("heading", { name: "Signers" }),
  ).toBeVisible();
  await expect(authedPage.getByRole("button", { name: "New signer" })).toBeVisible();
});

test("Rules page renders", async ({ authedPage }) => {
  await authedPage.click("text=Rules");
  await expect(
    authedPage.getByRole("heading", { name: "Rules" }),
  ).toBeVisible();
  await expect(authedPage.getByRole("button", { name: "New rule" })).toBeVisible();
});

test("API Keys page lists the bootstrap admin", async ({ authedPage }) => {
  await authedPage.getByRole("link", { name: "API Keys", exact: true }).click();
  await expect(
    authedPage.getByRole("heading", { name: "API Keys" }),
  ).toBeVisible();
  const row = authedPage.locator("tbody tr").filter({
    has: authedPage.locator("td:first-child .font-mono", { hasText: "admin" }),
  }).first();
  await expect(row).toBeVisible();
  await expect(row.getByText("enabled")).toBeVisible();
});
