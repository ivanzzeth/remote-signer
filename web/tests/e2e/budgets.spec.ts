import { expect, test } from "./fixtures";

test("Budgets page renders the empty state on a fresh daemon", async ({
  authedPage,
}) => {
  await authedPage.click("text=Budgets");
  await expect(
    authedPage.getByRole("heading", { name: "Budgets" }),
  ).toBeVisible();
  // A fresh daemon has no budget rows. The empty hint mentions both
  // creation paths (manual + auto via rule/simulation match).
  await expect(authedPage.locator("text=No budgets recorded")).toBeVisible();
});
