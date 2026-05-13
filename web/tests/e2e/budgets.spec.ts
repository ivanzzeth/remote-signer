import { expect, test } from "./fixtures";

test("Budgets page renders the empty state on a fresh daemon", async ({
  authedPage,
}) => {
  await authedPage.click("text=Budgets");
  await expect(
    authedPage.getByRole("heading", { name: "Budgets" }),
  ).toBeVisible();
  // A fresh daemon has no rules with budgets attached — the page shows
  // the dedicated empty hint. Rules created by other specs in the suite
  // don't attach budgets, so this stays empty across the run.
  await expect(
    authedPage.locator("text=No budgets configured"),
  ).toBeVisible();
});
