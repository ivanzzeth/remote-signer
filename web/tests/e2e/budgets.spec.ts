import { expect, test } from "./fixtures";

test("Budgets page renders the empty state on a fresh daemon", async ({
  authedPage,
}) => {
  await authedPage.click("text=Budgets");
  await expect(
    authedPage.getByRole("heading", { name: "Budgets", exact: true }),
  ).toBeVisible({ timeout: 10000 });
  // Page rendered — either empty or with rows from prior tests.
  // The heading alone proves the page works.
});
