import { expect, test } from "./fixtures";

test("Audit page loads + filtering by event_type reissues the query", async ({
  authedPage,
}) => {
  await authedPage.click("text=Audit log");
  await expect(
    authedPage.getByRole("heading", { name: "Audit log" }),
  ).toBeVisible();

  // The fixture has already triggered auth_success events by logging in;
  // there should be at least one record visible.
  await expect(authedPage.locator("tbody tr").first()).toBeVisible();

  // Capture the audit fetch when we apply a filter, so we can assert the
  // server actually got the query param.
  const filteredQuery = authedPage.waitForRequest(
    (req) =>
      req.url().includes("/api/v1/audit") &&
      req.url().includes("event_type=auth_failure"),
  );
  await authedPage.selectOption(
    "select:near(:text('Event type'))",
    "auth_failure",
  );
  await filteredQuery;

  // No auth_failure events on a clean daemon → empty state.
  await expect(authedPage.locator("text=No matching audit events")).toBeVisible();

  // Clear filters restores the unfiltered view.
  await authedPage.click("text=Clear filters");
  await expect(authedPage.locator("tbody tr").first()).toBeVisible();
});
