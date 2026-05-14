import { expect, test } from "./fixtures";

test("Requests page defaults to 'all' filter", async ({ authedPage }) => {
  // The page now defaults to status="" (all) so the operator sees both
  // active queue and history without flipping a filter first. The
  // initial list fetch omits the status query param — that's the
  // load-bearing assertion. We don't check for an empty state because
  // other specs in the suite seed requests against the shared daemon.
  const initialReq = authedPage.waitForRequest(
    (r) =>
      r.url().includes("/api/v1/evm/requests") && !r.url().includes("status="),
  );
  await authedPage.click("text=Requests");
  await initialReq;

  await expect(
    authedPage.getByRole("heading", { name: "Sign requests" }),
  ).toBeVisible();
});

test("changing the status filter reissues the list query", async ({
  authedPage,
}) => {
  await authedPage.click("text=Requests");

  const filteredReq = authedPage.waitForRequest(
    (r) =>
      r.url().includes("/api/v1/evm/requests") &&
      r.url().includes("status=rejected"),
  );
  await authedPage.selectOption("select:near(:text('Status'))", "rejected");
  await filteredReq;

  await expect(authedPage.locator("text=No matching requests")).toBeVisible();
});

test("switching to 'pending' filter narrows the list query", async ({
  authedPage,
}) => {
  await authedPage.click("text=Requests");

  const pendingReq = authedPage.waitForRequest(
    (r) =>
      r.url().includes("/api/v1/evm/requests") &&
      r.url().includes("status=pending"),
  );
  await authedPage.selectOption("select:near(:text('Status'))", "pending");
  await pendingReq;
});
