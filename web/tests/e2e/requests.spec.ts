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
  const req = await filteredReq;

  // ⚠️ Asserts the query was reissued with the filter, which is what this test
  // is named for — not that the result is empty. The suite shares one daemon
  // serially and the blocklist specs create genuinely rejected requests, so
  // "No matching requests" holds only when this spec runs before them. What
  // the filter does is issue a new query; whether rows come back is the
  // daemon's business.
  expect(req.url()).toContain("status=rejected");
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
