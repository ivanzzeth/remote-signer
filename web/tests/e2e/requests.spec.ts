import { expect, test } from "./fixtures";

test("Requests page defaults to pending filter and renders empty state", async ({
  authedPage,
}) => {
  // Capture the initial fetch so we can assert the default filter shape.
  const initialReq = authedPage.waitForRequest(
    (r) =>
      r.url().includes("/api/v1/evm/requests") && r.url().includes("status=pending"),
  );
  await authedPage.click("text=Requests");
  await initialReq;

  await expect(
    authedPage.getByRole("heading", { name: "Sign requests" }),
  ).toBeVisible();
  await expect(authedPage.locator("text=No matching requests")).toBeVisible();
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

test("'all' filter omits the status query param", async ({ authedPage }) => {
  await authedPage.click("text=Requests");

  // 'all' is the empty-string option; the SDK omits the param when status
  // is "" so the URL should not include status=...
  const allReq = authedPage.waitForRequest((r) => {
    if (!r.url().includes("/api/v1/evm/requests")) return false;
    return !r.url().includes("status=");
  });
  await authedPage.selectOption("select:near(:text('Status'))", "");
  await allReq;
});
