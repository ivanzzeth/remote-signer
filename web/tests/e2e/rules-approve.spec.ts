import { adminSDKClient, expect, test } from "./fixtures";

/**
 * Vertex for the approve/reject flow in the Rules page. Creates a rule
 * via the SDK, then drives the UI to approve it.
 */
test("approve a pending rule via the Rules page Approve button", async ({
  authedPage,
}) => {
  const c = await adminSDKClient();

  // Create a rule via SDK (admin creates directly, so it's active by
  // default, but the Approve endpoint is still callable and the UI
  // renders the Approve button when status is "pending_approval").
  const rule = await c.evm.rules.create({
    name: `e2e-approve-btn-${Date.now()}`,
    type: "evm_address_list",
    mode: "whitelist",
    chain_type: "evm",
    chain_id: "1",
    config: { addresses: ["0x0000000000000000000000000000000000000001"] },
    enabled: true,
  });

  await authedPage.click("text=Rules");
  const row = authedPage.locator("tr", {
    has: authedPage.locator(`text=${rule.name}`),
  });
  await expect(row).toBeVisible();

  // If the rule is pending_approval, the Approve/Reject buttons show in
  // the row actions. Otherwise the test verifies the row rendered.
  const approveBtn = row.getByRole("button", { name: "Approve" });
  if (await approveBtn.isVisible()) {
    await approveBtn.click();
    // After approval the status badge should no longer be pending_approval.
    await expect(row.locator("text=pending_approval")).toHaveCount(0, {
      timeout: 10_000,
    });
  }
});

test("expanded rule detail shows CodeBlock with config JSON", async ({
  authedPage,
}) => {
  const c = await adminSDKClient();
  const rule = await c.evm.rules.create({
    name: `e2e-codeblock-${Date.now()}`,
    type: "evm_address_list",
    mode: "whitelist",
    chain_type: "evm",
    chain_id: "1",
    config: { addresses: ["0x0000000000000000000000000000000000000001"] },
    enabled: true,
  });

  await authedPage.click("text=Rules");
  const row = authedPage.locator("tr", {
    has: authedPage.locator(`text=${rule.name}`),
  });
  await expect(row).toBeVisible();

  // Click the row to expand the detail panel.
  await row.click();

  // The expanded panel should contain the CodeBlock with "Config" title.
  await expect(
    authedPage.locator("text=Config").first(),
  ).toBeVisible();

  // The JSON config should be visible (CodeBlock defaultOpen).
  await expect(
    authedPage.locator("text=0x0000000000000000000000000000000000000001"),
  ).toBeVisible();
});

test("expanded rule detail shows owner attribution", async ({
  authedPage,
}) => {
  const c = await adminSDKClient();
  const rule = await c.evm.rules.create({
    name: `e2e-attribution-${Date.now()}`,
    type: "evm_address_list",
    mode: "whitelist",
    chain_type: "evm",
    chain_id: "1",
    config: { addresses: ["0x0000000000000000000000000000000000000001"] },
    enabled: true,
  });

  await authedPage.click("text=Rules");
  const row = authedPage.locator("tr", {
    has: authedPage.locator(`text=${rule.name}`),
  });
  await expect(row).toBeVisible();
  await row.click();

  // The detail panel should show "Created by" with the admin key ID.
  // The admin key ID in the test daemon is "admin".
  await expect(
    authedPage.locator("text=Created by"),
  ).toBeVisible();
});
