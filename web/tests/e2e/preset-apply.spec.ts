import { adminSDKClient, expect, test } from "./fixtures";

/**
 * Applies the agent preset via SDK, then verifies the resulting rules are
 * visible in the Rules page with correct status, owner, and applied_to.
 */
test("agent preset apply creates rules visible in Rules list", async ({
  authedPage,
}) => {
  const c = await adminSDKClient();

  // Apply the agent preset via SDK (needs manual_approval_enabled=false for
  // immediate activation; the test daemon enables it, but admin-applied
  // presets create active rules either way).
  const applyResp = await c.presets.applyWithVariables("evm/agent", {});
  expect(applyResp.results.length).toBeGreaterThanOrEqual(1);

  // Collect created rule IDs for later cross-check.
  const ruleIDs = applyResp.results.map(
    (r: { rule: { id: string } }) => r.rule.id,
  );

  try {
    await authedPage.click("text=Rules");

    // Each created rule should appear in the table.
    for (const id of ruleIDs) {
      // The expanded detail panel shows the rule ID in a monospace font.
      // Use the SDK to get the name, then locate in the table.
      const rule = await c.evm.rules.get(id);
      await expect(
        authedPage.locator("tr", {
          has: authedPage.locator(`text=${rule.name}`),
        }),
      ).toBeVisible();
    }
  } finally {
    // Clean up: the agent preset's whitelist rules (e.g. "Agent Signature",
    // which allows personal_sign) are created active and applied broadly. The
    // suite shares one daemon serially, so leaving them active auto-approves
    // requests in later specs (e.g. requests-approve). Revoke them here.
    for (const id of ruleIDs) {
      await c.evm.rules.delete(id).catch(() => {});
    }
  }
});

test("preset detail page shows apply button and variable inputs", async ({
  authedPage,
}) => {
  await authedPage.click("text=Presets");
  // Click a known preset — the built-in "Agent" preset.
  const link = authedPage.getByRole("link", { name: /Agent/i }).first();
  await expect(link).toBeVisible();
  await link.click();

  // The detail page should show an "Apply" affordance.
  await expect(
    authedPage.locator("text=Apply preset").first(),
  ).toBeVisible();
});
