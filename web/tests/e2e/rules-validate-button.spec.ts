import { expect, test } from "./fixtures";

test("Rules detail panel shows Validate button for evm_js rules", async ({
  authedPage,
}) => {
  // Create an evm_js rule via the SDK so we have one to validate.
  const { adminSDKClient } = await import("./fixtures");
  const c = await adminSDKClient();
  const rule = await c.evm.rules.create({
    name: `e2e-validate-btn-${Date.now()}`,
    type: "evm_js",
    mode: "whitelist",
    chain_type: "evm",
    chain_id: "1",
    config: {
      script: "function validate(input) { return ok(); }",
      test_cases: [
        {
          name: "should pass simple validation",
          input: { chain_id: "1", sign_type: "personal" },
          expect_pass: true,
        },
      ],
    },
    enabled: true,
  });

  await authedPage.click("text=Rules");
  const row = authedPage.locator("tr", {
    has: authedPage.locator(`text=${rule.name}`),
  });
  await expect(row).toBeVisible({ timeout: 15000 });

  // Click to expand detail panel (the row toggle).
  await row.click();

  // The expanded panel contains a "Validate" button in the Config section.
  const validateBtn = row.locator("..").getByRole("button", { name: "Validate" });
  await expect(validateBtn).toBeVisible();

  // Click Validate.
  await validateBtn.click();

  // Results should appear with pass/find indicators.
  await expect(
    row.locator("..").locator("text=passed"),
  ).toBeVisible({ timeout: 15000 });

  await expect(
    row.locator("..").locator("text=total"),
  ).toBeVisible();

  // Test case name should be visible.
  await expect(
    row.locator("..").locator("text=should pass simple validation"),
  ).toBeVisible();
});
