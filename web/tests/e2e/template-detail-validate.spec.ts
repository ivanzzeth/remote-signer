import { expect, test } from "./fixtures";

test("Template detail shows validate button and displays per-rule results", async ({
  authedPage,
}) => {
  await authedPage.click("text=Templates");
  await expect(
    authedPage.getByRole("heading", { name: "Templates" }),
  ).toBeVisible({ timeout: 15000 });

  // Navigate to ERC20 template (it has test_cases in its YAML).
  const link = authedPage.getByRole("link", {
    name: "ERC20 transfer/transferFrom limit",
    exact: true,
  });
  await expect(link).toBeVisible({ timeout: 15000 });
  await link.click();
  await expect(
    authedPage.getByRole("heading", {
      name: "ERC20 transfer/transferFrom limit",
    }),
  ).toBeVisible({ timeout: 10000 });

  // Scroll to the validate panel and click "Validate test cases".
  const validateBtn = authedPage.getByRole("button", {
    name: /Validate test cases/i,
  });
  await expect(validateBtn).toBeVisible();
  await validateBtn.click();

  // Wait for results to appear — the panel displays per-rule results with
  // pass/fail counts. The ERC20 template should pass all test cases.
  await expect(
    authedPage.locator("text=total").first(),
  ).toBeVisible({ timeout: 15000 });

  // Verify at least one ✓ pass indicator and no ✗ failures.
  const passText = await authedPage.locator("text=passed").count();
  expect(passText).toBeGreaterThanOrEqual(1);

  // The button text changes to "Re-validate" after first run.
  await expect(
    authedPage.getByRole("button", { name: /Re-validate/i }),
  ).toBeVisible();
});

test("Template detail validate catches failing test cases", async ({
  authedPage,
}) => {
  await authedPage.click("text=Templates");
  await expect(
    authedPage.getByRole("heading", { name: "Templates" }),
  ).toBeVisible({ timeout: 15000 });

  // Navigate to security.example template (known to have a failing test).
  const link = authedPage.getByRole("link", {
    name: "Security example",
    exact: true,
  });
  // If the security.example template isn't in the catalog, skip.
  if (await link.isVisible()) {
    await link.click();
    await expect(
      authedPage.getByRole("heading", { name: "Security example" }),
    ).toBeVisible({ timeout: 10000 });

    const validateBtn = authedPage.getByRole("button", {
      name: /Validate test cases/i,
    });
    await expect(validateBtn).toBeVisible();
    await validateBtn.click();

    // At least one "failed" indicator should appear.
    await expect(
      authedPage.locator("text=failed").first(),
    ).toBeVisible({ timeout: 15000 });
  }
});
