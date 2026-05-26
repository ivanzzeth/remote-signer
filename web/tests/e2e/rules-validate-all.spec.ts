import { expect, test } from "./fixtures";

test("Rules page shows Validate all button and batch results", async ({
  authedPage,
}) => {
  // Create a few evm_js rules via SDK so there is something to batch-validate.
  const { adminSDKClient } = await import("./fixtures");
  const c = await adminSDKClient();
  const ts = Date.now();

  await c.evm.rules.create({
    name: `e2e-batch-valid-${ts}`,
    type: "evm_js",
    mode: "whitelist",
    chain_type: "evm",
    chain_id: "1",
    config: {
      script: "function validate(input) { return ok(); }",
      test_cases: [
        {
          name: "passes",
          input: { chain_id: "1", sign_type: "personal" },
          expect_pass: true,
        },
      ],
    },
    enabled: true,
  });

  await authedPage.click("text=Rules");
  await expect(
    authedPage.getByRole("heading", { name: "Rules" }),
  ).toBeVisible({ timeout: 15000 });

  // Click "Validate all".
  const batchBtn = authedPage.getByRole("button", { name: "Validate all" });
  await expect(batchBtn).toBeVisible();
  await batchBtn.click();

  // Batch results appear as a card.
  await expect(
    authedPage.locator("text=total").first(),
  ).toBeVisible({ timeout: 15000 });

  // At least our created rules should be in the results.
  await expect(
    authedPage.locator(`text=e2e-batch-valid-${ts}`).first(),
  ).toBeVisible();
});
