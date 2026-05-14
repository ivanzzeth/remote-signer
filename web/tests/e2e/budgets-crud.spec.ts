import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  RemoteSignerClient,
  parsePrivateKey,
} from "remote-signer-client";
import { expect, test } from "./fixtures";
import { getState } from "./global-setup";

/**
 * Full Budget CRUD lifecycle driven through the UI:
 *
 *   1. Seed a rule via the SDK (the form's rule picker only lists
 *      existing rules — UI can't create one inline).
 *   2. Navigate to /budgets, open the New form, create a budget.
 *   3. Click the row → detail page.
 *   4. Edit limits; verify they persist.
 *   5. Reset spend.
 *   6. Delete; verify the row disappears.
 *
 * Uses unique names per run so re-running the suite locally doesn't
 * collide with leftovers in a shared daemon (the fixture wipes per
 * test class, not per test).
 */
function adminClient() {
  const state = getState();
  const seed = parsePrivateKey(
    readFileSync(join(state.home, "apikeys", "admin.key.priv"), "utf8"),
  );
  return new RemoteSignerClient({
    baseURL: `http://127.0.0.1:${process.env.E2E_PORT ?? 18548}`,
    apiKeyID: "admin",
    privateKey: seed,
  });
}

test("create → edit → reset → delete budget through the UI", async ({
  authedPage,
}) => {
  const c = adminClient();
  const ruleName = `e2e-budget-rule-${Date.now()}`;
  const rule = await c.evm.rules.create({
    name: ruleName,
    type: "evm_address_list",
    mode: "whitelist",
    chain_type: "evm",
    chain_id: "1",
    config: { addresses: ["0x0000000000000000000000000000000000000001"] },
    enabled: true,
  });

  const unit = `1:e2e-${Date.now()}`;

  // --- Create ---
  await authedPage.click("text=Budgets");
  await expect(
    authedPage.getByRole("heading", { name: "Budgets" }),
  ).toBeVisible();

  await authedPage.getByTestId("budget-new").click();
  await authedPage
    .getByTestId("budget-form-rule")
    .selectOption(rule.id);
  await authedPage.getByTestId("budget-form-unit").fill(unit);
  await authedPage.getByTestId("budget-form-max-total").fill("1000000");
  await authedPage.getByTestId("budget-form-max-per-tx").fill("100000");
  await authedPage.getByTestId("budget-form-submit").click();

  // After create, the form panel closes and the list refreshes. The
  // new row carries the rule name we picked.
  const row = authedPage.locator("tr", {
    has: authedPage.locator(`text=${ruleName}`),
  });
  await expect(row).toBeVisible();
  await expect(row.locator(`text=${unit}`)).toBeVisible();

  // --- Detail (row click navigates) ---
  await row.click();
  await expect(
    authedPage.getByRole("heading", { name: ruleName }),
  ).toBeVisible();
  await expect(authedPage.locator("text=1000000").first()).toBeVisible();

  // --- Edit ---
  await authedPage.getByTestId("budget-edit").click();
  await authedPage.getByTestId("budget-form-max-total").fill("9999999");
  await authedPage.getByTestId("budget-form-submit").click();
  await expect(authedPage.locator("text=9999999").first()).toBeVisible();

  // --- Reset spend (handle confirm() dialog) ---
  authedPage.once("dialog", (d) => d.accept());
  await authedPage.getByTestId("budget-reset").click();
  // After reset, the spent counter in the Usage card reads exactly "0".
  await expect(authedPage.getByTestId("budget-spent")).toHaveText("0");
  await expect(authedPage.getByTestId("budget-tx-count")).toHaveText("0");

  // --- Delete ---
  authedPage.once("dialog", (d) => d.accept());
  await authedPage.getByTestId("budget-delete").click();
  await expect(
    authedPage.getByRole("heading", { name: "Budgets" }),
  ).toBeVisible();
  await expect(
    authedPage.locator("tr", {
      has: authedPage.locator(`text=${unit}`),
    }),
  ).toHaveCount(0);
});

test("Budget form refuses sim:* rule creation", async ({ authedPage }) => {
  // The form filters sim:* out of the rule dropdown to begin with, so
  // the more direct check is at the SDK layer — but we can verify the
  // dropdown stays clean by ensuring it never offers a sim:* option.
  await authedPage.click("text=Budgets");
  await authedPage.getByTestId("budget-new").click();
  const options = authedPage
    .getByTestId("budget-form-rule")
    .locator("option");
  const texts = await options.allTextContents();
  for (const t of texts) {
    expect(t.startsWith("sim:")).toBe(false);
  }
});
