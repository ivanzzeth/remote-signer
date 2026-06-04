import { expect, test } from "./fixtures";

const PASSWORD = "e2e-hd-pw-K7m2pQ";

test("create HD wallet + derive a child index via the UI", async ({
  authedPage,
}) => {
  await authedPage.click("text=HD Wallets");
  await authedPage.click("button:has-text('New wallet')");

  await authedPage.fill("input[type=password] >> nth=0", PASSWORD);
  await authedPage.fill("input[type=password] >> nth=1", PASSWORD);
  await authedPage.click("button:has-text('Generate HD wallet')");

  // Newly created wallet shows up in the table. The primary address is
  // random; locate via the row count change.
  const rows = authedPage.locator("table tbody tr");
  await expect(rows.first()).toBeVisible({ timeout: 5_000 });

  // Click the first wallet row to expand its panel.
  await rows.first().click();
  await expect(authedPage.locator("text=Derived addresses")).toBeVisible();

  // Fresh wallets ship with index 0 already derived. Count current rows,
  // derive index 7, and assert a new row landed.
  const derivedTable = authedPage.locator("text=Derived addresses").locator(
    "xpath=ancestor::div[1]//table",
  );
  const primaryIndexCell = derivedTable.locator("tbody tr").first().locator("td").nth(1);
  await expect(primaryIndexCell).toHaveText("0");

  const before = await derivedTable.locator("tbody tr").count();
  await authedPage.fill("input[type=number]", "7");
  await authedPage.click("button:has-text('Derive')");
  await expect
    .poll(async () => derivedTable.locator("tbody tr").count(), {
      timeout: 5_000,
    })
    .toBeGreaterThan(before);
});

test("import requires a valid mnemonic", async ({ authedPage }) => {
  await authedPage.click("text=HD Wallets");
  await authedPage.click("button:has-text('Import')");

  await authedPage.fill("textarea", "not a real mnemonic");
  await authedPage.fill("input[type=password] >> nth=0", PASSWORD);
  await authedPage.fill("input[type=password] >> nth=1", PASSWORD);
  await authedPage.click("button:has-text('Import wallet')");

  await expect(
    authedPage.locator("text=mnemonic must be 12/15/18/21/24 words"),
  ).toBeVisible();
});
