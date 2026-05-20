import { adminSDKClient, expect, test } from "./fixtures";

/**
 * Round-trip: open Settings → security → typed form bumps
 * max_request_age via the duration input → Save → reload via SDK →
 * assert the value persisted as the right nanosecond count.
 */
test("security max_request_age edit persists via the typed form", async ({
  authedPage,
}) => {
  await authedPage.click("text=Settings");
  await expect(
    authedPage.getByRole("heading", { name: "Settings" }),
  ).toBeVisible();

  // Default selected group is "security"; the form renders one row per
  // field — the max_request_age row contains a duration text input.
  const ageRow = authedPage.locator("div", {
    hasText: "max_request_age",
  });
  await expect(ageRow.first()).toBeVisible({ timeout: 5_000 });

  // The duration input is the first <input type=text> inside the row.
  // Default value renders as "1m" (60 seconds in ns).
  const durationInput = authedPage
    .locator("input[type='text']")
    .filter({ hasNotText: "" })
    .first();
  // Actually grab the input by its proximity to the label.
  const input = authedPage
    .locator("dl > div", { has: authedPage.locator("text=max_request_age") })
    .locator("input")
    .first();
  await input.fill("90s");

  await authedPage.getByRole("button", { name: "Save" }).click();

  // Cross-check via SDK.
  const client = await adminSDKClient();
  await expect
    .poll(async () => (await client.settings.get("security")).max_request_age, {
      timeout: 5_000,
    })
    .toBe(90_000_000_000);

  // suppress unused
  void durationInput;
});

test("Advanced raw-JSON fallback still writes the snapshot", async ({
  authedPage,
}) => {
  await authedPage.click("text=Settings");
  await authedPage.getByRole("button", { name: "security" }).click();
  await authedPage
    .getByLabel(/Advanced \(raw JSON\)/)
    .check();
  const textarea = authedPage.locator("textarea").first();
  await expect(textarea).toBeVisible();

  const raw = JSON.parse(await textarea.inputValue());
  raw.rate_limit_default = 12345;
  await textarea.fill(JSON.stringify(raw, null, 2));
  await authedPage.getByRole("button", { name: "Save" }).click();

  const client = await adminSDKClient();
  await expect
    .poll(async () => (await client.settings.get("security")).rate_limit_default, {
      timeout: 5_000,
    })
    .toBe(12345);
});
