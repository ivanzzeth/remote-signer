import { expect, test } from "./fixtures";

test("create new API key surfaces the one-time PEM panel", async ({
  authedPage,
}) => {
  await authedPage.click("text=API Keys");
  await authedPage.click("button:has-text('New API key')");

  // Use a unique id so the spec is rerunnable against the same daemon
  // instance — the daemon's DB persists for the duration of globalSetup.
  const id = `e2e-create-${Date.now()}`;
  await authedPage.fill("input >> nth=0", id); // ID field
  await authedPage.fill("input >> nth=1", `${id} name`); // Name field
  await authedPage.selectOption("select", "dev");
  await authedPage.click("button:has-text('Generate keypair & create')");

  // One-time panel must surface BEGIN PRIVATE KEY — that's the operator's
  // single chance to copy the seed. Match on the BEGIN marker rather than
  // the panel heading because React renders the heading's quotes with
  // typographic curly quotes (`&ldquo;`/`&rdquo;`).
  await expect(authedPage.locator("text=Save the private key for")).toBeVisible();
  await expect(authedPage.locator(`text=${id}`).first()).toBeVisible();
  await expect(authedPage.locator("text=-----BEGIN PRIVATE KEY-----")).toBeVisible();

  // New row appears in the table after reload triggered by create().
  const row = authedPage.locator("tr", { has: authedPage.locator(`text=${id}`).first() });
  await expect(row).toBeVisible();
});

test("disable + re-enable round-trips through the daemon", async ({
  authedPage,
}) => {
  await authedPage.click("text=API Keys");
  await authedPage.click("button:has-text('New API key')");
  const id = `e2e-toggle-${Date.now()}`;
  await authedPage.fill("input >> nth=0", id);
  await authedPage.selectOption("select", "dev");
  await authedPage.click("button:has-text('Generate keypair & create')");
  await expect(authedPage.locator("text=-----BEGIN PRIVATE KEY-----")).toBeVisible();
  await authedPage.click("text=Dismiss");

  const row = authedPage.locator("tr", { has: authedPage.locator(`text=${id}`).first() });
  await expect(row.getByText("enabled")).toBeVisible();
  await row.getByRole("button", { name: "Disable" }).click();
  await expect(row.getByText("disabled")).toBeVisible();
  await row.getByRole("button", { name: "Enable" }).click();
  await expect(row.getByText("enabled")).toBeVisible();
});

test("edit API-sourced key name + rate_limit persists", async ({
  authedPage,
}) => {
  await authedPage.click("text=API Keys");
  await authedPage.click("button:has-text('New API key')");

  const id = `e2e-edit-${Date.now()}`;
  await authedPage.fill("input >> nth=0", id);
  await authedPage.selectOption("select", "dev");
  await authedPage.click("button:has-text('Generate keypair & create')");
  await authedPage.click("text=Dismiss");

  const row = authedPage.locator("tr", {
    has: authedPage.locator(`text=${id}`).first(),
  });
  await row.getByRole("button", { name: "Edit" }).click();

  // Edit panel is the only <form> on the page (Create dialog was dismissed).
  const editPanel = authedPage.locator("form").last();
  await editPanel.locator("input").nth(0).fill(`${id}-renamed`);
  await editPanel.locator("input[type=number]").fill("42");
  await editPanel.getByRole("button", { name: "Save" }).click();

  // Renamed row reflects the new label below the id.
  await expect(
    authedPage.locator(`text=${id}-renamed`).first(),
  ).toBeVisible({ timeout: 5_000 });
});

test("admin key cannot be deleted from the UI", async ({ authedPage }) => {
  await authedPage.click("text=API Keys");
  const adminRow = authedPage.locator("tr", {
    has: authedPage.locator("text=admin").first(),
  });
  const del = adminRow.getByRole("button", { name: "Delete" });
  await expect(del).toBeDisabled();
});
