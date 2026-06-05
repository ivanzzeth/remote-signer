import { expect, test } from "./fixtures";

function createForm(authedPage: import("@playwright/test").Page) {
  return authedPage.locator("form").filter({
    has: authedPage.getByRole("button", { name: "Generate keypair & create" }),
  });
}

async function openCreateForm(authedPage: import("@playwright/test").Page) {
  await authedPage.getByRole("link", { name: "API Keys", exact: true }).click();
  await expect(authedPage.getByRole("heading", { name: "API Keys" })).toBeVisible();
  await authedPage.getByRole("button", { name: "New API key" }).click();
  return createForm(authedPage);
}

async function createApiKey(
  authedPage: import("@playwright/test").Page,
  id: string,
  opts?: { name?: string; role?: string },
) {
  const form = await openCreateForm(authedPage);
  await form.locator("input").nth(0).fill(id);
  if (opts?.name) {
    await form.locator("input").nth(1).fill(opts.name);
  }
  await form.locator("select").selectOption(opts?.role ?? "dev");
  await form.getByRole("button", { name: "Generate keypair & create" }).click();
}

function apiKeyRow(authedPage: import("@playwright/test").Page, id: string) {
  return authedPage.locator("tbody tr").filter({
    has: authedPage.locator("td:first-child .font-mono", { hasText: id }),
  });
}

test("create new API key surfaces the one-time PEM panel", async ({
  authedPage,
}) => {
  const id = `e2e-create-${Date.now()}`;
  await createApiKey(authedPage, id, { name: `${id} name` });

  await expect(authedPage.locator("text=Save the private key for")).toBeVisible();
  await expect(authedPage.locator(`text=${id}`).first()).toBeVisible();
  await expect(authedPage.locator("text=-----BEGIN PRIVATE KEY-----")).toBeVisible();

  await expect(apiKeyRow(authedPage, id)).toBeVisible();
});

test("disable + re-enable round-trips through the daemon", async ({
  authedPage,
}) => {
  const id = `e2e-toggle-${Date.now()}`;
  await createApiKey(authedPage, id);
  await expect(authedPage.locator("text=-----BEGIN PRIVATE KEY-----")).toBeVisible();
  await authedPage.click("text=Dismiss");

  const row = apiKeyRow(authedPage, id);
  await expect(row.getByText("enabled")).toBeVisible();
  await row.getByRole("button", { name: "Disable" }).click();
  await expect(row.getByText("disabled")).toBeVisible();
  await row.getByRole("button", { name: "Enable" }).click();
  await expect(row.getByText("enabled")).toBeVisible();
});

test("edit API-sourced key name + rate_limit persists", async ({
  authedPage,
}) => {
  const id = `e2e-edit-${Date.now()}`;
  await createApiKey(authedPage, id);
  await authedPage.click("text=Dismiss");

  const row = apiKeyRow(authedPage, id);
  await row.getByRole("button", { name: "Edit" }).click();

  const editPanel = authedPage.locator("form").last();
  await editPanel.locator("input").nth(0).fill(`${id}-renamed`);
  await editPanel.locator("input[type=number]").fill("42");
  await editPanel.getByRole("button", { name: "Save" }).click();

  await expect(
    authedPage.locator(`text=${id}-renamed`).first(),
  ).toBeVisible({ timeout: 5_000 });
});

test("admin key cannot be deleted from the UI", async ({ authedPage }) => {
  await authedPage.getByRole("link", { name: "API Keys", exact: true }).click();
  await expect(authedPage.getByRole("heading", { name: "API Keys" })).toBeVisible();
  const adminRow = authedPage.locator("tbody tr").filter({
    has: authedPage.locator("td:first-child .font-mono", { hasText: "admin" }),
  }).first();
  const del = adminRow.getByRole("button", { name: "Delete" });
  await expect(del).toBeDisabled();
});
