import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "@playwright/test";
import { getState } from "./global-setup";

test("unauthenticated root redirects to /login", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("heading", { name: "Import API key" })).toBeVisible();
});

test("admin PEM import logs in and lands on Dashboard", async ({ page }) => {
  const state = getState();
  const pem = readFileSync(
    join(state.home, "apikeys", "admin.key.priv"),
    "utf8",
  );

  await page.goto("/login");
  await page.fill("#api-key-id", "admin");
  await page.fill("#key-input", pem);
  await page.click("button[type=submit]");

  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  // Three Dashboard cards prove auth + health + audit round-tripped.
  await expect(page.getByText("Daemon", { exact: true })).toBeVisible();
  await expect(page.getByText("This session", { exact: true })).toBeVisible();
  await expect(page.getByText("Recent audit events")).toBeVisible();
});

test("garbage key input surfaces a parse error", async ({ page }) => {
  await page.goto("/login");
  await page.fill("#api-key-id", "admin");
  await page.fill("#key-input", "this is not a pem");
  await page.click("button[type=submit]");
  await expect(page.locator("text=expected hex or PKCS#8 PEM input")).toBeVisible();
});
