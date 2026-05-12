import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  RemoteSignerClient,
  parsePrivateKey,
  type SettingsSnapshot,
} from "remote-signer-client";
import { expect, test } from "./fixtures";
import { getState } from "./global-setup";

/**
 * Round-trip: open Settings → Edit "security" → bump max_request_age →
 * Save → reload via SDK → assert the new value persisted.
 */
test("security settings edit persists across PUT/GET", async ({
  authedPage,
}) => {
  await authedPage.click("text=Settings");
  await expect(
    authedPage.getByRole("heading", { name: "Settings" }),
  ).toBeVisible();

  // Wait for security card content to land (rate_limit_default is in every
  // snapshot regardless of overrides).
  await expect(
    authedPage.locator("text=rate_limit_default").first(),
  ).toBeVisible();

  // Find the security card and click its Edit button.
  const securityCard = authedPage.locator("section", {
    has: authedPage.getByRole("heading", { name: "security" }),
  });
  await securityCard.getByRole("button", { name: "Edit" }).click();

  const textarea = securityCard.locator("textarea");
  await expect(textarea).toBeVisible();
  const initial = JSON.parse((await textarea.inputValue()) || "{}");

  // Bump max_request_age and save. The setting value is serialized in
  // Go's time.Duration form: number of nanoseconds, JSON-encoded.
  const patched: SettingsSnapshot = {
    ...initial,
    max_request_age: 90_000_000_000, // 90s
  };
  await textarea.fill(JSON.stringify(patched, null, 2));
  await securityCard.getByRole("button", { name: "Save" }).click();

  // After save the card returns to viewer mode.
  await expect(securityCard.locator("textarea")).toHaveCount(0);
  await expect(securityCard.locator("text=Edit")).toBeVisible();

  // Confirm the change is durable by reading via the SDK (server-side).
  const state = getState();
  const seed = parsePrivateKey(
    readFileSync(join(state.home, "apikeys", "admin.key.priv"), "utf8"),
  );
  const client = new RemoteSignerClient({
    baseURL: `http://127.0.0.1:${process.env.E2E_PORT ?? 18548}`,
    apiKeyID: "admin",
    privateKey: seed,
  });
  const reloaded = await client.settings.get("security");
  expect(reloaded.max_request_age).toBe(90_000_000_000);
});
