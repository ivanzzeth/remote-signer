import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  RemoteSignerClient,
  parsePrivateKey,
} from "remote-signer-client";
import { expect, test } from "./fixtures";
import { getState } from "./global-setup";

/**
 * Seed a rule via the SDK so we have something to mutate, then drive the
 * UI through the toggle + delete flows.
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

test("toggle a rule between enabled/disabled via the UI", async ({
  authedPage,
}) => {
  const c = adminClient();
  const rule = await c.evm.rules.create({
    name: `e2e-toggle-${Date.now()}`,
    type: "evm_address_list",
    mode: "whitelist",
    chain_type: "evm",
    chain_id: "1",
    config: { addresses: ["0x0000000000000000000000000000000000000001"] },
    enabled: true,
  });

  await authedPage.click("text=Rules");
  const row = authedPage.locator("tr", {
    has: authedPage.locator(`text=${rule.name}`),
  });
  await expect(row).toBeVisible();
  await expect(row.getByText("enabled")).toBeVisible();

  await row.getByRole("button", { name: "Disable" }).click();
  await expect(row.getByText("disabled")).toBeVisible();

  // Cross-check via SDK.
  const reloaded = await c.evm.rules.get(rule.id);
  expect(reloaded.enabled).toBe(false);
});

test("delete a rule via the UI removes it from the table", async ({
  authedPage,
}) => {
  const c = adminClient();
  const rule = await c.evm.rules.create({
    name: `e2e-delete-${Date.now()}`,
    type: "evm_address_list",
    mode: "whitelist",
    chain_type: "evm",
    chain_id: "1",
    config: { addresses: ["0x0000000000000000000000000000000000000002"] },
    enabled: true,
  });

  await authedPage.click("text=Rules");
  const row = authedPage.locator("tr", {
    has: authedPage.locator(`text=${rule.name}`),
  });
  await expect(row).toBeVisible();

  // Auto-accept the native confirm() the page raises.
  authedPage.once("dialog", (d) => d.accept());
  await row.getByRole("button", { name: "Delete" }).click();

  await expect(
    authedPage.locator(`text=${rule.name}`),
  ).toHaveCount(0);
});
