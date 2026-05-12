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

test("create a rule via the UI adds it to the table", async ({
  authedPage,
}) => {
  await authedPage.click("text=Rules");
  await authedPage.click("button:has-text('New rule')");

  const name = `e2e-create-${Date.now()}`;
  await authedPage.fill("input >> nth=0", name); // Name (first input)
  // Type defaults to evm_address_list — the textarea is pre-filled. Just
  // change mode to make the rule unique-ish and submit.
  await authedPage.selectOption("select >> nth=1", "blocklist");
  await authedPage.click("button:has-text('Create rule')");

  const row = authedPage.locator("tr", {
    has: authedPage.locator(`text=${name}`),
  });
  await expect(row).toBeVisible();
  await expect(row.getByText("blocklist")).toBeVisible();
});

test("create form with malformed config JSON shows a parse error", async ({
  authedPage,
}) => {
  await authedPage.click("text=Rules");
  await authedPage.click("button:has-text('New rule')");

  await authedPage.fill("input >> nth=0", `e2e-bad-config-${Date.now()}`);
  await authedPage.locator("textarea").fill("{ not valid json");
  await authedPage.click("button:has-text('Create rule')");

  // The component surfaces the JSON.parse() error in a red ErrorBanner
  // inside the form rather than going to the server. Chrome's JSON.parse
  // message starts with "Expected …" — match the banner specifically
  // rather than `JSON` (which appears in the label + textarea too).
  await expect(
    authedPage.locator("div.text-red-800", { hasText: "Expected" }),
  ).toBeVisible();
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
