import { adminSDKClient, expect, test } from "./fixtures";

/**
 * Verifies that the shared CodeBlock component renders correctly across
 * the three pages that use it: Rules (config JSON), TemplateDetail (scripts),
 * and RequestDetail (payload JSON / hex).
 */

test("Rules detail panel shows CodeBlock with expand/collapse and copy", async ({
  authedPage,
}) => {
  const c = await adminSDKClient();
  const rule = await c.evm.rules.create({
    name: `e2e-cb-rules-${Date.now()}`,
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

  // Expand the detail panel.
  await row.click();

  // The CodeBlock expand/collapse and copy buttons should be visible.
  await expect(
    authedPage.locator("button:has-text('Expand')"),
  ).toBeVisible();
  await expect(
    authedPage.locator("button:has-text('Copy')"),
  ).toBeVisible();

  // The config JSON should be visible in the CodeBlock body.
  await expect(
    authedPage.locator("text=0x0000000000000000000000000000000000000001"),
  ).toBeVisible();
});

test("Template detail shows CodeBlock for evm_js sub-rules", async ({
  authedPage,
}) => {
  const c = await adminSDKClient();

  // List templates — find one with sub-rules (e.g. the Agent template).
  // list() returns an envelope ({ templates, total }), not a bare array.
  const { templates } = await c.templates.list();
  const agentTmpl = templates.find(
    (t: { id: string }) => t.id === "evm/agent",
  );
  if (!agentTmpl) {
    // Template might not be loaded in this environment — skip gracefully.
    test.skip();
    return;
  }

  await authedPage.click("text=Templates");
  // Click the Agent template.
  const link = authedPage.getByRole("link", { name: /Agent/i }).first();
  await expect(link).toBeVisible();
  await link.click();

  // Sub-rules are listed collapsed behind a ▶ toggle; expand the first one to
  // reveal its evm_js script CodeBlock.
  const subRuleToggle = authedPage
    .getByRole("button", { name: /Agent Signature/ })
    .first();
  await expect(subRuleToggle).toBeVisible({ timeout: 10_000 });
  await subRuleToggle.click();

  // The expanded sub-rule should show a CodeBlock for its script. The toggle
  // reads "Expand" or "Collapse" depending on initial state; Copy is always present.
  await expect(
    authedPage.getByRole("button", { name: /Expand|Collapse/ }).first(),
  ).toBeVisible({ timeout: 10_000 });

  // The Copy button should also be present.
  await expect(
    authedPage.locator("button:has-text('Copy')").first(),
  ).toBeVisible();
});

test("Request detail shows CodeBlock for non-transaction payload", async ({
  authedPage,
}) => {
  const c = await adminSDKClient();

  // Create a signer to submit a request.
  const signer = await c.evm.signers.create({
    type: "keystore",
    keystore: { password: "e2e-cb-pw" },
  });

  // Submit an async personal_sign — it'll land as pending.
  try {
    await c.evm.sign.executeAsync({
      chain_id: "1",
      signer_address: signer.address,
      sign_type: "personal",
      payload: { message: "0x48656c6c6f" },
    });
  } catch {
    // executeAsync throws for pending — that's expected.
  }

  await authedPage.click("text=Requests");

  // Find the request row by signer address prefix.
  const shortPrefix = signer.address.slice(0, 10);
  const row = authedPage.locator("tr", {
    has: authedPage.locator(`text=${shortPrefix}`),
  });
  await expect(row).toBeVisible({ timeout: 10_000 });

  // Click the row to navigate to the detail page.
  await row.click();

  // The detail page should render a CodeBlock for the payload JSON. The
  // CodeBlock's toggle reads "Expand" or "Collapse" depending on whether the
  // content starts collapsed (short payloads render expanded → "Collapse"), so
  // match either; the Copy button is always present.
  await expect(
    authedPage.getByRole("button", { name: /Expand|Collapse/ }).first(),
  ).toBeVisible({ timeout: 10_000 });

  await expect(
    authedPage.locator("button:has-text('Copy')").first(),
  ).toBeVisible();
});
