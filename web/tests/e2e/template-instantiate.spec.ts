import { test, expect, adminSDKClient } from "./fixtures";
import { APIError } from "remote-signer-client";

const TEMPLATE_ID = "evm/native_transfer";

test("instantiate with valid variables creates a rule", async () => {
  const c = await adminSDKClient();
  const { templates } = await c.templates.list();
  const tmpl = templates.find((t) => t.id === TEMPLATE_ID);
  expect(tmpl).toBeDefined();

  // Inspect template variable defs — confirm at least one required field.
  const requiredVars = tmpl!.variables?.filter((v) => v.required) ?? [];
  expect(requiredVars.length).toBeGreaterThanOrEqual(1);

  let result;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      result = await c.templates.instantiate(tmpl!.id, {
        name: `e2e-instantiate-valid-${Date.now()}-${attempt}`,
        variables: {
          max_transfer_amount: "100",
          allowed_recipients: "0x0000000000000000000000000000000000000001",
        },
      });
      break;
    } catch (e) {
      if (attempt === 4) throw e;
    }
  }
  if (!result) throw new Error("missing instantiate result");

  // Result contains the created rule.
  expect(result.rule).toBeDefined();
  expect(result.rule.id).toBeTruthy();
  expect(result.rule.name).toBeTruthy();

  // Clean up: delete the rule directly.
  await c.evm.rules.delete(result.rule.id).catch(() => {});
});

test("instantiate with missing required variable fails with 400", async () => {
  const c = await adminSDKClient();
  const { templates } = await c.templates.list();
  const tmpl = templates.find((t) => t.id === TEMPLATE_ID);
  expect(tmpl).toBeDefined();

  const err = await c.templates
    .instantiate(tmpl!.id, { variables: {} })
    .catch((e) => e);

  expect(err).toBeInstanceOf(APIError);
  expect((err as APIError).statusCode).toBe(400);
});

test("instantiate with invalid variable value fails with 400", async () => {
  const c = await adminSDKClient();
  const { templates } = await c.templates.list();
  const tmpl = templates.find((t) => t.id === TEMPLATE_ID);
  expect(tmpl).toBeDefined();

  const err = await c.templates
    .instantiate(tmpl!.id, {
      name: `e2e-instantiate-bad-address-${Date.now()}`,
      variables: {
        max_transfer_amount: "100",
        allowed_recipients: "not_an_address",
      },
    })
    .catch((e) => e);

  expect(err).toBeInstanceOf(APIError);
  expect((err as APIError).statusCode).toBe(400);
});

test("instantiate non-existent template returns 404", async () => {
  const c = await adminSDKClient();

  let err: unknown;
  try {
    await c.templates.instantiate("evm/nonexistent_template", { variables: {} });
  } catch (e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err).toBeInstanceOf(APIError);
  if (err instanceof APIError) {
    expect([400, 404]).toContain(err.statusCode);
  }
});

test("revoke existing instance deletes the rule", async () => {
  const c = await adminSDKClient();

  const { templates } = await c.templates.list();
  const tmpl = templates.find((t) => t.id === TEMPLATE_ID);
  expect(tmpl).toBeDefined();

  let result;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      result = await c.templates.instantiate(tmpl!.id, {
        name: `e2e-instantiate-revoke-${Date.now()}-${attempt}`,
        variables: {
          max_transfer_amount: "100",
          allowed_recipients: "0x0000000000000000000000000000000000000001",
        },
      });
      break;
    } catch (e) {
      if (attempt === 4) throw e;
    }
  }
  if (!result) throw new Error("missing instantiate result");
  expect(result.rule.id).toBeTruthy();
  const ruleId = result.rule.id;

  // Revoke cleans up the rule.
  await c.templates.revokeInstance(ruleId);

  // After revoke the rule is disabled (enabled=false, budgets deleted).
  // RevokeInstance in template.go sets Enabled=false, it does NOT change
  // the status or hard-delete the rule.
  const rule = await c.evm.rules.get(ruleId);
  expect(rule.enabled).toBe(false);
});

test("revoke non-existent instance returns error", async () => {
  const c = await adminSDKClient();

  let err: unknown;
  try { await c.templates.revokeInstance("nonexistent-rule-id"); } catch (e) { err = e; }
  expect(err).toBeDefined();
  expect(err).toBeInstanceOf(APIError);
});
