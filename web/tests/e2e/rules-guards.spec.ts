import { APIError, SignError } from "remote-signer-client";
import { adminSDKClient, expect, test } from "./fixtures";

test("mutable rule can be updated", async () => {
  const c = await adminSDKClient();
  const name = `e2e-mutable-${Date.now()}`;
  let rule;

  try {
    rule = await c.evm.rules.create({
      name,
      type: "evm_address_list",
      mode: "whitelist",
      chain_type: "evm",
      chain_id: "1",
      config: { addresses: ["0x0000000000000000000000000000000000000001"] },
      enabled: true,
    });

    const updated = await c.evm.rules.update(rule.id, { name: `${name}-updated` });
    expect(updated.name).toBe(`${name}-updated`);
  } finally {
    if (rule) {
      await c.evm.rules.delete(rule.id).catch(() => {});
    }
  }
});

test("mutating a config-sourced rule is rejected with 403", async () => {
  const c = await adminSDKClient();
  const resp = await c.evm.rules.list({});
  const rulesArr = resp.rules || resp.items || [];
  const configRule = rulesArr.find((r: any) => r.source === "config");

  test.skip(!configRule, "no config-sourced rule found to test against");

  let thrown = false;
  try {
    await c.evm.rules.update(configRule!.id, { name: "hack" });
  } catch (e) {
    if (e instanceof APIError) {
      expect(e.statusCode).toBe(403);
      thrown = true;
    } else {
      throw e;
    }
  }
  expect(thrown).toBe(true);
});

test("deleting a non-existent rule returns 404", async () => {
  const c = await adminSDKClient();
  let thrown = false;

  try {
    await c.evm.rules.delete("nonexistent-id");
  } catch (e) {
    if (e instanceof APIError) {
      expect(e.statusCode).toBe(404);
      thrown = true;
    } else {
      throw e;
    }
  }
  expect(thrown).toBe(true);
});

test("create rule with invalid rule type returns 400", async () => {
  const c = await adminSDKClient();
  let thrown = false;

  try {
    await c.evm.rules.create({
      name: "bad",
      type: "nonexistent_type",
      mode: "whitelist",
      chain_type: "evm",
      config: {},
      enabled: true,
    });
  } catch (e) {
    if (e instanceof APIError) {
      expect(e.statusCode).toBe(400);
      thrown = true;
    } else {
      throw e;
    }
  }
  expect(thrown).toBe(true);
});

test("no matching rules causes sign request to enter pending", async () => {
  const c = await adminSDKClient();
  let signer;

  try {
    signer = await c.evm.signers.create({
      type: "keystore",
      keystore: { password: "e2e-guard-pw" },
    });

    let requestId = "";
    let caught = false;

    try {
      await c.evm.sign.executeAsync({
        chain_id: "1",
        signer_address: signer.address,
        sign_type: "personal",
        payload: { message: "0x48656c6c6f" },
      });
    } catch (e) {
      if (!(e instanceof SignError)) throw e;
      expect(["pending", "authorizing"]).toContain(e.status);
      requestId = e.requestID;
      caught = true;
    }

    expect(caught).toBe(true);
    expect(requestId).toBeTruthy();

    // Verify the request exists and is not rejected outright.
    const r = await c.evm.requests.get(requestId);
    expect(["pending", "authorizing"]).toContain(r.status);

    // Admin rejects the orphaned request so it doesn't pollute later specs.
    await c.evm.requests.approve(requestId, { approved: false });
  } finally {
    if (signer) {
      await c.evm.signers.deleteSigner(signer.address).catch(() => {});
    }
  }
});

test("manual approval: reject path", async () => {
  const c = await adminSDKClient();
  let signer;

  try {
    signer = await c.evm.signers.create({
      type: "keystore",
      keystore: { password: "e2e-reject-pw" },
    });

    let requestId = "";
    try {
      await c.evm.sign.executeAsync({
        chain_id: "1",
        signer_address: signer.address,
        sign_type: "personal",
        payload: { message: "0x776f726c64" },
      });
    } catch (e) {
      if (!(e instanceof SignError)) throw e;
      expect(["pending", "authorizing"]).toContain(e.status);
      requestId = e.requestID;
    }

    expect(requestId).toBeTruthy();

    await c.evm.requests.approve(requestId, { approved: false });
    const r = await c.evm.requests.get(requestId);
    expect(r.status).toBe("rejected");
  } finally {
    if (signer) {
      await c.evm.signers.deleteSigner(signer.address).catch(() => {});
    }
  }
});

test("create evm_js rule with valid script succeeds", async () => {
  const c = await adminSDKClient();
  const name = `e2e-js-${Date.now()}`;
  let rule;

  try {
    rule = await c.evm.rules.create({
      name,
      type: "evm_js",
      mode: "whitelist",
      chain_type: "evm",
      chain_id: "1",
      config: { script: "function validate(input) { return ok(); }" },
      enabled: true,
    });
    expect(rule.name).toBe(name);
    expect(rule.type).toBe("evm_js");
  } finally {
    if (rule) {
      await c.evm.rules.delete(rule.id).catch(() => {});
    }
  }
});
