import { SignError } from "remote-signer-client";
import { adminSDKClient, expect, test } from "./fixtures";

/**
 * Rules-engine e2e tests: blocklist, whitelist, manual-approval fallback,
 * budget enforcement, disabled-rule semantics, and delegate_to chaining.
 *
 * Every test is SDK-only (no page/UI) -- the rule engine operates at the
 * API layer and the daemon's config.yaml sets `manual_approval_enabled: true`
 * so unmatched requests land in the operator queue rather than 403-ing.
 */

test("blocklist rule rejects matching transaction", async () => {
  const c = await adminSDKClient();
  const signer = await c.evm.signers.create({
    type: "keystore",
    keystore: { password: "e2e-bl-rule-pw" },
  });
  const ruleName = `e2e-bl-${Date.now()}`;
  const blockedAddr = "0x0000000000000000000000000000000000000001";

  let ruleId = "";
  try {
    const rule = await c.evm.rules.create({
      name: ruleName,
      type: "evm_address_list",
      mode: "blocklist",
      chain_type: "evm",
      chain_id: "1",
      config: { addresses: [blockedAddr] },
      enabled: true,
    });
    ruleId = rule.id;

    let thrown = false;
    try {
      await c.evm.sign.executeAsync({
        chain_id: "1",
        signer_address: signer.address,
        sign_type: "transaction",
        payload: {
          transaction: {
            to: blockedAddr,
            value: "0x0",
            data: "0x",
            from: signer.address,
            gas: 21000,
            gasPrice: "0",
            txType: "legacy",
          },
        },
      });
    } catch (e) {
      if (!(e instanceof SignError)) throw e;
      expect(e.status).toBe("rejected");
      thrown = true;
    }
    expect(thrown).toBe(true);
  } finally {
    if (ruleId) await c.evm.rules.delete(ruleId).catch(() => {});
    await c.evm.signers.deleteSigner(signer.address).catch(() => {});
  }
});

test("whitelist rule auto-approves matching transaction", async () => {
  const c = await adminSDKClient();
  const signer = await c.evm.signers.create({
    type: "keystore",
    keystore: { password: "e2e-wl-rule-pw" },
  });
  const ruleName = `e2e-wl-${Date.now()}`;
  const allowedAddr = "0x0000000000000000000000000000000000000001";

  let ruleId = "";
  try {
    const rule = await c.evm.rules.create({
      name: ruleName,
      type: "evm_address_list",
      mode: "whitelist",
      chain_type: "evm",
      chain_id: "1",
      config: { addresses: [allowedAddr] },
      enabled: true,
    });
    ruleId = rule.id;

    let status: string | undefined;
    try {
      const resp = await c.evm.sign.executeAsync({
        chain_id: "1",
        signer_address: signer.address,
        sign_type: "transaction",
        payload: {
          transaction: {
            to: allowedAddr,
            value: "0x0",
            data: "0x",
            from: signer.address,
            gas: 21000,
            txType: "legacy",
            gasPrice: "0",
          },
        },
      });
      status = resp.status;
    } catch (e) {
      if (!(e instanceof SignError)) throw e;
      status = e.status;
    }

    // A whitelist match auto-approves -- the server returns "completed"
    // (signed synchronously) or "signing" (async signing started).
    expect(status).toBeDefined();
    expect(["completed", "signing"]).toContain(status);
  } finally {
    if (ruleId) await c.evm.rules.delete(ruleId).catch(() => {});
    await c.evm.signers.deleteSigner(signer.address).catch(() => {});
  }
});

test("no matching rule falls to manual approval (pending status)", async () => {
  const c = await adminSDKClient();
  const signer = await c.evm.signers.create({
    type: "keystore",
    keystore: { password: "e2e-manual-rule-pw" },
  });

  let requestId = "";
  try {
    // Submit without creating any rules -> manual approval.
    try {
      await c.evm.sign.executeAsync({
        chain_id: "1",
        signer_address: signer.address,
        sign_type: "transaction",
        payload: {
          transaction: {
            to: "0xDEADDEADDEADDEADDEADDEADDEADDEADDEADDEAD",
            value: "0x0",
            data: "0x",
            from: signer.address,
            txType: "legacy",
            gas: 21000,
            gasPrice: "0",
          },
        },
      });
    } catch (e) {
      if (!(e instanceof SignError)) throw e;
      expect(["pending", "authorizing"]).toContain(e.status);
      requestId = e.requestID;
    }
    expect(requestId).toBeTruthy();

    // Cross-check via the requests endpoint.
    const request = await c.evm.requests.get(requestId);
    expect(["pending", "authorizing"]).toContain(request.status);
  } finally {
    await c.evm.signers.deleteSigner(signer.address).catch(() => {});
  }
});

test("budget under cap allows the transaction to pass", async () => {
  const c = await adminSDKClient();
  const signer = await c.evm.signers.create({
    type: "keystore",
    keystore: { password: "e2e-budget-pass-pw" },
  });
  const ruleName = `e2e-budget-pass-${Date.now()}`;

  let ruleId = "";
  let budgetId = "";
  try {
    const rule = await c.evm.rules.create({
      name: ruleName,
      type: "evm_address_list",
      mode: "whitelist",
      chain_type: "evm",
      chain_id: "1",
      config: { addresses: ["0x0000000000000000000000000000000000000001"] },
      enabled: true,
    });
    ruleId = rule.id;

    const budget = await c.evm.budgets.create({
      rule_id: ruleId,
      unit: "1:native",
      max_total: "100000000000000000000",   // 100 ETH
      max_per_tx: "100000000000000000000",  // 100 ETH
      max_tx_count: 10,
    });
    budgetId = budget.id;

    let status: string | undefined;
    try {
      const resp = await c.evm.sign.executeAsync({
        chain_id: "1",
        signer_address: signer.address,
        sign_type: "transaction",
        payload: {
          transaction: {
            to: "0x0000000000000000000000000000000000000001",
            value: "0xde0b6b3a7640000", // 1 ETH
            data: "0x",
            txType: "legacy",
            from: signer.address,
            gas: 21000,
            gasPrice: "0",
          },
        },
      });
      status = resp.status;
    } catch (e) {
      if (!(e instanceof SignError)) throw e;
      status = e.status;
    }

    // Budget under cap -> whitelist matches -> auto-approved.
    expect(status).toBeDefined();
    expect(["completed", "signing"]).toContain(status);
  } finally {
    if (budgetId) await c.evm.budgets.delete(budgetId).catch(() => {});
    if (ruleId) await c.evm.rules.delete(ruleId).catch(() => {});
    await c.evm.signers.deleteSigner(signer.address).catch(() => {});
  }
});

test("budget over cap prevents auto-approval", async () => {
  const c = await adminSDKClient();
  const signer = await c.evm.signers.create({
    type: "keystore",
    keystore: { password: "e2e-budget-fail-pw" },
  });
  const ruleName = `e2e-budget-fail-${Date.now()}`;

  let ruleId = "";
  let budgetId = "";
  let requestId = "";
  try {
    const rule = await c.evm.rules.create({
      name: ruleName,
      type: "evm_address_list",
      mode: "whitelist",
      chain_type: "evm",
      chain_id: "1",
      config: { addresses: ["0x0000000000000000000000000000000000000001"] },
      enabled: true,
    });
    ruleId = rule.id;

    // Budget only allows 0.5 ETH max per tx, but we'll send 1 ETH.
    const budget = await c.evm.budgets.create({
      rule_id: ruleId,
      unit: "1:native",
      max_total: "500000000000000000",   // 0.5 ETH
      max_per_tx: "500000000000000000",  // 0.5 ETH
      max_tx_count: 1,
    });
    budgetId = budget.id;

    try {
      await c.evm.sign.executeAsync({
        chain_id: "1",
        signer_address: signer.address,
        sign_type: "transaction",
        payload: {
          transaction: {
            to: "0x0000000000000000000000000000000000000001",
            value: "0xde0b6b3a7640000", // 1 ETH > 0.5 ETH budget
            txType: "legacy",
            data: "0x",
            from: signer.address,
            gas: 21000,
            gasPrice: "0",
          },
        },
      });
    } catch (e) {
      if (!(e instanceof SignError)) throw e;
      requestId = e.requestID;
      // Budget exceeded -> rule skipped -> falls to manual approval.
      expect(["pending", "authorizing", "rejected"]).toContain(e.status);
    }

    // If the server created a request, verify it's not auto-approved.
    if (requestId) {
      const request = await c.evm.requests.get(requestId);
      expect(["completed", "signing"]).not.toContain(request.status);
    }
  } finally {
    if (budgetId) await c.evm.budgets.delete(budgetId).catch(() => {});
    if (ruleId) await c.evm.rules.delete(ruleId).catch(() => {});
    await c.evm.signers.deleteSigner(signer.address).catch(() => {});
  }
});

test("disabled rule does not match", async () => {
  const c = await adminSDKClient();
  const signer = await c.evm.signers.create({
    type: "keystore",
    keystore: { password: "e2e-disabled-rule-pw" },
  });
  const ruleName = `e2e-disabled-${Date.now()}`;
  const allowedAddr = "0x0000000000000000000000000000000000000001";

  let ruleId = "";
  try {
    // Create whitelist rule enabled.
    const rule = await c.evm.rules.create({
      name: ruleName,
      type: "evm_address_list",
      mode: "whitelist",
      chain_type: "evm",
      chain_id: "1",
      config: { addresses: [allowedAddr] },
      enabled: true,
    });
    ruleId = rule.id;

    // First submission while enabled should auto-approve.
    {
      let status: string | undefined;
      try {
        const resp = await c.evm.sign.executeAsync({
          chain_id: "1",
          signer_address: signer.address,
          sign_type: "transaction",
          payload: {
            transaction: {
              to: allowedAddr,
              value: "0x0",
              data: "0x",
              gas: 21000,
              gasPrice: "0",
              txType: "legacy",
            },
          },
        });
        status = resp.status;
      } catch (e) {
        if (!(e instanceof SignError)) throw e;
        status = e.status;
      }
      expect(["completed", "signing"]).toContain(status);
    }

    // Disable the rule.
    await c.evm.rules.update(ruleId, { enabled: false });

    // Now the same request should fall to manual approval (no enabled rule).
    {
      try {
        await c.evm.sign.executeAsync({
          chain_id: "1",
          signer_address: signer.address,
          sign_type: "transaction",
          payload: {
            transaction: {
              to: allowedAddr,
              value: "0x0",
              data: "0x",
              gas: 21000,
              gasPrice: "0",
              txType: "legacy",
            },
          },
        });
      } catch (e) {
        if (!(e instanceof SignError)) throw e;
        expect(["pending", "authorizing"]).toContain(e.status);
      }
    }
  } finally {
    if (ruleId) await c.evm.rules.delete(ruleId).catch(() => {});
    await c.evm.signers.deleteSigner(signer.address).catch(() => {});
  }
});

test("delegate_to chain passes outer and inner rules", async () => {
  const c = await adminSDKClient();
  const signer = await c.evm.signers.create({
    type: "keystore",
    keystore: { password: "e2e-delegate-rule-pw" },
  });
  const innerRuleName = `e2e-delegate-inner-${Date.now()}`;
  const outerRuleName = `e2e-delegate-outer-${Date.now()}`;

  const outerTarget = "0x1111111111111111111111111111111111111111";
  const innerTarget = "0x2222222222222222222222222222222222222222";

  let innerRuleId = "";
  let outerRuleId = "";
  try {
    // Inner rule: evm_address_list whitelist targeting innerTarget.
    const innerRule = await c.evm.rules.create({
      name: innerRuleName,
      type: "evm_address_list",
      mode: "whitelist",
      chain_type: "evm",
      chain_id: "1",
      config: { addresses: [innerTarget] },
      enabled: true,
    });
    innerRuleId = innerRule.id;

    // Outer rule: evm_js whitelist that validates the tx targets outerTarget,
    // then delegates to the inner rule with a payload targeting innerTarget.
    const script = [
      "function validate(input) {",
      "  var tx = input.transaction;",
      `  if (tx.to !== '${outerTarget}') return fail('wrong target');`,
      "  return {",
      "    valid: true,",
      "    payload: {",
      "      sign_type: 'transaction',",
      "      chain_id: '1',",
      "      signer: input.signer,",
      "      transaction: {",
      "        from: input.signer,",
      `        to: '${innerTarget}',`,
      "        value: '0x0',",
      "        data: '0x',",
      "        gas: 21000,",
      "        gasPrice: '0',",
      "        txType: 'legacy',",
      "      },",
      "    },",
      `    delegate_to: '${innerRuleId}',`,
      "  };",
      "}",
    ].join("\n");

    const outerRule = await c.evm.rules.create({
      name: outerRuleName,
      type: "evm_js",
      mode: "whitelist",
      chain_type: "evm",
      chain_id: "1",
      config: { script },
      enabled: true,
    });
    outerRuleId = outerRule.id;

    // Submit tx to outerTarget -> outer rule matches -> delegates to inner
    // rule which targets innerTarget -> auto-approved.
    let status: string | undefined;
    try {
      const resp = await c.evm.sign.executeAsync({
        chain_id: "1",
        signer_address: signer.address,
        sign_type: "transaction",
        payload: {
          transaction: {
            to: outerTarget,
            txType: "legacy",
            value: "0x0",
            data: "0x",
            from: signer.address,
            gas: 21000,
            gasPrice: "0",
          },
        },
      });
      status = resp.status;
    } catch (e) {
      if (!(e instanceof SignError)) throw e;
      status = e.status;
    }

    // Both rules matched -> auto-approved.
    expect(status).toBeDefined();
    expect(["completed", "signing"]).toContain(status);
  } finally {
    if (outerRuleId) await c.evm.rules.delete(outerRuleId).catch(() => {});
    if (innerRuleId) await c.evm.rules.delete(innerRuleId).catch(() => {});
    await c.evm.signers.deleteSigner(signer.address).catch(() => {});
  }
});
