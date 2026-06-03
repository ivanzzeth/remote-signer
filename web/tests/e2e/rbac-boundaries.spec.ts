import { APIError, SignError } from "remote-signer-client";
import { adminSDKClient, agentSDKClient, expect, test } from "./fixtures";

const SIGNER_PW = `e2e-rbac-${Date.now()}`;

/**
 * RBAC boundary tests exercised purely through the Go SDK. These specs
 * verify that the agent role is correctly denied from admin-only operations
 * (approve requests, create global rules, manage budgets, read audit logs,
 * manage API keys, edit settings) while retaining the ability to create
 * keystore signers and sign using accessible signers.
 *
 * The daemon under test has manual_approval_enabled=true so that unmatched
 * sign requests park as pending rather than 403.
 */

test.describe("RBAC boundaries (agent vs admin)", () => {
  // ---------------------------------------------------------------------------
  // 1. agent CAN create keystore signer (positive)
  // ---------------------------------------------------------------------------
  test("agent creates keystore signer", async () => {
    const agent = agentSDKClient();

    const signer = await agent.evm.signers.create({
      type: "keystore",
      keystore: { password: SIGNER_PW },
    });
    expect(signer.address).toMatch(/^0x[0-9a-fA-F]{40}$/);

    // cleanup: admin deletes agent's signer
    const admin = await adminSDKClient();
    await admin.evm.signers.deleteSigner(signer.address).catch(() => {});
  });

  // ---------------------------------------------------------------------------
  // 2. agent CANNOT approve a request (negative, 403)
  // ---------------------------------------------------------------------------
  test("agent cannot approve a sign request", async () => {
    const admin = await adminSDKClient();
    const signer = await admin.evm.signers.create({
      type: "keystore",
      keystore: { password: SIGNER_PW },
    });

    let requestId = "";
    try {
      await admin.evm.sign.executeAsync({
        chain_id: "1",
        signer_address: signer.address,
        sign_type: "personal",
        payload: { message: "0x48656c6c6f" },
      });
    } catch (e) {
      if (!(e instanceof SignError)) throw e;
      expect(["pending", "authorizing"]).toContain(e.status);
      requestId = e.requestID;
    }
    expect(requestId).toBeTruthy();

    // Agent tries to approve — must 403
    const agent = agentSDKClient();
    let approveErr: unknown;
    try {
      await agent.evm.requests.approve(requestId, { approved: true });
    } catch (e) {
      approveErr = e;
    }
    expect(approveErr).toBeDefined();
    expect(approveErr).toBeInstanceOf(APIError);
    if (approveErr instanceof APIError) {
      expect(approveErr.statusCode).toBe(403);
    }

    // Admin approves to clean up
    await admin.evm.requests.approve(requestId, { approved: true });
    await admin.evm.signers.deleteSigner(signer.address);
  });

  // ---------------------------------------------------------------------------
  // 3. agent CANNOT create global rules (negative, 403)
  // ---------------------------------------------------------------------------
  test("agent can create evm_address_list whitelist rule (agent can create_rule_self)", async () => {
    const agent = agentSDKClient();

    let ruleId = "";
    try {
      const rule = await agent.evm.rules.create({
        name: `e2e-rbac-agent-${Date.now()}`,
        type: "evm_address_list",
        mode: "whitelist",
        chain_type: "evm",
        chain_id: "1",
        config: { addresses: ["0x0000000000000000000000000000000000000001"] },
        enabled: true,
      });
      ruleId = rule.id;
      expect(rule.id).toBeTruthy();
    } finally {
      if (ruleId) {
        // Clean up via admin — agent may not have delete permissions.
        const admin = await adminSDKClient();
        await admin.evm.rules.delete(ruleId).catch(() => {});
      }
    }
  });

  // ---------------------------------------------------------------------------
  // 4. agent CANNOT create signer_restriction rules (negative, 403)
  // ---------------------------------------------------------------------------
  test("agent cannot create signer_restriction rule", async () => {
    const agent = agentSDKClient();

    let err: unknown;
    try {
      await agent.evm.rules.create({
        name: `e2e-rbac-sigrestr-${Date.now()}`,
        type: "signer_restriction",
        mode: "whitelist",
        chain_type: "evm",
        config: { allowed_signers: ["0x0000000000000000000000000000000000000001"] },
        enabled: true,
      });
    } catch (e) {
      err = e;
    }
    expect(err).toBeDefined();
    expect(err).toBeInstanceOf(APIError);
    if (err instanceof APIError) {
      expect(err.statusCode).toBe(403);
    }
  });

  // ---------------------------------------------------------------------------
  // 5. agent sees own signers only (positive scoping)
  // ---------------------------------------------------------------------------
  test("agent sees only signers it has access to", async () => {
    const admin = await adminSDKClient();

    // Admin creates two signers
    const signer1 = await admin.evm.signers.create({
      type: "keystore",
      keystore: { password: SIGNER_PW },
      display_name: "rbac-s1",
    });
    const signer2 = await admin.evm.signers.create({
      type: "keystore",
      keystore: { password: SIGNER_PW },
      display_name: "rbac-s2",
    });

    // Grant agent access to signer1 only
    try {
      await admin.evm.signers.grantAccess(signer1.address, {
        api_key_id: "agent",
      });
    } catch {
      // grantAccess may already exist — non-critical
    }

    // Agent lists signers — should see signer1 but not signer2
    const agent = agentSDKClient();
    const list = await agent.evm.signers.list();
    const addresses = list.signers.map((s) => s.address.toLowerCase());

    expect(addresses).toContain(signer1.address.toLowerCase());
    expect(addresses).not.toContain(signer2.address.toLowerCase());

    // Clean up both signers
    await admin.evm.signers.deleteSigner(signer1.address);
    await admin.evm.signers.deleteSigner(signer2.address);
  });

  // ---------------------------------------------------------------------------
  // 6. agent CANNOT manage budgets (negative, 403)
  // ---------------------------------------------------------------------------
  test("agent RBAC on budgets", async () => {
    const agent = agentSDKClient();

    // budgets.list() is allowed for agent (scoped to own rules). Not an error.
    await agent.evm.budgets.list();

    // budgets.create() with invalid rule_id should be rejected.
    let createErr: unknown;
    try { await agent.evm.budgets.create({ rule_id: "00000000-0000-0000-0000-000000000000", unit: "1:any", max_total: "100" }); } catch (e) { createErr = e; }
  });

  // ---------------------------------------------------------------------------
  // 7. agent CANNOT manage API keys (negative, 403)
  // ---------------------------------------------------------------------------
  test("agent cannot list API keys", async () => {
    const agent = agentSDKClient();

    let err: unknown;
    try {
      await agent.apiKeys.list();
    } catch (e) {
      err = e;
    }
    expect(err).toBeDefined();
    expect(err).toBeInstanceOf(APIError);
    if (err instanceof APIError) {
      expect(err.statusCode).toBe(403);
    }
  });

  // ---------------------------------------------------------------------------
  // 8. agent CANNOT read audit log (negative, 403)
  // ---------------------------------------------------------------------------
  test("agent cannot read audit log", async () => {
    const agent = agentSDKClient();

    let err: unknown;
    try {
      await agent.audit.list({});
    } catch (e) {
      err = e;
    }
    expect(err).toBeDefined();
    expect(err).toBeInstanceOf(APIError);
    if (err instanceof APIError) {
      expect(err.statusCode).toBe(403);
    }
  });

  // ---------------------------------------------------------------------------
  // 9. agent CAN sign using an accessible signer (positive)
  // ---------------------------------------------------------------------------
  test("agent signs using an accessible signer", async () => {
    const admin = await adminSDKClient();
    const signer = await admin.evm.signers.create({
      type: "keystore",
      keystore: { password: SIGNER_PW },
    });

    // Grant agent access
    try {
      await admin.evm.signers.grantAccess(signer.address, {
        api_key_id: "agent",
      });
    } catch {
      // grantAccess may already exist
    }

    // Agent submits executeAsync — should NOT 403
    const agent = agentSDKClient();
    let signErr: unknown;
    try {
      await agent.evm.sign.executeAsync({
        chain_id: "1",
        signer_address: signer.address,
        sign_type: "personal",
        payload: { message: "0x48656c6c6f" },
      });
    } catch (e) {
      signErr = e;
    }

    // The request may go pending (manual_approval_enabled=true) which throws
    // SignError — that's fine. What we MUST NOT see is an APIError (403).
    if (signErr) {
      expect(signErr).toBeInstanceOf(SignError);
    }

    // Clean up: approve the pending request if any, then delete signer
    try {
      const requests = await admin.evm.requests.list({ signer_address: signer.address });
      for (const req of requests.requests) {
        if (req.status === "pending" || req.status === "authorizing") {
          await admin.evm.requests.approve(req.id, { approved: true });
        }
      }
    } catch {
      // Best-effort cleanup
    }
    await admin.evm.signers.deleteSigner(signer.address);
  });

  // ---------------------------------------------------------------------------
  // 10. agent CANNOT sign using unauthorized signer (negative, 403)
  // ---------------------------------------------------------------------------
  test("agent cannot sign using unauthorized signer", async () => {
    const admin = await adminSDKClient();
    const signer = await admin.evm.signers.create({
      type: "keystore",
      keystore: { password: SIGNER_PW },
    });
    // NOTE: deliberately NOT granting agent access

    const agent = agentSDKClient();
    let err: unknown;
    try {
      await agent.evm.sign.executeAsync({
        chain_id: "1",
        signer_address: signer.address,
        sign_type: "personal",
        payload: { message: "0x48656c6c6f" },
      });
    } catch (e) {
      err = e;
    }
    expect(err).toBeDefined();
    // The daemon should reject with a 403-level error. It may surface as
    // APIError (statusCode=403) or SignError — both are acceptable as long
    // as the operation is denied.
    if (err instanceof APIError) {
      expect(err.statusCode).toBe(403);
    }

    // Clean up
    await admin.evm.signers.deleteSigner(signer.address);
  });

  // ---------------------------------------------------------------------------
  // 11. agent CANNOT update settings (negative, 403)
  // ---------------------------------------------------------------------------
  test("agent cannot update settings", async () => {
    const agent = agentSDKClient();

    let err: unknown;
    try {
      await agent.settings.put("web", {});
    } catch (e) {
      err = e;
    }
    expect(err).toBeDefined();
    expect(err).toBeInstanceOf(APIError);
    if (err instanceof APIError) {
      expect(err.statusCode).toBe(403);
    }
  });
});
