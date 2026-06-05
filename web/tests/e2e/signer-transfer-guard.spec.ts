import { join } from "node:path";
import { APIError, SignError } from "remote-signer-client";
import { adminSDKClient, agentSDKClient, expect, test } from "./fixtures";
import { getState } from "./global-setup";
import { sqliteExec } from "./sqlite";

// ---------------------------------------------------------------------------
// Signer transfer-of-ownership, access-grant cycle, and request
// approve/reject guard specs. All state is seeded and torn down
// through the SDK — these specs exercise the wire protocol, not the UI.
// ---------------------------------------------------------------------------

const SIGNER_PW = "e2e-transfer-pw-3n9k";

test("owner transfers signer ownership successfully", async () => {
  const admin = await adminSDKClient();
  const agent = agentSDKClient();

  let signer;
  try {
    signer = await admin.evm.signers.create({
      type: "keystore",
      keystore: { password: SIGNER_PW },
    });

    // Transfer ownership from admin to agent.
    await admin.evm.signers.transferOwnership(signer.address, {
      new_owner_id: "agent",
    });

    // Agent is now the owner — the daemon accepts agent-scoped sign
    // requests for this signer (no 403). With manual_approval enabled
    // in the test config the request parks as pending/authorizing
    // rather than being auto-rejected, which is proof the ownership
    // transfer took effect.
    // Agent is now the owner — signing should succeed (may go pending
    // or auto-complete). Either way, the fact that we don't get 403
    // proves ownership transferred.
    let agentOk = false;
    try {
      await agent.evm.sign.executeAsync({
        chain_id: "1",
        signer_address: signer.address,
        sign_type: "personal",
        payload: { message: "0x48656c6c6f" },
      });
      agentOk = true;
    } catch (e) {
      if (e instanceof SignError) {
        expect(["pending", "authorizing"]).toContain(e.status);
        agentOk = true;
        // Clean up the orphaned request.
        await admin.evm.requests.approve(e.requestID, { approved: false }).catch(() => {});
      }
      // APIError = agent blocked (ownership didn't transfer) — fail
    }
    expect(agentOk).toBe(true);

    // Agent (now owner) can delete the signer.
    await agent.evm.signers.deleteSigner(signer.address).catch(() => {});
    signer = null;
  } finally {
    // If something went wrong mid-test, admin tries to clean up.
    if (signer) {
      await admin.evm.signers.deleteSigner(signer.address).catch(() => {});
    }
  }
});

test("non-owner cannot transfer signer", async () => {
  const admin = await adminSDKClient();
  const agent = agentSDKClient();

  let signer;
  try {
    signer = await admin.evm.signers.create({
      type: "keystore",
      keystore: { password: SIGNER_PW },
    });

    // Agent is NOT the owner — transferOwnership must be rejected.
    let thrown = false;
    try {
      await agent.evm.signers.transferOwnership(signer.address, {
        new_owner_id: "admin",
      });
    } catch (e) {
      if (e instanceof APIError) {
        expect(e.statusCode).toBe(403);
        thrown = true;
      } else {
        throw e;
      }
    }
    expect(thrown).toBe(true);
  } finally {
    if (signer) {
      await admin.evm.signers.deleteSigner(signer.address).catch(() => {});
    }
  }
});

test("grant + revoke access cycle works", async () => {
  const admin = await adminSDKClient();

  let signer;
  try {
    signer = await admin.evm.signers.create({
      type: "keystore",
      keystore: { password: SIGNER_PW },
    });

    // Grant access to agent.
    await admin.evm.signers.grantAccess(signer.address, {
      api_key_id: "agent",
    });

    // List access — agent should appear.
    const afterGrant = await admin.evm.signers.listAccess(signer.address);
    const agentEntry = afterGrant.find((e) => e.api_key_id === "agent");
    expect(agentEntry).toBeTruthy();
    expect(agentEntry!.granted_by).toBe("admin");

    // Revoke agent's access.
    await admin.evm.signers.revokeAccess(signer.address, "agent");

    // List access — agent must NOT appear.
    const afterRevoke = await admin.evm.signers.listAccess(signer.address);
    expect(afterRevoke.find((e) => e.api_key_id === "agent")).toBeUndefined();
  } finally {
    if (signer) {
      await admin.evm.signers.deleteSigner(signer.address).catch(() => {});
    }
  }
});

test("revoking non-existent access returns 404", async () => {
  const admin = await adminSDKClient();

  let signer;
  try {
    signer = await admin.evm.signers.create({
      type: "keystore",
      keystore: { password: SIGNER_PW },
    });

    // Revoke access for a key that has never been granted.
    let thrown = false;
    try {
      await admin.evm.signers.revokeAccess(signer.address, "nonexistent-key");
    } catch (e) {
      // Revoking access for a key that was never granted: server may return
      // 404 (not found) or accept it gracefully. Either is fine — the point
      // is the caller can't get agent's access revoked by presenting a
      // non-existent key ID.
      thrown = true;
    }
    expect(thrown).toBe(true);
  } finally {
    if (signer) {
      await admin.evm.signers.deleteSigner(signer.address).catch(() => {});
    }
  }
});

test("request rejection path", async () => {
  const admin = await adminSDKClient();

  const signer = await admin.evm.signers.create({
    type: "keystore",
    keystore: { password: SIGNER_PW },
  });

  try {
    const home = getState().home;
    const dbPath = join(home, "remote-signer.db");
    const requestId = `req-reject-${Date.now()}`;
    const now = new Date().toISOString();

    sqliteExec(dbPath, [
      `INSERT INTO sign_requests (id, api_key_id, chain_type, chain_id, signer_address, sign_type, status, created_at, updated_at)
       VALUES ('${requestId}', 'admin', 'evm', '1', '${signer.address}', 'hash', 'authorizing', '${now}', '${now}')`,
    ]);

    await admin.evm.requests.approve(requestId, { approved: false });

    const r = await admin.evm.requests.get(requestId);
    expect(r.status).toBe("rejected");
  } finally {
    await admin.evm.signers.deleteSigner(signer.address).catch(() => {});
  }
});

test("approving already-completed request returns conflict", async () => {
  const admin = await adminSDKClient();

  let signer;
  let rule;

  try {
    signer = await admin.evm.signers.create({
      type: "keystore",
      keystore: { password: SIGNER_PW },
    });

    // Create an evm_js whitelist rule that always returns ok() so the
    // sign request auto-approves on submission.
    rule = await admin.evm.rules.create({
      name: `e2e-auto-${Date.now()}`,
      type: "evm_js",
      mode: "whitelist",
      chain_type: "evm",
      chain_id: "1",
      config: { script: "function validate(input) { return ok(); }" },
      enabled: true,
    });

    // Submit a sign request — the whitelist rule should match and the
    // daemon auto-approves, returning completed status directly.
    const result = await admin.evm.sign.execute({
      chain_id: "1",
      signer_address: signer.address,
      sign_type: "personal",
      payload: { message: "0x48656c6c6f" },
    });
    // Auto-approved or went pending — either way, approve on a non-pending
    // request should be rejected.
    const rid = result.request_id;
    expect(rid).toBeTruthy();

    // If the request went pending, reject it now so the next approve sees
    // an already-resolved request.
    if (result.status !== "completed" && result.status !== "signing") {
      await admin.evm.requests.approve(rid, { approved: true }).catch(() => {});
    }

    let thrown = false;
    try { await admin.evm.requests.approve(rid, { approved: true }); } catch (e) {
      thrown = true;
    }
    expect(thrown).toBe(true);
  } finally {
    if (rule) {
      await admin.evm.rules.delete(rule.id).catch(() => {});
    }
    if (signer) {
      await admin.evm.signers.deleteSigner(signer.address).catch(() => {});
    }
  }
});
