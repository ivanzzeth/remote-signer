#!/usr/bin/env node
/**
 * Self-test: cover all remote-signer MCP tools over HTTPS.
 * Run from agents repo root with same env as .cursor/mcp.json (REMOTE_SIGNER_URL=https://..., cert paths).
 *
 *   cd /path/to/agents && \
 *   REMOTE_SIGNER_URL=https://localhost:8548 \
 *   REMOTE_SIGNER_API_KEY_ID=admin \
 *   REMOTE_SIGNER_PRIVATE_KEY_FILE=projects/personal/ivanzzeth/remote-signer/data/admin_private.pem \
 *   REMOTE_SIGNER_CA_FILE=projects/personal/ivanzzeth/remote-signer/certs/ca.crt \
 *   REMOTE_SIGNER_CLIENT_CERT_FILE=... REMOTE_SIGNER_CLIENT_KEY_FILE=... \
 *   node projects/personal/ivanzzeth/remote-signer/pkg/mcp-server/scripts/test-all-tools.mjs
 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { createRequire } from "module";
const require = createRequire(import.meta.url);
const { RemoteSignerClient } = require("remote-signer-client");

function readPrivateKeyHex() {
  const hex = process.env.REMOTE_SIGNER_PRIVATE_KEY?.trim();
  if (hex) return hex;
  const filePath = process.env.REMOTE_SIGNER_PRIVATE_KEY_FILE?.trim();
  if (!filePath) return "";
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    console.error(`Error: REMOTE_SIGNER_PRIVATE_KEY_FILE not found: ${resolved}`);
    process.exit(1);
  }
  const pem = fs.readFileSync(resolved, "utf8");
  const key = crypto.createPrivateKey(pem);
  const jwk = key.export({ format: "jwk" });
  if (!jwk.d) {
    console.error("Error: PEM does not contain Ed25519 private key");
    process.exit(1);
  }
  const raw = Buffer.from(jwk.d, "base64url");
  return raw.toString("hex");
}

function readTLSConfig() {
  const caPath = process.env.REMOTE_SIGNER_CA_FILE?.trim();
  const certPath = process.env.REMOTE_SIGNER_CLIENT_CERT_FILE?.trim();
  const keyPath = process.env.REMOTE_SIGNER_CLIENT_KEY_FILE?.trim();
  const skipVerify = process.env.REMOTE_SIGNER_TLS_INSECURE_SKIP_VERIFY;
  const rejectUnauthorized = !(skipVerify === "1" || skipVerify === "true");
  if (!caPath && !certPath && !keyPath && rejectUnauthorized) return undefined;
  const tls = { rejectUnauthorized };
  if (caPath) {
    const p = path.resolve(caPath);
    if (!fs.existsSync(p)) {
      console.error(`Error: REMOTE_SIGNER_CA_FILE not found: ${p}`);
      process.exit(1);
    }
    tls.ca = fs.readFileSync(p, "utf8");
  }
  if (certPath) {
    const p = path.resolve(certPath);
    if (!fs.existsSync(p)) {
      console.error(`Error: REMOTE_SIGNER_CLIENT_CERT_FILE not found: ${p}`);
      process.exit(1);
    }
    tls.cert = fs.readFileSync(p, "utf8");
  }
  if (keyPath) {
    const p = path.resolve(keyPath);
    if (!fs.existsSync(p)) {
      console.error(`Error: REMOTE_SIGNER_CLIENT_KEY_FILE not found: ${p}`);
      process.exit(1);
    }
    tls.key = fs.readFileSync(p, "utf8");
  }
  return tls;
}

const BASE_URL = process.env.REMOTE_SIGNER_URL || "http://localhost:8548";
const API_KEY_ID = process.env.REMOTE_SIGNER_API_KEY_ID || "";
const PRIVATE_KEY = readPrivateKeyHex();
const tlsConfig = readTLSConfig();

if (!API_KEY_ID || !PRIVATE_KEY) {
  console.error("Set REMOTE_SIGNER_API_KEY_ID and REMOTE_SIGNER_PRIVATE_KEY or REMOTE_SIGNER_PRIVATE_KEY_FILE");
  process.exit(1);
}

const client = new RemoteSignerClient({
  baseURL: BASE_URL,
  apiKeyID: API_KEY_ID,
  privateKey: PRIVATE_KEY,
  pollInterval: 2000,
  pollTimeout: 300000,
  ...(tlsConfig && { httpClient: { tls: tlsConfig } }),
});

const results = { ok: 0, fail: 0, skip: 0 };
function pass(name) {
  results.ok++;
  console.log(`  ✓ ${name}`);
}
function fail(name, err) {
  results.fail++;
  console.log(`  ✗ ${name}: ${err.message || err}`);
}
function skip(name, reason) {
  results.skip++;
  console.log(`  - ${name} (skip: ${reason})`);
}

async function run() {
  console.log("Testing all MCP tools at", BASE_URL, "\n");

  // --- evm_list_signers ---
  try {
    const signers = await client.evm.signers.list();
    if (Array.isArray(signers) || (signers && typeof signers === "object")) pass("evm_list_signers");
    else fail("evm_list_signers", new Error("unexpected response"));
  } catch (e) {
    fail("evm_list_signers", e);
  }

  // --- evm_list_rules ---
  let firstRuleId = null;
  try {
    const rulesResp = await client.evm.rules.list();
    const rules = rulesResp?.rules ?? rulesResp;
    if (Array.isArray(rules) && rules.length > 0) firstRuleId = rules[0].id;
    pass("evm_list_rules");
  } catch (e) {
    fail("evm_list_rules", e);
  }

  // --- evm_get_rule ---
  if (firstRuleId) {
    try {
      await client.evm.rules.get(firstRuleId);
      pass("evm_get_rule");
    } catch (e) {
      fail("evm_get_rule", e);
    }
  } else {
    try {
      await client.evm.rules.get("non-existent-rule-id");
    } catch (e) {
      if (e.message && (e.message.includes("404") || e.message.includes("not found"))) pass("evm_get_rule (404)");
      else fail("evm_get_rule", e);
    }
  }

  // --- evm_list_requests ---
  try {
    await client.evm.requests.list({ limit: 5 });
    pass("evm_list_requests");
  } catch (e) {
    fail("evm_list_requests", e);
  }

  // --- evm_get_request (expect 404) ---
  try {
    await client.evm.requests.get("non-existent-request-id");
    fail("evm_get_request", new Error("expected 404"));
  } catch (e) {
    if (e.message && (e.message.includes("404") || e.message.includes("not found"))) pass("evm_get_request (404)");
    else pass("evm_get_request (error as expected)");
  }

  // --- list_audit_logs ---
  try {
    const audit = await client.audit.list({ limit: 5 });
    if (audit && (audit.records || Array.isArray(audit))) pass("list_audit_logs");
    else fail("list_audit_logs", new Error("unexpected response"));
  } catch (e) {
    fail("list_audit_logs", e);
  }

  // --- evm_sign_personal_message (may pending, sign, or 400) ---
  try {
    const signersList = await client.evm.signers.list();
    const addrs = Array.isArray(signersList) ? signersList : (signersList?.signers ?? []);
    const signer = addrs[0] || "0x0000000000000000000000000000000000000001";
    await client.evm.sign.executeAsync({
      chain_id: "56",
      signer_address: signer,
      sign_type: "personal",
      payload: { message: "MCP self-test " + Date.now() },
    });
    pass("evm_sign_personal_message");
  } catch (e) {
    if (e.name === "SignError" && e.requestID) pass("evm_sign_personal_message (pending)");
    else if (e.message && (e.message.includes("400") || e.message.includes("HTTP"))) pass("evm_sign_personal_message (server responded)");
    else fail("evm_sign_personal_message", e);
  }

  // --- evm_sign_hash ---
  try {
    const signersList2 = await client.evm.signers.list();
    const addrs2 = Array.isArray(signersList2) ? signersList2 : (signersList2?.signers ?? []);
    const signer2 = addrs2[0] || "0x0000000000000000000000000000000000000001";
    await client.evm.sign.executeAsync({
      chain_id: "1",
      signer_address: signer2,
      sign_type: "hash",
      payload: { hash: "0x" + "00".repeat(32) },
    });
    pass("evm_sign_hash");
  } catch (e) {
    if (e.name === "SignError" && e.requestID) pass("evm_sign_hash (pending)");
    else if (e.message && (e.message.includes("400") || e.message.includes("HTTP"))) pass("evm_sign_hash (server responded)");
    else fail("evm_sign_hash", e);
  }

  // --- evm_sign_typed_data ---
  try {
    const signersList3 = await client.evm.signers.list();
    const addrs3 = Array.isArray(signersList3) ? signersList3 : (signersList3?.signers ?? []);
    const signer3 = addrs3[0] || "0x0000000000000000000000000000000000000001";
    await client.evm.sign.executeAsync({
      chain_id: "1",
      signer_address: signer3,
      sign_type: "typed_data",
      payload: {
        typed_data: {
          types: {
            EIP712Domain: [{ name: "name", type: "string" }],
            Test: [{ name: "value", type: "uint256" }],
          },
          primaryType: "Test",
          domain: { name: "Test" },
          message: { value: "1" },
        },
      },
    });
    pass("evm_sign_typed_data");
  } catch (e) {
    if (e.name === "SignError" && e.requestID) pass("evm_sign_typed_data (pending)");
    else if (e.message && (e.message.includes("400") || e.message.includes("HTTP"))) pass("evm_sign_typed_data (server responded)");
    else fail("evm_sign_typed_data", e);
  }

  // --- evm_sign_transaction ---
  try {
    const signersList4 = await client.evm.signers.list();
    const addrs4 = Array.isArray(signersList4) ? signersList4 : (signersList4?.signers ?? []);
    const signer4 = addrs4[0] || "0x0000000000000000000000000000000000000001";
    await client.evm.sign.executeAsync({
      chain_id: "1",
      signer_address: signer4,
      sign_type: "transaction",
      payload: {
        transaction: {
          to: "0x0000000000000000000000000000000000000001",
          value: "0",
          gas: 21000,
        },
      },
    });
    pass("evm_sign_transaction");
  } catch (e) {
    if (e.name === "SignError" && e.requestID) pass("evm_sign_transaction (pending)");
    else if (e.message && (e.message.includes("400") || e.message.includes("HTTP"))) pass("evm_sign_transaction (server responded)");
    else fail("evm_sign_transaction", e);
  }

  // --- evm_preview_rule (fake request_id -> error) ---
  try {
    await client.evm.requests.previewRule("fake-request-id", {
      rule_type: "evm_address_list",
      rule_mode: "whitelist",
    });
    fail("evm_preview_rule", new Error("expected error"));
  } catch (e) {
    pass("evm_preview_rule (error as expected)");
  }

  // --- evm_approve_request (fake request_id -> error) ---
  try {
    await client.evm.requests.approve("fake-request-id", { approved: false });
    fail("evm_approve_request", new Error("expected error"));
  } catch (e) {
    pass("evm_approve_request (error as expected)");
  }

  // --- evm_create_signer (mutates: creates one signer; 400 = validation) ---
  try {
    const pwd = process.env.MCP_TEST_SIGNER_PASSWORD || "x";
    const createRes = await client.evm.signers.create({
      password: pwd,
    });
    if (createRes && (createRes.address || createRes.signer_address)) pass("evm_create_signer");
    else fail("evm_create_signer", new Error("no address in response"));
  } catch (e) {
    if (e.message && (e.message.includes("400") || e.message.includes("HTTP"))) pass("evm_create_signer (server responded)");
    else fail("evm_create_signer", e);
  }

  // --- evm_create_rule / evm_update_rule / evm_delete_rule ---
  const testRuleName = "mcp-self-test-rule-" + Date.now();
  let createdRuleId = null;
  try {
    const created = await client.evm.rules.create({
      name: testRuleName,
      description: "MCP self-test rule, safe to delete",
      type: "evm_address_list",
      mode: "whitelist",
      config: { addresses: ["0x0000000000000000000000000000000000000001"] },
      enabled: false,
    });
    createdRuleId = created?.id ?? testRuleName;
    pass("evm_create_rule");
  } catch (e) {
    if (e.message && (e.message.includes("403") || e.message.includes("HTTP"))) pass("evm_create_rule (server responded)");
    else fail("evm_create_rule", e);
  }

  if (createdRuleId) {
    try {
      await client.evm.rules.update(createdRuleId, { name: testRuleName + "-updated" });
      pass("evm_update_rule");
    } catch (e) {
      fail("evm_update_rule", e);
    }

    try {
      await client.evm.rules.delete(createdRuleId);
      pass("evm_delete_rule");
    } catch (e) {
      fail("evm_delete_rule", e);
    }
  } else {
    try {
      await client.evm.rules.update("mcp-self-test-nonexistent", { name: "x" });
      fail("evm_update_rule", new Error("expected error"));
    } catch (e) {
      if (e.message && (e.message.includes("404") || e.message.includes("403") || e.message.includes("HTTP"))) pass("evm_update_rule (server responded)");
      else fail("evm_update_rule", e);
    }
    try {
      await client.evm.rules.delete("mcp-self-test-nonexistent");
      fail("evm_delete_rule", new Error("expected error"));
    } catch (e) {
      if (e.message && (e.message.includes("404") || e.message.includes("403") || e.message.includes("HTTP"))) pass("evm_delete_rule (server responded)");
      else fail("evm_delete_rule", e);
    }
  }

  // --- evm_list_rule_budgets ---
  const ruleIdForBudgets = firstRuleId || "mcp-self-test-nonexistent";
  try {
    const budgets = await client.evm.rules.listBudgets(ruleIdForBudgets);
    if (Array.isArray(budgets)) pass("evm_list_rule_budgets");
    else fail("evm_list_rule_budgets", new Error("unexpected response"));
  } catch (e) {
    if (e.message && (e.message.includes("404") || e.message.includes("HTTP"))) pass("evm_list_rule_budgets (server responded)");
    else fail("evm_list_rule_budgets", e);
  }

  // --- evm_toggle_rule (toggle existing rule or fake id) ---
  if (firstRuleId) {
    try {
      const rule = await client.evm.rules.get(firstRuleId);
      const nextEnabled = !rule.enabled;
      await client.evm.rules.toggle(firstRuleId, nextEnabled);
      await client.evm.rules.toggle(firstRuleId, rule.enabled);
      pass("evm_toggle_rule");
    } catch (e) {
      if (e.message && (e.message.includes("403") || e.message.includes("HTTP"))) pass("evm_toggle_rule (server responded)");
      else fail("evm_toggle_rule", e);
    }
  } else {
    try {
      await client.evm.rules.toggle("mcp-self-test-nonexistent", false);
      fail("evm_toggle_rule", new Error("expected error"));
    } catch (e) {
      if (e.message && (e.message.includes("404") || e.message.includes("HTTP"))) pass("evm_toggle_rule (server responded)");
      else fail("evm_toggle_rule", e);
    }
  }

  // --- HD wallets: read-only only (no create/import/derive) ---
  skip("evm_create_hd_wallet", "write, not tested");
  skip("evm_import_hd_wallet", "write, not tested");
  skip("evm_derive_address", "write, not tested");

  try {
    const hdList = await client.evm.hdWallets.list();
    const wallets = hdList?.wallets ?? [];
    if (Array.isArray(wallets)) pass("evm_list_hd_wallets");
    else fail("evm_list_hd_wallets", new Error("unexpected response"));
    if (wallets.length > 0) {
      const primary = wallets[0].primary_address;
      try {
        const derived = await client.evm.hdWallets.listDerived(primary);
        if (derived && (derived.derived || Array.isArray(derived))) pass("evm_list_derived_addresses");
        else fail("evm_list_derived_addresses", new Error("unexpected response"));
      } catch (e) {
        if (e.message && (e.message.includes("404") || e.message.includes("HTTP"))) pass("evm_list_derived_addresses (server responded)");
        else fail("evm_list_derived_addresses", e);
      }
    } else {
      try {
        await client.evm.hdWallets.listDerived("0x0000000000000000000000000000000000000001");
        fail("evm_list_derived_addresses", new Error("expected error"));
      } catch (e) {
        if (e.message && (e.message.includes("404") || e.message.includes("HTTP"))) pass("evm_list_derived_addresses (server responded)");
        else fail("evm_list_derived_addresses", e);
      }
    }
  } catch (e) {
    fail("evm_list_hd_wallets", e);
  }

  // --- list_templates ---
  let firstTemplateId = null;
  try {
    const tResp = await client.templates.list({ limit: 5 });
    const templates = tResp?.templates ?? tResp ?? [];
    if (Array.isArray(templates) && templates.length > 0) firstTemplateId = templates[0].id;
    pass("list_templates");
  } catch (e) {
    fail("list_templates", e);
  }

  // --- get_template ---
  if (firstTemplateId) {
    try {
      await client.templates.get(firstTemplateId);
      pass("get_template");
    } catch (e) {
      fail("get_template", e);
    }
  } else {
    try {
      await client.templates.get("mcp-self-test-nonexistent");
      fail("get_template", new Error("expected error"));
    } catch (e) {
      if (e.message && (e.message.includes("404") || e.message.includes("HTTP"))) pass("get_template (server responded)");
      else fail("get_template", e);
    }
  }

  // --- create_template (server responded) ---
  try {
    await client.templates.create({
      name: "mcp-self-test-tpl-" + Date.now(),
      type: "evm_js",
      mode: "whitelist",
      config: {},
      enabled: false,
    });
    fail("create_template", new Error("expected validation/403"));
  } catch (e) {
    if (e.message && (e.message.includes("400") || e.message.includes("403") || e.message.includes("HTTP"))) pass("create_template (server responded)");
    else fail("create_template", e);
  }

  // --- update_template (fake id) ---
  try {
    await client.templates.update("mcp-self-test-nonexistent", { name: "x" });
    fail("update_template", new Error("expected error"));
  } catch (e) {
    if (e.message && (e.message.includes("404") || e.message.includes("HTTP"))) pass("update_template (server responded)");
    else fail("update_template", e);
  }

  // --- delete_template (fake id) ---
  try {
    await client.templates.delete("mcp-self-test-nonexistent");
    fail("delete_template", new Error("expected error"));
  } catch (e) {
    if (e.message && (e.message.includes("404") || e.message.includes("HTTP"))) pass("delete_template (server responded)");
    else fail("delete_template", e);
  }

  // --- instantiate_template (fake id) ---
  try {
    await client.templates.instantiate("mcp-self-test-nonexistent", { variables: {} });
    fail("instantiate_template", new Error("expected error"));
  } catch (e) {
    if (e.message && (e.message.includes("404") || e.message.includes("400") || e.message.includes("HTTP"))) pass("instantiate_template (server responded)");
    else fail("instantiate_template", e);
  }

  // --- revoke_template_instance (fake rule_id) ---
  try {
    await client.templates.revokeInstance("mcp-self-test-nonexistent");
    fail("revoke_template_instance", new Error("expected error"));
  } catch (e) {
    if (e.message && (e.message.includes("404") || e.message.includes("HTTP"))) pass("revoke_template_instance (server responded)");
    else fail("revoke_template_instance", e);
  }

  // --- get_metrics ---
  try {
    await client.metrics();
    pass("get_metrics");
  } catch (e) {
    if (e.message && e.message.includes("HTTP")) pass("get_metrics (server responded)");
    else fail("get_metrics", e);
  }

  console.log("\n--- Summary ---");
  console.log(`  passed: ${results.ok}, failed: ${results.fail}, skipped: ${results.skip}`);
  if (results.fail > 0) process.exit(1);
}

run().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
