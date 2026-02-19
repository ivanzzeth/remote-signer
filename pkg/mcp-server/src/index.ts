#!/usr/bin/env node

/**
 * Remote Signer MCP Server
 *
 * Provides MCP tools for interacting with the remote-signer service.
 * Uses the @remote-signer/client TypeScript SDK for authentication and API calls.
 *
 * Each tool has explicit, well-typed parameters so that LLMs can call them
 * without ambiguity.  EVM tools are prefixed with "evm_" for namespace clarity
 * and future multi-chain extensibility (e.g. solana_sign_message).
 *
 * Configuration via environment variables:
 *   REMOTE_SIGNER_URL        - Base URL of the remote-signer service (default: http://localhost:8548)
 *   REMOTE_SIGNER_API_KEY_ID - API key ID for authentication
 *   REMOTE_SIGNER_PRIVATE_KEY - Ed25519 private key (hex) for request signing
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { RemoteSignerClient } from "@remote-signer/client";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const BASE_URL = process.env.REMOTE_SIGNER_URL || "http://localhost:8548";
const API_KEY_ID = process.env.REMOTE_SIGNER_API_KEY_ID || "";
const PRIVATE_KEY = process.env.REMOTE_SIGNER_PRIVATE_KEY || "";

if (!API_KEY_ID || !PRIVATE_KEY) {
  console.error(
    "Error: REMOTE_SIGNER_API_KEY_ID and REMOTE_SIGNER_PRIVATE_KEY environment variables are required."
  );
  console.error("Set the following environment variables:");
  console.error("  REMOTE_SIGNER_API_KEY_ID   – your API key ID");
  console.error("  REMOTE_SIGNER_PRIVATE_KEY  – Ed25519 private key (hex)");
  console.error("See .mcp.json.example for a configuration template.");
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Client & Server instances
// ---------------------------------------------------------------------------

const client = new RemoteSignerClient({
  baseURL: BASE_URL,
  apiKeyID: API_KEY_ID,
  privateKey: PRIVATE_KEY,
  useNonce: true,
  pollInterval: 2000,
  pollTimeout: 300000,
});

const server = new McpServer({
  name: "remote-signer",
  version: "1.0.0",
});

// ---------------------------------------------------------------------------
// Helper: format result as MCP text content
// ---------------------------------------------------------------------------

function ok(data: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}

function err(error: unknown) {
  const message =
    error instanceof Error ? error.message : String(error);
  return {
    content: [{ type: "text" as const, text: `Error: ${message}` }],
    isError: true,
  };
}

// ===========================================================================
// Tool: evm_list_signers   –  GET /api/v1/evm/signers
// ===========================================================================

server.registerTool(
  "evm_list_signers",
  {
    title: "List EVM Signers",
    description:
      "List all available EVM signer addresses managed by the remote-signer service",
    inputSchema: {},
  },
  async () => {
    try {
      const signers = await client.listSigners();
      return ok(signers);
    } catch (error) {
      return err(error);
    }
  }
);

// ===========================================================================
// Tool: evm_create_signer  –  POST /api/v1/evm/signers
// ===========================================================================

server.registerTool(
  "evm_create_signer",
  {
    title: "Create EVM Signer",
    description:
      "Create a new EVM keystore signer (requires admin API key). " +
      "Generates a new key pair and stores it in the configured keystore directory.",
    inputSchema: {
      password: z
        .string()
        .describe("Password to encrypt the new keystore file"),
    },
  },
  async ({ password }) => {
    try {
      const response = await client.createSigner({ password });
      return ok(response);
    } catch (error) {
      return err(error);
    }
  }
);

// ---------------------------------------------------------------------------
// Helper: handle sign errors (pending approval → structured info, not error)
// ---------------------------------------------------------------------------

function handleSignResult(error: any) {
  if (error.name === "SignError" && error.requestID) {
    return ok({
      status: error.status,
      request_id: error.requestID,
      message: error.message,
      hint: "Use evm_get_request to check status, or evm_approve_request to approve.",
    });
  }
  return err(error);
}

// ===========================================================================
// Tool: evm_sign_personal_message  –  POST /api/v1/evm/sign (sign_type=personal)
// ===========================================================================

server.registerTool(
  "evm_sign_personal_message",
  {
    title: "Sign Personal Message",
    description:
      "Sign a personal message (eth_sign / personal_sign). Returns the ECDSA signature. " +
      "If the request requires manual approval, returns a pending status with request_id.",
    inputSchema: {
      chain_id: z
        .string()
        .describe("Chain ID, e.g. '1' for Ethereum mainnet, '56' for BSC"),
      signer_address: z
        .string()
        .describe("Ethereum address of the signer (0x-prefixed)"),
      message: z.string().describe("The message to sign"),
      sign_type: z
        .enum(["personal", "eip191"])
        .default("personal")
        .describe("Sign type: 'personal' (default) or 'eip191'"),
      wait_for_approval: z
        .boolean()
        .default(false)
        .describe("Whether to wait for manual approval if pending. Default false."),
    },
  },
  async ({ chain_id, signer_address, message, sign_type, wait_for_approval }) => {
    try {
      const response = await client.sign(
        { chain_id, signer_address, sign_type, payload: { message } },
        wait_for_approval
      );
      return ok(response);
    } catch (error: any) {
      return handleSignResult(error);
    }
  }
);

// ===========================================================================
// Tool: evm_sign_hash  –  POST /api/v1/evm/sign (sign_type=hash)
// ===========================================================================

server.registerTool(
  "evm_sign_hash",
  {
    title: "Sign Hash",
    description:
      "Sign a pre-computed 32-byte hash. Returns the ECDSA signature.",
    inputSchema: {
      chain_id: z.string().describe("Chain ID, e.g. '1' for Ethereum mainnet"),
      signer_address: z
        .string()
        .describe("Ethereum address of the signer (0x-prefixed)"),
      hash: z
        .string()
        .describe("The 32-byte hash to sign (0x-prefixed, 66 hex chars)"),
      wait_for_approval: z.boolean().default(false).describe("Wait for manual approval if pending"),
    },
  },
  async ({ chain_id, signer_address, hash, wait_for_approval }) => {
    try {
      const response = await client.sign(
        { chain_id, signer_address, sign_type: "hash", payload: { hash } },
        wait_for_approval
      );
      return ok(response);
    } catch (error: any) {
      return handleSignResult(error);
    }
  }
);

// ===========================================================================
// Tool: evm_sign_typed_data  –  POST /api/v1/evm/sign (sign_type=typed_data)
// ===========================================================================

server.registerTool(
  "evm_sign_typed_data",
  {
    title: "Sign EIP-712 Typed Data",
    description:
      "Sign EIP-712 structured typed data (eth_signTypedData_v4). " +
      "Used for Permits, orders, off-chain approvals, etc.",
    inputSchema: {
      chain_id: z.string().describe("Chain ID"),
      signer_address: z
        .string()
        .describe("Ethereum address of the signer (0x-prefixed)"),
      typed_data: z
        .object({
          types: z
            .record(z.array(z.object({ name: z.string(), type: z.string() })))
            .describe("Type definitions including EIP712Domain"),
          primaryType: z.string().describe("Primary type name"),
          domain: z
            .object({
              name: z.string().optional(),
              version: z.string().optional(),
              chainId: z.string().optional(),
              verifyingContract: z.string().optional(),
              salt: z.string().optional(),
            })
            .describe("EIP-712 domain separator"),
          message: z
            .record(z.any())
            .describe("Message data matching the primary type"),
        })
        .describe("The full EIP-712 typed data object"),
      wait_for_approval: z.boolean().default(false).describe("Wait for manual approval if pending"),
    },
  },
  async ({ chain_id, signer_address, typed_data, wait_for_approval }) => {
    try {
      const response = await client.sign(
        { chain_id, signer_address, sign_type: "typed_data", payload: { typed_data } },
        wait_for_approval
      );
      return ok(response);
    } catch (error: any) {
      return handleSignResult(error);
    }
  }
);

// ===========================================================================
// Tool: evm_sign_transaction  –  POST /api/v1/evm/sign (sign_type=transaction)
// ===========================================================================

server.registerTool(
  "evm_sign_transaction",
  {
    title: "Sign Transaction",
    description:
      "Sign an EVM transaction (Legacy, EIP-2930, or EIP-1559). " +
      "Returns the signed raw transaction hex.",
    inputSchema: {
      chain_id: z.string().describe("Chain ID, e.g. '1' for Ethereum mainnet"),
      signer_address: z
        .string()
        .describe("Ethereum address of the signer (0x-prefixed)"),
      to: z
        .string()
        .optional()
        .describe("Recipient address (0x-prefixed). Omit for contract creation."),
      value: z.string().describe("Transaction value in wei (decimal string)"),
      data: z
        .string()
        .optional()
        .describe("Transaction calldata (0x-prefixed hex)"),
      gas: z.number().describe("Gas limit"),
      nonce: z.number().optional().describe("Transaction nonce"),
      tx_type: z
        .enum(["legacy", "eip1559", "eip2930"])
        .default("legacy")
        .describe("Transaction type"),
      gas_price: z
        .string()
        .optional()
        .describe("Gas price in wei (for legacy / eip2930)"),
      gas_tip_cap: z
        .string()
        .optional()
        .describe("Max priority fee per gas in wei (for EIP-1559)"),
      gas_fee_cap: z
        .string()
        .optional()
        .describe("Max fee per gas in wei (for EIP-1559)"),
      wait_for_approval: z.boolean().default(false).describe("Wait for manual approval if pending"),
    },
  },
  async ({
    chain_id, signer_address, to, value, data, gas, nonce,
    tx_type, gas_price, gas_tip_cap, gas_fee_cap, wait_for_approval,
  }) => {
    try {
      const response = await client.sign(
        {
          chain_id,
          signer_address,
          sign_type: "transaction",
          payload: {
            transaction: {
              to, value, data, gas, nonce,
              txType: tx_type,
              gasPrice: gas_price,
              gasTipCap: gas_tip_cap,
              gasFeeCap: gas_fee_cap,
            },
          },
        },
        wait_for_approval
      );
      return ok(response);
    } catch (error: any) {
      return handleSignResult(error);
    }
  }
);

// ===========================================================================
// Tool: evm_get_request  –  GET /api/v1/evm/requests/{id}
// ===========================================================================

server.registerTool(
  "evm_get_request",
  {
    title: "Get Request",
    description:
      "Get the detailed status of a signing request by its ID",
    inputSchema: {
      request_id: z.string().describe("The signing request ID"),
    },
  },
  async ({ request_id }) => {
    try {
      const response = await client.getRequest(request_id);
      return ok(response);
    } catch (error) {
      return err(error);
    }
  }
);

// ===========================================================================
// Tool: evm_list_requests  –  GET /api/v1/evm/requests
// ===========================================================================

server.registerTool(
  "evm_list_requests",
  {
    title: "List Requests",
    description:
      "List signing requests with optional filters for status, signer, and chain",
    inputSchema: {
      status: z
        .enum(["pending", "authorizing", "signing", "completed", "rejected", "failed"])
        .optional()
        .describe("Filter by request status"),
      signer_address: z
        .string()
        .optional()
        .describe("Filter by signer address"),
      chain_id: z.string().optional().describe("Filter by chain ID"),
      limit: z.number().optional().default(20).describe("Max number of results (default 20)"),
    },
  },
  async ({ status, signer_address, chain_id, limit }) => {
    try {
      const response = await client.listRequests({
        status,
        signer_address,
        chain_id,
        limit,
      });
      return ok(response);
    } catch (error) {
      return err(error);
    }
  }
);

// ===========================================================================
// Tool: evm_approve_request  –  POST /api/v1/evm/requests/{id}/approve
// ===========================================================================

server.registerTool(
  "evm_approve_request",
  {
    title: "Approve/Reject Request",
    description:
      "Approve or reject a pending signing request (requires admin API key). " +
      "Optionally generate a rule to auto-approve similar future requests.",
    inputSchema: {
      request_id: z.string().describe("The signing request ID to approve/reject"),
      approved: z.boolean().describe("true to approve, false to reject"),
      rule_type: z
        .string()
        .optional()
        .describe(
          "Optional: generate a rule on approval. " +
          "Type: evm_address_whitelist, evm_contract_method, evm_value_limit, etc."
        ),
      rule_mode: z
        .enum(["whitelist", "blocklist"])
        .optional()
        .describe("Rule mode (required if rule_type is set)"),
      rule_name: z
        .string()
        .optional()
        .describe("Optional custom name for the generated rule"),
      max_value: z
        .string()
        .optional()
        .describe("Max value in wei (required for evm_value_limit rule)"),
    },
  },
  async ({ request_id, approved, rule_type, rule_mode, rule_name, max_value }) => {
    try {
      const response = await client.approveRequest(request_id, {
        approved,
        rule_type,
        rule_mode,
        rule_name,
        max_value,
      });
      return ok(response);
    } catch (error) {
      return err(error);
    }
  }
);

// ===========================================================================
// Tool: evm_preview_rule  –  POST /api/v1/evm/requests/{id}/preview-rule
// ===========================================================================

server.registerTool(
  "evm_preview_rule",
  {
    title: "Preview Rule",
    description:
      "Preview what rule would be generated for a pending request before approving it",
    inputSchema: {
      request_id: z.string().describe("The signing request ID"),
      rule_type: z
        .string()
        .describe(
          "Rule type: evm_address_whitelist, evm_contract_method, evm_value_limit, etc."
        ),
      rule_mode: z
        .enum(["whitelist", "blocklist"])
        .describe("Rule mode"),
      rule_name: z.string().optional().describe("Custom name for the rule"),
      max_value: z
        .string()
        .optional()
        .describe("Max value in wei (for evm_value_limit)"),
    },
  },
  async ({ request_id, rule_type, rule_mode, rule_name, max_value }) => {
    try {
      const response = await client.previewRule(request_id, {
        rule_type,
        rule_mode,
        rule_name,
        max_value,
      });
      return ok(response);
    } catch (error) {
      return err(error);
    }
  }
);

// ===========================================================================
// Tool: evm_list_rules  –  GET /api/v1/evm/rules
// ===========================================================================

server.registerTool(
  "evm_list_rules",
  {
    title: "List Rules",
    description:
      "List all authorization rules (requires admin API key). " +
      "Rules control auto-approve (whitelist) and auto-block (blocklist) behavior.",
    inputSchema: {},
  },
  async () => {
    try {
      const response = await client.listRules();
      return ok(response);
    } catch (error) {
      return err(error);
    }
  }
);

// ===========================================================================
// Tool: evm_get_rule  –  GET /api/v1/evm/rules/{id}
// ===========================================================================

server.registerTool(
  "evm_get_rule",
  {
    title: "Get Rule",
    description: "Get details of a specific rule by ID (requires admin API key)",
    inputSchema: {
      rule_id: z.string().describe("The rule ID"),
    },
  },
  async ({ rule_id }) => {
    try {
      const response = await client.getRule(rule_id);
      return ok(response);
    } catch (error) {
      return err(error);
    }
  }
);

// ===========================================================================
// Tool: evm_create_rule  –  POST /api/v1/evm/rules
// ===========================================================================

server.registerTool(
  "evm_create_rule",
  {
    title: "Create Rule",
    description:
      "Create a new authorization rule (requires admin API key). " +
      "Rule types: evm_address_whitelist, evm_contract_method, evm_value_limit, " +
      "evm_solidity_expression, signer_restriction, sign_type_restriction, message_pattern",
    inputSchema: {
      name: z.string().describe("Rule name"),
      description: z.string().optional().describe("Rule description"),
      type: z
        .string()
        .describe(
          "Rule type: evm_address_whitelist, evm_contract_method, evm_value_limit, " +
          "evm_solidity_expression, signer_restriction, sign_type_restriction, message_pattern"
        ),
      mode: z
        .enum(["whitelist", "blocklist"])
        .describe("whitelist = auto-approve on match, blocklist = auto-block on match"),
      chain_id: z.string().optional().describe("Scope to specific chain ID"),
      signer_address: z
        .string()
        .optional()
        .describe("Scope to specific signer address"),
      config: z
        .record(z.any())
        .describe(
          "Rule configuration. Structure depends on type. " +
          "e.g. {addresses: [...]} for evm_address_whitelist, " +
          "{max_value: '...'} for evm_value_limit, " +
          "{contract: '...', method_sigs: [...]} for evm_contract_method"
        ),
      enabled: z.boolean().optional().default(true).describe("Whether the rule is enabled"),
    },
  },
  async ({ name, description, type, mode, chain_id, signer_address, config, enabled }) => {
    try {
      const response = await client.createRule({
        name,
        description,
        type: type as any,
        mode,
        chain_id,
        signer_address,
        config,
        enabled,
      });
      return ok(response);
    } catch (error) {
      return err(error);
    }
  }
);

// ===========================================================================
// Tool: evm_update_rule  –  PATCH /api/v1/evm/rules/{id}
// ===========================================================================

server.registerTool(
  "evm_update_rule",
  {
    title: "Update Rule",
    description: "Update an existing rule (requires admin API key)",
    inputSchema: {
      rule_id: z.string().describe("The rule ID to update"),
      name: z.string().optional().describe("New rule name"),
      description: z.string().optional().describe("New description"),
      mode: z
        .enum(["whitelist", "blocklist"])
        .optional()
        .describe("New rule mode"),
      config: z
        .record(z.any())
        .optional()
        .describe("New rule configuration"),
      enabled: z.boolean().optional().describe("Enable/disable the rule"),
    },
  },
  async ({ rule_id, name, description, mode, config, enabled }) => {
    try {
      const response = await client.updateRule(rule_id, {
        name,
        description,
        mode,
        config,
        enabled,
      });
      return ok(response);
    } catch (error) {
      return err(error);
    }
  }
);

// ===========================================================================
// Tool: evm_delete_rule  –  DELETE /api/v1/evm/rules/{id}
// ===========================================================================

server.registerTool(
  "evm_delete_rule",
  {
    title: "Delete Rule",
    description: "Delete a rule by ID (requires admin API key)",
    inputSchema: {
      rule_id: z.string().describe("The rule ID to delete"),
    },
  },
  async ({ rule_id }) => {
    try {
      await client.deleteRule(rule_id);
      return ok({ success: true, message: `Rule ${rule_id} deleted` });
    } catch (error) {
      return err(error);
    }
  }
);

// ===========================================================================
// Tool: list_audit_logs  –  GET /api/v1/audit
// ===========================================================================

server.registerTool(
  "list_audit_logs",
  {
    title: "List Audit Logs",
    description:
      "Query audit log records. Supports filtering by event type, time range, etc. " +
      "Event types: auth_success, auth_failure, sign_request, sign_complete, " +
      "sign_failed, sign_rejected, rule_matched, approval_request, approval_granted, " +
      "approval_denied, rule_created, rule_updated, rule_deleted, rate_limit_hit",
    inputSchema: {
      event_type: z
        .string()
        .optional()
        .describe("Filter by event type (e.g. sign_request, auth_failure)"),
      api_key_id: z
        .string()
        .optional()
        .describe("Filter by API key ID"),
      chain_type: z
        .string()
        .optional()
        .describe("Filter by chain type (e.g. evm, solana)"),
      start_time: z
        .string()
        .optional()
        .describe("Start time filter (RFC3339 format, e.g. 2024-01-01T00:00:00Z)"),
      end_time: z
        .string()
        .optional()
        .describe("End time filter (RFC3339 format)"),
      limit: z
        .number()
        .optional()
        .default(30)
        .describe("Max number of records (1-100, default 30)"),
    },
  },
  async ({ event_type, api_key_id, chain_type, start_time, end_time, limit }) => {
    try {
      const response = await client.listAuditLogs({
        event_type: event_type as any,
        api_key_id,
        chain_type,
        start_time,
        end_time,
        limit,
      });
      return ok(response);
    } catch (error) {
      return err(error);
    }
  }
);

// ===========================================================================
// Start server
// ===========================================================================

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Remote Signer MCP Server running on stdio");
  console.error(`  Base URL: ${BASE_URL}`);
  console.error(`  API Key ID: ${API_KEY_ID}`);
}

main().catch((error) => {
  console.error("Fatal error in main():", error);
  process.exit(1);
});
