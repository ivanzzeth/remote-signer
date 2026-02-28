/**
 * EVM rule service: CRUD operations for signing rules.
 */

import { HttpTransport } from "../transport";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type RuleType =
  | "evm_address_list"
  | "evm_contract_method"
  | "evm_value_limit"
  | "evm_solidity_expression"
  | "signer_restriction"
  | "sign_type_restriction"
  | "message_pattern";

export type RuleMode = "whitelist" | "blocklist";

export interface Rule {
  id: string;
  name: string;
  description?: string;
  type: RuleType;
  mode: RuleMode;
  source: string;
  chain_type?: string;
  chain_id?: string;
  api_key_id?: string;
  signer_address?: string;
  config: Record<string, any>;
  enabled: boolean;
  expires_at?: string;
  created_at: string;
  updated_at: string;
}

export interface ListRulesResponse {
  rules: Rule[];
}

export interface CreateRuleRequest {
  name: string;
  description?: string;
  type: RuleType;
  mode: RuleMode;
  chain_type?: string;
  chain_id?: string;
  api_key_id?: string;
  signer_address?: string;
  config: Record<string, any>;
  enabled?: boolean;
  expires_at?: string;
}

export interface UpdateRuleRequest {
  name?: string;
  description?: string;
  mode?: RuleMode;
  config?: Record<string, any>;
  enabled?: boolean;
  expires_at?: string;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class EvmRuleService {
  constructor(private readonly transport: HttpTransport) {}

  /**
   * List all rules.
   */
  async list(): Promise<ListRulesResponse> {
    return this.transport.request<ListRulesResponse>(
      "GET",
      "/api/v1/evm/rules",
      null,
    );
  }

  /**
   * Get a rule by ID.
   */
  async get(ruleID: string): Promise<Rule> {
    return this.transport.request<Rule>(
      "GET",
      `/api/v1/evm/rules/${ruleID}`,
      null,
    );
  }

  /**
   * Create a new rule.
   */
  async create(rule: CreateRuleRequest): Promise<Rule> {
    return this.transport.request<Rule>(
      "POST",
      "/api/v1/evm/rules",
      rule,
    );
  }

  /**
   * Update an existing rule.
   */
  async update(ruleID: string, update: UpdateRuleRequest): Promise<Rule> {
    return this.transport.request<Rule>(
      "PATCH",
      `/api/v1/evm/rules/${ruleID}`,
      update,
    );
  }

  /**
   * Delete a rule.
   */
  async delete(ruleID: string): Promise<void> {
    await this.transport.request<void>(
      "DELETE",
      `/api/v1/evm/rules/${ruleID}`,
      null,
    );
  }
}
