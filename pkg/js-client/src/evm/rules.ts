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

export interface ListRulesFilter {
  chain_type?: string;
  signer_address?: string;
  api_key_id?: string;
  type?: string;
  mode?: string;
  enabled?: boolean;
  limit?: number;
  offset?: number;
}

export interface ListRulesResponse {
  rules: Rule[];
  total: number;
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

/** Budget record for a rule (GET /api/v1/evm/rules/{id}/budgets). */
export interface RuleBudget {
  id: string;
  rule_id: string;
  unit: string;
  max_total: string;
  max_per_tx: string;
  spent: string;
  alert_pct: number;
  alert_sent: boolean;
  tx_count: number;
  max_tx_count: number;
  created_at: string;
  updated_at: string;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class EvmRuleService {
  constructor(private readonly transport: HttpTransport) {}

  /**
   * List rules with optional filters.
   */
  async list(filter?: ListRulesFilter): Promise<ListRulesResponse> {
    const params = new URLSearchParams();
    if (filter?.chain_type) params.append("chain_type", filter.chain_type);
    if (filter?.signer_address) params.append("signer_address", filter.signer_address);
    if (filter?.api_key_id) params.append("api_key_id", filter.api_key_id);
    if (filter?.type) params.append("type", filter.type);
    if (filter?.mode) params.append("mode", filter.mode);
    if (filter?.enabled !== undefined) params.append("enabled", String(filter.enabled));
    if (filter?.limit) params.append("limit", filter.limit.toString());
    if (filter?.offset) params.append("offset", filter.offset.toString());
    const qs = params.toString();
    return this.transport.request<ListRulesResponse>(
      "GET",
      `/api/v1/evm/rules${qs ? `?${qs}` : ""}`,
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

  /**
   * Toggle a rule's enabled state.
   */
  async toggle(ruleID: string, enabled: boolean): Promise<Rule> {
    return this.update(ruleID, { enabled });
  }

  /**
   * List budgets for a rule (GET /api/v1/evm/rules/{ruleID}/budgets).
   */
  async listBudgets(ruleID: string): Promise<RuleBudget[]> {
    const list = await this.transport.request<RuleBudget[]>(
      "GET",
      `/api/v1/evm/rules/${encodeURIComponent(ruleID)}/budgets`,
      null,
    );
    return list ?? [];
  }

  /**
   * Approve a pending rule (POST /api/v1/evm/rules/{ruleID}/approve).
   */
  async approve(ruleID: string): Promise<Rule> {
    return this.transport.request<Rule>(
      "POST",
      `/api/v1/evm/rules/${encodeURIComponent(ruleID)}/approve`,
      null,
    );
  }

  /**
   * Reject a pending rule (POST /api/v1/evm/rules/{ruleID}/reject).
   */
  async reject(ruleID: string, reason: string): Promise<Rule> {
    return this.transport.request<Rule>(
      "POST",
      `/api/v1/evm/rules/${encodeURIComponent(ruleID)}/reject`,
      { reason },
    );
  }
}
