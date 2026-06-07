/**
 * EVM budgets service.
 *
 * Exposes GET /api/v1/evm/budgets — the operator-facing list of every
 * budget row, real or synthetic. Per-rule budgets are still available
 * via EvmRuleService.listBudgets; this endpoint exists because the
 * simulation fallback creates budget rows under synthetic rule IDs
 * (`sim:0x<address>`) that never appear in the rules table, so a
 * client that fans out over rules.list() can never see them.
 */

import { HttpTransport } from "../transport";

/** Discriminator for a {@link BudgetEntry}. */
export type BudgetKind = "rule" | "simulation";

/**
 * Single budget row as returned by GET /api/v1/evm/budgets, annotated
 * server-side with whatever rule metadata is resolvable so the client
 * doesn't need a second roundtrip.
 *
 * - `kind="rule"`: backs a real rule. `rule_name`/`rule_type`/`rule_mode`
 *   are populated; `signer_address` is empty (signer is implicit from
 *   the rule's own scope).
 * - `kind="simulation"`: created by the simulation fallback. `rule_id`
 *   has the form `sim:<address>` and `signer_address` is the decoded
 *   address; no real rule exists for it.
 */
export interface BudgetEntry {
  id: string;
  kind: BudgetKind;
  rule_id: string;
  rule_name?: string;
  rule_type?: string;
  rule_mode?: string;
  rule_owner?: string;
  signer_address?: string;
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
  unit_display?: string;
  budget_period?: string;
  period_start?: string;
  period_ends_at?: string;
  enforces_limit?: boolean;
  is_stale_placeholder?: boolean;
}

/** Response envelope for the list endpoint. */
export interface ListBudgetsResponse {
  budgets: BudgetEntry[];
  total: number;
}

/**
 * POST /api/v1/evm/budgets body. The daemon refuses rule_id values that
 * start with "sim:" — simulation budgets are owned by the simulation
 * fallback's auto-create path which has security guards (max dynamic
 * units, post-create TOCTOU re-check) that a manual POST would bypass.
 */
export interface CreateBudgetRequest {
  rule_id: string;
  unit: string;
  max_total: string;
  max_per_tx?: string;
  max_tx_count?: number;
  alert_pct?: number;
}

/**
 * PATCH /api/v1/evm/budgets/{id} body. Omitted fields are left
 * untouched; sending an explicit zero/empty value applies the change.
 * Identity fields (rule_id, unit, id) cannot be changed — delete and
 * recreate instead.
 */
export interface UpdateBudgetRequest {
  max_total?: string;
  max_per_tx?: string;
  max_tx_count?: number;
  alert_pct?: number;
  alert_sent?: boolean;
  spent?: string;
  tx_count?: number;
}

export class EvmBudgetService {
  constructor(private readonly transport: HttpTransport) {}

  /**
   * List every budget row visible to the caller.
   *
   * Admin/dev see all rows including synthetic simulation budgets;
   * agents see only budgets attached to rules they own and never see
   * simulation budgets (signer-level spend across peers is operator
   * information).
   */
  async list(): Promise<ListBudgetsResponse> {
    return this.transport.request<ListBudgetsResponse>(
      "GET",
      "/api/v1/evm/budgets",
      null,
    );
  }

  /** Fetch a single budget by its primary key. */
  async get(id: string): Promise<BudgetEntry> {
    return this.transport.request<BudgetEntry>(
      "GET",
      `/api/v1/evm/budgets/${encodeURIComponent(id)}`,
      null,
    );
  }

  /** Create a budget for an existing rule. Admin only. */
  async create(req: CreateBudgetRequest): Promise<BudgetEntry> {
    return this.transport.request<BudgetEntry>(
      "POST",
      "/api/v1/evm/budgets",
      req,
    );
  }

  /** Patch mutable fields on an existing budget. Admin only. */
  async update(id: string, req: UpdateBudgetRequest): Promise<BudgetEntry> {
    return this.transport.request<BudgetEntry>(
      "PATCH",
      `/api/v1/evm/budgets/${encodeURIComponent(id)}`,
      req,
    );
  }

  /** Zero spent/tx_count/alert_sent in one shot. Admin only. */
  async reset(id: string): Promise<BudgetEntry> {
    return this.transport.request<BudgetEntry>(
      "POST",
      `/api/v1/evm/budgets/${encodeURIComponent(id)}/reset`,
      null,
    );
  }

  /** Delete a budget row. Admin only. */
  async delete(id: string): Promise<void> {
    await this.transport.request<void>(
      "DELETE",
      `/api/v1/evm/budgets/${encodeURIComponent(id)}`,
      null,
    );
  }

  /**
   * Delete all budget rows for a rule_id, and remove orphan sim:0x...
   * placeholder rules when budgets are already gone. Admin only.
   */
  async deleteByRuleID(ruleID: string): Promise<void> {
    await this.transport.request<void>(
      "DELETE",
      `/api/v1/evm/budgets/by-rule/${encodeURIComponent(ruleID)}`,
      null,
    );
  }
}
