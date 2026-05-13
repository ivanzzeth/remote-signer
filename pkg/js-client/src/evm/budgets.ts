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
}

/** Response envelope for the list endpoint. */
export interface ListBudgetsResponse {
  budgets: BudgetEntry[];
  total: number;
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
}
