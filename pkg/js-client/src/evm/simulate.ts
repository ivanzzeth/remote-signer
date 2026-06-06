/**
 * EVM simulate service: transaction simulation operations.
 */

import { HttpTransport } from "../transport";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Request for simulating a single transaction. */
export interface SimulateRequest {
  chain_id: string;
  from: string;
  to: string;
  value?: string;
  data?: string;
  gas?: string;
}

/** Balance change in a simulation result. */
export interface BalanceChangeDTO {
  token: string;
  standard: string;
  amount: string;
  direction: string;
  token_id?: string;
}

/** Parsed event in a simulation result. */
export interface SimEventDTO {
  address: string;
  event: string;
  standard: string;
  args: Record<string, string>;
  topic0?: string;
  signature?: string;
  source?: string;
  confidence?: string;
  candidates?: string[];
}

/** Structured revert metadata from the simulation engine. */
export interface RevertDetailDTO {
  revert_reason?: string;
  revert_data?: string;
  revert_selector?: string;
  revert_signature?: string;
  revert_source?: string;
  revert_confidence?: string;
  revert_candidates?: string[];
  revert_args?: Record<string, string>;
}

/** Response from simulating a single transaction. */
export interface SimulateResponse extends RevertDetailDTO {
  success: boolean;
  gas_used: number;
  balance_changes: BalanceChangeDTO[];
  events: SimEventDTO[];
  has_approval: boolean;
}

/** A single transaction in a batch simulate request. */
export interface SimulateTxDTO {
  to: string;
  value?: string;
  data?: string;
  gas?: string;
}

/** Request for simulating multiple transactions. */
export interface SimulateBatchRequest {
  chain_id: string;
  from: string;
  transactions: SimulateTxDTO[];
}

/** Per-transaction result in a batch simulate response. */
export interface SimulateResultDTO extends RevertDetailDTO {
  index: number;
  success: boolean;
  gas_used: number;
  balance_changes: BalanceChangeDTO[];
  events: SimEventDTO[];
  has_approval: boolean;
}

/** Response from simulating a batch of transactions. */
export interface SimulateBatchResponse {
  results: SimulateResultDTO[];
  net_balance_changes: BalanceChangeDTO[];
}

/** Per-chain simulator status (optional; RPC backend may return empty). */
export interface ChainStatusDTO {
  status: string;
  port: number;
  block_number?: string;
  restart_count: number;
  dirty: boolean;
  error?: string;
}

/** Response from GET /api/v1/evm/simulate/status. */
export interface SimulationStatusResponse {
  enabled: boolean;
  engine_version: string;
  chains: Record<string, ChainStatusDTO>;
}

/** Filter for GET /api/v1/evm/simulations. */
export interface ListSimulationsFilter {
  decision?: string;
  chain_id?: string;
  success?: boolean;
  limit?: number;
  cursor?: string;
  cursor_id?: string;
}

/** Summary row from persisted simulation history. */
export interface SimulationHistoryItem {
  sign_request_id: string;
  chain_id: string;
  decision: string;
  reason?: string;
  success: boolean;
  gas_used: number;
  revert_reason?: string;
  simulated_at: string;
  updated_at: string;
}

/** Response from GET /api/v1/evm/simulations. */
export interface ListSimulationsResponse {
  simulations: SimulationHistoryItem[];
  has_more: boolean;
  next_cursor?: string;
  next_cursor_id?: string;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class EvmSimulateService {
  constructor(private readonly transport: HttpTransport) {}

  /**
   * Simulate a single transaction.
   */
  async simulate(req: SimulateRequest): Promise<SimulateResponse> {
    return this.transport.request<SimulateResponse>(
      "POST",
      "/api/v1/evm/simulate",
      req,
    );
  }

  /**
   * Simulate multiple transactions in sequence.
   */
  async simulateBatch(req: SimulateBatchRequest): Promise<SimulateBatchResponse> {
    return this.transport.request<SimulateBatchResponse>(
      "POST",
      "/api/v1/evm/simulate/batch",
      req,
    );
  }

  /**
   * Get simulation engine status (enabled flag, engine id string, optional per-chain details).
   */
  async status(): Promise<SimulationStatusResponse> {
    return this.transport.request<SimulationStatusResponse>(
      "GET",
      "/api/v1/evm/simulate/status",
      null,
    );
  }

  /**
   * List persisted simulation snapshots from the sign pipeline.
   */
  async list(filter?: ListSimulationsFilter): Promise<ListSimulationsResponse> {
    const params = new URLSearchParams();
    if (filter?.decision) params.append("decision", filter.decision);
    if (filter?.chain_id) params.append("chain_id", filter.chain_id);
    if (filter?.success !== undefined) {
      params.append("success", filter.success ? "true" : "false");
    }
    if (filter?.limit) params.append("limit", String(filter.limit));
    if (filter?.cursor) params.append("cursor", filter.cursor);
    if (filter?.cursor_id) params.append("cursor_id", filter.cursor_id);
    const qs = params.toString();
    return this.transport.request<ListSimulationsResponse>(
      "GET",
      `/api/v1/evm/simulations${qs ? `?${qs}` : ""}`,
      null,
    );
  }
}
