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
}

/** Response from simulating a single transaction. */
export interface SimulateResponse {
  success: boolean;
  gas_used: number;
  balance_changes: BalanceChangeDTO[];
  events: SimEventDTO[];
  has_approval: boolean;
  revert_reason?: string;
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
export interface SimulateResultDTO {
  index: number;
  success: boolean;
  gas_used: number;
  balance_changes: BalanceChangeDTO[];
  events: SimEventDTO[];
  has_approval: boolean;
  revert_reason?: string;
}

/** Response from simulating a batch of transactions. */
export interface SimulateBatchResponse {
  results: SimulateResultDTO[];
  net_balance_changes: BalanceChangeDTO[];
}

/** Status of a single anvil fork instance. */
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
  anvil_version: string;
  chains: Record<string, ChainStatusDTO>;
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
   * Get the status of all running simulation anvil forks.
   */
  async status(): Promise<SimulationStatusResponse> {
    return this.transport.request<SimulationStatusResponse>(
      "GET",
      "/api/v1/evm/simulate/status",
      null,
    );
  }
}
