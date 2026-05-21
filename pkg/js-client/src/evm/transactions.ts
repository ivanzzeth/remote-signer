/**
 * EVM transactions — read-only view over the daemon's on-chain
 * tracking table. The wallet RPC proxy writes a row when an
 * eth_sendRawTransaction is broadcast; the background poller drives
 * it to Mined / Dropped. This service is how UIs surface that
 * lifecycle without round-tripping to the chain themselves.
 *
 * Endpoints:
 *   GET /api/v1/evm/transactions[?status=&chain_id=&from=&sign_request_id=&api_key_id=]
 *   GET /api/v1/evm/transactions/{id}
 *
 * Visibility is server-enforced: non-admin callers see only
 * transactions whose linked sign_request was created by their key;
 * passing api_key_id for a different key returns 403.
 */

import type { HttpTransport } from "../transport";

export type TransactionStatus =
  | "broadcasted"
  | "mined"
  | "dropped"
  | "failed";

export interface Transaction {
  id: string;
  sign_request_id?: string;
  chain_id: string;
  tx_hash: string;
  from_address: string;
  status: TransactionStatus;
  block_number?: number;
  block_hash?: string;
  tx_index?: number;
  gas_used?: number;
  receipt_status?: number; // 0 = revert, 1 = success
  error_message?: string;
  last_checked_at?: string;
  broadcasted_at: string;
  mined_at?: string;
  created_at: string;
  updated_at: string;
}

export interface ListTransactionsFilter {
  status?: TransactionStatus;
  chain_id?: string | number;
  /** Filter to txs sent from this address (case-insensitive). */
  from?: string;
  sign_request_id?: string;
  /** Admin-only override; non-admins are auto-scoped to their key. */
  api_key_id?: string;
  limit?: number;
  offset?: number;
}

export interface ListTransactionsResponse {
  transactions: Transaction[];
  total: number;
  has_more: boolean;
}

export class EvmTransactionService {
  constructor(private readonly transport: HttpTransport) {}

  async list(filter?: ListTransactionsFilter): Promise<ListTransactionsResponse> {
    const params = new URLSearchParams();
    if (filter?.status) params.append("status", filter.status);
    if (filter?.chain_id !== undefined) {
      params.append("chain_id", String(filter.chain_id));
    }
    if (filter?.from) params.append("from", filter.from);
    if (filter?.sign_request_id) params.append("sign_request_id", filter.sign_request_id);
    if (filter?.api_key_id) params.append("api_key_id", filter.api_key_id);
    if (filter?.limit !== undefined) params.append("limit", String(filter.limit));
    if (filter?.offset !== undefined) params.append("offset", String(filter.offset));
    const qs = params.toString();
    return this.transport.request<ListTransactionsResponse>(
      "GET",
      `/api/v1/evm/transactions${qs ? `?${qs}` : ""}`,
      null,
    );
  }

  async get(id: string): Promise<Transaction> {
    return this.transport.request<Transaction>(
      "GET",
      `/api/v1/evm/transactions/${encodeURIComponent(id)}`,
      null,
    );
  }
}
