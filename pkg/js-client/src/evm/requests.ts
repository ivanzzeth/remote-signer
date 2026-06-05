/**
 * EVM request service: get, list, approve, and preview rules for signing requests.
 */

import { HttpTransport } from "../transport";
import type { RequestStatus } from "./types";
import type { RuleMode } from "./rules";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Request status response */
export interface RequestStatusResponse {
  id: string;
  api_key_id: string;
  chain_type: string;
  chain_id: string;
  signer_address: string;
  sign_type: string;
  status: RequestStatus;
  client_ip?: string;
  // Chain-specific request payload. Only populated by GET
  // /api/v1/evm/requests/{id} (the detail endpoint); list responses
  // typically omit it to keep page payloads small.
  payload?: Record<string, unknown>;
  signature?: string;
  signed_data?: string;
  error_message?: string;
  rule_matched_id?: string;
  rule_matched_name?: string;
  approved_by?: string;
  approved_at?: string;
  // How the request transitioned out of authorizing: "manual" (admin),
  // "rule" (whitelist rule matched), "simulation" (simulation fallback
  // allowed it). Empty until the request reaches signing/completed.
  approval_source?: "manual" | "rule" | "simulation";
  // last_no_match_reason carries the whitelist engine's diagnostic when
  // no rule matched this request. Surfaced in the activity drawer to
  // explain why a sign is stuck on manual approval. Empty when a rule
  // auto-approved.
  last_no_match_reason?: string;
  // transaction_id is the FK into /api/v1/evm/transactions, set
  // when the wallet RPC proxy observes an eth_sendRawTransaction
  // whose payload matches this request's signed_data. Empty for
  // personal_sign / typed_data requests (never broadcast) and for
  // tx requests that haven't been broadcast yet.
  transaction_id?: string;
  /** Rule types auto-generatable from this request payload (detail GET, pending/authorizing only). */
  generatable_rule_types?: string[];
  rule_generation_hints?: {
    max_value?: string;
  };
  created_at: string;
  updated_at: string;
  completed_at?: string;
}

/** List requests filter */
export interface ListRequestsFilter {
  status?: RequestStatus;
  signer_address?: string;
  chain_id?: string;
  sign_type?: string;
  transaction_status?: "none" | "broadcasted" | "mined" | "dropped" | "failed";
  /** Admin/dev only */
  api_key_id?: string;
  /** Admin/dev only */
  role?: string;
  limit?: number;
  cursor?: string;
  cursor_id?: string;
}

/** List requests response */
export interface ListRequestsResponse {
  requests: RequestStatusResponse[];
  total: number;
  next_cursor?: string;
  next_cursor_id?: string;
  has_more: boolean;
}

/** Batch approve/reject request */
export interface BatchApproveRequest {
  request_ids: string[];
  approved: boolean;
}

/** Per-item result from batch approve */
export interface BatchApproveItemResult {
  request_id: string;
  status?: RequestStatus;
  signature?: string;
  signed_data?: string;
  message?: string;
  idempotent: boolean;
  error?: string;
}

/** Batch approve response */
export interface BatchApproveResponse {
  results: BatchApproveItemResult[];
  summary: {
    total: number;
    succeeded: number;
    failed: number;
    idempotent: number;
  };
}

/** Approve request */
export interface ApproveRequest {
  approved: boolean;
  rule_type?: string;
  rule_mode?: "whitelist" | "blocklist";
  rule_name?: string;
  max_value?: string; // for evm_value_limit
}

/** Approve response */
export interface ApproveResponse {
  request_id: string;
  status: RequestStatus;
  signature?: string;
  signed_data?: string;
  generated_rule?: {
    id: string;
    name: string;
    type: string;
    mode: string;
  };
}

/** Preview rule request */
export interface PreviewRuleRequest {
  rule_type: string;
  rule_mode: RuleMode;
  rule_name?: string;
  max_value?: string;
}

/** Preview rule response */
export interface PreviewRuleResponse {
  id: string;
  name: string;
  type: string;
  mode: string;
  source: string;
  chain_type?: string;
  chain_id?: string;
  api_key_id?: string;
  signer_address?: string;
  config: Record<string, any>;
  enabled: boolean;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class EvmRequestService {
  constructor(private readonly transport: HttpTransport) {}

  /**
   * Get the status of a signing request.
   */
  async get(requestID: string): Promise<RequestStatusResponse> {
    return this.transport.request<RequestStatusResponse>(
      "GET",
      `/api/v1/evm/requests/${requestID}`,
      null,
    );
  }

  /**
   * List signing requests with optional filters.
   */
  async list(filter?: ListRequestsFilter): Promise<ListRequestsResponse> {
    const params = new URLSearchParams();
    if (filter?.status) {
      params.append("status", filter.status);
    }
    if (filter?.signer_address) {
      params.append("signer_address", filter.signer_address);
    }
    if (filter?.chain_id) {
      params.append("chain_id", filter.chain_id);
    }
    if (filter?.sign_type) {
      params.append("sign_type", filter.sign_type);
    }
    if (filter?.transaction_status) {
      params.append("transaction_status", filter.transaction_status);
    }
    if (filter?.api_key_id) {
      params.append("api_key_id", filter.api_key_id);
    }
    if (filter?.role) {
      params.append("role", filter.role);
    }
    if (filter?.limit) {
      params.append("limit", filter.limit.toString());
    }
    if (filter?.cursor) {
      params.append("cursor", filter.cursor);
    }
    if (filter?.cursor_id) {
      params.append("cursor_id", filter.cursor_id);
    }

    const queryString = params.toString();
    const path = `/api/v1/evm/requests${queryString ? `?${queryString}` : ""}`;

    return this.transport.request<ListRequestsResponse>("GET", path, null);
  }

  /**
   * Approve or reject a pending request.
   */
  async approve(
    requestID: string,
    approveRequest: ApproveRequest,
  ): Promise<ApproveResponse> {
    return this.transport.request<ApproveResponse>(
      "POST",
      `/api/v1/evm/requests/${requestID}/approve`,
      approveRequest,
    );
  }

  /**
   * Approve or reject many pending requests in one server-side call.
   * Each item is processed independently; partial success is normal.
   * Re-applying the same decision is idempotent per request.
   */
  async batchApprove(
    batchRequest: BatchApproveRequest,
  ): Promise<BatchApproveResponse> {
    return this.transport.request<BatchApproveResponse>(
      "POST",
      "/api/v1/evm/requests/batch-approve",
      batchRequest,
    );
  }

  /**
   * Preview what rule would be generated for a pending request.
   */
  async previewRule(
    requestID: string,
    previewRequest: PreviewRuleRequest,
  ): Promise<PreviewRuleResponse> {
    return this.transport.request<PreviewRuleResponse>(
      "POST",
      `/api/v1/evm/requests/${requestID}/preview-rule`,
      previewRequest,
    );
  }

  /**
   * Get the simulation pipeline's most recent evaluation of this
   * request. Returns a `RequestSimulation` row populated with the
   * decision, balance changes, decoded events, and contracts the
   * simulation touched. Throws an APIError(404) when the
   * simulation hasn't run yet — callers should treat that as
   * "evaluating, retry in a few seconds" rather than a hard error.
   *
   * The web UI's request-detail page polls this every 3s while the
   * request is pending so the operator sees what the tx would do
   * before deciding to manually approve.
   */
  async getSimulation(requestID: string): Promise<RequestSimulation> {
    return this.transport.request<RequestSimulation>(
      "GET",
      `/api/v1/evm/requests/${requestID}/simulation`,
      null,
    );
  }
}

// ---------------------------------------------------------------------------
// Simulation preview shapes
// ---------------------------------------------------------------------------

/** Outcome the simulation pipeline would settle on for this request. */
export type SimulationDecision = "allow" | "deny" | "no_match";

/**
 * Persisted snapshot of the simulation engine's most recent run
 * against a sign request. Created lazily on the first eval, upserted
 * on every re-eval — UIs reading this get the latest known state
 * without having to track which evaluation tick produced it.
 */
export interface RequestSimulation {
  sign_request_id: string;
  chain_id: string;
  decision: SimulationDecision | string;
  reason?: string;
  success: boolean;
  gas_used: number;
  revert_reason?: string;
  /** Per-account balance deltas as a JSON-encoded array. */
  balance_changes?: unknown;
  /** Decoded event log as a JSON-encoded array. */
  events?: unknown;
  /** Distinct event-emitting addresses, sorted. */
  contracts?: string[];
  /** Decoded calldata (function + args). Empty for non-transaction sign_types. */
  decoded_calldata?: unknown;
  /** Raw SimulationResult JSON — fallback for clients that want to render fields the typed columns don't surface. */
  raw_result?: unknown;
  simulated_at: string;
  updated_at: string;
}
