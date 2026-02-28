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
  signature?: string;
  signed_data?: string;
  error_message?: string;
  rule_matched_id?: string;
  approved_by?: string;
  approved_at?: string;
  created_at: string;
  updated_at: string;
  completed_at?: string;
}

/** List requests filter */
export interface ListRequestsFilter {
  status?: RequestStatus;
  signer_address?: string;
  chain_id?: string;
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
}
