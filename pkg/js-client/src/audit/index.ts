/**
 * Audit service: list audit log records.
 */

import { HttpTransport } from "../transport";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AuditEventType =
  | "auth_success"
  | "auth_failure"
  | "sign_request"
  | "sign_complete"
  | "sign_failed"
  | "sign_rejected"
  | "rule_matched"
  | "approval_request"
  | "approval_granted"
  | "approval_denied"
  | "rule_created"
  | "rule_updated"
  | "rule_deleted"
  | "rate_limit_hit";

export interface AuditRecord {
  id: string;
  event_type: AuditEventType;
  severity: "info" | "warning" | "critical";
  timestamp: string;
  api_key_id: string;
  actor_address?: string;
  sign_request_id?: string;
  signer_address?: string;
  chain_type?: string;
  chain_id?: string;
  rule_id?: string;
  details?: Record<string, any>;
  error_message?: string;
  request_method?: string;
  request_path?: string;
}

export interface ListAuditFilter {
  event_type?: AuditEventType;
  severity?: "info" | "warning" | "critical";
  api_key_id?: string;
  signer_address?: string;
  chain_type?: string;
  chain_id?: string;
  start_time?: string; // RFC3339
  end_time?: string; // RFC3339
  limit?: number;
  cursor?: string;
  cursor_id?: string;
}

export interface ListAuditResponse {
  records: AuditRecord[];
  total: number;
  next_cursor?: string;
  next_cursor_id?: string;
  has_more: boolean;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class AuditService {
  constructor(private readonly transport: HttpTransport) {}

  /**
   * List audit log records with optional filters.
   */
  async list(filter?: ListAuditFilter): Promise<ListAuditResponse> {
    const params = new URLSearchParams();
    if (filter?.event_type) {
      params.append("event_type", filter.event_type);
    }
    if (filter?.severity) {
      params.append("severity", filter.severity);
    }
    if (filter?.api_key_id) {
      params.append("api_key_id", filter.api_key_id);
    }
    if (filter?.signer_address) {
      params.append("signer_address", filter.signer_address);
    }
    if (filter?.chain_type) {
      params.append("chain_type", filter.chain_type);
    }
    if (filter?.chain_id) {
      params.append("chain_id", filter.chain_id);
    }
    if (filter?.start_time) {
      params.append("start_time", filter.start_time);
    }
    if (filter?.end_time) {
      params.append("end_time", filter.end_time);
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
    const path = `/api/v1/audit${queryString ? `?${queryString}` : ""}`;

    return this.transport.request<ListAuditResponse>("GET", path, null);
  }
}
