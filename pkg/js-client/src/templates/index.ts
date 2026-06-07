/**
 * Template service: CRUD operations, instantiation, and instance revocation.
 */

import { HttpTransport } from "../transport";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Canonical variable type tags (v0.3). Matches internal/core/types
 * VarType* constants. The frontend dispatches widget choice on this
 * value: address → checksum-aware input, bool → switch, bigint →
 * big-integer-safe number input, enum → select bound to Options, etc.
 */
export type VariableType =
  | "address"
  | "address_list"
  | "bigint"
  | "bigint_list"
  | "string"
  | "bool"
  | "bytes"
  | "bytes4"
  | "duration"
  | "enum"
  | "json";

export interface TemplateVariable {
  name: string;
  type: VariableType;
  /** UI display label; falls back to `name` when empty. */
  label?: string;
  description?: string;
  required: boolean;
  /** Default value. Type follows `type`; the frontend coerces at render. */
  default?: unknown;
  placeholder?: string;
  hint?: string;
  /** Legal values for `type: "enum"`. */
  options?: string[];
  /** Mask in UI, redact in audit log. */
  sensitive?: boolean;
  /** Optional regex applied after type-specific format check. */
  pattern?: string;
  /** Numeric bounds (decimal big-int for bigint, Go duration for duration). */
  min?: string;
  max?: string;
}

/**
 * Optional UI grouping hint for long variable lists. The frontend
 * renders one collapsible section per group; variables not in any
 * group fall into a trailing "Other" section.
 */
export interface VariableGroup {
  title: string;
  description?: string;
  variables: string[];
}

export interface Template {
  id: string;
  name: string;
  description?: string;
  type: string;
  mode: string;
  source: string;
  /** Chain family (e.g. "evm"); empty for off-chain templates. */
  chain_type?: string;
  variables?: TemplateVariable[];
  /** UI grouping hint (v0.3+); empty = flat list. */
  variable_groups?: VariableGroup[];
  config?: Record<string, any>;
  budget_metering?: Record<string, any>;
  /** Origin tag: "config", "file" (Registry), "api". */
  source_path?: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface ListTemplatesFilter {
  type?: string;
  source?: string;
  enabled?: boolean;
  limit?: number;
  offset?: number;
}

export interface ListTemplatesResponse {
  templates: Template[];
  total: number;
}

export interface CreateTemplateRequest {
  name: string;
  description?: string;
  type: string;
  mode: string;
  variables?: TemplateVariable[];
  config: Record<string, any>;
  budget_metering?: Record<string, any>;
  test_variables?: Record<string, string>;
  enabled: boolean;
}

export interface UpdateTemplateRequest {
  name?: string;
  description?: string;
  config?: Record<string, any>;
  enabled?: boolean;
}

export interface BudgetConfig {
  max_total: string;
  max_per_tx: string;
  max_tx_count?: number;
  alert_pct?: number;
}

export interface ScheduleConfig {
  period: string;
  start_at?: string;
}

export interface InstantiateRequest {
  template_name?: string;
  name?: string;
  variables: Record<string, string>;
  chain_type?: string;
  chain_id?: string;
  api_key_id?: string;
  signer_address?: string;
  expires_at?: string;
  expires_in?: string;
  budget?: BudgetConfig;
  schedule?: ScheduleConfig;
  // FORCED VALIDATION — do not send skip_validation. Server rejects it (fund-loss risk).
  // skip_validation?: boolean;
}

export interface InstantiateResponse {
  rule: Record<string, any>;
  budget?: Record<string, any>;
}

/** Result of a single test case validation */
export interface ValidateTestResult {
  name: string;
  passed: boolean;
  actual_pass: boolean;
  reason?: string;
}

/** Result of a single rule validation */
export interface ValidateRuleResultItem {
  rule_name: string;
  type: string;
  mode: string;
  valid: boolean;
  error?: string;
  results?: ValidateTestResult[];
}

/** Response from POST /api/v1/templates/{id}/validate */
export interface ValidateTemplateResponse {
  template_id: string;
  template_name: string;
  results: ValidateRuleResultItem[];
  total: number;
  passed: number;
  failed: number;
}

export interface RevokeInstanceResponse {
  status: string;
  rule_id: string;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class TemplateService {
  constructor(private readonly transport: HttpTransport) {}

  /**
   * List templates with optional filters.
   */
  async list(filter?: ListTemplatesFilter): Promise<ListTemplatesResponse> {
    const params = new URLSearchParams();
    if (filter?.type) params.append("type", filter.type);
    if (filter?.source) params.append("source", filter.source);
    if (filter?.enabled !== undefined) params.append("enabled", String(filter.enabled));
    if (filter?.limit) params.append("limit", filter.limit.toString());
    if (filter?.offset) params.append("offset", filter.offset.toString());
    const qs = params.toString();
    return this.transport.request<ListTemplatesResponse>(
      "GET",
      `/api/v1/templates${qs ? `?${qs}` : ""}`,
      null,
    );
  }

  /**
   * Get a template by ID.
   */
  async get(templateID: string): Promise<Template> {
    return this.transport.request<Template>(
      "GET",
      `/api/v1/templates/${templateID}`,
      null,
    );
  }

  /**
   * Create a new template.
   */
  async create(req: CreateTemplateRequest): Promise<Template> {
    return this.transport.request<Template>(
      "POST",
      "/api/v1/templates",
      req,
    );
  }

  /**
   * Update an existing template.
   */
  async update(templateID: string, req: UpdateTemplateRequest): Promise<Template> {
    return this.transport.request<Template>(
      "PATCH",
      `/api/v1/templates/${templateID}`,
      req,
    );
  }

  /**
   * Delete a template.
   */
  async delete(templateID: string): Promise<void> {
    await this.transport.request<void>(
      "DELETE",
      `/api/v1/templates/${templateID}`,
      null,
    );
  }

  /**
   * Instantiate a template into a concrete rule.
   */
  async instantiate(templateID: string, req: InstantiateRequest): Promise<InstantiateResponse> {
    return this.transport.request<InstantiateResponse>(
      "POST",
      `/api/v1/templates/${templateID}/instantiate`,
      req,
    );
  }

  /**
   * Validate test cases for a template.
   */
  async validate(templateID: string): Promise<ValidateTemplateResponse> {
    return this.transport.request<ValidateTemplateResponse>(
      "POST",
      `/api/v1/templates/${templateID}/validate`,
      null,
    );
  }

  /**
   * Revoke (delete) a rule instance created from a template.
   */
  async revokeInstance(ruleID: string): Promise<RevokeInstanceResponse> {
    return this.transport.request<RevokeInstanceResponse>(
      "POST",
      `/api/v1/templates/instances/${ruleID}/revoke`,
      null,
    );
  }
}
