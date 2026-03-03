/**
 * Template service: CRUD operations, instantiation, and instance revocation.
 */

import { HttpTransport } from "../transport";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TemplateVariable {
  name: string;
  type: string;
  description?: string;
  required: boolean;
  default?: string;
}

export interface Template {
  id: string;
  name: string;
  description?: string;
  type: string;
  mode: string;
  source: string;
  variables?: TemplateVariable[];
  config?: Record<string, any>;
  budget_metering?: Record<string, any>;
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
}

export interface InstantiateResponse {
  rule: Record<string, any>;
  budget?: Record<string, any>;
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
   * Revoke (delete) a rule instance created from a template.
   */
  async revokeInstance(ruleID: string): Promise<RevokeInstanceResponse> {
    return this.transport.request<RevokeInstanceResponse>(
      "DELETE",
      `/api/v1/templates/instances/${ruleID}`,
      null,
    );
  }
}
