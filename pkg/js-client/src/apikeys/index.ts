/**
 * API Keys service: CRUD operations for API key management.
 */

import { HttpTransport } from "../transport";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface APIKey {
  id: string;
  name: string;
  source: string;
  role: string; // admin, dev, agent, strategy
  enabled: boolean;
  rate_limit: number;
  created_at: string;
  updated_at: string;
  last_used_at?: string;
  expires_at?: string;
}

export interface ListAPIKeysFilter {
  source?: string;
  enabled?: boolean;
  limit?: number;
  offset?: number;
}

export interface ListAPIKeysResponse {
  keys: APIKey[];
  total: number;
}

/**
 * Lightweight projection returned by GET /api/v1/api-keys/names —
 * accessible to any authenticated key (no `manage_api_keys` perm
 * required), so non-admin operators can populate Grant-access or
 * filter dropdowns without seeing audit-relevant metadata.
 */
export interface APIKeyName {
  id: string;
  name: string;
  role: string;
  enabled: boolean;
}

export interface ListAPIKeyNamesResponse {
  keys: APIKeyName[];
}

export interface CreateAPIKeyRequest {
  id: string;
  name: string;
  public_key: string;
  role: string; // admin, dev, agent, strategy
  rate_limit?: number;
}

export interface UpdateAPIKeyRequest {
  name?: string;
  enabled?: boolean;
  role?: string; // admin, dev, agent, strategy
  rate_limit?: number;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class APIKeyService {
  constructor(private readonly transport: HttpTransport) {}

  /**
   * List API keys with optional filters.
   */
  async list(filter?: ListAPIKeysFilter): Promise<ListAPIKeysResponse> {
    const params = new URLSearchParams();
    if (filter?.source) params.append("source", filter.source);
    if (filter?.enabled !== undefined)
      params.append("enabled", String(filter.enabled));
    if (filter?.limit) params.append("limit", filter.limit.toString());
    if (filter?.offset) params.append("offset", filter.offset.toString());
    const qs = params.toString();
    return this.transport.request<ListAPIKeysResponse>(
      "GET",
      `/api/v1/api-keys${qs ? `?${qs}` : ""}`,
      null,
    );
  }

  /**
   * Lightweight directory of every enabled API key, accessible to any
   * authenticated caller — feeds the Signers filter + Grant-access
   * dropdowns. Returns only id/name/role/enabled; audit-relevant
   * fields (timestamps, rate limit, source) are intentionally
   * stripped daemon-side.
   */
  async names(): Promise<ListAPIKeyNamesResponse> {
    return this.transport.request<ListAPIKeyNamesResponse>(
      "GET",
      "/api/v1/api-keys/names",
      null,
    );
  }

  /**
   * Get an API key by ID.
   */
  async get(id: string): Promise<APIKey> {
    return this.transport.request<APIKey>(
      "GET",
      `/api/v1/api-keys/${encodeURIComponent(id)}`,
      null,
    );
  }

  /**
   * Create a new API key (admin only).
   */
  async create(req: CreateAPIKeyRequest): Promise<APIKey> {
    return this.transport.request<APIKey>("POST", "/api/v1/api-keys", req);
  }

  /**
   * Update an API key (admin only).
   */
  async update(id: string, req: UpdateAPIKeyRequest): Promise<APIKey> {
    return this.transport.request<APIKey>(
      "PUT",
      `/api/v1/api-keys/${encodeURIComponent(id)}`,
      req,
    );
  }

  /**
   * Delete an API key (admin only).
   */
  async delete(id: string): Promise<void> {
    await this.transport.request<void>(
      "DELETE",
      `/api/v1/api-keys/${encodeURIComponent(id)}`,
      null,
    );
  }
}
