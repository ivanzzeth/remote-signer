/**
 * Presets service: list, inspect, and apply rule presets.
 */

import { HttpTransport } from "../transport";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PresetEntry {
  id: string;
  /** Human-readable name from the preset YAML (`name:`); empty for ad-hoc presets. */
  name?: string;
  /** Chain scope, e.g. "evm". */
  chain_type?: string;
  /** Chain ID, e.g. "1" for Ethereum mainnet. */
  chain_id?: string;
  template_names: string[];
}

export interface ListPresetsResponse {
  presets: PresetEntry[];
}

/** Rich variable metadata for a preset's override hint. */
export interface PresetVariableDetail {
  name: string;
  type?: string;
  description?: string;
  default_value?: string;
  required: boolean;
}

/** GET /api/v1/presets/{id} response. */
export interface PresetDetail {
  id: string;
  name?: string;
  chain_type?: string;
  chain_id?: string;
  enabled: boolean;
  template_names: string[];
  variables: PresetVariableDetail[];
}

export interface ApplyPresetRequest {
  variables?: Record<string, string>;
  applied_to?: string[];
}

export interface ApplyResultItem {
  rule: Record<string, any>;
  budget?: Record<string, any>;
}

export interface ApplyPresetResponse {
  results: ApplyResultItem[];
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class PresetService {
  constructor(private readonly transport: HttpTransport) {}

  /**
   * List all available presets (admin only).
   */
  async list(): Promise<ListPresetsResponse> {
    return this.transport.request<ListPresetsResponse>(
      "GET",
      "/api/v1/presets",
      null,
    );
  }

  /**
   * Get the full detail for a preset: identity, chain, template names,
   * and each override hint resolved against the referenced template's
   * variable definition (type/description/default). Replaces the old
   * /vars endpoint which only returned bare hint names.
   */
  async get(id: string): Promise<PresetDetail> {
    return this.transport.request<PresetDetail>(
      "GET",
      `/api/v1/presets/${encodeURIComponent(id)}`,
      null,
    );
  }

  /**
   * Apply a preset to create rule/template instances (admin only).
   */
  async apply(
    id: string,
    req: ApplyPresetRequest,
  ): Promise<ApplyPresetResponse> {
    return this.transport.request<ApplyPresetResponse>(
      "POST",
      `/api/v1/presets/${encodeURIComponent(id)}/apply`,
      req,
    );
  }

  /**
   * Convenience: apply a preset with just variables (no applied_to).
   */
  async applyWithVariables(
    id: string,
    variables: Record<string, string>,
  ): Promise<ApplyPresetResponse> {
    return this.apply(id, { variables });
  }
}
