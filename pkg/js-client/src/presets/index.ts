/**
 * Presets service: list, inspect, and apply rule presets.
 *
 * v0.3 changes (Registry-backed):
 *   - `template_names` renamed to `template_ids` (file-stem IDs, stable
 *     across renames).
 *   - PresetEntry / PresetDetail gain a `description` field surfaced
 *     from the preset YAML.
 *   - Variables carry an `operator_overrides`-derived `required` flag
 *     that may be true even when the underlying template variable is
 *     optional — i.e. the preset author chose to require it.
 */

import { HttpTransport } from "../transport";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PresetEntry {
  id: string;
  /** Human-readable name from the preset YAML (`name:`). */
  name?: string;
  /** Short summary from the preset YAML (`description:`). */
  description?: string;
  /** Chain scope, e.g. "evm"; empty for off-chain presets. */
  chain_type?: string;
  /** Chain ID, e.g. "1" for Ethereum mainnet. */
  chain_id?: string;
  /** File-stem template IDs the preset bundles. */
  template_ids: string[];
  enabled: boolean;
}

export interface ListPresetsResponse {
  presets: PresetEntry[];
}

/**
 * Rich variable metadata for one operator-overridable preset variable.
 * Joins preset.operator_overrides (Required flag, ordering) against the
 * referenced template's variable definitions (type, description,
 * default).
 */
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
  description?: string;
  chain_type?: string;
  chain_id?: string;
  enabled: boolean;
  template_ids: string[];
  variables: PresetVariableDetail[];
}

export interface ApplyPresetRequest {
  variables?: Record<string, string>;
  applied_to?: string[];
  skip_validation?: boolean;
}

export interface ApplyResultItem {
  rule: Record<string, any>;
  budget?: Record<string, any>;
}

export interface ApplyPresetResponse {
  results: ApplyResultItem[];
}

/** Response from POST /api/v1/presets/{id}/validate */
export interface ValidatePresetResponse {
  preset_id: string;
  preset_name: string;
  results: import("../templates").ValidateRuleResultItem[];
  total: number;
  passed: number;
  failed: number;
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
   * Get the full detail for a preset: identity, chain, template ids, and
   * each operator-overridable variable joined against the referenced
   * template's variable definition (type/description/default).
   */
  async get(id: string): Promise<PresetDetail> {
    return this.transport.request<PresetDetail>(
      "GET",
      `/api/v1/presets/${encodeURIComponent(id)}`,
      null,
    );
  }

  /**
   * Apply a preset to create rule instances (admin only). Returns one
   * result entry per materialised rule.
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

  /**
   * Validate test cases for a preset (admin only).
   * Optionally override variables to test different configurations.
   */
  async validate(
    id: string,
    variables?: Record<string, string>,
  ): Promise<ValidatePresetResponse> {
    return this.transport.request<ValidatePresetResponse>(
      "POST",
      `/api/v1/presets/${encodeURIComponent(id)}/validate`,
      variables ? { variables } : null,
    );
  }
}
