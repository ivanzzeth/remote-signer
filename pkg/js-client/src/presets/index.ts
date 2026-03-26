/**
 * Presets service: list, inspect, and apply rule presets.
 */

import { HttpTransport } from "../transport";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PresetEntry {
  id: string;
  template_names: string[];
}

export interface ListPresetsResponse {
  presets: PresetEntry[];
}

export interface PresetVarsResponse {
  override_hints: string[];
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
   * Get variable hints for a preset (admin only).
   */
  async vars(id: string): Promise<PresetVarsResponse> {
    return this.transport.request<PresetVarsResponse>(
      "GET",
      `/api/v1/presets/${encodeURIComponent(id)}/vars`,
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
