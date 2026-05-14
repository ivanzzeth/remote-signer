/**
 * Registry service: hot-reload templates and presets from disk without
 * restarting the daemon.
 *
 * Use case: the operator edits a YAML in rules/templates/ or
 * rules/presets/, then calls `client.registry.refresh()` to make the
 * change visible. Maps to POST /api/v1/registry/refresh server-side.
 *
 * Requires apply_preset permission — admin-only, same gate as preset
 * apply, because refresh can prune rows whose source file was removed.
 */

import { HttpTransport } from "../transport";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RegistryRefreshError {
  /** Stable ID (file-stem). May be empty when the parse failed before
   * the ID could be derived. */
  id?: string;
  /** Relative source path; always set so the operator can find the file. */
  path?: string;
  /** Human-readable error message. */
  error: string;
}

export interface RegistryRefreshReport {
  /** Source kind label, e.g. "file" for the local FileSource. */
  source: string;
  /** Rows whose ContentHash differed and were inserted or updated. */
  changed: number;
  /** Rows whose ContentHash matched the stored value (no write). */
  skipped: number;
  /** Rows present in DB but missing from the source list (pruned). */
  deleted: number;
  /** Per-item parse failures; the rest of the sync still succeeded. */
  errors?: RegistryRefreshError[];
}

export interface RegistryRefreshResponse {
  templates: RegistryRefreshReport;
  presets: RegistryRefreshReport;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class RegistryService {
  constructor(private readonly transport: HttpTransport) {}

  /**
   * Re-run Template + Preset Registry sync against disk. Returns one
   * report per kind. Per-file errors come back as entries on
   * `templates.errors` / `presets.errors` — the rest of the sync still
   * went through, so the operator can fix one file at a time.
   */
  async refresh(): Promise<RegistryRefreshResponse> {
    return this.transport.request<RegistryRefreshResponse>(
      "POST",
      "/api/v1/registry/refresh",
      null,
    );
  }
}
