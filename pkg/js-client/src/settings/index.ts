/**
 * Settings service: read runtime-mutable configuration groups.
 *
 * The daemon exposes nine groups (security, notify, audit_monitor, web,
 * plus five evm.*) each backed by a different snapshot shape. For now
 * we only model the read path — every group returns whatever JSON the
 * server emits as a Record<string, unknown>, so the UI can render
 * key/value rows generically. Typed snapshots can be layered on later
 * if a consumer needs them.
 */

import { HttpTransport } from "../transport";

export type SettingsGroup =
  | "security"
  | "notify"
  | "audit_monitor"
  | "web"
  | "evm.dynamic_blocklist"
  | "evm.simulation"
  | "evm.foundry"
  | "evm.rpc_gateway"
  | "evm.material_check";

export const SETTINGS_GROUPS: SettingsGroup[] = [
  "security",
  "notify",
  "audit_monitor",
  "web",
  "evm.dynamic_blocklist",
  "evm.simulation",
  "evm.foundry",
  "evm.rpc_gateway",
  "evm.material_check",
];

export type SettingsSnapshot = Record<string, unknown>;

export class SettingsService {
  constructor(private readonly transport: HttpTransport) {}

  /** Fetches the current snapshot for one group. */
  async get(group: SettingsGroup): Promise<SettingsSnapshot> {
    return this.transport.request<SettingsSnapshot>(
      "GET",
      `/api/v1/admin/settings/${group}`,
      null,
    );
  }

  /**
   * Replaces the snapshot for one group. The daemon validates the shape per
   * group; bad input returns 400 with the validation error in the body.
   */
  async put(
    group: SettingsGroup,
    snapshot: SettingsSnapshot,
  ): Promise<SettingsSnapshot> {
    return this.transport.request<SettingsSnapshot>(
      "PUT",
      `/api/v1/admin/settings/${group}`,
      snapshot,
    );
  }
}
