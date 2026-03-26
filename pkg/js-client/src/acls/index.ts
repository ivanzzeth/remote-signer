/**
 * ACLs service: read-only access to IP whitelist configuration.
 */

import { HttpTransport } from "../transport";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface IPWhitelistResponse {
  enabled: boolean;
  allowed_ips: string[];
  trust_proxy: boolean;
  trusted_proxies: string[];
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class ACLService {
  constructor(private readonly transport: HttpTransport) {}

  /**
   * Get IP whitelist configuration (admin only).
   */
  async getIPWhitelist(): Promise<IPWhitelistResponse> {
    return this.transport.request<IPWhitelistResponse>(
      "GET",
      "/api/v1/acls/ip-whitelist",
      null,
    );
  }
}
