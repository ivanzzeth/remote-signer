/**
 * EVM signer service: list and create keystore signers.
 */

import { HttpTransport } from "../transport";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SignerInfo {
  address: string;
  type: string;
  enabled: boolean;
  locked: boolean;
  /** Ownership state: "active" or "pending_approval". Empty for legacy signers. */
  status?: string;
  owner_id?: string;
  display_name?: string;
  tags?: string[];
  /** True for HD-derived child addresses (the parent address is in primary_address). */
  primary_address?: string;
  hd_derivation_index?: number;
  /** Local keystore material: present, missing, corrupted. */
  material_status?: string;
  material_checked_at?: string;
  material_missing_at?: string;
  material_error?: string;
}

export interface ListSignersFilter {
  type?: string;
  /**
   * Restrict the listing to signers owned-by or accessible-to this API
   * key. Admins can target any key; non-admins must omit or pass their
   * own ID — the daemon 403s any other value to prevent cross-key
   * privilege probing.
   */
  api_key_id?: string;
  /** Tri-state: true / false / undefined (either). */
  locked?: boolean;
  /** Tri-state: true / false / undefined (either). */
  enabled?: boolean;
  /**
   * Admin-only global queue filter. When set to `pending_approval`, returns
   * every signer awaiting admin approval across all API keys.
   */
  ownership_status?: "pending_approval";
  offset?: number;
  limit?: number;
}

export interface ListSignersResponse {
  signers: SignerInfo[];
  total?: number;
  has_more?: boolean;
}

/**
 * Parameters for keystore-backed signer creation. Set at most one of
 * private_key_hex / keystore_json — leaving both empty creates a fresh
 * keypair.
 */
export interface CreateKeystoreParams {
  password: string;
  /**
   * Raw secp256k1 private key (64 hex chars, with or without 0x prefix).
   * When set the daemon imports the key into a new encrypted keystore.
   */
  private_key_hex?: string;
  /**
   * Full v3 keystore JSON (as written by `remote-signer keystore create`
   * or any compatible tool). The daemon decrypts with `password`, then
   * re-encrypts under its keystore dir.
   */
  keystore_json?: string;
}

/**
 * Body shape for POST /api/v1/evm/signers. The daemon supports one signer
 * `type` today (`"keystore"`); future types (e.g. HSM, MPC) would be
 * disjoint top-level options, hence the nested params rather than a flat
 * `password` field.
 */
export interface CreateSignerRequest {
  type: string;
  keystore?: CreateKeystoreParams;
  display_name?: string;
  tags?: string[];
}

export interface CreateSignerResponse {
  address: string;
  type: string;
  enabled: boolean;
  display_name?: string;
  tags?: string[];
}

export interface UnlockSignerRequest {
  password: string;
}

export interface UnlockSignerResponse {
  address: string;
  type: string;
  enabled: boolean;
  locked: boolean;
}

export interface LockSignerResponse {
  address: string;
  type: string;
  enabled: boolean;
  locked: boolean;
}

export interface GrantAccessRequest {
  api_key_id: string;
}

export interface TransferOwnershipRequest {
  new_owner_id: string;
}

export interface SignerAccessEntry {
  api_key_id: string;
  granted_by: string;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class EvmSignerService {
  constructor(private readonly transport: HttpTransport) {}

  /**
   * List signers with optional filters.
   */
  async list(filter?: ListSignersFilter): Promise<ListSignersResponse> {
    const params = new URLSearchParams();
    if (filter?.type) params.append("type", filter.type);
    if (filter?.api_key_id) params.append("api_key_id", filter.api_key_id);
    if (typeof filter?.locked === "boolean") {
      params.append("locked", String(filter.locked));
    }
    if (typeof filter?.enabled === "boolean") {
      params.append("enabled", String(filter.enabled));
    }
    if (filter?.ownership_status) {
      params.append("ownership_status", filter.ownership_status);
    }
    if (filter?.offset) params.append("offset", filter.offset.toString());
    if (filter?.limit) params.append("limit", filter.limit.toString());
    const qs = params.toString();
    return this.transport.request<ListSignersResponse>(
      "GET",
      `/api/v1/evm/signers${qs ? `?${qs}` : ""}`,
      null,
    );
  }

  /**
   * Create a new keystore signer.
   */
  async create(req: CreateSignerRequest): Promise<CreateSignerResponse> {
    return this.transport.request<CreateSignerResponse>(
      "POST",
      "/api/v1/evm/signers",
      req,
    );
  }

  /**
   * Unlock a locked signer (admin only).
   */
  async unlock(
    address: string,
    req: UnlockSignerRequest,
  ): Promise<UnlockSignerResponse> {
    return this.transport.request<UnlockSignerResponse>(
      "POST",
      `/api/v1/evm/signers/${address}/unlock`,
      req,
    );
  }

  /**
   * Lock an unlocked signer (admin only).
   */
  async lock(address: string): Promise<LockSignerResponse> {
    return this.transport.request<LockSignerResponse>(
      "POST",
      `/api/v1/evm/signers/${address}/lock`,
      null,
    );
  }

  /**
   * Approve a pending signer (admin only).
   */
  async approveSigner(address: string): Promise<void> {
    await this.transport.request<void>(
      "POST",
      `/api/v1/evm/signers/${address}/approve`,
      null,
    );
  }

  /**
   * Grant access to a signer for another API key (owner only).
   */
  async grantAccess(address: string, req: GrantAccessRequest): Promise<void> {
    await this.transport.request<void>(
      "POST",
      `/api/v1/evm/signers/${address}/access`,
      req,
    );
  }

  /**
   * Revoke access from a signer for an API key (owner only).
   */
  async revokeAccess(address: string, apiKeyId: string): Promise<void> {
    await this.transport.request<void>(
      "DELETE",
      `/api/v1/evm/signers/${address}/access/${apiKeyId}`,
      null,
    );
  }

  /**
   * List access grants for a signer (owner only).
   */
  async listAccess(address: string): Promise<SignerAccessEntry[]> {
    const list = await this.transport.request<SignerAccessEntry[]>(
      "GET",
      `/api/v1/evm/signers/${address}/access`,
      null,
    );
    return list ?? [];
  }

  /**
   * Transfer signer ownership to a new API key (owner only).
   * Clears the entire access list; old owner loses ALL access.
   */
  async transferOwnership(address: string, req: TransferOwnershipRequest): Promise<void> {
    await this.transport.request<void>(
      "POST",
      `/api/v1/evm/signers/${address}/transfer`,
      req,
    );
  }

  /**
   * Delete a signer's ownership and access records (owner only).
   */
  async deleteSigner(address: string): Promise<void> {
    await this.transport.request<void>(
      "DELETE",
      `/api/v1/evm/signers/${address}`,
      null,
    );
  }
}
