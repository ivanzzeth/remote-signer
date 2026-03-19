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
}

export interface ListSignersFilter {
  type?: string;
  offset?: number;
  limit?: number;
}

export interface ListSignersResponse {
  signers: SignerInfo[];
}

export interface CreateSignerRequest {
  password: string;
}

export interface CreateSignerResponse {
  address: string;
  message: string;
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
