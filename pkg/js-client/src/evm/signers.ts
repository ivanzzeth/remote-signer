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
}
