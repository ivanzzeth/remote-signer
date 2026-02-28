/**
 * EVM signer service: list and create keystore signers.
 */

import { HttpTransport } from "../transport";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SignerInfo {
  address: string;
  chain_type: string;
  enabled: boolean;
  source: string; // "config" | "api"
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

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class EvmSignerService {
  constructor(private readonly transport: HttpTransport) {}

  /**
   * List all available signers.
   */
  async list(): Promise<ListSignersResponse> {
    return this.transport.request<ListSignersResponse>(
      "GET",
      "/api/v1/evm/signers",
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
}
