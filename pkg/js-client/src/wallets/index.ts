/**
 * Wallet (collection) service: groups signer addresses under a named
 * container. This is an organizational concept — wallets are NOT multi-sig
 * smart contracts, just labels/folders the operator uses to bundle related
 * signers (per-strategy / per-chain / per-environment).
 */

import { HttpTransport } from "../transport";

export interface Wallet {
  id: string;
  name: string;
  description?: string;
  owner_id?: string;
  member_count?: number;
  created_at: string;
  updated_at: string;
}

export interface WalletMember {
  wallet_id: string;
  signer_address: string;
  wallet_type?: string;
  added_at: string;
}

export interface CreateWalletRequest {
  name: string;
  description?: string;
}

export interface ListWalletsFilter {
  offset?: number;
  limit?: number;
}

export interface ListWalletsResponse {
  wallets: Wallet[];
  total: number;
  has_more: boolean;
}

export interface AddWalletMemberRequest {
  signer_address: string;
}

export interface ListWalletMembersResponse {
  members: WalletMember[];
}

export class WalletService {
  constructor(private readonly transport: HttpTransport) {}

  async list(filter?: ListWalletsFilter): Promise<ListWalletsResponse> {
    const params = new URLSearchParams();
    if (filter?.offset !== undefined)
      params.append("offset", String(filter.offset));
    if (filter?.limit !== undefined)
      params.append("limit", String(filter.limit));
    const qs = params.toString();
    return this.transport.request<ListWalletsResponse>(
      "GET",
      `/api/v1/wallets${qs ? `?${qs}` : ""}`,
      null,
    );
  }

  async get(id: string): Promise<Wallet> {
    return this.transport.request<Wallet>(
      "GET",
      `/api/v1/wallets/${encodeURIComponent(id)}`,
      null,
    );
  }

  async create(req: CreateWalletRequest): Promise<Wallet> {
    return this.transport.request<Wallet>("POST", "/api/v1/wallets", req);
  }

  async delete(id: string): Promise<void> {
    await this.transport.request<void>(
      "DELETE",
      `/api/v1/wallets/${encodeURIComponent(id)}`,
      null,
    );
  }

  async listMembers(walletID: string): Promise<ListWalletMembersResponse> {
    return this.transport.request<ListWalletMembersResponse>(
      "GET",
      `/api/v1/wallets/${encodeURIComponent(walletID)}/members`,
      null,
    );
  }

  async addMember(
    walletID: string,
    req: AddWalletMemberRequest,
  ): Promise<WalletMember> {
    return this.transport.request<WalletMember>(
      "POST",
      `/api/v1/wallets/${encodeURIComponent(walletID)}/members`,
      req,
    );
  }

  async removeMember(walletID: string, signerAddress: string): Promise<void> {
    await this.transport.request<void>(
      "DELETE",
      `/api/v1/wallets/${encodeURIComponent(walletID)}/members/${encodeURIComponent(signerAddress)}`,
      null,
    );
  }
}
