/**
 * EVM HD wallet service: create, import, list, derive, and list derived addresses.
 */

import { HttpTransport } from "../transport";
import type { EvmSignService } from "./sign";
import { RemoteSigner } from "./remote_signer";
import type { SignerInfo } from "./signers";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CreateHDWalletRequest {
  action?: "create" | "import"; // default: "create"
  password: string;
  mnemonic?: string; // required for import
  entropy_bits?: number; // for create, default 256
}

export interface HDWalletResponse {
  primary_address: string;
  base_path: string;
  derived_count: number;
  derived?: SignerInfo[];
}

export interface ListHDWalletsResponse {
  wallets: HDWalletResponse[];
}

export interface DeriveAddressRequest {
  index?: number;
  start?: number;
  count?: number;
}

export interface DeriveAddressResponse {
  derived: SignerInfo[];
}

export interface ListDerivedAddressesResponse {
  derived: SignerInfo[];
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class EvmHDWalletService {
  constructor(
    private readonly transport: HttpTransport,
    private readonly signService: EvmSignService,
  ) {}

  /**
   * Create a new HD wallet.
   */
  async create(req: CreateHDWalletRequest): Promise<HDWalletResponse> {
    return this.transport.request<HDWalletResponse>(
      "POST",
      "/api/v1/evm/hd-wallets",
      { action: "create", ...req },
    );
  }

  /**
   * Import an HD wallet from a mnemonic.
   */
  async import(req: CreateHDWalletRequest): Promise<HDWalletResponse> {
    return this.transport.request<HDWalletResponse>(
      "POST",
      "/api/v1/evm/hd-wallets",
      { action: "import", ...req },
    );
  }

  /**
   * List all HD wallets.
   */
  async list(): Promise<ListHDWalletsResponse> {
    return this.transport.request<ListHDWalletsResponse>(
      "GET",
      "/api/v1/evm/hd-wallets",
      null,
    );
  }

  /**
   * Derive address(es) from an HD wallet.
   */
  async deriveAddress(
    primaryAddr: string,
    req: DeriveAddressRequest,
  ): Promise<DeriveAddressResponse> {
    return this.transport.request<DeriveAddressResponse>(
      "POST",
      `/api/v1/evm/hd-wallets/${primaryAddr}/derive`,
      req,
    );
  }

  /**
   * List derived addresses for an HD wallet.
   */
  async listDerived(
    primaryAddr: string,
  ): Promise<ListDerivedAddressesResponse> {
    return this.transport.request<ListDerivedAddressesResponse>(
      "GET",
      `/api/v1/evm/hd-wallets/${primaryAddr}/derived`,
      null,
    );
  }

  /**
   * Derive (if needed) the address at the given index and return a RemoteSigner.
   * The RemoteSigner provides convenience methods (signHash, personalSign, etc.)
   * mirroring the Go client's RemoteSigner.
   */
  async getSigner(
    primaryAddr: string,
    chainId: string,
    index: number,
  ): Promise<RemoteSigner> {
    const resp = await this.deriveAddress(primaryAddr, { index });
    if (!resp.derived.length) {
      throw new Error(`no address derived at index ${index}`);
    }
    return new RemoteSigner(this.signService, resp.derived[0].address, chainId);
  }

  /**
   * Derive a batch of addresses and return RemoteSigner instances.
   */
  async getSigners(
    primaryAddr: string,
    chainId: string,
    start: number,
    count: number,
  ): Promise<RemoteSigner[]> {
    const resp = await this.deriveAddress(primaryAddr, { start, count });
    return resp.derived.map(
      (d) => new RemoteSigner(this.signService, d.address, chainId),
    );
  }
}
