import type { RemoteSigner } from "./remote_signer";
import type { RemoteSignerClient } from "../client";

/**
 * Three modes for initializing the provider's signer list
 */
export type SignersSource =
  /**
   * Auto-fetch all available signers from remote-signer backend
   * Filters for enabled and unlocked signers
   * @example
   * { type: "client", client: remoteSignerClient, chainId: 1 }
   */
  | {
      type: "client";
      client: RemoteSignerClient;
      chainId?: number;
    }

  /**
   * Batch derive signers from an HD wallet
   * @example
   * {
   *   type: "hdwallet",
   *   client: remoteSignerClient,
   *   primaryAddress: "0x...",
   *   chainId: "1",
   *   start: 0,
   *   count: 10
   * }
   */
  | {
      type: "hdwallet";
      client: RemoteSignerClient;
      primaryAddress: string;
      chainId: string;
      start?: number;
      count?: number;
    }

  /**
   * Provide a pre-created array of RemoteSigner instances
   * @example
   * { type: "manual", signers: [signer1, signer2] }
   */
  | {
      type: "manual";
      signers: RemoteSigner[];
    };

/**
 * Configuration for EIP-1193 Provider
 */
export interface EIP1193ProviderConfig {
  /**
   * How to initialize the signer list (required)
   */
  signersSource: SignersSource;

  /**
   * Default chain ID to use (optional, defaults to 1 for Ethereum mainnet)
   */
  defaultChainId?: number;

  /**
   * Default active account index (optional, defaults to 0)
   */
  defaultAccountIndex?: number;

  /**
   * Override RPC URLs for specific chain IDs
   * @example
   * { 1: "https://eth-mainnet.alchemyapi.io/v2/...", 137: "https://polygon-rpc.com" }
   */
  rpcOverrides?: Record<number, string>;

  /**
   * Dynamic RPC URL resolver function
   * Called when a chain ID is not found in rpcOverrides
   * @example
   * (chainId) => `https://rpc.chain-${chainId}.example.com`
   */
  rpcResolver?: (chainId: number) => string | Promise<string>;
}

/**
 * EIP-1193 request arguments
 */
export interface RequestArguments {
  readonly method: string;
  readonly params?: readonly unknown[] | object;
}

/**
 * EIP-1193 ProviderConnectInfo
 */
export interface ProviderConnectInfo {
  readonly chainId: string;
}

/**
 * EIP-1193 ProviderMessage
 */
export interface ProviderMessage {
  readonly type: string;
  readonly data: unknown;
}
