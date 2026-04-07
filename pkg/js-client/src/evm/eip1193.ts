/**
 * EIP-1193 Ethereum Provider implementation with multi-account support
 * @see https://eips.ethereum.org/EIPS/eip-1193
 */

import { RemoteSigner } from "./remote_signer";
import { ProviderRpcError, providerErrors } from "./provider-errors";
import type {
  EIP1193ProviderConfig,
  SignersSource,
  RequestArguments,
  ProviderConnectInfo,
  ProviderMessage,
} from "./provider-types";

/**
 * EIP-1193 compliant Ethereum Provider with multi-account support
 *
 * Features:
 * - Multi-account management (switchAccount, addAccount, removeAccount)
 * - Three initialization modes (client auto-fetch, HD wallet derive, manual)
 * - Full EIP-1193 event system (connect, disconnect, chainChanged, accountsChanged, message)
 * - MetaMask compatibility (selectedAddress, isMetaMask, isConnected)
 * - Standard ProviderRpcError with EIP-1193 error codes
 *
 * @example
 * // Initialize from remote-signer client
 * const provider = await EIP1193Provider.create({
 *   signersSource: {
 *     type: "client",
 *     client: remoteSignerClient,
 *     chainId: 1
 *   }
 * });
 *
 * // Switch account
 * await provider.switchAccount(1); // by index
 * await provider.switchAccount("0x..."); // by address
 *
 * // Listen to events
 * provider.on("accountsChanged", (accounts) => console.log("Accounts:", accounts));
 */
export class EIP1193Provider {
  // Internal state
  private _signers: RemoteSigner[] = [];
  private _activeIndex: number = 0;
  private _chainId: number;
  private _connected: boolean = false;
  private _rpcOverrides: Record<number, string>;
  private _rpcResolver?: (chainId: number) => string | Promise<string>;

  // Event emitter
  private _eventHandlers: Map<string, Set<(...args: any[]) => void>> = new Map();

  // MetaMask compatibility flag
  public readonly isMetaMask = true;

  /**
   * Private constructor - use EIP1193Provider.create() instead
   */
  private constructor(config: EIP1193ProviderConfig) {
    this._chainId = config.defaultChainId ?? 1;
    this._activeIndex = config.defaultAccountIndex ?? 0;
    this._rpcOverrides = config.rpcOverrides ?? {};
    this._rpcResolver = config.rpcResolver;
  }

  /**
   * Create and initialize a new EIP-1193 Provider
   *
   * This async factory method replaces the constructor to support async initialization
   *
   * @param config Provider configuration with signersSource
   * @returns Initialized provider instance
   * @throws {ProviderRpcError} If initialization fails
   */
  public static async create(config: EIP1193ProviderConfig): Promise<EIP1193Provider> {
    const provider = new EIP1193Provider(config);
    await provider._initializeSigners(config.signersSource);

    // Validate active index
    if (provider._signers.length > 0) {
      if (provider._activeIndex >= provider._signers.length) {
        provider._activeIndex = 0;
      }
      provider._connected = true;

      // Emit connect event
      provider._emit("connect", {
        chainId: `0x${provider._chainId.toString(16)}`,
      } as ProviderConnectInfo);
    }

    return provider;
  }

  /**
   * Initialize signers from the configured source
   *
   * Supports three modes:
   * 1. client: Auto-fetch from remote-signer backend (filters enabled & unlocked)
   * 2. hdwallet: Batch derive from HD wallet
   * 3. manual: Use pre-created RemoteSigner array
   */
  private async _initializeSigners(source: SignersSource): Promise<void> {
    switch (source.type) {
      case "client": {
        // Auto-fetch all available signers from backend
        const { signers: signerInfos } = await source.client.evm.signers.list();

        // Filter for enabled and unlocked signers
        const validSigners = signerInfos.filter((s) => s.enabled && !s.locked);

        // Convert to RemoteSigner instances
        this._signers = validSigners.map((info) =>
          new RemoteSigner(
            source.client.evm.sign,
            info.address,
            source.chainId?.toString() ?? this._chainId.toString()
          )
        );
        break;
      }

      case "hdwallet": {
        // Batch derive from HD wallet
        const start = source.start ?? 0;
        const count = source.count ?? 10;

        this._signers = await source.client.evm.hdWallets.getSigners(
          source.primaryAddress,
          source.chainId,
          start,
          count
        );
        break;
      }

      case "manual": {
        // Use pre-created signers directly
        this._signers = [...source.signers];
        break;
      }

      default:
        throw new Error("Invalid signers source type");
    }
  }

  /**
   * Get current active account address
   * Returns null if not connected or no accounts
   */
  public get selectedAddress(): string | null {
    return this._connected && this._signers.length > 0
      ? this._signers[this._activeIndex].address
      : null;
  }

  /**
   * Get current chain ID as hex string
   */
  public get chainId(): string {
    return `0x${this._chainId.toString(16)}`;
  }

  /**
   * Check if provider is connected
   * Returns true only if connected AND has at least one account
   */
  public isConnected(): boolean {
    return this._connected && this._signers.length > 0;
  }

  /**
   * Get all account addresses (active account first)
   */
  private _getAccounts(): string[] {
    if (!this._connected || this._signers.length === 0) {
      return [];
    }

    // Return all accounts with active first
    const active = this._signers[this._activeIndex].address;
    const others = this._signers
      .filter((_, i) => i !== this._activeIndex)
      .map((s) => s.address);

    return [active, ...others];
  }

  /**
   * Get current active signer
   */
  private _getActiveSigner(): RemoteSigner {
    if (!this._connected || this._signers.length === 0) {
      throw providerErrors.disconnected();
    }
    return this._signers[this._activeIndex];
  }

  /**
   * Switch active account by address or index
   *
   * @param addressOrIndex Account address (string) or index (number)
   * @throws {ProviderRpcError} If account not found or provider disconnected
   */
  public async switchAccount(addressOrIndex: string | number): Promise<void> {
    if (!this._connected || this._signers.length === 0) {
      throw providerErrors.disconnected();
    }

    let newIndex: number;

    if (typeof addressOrIndex === "number") {
      // Switch by index
      if (addressOrIndex < 0 || addressOrIndex >= this._signers.length) {
        throw new Error(`Invalid account index: ${addressOrIndex}`);
      }
      newIndex = addressOrIndex;
    } else {
      // Switch by address
      const address = addressOrIndex.toLowerCase();
      newIndex = this._signers.findIndex((s) => s.address.toLowerCase() === address);

      if (newIndex === -1) {
        throw new Error(`Account not found: ${addressOrIndex}`);
      }
    }

    if (newIndex === this._activeIndex) {
      // Already active, no-op
      return;
    }

    this._activeIndex = newIndex;
    this._emit("accountsChanged", this._getAccounts());
  }

  /**
   * Add a new account to the provider
   *
   * @param signer RemoteSigner instance to add
   */
  public async addAccount(signer: RemoteSigner): Promise<void> {
    // Check if account already exists
    const exists = this._signers.some(
      (s) => s.address.toLowerCase() === signer.address.toLowerCase()
    );

    if (exists) {
      throw new Error(`Account already exists: ${signer.address}`);
    }

    this._signers.push(signer);

    // If this is the first account, set as active and mark connected
    if (this._signers.length === 1) {
      this._activeIndex = 0;
      this._connected = true;

      this._emit("connect", {
        chainId: this.chainId,
      } as ProviderConnectInfo);
    }

    this._emit("accountsChanged", this._getAccounts());
  }

  /**
   * Remove an account from the provider
   *
   * @param addressOrIndex Account address (string) or index (number)
   * @throws {Error} If account not found
   */
  public async removeAccount(addressOrIndex: string | number): Promise<void> {
    if (this._signers.length === 0) {
      throw new Error("No accounts to remove");
    }

    let indexToRemove: number;

    if (typeof addressOrIndex === "number") {
      if (addressOrIndex < 0 || addressOrIndex >= this._signers.length) {
        throw new Error(`Invalid account index: ${addressOrIndex}`);
      }
      indexToRemove = addressOrIndex;
    } else {
      const address = addressOrIndex.toLowerCase();
      indexToRemove = this._signers.findIndex(
        (s) => s.address.toLowerCase() === address
      );

      if (indexToRemove === -1) {
        throw new Error(`Account not found: ${addressOrIndex}`);
      }
    }

    // Remove the account
    this._signers.splice(indexToRemove, 1);

    // Adjust active index if necessary
    if (indexToRemove === this._activeIndex) {
      // Removed active account, switch to first available
      this._activeIndex = 0;
    } else if (indexToRemove < this._activeIndex) {
      // Removed account before active, adjust index
      this._activeIndex--;
    }

    // If no accounts left, disconnect
    if (this._signers.length === 0) {
      this._connected = false;
      this._emit("disconnect", providerErrors.disconnected("All accounts removed"));
    } else {
      this._emit("accountsChanged", this._getAccounts());
    }
  }

  /**
   * Disconnect provider and clear all accounts
   */
  public async disconnect(): Promise<void> {
    this._signers = [];
    this._activeIndex = 0;
    this._connected = false;

    this._emit("disconnect", providerErrors.disconnected("User disconnected"));
  }

  /**
   * Handle EIP-1193 JSON-RPC requests
   *
   * @param args Request arguments
   * @returns Promise resolving to the result
   */
  public async request(args: RequestArguments): Promise<unknown> {
    const { method, params } = args;

    switch (method) {
      // Account methods
      case "eth_accounts":
      case "eth_requestAccounts":
        return this._getAccounts();

      case "eth_coinbase":
        return this.selectedAddress;

      // Chain methods
      case "eth_chainId":
      case "net_version":
        return this.chainId;

      // Signing methods
      case "personal_sign": {
        const [message, address] = params as [string, string];
        const signer = this._getActiveSigner();

        // Verify address matches active signer
        if (address.toLowerCase() !== signer.address.toLowerCase()) {
          throw providerErrors.unauthorized(
            `Address mismatch: expected ${signer.address}, got ${address}`
          );
        }

        return await signer.personalSign(message);
      }

      case "eth_sign": {
        const [address, hash] = params as [string, string];
        const signer = this._getActiveSigner();

        if (address.toLowerCase() !== signer.address.toLowerCase()) {
          throw providerErrors.unauthorized(
            `Address mismatch: expected ${signer.address}, got ${address}`
          );
        }

        return await signer.signHash(hash);
      }

      case "eth_signTypedData":
      case "eth_signTypedData_v3":
      case "eth_signTypedData_v4": {
        const [address, typedData] = params as [string, any];
        const signer = this._getActiveSigner();

        if (address.toLowerCase() !== signer.address.toLowerCase()) {
          throw providerErrors.unauthorized(
            `Address mismatch: expected ${signer.address}, got ${address}`
          );
        }

        // signTypedData expects typed data object, handle both string and object
        const typedDataObj = typeof typedData === "string" ? JSON.parse(typedData) : typedData;
        return await signer.signTypedData(typedDataObj);
      }

      case "eth_sendTransaction": {
        const [tx] = params as [any];
        const signer = this._getActiveSigner();

        // Verify from address if provided
        if (tx.from && tx.from.toLowerCase() !== signer.address.toLowerCase()) {
          throw providerErrors.unauthorized(
            `Address mismatch: expected ${signer.address}, got ${tx.from}`
          );
        }

        const signedTx = await signer.signTransaction(tx);

        // Broadcast via RPC
        const rpcUrl = await this._getRpcUrl();
        const response = await fetch(rpcUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: Date.now(),
            method: "eth_sendRawTransaction",
            params: [signedTx],
          }),
        });

        const result: any = await response.json();
        if (result.error) {
          throw new Error(result.error.message);
        }
        return result.result;
      }

      case "eth_signTransaction": {
        const [tx] = params as [any];
        const signer = this._getActiveSigner();

        if (tx.from && tx.from.toLowerCase() !== signer.address.toLowerCase()) {
          throw providerErrors.unauthorized(
            `Address mismatch: expected ${signer.address}, got ${tx.from}`
          );
        }

        return await signer.signTransaction(tx);
      }

      // Read methods - delegate to RPC provider
      case "eth_blockNumber":
      case "eth_call":
      case "eth_estimateGas":
      case "eth_gasPrice":
      case "eth_getBalance":
      case "eth_getBlockByHash":
      case "eth_getBlockByNumber":
      case "eth_getCode":
      case "eth_getLogs":
      case "eth_getStorageAt":
      case "eth_getTransactionByHash":
      case "eth_getTransactionCount":
      case "eth_getTransactionReceipt": {
        const rpcUrl = await this._getRpcUrl();
        const response = await fetch(rpcUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: Date.now(),
            method,
            params: (params as any[]) ?? [],
          }),
        });

        const result: any = await response.json();
        if (result.error) {
          throw new Error(result.error.message);
        }
        return result.result;
      }

      // Unsupported methods
      default:
        throw providerErrors.unsupportedMethod(method);
    }
  }

  /**
   * Get RPC URL for the current chain
   */
  private async _getRpcUrl(): Promise<string> {
    let rpcUrl: string | undefined = this._rpcOverrides[this._chainId];

    if (!rpcUrl && this._rpcResolver) {
      rpcUrl = await this._rpcResolver(this._chainId);
    }

    if (!rpcUrl) {
      throw new Error(`No RPC URL configured for chain ${this._chainId}`);
    }

    return rpcUrl;
  }

  /**
   * Switch to a different chain
   *
   * @param chainId New chain ID (number or hex string)
   */
  public async switchChain(chainId: number | string): Promise<void> {
    const newChainId =
      typeof chainId === "string"
        ? parseInt(chainId.replace("0x", ""), 16)
        : chainId;

    if (newChainId === this._chainId) {
      return; // Already on this chain
    }

    const oldChainId = this._chainId;
    this._chainId = newChainId;

    // Update all signers to use new chain
    const chainIdStr = newChainId.toString();
    this._signers.forEach((signer) => {
      signer.setChainID(chainIdStr);
    });

    // Emit both chainChanged and accountsChanged (per EIP-1193)
    this._emit("chainChanged", `0x${newChainId.toString(16)}`);
    this._emit("accountsChanged", this._getAccounts());
  }

  /**
   * Register an event listener
   *
   * @param event Event name
   * @param handler Event handler function
   */
  public on(event: string, handler: (...args: any[]) => void): void {
    if (!this._eventHandlers.has(event)) {
      this._eventHandlers.set(event, new Set());
    }
    this._eventHandlers.get(event)!.add(handler);
  }

  /**
   * Unregister an event listener
   *
   * @param event Event name
   * @param handler Event handler function
   */
  public removeListener(event: string, handler: (...args: any[]) => void): void {
    const handlers = this._eventHandlers.get(event);
    if (handlers) {
      handlers.delete(handler);
    }
  }

  /**
   * Emit an event to all registered listeners
   *
   * @param event Event name
   * @param args Event arguments
   */
  private _emit(event: string, ...args: any[]): void {
    const handlers = this._eventHandlers.get(event);
    if (handlers) {
      handlers.forEach((handler) => {
        try {
          handler(...args);
        } catch (error) {
          console.error(`Error in ${event} handler:`, error);
        }
      });
    }
  }
}
