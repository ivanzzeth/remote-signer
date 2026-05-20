/**
 * EIP-1193 Ethereum Provider implementation with multi-account support
 * @see https://eips.ethereum.org/EIPS/eip-1193
 */

import { RemoteSigner } from "./remote_signer";
import { ProviderRpcError, providerErrors } from "./provider-errors";
import type { Transaction } from "./types";
import type {
  EIP1193ProviderConfig,
  SignersSource,
  RequestArguments,
  ProviderConnectInfo,
  ProviderMessage,
} from "./provider-types";
import {
  type ProviderStorage,
  type PersistedProviderState,
  DEFAULT_PROVIDER_STORAGE_KEY,
  readPersistedState,
  writePersistedState,
} from "./provider-storage";

/**
 * EIP-1193 transactions arrive with hex-encoded quantity fields (value, gas,
 * nonce, gasPrice, maxFeePerGas, maxPriorityFeePerGas). Our SDK + backend
 * use decimal strings for big numbers and Go uint64 for gas/nonce. Convert
 * at the IO boundary so the rest of the pipeline never has to think about
 * which encoding it received.
 */
function normalizeEip1193Tx(tx: any): Transaction {
  const hexToDec = (v: any): string | undefined => {
    if (v == null) return undefined;
    if (typeof v === "string") {
      if (v.startsWith("0x") || v.startsWith("0X")) return BigInt(v).toString(10);
      return v;
    }
    if (typeof v === "number" || typeof v === "bigint") return BigInt(v).toString(10);
    return String(v);
  };
  const hexToNum = (v: any): number | undefined => {
    if (v == null) return undefined;
    if (typeof v === "number") return v;
    if (typeof v === "string") {
      return v.startsWith("0x") || v.startsWith("0X") ? Number(BigInt(v)) : Number(v);
    }
    return Number(v);
  };

  const hasMaxFee = tx.maxFeePerGas != null || tx.maxPriorityFeePerGas != null;
  const out: Transaction = {
    to: tx.to,
    value: hexToDec(tx.value) ?? "0",
    data: tx.data ?? tx.input,
    nonce: hexToNum(tx.nonce),
    // EIP-1193 uses "gas"; our struct names it the same.
    gas: hexToNum(tx.gas ?? tx.gasLimit) ?? 0,
    txType: tx.txType ?? (hasMaxFee ? "eip1559" : "legacy"),
  };
  if (tx.gasPrice != null) out.gasPrice = hexToDec(tx.gasPrice);
  if (tx.maxFeePerGas != null) out.gasFeeCap = hexToDec(tx.maxFeePerGas);
  if (tx.maxPriorityFeePerGas != null) out.gasTipCap = hexToDec(tx.maxPriorityFeePerGas);
  return out;
}

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

  // Persistence (optional). When set, every state-changing operation
  // writes back so a host that re-creates the provider (MV3 SW resume,
  // long-running Node service restart) keeps the user's last choice.
  private _storage?: ProviderStorage;
  private _storageKey: string = DEFAULT_PROVIDER_STORAGE_KEY;

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
    this._storage = config.storage;
    this._storageKey = config.storageKey ?? DEFAULT_PROVIDER_STORAGE_KEY;
  }

  /**
   * Persist the current chain + active address to the configured storage.
   * No-op when no storage was provided. Best-effort: failures are swallowed
   * so a flaky backing store can never break the live request path.
   */
  private async _persistState(): Promise<void> {
    if (!this._storage) return;
    const state: PersistedProviderState = { chainId: this._chainId };
    if (this._connected && this._signers.length > 0) {
      state.activeAddress = this._signers[this._activeIndex].address.toLowerCase();
    }
    await writePersistedState(this._storage, this._storageKey, state);
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

    // Hydrate from persisted state when a storage backend is provided.
    // The order matters: signers are loaded first (we need their addresses
    // to map activeAddress → index), then chainId, then activeIndex.
    // The constructor's defaults are kept as the fallback when there is
    // no persisted state (first run, or storage that returned null).
    if (provider._storage) {
      const persisted = await readPersistedState(provider._storage, provider._storageKey);
      if (persisted) {
        if (typeof persisted.chainId === "number" && persisted.chainId > 0) {
          provider._chainId = persisted.chainId;
          // Keep the per-signer chainID in sync so subsequent sign calls
          // hit the right chain on the backend.
          for (const s of provider._signers) {
            (s as any)._chainID = String(persisted.chainId);
          }
        }
        if (persisted.activeAddress) {
          const idx = provider._signers.findIndex(
            (s) => s.address.toLowerCase() === persisted.activeAddress!.toLowerCase()
          );
          if (idx >= 0) provider._activeIndex = idx;
        }
      }
    }

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

      // Make sure persisted state reflects the final, validated values
      // even on a first-run create() — so a subsequent re-create() finds
      // them. Fire-and-forget; we don't block the caller on storage.
      void provider._persistState();
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
    void this._persistState();
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
    void this._persistState();
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
    void this._persistState();
  }

  /**
   * Disconnect provider and clear all accounts
   */
  public async disconnect(): Promise<void> {
    this._signers = [];
    this._activeIndex = 0;
    this._connected = false;

    // EIP-1193: disconnect event error code MUST follow CloseEvent status codes (1000-1015)
    // 1000 = Normal Closure
    this._emit("disconnect", {
      code: 1000,
      message: "User disconnected",
    } as any);
    void this._persistState();
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
        const [messageParam, address] = params as [string, string];
        const signer = this._getActiveSigner();

        // Pass the message through to the backend unchanged. The
        // remote-signer chain adapter is the SINGLE hex-aware decode
        // point (internal/chain/evm/adapter.go::decodePersonalSignMessage)
        // — it normalises both SIWE text payloads (USE CASE A, hex of
        // UTF-8 text) and binary challenges (USE CASE B, hex of raw
        // bytes) into the bytes EIP-191 should prefix. Doing the decode
        // here too would either double-decode (corrupt the message) or
        // mangle binary payloads on their way through JSON's UTF-8
        // string field. So: do nothing, let the backend handle it.

        // Verify address matches active signer
        if (address.toLowerCase() !== signer.address.toLowerCase()) {
          throw providerErrors.unauthorized(
            `Address mismatch: expected ${signer.address}, got ${address}`
          );
        }

        return await signer.personalSign(messageParam);
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

        const rpcUrl = await this._getRpcUrl();
        const filled = await this._fillTxDefaults(tx, signer.address, rpcUrl);
        const signedTx = await signer.signTransaction(normalizeEip1193Tx(filled));

        // Broadcast via RPC
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

        return await signer.signTransaction(normalizeEip1193Tx(tx));
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

      // Wallet methods
      case "wallet_requestPermissions": {
        // Return permission approval (for eth_accounts)
        return [{ parentCapability: "eth_accounts" }];
      }

      case "wallet_switchEthereumChain": {
        console.log("[EIP1193] wallet_switchEthereumChain called:", params);

        // Switch chain
        const chainIdParam = (params as any[])?.[0]?.chainId;
        if (!chainIdParam) {
          console.error("[EIP1193] wallet_switchEthereumChain: Missing chainId parameter");
          throw providerErrors.rpc(-32602, "Missing chainId parameter");
        }

        const newChainId = parseInt(chainIdParam, 16);
        if (isNaN(newChainId)) {
          console.error("[EIP1193] wallet_switchEthereumChain: Invalid chainId format:", chainIdParam);
          throw providerErrors.rpc(-32602, "Invalid chainId format");
        }

        console.log("[EIP1193] Switching from chain", this._chainId, "to chain", newChainId);

        // Update chainId and all signers
        this._chainId = newChainId;
        const newChainIdStr = newChainId.toString();
        console.log("[EIP1193] Updating signers to chainId:", newChainIdStr);
        for (const signer of this._signers) {
          signer.setChainID(newChainIdStr);
        }

        // Emit chainChanged event
        console.log("[EIP1193] Emitting chainChanged:", `0x${newChainId.toString(16)}`);
        this._emit("chainChanged", `0x${newChainId.toString(16)}`);

        // EIP-1193: MUST also emit accountsChanged when chain switches
        // Because the accounts available may change when switching chains
        console.log("[EIP1193] Emitting accountsChanged:", this._getAccounts());
        this._emit("accountsChanged", this._getAccounts());

        void this._persistState();
        console.log("[EIP1193] wallet_switchEthereumChain completed successfully");
        return null;
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
   * Fill in transaction defaults that dApps routinely omit — gas, gasPrice
   * (or EIP-1559 caps), and nonce. The remote-signer backend signs whatever
   * we hand it, so we have to mimic the same auto-fill MetaMask performs
   * client-side before signing. Missing fields are fetched from the chain
   * RPC; values the caller supplied are preserved as-is.
   */
  private async _fillTxDefaults(tx: any, fromAddr: string, rpcUrl: string): Promise<any> {
    const filled = { ...tx, from: tx.from ?? fromAddr };
    const rpc = async (method: string, params: any[]): Promise<any> => {
      const res = await fetch(rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: Date.now(), method, params }),
      });
      const json: any = await res.json();
      if (json.error) throw new Error(`${method}: ${json.error.message}`);
      return json.result;
    };

    if (filled.nonce == null) {
      filled.nonce = await rpc("eth_getTransactionCount", [fromAddr, "pending"]);
    }
    if (filled.gas == null && filled.gasLimit == null) {
      filled.gas = await rpc("eth_estimateGas", [{ ...filled, from: fromAddr }]);
    }
    const hasFeeCap = filled.maxFeePerGas != null || filled.maxPriorityFeePerGas != null;
    if (filled.gasPrice == null && !hasFeeCap) {
      filled.gasPrice = await rpc("eth_gasPrice", []);
    }
    return filled;
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
    void this._persistState();
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
