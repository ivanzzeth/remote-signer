/**
 * EIP-1193 Ethereum Provider implementation with multi-account support
 * @see https://eips.ethereum.org/EIPS/eip-1193
 */

import { RemoteSigner } from "./remote_signer";
import { ProviderRpcError, providerErrors } from "./provider-errors";
import type { Transaction } from "./types";
import type { RemoteSignerClient } from "../client";
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
 * EIP-1193 chainId comes in as a hex string ("0x1", "0x38") or a
 * raw number depending on the dApp. We need a uint for the daemon
 * proxy URL and a decimal string for the sign envelope, so normalise
 * to a number once at the IO boundary. Returns undefined when the
 * input is absent — that's the "no override, use provider global"
 * signal.
 */
function normalizeChainID(raw: unknown): number | undefined {
  if (raw == null) return undefined;
  if (typeof raw === "number") return raw;
  if (typeof raw === "bigint") return Number(raw);
  if (typeof raw === "string") {
    const trimmed = raw.trim();
    if (trimmed === "") return undefined;
    return trimmed.startsWith("0x") || trimmed.startsWith("0X")
      ? Number(BigInt(trimmed))
      : Number(trimmed);
  }
  return undefined;
}

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
  // RemoteSignerClient used to call the daemon's RPC proxy. Read
  // methods + signed-tx broadcast go through `_client.evm.rpcProxy`
  // — the daemon centralises every chain-RPC config (upstream URL,
  // API key, rate limit, SSRF guardrails) so this provider holds
  // zero RPC knowledge.
  private _client?: RemoteSignerClient;
  // Stashed so refreshSigners() can re-run the same resolution as
  // create(). Without it, a host that just unlocked or added a signer on
  // the daemon side would have to tear down and re-create the entire
  // provider (losing per-origin chain + active-address state) just to
  // pick the change up.
  private _signersSource?: SignersSource;

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
    this._storage = config.storage;
    this._storageKey = config.storageKey ?? DEFAULT_PROVIDER_STORAGE_KEY;
    // Resolve the SDK client used for the RPC proxy. Explicit config
    // wins; otherwise extract from signersSource if it carries one.
    // Manual mode without a client means read methods + broadcast
    // will throw at call time — that's by design (the caller opted
    // out of the daemon proxy by not supplying a client).
    this._client = config.client
      ?? (config.signersSource.type !== "manual"
        ? config.signersSource.client
        : undefined);
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
    provider._signersSource = config.signersSource;
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
   * Forward a JSON-RPC method through the daemon's wallet RPC proxy.
   *
   * The daemon is the single source of chain-RPC config — it knows
   * the upstream URL, optional API key, rate-limit budget, and SSRF
   * guardrails. The provider holds zero RPC knowledge; it just
   * names the chain and the method.
   *
   * Throws when no client was wired (manual signersSource without
   * an explicit `client` config option); throws with the daemon's
   * upstream error on transport / RPC failure so dApp-side error
   * messages identify the failing layer rather than collapsing
   * everything into "network or connection issue".
   */
  private async _proxyRPCCall(
    method: string,
    params: unknown[],
    chainIdOverride?: number,
  ): Promise<unknown> {
    if (!this._client) {
      throw new Error(
        `EIP1193Provider: ${method} requires a client for the daemon RPC proxy ` +
        `— pass one via config.client or use signersSource.type "client" / "hdwallet"`,
      );
    }
    // chainIdOverride wins over the provider's global. dApps that ship
    // a chain-specific tx (`tx.chainId`) MUST be able to broadcast +
    // pre-fill against THAT chain, regardless of whichever chain the
    // popup was last viewing — otherwise EIP-155 signatures bind to
    // the wrong chain (the BSC USDT approve regression) and no
    // network will mine the result.
    const chain = chainIdOverride ?? this._chainId;
    return await this._client.evm.rpcProxy.call(chain, method, params);
  }

  /**
   * Pick the signer a sign / send request should route through.
   *
   * Sign-method parameters carry an address: personal_sign /
   * signTypedData take it as the second positional, sendTransaction /
   * signTransaction read it from tx.from. MetaMask et al. route the
   * call to whatever signer matches that address, NOT to whichever
   * account the wallet UI happens to call "active". A dApp can
   * legitimately ask any account it was granted to sign — including
   * one that isn't currently selected in the popup.
   *
   * Behavior:
   *   - target empty → active signer (legacy callers that omit `from`).
   *   - target matches some signer in `_signers` → that signer.
   *   - target provided but unknown → unauthorized, throw early so the
   *     daemon never sees a request for an address the user hasn't
   *     unlocked. Matches the original threat model — the SDK is the
   *     last check before the daemon does its own access gate.
   *
   * Match is case-insensitive (EIP-55 vs lowercase) since dApps
   * routinely lowercase before sending.
   */
  private _resolveSigner(target: string | undefined): RemoteSigner {
    if (!this._connected || this._signers.length === 0) {
      throw providerErrors.disconnected();
    }
    if (!target) return this._signers[this._activeIndex];
    const wanted = target.toLowerCase();
    const found = this._signers.find((s) => s.address.toLowerCase() === wanted);
    if (!found) {
      throw providerErrors.unauthorized(
        `Address ${target} is not available in this provider`
      );
    }
    return found;
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
   * Re-fetch the signer list from the originally-configured source.
   *
   * Use this when the host knows daemon-side state changed out of band —
   * a CLI `signer unlock`, a new signer created via the popup, a key
   * deleted by an admin. Without it, the only way to pick up changes is
   * to re-create the provider (which loses per-origin chain + active
   * address state).
   *
   * Preserves the active address across the refresh when it survives the
   * new list; otherwise falls back to index 0. Emits accountsChanged if
   * the address set actually shifted, and a fresh `connect` if we went
   * from zero accounts to non-zero (the moment a fresh dApp request
   * could now succeed).
   *
   * Throws when there is no stored source (provider not created via
   * EIP1193Provider.create with a signersSource), so callers don't
   * silently swallow a config mistake.
   */
  public async refreshSigners(): Promise<void> {
    if (!this._signersSource) {
      throw new Error("refreshSigners requires a signersSource — provider was not created with one");
    }
    const prevAddresses = this._signers.map((s) => s.address.toLowerCase());
    const prevActiveAddress = prevAddresses[this._activeIndex];
    const wasConnected = this._connected && this._signers.length > 0;
    await this._initializeSigners(this._signersSource);
    if (this._signers.length === 0) {
      this._activeIndex = 0;
      if (wasConnected) {
        this._connected = false;
        this._emit("disconnect", providerErrors.disconnected("All signers gone after refresh"));
        this._emit("accountsChanged", []);
        void this._persistState();
      }
      return;
    }
    // Try to keep the same active address pinned across the refresh.
    if (prevActiveAddress) {
      const idx = this._signers.findIndex(
        (s) => s.address.toLowerCase() === prevActiveAddress
      );
      this._activeIndex = idx >= 0 ? idx : 0;
    } else {
      this._activeIndex = 0;
    }
    if (!wasConnected) {
      this._connected = true;
      this._emit("connect", { chainId: this.chainId } as ProviderConnectInfo);
    }
    const newAddresses = this._signers.map((s) => s.address.toLowerCase());
    const changed =
      newAddresses.length !== prevAddresses.length ||
      newAddresses.some((a, i) => a !== prevAddresses[i]);
    if (changed) {
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
        // Route to whichever signer matches the requested address —
        // multi-account dApps don't pin the "active" account, they
        // sign for whichever account the user picked. See
        // _resolveSigner for the full rationale.
        const signer = this._resolveSigner(address);

        // Pass the message through to the backend unchanged. The
        // remote-signer chain adapter is the SINGLE hex-aware decode
        // point (internal/chain/evm/adapter.go::decodePersonalSignMessage)
        // — it normalises both SIWE text payloads (USE CASE A, hex of
        // UTF-8 text) and binary challenges (USE CASE B, hex of raw
        // bytes) into the bytes EIP-191 should prefix. Doing the decode
        // here too would either double-decode (corrupt the message) or
        // mangle binary payloads on their way through JSON's UTF-8
        // string field. So: do nothing, let the backend handle it.
        return await signer.personalSign(messageParam);
      }

      case "eth_sign": {
        const [address, hash] = params as [string, string];
        const signer = this._resolveSigner(address);
        return await signer.signHash(hash);
      }

      case "eth_signTypedData":
      case "eth_signTypedData_v3":
      case "eth_signTypedData_v4": {
        const [address, typedData] = params as [string, any];
        const signer = this._resolveSigner(address);

        // signTypedData expects typed data object, handle both string and object
        const typedDataObj = typeof typedData === "string" ? JSON.parse(typedData) : typedData;
        return await signer.signTypedData(typedDataObj);
      }

      case "eth_sendTransaction": {
        const [tx] = params as [any];
        const signer = this._resolveSigner(tx.from);

        // dApp-supplied `tx.chainId` wins over the provider's global.
        // Without this, popup-on-chain-1 + dApp-on-chain-56 produces
        // an EIP-155 signature for the wrong chain and the broadcast
        // is silently rejected by every network (the BSC USDT
        // regression). normalizeChainID handles both hex strings
        // ("0x38") and numeric inputs.
        const txChain = normalizeChainID(tx.chainId);

        const filled = await this._fillTxDefaults(tx, signer.address, txChain);
        const signedTx = await signer.signTransaction(
          normalizeEip1193Tx(filled),
          txChain !== undefined ? String(txChain) : undefined,
        );

        // Broadcast through the daemon's wallet RPC proxy — also on
        // the dApp's chain, otherwise the tx hash exists on chain X
        // but the daemon's eth_sendRawTransaction goes to chain Y.
        return await this._proxyRPCCall(
          "eth_sendRawTransaction",
          [signedTx],
          txChain,
        );
      }

      case "eth_signTransaction": {
        const [tx] = params as [any];
        const signer = this._resolveSigner(tx.from);
        const txChain = normalizeChainID(tx.chainId);
        return await signer.signTransaction(
          normalizeEip1193Tx(tx),
          txChain !== undefined ? String(txChain) : undefined,
        );
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
        return await this._proxyRPCCall(method, (params as any[]) ?? []);
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
  /**
   * Fill in transaction defaults that dApps routinely omit — gas, gasPrice
   * (or EIP-1559 caps), and nonce. The remote-signer backend signs
   * whatever we hand it, so we have to mimic the same auto-fill MetaMask
   * performs client-side before signing. Missing fields come from the
   * daemon's RPC proxy; values the caller supplied are preserved as-is.
   */
  private async _fillTxDefaults(
    tx: any,
    fromAddr: string,
    chainIdOverride?: number,
  ): Promise<any> {
    const filled = { ...tx, from: tx.from ?? fromAddr };
    if (filled.nonce == null) {
      filled.nonce = await this._proxyRPCCall(
        "eth_getTransactionCount",
        [fromAddr, "pending"],
        chainIdOverride,
      );
    }
    if (filled.gas == null && filled.gasLimit == null) {
      filled.gas = await this._proxyRPCCall(
        "eth_estimateGas",
        [{ ...filled, from: fromAddr }],
        chainIdOverride,
      );
    }
    const hasFeeCap = filled.maxFeePerGas != null || filled.maxPriorityFeePerGas != null;
    if (filled.gasPrice == null && !hasFeeCap) {
      filled.gasPrice = await this._proxyRPCCall("eth_gasPrice", [], chainIdOverride);
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
