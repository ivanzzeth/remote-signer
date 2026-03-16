/**
 * EIP-1193 Provider backed by RemoteSigner.
 *
 * Signing operations (personal_sign, eth_signTypedData_v4, eth_sendTransaction)
 * are proxied to the remote-signer service. Read-only RPC calls (eth_call,
 * eth_getBalance, etc.) are forwarded to a JSON-RPC node resolved automatically
 * via `eip155-chains` or user-provided overrides.
 *
 * @example
 * ```typescript
 * import { RemoteSignerClient, EIP1193Provider } from 'remote-signer-client';
 *
 * const client = new RemoteSignerClient({ ... });
 * const signer = client.evm.hdWallets.getSigner(primaryAddr, "1", 0);
 * const provider = await EIP1193Provider.create({
 *   signer,
 *   defaultChainId: 1,
 * });
 *
 * // Use as window.ethereum in a browser context
 * window.ethereum = provider;
 * ```
 */

import type { TypedData, Transaction } from "./types";
import type { RemoteSigner } from "./remote_signer";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EIP1193ProviderConfig {
  /** RemoteSigner instance (from client.evm.hdWallets.getSigner or manual construction). */
  signer: RemoteSigner;
  /** Initial chain ID. Defaults to 1 (Ethereum mainnet). */
  defaultChainId?: number;
  /** Optional RPC URL overrides per chain ID. Takes precedence over eip155-chains. */
  rpcOverrides?: Record<number, string>;
  /**
   * Custom RPC resolver. If provided, takes precedence over eip155-chains.
   * Called when no rpcOverrides entry exists for a chain.
   */
  rpcResolver?: (chainId: number) => string | Promise<string>;
}

export interface EIP1193RequestArgs {
  method: string;
  params?: unknown[] | Record<string, unknown>;
}

type EventListener = (...args: unknown[]) => void;

// ---------------------------------------------------------------------------
// EIP-1193 Provider
// ---------------------------------------------------------------------------

export class EIP1193Provider {
  // MetaMask compatibility flags
  public readonly isMetaMask = true;
  public readonly isConnected = () => true;

  private _chainId: number;
  private _rpcUrl: string | null = null;
  private readonly _signer: RemoteSigner;
  private readonly _rpcOverrides: Record<number, string>;
  private readonly _rpcResolver?: (chainId: number) => string | Promise<string>;
  private readonly _events: Map<string, Set<EventListener>> = new Map();
  private readonly _rpcCache: Map<number, string> = new Map();

  private constructor(config: EIP1193ProviderConfig) {
    this._signer = config.signer;
    this._chainId = config.defaultChainId ?? 1;
    this._rpcOverrides = config.rpcOverrides ?? {};
    this._rpcResolver = config.rpcResolver;
  }

  /**
   * Create and initialize an EIP1193Provider.
   * Resolves the initial RPC URL before returning.
   */
  static async create(config: EIP1193ProviderConfig): Promise<EIP1193Provider> {
    const provider = new EIP1193Provider(config);
    provider._syncSignerChainId();
    await provider._resolveRpc(provider._chainId);
    provider._emit("connect", { chainId: provider.chainId });
    return provider;
  }

  // -------------------------------------------------------------------------
  // EIP-1193 properties (MetaMask-compatible)
  // -------------------------------------------------------------------------

  get selectedAddress(): string {
    return this._signer.getAddress();
  }

  get chainId(): string {
    return "0x" + this._chainId.toString(16);
  }

  get networkVersion(): string {
    return this._chainId.toString();
  }

  // -------------------------------------------------------------------------
  // EIP-1193 core method
  // -------------------------------------------------------------------------

  async request(args: EIP1193RequestArgs): Promise<unknown> {
    const { method, params } = args;
    const p = (params ?? []) as unknown[];

    switch (method) {
      case "eth_requestAccounts":
      case "eth_accounts":
        return [this._signer.getAddress()];

      case "eth_chainId":
        return this.chainId;

      case "net_version":
        return this.networkVersion;

      case "personal_sign":
        return this._personalSign(p);

      case "eth_sign":
        return this._ethSign(p);

      case "eth_signTypedData_v4":
        return this._signTypedDataV4(p);

      case "eth_sendTransaction":
        return this._sendTransaction(p);

      case "wallet_switchEthereumChain":
        return this._switchChain(p);

      case "wallet_addEthereumChain":
        return null;

      case "wallet_requestPermissions":
        return [{ parentCapability: "eth_accounts" }];

      case "wallet_getPermissions":
        return [{ parentCapability: "eth_accounts" }];

      default:
        return this._rpcCall(method, p);
    }
  }

  // -------------------------------------------------------------------------
  // EIP-1193 events
  // -------------------------------------------------------------------------

  on(event: string, listener: EventListener): this {
    if (!this._events.has(event)) {
      this._events.set(event, new Set());
    }
    this._events.get(event)!.add(listener);
    return this;
  }

  removeListener(event: string, listener: EventListener): this {
    this._events.get(event)?.delete(listener);
    return this;
  }

  removeAllListeners(event?: string): this {
    if (event) {
      this._events.delete(event);
    } else {
      this._events.clear();
    }
    return this;
  }

  /** Legacy enable method. */
  async enable(): Promise<string[]> {
    return [this._signer.getAddress()];
  }

  /** Legacy sendAsync method. */
  sendAsync(
    payload: { id?: number; method: string; params?: unknown[] },
    callback: (error: unknown, result?: unknown) => void,
  ): void {
    this.request({ method: payload.method, params: payload.params })
      .then((result) =>
        callback(null, { id: payload.id, jsonrpc: "2.0", result }),
      )
      .catch((error) => callback(error));
  }

  // -------------------------------------------------------------------------
  // Signing methods (proxied to remote-signer)
  // -------------------------------------------------------------------------

  private async _personalSign(params: unknown[]): Promise<string> {
    const [message] = params as [string, string];
    return this._signer.personalSign(message);
  }

  private async _ethSign(params: unknown[]): Promise<string> {
    const [, hash] = params as [string, string];
    return this._signer.signHash(hash);
  }

  private async _signTypedDataV4(params: unknown[]): Promise<string> {
    const [, typedDataRaw] = params as [string, string | TypedData];
    const typedData: TypedData =
      typeof typedDataRaw === "string" ? JSON.parse(typedDataRaw) : typedDataRaw;
    return this._signer.signTypedData(typedData);
  }

  private async _sendTransaction(params: unknown[]): Promise<string> {
    const [txParams] = params as [Record<string, unknown>];

    const from = (txParams.from as string) ?? this._signer.getAddress();
    const to = txParams.to as string | undefined;
    const value = (txParams.value as string) ?? "0x0";
    const data = (txParams.data as string) ?? "0x";

    // Fill nonce
    let nonce = txParams.nonce as number | undefined;
    if (nonce === undefined) {
      const nonceHex = (await this._rpcCall("eth_getTransactionCount", [
        from,
        "pending",
      ])) as string;
      nonce = parseInt(nonceHex, 16);
    }

    // Fill gas
    let gas = txParams.gas as number | string | undefined;
    if (gas === undefined) {
      gas = txParams.gasLimit as string | undefined;
    }
    if (gas === undefined) {
      const gasHex = (await this._rpcCall("eth_estimateGas", [
        { from, to, value, data },
      ])) as string;
      gas = parseInt(gasHex, 16);
    }
    if (typeof gas === "string") {
      gas = parseInt(gas, 16);
    }

    // Determine tx type and gas pricing
    const maxFeePerGas = txParams.maxFeePerGas as string | undefined;
    const maxPriorityFeePerGas = txParams.maxPriorityFeePerGas as string | undefined;
    const gasPrice = txParams.gasPrice as string | undefined;

    let tx: Transaction;

    if (maxFeePerGas || maxPriorityFeePerGas) {
      let feeCap = maxFeePerGas;
      let tipCap = maxPriorityFeePerGas;
      if (!feeCap || !tipCap) {
        const block = (await this._rpcCall("eth_getBlockByNumber", [
          "latest",
          false,
        ])) as { baseFeePerGas?: string } | null;
        const baseFee = block?.baseFeePerGas ?? "0x0";
        tipCap = tipCap ?? "0x59682F00"; // 1.5 gwei default
        feeCap =
          feeCap ??
          "0x" +
            (parseInt(baseFee, 16) * 2 + parseInt(tipCap, 16)).toString(16);
      }
      tx = { to, value, data, nonce, gas, gasFeeCap: feeCap, gasTipCap: tipCap, txType: "eip1559" };
    } else {
      let price = gasPrice;
      if (!price) {
        price = (await this._rpcCall("eth_gasPrice", [])) as string;
      }
      tx = { to, value, data, nonce, gas, gasPrice: price, txType: "legacy" };
    }

    // Sign via remote-signer
    const signedTx = await this._signer.signTransaction(tx);

    // Broadcast
    return (await this._rpcCall("eth_sendRawTransaction", [signedTx])) as string;
  }

  // -------------------------------------------------------------------------
  // Chain switching
  // -------------------------------------------------------------------------

  private async _switchChain(params: unknown[]): Promise<null> {
    const [{ chainId: chainIdHex }] = params as [{ chainId: string }];
    const newChainId = parseInt(chainIdHex, 16);

    if (newChainId === this._chainId) {
      return null;
    }

    await this._resolveRpc(newChainId);
    this._chainId = newChainId;
    this._syncSignerChainId();
    this._emit("chainChanged", this.chainId);
    return null;
  }

  // -------------------------------------------------------------------------
  // RPC proxy
  // -------------------------------------------------------------------------

  private async _rpcCall(method: string, params: unknown[]): Promise<unknown> {
    const rpcUrl = await this._getCurrentRpcUrl();
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: Date.now(),
      method,
      params,
    });

    const resp = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });

    if (!resp.ok) {
      throw new Error(`RPC request failed: ${resp.status} ${resp.statusText}`);
    }

    const json = (await resp.json()) as {
      result?: unknown;
      error?: { code: number; message: string };
    };

    if (json.error) {
      const err = new Error(json.error.message) as Error & { code: number };
      err.code = json.error.code;
      throw err;
    }

    return json.result;
  }

  // -------------------------------------------------------------------------
  // RPC resolution
  // -------------------------------------------------------------------------

  private async _getCurrentRpcUrl(): Promise<string> {
    if (this._rpcUrl) {
      return this._rpcUrl;
    }
    return this._resolveRpc(this._chainId);
  }

  private async _resolveRpc(chainId: number): Promise<string> {
    const cached = this._rpcCache.get(chainId);
    if (cached) {
      this._rpcUrl = cached;
      return cached;
    }

    const override = this._rpcOverrides[chainId];
    if (override) {
      this._rpcCache.set(chainId, override);
      this._rpcUrl = override;
      return override;
    }

    if (this._rpcResolver) {
      const url = await this._rpcResolver(chainId);
      this._rpcCache.set(chainId, url);
      this._rpcUrl = url;
      return url;
    }

    try {
      const { getRpcsByChainId } = await import("eip155-chains");
      const rpcs = await getRpcsByChainId(chainId);
      if (!rpcs || rpcs.length === 0) {
        throw new Error(`No RPC endpoints found for chain ${chainId}`);
      }
      const httpsRpc = rpcs.find((r) => r.url.startsWith("https://"));
      const url = httpsRpc ? httpsRpc.url : rpcs[0].url;
      this._rpcCache.set(chainId, url);
      this._rpcUrl = url;
      return url;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`Failed to resolve RPC for chain ${chainId}: ${msg}`);
    }
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  private _syncSignerChainId(): void {
    this._signer.setChainID(this._chainId.toString());
  }

  private _emit(event: string, ...args: unknown[]): void {
    const listeners = this._events.get(event);
    if (!listeners) return;
    for (const listener of listeners) {
      try {
        listener(...args);
      } catch {
        // Event listeners must not break the provider
      }
    }
  }
}
