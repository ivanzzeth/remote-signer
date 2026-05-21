/**
 * Wallet RPC proxy — POST /api/v1/evm/rpc/{chainId}.
 *
 * The daemon centralises every chain-RPC config (upstream URL,
 * optional API key, rate limit, circuit breaker, SSRF guardrails)
 * so callers — the browser-extension EIP1193Provider, the popup,
 * the web UI, any third-party Node consumer — never need to ship
 * a list of public RPC URLs.
 *
 * The daemon enforces a hard allowlist that excludes every sign
 * method (eth_sign, personal_sign, eth_sendTransaction, the typed
 * data family). Those go through /api/v1/evm/sign where the rule
 * engine + budget tracking apply. eth_sendRawTransaction (signed
 * tx broadcast) IS allowed — no key material involved.
 */

import type { HttpTransport } from "../transport";

/**
 * Outbound JSON-RPC envelope. `id` is a passthrough field — the
 * daemon echoes whatever value the caller supplies back in the
 * response, mirroring direct-RPC behaviour.
 */
export interface RPCProxyRequest {
  jsonrpc: "2.0";
  id?: number | string;
  method: string;
  params: unknown[];
}

export interface RPCProxyResponse<T = unknown> {
  jsonrpc: "2.0";
  id?: number | string;
  result?: T;
  error?: { code: number; message: string };
}

export class EvmRPCProxyService {
  constructor(private readonly transport: HttpTransport) {}

  /**
   * Call a JSON-RPC method through the daemon proxy.
   *
   * Returns the parsed `result` field on success and throws on
   * upstream/transport failures — callers shouldn't have to
   * unpack the JSON-RPC envelope themselves, but the raw envelope
   * is available via `callRaw` when needed (e.g., when the result
   * is meant to round-trip the dApp's original id field).
   */
  async call<T = unknown>(
    chainId: number | string,
    method: string,
    params: unknown[] = [],
  ): Promise<T> {
    const env = await this.callRaw(chainId, method, params);
    if (env.error) {
      throw new Error(
        `daemon rpc proxy: ${env.error.message ?? "unknown"} (code ${env.error.code ?? "?"})`,
      );
    }
    return env.result as T;
  }

  /** Lower-level variant that returns the full JSON-RPC envelope. */
  async callRaw(
    chainId: number | string,
    method: string,
    params: unknown[] = [],
  ): Promise<RPCProxyResponse> {
    const body: RPCProxyRequest = {
      jsonrpc: "2.0",
      id: Date.now(),
      method,
      params,
    };
    return this.transport.request<RPCProxyResponse>(
      "POST",
      `/api/v1/evm/rpc/${encodeURIComponent(String(chainId))}`,
      body,
    );
  }
}
