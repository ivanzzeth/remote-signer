/**
 * HTTP transport layer for remote-signer client.
 * Handles authenticated requests, TLS configuration, and error parsing.
 *
 * Environment support:
 * - Browser: uses globalThis.fetch. httpClient.tls is ignored (no custom CA or mTLS in browser).
 * - Node.js: uses globalThis.fetch by default; if httpClient.tls is set, uses Node https module for custom CA / mTLS.
 */

import { parsePrivateKey, generateNonce, signRequestWithNonce } from "./crypto";
import {
  RemoteSignerError,
  APIError,
  TimeoutError,
} from "./errors";

/** TLS configuration (Node.js only, ignored in browser) */
export interface TLSConfig {
  /** CA certificate (PEM string or Buffer). Required for self-signed server certs. */
  ca?: string | Uint8Array;
  /** Client certificate (PEM string or Buffer). Required for mTLS. */
  cert?: string | Uint8Array;
  /** Client private key (PEM string or Buffer). Required for mTLS. */
  key?: string | Uint8Array;
  /** Skip server certificate verification. WARNING: insecure, testing only. Default: true */
  rejectUnauthorized?: boolean;
}

/** Client configuration */
export interface ClientConfig {
  baseURL: string;
  apiKeyID: string;
  privateKey: string | Uint8Array; // hex string or bytes
  httpClient?: {
    timeout?: number;
    /** Custom fetch function. Overrides default globalThis.fetch and TLS config. */
    fetch?: typeof fetch;
    /** TLS configuration for Node.js environments. Ignored in browsers. */
    tls?: TLSConfig;
  };
  pollInterval?: number; // milliseconds, default: 2000
  pollTimeout?: number; // milliseconds, default: 300000 (5 minutes)
}

/**
 * HttpTransport encapsulates all HTTP communication with the remote-signer server.
 * It handles authentication signing, TLS setup, timeouts, and error parsing.
 */
export class HttpTransport {
  private baseURL: string;
  private apiKeyID: string;
  private privateKey: Uint8Array;
  private httpClient: {
    fetch: typeof fetch;
    timeout?: number;
  };

  constructor(config: ClientConfig) {
    if (!config.baseURL) {
      throw new Error("baseURL is required");
    }
    if (!config.apiKeyID) {
      throw new Error("apiKeyID is required");
    }
    if (!config.privateKey) {
      throw new Error("privateKey is required");
    }

    this.baseURL = config.baseURL.replace(/\/$/, "");
    this.apiKeyID = config.apiKeyID;
    this.privateKey = parsePrivateKey(config.privateKey);

    // Setup HTTP client
    const timeout = config.httpClient?.timeout ?? 30000; // 30 seconds
    const base = config.baseURL.replace(/\/$/, "");
    const isHttps = base.toLowerCase().startsWith("https://");

    if (config.httpClient?.fetch) {
      // User provided custom fetch function - use directly
      this.httpClient = { fetch: config.httpClient.fetch, timeout };
    } else if (
      HttpTransport.isNodeJS() &&
      (isHttps || config.httpClient?.tls)
    ) {
      // Node.js: use https module for https URLs or when TLS config is provided.
      // This avoids "Client sent an HTTP request to an HTTPS server" when
      // globalThis.fetch behaves inconsistently (e.g. in MCP subprocess).
      this.httpClient = {
        fetch: HttpTransport.createNodeTLSFetch(config.httpClient?.tls ?? {}),
        timeout,
      };
    } else {
      // Browser or Node.js with http URL and no TLS - use globalThis.fetch
      this.httpClient = {
        fetch: globalThis.fetch.bind(globalThis),
        timeout,
      };
    }
  }

  /**
   * Detect if running in Node.js environment.
   */
  private static isNodeJS(): boolean {
    return (
      typeof process !== "undefined" &&
      process.versions != null &&
      process.versions.node != null
    );
  }

  /**
   * Create a fetch function with TLS/mTLS support for Node.js.
   * Uses Node.js built-in https.Agent for certificate configuration.
   *
   * @param tlsConfig - TLS configuration with CA, client cert, and key
   * @returns A fetch-compatible function with TLS configured
   */
  private static createNodeTLSFetch(tlsConfig: TLSConfig): typeof fetch {
    // Dynamic require to avoid bundling Node.js modules in browser builds
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const https = require("https");
    const agent = new https.Agent({
      ca: tlsConfig.ca,
      cert: tlsConfig.cert,
      key: tlsConfig.key,
      rejectUnauthorized: tlsConfig.rejectUnauthorized ?? true,
    });

    // Return a fetch wrapper that injects the https agent.
    // Node.js native fetch (undici-based, 18+) does not support 'agent' directly,
    // so we use the lower-level https/http module to make requests.
    const fetchWithTLS = (input: string | URL, init?: any): Promise<any> => {
      const url = typeof input === "string" ? input : input.toString();
      const method = init?.method ?? "GET";
      const headers = init?.headers as Record<string, string> | undefined;
      const body = init?.body as string | undefined;
      const signal = init?.signal as AbortSignal | undefined;

      return new Promise((resolve, reject) => {
        if (signal?.aborted) {
          const err = new Error("The operation was aborted.");
          err.name = "AbortError";
          reject(err);
          return;
        }

        const parsed = new URL(url);
        const options: any = {
          hostname: parsed.hostname,
          port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
          path: parsed.pathname + parsed.search,
          method,
          headers: headers || {},
          agent: parsed.protocol === "https:" ? agent : undefined,
        };

        const proto = parsed.protocol === "https:" ? https : require("http");
        const req = proto.request(options, (res: any) => {
          const chunks: any[] = [];
          res.on("data", (chunk: any) => chunks.push(chunk));
          res.on("end", () => {
            const buffer = Buffer.concat(chunks);
            const bodyText = buffer.toString("utf-8");
            // Build a Response-like object compatible with our client's usage
            resolve({
              ok: res.statusCode >= 200 && res.statusCode < 300,
              status: res.statusCode,
              statusText: res.statusMessage || "",
              headers: {
                get: (name: string) => res.headers[name.toLowerCase()] || null,
              },
              text: () => Promise.resolve(bodyText),
              json: () => Promise.resolve(JSON.parse(bodyText)),
            });
          });
          res.on("error", reject);
        });

        req.on("error", reject);

        // Handle abort signal
        if (signal) {
          const onAbort = () => {
            req.destroy();
            const err = new Error("The operation was aborted.");
            err.name = "AbortError";
            reject(err);
          };
          signal.addEventListener("abort", onAbort, { once: true });
          req.on("close", () => signal.removeEventListener("abort", onAbort));
        }

        if (body) {
          req.write(body);
        }
        req.end();
      });
    };

    return fetchWithTLS as typeof fetch;
  }

  /**
   * Make an authenticated HTTP request.
   */
  async request<T>(
    method: string,
    path: string,
    body: any
  ): Promise<T> {
    const url = this.baseURL + path;
    const bodyBytes = body ? new TextEncoder().encode(JSON.stringify(body)) : new Uint8Array(0);
    const timestamp = Date.now();

    // Sign the request with nonce for replay protection
    const nonce = generateNonce();
    const signature = signRequestWithNonce(
      this.privateKey,
      timestamp,
      nonce,
      method,
      path,
      bodyBytes
    );

    // Build headers
    const headers: Record<string, string> = {
      "X-API-Key-ID": this.apiKeyID,
      "X-Timestamp": timestamp.toString(),
      "X-Nonce": nonce,
      "X-Signature": signature,
    };

    if (body) {
      headers["Content-Type"] = "application/json";
    }

    return this.doFetch<T>(url, method, headers, body);
  }

  /**
   * Make an unauthenticated HTTP request (for /health, /metrics).
   */
  async requestNoAuth<T>(
    method: string,
    path: string
  ): Promise<T> {
    const url = this.baseURL + path;
    return this.doFetch<T>(url, method, {}, null);
  }

  /**
   * Execute the actual HTTP fetch with timeout and error handling.
   */
  private async doFetch<T>(
    url: string,
    method: string,
    headers: Record<string, string>,
    body: any
  ): Promise<T> {
    const controller = new AbortController();
    const timeoutId = this.httpClient.timeout
      ? setTimeout(() => controller.abort(), this.httpClient.timeout)
      : null;

    try {
      const response = await this.httpClient.fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      if (timeoutId) {
        clearTimeout(timeoutId);
      }

      const responseBody = await response.text();
      let data: any;

      try {
        data = responseBody ? JSON.parse(responseBody) : {};
      } catch {
        data = { message: responseBody };
      }

      if (!response.ok) {
        const error = data as { error?: string; message?: string };
        throw new APIError(
          error.message || `HTTP ${response.status}`,
          response.status,
          error.error
        );
      }

      return data as T;
    } catch (error) {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }

      if (error instanceof APIError) {
        throw error;
      }

      if (error instanceof Error && error.name === "AbortError") {
        throw new TimeoutError("Request timeout");
      }

      throw new RemoteSignerError(
        error instanceof Error ? error.message : "Unknown error"
      );
    }
  }
}
