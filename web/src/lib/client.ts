// Authenticated fetch wrapper. Mirrors pkg/js-client/src/transport.ts at
// the HTTP layer (same header names, same canonical payload) so the web
// UI and the CLI talk to the daemon identically.
//
// Every call is signed: `payload = ts|nonce|method|path|sha256(body)`.
// /health, /metrics and the SPA assets themselves are NOT signed —
// callers route those through plain fetch().

import { getCredentials } from "./auth";
import { generateNonce, signRequest } from "./crypto";

/**
 * Error thrown when the daemon returns a non-2xx. Carries both the status
 * code and the parsed response body (when JSON) so callers can branch on
 * either, eg. show a different toast for 403 vs 500.
 */
export class APIError extends Error {
  status: number;
  body: unknown;
  constructor(status: number, message: string, body: unknown) {
    super(`API error ${status}: ${message}`);
    this.status = status;
    this.body = body;
  }
}

export interface RequestOptions {
  body?: unknown;
  signal?: AbortSignal;
  // Override the canonical sign path. Used for endpoints whose URL is
  // dynamic per request; defaults to `path` itself.
  signPath?: string;
}

/**
 * Sends a signed request and decodes the JSON response. Throws APIError
 * on non-2xx.
 */
export async function apiRequest<T>(
  method: string,
  path: string,
  opts: RequestOptions = {},
): Promise<T> {
  const creds = getCredentials();
  if (!creds) {
    throw new Error("not authenticated; import an API key first");
  }
  const bodyBytes = opts.body
    ? new TextEncoder().encode(JSON.stringify(opts.body))
    : new Uint8Array(0);
  const ts = Date.now();
  const nonce = generateNonce();
  const signature = signRequest(
    creds.privateKey,
    ts,
    nonce,
    method,
    opts.signPath ?? path,
    bodyBytes,
  );

  const headers: Record<string, string> = {
    "X-API-Key-ID": creds.apiKeyID,
    "X-Timestamp": ts.toString(),
    "X-Nonce": nonce,
    "X-Signature": signature,
  };
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  const resp = await fetch(path, {
    method,
    headers,
    body: opts.body !== undefined ? bodyBytes : undefined,
    signal: opts.signal,
  });

  if (!resp.ok) {
    const text = await resp.text();
    let parsed: unknown = text;
    try {
      parsed = JSON.parse(text);
    } catch {
      // text remains as fallback
    }
    const msg =
      typeof parsed === "object" && parsed !== null && "message" in parsed
        ? String((parsed as { message: unknown }).message)
        : typeof parsed === "string" && parsed.length > 0
          ? parsed
          : resp.statusText;
    throw new APIError(resp.status, msg, parsed);
  }

  if (resp.status === 204 || resp.headers.get("content-length") === "0") {
    return undefined as T;
  }
  const ct = resp.headers.get("content-type") ?? "";
  if (ct.includes("application/json")) {
    return (await resp.json()) as T;
  }
  return (await resp.text()) as unknown as T;
}

/** Unauthenticated GET, for /health, /metrics, /favicon.svg, etc. */
export async function plainGet<T>(path: string): Promise<T> {
  const resp = await fetch(path);
  if (!resp.ok) {
    throw new APIError(resp.status, resp.statusText, null);
  }
  const ct = resp.headers.get("content-type") ?? "";
  if (ct.includes("application/json")) {
    return (await resp.json()) as T;
  }
  return (await resp.text()) as unknown as T;
}
