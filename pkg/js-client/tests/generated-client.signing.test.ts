/**
 * Differential test for the generated TS client's Ed25519 signing.
 *
 * ⛔ Same reason as the Go side (pkg/client/internal/transport/
 * signing_differential_test.go): OpenAPI cannot express this service's request
 * signature, so the injection is hand-written, and a hand-written injection
 * that is subtly wrong produces a 401 whose message mentions neither the path
 * nor its encoding. A generated SDK that 401s on every call is worse than no
 * generated SDK.
 *
 * Two comparisons, and both are needed:
 *
 *   1. **against the hand-written HttpTransport** — the client that already
 *      works in production. Same logical call, same signed message.
 *   2. **against the server's own canonicalisation** — reimplemented here from
 *      internal/api/middleware/auth.go rather than by calling the SDK's own
 *      helper. ⛔ If both sides of a differential call the same function, the
 *      test proves only that the function agrees with itself.
 */

import { createSignedClient } from "../src/generated-client";
import { HttpTransport } from "../src/transport";
import { bytesToHex, parsePrivateKey } from "../src/crypto";
import { sha256 } from "@noble/hashes/sha256";
import * as ed25519 from "@noble/ed25519";

// A fixed 32-byte seed. ⚠️ Test-only; it never leaves this file.
const SEED_HEX = "4242424242424242424242424242424242424242424242424242424242424242";
const BASE_URL = "http://signer.invalid:8548";
const KEY_ID = "agent";

interface Captured {
  method: string;
  /** EscapedPath + ("?" + RawQuery when non-empty) — what the server signs. */
  pathAndQuery: string;
  body: Uint8Array;
  headers: Record<string, string>;
}

/** A fetch stand-in that records the request and answers 200 {}. */
function recordingFetch(sink: Captured[]): typeof fetch {
  return (async (input: any, init?: any): Promise<any> => {
    // Both callers reach here differently: openapi-fetch hands over a Request,
    // HttpTransport hands over (url, init).
    let method: string;
    let url: string;
    let body: Uint8Array;
    let headers: Record<string, string> = {};

    if (typeof input === "object" && input !== null && "url" in input && "clone" in input) {
      const req = input as Request;
      method = req.method;
      url = req.url;
      body = new Uint8Array(await req.clone().arrayBuffer());
      req.headers.forEach((v, k) => {
        headers[k] = v;
      });
    } else {
      url = typeof input === "string" ? input : String(input);
      method = (init?.method as string) ?? "GET";
      const raw = init?.body as string | undefined;
      body = raw ? new TextEncoder().encode(raw) : new Uint8Array(0);
      headers = { ...((init?.headers as Record<string, string>) ?? {}) };
    }

    const parsed = new URL(url);
    sink.push({
      method,
      // ⚠️ `pathname` keeps percent-encoding; `search` is "" or "?…".
      pathAndQuery: parsed.pathname + parsed.search,
      body,
      // Header names are lower-cased on a Request; normalise both shapes.
      headers: Object.fromEntries(
        Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]),
      ),
    });

    return {
      ok: true,
      status: 200,
      statusText: "OK",
      headers: new Headers({ "content-type": "application/json" }),
      text: () => Promise.resolve("{}"),
      json: () => Promise.resolve({}),
      clone() {
        return this;
      },
    };
  }) as unknown as typeof fetch;
}

/** Rebuilds the signed message the way middleware/auth.go does, then verifies. */
async function verifyLikeServer(c: Captured): Promise<string> {
  const ts = c.headers["x-timestamp"];
  const nonce = c.headers["x-nonce"];
  const sig = c.headers["x-signature"];
  expect(ts).toBeTruthy();
  expect(nonce).toBeTruthy();
  expect(sig).toBeTruthy();

  const message = `${ts}|${nonce}|${c.method}|${c.pathAndQuery}|${bytesToHex(sha256(c.body))}`;
  const seed = parsePrivateKey(SEED_HEX);
  const pub = await ed25519.getPublicKeyAsync(seed);
  const sigBytes = Uint8Array.from(atob(sig), (ch) => ch.charCodeAt(0));
  const ok = await ed25519.verifyAsync(sigBytes, new TextEncoder().encode(message), pub);
  expect(ok).toBe(true);
  return message;
}

/** Strips the two fields that are random by design, so messages are comparable. */
function withoutTimestampAndNonce(message: string): string {
  const parts = message.split("|");
  return parts.slice(2).join("|");
}

describe("createSignedClient signing", () => {
  const cases: Array<{
    name: string;
    handWritten: (t: HttpTransport) => Promise<unknown>;
    generated: (api: ReturnType<typeof createSignedClient>) => Promise<unknown>;
  }> = [
    {
      name: "GET collection",
      handWritten: (t) => t.request("GET", "/api/v1/evm/rules", undefined),
      generated: (api) => api.GET("/api/v1/evm/rules", {}),
    },
    {
      // ⭐ The case the middleware exists for: a template id containing '/'.
      // Signing a decoded path passes every other case here and fails only
      // this one.
      name: "GET item whose id contains a slash",
      handWritten: (t) => t.request("GET", "/api/v1/templates/evm%2Ferc20", undefined),
      generated: (api) =>
        api.GET("/api/v1/templates/{id}", { params: { path: { id: "evm/erc20" } } }),
    },
    {
      name: "POST with JSON body",
      handWritten: (t) => t.request("POST", "/api/v1/evm/rules", { name: "diff-test" }),
      generated: (api) =>
        api.POST("/api/v1/evm/rules", { body: { name: "diff-test" } as never }),
    },
    {
      name: "GET with one query parameter",
      handWritten: (t) => t.request("GET", "/api/v1/evm/rules?enabled=true", undefined),
      generated: (api) =>
        api.GET("/api/v1/evm/rules", { params: { query: { enabled: "true" } } }),
    },
  ];

  for (const tc of cases) {
    it(`${tc.name}: signs what the server verifies, and the same bytes as HttpTransport`, async () => {
      const hwSink: Captured[] = [];
      const transport = new HttpTransport({
        baseURL: BASE_URL,
        apiKeyID: KEY_ID,
        privateKey: SEED_HEX,
        httpClient: { fetch: recordingFetch(hwSink) },
      });
      await tc.handWritten(transport);
      expect(hwSink).toHaveLength(1);
      const hwMsg = await verifyLikeServer(hwSink[0]);

      const genSink: Captured[] = [];
      const api = createSignedClient({
        baseURL: BASE_URL,
        apiKeyID: KEY_ID,
        privateKey: SEED_HEX,
        fetch: recordingFetch(genSink),
      });
      await tc.generated(api);
      expect(genSink).toHaveLength(1);
      const genMsg = await verifyLikeServer(genSink[0]);

      expect(genSink[0].method).toBe(hwSink[0].method);
      expect(genSink[0].pathAndQuery).toBe(hwSink[0].pathAndQuery);
      expect(Array.from(genSink[0].body)).toEqual(Array.from(hwSink[0].body));
      expect(genSink[0].headers["x-api-key-id"]).toBe(KEY_ID);
      // ⚠️ Timestamp and nonce are random by design, so the comparable part is
      // everything after them. Each message was already verified against the
      // key above, so equality here means the two clients signed the same
      // method, path and body.
      expect(withoutTimestampAndNonce(genMsg)).toBe(withoutTimestampAndNonce(hwMsg));
    });
  }

  it("signs the percent-encoded path, not the decoded one (§4.3 point 1)", async () => {
    const sink: Captured[] = [];
    const api = createSignedClient({
      baseURL: BASE_URL,
      apiKeyID: KEY_ID,
      privateKey: SEED_HEX,
      fetch: recordingFetch(sink),
    });
    await api.GET("/api/v1/templates/{id}", { params: { path: { id: "evm/erc20" } } });
    const msg = await verifyLikeServer(sink[0]);
    expect(msg).toContain("|GET|/api/v1/templates/evm%2Ferc20|");
    expect(msg).not.toContain("/api/v1/templates/evm/erc20");
  });

  it("appends '?' only when there is a query string (§4.3 point 2)", async () => {
    const sink: Captured[] = [];
    const api = createSignedClient({
      baseURL: BASE_URL,
      apiKeyID: KEY_ID,
      privateKey: SEED_HEX,
      fetch: recordingFetch(sink),
    });
    await api.GET("/api/v1/evm/rules", {});
    const msg = await verifyLikeServer(sink[0]);
    expect(msg).toContain("|GET|/api/v1/evm/rules|");
    expect(msg).not.toContain("/api/v1/evm/rules?");
  });

  it("covers the body it actually sends (§4.3 point 3)", async () => {
    const sink: Captured[] = [];
    const api = createSignedClient({
      baseURL: BASE_URL,
      apiKeyID: KEY_ID,
      privateKey: SEED_HEX,
      fetch: recordingFetch(sink),
    });
    await api.POST("/api/v1/evm/rules", { body: { name: "body-check" } as never });
    // ⛔ Non-empty body on the wire — a middleware that read (and consumed) the
    // request instead of cloning it would send nothing here while signing the
    // real bytes, and the server would answer 401 for a body-hash mismatch.
    expect(sink[0].body.length).toBeGreaterThan(0);
    const msg = await verifyLikeServer(sink[0]);
    expect(msg).toContain(bytesToHex(sha256(sink[0].body)));
  });
});
