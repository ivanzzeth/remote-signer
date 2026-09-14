/**
 * Typed client over the generated OpenAPI schema.
 *
 * ⛔ 这个文件是**手写的薄封装**,不是生成物。生成物只有一份:
 * `src/gen/schema.d.ts`(由 `npm run prebuild` → `scripts/gen-sdk.sh ts` 从
 * internal/apidocs/openapi.json 生成,**不入库**)。
 *
 * ## 为什么这里只有一个 `createSignedClient`,而不是 92 个方法
 *
 * openapi-fetch 是一个泛型客户端:`client.GET("/api/v1/evm/rules")` 里的路径
 * 字面量由 `paths` 类型检查,而 `paths` 是从 spec 生成的。也就是说
 * **spec 里的每一条路由都自动可调用,而 spec 里没有的路径是一个编译错误**。
 * ⭐ 这正是门禁 C 在 TS 侧要的形状:覆盖是由构造保证的,不是靠人逐条补方法。
 *
 * ## §4.4 的边界 —— 哪一半归谁
 *
 * | 归这里(手写)          | 归生成层                |
 * |------------------------|-------------------------|
 * | Ed25519 鉴权注入        | 路径 / 查询参数拼装      |
 * | 重试 / 退避             | 请求构造、序列化         |
 * | 分页迭代器              | 状态码 → 类型分派        |
 * | 错误友好化              | DTO 类型定义             |
 * | 异步签名轮询            |                         |
 * | EIP-1193 provider       |                         |
 *
 * ⛔ 封装层永远不做业务判断:看到 `status === "pending"` 就轮询是调用协议;
 * 判断某条规则该不该匹配、某个额度够不够是 `internal/core/rule` 的事。
 *
 * ## ⚠️ 这不替换 `RemoteSignerClient`
 *
 * 既有的 `RemoteSignerClient` / `HttpTransport` 一个字都没动 —— 它们是这个 npm
 * 包已经发布出去的公开接口。这里是**并存的第二条路**:类型来自 spec,所以
 * 一个端点改了形状,用它的代码在 `tsc` 时就红,而不是在运行时 404。
 */

import createClient, { type Client, type Middleware } from "openapi-fetch";

import type { paths } from "./gen/schema";
import { generateNonce, parsePrivateKey, signRequestWithNonce } from "./crypto";

/** Options for {@link createSignedClient}. */
export interface SignedClientOptions {
  /** Base URL of the remote-signer daemon, e.g. `http://127.0.0.1:8548`. */
  baseURL: string;
  /** API key id sent as `X-API-Key-ID`. */
  apiKeyID: string;
  /** Ed25519 private key: 32-byte seed or 64-byte key, hex string or bytes. */
  privateKey: string | Uint8Array;
  /** Custom fetch, e.g. one carrying a Node TLS agent. Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
}

/**
 * Builds the middleware that signs every outgoing request.
 *
 * # ⛔ The three things that are easy to get wrong (proposal §4.3)
 *
 * The server rebuilds and verifies, in `internal/api/middleware/auth.go`:
 *
 *     {unix-millis}|{nonce}|{METHOD}|{EscapedPath}[?{RawQuery}]|{hex sha256(body)}
 *
 * 1. **编码后的路径,不是解码后的。** template / preset 的 id 含 '/'
 *    ("evm/erc20"),线上形式是 `%2F`。`new URL(...).pathname` 给的正是编码后
 *    的那一份 —— 与 Go 侧 `req.URL.EscapedPath()` 对应。⛔ 别先 decodeURI。
 * 2. **只有真有查询串时才拼 `?`。** 多一个尾随 `?` 就是另一个字符串。
 * 3. **body 要 clone 了再读。** `await request.text()` 会消费掉请求体,请求随后
 *    带着空 body 发出去,而签名覆盖的是真 body —— 症状是一个与路径、与编码
 *    都无关的 401。`request.clone()` 是 TS 侧的 `GetBody()`。
 *
 * ⚠️ 这三条在 tests/generated-client.signing.test.ts 里各有一条断言,并且都做过
 * 「改坏它,看它红」的负向验证 —— 与 Go 侧 signing_differential_test.go 同形。
 */
function signingMiddleware(apiKeyID: string, privateKey: Uint8Array): Middleware {
  return {
    async onRequest({ request }) {
      const url = new URL(request.url);

      // 1. + 2.
      let path = url.pathname;
      // ⚠️ url.search 已经带上了 "?",空查询串时它是 ""。
      if (url.search) {
        path += url.search;
      }

      // 3.
      const raw = await request.clone().arrayBuffer();
      const body = new Uint8Array(raw);

      const timestamp = Date.now();
      const nonce = generateNonce();
      const signature = await signRequestWithNonce(
        privateKey,
        timestamp,
        nonce,
        request.method,
        path,
        body,
      );

      request.headers.set("X-API-Key-ID", apiKeyID);
      request.headers.set("X-Timestamp", String(timestamp));
      request.headers.set("X-Nonce", nonce);
      request.headers.set("X-Signature", signature);
      return request;
    },
  };
}

/**
 * Creates an openapi-fetch client for the remote-signer API with Ed25519
 * request signing already wired in.
 *
 * @example
 * ```ts
 * const api = createSignedClient({
 *   baseURL: "http://127.0.0.1:8548",
 *   apiKeyID: "agent",
 *   privateKey: process.env.AGENT_KEY_HEX!,
 * });
 * const { data, error } = await api.GET("/api/v1/evm/rules", {
 *   params: { query: { enabled: "true" } },
 * });
 * ```
 */
export function createSignedClient(options: SignedClientOptions): Client<paths> {
  if (!options.baseURL) throw new Error("baseURL is required");
  if (!options.apiKeyID) throw new Error("apiKeyID is required");
  if (!options.privateKey) throw new Error("privateKey is required");

  const client = createClient<paths>({
    baseUrl: options.baseURL.replace(/\/$/, ""),
    fetch: options.fetch,
  });
  client.use(signingMiddleware(options.apiKeyID, parsePrivateKey(options.privateKey)));
  return client;
}

/** The generated path map. Re-exported so callers can type their own helpers. */
export type { paths };
