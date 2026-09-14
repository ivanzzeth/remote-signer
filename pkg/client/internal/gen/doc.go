// Package gen holds the Go SDK generated from internal/apidocs/openapi.json.
//
// ⛔ 生成的代码 —— 改 *.gen.go 没有意义,下一次 `make sdk` 会覆盖。
//
//	要改**接口形状**(路径 / 参数 / 状态码 / DTO):
//	    改 handler 上的 @Router/@Param/@Success 注解 → make openapi && make sdk
//	要改**重试 / 分页 / 鉴权 / 错误信息**:
//	    改 pkg/client/<域>/*.go 的手写封装,或 pkg/client/internal/transport/
//	要改**业务行为**:
//	    ⛔ 不在 SDK 里,在 internal/ 里
//
// ⭐ 三行「要改 X 去哪」比一行 DO NOT EDIT 有用得多(提案 §4.5)。
//
// # 这个包为什么是 internal 的
//
// 它是 pkg/client 的实现细节,不是对外接口。对外接口是 pkg/client 那些手写的
// 服务方法,它们的签名和文档是人写给人看的;⛔ 把生成出来的
// `GetApiV1EvmRulesIdBudgetsWithResponse` 暴露成公开 API,等于把「swag 怎么
// 拼 operationId」变成本仓库的兼容性承诺。
//
// # ⛔ 签名不在这里,而且不可能在这里
//
// 服务端要的是 Ed25519 签名头(X-API-Key-ID / X-Timestamp / X-Nonce /
// X-Signature,签的是 `{ts}|{nonce}|{method}|{EscapedPath}[?{RawQuery}]|{sha256(body)}`)。
// OpenAPI 的 securitySchemes 表达不了「把这五段按这个顺序拼起来再签」——
// S9 量过这件事。所以注入点是手写的:
// pkg/client/internal/transport.SigningRequestEditor。
//
// ⚠️ 一个每次调用都 401 的生成 SDK 比没有更糟,所以那段注入有一条差分测试钉着:
// pkg/client/internal/transport/signing_differential_test.go 让生成客户端和手写
// 客户端发同一个逻辑调用,断言两边的 X-Signature **逐字节相同**。
package gen
