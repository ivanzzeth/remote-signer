# OpenAPI 链路提案:结构性消除 SDK 漂移

**用途**：把「handler 注解 → openapi.json → 生成 SDK → 薄封装 + archcheck 门禁」这条链路落到本仓库。

**判据**：*这条链路建成后，一个新端点漏掉 SDK，什么会变红？* 答不上来的环节就是没建成。

⚠️ 这是草稿，不是已定方案。每一条对现状的断言都带 `file:line`，都是实际读过的；凡是没读到就不写，写成「不确定」（见 §9）。

---

## 0. 落地状态与订正（2026-09-10）

⛔ **§1 是写作当时的快照，现在有几处已经不成立** —— 保留原文是为了让后来的人看得出判断是怎么下的，但**别拿 §1 的数字当基线**，照下表重新推导。

| 步 | 状态 | 提交 |
|---|---|---|
| S0 门禁 A（handler-path-dispatch） | ✅ 已落地 | `cb1a6d0` |
| （插入）路由鉴权三件套 | ✅ 已落地 | `5e07343` |
| （插入）构建产物门禁 + CI 真正执行门禁 | ✅ 已落地 | `f1ac7ba` |
| S1① 循环展成 4 条字面量 | ✅ 已落地 | `c17665b` |
| S1② `/api/v1/` JSON 404 兜底 | ✅ 已落地 | `c17665b` `97e4a29` |
| S1③ maximal-config 冲突测试 | ✅ 已落地 | `8175a6b` |
| S2 wallet 测试走真 mux | ✅ 已落地 | `e9cdbbf` |
| （插入）每条路由的权限上棘轮 | ✅ 已落地 | `309065a` |
| S3 wallet 拆 8 条（**范本**） | ✅ 已落地 | `cb1a624` |
| S4 hd-wallets 4 条 + api-keys 6 条 | ✅ 已落地 | `8e82a82` |
| （插入）signers 的动词洞（GET 能解锁） | ✅ 已修 | `6d30ba1` |
| S4 signers 拆 11 条 | ✅ 已落地 | `2daf1f0` |
| （插入）blackbox 层吃缓存的假绿 | ✅ 已修 | `2daf1f0` |
| S5 settings 拆 18 条 | ✅ 已落地 | `0c660bd` |
| S6 templates + instances 闭包 | ⬜ 未开始 | |
| S7 requests 闭包 | ⬜ 未开始 | |
| S8 rule.go 12 条（⛔ 切 3 个 PR） | ⬜ 未开始 | |
| S9 起（swag / SDK 生成 / 门禁 C） | ⬜ 未开始 | |

### ⏸ 已挂起、**不要顺手清理**的东西

| 项 | 状态 |
|---|---|
| **`SignerHandler.HandleWalletSigners`** | ⛔ 没有任何路由注册它，但**不是死代码**——2026-09-10 决定：它是**还没接上的功能**，后续要接路由 **且 Web UI 要调这个 API**。已从 `signer.go` 挪到 `signer_wallet.go` 并留注释。⛔ 别删、别在基线里当债务消掉。接的时候按 AGENTS.md 的「变更影响面检查」表过一遍 SDK / MCP / Skills。 |
| **hd-wallets 的 RBAC 缺口** | `PermReadHDWallets` / `PermCreateHDWallet` 存在且按角色授予，但四条 hd-wallet 路由都挂 `AuthenticatedOnly(hdWalletGap)`。⛔ 是被刻意推迟的**安全决定**，单独 PR。 |
| **8 条「写操作挂只读权限」** | `route-mutating-perm` 基线里的 8 行。同上：能被看见和被改掉是两件事。 |
| **`internal/cli/admin/settings_cmd.go:22-25` 帮助文本陈旧** | 写着「Available groups today: security」，实际九个 group 早就都有了。 |

### 实测订正 —— 以下几条是**量过的**，不是重读原文得出的

1. ⛔ **`e2e/test_server.go` 不设的是 14 个字段，不是 8 个**（§1.5 / §2.2 / §4.1 都写着 8）。29 个字段里设了 15 个，留零的 14 个是：`AlertService`、`AuditRetentionDays`、`IPWhitelistConfig`、`IPWhitelistConfigForRead`、`Modules`、`PresetRegistry`、`RPCProvider`、`RequestRepo`、`RequestSimulationRepo`、`RuleEngine`、`SimulationRule`、`SolidityValidator`、`TemplateRegistry`、`TransactionService`。也就是说 rpc-proxy、broadcast、batch-sign、ACL、registry-refresh、request-simulation、module 这些分支在 e2e 里**一条都不注册**。缺口差不多是记录值的两倍。行号是 `639-656`，不是 `640-655`。

2. ⛔ **那个 4 次循环并不是「谁都读不到」**（§5 的门禁 B 备注这么写）。`route-mutating-perm` 早就把它记成了**一行**不可解析的 `POST /api/v1/evm/signers/{address}/*` —— archcheck 的 `resolveString` 把循环变量渲染成 `*`。所以展开的真正收益不是「从看不见到看得见」，而是**从一行糊掉的记录变成四个各有其名的条目**：以后单独改其中任何一条都会各自变红。⚠️ 展开时基线会**双向变红**（新增 4 条 + 旧键失效），这是预期行为，不是出错。

3. ⚠️ **`handlePerm` 已经不存在**，§1.1 那张「5 种形状」的表整体作废：现在所有注册都走唯一入口 `(*Router).handle(pattern, RouteAuth, h)`（见 `internal/api/route_auth.go`），而且**绕过它是门禁禁止的**。§1.1 的行号（`436-439`、`695-698` 等）全部失效。

4. ⚠️ **「55 条 mux pattern」需要重新推导**。maximal config 下实际注册 51 条（50 真实 + 1 条测试探针），S1② 之后 `r.handle(` 是 51 处。门禁 C 的分母别直接用 55。

5. ⛔ **§2.4「每个 handler 测试族都有一个同形状的 helper，换掉即可」对 wallet 不成立。** wallet 有 **42 处**直接分发（⚠️ `WalletHandler` 有**两个** mux 入口：`ServeHTTP` 12 处 + `ServeWalletHTTP` 30 处；只 grep 前者会少算 4 倍），而且 46 个 wallet 测试里有 **20 个用到非导出方法/DTO**，永远成不了路由测试。所以 S2 对每个 handler 都是**文件拆分**，不是换一个函数 —— 后面 S4–S8 按「拆分」估工作量，别按「换 helper」。

6. ⛔ **包依赖方向决定了 S2 的形状**：`internal/api` import 了 `internal/api/handler`，所以 `package handler` 内的测试**不能**反向 import 去拿真 mux（成环）。可行解是把面向 mux 的那些测试挪到**外部测试包 `package handler_test`**（它可以 import 一个 import 了被测包的包）。⭐ 范本形状 = **feature module（`module_wallets.go`）+ 外部测试包 + 测试用 RouteRegistrar**，S4–S8 复制这个形状。

7. ⚠️ **S2 走通的是「分发」，不是「鉴权」。** 测试用的 registrar 丢掉 `RouteAuth` 只注册裸 handler —— 因为 `handle` 套的链首是 `AuthMiddleware`（`middleware/auth.go:62-69`），没有签名头一律 401，而这些测试是从 context 注入 API key 的；走真链等于把 46 个测试全改成鉴权测试。补偿是一条断言「模块注册的就是这两条 pattern **且**带 `permitted(manage_wallets)`」的测试（已负向验证：改权限即红）。⭐ S3 拆解时**必须同步扩充那条断言**到全部 8 条路由及其权限 —— 它是唯一挡住「拆解顺手改权限」的东西，而 §6 把那件事列为**唯一语义不可逆**的风险。

8. ⚠️ **wallet 作为范本 PR 在「快反馈」这条轴上偏弱**：三个文件全是 `//go:build integration`，不在 `http` 层，所以 §2.4「mux 冲突 panic 落到 2.5 秒的 http 层」在它身上不成立（那张网由 `router_maximal_config_test.go` 提供）。⭐ 真能兑现这条收益的是 `internal/api/handler/**` 里**无 tag 的那 569 个用例**。wallet 在 §2.5 的其余判据（自包含、测试厚、无跨 handler 闭包）上仍然成立，可以继续当范本 —— 它的可迁移资产是**形状**，不是它跑在哪一层。

9. ⚠️ **§2.3 的「405 语义不变」在 S1② 之后有一处例外**：method 不匹配的请求会落到 `/api/v1/` 拿到 404 而不是 405。⭐ 但只在**没有 `SettingsManager` 的 Router** 上可见 —— 有 Web UI 的部署里 `/` 早就把这类请求接走并回 HTML 200 了，本来就没有 405 可丢。

---

## 1. 现状核对

### 1.1 路由注册的 5 种形状

| 形状 | 位置 | 条数 |
|---|---|---|
| `r.handlePerm(pattern, perm, h)` | `internal/api/router.go:695-698` | 23 个调用点，其中 `router.go:436-439` 是 4 次循环 → **26 条 pattern** |
| `r.mux.Handle(p, r.withAuth(h))` | `router.go:670-686` | — |
| `r.mux.Handle(p, r.withAuthAndPerm(...))` | `router.go:709-725` | 两者合计 **25 条** |
| `reg.Public / Authenticated / Permitted` | `internal/api/module.go:39-46` | **4 条**（`module_bootstrap.go:35-36`、`module_transactions.go:36-37`） |
| 合计 | | **55 条 mux pattern** |

⚠️ `router.go:436-439` 用字符串拼接造 pattern：

```go
for _, action := range []string{"unlock", "lock", "approve", "transfer"} {
    r.handlePerm("POST /api/v1/evm/signers/{address}/"+action, ...)
}
```

**任何静态读取路由表的工具都读不到这 4 条。** 这是 §5 门禁的前置障碍，也是 §6 的第一步。

### 1.2 ⛔ 真正的阻塞：pattern 数 ≠ 端点数

| handler | 文件:行 | 1 条 pattern 背后 | 真实端点数 |
|---|---|---|---|
| `RuleHandler.ServeHTTP` | `handler/evm/rule.go:171-289` | `/api/v1/evm/rules` + `/api/v1/evm/rules/` | **12** |
| `WalletHandler` | `handler/wallet.go:87-96`、`99-178` | `/api/v1/wallets` + `/api/v1/wallets/` | **8** |
| `SignerHandler.HandleSignerAction` | `handler/evm/signer.go:93-149`、`153-172` | `/api/v1/evm/signers/` | **7** |
| `TemplateHandler` | `handler/template.go:105-182` | `/api/v1/templates/`（内含闭包 `router.go:601-609`） | **≥8** |
| `HDWalletHandler` | `handler/evm/hdwallet.go:129-149` | `/api/v1/evm/hd-wallets/` | **≥5** |
| `SettingsHandler` | `handler/settings.go:44-65`、`83-217` | `/api/v1/admin/settings/` | **18**（9 个 group × GET/PUT，group 表在 `internal/settings/model.go:38-46`） |
| requests 闭包 | `router.go:336-361` | `/api/v1/evm/requests/` | **4** |

按路径分发与 method 分发的分布（逐文件实测）：

| 文件 | 路径分发处 | `switch r.Method` |
|---|---|---|
| `handler/evm/rule.go` | 8 | 2 |
| `handler/evm/signer.go` | 3 | 2 |
| `handler/wallet.go` | 2 | 4 |
| `handler/template.go` | 2 | 2 |
| `handler/settings.go` | 2 | 1 |
| `handler/evm/hdwallet.go` | 2 | 1 |
| `handler/evm/transactions.go` | 2 | 0 |
| 其余 5 个文件 | 各 0–1 | 各 0–2 |

### 1.3 ⭐ `PathValue` 全仓 **0 次**

```
$ grep -rn "PathValue" internal/ --include="*.go" | wc -l
0
```

`router.go:437`、`:445`、`:446` 已经用 `{address}` 通配符注册了，但 **handler 一律仍从 `r.URL.Path` 手工切**（`signer.go:101-110`）。现有的通配符 pattern 是**装饰性的**。

⭐ **这决定了「拆解」是两件事，不是一件**：

1. 按 method + 子路径**注册**（mux 层）
2. handler 改读 `r.PathValue(...)`，删掉 `TrimPrefix/SplitN/HasSuffix`（handler 层）

只做 1 不做 2，`r.URL.Path` 的读取还在，门禁数字不动，而 handler 仍然可以被别的 pattern 打到——**这正是今天的状态**。

### 1.4 类型与响应

| 事实 | 实测 | 说明 |
|---|---|---|
| `respond.JSON` 出口 | **83 处** | `internal/api/respond/respond.go:36` 是唯一签名 |
| 另外两个写出口 | `handler/settings.go` 的 `writeSettingsJSON`、`handler/evm/rpc_proxy.go:222` 的 `writeRPCError` | 后者是 `api-layer-counts.txt:7-10` 明确豁免的 |
| 匿名 `map[string]interface{}` 响应 | **2 处**（`handler/preset.go:247`、`:709`） | ⚠️ 与先前「~13 处」的说法不符，复现不出来 |
| 匿名 struct 响应 | **1 处**（`handler/bootstrap.go:155`） | |
| **未导出 DTO** | **18 个** | 集中在 `handler/evm/hdwallet.go`（6）、`handler/wallet.go`（7） |

⭐ 类型确实处在好形状。**真正要动的是 18 个未导出 DTO** —— 它们会让生成的 SDK 出现难读的名字，或者干脆生成不出来。

### 1.5 测试网

| 层 | 覆盖 | 缺口 |
|---|---|---|
| `http` 层（`scripts/lib/layers.sh:27`） | **76 个测试文件** | ⛔ **全部直接调 `h.ServeHTTP(rec, req)`**（`handler/evm/rule_crud_test.go:38-44`），不经过 mux |
| `internal/api` 包级 | `route_permissions_test.go:41-45` | ⛔ **诱饵**：构造 `&Router{routePerms: ...}` 字面量塞 2 行，从不调 `setupRoutes` |
| `e2e` 层 | 49 个文件 | ⛔ `e2e/test_server.go:639-656` 的 `RouterConfig` **不设** 14 个字段（原文写 8，实测 14 —— 见 §0 订正 1），这些条件路由一条都没跑到 |

⭐ **`h.ServeHTTP` 直调既是最大的迁移成本，也是最好的施力点**：改成经真 mux 路由，1200+ 个既有 handler 测试**一次性变成路由测试**。见 §2.4。

---

## 2. 第 0 步：handler 拆解

### 2.1 目标形状

⭐ **就是 Go 1.22+ 的 method + wildcard pattern，不发明新东西。仓库已经写下了方向。**

| 证据 | 内容 |
|---|---|
| `scripts/lib/arch-baseline/api-layer-counts.txt:20-31` | `manual_method_checks 7`，注释写死：「要消掉它们得先把那两个闭包拆成按子路径注册的路由 —— 那是 feature module 那一步的一部分」 |
| `internal/api/module.go:29-34` | 「⚠️ 这是在增量采纳的：下面这些模块已经搬了，setupRoutes 的其余部分还没」 |
| `internal/api/module_bootstrap.go:35-36` | 已经是 `reg.Public("GET /api/v1/bootstrap/status", ...)` 两条 |

⛔ **不要另起炉灶**（不引入 chi/gin，不引入 huma 的 router）。

### 2.2 mux pattern 冲突：能行，但有一个会炸的形状

| 组合 | 结论 |
|---|---|
| `POST /api/v1/evm/rules/{id}/approve` vs `/api/v1/evm/rules/` | ✅ 严格子集。**仓库已有实证**：`router.go:370` 与 `:365` 共存，daemon 正常启动 |
| `POST /api/v1/evm/rules/validate` vs `POST /api/v1/evm/rules/{id}` | ✅ 字面量段是通配符段的严格子集 |
| `POST /a/{x}/c` vs `POST /a/b/{y}` | ⛔ **在 `/a/b/c` 上重叠且互不包含 → panic** |

⛔ **这是本提案最危险的一处**：冲突 panic 发生在 `NewRouter`（`router.go:168`），即**进程起不来**；而 `setupRoutes` 有 13 处 `if` 条件注册，所以**一个冲突可能只在某种配置下出现**。

⭐ 对策（§6 的 S1，必须在任何拆解之前落地）：把 `RouterConfig` **每一个字段**都填非 nil 的桩，调 `NewRouter`，断言不 panic。✅ 已落地（`8175a6b`，`internal/api/router_maximal_config_test.go`），并用反射钉住「新加字段没填桩就红」——手写字面量只在没人加字段之前是 maximal 的。`e2e/test_server.go:639-656` 仍不覆盖（留零 14 个字段，见 §0 订正 1）。

### 2.3 ⚠️ 两个会被拆解改掉的对外行为

| # | 现状 | 拆解后 | 处置 |
|---|---|---|---|
| 1 | `/api/v1/evm/rules/` 前缀吞掉 `/rules/a/b/c/d`，回 **400 JSON**（`rule.go:271-273`） | 不匹配多段 → 落到 `router.go:663` 的 SPA catch-all → **返回 HTML** | ⛔ 客户端可见回归。**S1 里补 `/api/v1/` 的 JSON 404 兜底** —— ✅ 已落地 `c17665b`（`AuthenticatedOnly`，理由写在注册处）|
| 2 | `%2F`：preset id 含 `/`，handler 用 `EscapedPath()` 手工解（`template.go:105`） | Go mux 按段解转义，`PathValue("id")` 直接得到 `evm/weth` | ⭐ 净收益。但 ⚠️ `rule.go:212` 的 `!strings.Contains(ruleID, "/")` 守卫语义会变 |

⚠️ 405 语义**基本不变**，但 S1② 之后有一处例外：method 不匹配的请求会落到 `/api/v1/` 兜底拿到 404 而不是 405。⭐ 只在**没有 `SettingsManager` 的 Router** 上可见 —— 有 Web UI 的部署里 `/` 早就把这类请求接走并回 HTML 200，本来就没有 405 可丢。见 §0 订正 5。

### 2.4 ⭐ 关键增量：先改测试辅助函数，不改 handler

每个 handler 测试族都有一个同形状的 helper（`handler/evm/rule_crud_test.go:23-45` 是范本），把 `h.ServeHTTP(rec, req)` 换成经真 mux。

- **行为保持可证**：换 helper 之前跑 `make test LAYER=http` 记下全绿；换完再跑，**任何差异都是拆解引入的**
- `PathValue` 自动生效——不必逐用例加 `req.SetPathValue`（⚠️ 那是备用方案，改 1200 次不可接受）
- **mux 冲突 panic 落到 `http` 层**（2.5 秒），而不是 e2e 或线上

⛔ 反过来做——先拆 handler、再修测试——会让「测试红」同时可能是行为变了或 helper 没跟上，分辨成本极高。

### 2.5 顺序

| 序 | handler | 端点数 | 测试量 | 理由 |
|---|---|---|---|---|
| 1 | **`wallet.go`** | 8 | 63 | 自包含、测试厚、无跨 handler 闭包。**范本 PR** |
| 2 | `hdwallet.go` | ≥5 | 22 | 已有 2 条 method pattern 打底 |
| 3 | `signer.go` access 子树 | 7 | 49 | 4 个 action 已拆 |
| 4 | **`settings.go`** | 18 | 39 | ⭐ 一次性消灭「请求体类型随路径参数变」这个 OpenAPI 表达不了的形状 |
| 5 | `template.go` + instances 闭包 | ≥8 | 74 | 消掉闭包 |
| 6 | requests 闭包 | 4 | 18 | 消掉 4 处 method 检查 |
| 7 | **`rule.go`** | 12 | ~90 | ⛔ **最后**。守卫最细，逐条搬运最容易掉字段 |

⛔ **拆解 PR 里不许改权限。** 拆成 12 条路由**给了**逐条声明正确权限的机会——⚠️ 但那是行为变更，不是重构。**先原样搬，权限收紧走单独 PR**，否则「测试红」的原因空间会翻倍。

### 2.6 每一步怎么证明行为不变

| 手段 | 覆盖什么 | 缺口 |
|---|---|---|
| `make test LAYER=http`（2.5s） | 拆解前后同一批用例 | ⛔ helper 换 mux 之后才算路由测试 |
| `make test LAYER=e2e` | 经 Go SDK 的真实请求 | ⛔ 只覆盖 Go SDK 的 59 条路径 |
| `cd pkg/js-client && npm test` | TS SDK 独有的那部分 | ⚠️ 覆盖面未核对，见 §9.4 |
| **新增** maximal-config 冲突测试 | pattern 冲突 | 今天完全没有 |
| **新增** `handler-path-dispatch` 门禁 | 「还有没有人在读 `URL.Path`」 | 今天完全没有 |

⛔ **不安全触碰**：`rpc_proxy.go`（`:119-123`），建议豁免，见 §3.4。

---

## 3. 注解与生成方案

### 3.1 选项对比

| 方案 | 维护状态（2026-09 实测） | 侵入性 | 契合「注释即接口文档」 | 风险 |
|---|---|---|---|---|
| **swaggo/swag v1** | v1.16.6 **2025-07-29**；master 提交到 **2026-04-29** | 零 | ⭐ 完全契合 | ⛔ **只出 Swagger 2.0**，要先转 3.x |
| **swaggo/swag v2** | v2.0.0-rc5 **2026-01-09** | 零 | ⭐ 完全契合 | ⚠️ 长期 rc，但直出 **OpenAPI 3.1** |
| **huma** | v2.39.1 **2026-07-29**，发布密集 | ⛔ **极高**：换 router、重写 87 个 handler、重接 8 层中间件链 | ❌ 相反（类型即文档） | ⛔ 它也表达不了 JSON-RPC 信封与 group 变体 |
| **手写 AST 发射器** | — | 零 | ⭐ | ⛔ **Go struct → JSON Schema 是最难的那部分**，手写是在低估工作量 |

### 3.2 推荐

⭐ **swag 注释语言 + v2-rc5 直出 OpenAPI 3.1，不做格式转换。**

1. **注解语法在 v1/v2 之间基本一致**，即使将来判定 rc 不可用，退回 v1 + 转换器只是换生成命令，**注释一行不用改**。选型风险有便宜的退出。
2. **零侵入**是硬约束。中间件链、fail-closed 权限、`respond` 包是多轮重构攒下的资产。
3. ⛔ **不手写 schema 发射器**。`cmd/archcheck` 的成功恰恰在于它只做**结构判定**；`repo.go:20-25` 自己承认「这是语法的，不是类型检查的」。
4. swag 只作构建期工具，⛔ **不进 `go.mod` require 段被 `pkg/client` 传递依赖**——那正是 `cmd/archcheck/main.go:16-19` 拒绝 golangci-lint 的理由。

⚠️ 推荐附带一个 1 天的 spike，见 §9.1。

### 3.3 注解写在哪

拆解之后，**一个方法 = 一个注解块**，贴在**具体处理函数**上：

```go
// @Summary     列出规则
// @Tags        evm-rules
// @Param       status query string false "过滤状态" Enums(active,pending,rejected)
// @Success     200 {object} evm.RuleListResponse
// @Router      /api/v1/evm/rules [get]
func (h *RuleHandler) listRules(w http.ResponseWriter, r *http.Request) {
```

| 约定 | 内容 |
|---|---|
| ⛔ 注解**不**写在 `ServeHTTP` 上 | 今天的 doc comment 就在那儿，一句话盖 12 个端点——**这正是漂移的形状** |
| ⛔ **拆解未完成的 handler 不许加注解** | 还在 `HasSuffix` 分发的函数，注解只能是猜的 |
| ⚠️ 18 个未导出 DTO 要导出 | 拆解 PR 顺手做 |

### 3.4 ⛔ 4 个非 REST 端点：显式豁免，不许沉默

| 端点 | 为什么描述不了 | 处置 |
|---|---|---|
| `POST /api/v1/evm/rpc/{chainID}` | JSON-RPC 信封，**错误也回 HTTP 200**（`rpc_proxy.go:222`） | 打 `x-non-rest: true`；⛔ 排除出 SDK 生成，保留手写 |
| `/api/v1/admin/settings/{group}` | 请求体**和**响应体都随路径参数变 | ⭐ 拆成 18 条显式路由，问题消失。⛔ 不要用 `oneOf` 硬套 |
| `/metrics` | Prometheus 文本 | `x-non-rest: true`，不生成 |
| `/` | SPA catch-all | ⛔ 不进 spec |
| 异步签名（`sign.go:43-45` 接受 200/201/202，`:73-118` 轮询） | 描述不了轮询循环 | 照实写 3 个状态码；轮询留在手写封装 |

⭐ **判据：一个端点如果 spec 只能描述它的一半，就把「哪一半没描述」写进 `x-` 扩展，而不是让它看起来完整。**

---

## 4. `openapi` 子命令 + 生成 SDK + 薄封装

### 4.1 ⛔ spec 不能从活 router 来

| 障碍 | 证据 |
|---|---|
| `NewRouter` 要 5 个依赖 | `router.go:145-153` |
| 依赖来自组装根、要 DB | `internal/cli/server/run_router.go:132` |
| 即使全桩掉，结果也是**某一次部署**而不是 API | 13 处 `if`；`e2e/test_server.go` 就少配 **14** 个字段（见 §0 订正 1） |

⭐ **spec 必须来自注解（静态）。子命令的职责只是「把已生成的 spec 吐出来」，不是「生成它」。**

### 4.2 落地形状

| 项 | 位置 |
|---|---|
| 生成命令 | `make openapi` → `swag init -g internal/api/router.go -o internal/apidocs --outputTypes json` |
| 子命令 | `internal/cli/apidocs/openapi.go`，`//go:embed openapi.json` 直接写 stdout |
| 用法 | `remote-signer openapi > openapi.json`（无 DB、无 socket、无 Go 工具链） |
| 漂移检查 | CI：`make openapi && git diff --exit-code internal/apidocs/` |

⚠️ **这里必须偏离 lingxiao 的 gitignore 做法，理由是 Go 的构建模型**：

⛔ **`go build` 不跑代码生成。** 任何被已提交代码 import 的生成产物**必须一起提交**，否则 fresh clone 上 `go build ./...` 直接失败。

| 产物 | 提交？ | 理由 |
|---|---|---|
| `internal/apidocs/openapi.json` | ✅ | `//go:embed` 需要它在构建时存在 |
| `pkg/client/internal/gen/*.gen.go` | ✅ | 手写封装 import 它 |
| `pkg/js-client/src/gen/` | ❌ | `npm run prebuild` 从已提交的 `openapi.json` 重生成 |
| 根目录 `/openapi.json` | ❌ | 导出副本，随时可再生 |

### 4.3 生成器与注入式 transport

| 语言 | 生成器 | 版本（实测） | 注入点 |
|---|---|---|---|
| Go | `oapi-codegen` | **v2.8.0 / 2026-07-17**，支持 3.1 | `HttpRequestDoer` + `RequestEditorFn` |
| TS | `openapi-typescript` + `openapi-fetch` | **7.13.0** / **0.17.0**，均 2026-02-11 | `client.use({ onRequest })` |
| Rust | ⛔ 不做 | 见 §7 | — |

⭐ **签名注入是最容易做错的一处。** 服务端签的是 `middleware/auth.go:97-100`，客户端签的是 `transport/auth.go:27-32`。⛔ 生成客户端的 `RequestEditorFn` **必须**：

1. 用 `req.URL.EscapedPath()`（**不是** `req.URL.Path`）——preset id 含 `/` 时编码成 `%2F`，用 `Path` 会永远对不上
2. `RawQuery` 非空才拼 `?`
3. 用 `req.GetBody()` 取 body（读 `req.Body` 会消费掉）

⭐ **必须有差分测试**：同一逻辑调用分别走既有 `transport.doSignedRequest` 与 generated + editor，断言**签名输入串逐字节相同**。⛔ 没有它，鉴权失败的症状是 401 而错误信息不会提到路径编码。

### 4.4 薄封装的边界

| 归封装层（手写） | 归生成层 |
|---|---|
| 重试 / 退避 | 请求构造、序列化 |
| 分页迭代器 | 路径、查询参数拼装 |
| Ed25519 鉴权注入 | 状态码 → 类型分派 |
| 错误友好化 | DTO 类型定义 |
| **异步签名轮询** | |
| EIP-1193 provider | |

⛔ **封装层永远不做业务判断。** 判据：✅ 看到 `status == pending` 就轮询（调用协议）；⛔ 判断某条规则该不该匹配、某个额度够不够（那是 `internal/core/rule` 的事）。

### 4.5 生成文件头

```go
// ⛔ 生成文件 —— 改这里没有意义，下一次 `make sdk` 会覆盖。
//
// 要改**接口形状**：改 handler 上的 @Router/@Param/@Success 注解，然后 make openapi && make sdk
// 要改**重试 / 分页 / 鉴权 / 错误信息**：改 pkg/client/<域>/*.go 的手写封装
// 要改**业务行为**：⛔ 不在 SDK 里，在 internal/ 里
```

⭐ 三行「要改 X 去哪」比一行 "DO NOT EDIT" 有用得多。

---

## 5. archcheck 门禁

`cmd/archcheck/main.go:54-59` 的 `checkDef` + `:61-110` 的 `var checks` 追加即可；双向棘轮由 `:185-252` 提供，**不用改**。

⚠️ `cmd/archcheck/repo.go:39-88` 的 `loadRepo` **只解析无 build tag 的非 `_test.go` 文件**。⛔ **TS SDK 读不到**。

### 门禁 A：`handler-path-dispatch`（⭐ 今天就能建）

| 项 | 内容 |
|---|---|
| 断言 | `internal/api/handler/**` 下任何函数体内出现 `r.URL.Path` / `r.URL.EscapedPath()` |
| Key | `<pkg>.<Recv>.<FuncName>`，⛔ 不含行号 |
| Hint | 「在路由注册时声明子路径，handler 读 `r.PathValue("id")`。⛔ 一个还在切 `URL.Path` 的 handler，它的 `@Router` 注解只能是猜的。」 |
| **预期初始基线** | **16 个文件**，按函数算估 **20–26 条** |

⭐ **这条先建，回报最高**：不依赖 swag、spec、SDK，**独立可发布**，而且让后面每一步拆解**单调**——修好一个，基线少一行，回退会红。

### 门禁 B：`route-annotation`

| 项 | 内容 |
|---|---|
| 断言 | 每条注册的 mux pattern，存在对应的 `@Router <path> [<method>]` |
| ⛔ 前置 | 循环拼接的 pattern 静态读不到（⚠️ 但 `route-mutating-perm` 把它记成了一行糊掉的 `…/{address}/*` —— 见 §0 订正 2），必须先展成 4 条字面量。✅ 已落地 `c17665b` |
| Hint | 「⛔ 别把它加进基线了事——基线里的每一行都是一个 SDK 生成不出来的端点。」 |
| **预期初始基线** | **55 条**，单调递减到 0 |

### 门禁 C：`sdk-route-coverage`

| 项 | 内容 |
|---|---|
| 断言 | `openapi.json` 的 `(method, path)` 集合 **⊆** Go 生成 SDK 覆盖集合 |
| ⛔ TS 侧 | 改为 `pkg/js-client` 的一个测试，红在 js 测试里，不在 archcheck |
| **预期初始基线** | 理想为 0；⚠️ 现实第一次跑大概率 3–8 条 |

### ⛔ 怎么验证门禁真的会红

lingxiao 的原话：**「松判据比没判据更糟：它让人以为有人在看着」**。

| 门禁 | 正向（新增违规必须红） | 反向（修好了没删基线也必须红） |
|---|---|---|
| A | 往基线外的 `health.go` 加 `_ = r.URL.Path` | 把 `rule.go:182` 的 `TrimPrefix` 改成常量 |
| B | 删掉 `POST /api/v1/evm/sign` 的 `@Router` 行 | 补上注解但不删基线行 |
| C | 加一条 `GET /api/v1/evm/ping` 写 `@Router` 不动 SDK | 删掉不再存在的基线条目 |

⛔ **三条都要在合入门禁的那个 PR 里当场跑一遍，输出贴进 PR 描述。** 「已实现」不等于「对这条新 check 生效」——Key 不稳定时反向永远误报，而人会把它当噪声关掉。

⚠️ 同时必须改 `scripts/arch/90-gate-docs-in-sync.sh` 与 `TESTING.md`（现有 14 条已负向验证的门禁，arch/90 钉住这个数）。

---

## 6. 顺序与风险

| 步 | 内容 | 独立价值 |
|---|---|---|
| **S0** | 门禁 A + 基线 + 负向验证 + 更新 `TESTING.md`/arch/90 | ⭐ 拆解从此单调 |
| **S1** | ① 循环展成 4 条字面量 ② `/api/v1/` JSON 404 兜底 ③ maximal-config 冲突测试 | 路由表可静态读；冲突有网 |
| **S2** | handler 测试 helper 改走真 mux（先 wallet） | ⭐ 1200+ 测试变成路由测试 |
| **S3** | `walletsModule`：8 条路由 + `PathValue` + 导出 7 个 DTO | 基线 −1 文件 |
| **S4** | hd-wallets / signers-access / api-keys | 基线 −3 |
| **S5** | `settings` 拆 18 条 | ⭐ 消灭 group 变体 |
| **S6** | templates + instances 闭包 | `manual_method_checks` 7 → 6 |
| **S7** | requests 闭包 | 6 → 2 |
| **S8** | `rule.go` 拆 12 条 | ⛔ 建议切 3 个 PR |
| **S9** | swag spike + 注解 + `make openapi` + 子命令 + 门禁 B | |
| **S10** | oapi-codegen Go SDK + 签名差分测试 | |
| **S11** | openapi-typescript TS SDK | |
| **S12** | 门禁 C | 链路闭合 |

### 会出错的地方

| 风险 | 后果 | 可逆？ | 缓解 |
|---|---|---|---|
| ⛔ mux pattern 冲突 | `NewRouter` panic = **daemon 起不来**，可能只在某种配置下 | 可逆 | S1 的测试**必须先于 S3** |
| ⛔ 404 从 JSON 变 HTML | 客户端解析炸，报错与真因无关 | 可逆 | S1 的兜底 |
| ⛔ 拆解顺手改权限 | ⚠️ **过严会在 e2e 里显形，过松不会** | ⛔ 语义上不可逆 | 拆解 PR 权限逐字照抄 |
| ⚠️ 签名路径编码不一致 | 401，错误信息不提路径 | 可逆 | §4.3 差分测试 |
| ⛔ 生成产物 gitignore 错 | fresh clone `go build` 失败 | 可逆 | §4.2 的表 |
| ⚠️ 门禁 Key 不稳定 | 反向棘轮持续误报 → 有人把 check 关掉 | 可逆 | §5 负向验证当场跑 |

**真正不可逆的只有一件**：拆解过程中悄悄改掉某条路由的权限或可见性，并且被真实调用方消费了。其余全部可 revert。

---

## 7. Rust SDK

| 事实 | 证据 |
|---|---|
| 覆盖 41 条唯一路径（TS 67 / Go 59） | — |
| ⛔ **CI 里没有任何 cargo / rust 步骤** | `grep -rin "cargo\|rust" .github/workflows/` → **空** |
| ⛔ `progenitor` **没有任何 release** | GitHub releases API 返回空 |

### 建议：⛔ 本轮出范围，但把缺口记成计数棘轮

1. ⭐ **一个没有任何东西构建的 SDK，门禁盖不住它。**
2. 生成 Rust SDK 而没人编译它，是**把静默漂移换成静默的生成漂移**。
3. progenitor 无 release、只吃 3.0（我们出 3.1），风险与收益不成比例。

在 `api-layer-counts.txt` 追加计数棘轮 `rust_sdk_path_gap`，注释写明：**这条不是要求补齐，是要求「差距扩大时有人知道」**；要动它先把 `cargo check` 加进 CI。

⚠️ 初值按 67 − 41 = 26 估的占位；真正的分母是 spec 里非豁免端点数，S9 之后才知道。

---

## 8. 落地清单

| # | 动作 | 前置 |
|---|---|---|
| 1 | 门禁 A + 负向验证 + 更新文档 | 无 |
| 2 | 展开循环；`/api/v1/` JSON 404；maximal-config 测试 | 无 |
| 3 | wallet 测试 helper 走真 mux | 2 |
| 4 | 拆 wallet（范本 PR） | 3 |
| 5 | 复制范本：hd-wallets / signers / api-keys / settings / templates / requests | 4 |
| 6 | 拆 `rule.go`（3 个 PR） | 5 |
| 7 | swag spike（3 个 handler，1 天） | 4 |
| 8 | 注解 + `make openapi` + 子命令 + 门禁 B | 6,7 |
| 9 | oapi-codegen Go SDK + 签名差分测试 | 8 |
| 10 | openapi-typescript TS SDK | 8 |
| 11 | 门禁 C | 9,10 |
| 12 | `rust_sdk_path_gap` 棘轮 | 8 |

---

## 9. 不确定的地方

⛔ 说不清的不编答案。

### 9.1 swag v2-rc5 在这份代码上能不能用 —— **必须 spike**

核实的只有发布日期。**没有验证**：泛型 / 内嵌 struct / `json.RawMessage` / `time.Time` / `*T` 的 schema 生成质量；中文 `@Summary` 的处理；rc 与 v1 的注解语法差异。

⭐ **spike 判据**：挑 `bootstrap.go`（最简）、`wallet.go`（已拆）、`rule_crud.go` 的 create（最复杂），看生成的 schema 是否**不用手改就能喂给 oapi-codegen**。不行就退回 v1 + `openapi2conv`，注释一行不用改。

### 9.2 oapi-codegen 生成的方法集合怎么静态提取

**没有看过** v2.8.0 的输出模板。⚠️ 如果路径只在 `fmt.Sprintf` 里，AST 提取会很脆——那时更好的做法是让 `gen-sdk.sh` 顺手产出 `routes.txt`，门禁读它。

### 9.3 「~13 处 ad-hoc map 响应」复现不出来

实测只有 **2 处** + 1 处匿名 struct。**不影响结论**，但记下来免得下一个人照着找 13 处。

### 9.4 js-client 测试到底覆盖哪些端点

`pkg/js-client/tests/` 的 11 个文件名字集中在 crypto / eip1193 / provider —— 看起来**偏 provider 层而非端点层**。TS 有 67 条而 Go 只有 59，**那多出来的 8 条谁在测，没查**。⚠️ 直接影响 §2.6 的行为保持判断：如果那 8 条没测试，拆解到它们时**没有网**。S3 之前应查清。

### 9.5 `manual_method_checks` 能不能归零

实测 7 处分布在 **5 个文件**，比 `api-layer-counts.txt:27-31` 注释描述的范围广。S6/S7 之后应该能到 1–2。⚠️ **注释本身略微漂了**，顺手修。
