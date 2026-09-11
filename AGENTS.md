# Remote Signer — AI Agent 项目指令

> 本文件是**唯一规范的 AI Agent 项目指令来源**。

---

## AI Agent 目录规范

本项目所有 AI Agent 相关的内容统一放在 `.agents/` 目录下：

```
.agents/
├── skills/             # → symlink to ../skills/（AI Agent 技能全集）
├── agents/             # AI Agent 定义文件（由各工具 symlink 引用）
├── rules/              # 项目级规则（可选）
└── ...
```

### Symlink 映射

| 工具 | 位置 | 说明 |
|------|------|------|
| Claude Code | `.claude/skills` → `../.agents/skills` | 技能定义 |
| Claude Code | `.claude/agents` → `../.agents/agents` | 代理定义 |
| Claude Code | `CLAUDE.md` → `AGENTS.md` | 项目指令 |
| Cursor | `.cursor/rules` → `.agents/` | 直接引用 |
| Windsurf | `.windsurf/` → `.agents/` | 直接引用 |

### 为什么用 `.agents/`

- **工具无关** — `.claude/`、`.cursor/`、`.windsurf/` 是工具专属目录，`.agents/` 是项目自有
- **单一事实源** — `AGENTS.md` 是唯一入口，避免多份指令文件不同步
- **开放标准** — `./skills/` 存放对外可发布的技能，用户可通过 `npx skills` 安装；`.agents/skills/` symlink 指向它，AI 工具消费的是 symlink
- **版本可控** — `.agents/` 纳入版本控制，随项目分支一起管理
- **可迁移** — 切换 AI 工具只需建 symlink，无需重写指令

---

## 仓库结构

```
remote-signer/
├── cmd/remote-signer/      # 主入口（server start, tui, validate, api-key, evm）
├── internal/               # 核心实现
│   ├── api/handler/        # REST API handlers
│   ├── api/handler/evm/    # EVM-specific handlers
│   ├── chain/evm/          # EVM chain adapter + rule engine
│   ├── core/               # 核心领域模型（rule, service, registry, notify）
│   ├── config/             # 配置加载与模板初始化
│   └── storage/            # GORM 数据层（SQLite/PostgreSQL）
├── pkg/                    # 公开 SDK
│   ├── client/             # Go SDK
│   ├── rs-client/          # Rust SDK
│   └── ...                 # 共享工具
├── web/                    # React Web UI (Vite)
├── tui/                    # ⛔ 冻结的遗留终端界面（2026-04-03；只修 bug，不接新功能）
├── electron/               # Electron 桌面壳
├── extension/              # Chrome 浏览器扩展
├── e2e/                    # E2E 测试（build tag: e2e）
├── tests/integration/      # 黑盒集成测试（build tag: integration）
├── rules/                  # 规则预设和模板 YAML
├── docs/                   # 文档（配置、部署、规则语法、TLS、TUI）
├── skills/                 # 对外发布的 AI Agent 技能
├── .agents/skills/         # → symlink to ../skills/
├── .githooks/              # Git hooks
├── .github/workflows/      # CI/CD
├── Makefile                # 项目级命令
├── AGENTS.md               # AI Agent 项目指令（本文件）
├── CLAUDE.md               # → symlink to AGENTS.md
├── ARCHITECTURE.md          # 核心架构
├── SECURITY.md             # 安全模型
├── GIT.md                  # Git 工作流 + 版本规范
├── TESTING.md              # 测试分层规范
└── README.md               # 项目 README
```

## 参考文档

| 文档 | 用途 |
|------|------|
| [`docs/README.md`](docs/README.md) | **文档索引**(专题文档的唯一入口;完整性由 `check-docs.sh` 强制) |
| [`docs/prd.md`](docs/prd.md) | **产品需求** —— 架构与模块文档从它反推。⛔ 里面不写技术 |
| `ARCHITECTURE.md` | 核心概念（Signer, Wallet, API Key, Rule, Template, Preset, Budget, Audit）、数据流、安全边界 |
| `SECURITY.md` | 威胁模型、密钥管理、纵深防御 |
| `GIT.md` | 分支策略、提交规范、发布流程 |
| `docs/integration.md` | Go/TS/Rust SDK、MCP 服务器集成 |
| `TESTING.md` | 三层测试体系（unit / integration / e2e）、build tag 规范 |
| `docs/configuration.md` | `config.yaml` 完整参考 |
| `docs/deployment.md` | Docker、Kubernetes、HA、备份 |
| `docs/rules-templates-and-presets.md` | 规则模板、实例、预设概念 |
| `docs/rule-syntax.md` | 所有规则类型及示例 |
| `docs/tls.md` | TLS/mTLS 证书配置 |
| [`docs/product-forms.md`](docs/product-forms.md) | 五种壳；⛔ **TUI 已冻结**的缺口清单（§3.3）与 PRD **D16** |
| `docs/tui.md` | TUI 操作指南 —— ⛔ 冻结的遗留形态，新功能一律进 Web UI |

## 常用命令

```bash
make build              # ⬅ 默认：带 Web UI 的二进制（= build-embed）
make build-embed        # 同 make build
make build-cli          # 仅 Go 二进制（无 Web UI，后端快速迭代用）
make check              # ⬅ 秒级反馈（≈9s 热跑）：fmt/vet/staticcheck/丢掉的错误/TS-JS lint/测试结构/架构约束
make lint-deps          # 门禁 ⑬ 需要的 node_modules（锁没变会跳过）
make lint-js            # 只跑门禁 ⑬（类型感知 eslint：pkg/js-client + web）
make test               # 默认层（unit http cli，≈16s 冷跑）
make test LAYER=unit    # 只跑单元层（零/低 IO，最快）
make test LAYER=e2e     # 端到端（真起 daemon）
make test LAYER=all     # 全部层级
make test LAYER=unit RUN=TestFoo   # 再按用例名收窄
make test-unit / test-integration / integration   # = LAYER=unit / integration / blackbox
make tidy               # go mod tidy
make clean              # 清理构建产物
```

### 开发命令

```bash
# 启动服务（SQLite，单实例，前台运行）
./remote-signer

# 后台运行（本地开发默认用法）：分离进程，日志写入 ~/.remote-signer/remote-signer.log
./remote-signer server start --daemon
./remote-signer server stop            # 优雅停止（读取 ~/.remote-signer/remote-signer.pid）
tail -f ~/.remote-signer/remote-signer.log

# 启动 TUI（⛔ 冻结的遗留形态，与 Web UI 不对等 —— docs/product-forms.md §3.3）
./remote-signer tui

# 验证规则
./remote-signer validate

# 运行特定包的测试
go test ./internal/core/service/...
go test -tags integration ./internal/chain/evm/...

# E2E 测试
go test -tags e2e ./e2e/...
```

### 测试分层

**两个正交的轴**，别混：

- **Build tag = 这个测试允许碰什么**（tier）：无 tag / `integration` / `e2e`
- **LAYER = 你现在要跑哪一片**（反馈速度）：定义在 `scripts/lib/layers.sh`，
  **唯一事实来源** —— ⛔ 不要在 Makefile 或别处另抄一份包列表

| LAYER | 包 | Build Tag | 冷跑 |
|-------|-----|-----------|------|
| `unit` | `@rest`（**算出来的余量**：无 tag 全部包 − http/cli 已认领） | 无 | 5.3s |
| `http` | `internal/api/...` | 无 | 2.5s |
| `cli` | `internal/cli`,`internal/web`,`tui`,`pkg` | 无 | 7.8s |
| `integration` | `internal/...`（真 SQLite 的仓储测试在这里） | `integration` | 慢 |
| `blackbox` | `tests/integration/...` | `integration` | 慢 |
| `e2e` | `e2e/...` | `e2e` | 慢 |
| `web-unit` | Vitest 打 `web/src`（`src/lib/*.test.ts`） | 无（`@cmd`，不是 go test） | 只需 node，≈18s，**进 `all`** |
| `web-e2e` | Playwright 打嵌入式 React UI | 无（`@cmd`，不是 go test） | 需 node + 浏览器，`all` 不含；`LAYER=web-e2e` 或 `everything` |

⭐ `unit` 是**余量**而非写死列表 —— 这样**新包不可能逃出所有层**。写死的那一版
漏了 7 个包，它们的单测只在慢层被顺带跑到，而全量仍然是绿的。

⚠️ **没有 `repo` 层**：`internal/storage` 的无 tag 测试其实是纯内存的，真仓储
测试带 `integration` tag。一个名叫「仓储·真 SQLite」而实际跑纯测试的层会骗人。

判据：**这个 bug 最早能在哪一层被抓到？** 那就是它该待的层。
详见 [TESTING.md](TESTING.md)。`make check` 现有 **15 条已负向验证的门禁**：6 条测试结构（`scripts/check-tests.sh`）+ 9 条架构约束（`scripts/arch/*.sh`，每条一个文件、可单独跑）。其中 arch/05 是 **AST 判定**（`cmd/archcheck`，仅用标准库，0.2s 扫全树）：Clean Architecture 依赖方向、settings 开关冻结、规则写入收口、write helper 参数顺序、同一份配置格式的多份镜像结构体（按序列化 tag 比对，⛔ 修法是让格式只有一个结构体并用 `type X = pkg.X` 别名，不是把缺的字段补齐）、规则类型表的完整性（零基线）、调用方对引擎的分发（⛔ 收敛方向是让引擎自己回答问题，永远不是删掉某个引擎）、形状高度相似的函数对（归一化后 ≥88%、各 ≥30 行；⚠️ 相似不等于重复，长得像但意思不同的对留在基线里写清理由）、handler 自己按 `r.URL.Path` 分发（`internal/api/handler/**` 里一条 mux pattern 背后藏着好几个端点；⭐ 盯的是 handler 侧而非注册侧——通配符已注册但全仓 `PathValue` 0 次）、**路由鉴权四件套**（`route-auth` 零基线：谁都不许绕过唯一注册入口 `(*Router).handle` 直接摸 mux，豁免必须带**写下来的**理由——⛔ 没有理由的豁免等于关掉检查；`route-auth-exempt`：**不带权限的路由清单**，15 条，双向棘轮让它自己过期——新增一条没权限的路由、或某条**补上了**权限却没删基线行，都红；`route-mutating-perm`：写操作挂在只读权限上；`route-perm-binding`：**每条路由挂哪个权限**，46 条，key 同时含 pattern 和权限的线上取值——⛔ 这一条的基线**是当前事实的记录、不是债务清单**，本来就该每条带权限的路由一行、⛔ 不许「清理」变短。2026-09-10 提案 S3 实测：把 `GET /api/v1/wallets/{id}` 从 `PermManageWallets` 松成 `PermReadSigners`，前三条门禁和其余 12 条**全绿**——只读路由被放松是唯一没人看得见的方向）；arch/40 钉住**构建产物不许入库**（二进制按 git 自己的内容判定，不看后缀；另加 1 MB 上限，两条各自漏掉对方抓的那一半）；arch/90 钉住「门禁清单与 TESTING.md 一致」——这句话本身漂过一次。⚠️ 这个数字只数那**两族**；`make check` 还跑两条同样做过负向验证、但不在这两族里的门禁：`scripts/check-docs.sh`（文档）与 **`scripts/check-lint.sh` ⑫（被丢掉的错误）**——⑫a 签名路径（`core/service` + `chain/evm` + `core/rule`）零容忍、无基线；⑫c `forcetypeassert` 全仓 0；⑫b 其余按九档计数棘轮登记在 `scripts/lib/arch-baseline/ignored-errors.txt`。⛔ 在此之前 errcheck 这一整类**由什么都没有在检查**（`go vet` 和 `staticcheck` 都不做），而一次「测出 0 条」其实是 errcheck 在编译不过的包上崩了。配置见 `.golangci.yml`，版本钉在 `.golangci-version`。⚠️ 第三条同族门禁是 **`scripts/check-js-lint.sh` ⑬（TS/JS lint）**：**类型感知** eslint（版本精确钉死，配置在各包的 `eslint.config.mjs`）扫 `pkg/js-client/src` 与 `web/src`，按「包 × 规则」计数棘轮登记在 `scripts/lib/arch-baseline/js-lint.txt` —— ⭐ **表里没有条目的规则就是硬零**，所以 `no-floating-promises` / `no-misused-promises` / `only-throw-error` / `ban-ts-comment` 在 js-client 是零容忍。⛔ 在此之前:js-client 配了 `.eslintrc.json` 和 `"lint"` 脚本而 **`make check` / `layers.sh` / `.github/workflows/*` 里一次都没出现过 eslint**，第一次真跑就是 3 个 error；那份配置还 extends 非类型感知的 `recommended`，于是对一个签名客户端最要紧的三条 promise 规则**根本没开**，`no-explicit-any` 是 `"warn"`（门禁里 warn 等于没有）；`web/` 一个 lint 配置都没有，开起来实测 **61 处 promise 错误**。依赖用 `make lint-deps` 装，缺了门禁**直接红**不跳过。

> ⛔ **门禁在哪儿执行，比门禁有几条重要。** 2026-09-10 之前，这些门禁只挂在
> `.githooks/pre-commit` 上，而 `core.hooksPath` 从来没人设过 —— 也就是说
> 它们由**什么都没有**在执行，绿是因为有人手动跑 `make check`。那次事故里
> pre-commit 明明有 >1MB 拦截，3.8 MB 的二进制照样进了库。
>
> 现在 `.github/workflows/check.yml` 在**每个分支的每次 push** 上跑
> `make check`（⚠️ ci.yml 只认 main/dev，而事故正是顺着 feature 分支进来的）。
> 本地快反馈用 `make hooks` 装 —— 但那只是快反馈，⛔ 保证在 CI。

## 架构概览

```
Client → Ed25519 Auth → Middleware Pipeline → Handler → SignService
                                                            │
                              ChainAdapter ◄── SignService ─┤
                                                            │
                              Rule Engine  ◄── SignService ─┤
                                                            │
                              Budget Check ◄── SignService ─┤
                                                            │
                              Signer ──signs──► Signature ──┤
                                                            │
                              Audit Log ◄───── Every step ──┘
```

**规则引擎核心流程：**
1. Authentication — Ed25519 API Key 签名验证 + nonce 防重放
2. Authorization — API Key 权限范围检查
3. Blocklist evaluation — 任一匹配则立即拒绝
4. Whitelist evaluation — 任一匹配则自动批准（可委托链）
5. Budget enforcement — 匹配的 whitelist rule 的预算检查
6. Manual approval — 无规则匹配时进入人工审批
7. Signing — 链适配器执行加密签名
8. Audit logging — 全链路审计记录

## 开发流程：变更影响面检查

当 API 端点（handler）新增/修改/删除，或数据模型（storage GORM model）变更时，**务必**检查以下
联动项是否也需要更新。遗漏这些会导致 SDK/MCP 接口缺失或不一致：

| 影响面 | 位置 | 检查方法 |
|--------|------|---------|
| Go SDK | `pkg/client/` | `go build ./pkg/client/...` — 确认 service + types + mock 覆盖新端点 |
| Rust SDK | `pkg/rs-client/` | `cargo check` — 确认 service + types 覆盖新端点 |
| JS Client | `pkg/mcp-server/node_modules/remote-signer-client/` | 检查 `.d.ts`，必要时提 PR 更新 npm 包 |
| MCP Server | `pkg/mcp-server/src/index.ts` | `npm run build` — 确认新工具或参数变更已反映 |
| Skills | `skills/remote-signer-agent/SKILL.md` | Agent RBAC、签名流程、authorizing 自助、CLI 示例是否需要更新 |

**原则**：API 变更是源头；SDK 是自动可推导的（对照 handler 检查 1:1 映射）；MCP 工具是 SDK 的薄封装；
Skills 是面向 AI Agent 的使用文档。

## 关键决策记录

- Go 项目，monorepo（cmd + internal + pkg）
- 两层规则引擎（blocklist → whitelist），fail-closed 安全模型
- SQLite 默认（单实例），PostgreSQL 可选（多实例）
- Web UI 通过 `embed_web` build tag 嵌入二进制
- 测试三层 build tag：无 tag（unit）/ `integration` / `e2e`
- LAYER 分层与 tag 正交，定义在 `scripts/lib/layers.sh`（唯一事实来源）；`unit` 为算出来的余量
- `make check` 承载结构/架构门禁，每条都做过负向验证；pre-commit 只跑 check + unit（秒级）
- 共享 test helpers 放在 **untagged `shared_test_helpers_test.go`**：不带 build tag 所以每个 tier 都编译得到，`_test.go` 后缀所以不进守护进程二进制（Go 按后缀判断，不看名字里有没有 test）
- `AGENTS.md` 是 AI 配置的唯一规范源，`.agents/` 存放 skills/agents 引用
- `./skills/` 对外发布（`npx skills` 安装），`.agents/skills/` symlink 指向它

## 初始化 symlink

在全新 clone 的仓库上，运行以下命令建立 symlink：

```bash
# Claude Code
ln -sf ../.agents/skills .claude/skills
ln -sf ../.agents/agents .claude/agents
ln -sf AGENTS.md CLAUDE.md

# Cursor
ln -sf .agents .cursor/rules

# Windsurf
ln -sf .agents .windsurf
```

## AI Agent 可用技能

> ⚠️ **强制规则**：凡是涉及 agent 侧 remote-signer 操作（CLI 调用、签名流程、RBAC 权限、agent 规则 CRUD、authorizing 卡住处理），必须先调用 `remote-signer-agent` 技能获取当前正确的 CLI 用法、RBAC 权限表和操作步骤，严禁凭训练数据猜测。

项目中 `skills/` 目录提供以下技能：

| 技能 | 文件 | 说明 |
|------|------|------|
| `remote-signer-agent` | `skills/remote-signer-agent/SKILL.md` | Agent 侧操作：agent API key、RBAC、签名流程、authorizing 自助、agent 规则更新 |
| `remote-signer-rule-development` | `skills/remote-signer-rule-development/SKILL.md` | Remote Signer 规则开发（evm_js, solidity, templates, presets, delegate_to） |
| `go-testing` | `skills/go-testing/SKILL.md` | Go 测试模式（table-driven, subtests, benchmarks, fuzzing, coverage） |
| `go-security` | `skills/go-security/SKILL.md` | Go 安全审计（keystore, 密钥管理, 输入校验） |
