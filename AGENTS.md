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
├── tui/                    # Terminal UI (Bubble Tea)
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
├── INTEGRATION.md          # SDK / MCP 集成指南
├── TESTING.md              # 测试分层规范
└── README.md               # 项目 README
```

## 参考文档

| 文档 | 用途 |
|------|------|
| `ARCHITECTURE.md` | 核心概念（Signer, Wallet, API Key, Rule, Template, Preset, Budget, Audit）、数据流、安全边界 |
| `SECURITY.md` | 威胁模型、密钥管理、纵深防御 |
| `GIT.md` | 分支策略、提交规范、发布流程 |
| `INTEGRATION.md` | Go/TS/Rust SDK、MCP 服务器集成 |
| `TESTING.md` | 三层测试体系（unit / integration / e2e）、build tag 规范 |
| `docs/configuration.md` | `config.yaml` 完整参考 |
| `docs/deployment.md` | Docker、Kubernetes、HA、备份 |
| `docs/rules-templates-and-presets.md` | 规则模板、实例、预设概念 |
| `docs/rule-syntax.md` | 所有规则类型及示例 |
| `docs/tls.md` | TLS/mTLS 证书配置 |
| `docs/tui.md` | TUI 操作指南 |
| `docs/testing.md` | 单元测试、E2E、规则验证 |

## 常用命令

```bash
make build              # ⬅ 默认：带 Web UI 的二进制（= build-embed）
make build-embed        # 同 make build
make build-cli          # 仅 Go 二进制（无 Web UI，后端快速迭代用）
make check              # ⬅ 秒级反馈（≈13s）：fmt/vet/staticcheck/测试结构/架构约束
make test               # 默认层（unit http cli，≈16s 冷跑）
make test LAYER=unit    # 只跑单元层（零/低 IO，最快）
make test LAYER=e2e     # 端到端（真起 daemon）
make test LAYER=all     # 全部层级
make test LAYER=unit RUN=TestFoo   # 再按用例名收窄
make test-unit          # = make test LAYER=unit
make test-integration   # = make test LAYER=integration
make integration        # = make test LAYER=blackbox
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

# 启动 TUI
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

⭐ `unit` 是**余量**而非写死列表 —— 这样**新包不可能逃出所有层**。写死的那一版
漏了 7 个包，它们的单测只在慢层被顺带跑到，而全量仍然是绿的。

⚠️ **没有 `repo` 层**：`internal/storage` 的无 tag 测试其实是纯内存的，真仓储
测试带 `integration` tag。一个名叫「仓储·真 SQLite」而实际跑纯测试的层会骗人。

判据：**这个 bug 最早能在哪一层被抓到？** 那就是它该待的层。
详见 [TESTING.md](TESTING.md)（含 5 条已负向验证的结构/架构门禁）。

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
- 共享 test helpers 放在 untagged `shared_test_helpers.go`，确保所有 tier 可复用
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
