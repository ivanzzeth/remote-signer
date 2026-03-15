**中文** | [English](README.md)

---

# Remote Signer

面向 EVM 链的安全、策略驱动的签名服务。通过规则引擎控制**签什么**，而不仅是**谁可以签**。

## 功能特性

- **策略驱动签名** — 白名单/黑名单规则，支持 Solidity 表达式、JS 规则、地址列表、金额限制
- **多链可扩展** — 当前支持 EVM，架构上可扩展至 Solana / Cosmos / Bitcoin
- **人工审批流程** — 通过 Slack、Pushover、Webhook 接收待审批通知
- **Ed25519 API 认证** — 请求签名 + nonce/时间戳防重放
- **动态签名者管理** — 通过 API 或 TUI 在运行时创建 keystore 与 HD 钱包（助记词钱包）
- **终端界面 (TUI)** — 在终端中管理规则、审批请求、创建签名者

## 架构

```
┌─────────────────────────────────────────────────────────────────┐
│                         API 层                                   │
│  /api/v1/evm/sign    /api/v1/solana/sign    /api/v1/.../sign   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                       核心层                                      │
│   SignService  │  RuleEngine  │  StateMachine  │  AuditLogger   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                    链适配层                                        │
│      EVM Adapter (ethsig)  │  Solana / Cosmos / ... (规划中)    │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                      存储层                                       │
│              GORM + PostgreSQL / SQLite                           │
└─────────────────────────────────────────────────────────────────┘
```

## 快速开始

### 一键安装（推荐）

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ivanzzeth/remote-signer/main/scripts/setup.sh)
```

脚本会自动克隆仓库（如未克隆）、安装依赖并运行引导式配置。

### 或手动克隆

```bash
git clone https://github.com/ivanzzeth/remote-signer.git
cd remote-signer
./scripts/setup.sh
```

### 环境要求

- openssl
- Docker（推荐）或 Go 1.24+（本地模式）

### 安装向导会做什么

交互式安装包含 5 步：
1. **部署模式** — Docker + PostgreSQL（推荐）或 本地 + SQLite（仅开发）
2. **API 密钥** — 生成 `admin` 与 `dev` 的 Ed25519 密钥对
3. **TLS** — HTTP、TLS 或 mTLS（Docker 默认 mTLS）
4. **配置** — 生成可运行的配置文件与自动生成的密钥
5. **后续步骤** — 启动命令、健康检查、如何添加签名者

安装完成后：

```bash
# 启动（Docker 模式，推荐）
./scripts/deploy.sh run

# 或启动（本地模式）
./scripts/deploy.sh local-run

# 健康检查（HTTP）
curl http://localhost:8548/health

# 健康检查（mTLS）
curl --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key https://localhost:8548/health
```

服务启动时没有签名者。要添加第一个签名者（导入私钥或 HD 钱包/助记词钱包），请使用 TUI：先构建 TUI，用 `admin` 密钥连接（密钥路径在安装向导最后会给出），在 **签名者** 标签页中可创建 keystore（导入私钥）或创建/导入 HD 钱包。详见下方 [添加签名者](#添加签名者)。

### 手动配置

若需完全手动配置，请参阅 [docs/configuration.md](docs/configuration.md) 的完整配置说明，并以 `config.example.yaml` 为起点。

### 添加签名者

服务启动时没有签名者，需在启动后添加：

- **TUI**（推荐）：使用 `-api-key-file data/admin_private.pem` 无需粘贴密钥。示例（明文 HTTP）：`./remote-signer-tui -api-key-id admin -api-key-file data/admin_private.pem -url http://localhost:8548`。**若安装时启用了 TLS**，需使用 `https://` 并指定 CA（mTLS 时还需客户端证书与私钥），例如 `-url https://localhost:8548 -tls-ca ./certs/ca.crt`，或 mTLS：`-tls-ca ./certs/ca.crt -tls-cert ./certs/client.crt -tls-key ./certs/client.key`。详见 [docs/tui.md](docs/tui.md#tls--mtls)。安装完成后（Docker 模式）可选择「Open TUI to add signers now?」直接启动 TUI。在 **签名者** 标签页可创建 keystore（导入私钥）或创建/导入 HD 钱包。**密码强度要求（强制校验）**：至少 16 位，且必须包含大写 + 小写 + 数字 + 符号；建议 24 位以上。
- **API**：`POST /api/v1/evm/signers`（仅 admin）。见 [docs/api.md](docs/api.md)
- **配置文件**：编辑配置中的 `chains.evm.signers.private_keys`。见 [docs/configuration.md](docs/configuration.md#chains-evm)

## 支持的签名类型

| 类型 | 说明 |
|------|------|
| `hash` | 签预哈希数据（32 字节） |
| `raw_message` | 签原始字节 |
| `eip191` | 签 EIP-191 格式消息 |
| `personal` | 签个人消息（`\x19Ethereum Signed Message:\n`） |
| `typed_data` | 签 EIP-712 结构化数据 |
| `transaction` | 签交易（Legacy / EIP-2930 / EIP-1559） |

## 文档

### 入门

| 文档 | 说明 |
|------|------|
| [使用场景](docs/use-cases.md) | 资金库、机器人、DeFi 等场景 |
| [架构](docs/architecture.md) | 系统设计、分层、适配器 |

### 配置

| 文档 | 说明 |
|------|------|
| [配置参考](docs/configuration.md) | 完整 `config.yaml` 说明 |
| [规则、模板与预设](docs/rules-templates-and-presets.md) | 概念：规则模板、实例、预设及示例 |
| [规则语法参考](docs/rule-syntax.md) | 规则类型：地址列表、金额限制、Solidity、JS、消息模式 |
| [JS 规则 (evm_js)](docs/architecture/js-rules-v1.md) | 基于 Sobek 的进程内 JavaScript 规则 |
| [config.example.yaml](config.example.yaml) | 带注释的配置模板 |

### 集成

| 文档 | 说明 |
|------|------|
| [API 参考](docs/api.md) | 认证、签名、规则、审计等接口说明 |
| [集成指南](INTEGRATION.md) | JS/TS 客户端库、MetaMask Snap |

### 部署与运维

| 文档 | 说明 |
|------|------|
| [部署指南](docs/deployment.md) | Docker、Kubernetes、高可用、监控、备份 |
| [TLS / mTLS 指南](docs/tls.md) | 证书信任模型、生成、生产实践 |
| [TUI 指南](docs/tui.md) | 终端界面：构建、运行、快捷键 |

### 安全

| 文档 | 说明 |
|------|------|
| [安全概览](docs/security.md) | 从网络到应用的 8 层防护 |
| [安全审查](docs/security-review.md) | 发现项、优先级与实施状态 |

### 开发

| 文档 | 说明 |
|------|------|
| [组件](docs/components.md) | 核心接口、数据类型、服务 |
| [请求流程](docs/flow.md) | 带状态机的 8 步签名流程 |
| [测试指南](docs/testing.md) | 单元测试、E2E、规则校验、覆盖率 |

## 路线图

- [x] EIP-712 结构化数据校验
- [x] 终端界面 (TUI)
- [x] Go 客户端 SDK
- [x] JS/TS 客户端 SDK
- [ ] Solidity 规则覆盖率强制
- [ ] Solana 链支持
- [ ] Cosmos 链支持
- [ ] Bitcoin 链支持
- [ ] Web 控制台
- [ ] 审计日志导出（S3、Elasticsearch）

## 许可证

MIT License
