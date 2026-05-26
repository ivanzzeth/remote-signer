# 本地开发指南

## 系统要求

- Go >= 1.22
- Node.js >= 18（仅需 Web UI 构建时）
- Docker & Docker Compose（可选，用于 Docker 部署）
- Foundry / Forge（可选，用于 Solidity 规则测试）

## 快速开始

### 1. 安装 Git Hooks

```bash
git config core.hooksPath .githooks
```

### 2. 构建 & 运行

```bash
# 纯 Go 二进制构建（无需 Node）
make build
./remote-signer

# 或带 Web UI 的构建
make build-embed
./remote-signer
```

首次启动会在 `~/.remote-signer/` 下生成默认配置（SQLite、`:8548`、无 TLS），并在 stderr 输出一次 admin 私钥路径。

### 3. 运行测试

```bash
make test               # 纯单元测试
make test-integration   # 单元 + 内部集成测试
make integration        # 黑盒集成测试
```

## 配置体系

### 配置文件

默认配置路径：`~/.remote-signer/config.yaml`

| 配置项 | 说明 |
|--------|------|
| `server.port` | 服务端口（默认 8548） |
| `database.driver` | `sqlite3`（默认）或 `postgres` |
| `database.dsn` | 数据库连接串 |
| `keystore.dir` | 签名密钥存储目录 |
| `templates` | 规则模板定义 |
| `rules` | 规则实例定义 |
| `presets.dir` | 预设目录路径 |

参考 → [docs/configuration.md](docs/configuration.md)

## 测试策略

| 层级 | 命令 | 覆盖范围 | 外部依赖 |
|------|------|---------|---------|
| 单元 | `make test` | 纯逻辑、mock | 无 |
| 集成 | `make test-integration` | GORM+SQLite、httptest | SQLite 内存 |
| 黑盒集成 | `make integration` | CLI/HTTP 黑盒测试 | 二进制 |
| E2E | `go test -tags e2e ./e2e/...` | 完整流程 | 链上 RPC |

参考 → [TESTING.md](TESTING.md)

## 项目结构

```
remote-signer/
├── cmd/remote-signer/      # 主入口
├── internal/               # 核心实现
│   ├── api/                # REST API (handler, middleware)
│   ├── chain/evm/          # EVM 链适配器 + 规则引擎
│   ├── core/               # 领域模型 (rule, service, registry, notify)
│   ├── config/             # 配置加载
│   └── storage/            # 数据层 (GORM)
├── pkg/                    # 公开 SDK
├── web/                    # React Web UI
├── tui/                    # Terminal UI
├── electron/               # Electron 桌面壳
├── extension/              # Chrome 扩展
├── e2e/                    # E2E 测试
├── tests/integration/      # 黑盒集成测试
├── rules/                  # 规则预设和模板
├── docs/                   # 文档
└── skills/                 # AI Agent 技能
```

## Docker 部署

```bash
# 本地开发（SQLite + bind-mount config）
HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose -f docker-compose.local.yml up -d

# 生产部署（PostgreSQL）
docker compose up -d
```

参考 → [docs/deployment.md](docs/deployment.md)

## 常用命令速查

```bash
# 构建
make build              # Go 二进制（无 Web UI）
make build-embed        # 带 Web UI 的二进制

# 测试
make test               # 单元测试
make test-integration   # 单元 + 集成
make integration        # 黑盒集成

# 代码质量
go vet ./...            # 静态分析
go fmt ./...            # 格式化

# 规则验证
./remote-signer validate rules/
./remote-signer validate

# TUI
./remote-signer tui

# 清理
make clean
make tidy
```
