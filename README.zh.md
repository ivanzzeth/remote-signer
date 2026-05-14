**中文** | [English](README.md)

---

# Remote Signer

面向 EVM 链的安全、策略驱动的签名服务。通过规则引擎控制**签什么**，而不仅是**谁可以签**。

## 快速开始

### 一条命令单实例启动（SQLite，零配置）

```bash
curl -sSLf -o remote-signer \
  "https://github.com/ivanzzeth/remote-signer/releases/latest/download/remote-signer-$(uname -s | tr A-Z a-z)-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" \
  && chmod +x remote-signer

./remote-signer
```

首次启动自动创建 `~/.remote-signer/`，写入默认配置，并生成 admin Ed25519 密钥对。私钥路径仅打印一次到 stderr。

### 一键安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ivanzzeth/remote-signer/main/scripts/setup.sh)
```

### 手动克隆

```bash
git clone https://github.com/ivanzzeth/remote-signer.git && cd remote-signer && ./scripts/setup.sh
```

## 文档

| 文档 | 说明 |
|------|------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | 核心概念、关系、数据流（Signer、Wallet、API Key、Rule、Template、Preset、Budget、Audit） |
| [SECURITY.md](SECURITY.md) | 威胁模型、安全边界、密钥管理、破坏影响分析 |
| [配置参考](docs/configuration.md) | 完整 `config.yaml` 说明 |
| [部署指南](docs/deployment.md) | Docker、Kubernetes、高可用、监控、备份 |
| [规则、模板与预设](docs/rules-templates-and-presets.md) | 概念：规则模板、实例、预设 |
| [规则语法参考](docs/rule-syntax.md) | 所有规则类型及示例 |
| [API 参考](docs/api.md) | 完整接口说明 |
| [集成指南](INTEGRATION.md) | Go/TS/Rust SDK、MCP 服务器 |
| [TLS / mTLS 指南](docs/tls.md) | 证书信任模型、生成、生产实践 |
| [TUI 指南](docs/tui.md) | 终端界面：构建、运行、快捷键 |
| [测试指南](docs/testing.md) | 单元测试、E2E、规则校验 |

## 许可证

MIT License
