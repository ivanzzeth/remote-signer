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

### Docker（个人单机，无缝替换原生 daemon）

```bash
HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose -f docker-compose.local.yml up -d
```

拉 `ghcr.io/ivanzzeth/remote-signer:latest`（multi-arch：`linux/amd64`、`linux/arm64`），把宿主机的 `~/.remote-signer` 挂进容器，自带 restart-on-crash。SQLite 库、admin keystore、signers、API keys 都和原生 daemon 同一份，可以随时切换不用迁移数据。

生产多实例 + PostgreSQL 看 [`docker-compose.yml`](docker-compose.yml) 和 [部署指南](docs/deployment.md)。release 流程与版本约定看 [GIT.md](GIT.md)。

### 桌面应用

每个 release 附带 `.dmg`（macOS）、`.exe`（Windows）、`.AppImage`（Linux）安装包，基于 Electron shell 内嵌 daemon。在 [Releases](https://github.com/ivanzzeth/remote-signer/releases) 页面下载。

Electron 本质上就是一个指向本地 `http://127.0.0.1:8548` 的浏览器窗口，所以桌面应用运行的同时，你可以在普通浏览器里打开同一个 URL——同一份 React 应用、同一个 session、同一份 state。适合让桌面端管 daemon 的生命周期（开机自启、崩溃重启），但 UI 用自己的浏览器。

### TypeScript / JavaScript SDK

```bash
npm install remote-signer-client
```

SDK 版本与 daemon 同步——`remote-signer-client@0.3.9` 对应 daemon `v0.3.9`。用法见 [集成指南](INTEGRATION.md)。

## Chrome 浏览器插件

Remote Signer 提供 Chrome 浏览器扩展，为每个页面注入 EIP-1193 标准的 `window.ethereum` provider，让 dApp 可以直接使用 remote-signer 服务签名。

### 安装

1. 构建扩展：
   ```bash
   cd extension && npm ci --no-audit --no-fund && node build.mjs
   ```
2. 打开 Chrome → `chrome://extensions`
3. 开启**开发者模式**（右上角开关）
4. 点击**加载已解压的扩展程序**，选择 `extension/` 目录
5. **Remote Signer** 图标出现在工具栏

### 使用

1. 点击扩展图标打开弹窗
2. 进入 **Settings**，填写：
   - **Remote Signer URL**（默认 `http://127.0.0.1:8548`）
   - **API Key ID** 和 **Private Key**（从 remote-signer 配置获取）
3. 点击 **Test Connection** 验证连接
4. 打开任意 dApp — 会自动检测到 Remote Signer provider

管理 Rules/Signers/Budgets 等请点击弹窗中的 **Open Management** 打开完整的 web 管理后台。

### 架构

扩展采用三层隔离模式（与 MetaMask 一致）：

```
dApp 页面 (MAIN world)  ←postMessage→  content-script (ISOLATED)  ←chrome.runtime→  background (service worker)  ←fetch→  remote-signer API
```

- `inpage.js` — 注入 `window.ethereum`，支持 EIP-1193 + EIP-6963，零网络 I/O
- `content-script.js` — 纯双向转发，MAIN world ↔ service worker
- `background.js` — EIP1193Provider + RemoteSignerClient，处理所有签名和 RPC
- 无需代理 — service worker 直接使用 Ed25519 签名请求

## 文档

| 文档 | 说明 |
|------|------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | 核心概念、关系、数据流（Signer、Wallet、API Key、Rule、Template、Preset、Budget、Audit） |
| [SECURITY.md](SECURITY.md) | 威胁模型、安全边界、密钥管理、破坏影响分析 |
| [配置参考](docs/configuration.md) | 完整 `config.yaml` 说明 |
| [部署指南](docs/deployment.md) | Docker、Kubernetes、高可用、监控、备份 |
| [规则、模板与预设](docs/rules-templates-and-presets.md) | 概念：规则模板、实例、预设 |
| [规则语法参考](docs/rule-syntax.md) | 所有规则类型及示例 |
| [集成指南](INTEGRATION.md) | Go/TS/Rust SDK、MCP 服务器 |
| [TLS / mTLS 指南](docs/tls.md) | 证书信任模型、生成、生产实践 |
| [TUI 指南](docs/tui.md) | 终端界面：构建、运行、快捷键 |
| [测试指南](docs/testing.md) | 单元测试、E2E、规则校验 |
| [GIT.md](GIT.md) | Release 流程、版本约定、NPM_TOKEN 配置、Docker compose 模式 |

## 许可证

MIT License
