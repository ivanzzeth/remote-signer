# Remote Signer MetaMask Snap

MetaMask Snap integration for the remote-signer service. This snap allows MetaMask to use a centralized signing service with rule-based authorization.

## ⚠️ 重要提示

**当前状态：MetaMask Flask 集成存在问题，使用体验较差，暂不推荐使用。**

MetaMask Flask 集成存在以下问题：
- 集成过程复杂，配置繁琐
- 开发环境设置困难
- 实际使用中可能遇到各种兼容性问题

建议优先考虑其他集成方式（如直接使用 `@remote-signer/client` 库）。

## Keyring 模式（让 Snap “接管” MetaMask 的签名）

当前 Snap 已支持 **Keyring Snap（账户型）** 的最小实现：MetaMask 里创建一个“远程签名账户”，之后常规的签名请求会通过 Snap 转发到 `remote-signer` 服务完成签名。

### 为什么还会出现 “dApp”？

- **Keyring 模式接管签名**：当你在 MetaMask 里选中这个 Keyring 账户后，后续的签名/交易签名是 **MetaMask → Snap → remote-signer**，不是 dApp 去调 `snap.sign()`。
- **allowedOrigins**：`endowment:keyring.allowedOrigins` 只是 **“哪些网页 origin 有权限触发 keyring 请求”** 的白名单；开发/测试时可以用 `"*"`，生产必须收敛到你的 dApp 域名列表。
- **当前仓库的最小实现**：为了不依赖浏览器 UI 自动化，我们在 e2e 里是直接调用 `onKeyringRequest` 来模拟 MetaMask 的调用（不是要求你写 dApp 代码）。

### 必要权限

`snap.manifest.json` 需要包含：

- `endowment:keyring`（并配置 `allowedOrigins`）
- `snap_manageAccounts`
- `snap_manageState`
- `endowment:network-access`

> 注意：生产环境请把 `allowedOrigins` 从 `"*"` 收敛到你的 dApp 域名列表。

### 当前实现范围（最小可用）

- **账户管理**：`listAccounts` / `createAccount` / `getAccount` / `deleteAccount`
- **签名方法**（通过远程 signer）：`personal_sign`、`eth_signTypedData(_v3/_v4)`、`eth_signTransaction`

### 配置流程

Keyring 账户签名依赖 Snap 内部已配置的 remote-signer 连接信息（`baseURL/apiKeyID/privateKey`），可以通过现有的 `configure` RPC 先写入配置。

> TODO: 后续可以把“创建 Keyring 账户 + 配置 remote-signer”整合成一个更符合 MetaMask UI 的流程。

## 依赖导入说明

### 如何导入 @remote-signer/client

MetaMask Snap 通过以下方式导入 `@remote-signer/client`：

1. **package.json 配置**：
```json
{
  "dependencies": {
    "@remote-signer/client": "file:../../pkg/js-client"
  }
}
```

2. **代码中导入**：
```typescript
import { RemoteSignerClient } from "@remote-signer/client";
import type { SignRequest, SignResponse } from "@remote-signer/client";
```

3. **构建流程**：
   - `@remote-signer/client` 是一个本地文件依赖，指向 `../../pkg/js-client`
   - npm 安装时会创建符号链接：`node_modules/@remote-signer/client -> ../../pkg/js-client`
   - MetaMask Snap 的构建工具（`@metamask/snaps-cli`）会自动将依赖打包到最终的 bundle 中
   - 确保 `pkg/js-client` 已经构建（`npm run build`），生成 `dist/` 目录

### 构建步骤

1. **首先构建 js-client**：
```bash
cd ../../pkg/js-client
npm install
npm run build  # 生成 dist/ 目录
```

2. **然后构建 MetaMask Snap**：
```bash
cd ../../app/metamask-snap
npm install  # 这会链接 @remote-signer/client
npm run build  # 使用 mm-snap build 打包所有依赖
```

### 依赖解析

- `@remote-signer/client` 的 `package.json` 中定义了：
  - `"main": "dist/index.js"` - CommonJS 入口
  - `"module": "dist/index.esm.js"` - ES Module 入口
  - `"types": "dist/index.d.ts"` - TypeScript 类型定义

- MetaMask Snap 的构建工具会：
  1. 解析 `@remote-signer/client` 的入口文件
  2. 递归打包所有依赖（包括 `@noble/ed25519`, `@noble/hashes`）
  3. 生成单个 bundle 文件

## 编译和安装

### 前置条件

1. **安装 Node.js** (v18+)
2. **安装 MetaMask**：
   - 开发环境：需要安装 [MetaMask Flask](https://metamask.io/flask/)（开发版本）
   - 生产环境：使用标准 MetaMask（需要 Snap 已发布到官方目录）

### 编译步骤

#### 1. 构建依赖

首先需要构建 JavaScript client 库：

```bash
# 进入 js-client 目录
cd ../../pkg/js-client

# 安装依赖
npm install

# 构建
npm run build
```

#### 2. 构建 MetaMask Snap

```bash
# 进入 metamask-snap 目录
cd ../../app/metamask-snap

# 安装依赖
npm install

# 构建 Snap
npm run build
```

构建成功后，会在 `dist/` 目录生成 `bundle.js` 文件。

#### 3. 验证构建

```bash
# 验证 manifest
npm run manifest

# 检查构建产物
ls -lh dist/bundle.js
```

### 安装到 MetaMask

#### 方式一：开发环境（MetaMask Flask）

> **⚠️ 警告：MetaMask Flask 集成目前存在问题，使用体验较差，不推荐使用。** 以下内容仅供参考，实际使用中可能遇到各种问题。

MetaMask Flask 是 MetaMask 的开发版本，允许安装未发布的 Snap。

1. **安装 MetaMask Flask**：
   - 访问 https://metamask.io/flask/
   - 按照说明安装 Flask 扩展

2. **本地安装 Snap**：

**选项 A：使用本地文件**

```bash
# 启动本地服务器
npm run serve
```

然后在 MetaMask Flask 里安装：

```javascript
// 获取 Snap ID（本地开发）
const snapId = `local:http://localhost:8549`;

// 安装 Snap
await window.ethereum.request({
  method: 'wallet_requestSnaps',
  params: {
    [snapId]: {}
  }
});
```

> 说明：上面这段 `wallet_requestSnaps` 代码只是用来触发 MetaMask 安装 Snap。你可以在任意网页控制台执行，或者用一个简单的本地 html 页面执行。

**选项 B：使用本地文件路径**

```javascript
// 使用 file:// 协议（需要启用 Flask 的本地文件访问）
const snapId = `local:file://${window.location.origin}/path/to/dist/bundle.js`;

await window.ethereum.request({
  method: 'wallet_requestSnaps',
  params: {
    [snapId]: {}
  }
});
```

**选项 C：使用 npm link（开发）**

```bash
# 在 metamask-snap 目录
npm link

# 在 dApp 中使用
const snapId = 'npm:remote-signer-snap';
```

#### 方式二：生产环境（标准 MetaMask）

生产环境需要将 Snap 发布到 MetaMask Snaps 目录。

1. **发布到 npm**：

```bash
# 确保已登录 npm
npm login

# 发布
npm publish
```

2. **提交到 MetaMask Snaps 目录**：

- 访问 MetaMask Snaps 目录提交页面
- 填写 Snap 信息
- 等待审核通过

3. **在 dApp 中安装**：

```javascript
// 使用发布的 Snap ID
const snapId = 'npm:remote-signer-snap';

await window.ethereum.request({
  method: 'wallet_requestSnaps',
  params: {
    [snapId]: {
      version: '1.0.0'  // 可选：指定版本
    }
  }
});
```

### 开发模式

#### 监听文件变化

```bash
npm run watch
```

这会在文件变化时自动重新构建。

#### 本地服务器

```bash
npm run serve
```

启动本地服务器，用于测试 Snap。

### 完整开发流程示例

```bash
# 1. 构建 js-client
cd ../../pkg/js-client
npm install
npm run build

# 2. 构建并启动开发服务器
cd ../../app/metamask-snap
npm install
npm run build
npm run serve

# 3. 在另一个终端，启动你的 dApp
# 4. 在 dApp 中安装 Snap
```

## Features

- **Centralized Key Management**: Store signing keys securely on a remote server
- **Rule-Based Authorization**: Automatic approval based on configured rules
- **Manual Approval Workflow**: Support for pending requests requiring manual approval
- **Multiple Sign Types**: Support for personal messages, transactions, EIP-712, etc.

## Usage

### Keyring 模式（推荐）

你需要做 2 件事：

1) **配置 remote-signer 连接信息**（只做一次）
2) **创建一个 Keyring 账户**（把“远程签名地址”作为账户地址）

目前仓库提供的是最小实现：配置/创建账户依然通过 `wallet_invokeSnap` 触发（用于把数据写入 Snap 状态、以及创建账户记录）。但一旦账户创建并在 MetaMask 里选中，后续签名将由 MetaMask 自动走 Keyring 流程，不需要 dApp 调 `sign` 这个自定义 RPC。

#### 1) 配置 remote-signer（一次性）

First, configure the snap with your remote signer service details:

```javascript
await window.ethereum.request({
  method: 'wallet_invokeSnap',
  params: {
    snapId: 'YOUR_SNAP_ID',
    request: {
      method: 'configure',
      params: {
        baseURL: 'http://localhost:8548',
        apiKeyID: 'my-api-key',
        privateKey: 'your-ed25519-private-key-hex'
      }
    }
  }
});
```

#### 2) 创建 Keyring 账户（一次性）

> TODO: 后续会提供更贴近 MetaMask UI 的引导流程。当前最小实现要求你显式传入要托管的地址。

```javascript
const account = await window.ethereum.request({
  method: 'wallet_invokeSnap',
  params: {
    snapId: 'YOUR_SNAP_ID',
    request: {
      method: 'createAccount',
      params: {
        // 这里填你的远程 signer 对应的 EVM 地址
        options: { address: '0x...' }
      }
    }
  }
});
console.log('Created keyring account:', account);
```

### Legacy：RPC 模式（不推荐，仅用于兼容/调试）

以下 `sign/getRequest/health/getState` 是自定义 RPC 方法，属于 dApp 调用型模式；Keyring 模式下不需要 dApp 调用 `sign`。

## API Methods

### `configure`

Configure the remote signer connection.

**Parameters:**
- `baseURL` (string): Base URL of the remote signer service
- `apiKeyID` (string): API key identifier
- `privateKey` (string): Ed25519 private key (hex format)

**Returns:** `{ success: boolean }`

### `sign`

Sign a request using the remote signer service.

**Parameters:**
- `request` (SignRequest): Signing request object
- `waitForApproval` (boolean, optional): Wait for manual approval if needed (default: true)

**Returns:** `SignResponse`

### `getRequest`

Get the status of a signing request.

**Parameters:**
- `requestID` (string): Request ID

**Returns:** `RequestStatusResponse`

### `health`

Check the health of the remote signer service.

**Returns:** `{ status: string, version: string }`

### `getState`

Get the current configuration state (without sensitive data).

**Returns:** `{ configured: boolean, baseURL?: string, apiKeyID?: string }`

## Security Considerations

1. **Private Key Storage**: The private key is stored in the snap's encrypted state. However, users should be aware that this key is stored locally in MetaMask.

2. **Confirmation Dialogs**: All signing requests require user confirmation through MetaMask's dialog system.

3. **Network Access**: The snap requires network access to communicate with the remote signer service.

## Development

### Building

```bash
npm run build
```

### Testing

```bash
npm test
```

### Linting

```bash
npm run lint
```

## Troubleshooting

### 构建错误

**问题：找不到 `@remote-signer/client`**
- 确保已先构建 `pkg/js-client`
- 运行 `npm install` 重新安装依赖

**问题：Babel 运行时错误**
- 确保 `@babel/runtime` 已安装
- 检查 `pkg/js-client` 中是否也安装了 `@babel/runtime`

**问题：ES Module 解析错误**
- 使用 `--transpilationMode localAndDeps` 转译所有依赖

### 安装错误

**问题：Snap 无法安装**
- 确保使用 MetaMask Flask（开发环境）
- 检查 Snap ID 格式是否正确
- 查看 MetaMask 控制台的错误信息

**问题：权限被拒绝**
- 确保在 `snap.manifest.json` 中声明了所需权限
- 检查网络访问权限是否已授予

## License

MIT
