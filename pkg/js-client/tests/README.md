# E2E Tests for Remote Signer JavaScript Client

这些测试用于验证 JavaScript client 库与 remote-signer 服务器的集成。

## 前置条件

1. **Node.js** (v18+)
2. **Go** (v1.21+) - 用于启动测试服务器
3. **OpenSSL** - 用于生成 Ed25519 密钥对（可选，测试会使用 fallback）

## 运行测试

### 方式一：使用外部服务器（推荐）

如果你已经有一个运行中的 remote-signer 服务器：

```bash
# 设置环境变量
export E2E_EXTERNAL_SERVER=true
export E2E_BASE_URL=http://localhost:8548
export E2E_API_KEY_ID=your-api-key-id
export E2E_PRIVATE_KEY=your-ed25519-private-key-hex

# 运行测试
npm test
```

### 方式二：自动启动测试服务器

测试会自动尝试启动 Go 测试服务器：

```bash
# 确保在项目根目录
cd ../../

# 运行 Go e2e 测试以启动服务器（在另一个终端）
go test -tags=e2e -run TestMain ./e2e

# 然后在 js-client 目录运行测试
cd pkg/js-client
npm test
```

### 方式三：使用预配置的测试服务器

```bash
# 在项目根目录启动测试服务器
cd ../../
E2E_EXTERNAL_SERVER=false go test -tags=e2e -run TestMain ./e2e &

# 等待服务器启动
sleep 5

# 运行 JavaScript 测试
cd pkg/js-client
npm test
```

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `E2E_EXTERNAL_SERVER` | 是否使用外部服务器 | `false` |
| `E2E_BASE_URL` | 服务器基础 URL | `http://localhost:8549` |
| `E2E_API_KEY_ID` | API Key ID | `test-admin-key` |
| `E2E_PRIVATE_KEY` | Ed25519 私钥（hex） | 测试默认值 |
| `E2E_SIGNER_ADDRESS` | 测试用的签名地址 | `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` |
| `E2E_CHAIN_ID` | 测试用的链 ID | `1` |

## 测试覆盖

E2E 测试覆盖以下功能：

1. **健康检查**
   - 服务器健康状态检查

2. **签名请求**
   - Personal message 签名
   - Hash 签名
   - EIP-712 typed data 签名
   - Transaction 签名

3. **请求管理**
   - 列出请求
   - 根据 ID 获取请求
   - 按状态过滤
   - 按签名地址过滤

4. **错误处理**
   - 无效 API key
   - 无效签名地址
   - 网络错误

5. **轮询机制**
   - 等待待处理请求完成

## 故障排除

### 服务器无法启动

如果测试服务器无法启动，检查：
- Go 环境是否正确配置
- 项目依赖是否已安装（`go mod download`）
- 端口是否被占用

### 认证失败

如果遇到认证错误：
- 检查 API key ID 和私钥是否正确
- 确保私钥格式是 hex（64 字符）
- 检查服务器中是否注册了对应的公钥

### 测试超时

如果测试超时：
- 检查服务器是否正常运行
- 增加 `testTimeout` 配置
- 检查网络连接

## 持续集成

在 CI 环境中，建议：

1. 使用外部服务器模式
2. 在 CI 配置中启动测试服务器
3. 使用环境变量传递配置

示例 GitHub Actions：

```yaml
- name: Start test server
  run: |
    cd ${{ github.workspace }}
    go test -tags=e2e -run TestMain ./e2e &
    sleep 10

- name: Run e2e tests
  env:
    E2E_EXTERNAL_SERVER: false
    E2E_BASE_URL: http://localhost:8548
  run: |
    cd pkg/js-client
    npm test
```
