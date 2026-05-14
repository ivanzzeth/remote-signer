# E2E 测试指南

本指南说明如何运行 JavaScript client 的端到端测试，确保客户端库与 remote-signer 服务器的集成正常工作。

## 快速开始

### 方式一：使用外部服务器（推荐用于 CI/CD）

如果你已经有一个运行中的 remote-signer 服务器：

```bash
# 设置环境变量
export E2E_EXTERNAL_SERVER=true
export E2E_BASE_URL=http://localhost:8548
export E2E_API_KEY_ID=your-api-key-id
export E2E_PRIVATE_KEY=your-ed25519-private-key-hex

# 运行测试
npm run test:e2e
```

### 方式二：自动启动测试服务器

使用提供的脚本启动 Go 测试服务器：

```bash
# 在后台启动测试服务器
./scripts/start-test-server.sh &

# 等待服务器启动（约 5 秒）
sleep 5

# 运行测试
npm run test:e2e
```

### 方式三：手动启动测试服务器

```bash
# 在项目根目录
cd ../../

# 生成 Ed25519 密钥对（如果还没有）
ADMIN_PRIV_KEY=$(openssl genpkey -algorithm ed25519 -outform DER 2>/dev/null | xxd -p -c 256 | head -c 64)
ADMIN_PUB_KEY=$(echo "$ADMIN_PRIV_KEY" | xxd -r -p | openssl pkey -pubout -outform DER 2>/dev/null | xxd -p -c 256 | head -c 64)
ADMIN_KEY_ID="test-admin-$(date +%s)"

# 设置环境变量
export E2E_API_PORT=8548
export E2E_API_KEY_ID=$ADMIN_KEY_ID
export E2E_PRIVATE_KEY=$ADMIN_PRIV_KEY
export E2E_SIGNER_ADDRESS="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
export E2E_CHAIN_ID="1"

# 启动测试服务器
go test -tags=e2e -run TestMain ./e2e &

# 在另一个终端，运行 JavaScript 测试
cd pkg/js-client
export E2E_EXTERNAL_SERVER=true
export E2E_BASE_URL=http://localhost:8548
export E2E_API_KEY_ID=$ADMIN_KEY_ID
export E2E_PRIVATE_KEY=$ADMIN_PRIV_KEY
npm run test:e2e
```

## 环境变量说明

| 变量 | 说明 | 默认值 | 必需 |
|------|------|--------|------|
| `E2E_EXTERNAL_SERVER` | 是否使用外部服务器 | `false` | 否 |
| `E2E_BASE_URL` | 服务器基础 URL | `http://localhost:8548` | 否 |
| `E2E_API_KEY_ID` | API Key ID | `test-admin-key` | 是（外部服务器模式） |
| `E2E_PRIVATE_KEY` | Ed25519 私钥（hex） | 测试默认值 | 是（外部服务器模式） |
| `E2E_SIGNER_ADDRESS` | 测试用的签名地址 | `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` | 否 |
| `E2E_CHAIN_ID` | 测试用的链 ID | `1` | 否 |

## 测试覆盖

E2E 测试覆盖以下功能：

### 1. 健康检查
- ✅ 服务器健康状态检查

### 2. 签名请求
- ✅ Personal message 签名
- ✅ Hash 签名
- ✅ EIP-712 typed data 签名
- ✅ Transaction 签名

### 3. 请求管理
- ✅ 列出请求
- ✅ 根据 ID 获取请求
- ✅ 按状态过滤
- ✅ 按签名地址过滤
- ✅ 分页（cursor）

### 4. 错误处理
- ✅ 无效 API key
- ✅ 无效签名地址
- ✅ 网络错误
- ✅ 无效请求格式

### 5. 轮询机制
- ✅ 等待待处理请求完成

### 6. 认证
- ✅ Ed25519 签名验证
- ✅ 认证错误处理

## 故障排除

### 问题：服务器无法启动

**症状：** 测试失败，提示无法连接到服务器

**解决方案：**
1. 检查 Go 环境：`go version`
2. 安装依赖：`go mod download`
3. 检查端口是否被占用：`lsof -i :8548`
4. 查看 Go 测试服务器日志

### 问题：认证失败

**症状：** 测试失败，返回 401 或 403 错误

**解决方案：**
1. 检查 API key ID 和私钥是否正确
2. 确保私钥格式是 hex（64 字符，无 0x 前缀）
3. 检查服务器中是否注册了对应的公钥
4. 验证时间戳是否在有效范围内（5 分钟）

### 问题：测试超时

**症状：** 测试运行时间过长或超时

**解决方案：**
1. 检查服务器是否正常运行：`curl http://localhost:8548/health`
2. 增加测试超时时间（在 `jest.config.js` 中）
3. 检查网络连接
4. 查看服务器日志，确认请求是否被处理

### 问题：签名失败

**症状：** 签名请求返回错误

**解决方案：**
1. 检查签名地址是否在服务器中配置
2. 验证链 ID 是否正确
3. 检查请求格式是否符合 API 规范
4. 查看服务器日志获取详细错误信息

## CI/CD 集成

### GitHub Actions 示例

```yaml
name: E2E Tests

on: [push, pull_request]

jobs:
  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Set up Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install Go dependencies
        run: go mod download

      - name: Install Node.js dependencies
        run: |
          cd pkg/js-client
          npm ci

      - name: Start test server
        run: |
          cd pkg/js-client
          ./scripts/start-test-server.sh &
          sleep 10
        env:
          E2E_API_PORT: 8548

      - name: Run e2e tests
        run: |
          cd pkg/js-client
          npm run test:e2e
        env:
          E2E_EXTERNAL_SERVER: false
          E2E_BASE_URL: http://localhost:8548
```

## 最佳实践

1. **使用外部服务器模式进行 CI/CD**：更稳定，避免启动/停止服务器的复杂性
2. **使用独立的测试端口**：避免与开发服务器冲突
3. **清理测试数据**：测试后清理创建的请求和规则
4. **使用测试专用的 API key**：不要使用生产环境的密钥
5. **监控测试执行时间**：及时发现性能问题

## 相关文档

- [API 文档](../../../docs/api.md)
- [Go E2E 测试](../../../e2e/e2e_test.go)
- [客户端 README](../README.md)
