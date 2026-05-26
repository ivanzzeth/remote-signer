# Git Hooks

## 安装

```bash
git config core.hooksPath .githooks
```

## Hooks 说明

### pre-commit

在每次 `git commit` 前自动运行：

1. **密钥扫描** — 检测 staged 文件中的敏感信息：
   - Ed25519 私钥（64+ hex 字符）
   - secp256k1 / Ethereum 私钥
   - keystore 密码
   - API key 赋值
   - SSH/PGP 私钥
   - GitHub tokens
2. **大文件检查** — 拦截 >1MB 的 staged 文件
3. **go vet** — 静态分析
4. **单元 + 集成测试** — `go test -tags integration ./internal/...`

排除路径：`tests/`、`testdata/`、`e2e/`、`mock`、`fixtures`、`.env.example`

### pre-push

在每次 `git push` 前自动运行：

1. **密钥扫描** — 扫描推送范围内所有 commit 的所有文件
2. **大文件拦截** — 拦截 >50MB 的文件
3. **集成测试** — 普通推送跑黑盒集成测试；SemVer tag 推送跑全部测试

## 跳过 Hooks

```bash
# 仅跳过 pre-commit（不推荐，但紧急修复时可用）
git commit --no-verify

# 仅跳过 pre-push
git push --no-verify
```

> 跳过 hooks 前请确保没有密钥泄漏风险。
