# Git Hooks

## 安装

```bash
make hooks
```

> ⛔ **装了才算数,而「装没装」以前没有任何东西在看。**
>
> 2026-09-10:一个 3.8 MB 的构建产物被提交进库,躺了 8 个版本 —— 而下面
> 第 2 条「大文件检查」本来就该拦住它。没拦住的原因是 `core.hooksPath`
> 从来没人设过,**这些 hook 一次都没跑过**。清理它的代价是重写两个仓库的
> 全历史、force-push main 和 32 个 tag、改写父仓库 41 个 submodule 指针。
>
> ⚠️ 所以别把 hook 当保证:它挡不住 `--no-verify`,也挡不住一个没跑过
> `make hooks` 的新 clone。**保证在 CI** —— `.github/workflows/check.yml`
> 在每个分支的每次 push 上跑 `make check`,那里绕不过去。
> hook 的价值是**快**:在提交前 20 秒内告诉你,而不是推上去等 CI。

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
