# AI Agent 协作工作流

> 本文件定义 AI Agent 接到 issue/task 后的完整工作流程。

---

## 前置条件

```bash
git config core.hooksPath .githooks
```

参考：[DEVELOPMENT.md](./DEVELOPMENT.md)、[.githooks/README.md](./.githooks/README.md)

## 工作流

每个 issue/task 按以下 8 个阶段顺序执行：

```
① 理解需求 → ② 研究存量 → ③ 规划方案 → ④ 实现 → ⑤ 本地验证 → ⑥ 文档同步 → ⑦ 代码审查 → ⑧ 提交推送
```

### ① 理解需求

- 阅读 issue/task，拆解出明确的需求点
- 识别模糊或不完整的地方，向用户确认
- 判断改动范围：单文件简单改动？跨模块功能？架构级变更？

### ② 研究存量

- 搜索代码库中已有的相似实现
- 确认是否有可复用的函数、工具、组件
- 检查 `internal/`、`pkg/` 中相关代码

### ③ 规划方案

| 改动范围 | 行动 |
|---------|------|
| 简单改动（修 typo、单函数调整） | 直接进入实现 |
| 跨 3+ 文件的功能 | 先规划方案再编码 |
| 架构级变更 | 先完成系统设计再进入实现 |

### ④ 实现

项目中 `skills/` 目录提供了各领域技能：

| 场景 | 调用技能 | 说明 |
|------|---------|------|
| 测试驱动开发 | `go-testing` | RED → GREEN → REFACTOR |
| 安全审查 | `go-security` | keystore, Ed25519, 输入校验 |
| 规则开发 | `rule-development` | evm_js, solidity, templates, presets, delegate_to |

### ⑤ 本地验证

```bash
make test               # 单元测试
make test-integration   # 单元 + 内部集成测试
make integration        # 黑盒集成测试
go test -tags e2e ./e2e/...  # E2E 测试
```

#### 服务验证

实现完成后，验证服务可正常启动：

```bash
./remote-signer          # 启动 daemon
curl http://127.0.0.1:8548/health
```

参考 → [Makefile](./Makefile)

### ⑥ 文档同步

| 场景 | 需更新 |
|------|--------|
| 新增/修改 API 端点 | `ARCHITECTURE.md`（若架构变化） |
| 新增/修改规则类型或语法 | `docs/rule-syntax.md` |
| 新增/修改模板或预设 | `docs/rules-templates-and-presets.md` |
| 修改测试策略 | `TESTING.md` |
| 修改安全模型 | `SECURITY.md` |
| 新增/删除模块 | `AGENTS.md` 的仓库结构图 |

原则：**文档与代码实现必须一致**。

### ⑦ 代码审查

逐项检查：

- 安全：无硬编码密钥、输入校验、keystore 密码安全
- 质量：函数 ≤ 50 行、文件 ≤ 800 行、嵌套 ≤ 4 层
- 正确性：错误处理、边界条件、build tag 正确

### ⑧ 提交推送

```bash
git add <files>
git commit -m "<type>: <description>"
git push
```

- 提交信息格式：`<type>: <description>`（type: feat/fix/refactor/docs/test/chore/perf/ci）
- pre-commit hook：密钥扫描 → 大文件检查 → go vet → 单元+集成测试
- pre-push hook：密钥扫描 → 大文件拦截 → 集成测试

## 质量门禁

- [ ] 无硬编码密钥（API Key, keystore password, 私钥）
- [ ] 函数 ≤ 50 行，文件 ≤ 800 行，嵌套 ≤ 4 层
- [ ] go vet 通过
- [ ] 测试覆盖率 ≥ 80%
- [ ] pre-commit hooks 全部通过
- [ ] pre-push hooks 全部通过

## 决策速查

| 场景 | 查阅 |
|------|------|
| 环境搭建 | [DEVELOPMENT.md](./DEVELOPMENT.md) |
| 分支策略、版本规范 | [GIT.md](./GIT.md) |
| 测试分层、build tag | [TESTING.md](./TESTING.md) |
| Git hooks 说明 | [.githooks/README.md](./.githooks/README.md) |
| Agent/skills 目录规范 | [AGENTS.md](./AGENTS.md) |
| 常用命令 | [Makefile](./Makefile) |
| 系统架构 | [ARCHITECTURE.md](./ARCHITECTURE.md) |
| 安全模型 | [SECURITY.md](./SECURITY.md) |
| SDK/集成 | [INTEGRATION.md](./INTEGRATION.md) |
