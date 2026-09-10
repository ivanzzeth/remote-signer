# 文档索引

索引的完整性由 [`../scripts/check-docs.sh`](../scripts/check-docs.sh) 强制 ——
新增文档没挂进来、或挂了不存在的文档,`make check` 都会红。

⛔ **文档分层,别串**:**需求**说「为谁解决什么问题」,**架构**说「系统应该长什么样」,
**模块**说「这一块守哪几条、重构不能弄丢什么」,**专题**说「这件事具体怎么做」。
判据:*这句话换一套完全不同的实现还成立吗?* 成立 = 需求;不成立 = 架构或专题。

## 先读这三份

| 文档 | 回答什么 |
|---|---|
| [`prd.md`](prd.md) | **为谁解决什么问题**、必须给出什么保证、哪些事绝不许发生 |
| [`../ARCHITECTURE.md`](../ARCHITECTURE.md) | 系统**应该**长什么样。代码与它不一致 = 缺陷,停下上报 |
| [`../SECURITY.md`](../SECURITY.md) | 威胁模型、密钥管理、纵深防御 |
| [`product-forms.md`](product-forms.md) | **五种壳**(内嵌/独立 Web UI · TUI · 扩展 · 桌面)、profile 切后端、UI 草图。⛔ 含 **TUI 已冻结**的缺口清单(§3.3) |

## 动手前

| 文档 | 回答什么 |
|---|---|
| [`incidents.md`](incidents.md) | **七次真实事故**。PRD 每条「不许发生」都能追到其中一次 |
| [`glossary.md`](glossary.md) | 术语:Signer / Wallet / Rule / Template / Preset / Budget 各是什么 |
| [`../TESTING.md`](../TESTING.md) | 测试分层、`make check` 的全部门禁、发版前检查 |
| [`../GIT.md`](../GIT.md) | 分支、提交规范、发布流程(⛔ 含 `preflight-release.sh`) |

## 模块设计

⭐ 每份末尾都有「**重构时必须保住的**」清单 —— 这一层写的不是「代码现在长什么样」
(重构完就过时),而是**重构不能弄丢什么**。

| 文档 | 守 PRD 的哪几条 |
|---|---|
| [`modules/rule-engine.md`](modules/rule-engine.md) | G2 默认拒绝 · G4 答得出哪条 · G6 说不清就拒 · N6 拒绝要说理由 |
| [`modules/budget.md`](modules/budget.md) | §5.1 封顶 · N1 算不出 ≠ 无限 · G3 用完就停 |
| [`modules/identity.md`](modules/identity.md) | D2 人钥分离 · D5 多管理员 · N7 不匹配要说得出 |
| [`modules/permissions.md`](modules/permissions.md) | D4 能力档 · G7 不能自我提权 · D6 越权即不存在 |
| [`modules/custody.md`](modules/custody.md) | G1 私钥不离开 · G5 收回立即生效 |
| [`modules/catalogue.md`](modules/catalogue.md) | §5.2 可组合 · §5.4 跨链 · N5 看得出实际允许什么 |

## 工程

| 文档 | 回答什么 |
|---|---|
| [`development.md`](development.md) | 本地开发:环境、构建、常用命令 |
| [`agent-workflow.md`](agent-workflow.md) | AI 协作:从 issue 到提交的完整流程 |
| [`integration.md`](integration.md) | Go / TS / Rust SDK、MCP 服务器集成 |
| [`sdk-cli-matrix.md`](sdk-cli-matrix.md) | SDK 与命令行的可审计映射 |

## 运维与配置

| 文档 | 回答什么 |
|---|---|
| [`configuration.md`](configuration.md) | `config.yaml` 完整参考 |
| [`deployment.md`](deployment.md) | Docker、Kubernetes、HA、监控、备份 |
| [`tls.md`](tls.md) | 证书信任模型、生成、生产实践 |

## 规则

| 文档 | 回答什么 |
|---|---|
| [`rules-templates-and-presets.md`](rules-templates-and-presets.md) | 模板 / 实例 / 预设三个概念的关系 |
| [`rule-syntax.md`](rule-syntax.md) | 所有规则类型与示例 |
| [`rules/README.md`](rules/README.md) | 按协议分的规则教程索引 |

### 按协议的规则教程

| 协议 | 文档 |
|---|---|
| Polymarket | [EN](rules/polymarket.en.md) · [中文](rules/polymarket.zh.md) |
| Predict | [EN](rules/predict.en.md) · [中文](rules/predict.zh.md) |
| Uniswap | [EN](rules/uniswap.en.md) · [中文](rules/uniswap.zh.md) |
| USDC | [EN](rules/usdc.en.md) · [中文](rules/usdc.zh.md) |

## 界面

| 文档 | 回答什么 |
|---|---|
| [`tui.md`](tui.md) | ⛔ **冻结的遗留形态**(2026-04-03)。构建、运行、快捷键;缺什么见 `product-forms.md` §3.3 |
| [`tui-design-notes.md`](tui-design-notes.md) | ⚠️ 2026-03 的**历史设计提案**,方案已实现;现状看 `tui.md` |
