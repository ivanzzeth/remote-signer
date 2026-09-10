# 文档索引

索引的完整性由 [`../scripts/check-docs.sh`](../scripts/check-docs.sh) 强制 ——
新增文档没挂进来、或挂了不存在的文档,`make check` 都会红。

⛔ 文档分层,别串:**需求**说「为谁解决什么问题」,**架构**说「系统应该长什么样」,
**专题**说「这件事具体怎么做」。判据:*这句话换一套完全不同的实现还成立吗?*
成立 = 它属于需求;不成立 = 它属于架构或专题。

## 先读这三份

| 文档 | 回答什么 |
|---|---|
| [`incidents.md`](incidents.md) | PRD §6 每一条「不许发生」背后的**真实事故**。约束是学来的,不是设想的 |
| [`prd.md`](prd.md) | **为谁解决什么问题**、必须给出什么保证、哪些事绝不许发生。所有其它文档从这里反推 |
| [`../ARCHITECTURE.md`](../ARCHITECTURE.md) | 系统**应该**长什么样。代码与它不一致 = 缺陷,停下上报 |
| [`../SECURITY.md`](../SECURITY.md) | 威胁模型、密钥管理、纵深防御 |
| [`glossary.md`](glossary.md) | **术语**:Signer / Wallet / Rule / Template / Preset / Budget 各是什么 |

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

## 模块设计

| 文档 | 回答什么 |
|---|---|
| [`modules/rule-engine.md`](modules/rule-engine.md) | 判定顺序、每道门失败的方向、委托链 |
| [`modules/budget.md`](modules/budget.md) | 三个上限字段为何都用同一个值表示「无限」、原子扣减、动态额度的单位数上限 |
| [`modules/identity.md`](modules/identity.md) | 人和钥匙**尚未分开**、三处归属互不担保、认证失败要分两种结论 |
| [`modules/permissions.md`](modules/permissions.md) | 权限矩阵住错了层、危险性按属性推导、**G7 目前只成立一半** |
| [`modules/custody.md`](modules/custody.md) | 私钥只进不出、密钥在磁盘而数据库只存公钥、锁是运行时状态 |
| [`modules/catalogue.md`](modules/catalogue.md) | 模板/预设/实例三层、变量四个阶段、引用键不被文件覆盖 |

⭐ 每份末尾都有「**重构时必须保住的**」清单 —— 这一层写的不是「代码现在长什么样」
(重构完就过时),而是**重构不能弄丢什么**。

## 工程

| 文档 | 回答什么 |
|---|---|
| [`testing.md`](testing.md) | 单元测试、E2E、规则验证 |
| [`sdk-cli-matrix.md`](sdk-cli-matrix.md) | `pkg/client` 与 CLI 的可审计映射 |
| [`../TESTING.md`](../TESTING.md) | 测试分层与 `make check` 的全部门禁 |

## 界面

| 文档 | 回答什么 |
|---|---|
| [`tui.md`](tui.md) | 终端界面:构建、运行、快捷键 |
| [`tui-rules-subtabs-design.md`](tui-rules-subtabs-design.md) | 终端界面规则管理的交互设计 |
| [`tui-signers-hdwallets-design.md`](tui-signers-hdwallets-design.md) | 终端界面签名者管理的交互设计 |
