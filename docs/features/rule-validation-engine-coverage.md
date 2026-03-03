# 规则校验与引擎覆盖缺口（Rule Validation vs Engine Coverage）

## 1. 问题

委托（delegation）模式下出现的 bug（如「delegation target scope mismatch」）在单元测试和 e2e 中都没有暴露，上线后真实请求才失败。根因不是单点逻辑写错，而是**规则测试体系没有覆盖「实例化后的规则 + 完整引擎（含委托与 scope 匹配）」这条路径**。

- **validate-rules** 只做「单条规则的脚本级校验」，不跑引擎、不跑委托、不跑 scope 匹配。
- **-config 展开后的规则** 在 validate-rules 里**根本不会用 test_cases 做任何断言**（见下）。
- 模板里（如 polymarket_safe.template.yaml / polymarket_safe.template.js.yaml）定义的「完整闭环」test_cases，在 JS 规则这条线上**没有**被「用引擎跑一遍实例化规则」的流程用到，相当于闭环测试在 JS 规则里**丢失**了。

结果是：新写规则或改 delegate_to/scope 时，验证工具无法提前发现「委托目标 scope 不匹配」这类问题，只能靠上线后出错再修。

---

## 2. 当前规则测试是怎么加的

### 2.1 validate-rules 单文件（如 `rules/templates/polymarket_safe.template.js.yaml`）

- 读 YAML → 用 `test_variables` 做变量替换 → 得到若干条 `RuleConfig`。
- 对每条 **evm_js** 规则：若有 `test_cases` 且 `templateTestVariables != nil`，则调用  
  `jsValidator.ValidateRule(ctx, script, jsTestCases, templateTestVariables)`。
- `JSRuleValidator.ValidateRule` 内部只做：对每个 test case 的 input 调  
  `evaluator.ValidateWithInput(script, ruleInput, configObj)`，然后对比 `expect_pass` / `expect_reason`。

也就是说：**只跑了「脚本 + 单条 input」**，没有 RuleEngine、没有 RuleRepository、没有 `delegate_to`、没有 `ruleScopeMatches`。委托和 scope 完全没被练到。

### 2.2 validate-rules -config（如 `validate-rules -config config.yaml`）

- 与服务器一致：`ExpandTemplatesFromFiles` → `ExpandInstanceRules` → `ExpandFileRules`，得到展开后的规则列表。
- 调用 `validateRules(ctx, localRules, ..., templateTestVariables, ...)` 时，**传入的 `templateTestVariables` 是 `nil`**（见 `validateConfig` 的调用处）。
- 对 evm_js 分支条件：`len(ruleCfg.TestCases) > 0 && jsValidator != nil && templateTestVariables != nil`。  
  因为 `templateTestVariables == nil`，所以**永远不会跑 test_cases**，直接走 `result.Valid = true; passed++`。

因此：**用 -config 校验时，实例化后的规则集根本没有用任何 test_cases 做断言**，只是语法/结构过了就算过。

### 2.3 e2e（config.e2e.yaml + TestRule_PolymarketSafeChain 等）

- 服务启动时用与 main 相同的流程：展开模板与实例规则，**把展开后的规则同步到 DB**，再用 `WhitelistRuleEngine` + 委托 converter 处理请求。
- 所以 e2e **确实**走了「完整引擎 + 委托 + scope 匹配」。
- 但存在缺口：
  - e2e 用的是 **config.e2e.yaml** 的规则（如 `e2e-safe-polymarket` → `e2e-polymarket#transactions`），与生产 config 的 rule ID/名称可能不同。
  - 模板里定义的 test_cases（如 polymarket_safe.template.yaml 里那一整套 pass/reject）**没有**被「展开成规则 → 用引擎跑这些 test_cases」的流程复用；e2e 是手写请求、手写断言，和模板里的 test_cases 不是同一套数据。
  - 若某条真实请求（例如 split）没有对应的 e2e 用例，就不会在 e2e 里暴露 scope mismatch。

结论：**规则实例化后的「用同一套 test_cases 走完整引擎」的验证路径目前不存在**；polymarket_safe.template.yaml 那种「完整闭环」测试在 JS 规则链路上相当于丢了。

---

## 3. 根因归纳

| 层级 | 是否覆盖 | 说明 |
|------|----------|------|
| 模板 test_cases（YAML） | 仅脚本级 | validate-rules 单文件时，只跑 JSRuleValidator：script + input → result，无引擎、无委托。 |
| 实例化后的规则（-config 展开） | 未用 test_cases | validate-rules -config 时 templateTestVariables 为 nil，evm_js 的 test_cases 根本不跑。 |
| 完整引擎（委托 + scope） | 仅 e2e 手写用例 | e2e 用 config 展开规则并跑引擎，但不使用模板内 test_cases，且 e2e 用例未必覆盖所有真实请求形态。 |

所以：**没有「实例化规则 + 同一套 test_cases + 完整引擎」的验证环节**，委托/scope 类 bug 无法被验证工具发现。

---

## 4. 修复方向（建议）

目标：**让模板/实例里定义的 test_cases 能对「实例化后的规则集」做一次「完整引擎」的闭环验证**，这样委托、scope 匹配、目标规则行为都会在同一套测试数据下被覆盖。

### 4.1 增加「引擎校验」路径（推荐）

- **入口**：可以是 validate-rules 的新模式（如 `-config -engine-validate`）或独立小工具。
- **步骤**：
  1. 与现在一样：`Load(config)` → `ExpandTemplatesFromFiles` → `ExpandInstanceRules` → `ExpandFileRules`，得到展开后的规则列表。
  2. 将**展开后的规则**写入**内存 RuleRepository**（不写真实 DB）。
  3. 用与服务器相同的依赖构造 **WhitelistRuleEngine**（含 `WithDelegationPayloadConverter(evm.DelegatePayloadToSignRequest)`），并注册同样的 evaluators。
  4. 对「带有 test_cases 的 evm_js 规则」：
     - 用该规则的 scope（chain_id, chain_type, signer_address 等）和 test case 的 input，构造出 `SignRequest` 和（若需要）`ParsedPayload`。
     - 调用 `engine.EvaluateWithResult(ctx, req, parsed)`。
     - 用 test case 的 `expect_pass` / `expect_reason` 做断言。
  5. 若任一 test case 不通过，则校验失败并报错（可输出 last_no_match_reason 等便于排查）。

这样：

- **同一套 YAML test_cases** 既可以被「脚本级」校验保留（现有行为），又可以被「引擎级」校验使用。
- **委托链**（Safe → polymarket#transactions）和 **ruleScopeMatches** 都会被执行，scope mismatch 会在校验阶段暴露。
- 新规则或修改 delegate_to/scope 后，只要跑一遍引擎校验，就能在合并/上线前发现类似问题。

### 4.2 其它可选项

- **e2e 复用模板 test_cases**：在 e2e 里读取模板/实例的 test_cases，构造请求后调 API，再断言。能加强 e2e 覆盖，但 e2e 较慢、依赖服务；更适合作为补充，而不是唯一的「闭环」保障。
- **-config 时传入 test_variables**：给展开后的规则补一层「默认 test_variables」（例如从各模板的 test_variables 合并而来），让现有 validate-rules 至少能跑脚本级 test_cases。这仍不覆盖引擎/委托，但比完全不跑 test_cases 好，可作为短期缓解。

---

## 5. 小结

- **现状**：规则测试 = 单规则脚本级校验；实例化后的规则集没有用 test_cases 跑完整引擎；模板里「完整闭环」测试在 JS 规则路径上缺失。
- **后果**：委托、scope 等依赖引擎行为的 bug 无法被 validate-rules 或现有 e2e 用例稳定发现。
- **建议**：增加「引擎校验」路径，用展开后的规则 + 内存 repo + 同一套 test_cases 跑 `WhitelistRuleEngine.EvaluateWithResult`，使「实例化规则 + 完整闭环」可被验证工具覆盖。
