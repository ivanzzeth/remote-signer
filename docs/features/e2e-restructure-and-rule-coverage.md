# E2E 拆分与规则覆盖方案

## 1. 目标

- **拆分 e2e**：按规则类型/功能划分测试文件，不再全部放在 `e2e_test.go`。
- **规则与模板双覆盖**：在 e2e 中再次覆盖规则模板内的 `test_cases`，与 `validate-rules` 的单元级校验形成双重保障（高安全要求）。
- **规则类型全覆盖**：当前所有规则类型和已用模板在 e2e 中都有对应用例。
- **清理旧规则文件**：移除不采用模板的大型协议规则文件，仅保留简单规则示例并在 e2e 中测试。

---

## 2. 规则文件清理

### 2.1 移除（不采用模板的旧规则文件）

| 文件 | 说明 |
|------|------|
| `rules/polymarket_safe.yaml` | 大型 Polymarket Safe 规则，已由 `rules/templates/polymarket_safe.template.js.yaml` + 实例替代 |
| `rules/polymarket_eoa.yaml` | 旧 EOA 规则，协议用模板即可 |
| `rules/predict_eoa.yaml` | 旧 Predict 规则，有 `rules/templates/predict_eoa.template.yaml` |
| `rules/opinion.yaml` | 旧 Opinion 规则，有 `rules/templates/opinion_safe.template.yaml` |

**需同步修改**：

- `cmd/validate-rules/main.go`：若示例/帮助中引用 `rules/polymarket_safe.yaml`，改为引用 `rules/treasury.example.yaml` 或 `config.e2e.yaml`。

### 2.2 保留（简单规则示例，并在 e2e 中覆盖）

| 文件 | 规则类型 | 用途 |
|------|----------|------|
| `rules/treasury.example.yaml` | evm_address_list, evm_value_limit | 示例 + e2e 覆盖 |
| `rules/security.example.yaml` | evm_solidity_expression, sign_type_restriction | 示例 + e2e 覆盖 |

### 2.3 模板文件（保留，e2e 通过 config 实例覆盖）

- `rules/templates/safe.template.js.yaml`
- `rules/templates/multisend.template.js.yaml`
- `rules/templates/erc20.template.js.yaml`
- `rules/templates/erc721.template.js.yaml`
- `rules/templates/polymarket_safe.template.js.yaml`
- `rules/templates/opinion_safe.template.yaml`、`predict_eoa.template.yaml`、`polymarket_safe.template.yaml` 等：不纳入 e2e config，仅作非 e2e 环境使用或后续按需加入。

e2e 使用的模板以 `config.e2e.yaml` 中声明的为准（E2E Minimal, E2E Safe, E2E Multisend, E2E ERC20, E2E ERC721, E2E Polymarket）。

---

## 3. E2E 按规则/功能拆分文件

### 3.1 公共与基础设施（保留或小幅调整）

| 文件 | 内容 |
|------|------|
| `e2e_test.go` | 仅保留：`TestMain`、包级常量、共享变量（signer 地址、chainID、client 等）。可考虑改名为 `e2e_main_test.go` 或保持 `e2e_test.go`。 |
| `test_server.go` | 服务启动、admin/non-admin client 初始化、fixture 路径等，不变。 |
| `e2e_helpers.go`（新建，可选） | 公共辅助函数：构建 SignRequest、发 sign、解析结果、常用断言等，供各 `*_test.go` 使用。若量不大可继续放在各测试文件或 `test_server.go`。 |

### 3.2 按规则类型与功能拆分的测试文件

| 文件 | 测试范围 | 对应规则类型 / 模板 |
|------|----------|----------------------|
| `e2e_health_test.go` | `TestHealthCheck` | - |
| `e2e_auth_test.go` | `TestAuth_AdminCanAccessAdminEndpoints`、`TestAuth_NonAdminCannotAccessAdminEndpoints`、`TestAuth_NonAdminCanSubmitSignRequest`、`TestAuth_AdminCanSubmitSignRequest` | - |
| `e2e_sign_test.go` | 所有 `TestSign_*`（PersonalSign, Hash, RawMessage, EIP191, TypedData, LegacyTransaction, EIP1559Transaction, SignerNotFound, ContextCancellation, MultipleRequests, DirectSignAPI） | - |
| `e2e_approval_guard_test.go` | `TestApprovalGuard_PauseAndResume` | - |
| `e2e_rule_crud_test.go` | 规则 CRUD 与权限：`TestRule_AdminCanCreateRule`、`TestRule_AdminCanListRules`、`TestRule_AdminCanGetRule`、`TestRule_AdminCanUpdateRule`、`TestRule_AdminCanDeleteRule`、`TestRule_AdminCanDisableRule`、`TestRule_NonAdminCannot*` | - |
| `e2e_rule_address_test.go` | 地址名单：`TestRule_TransactionToTreasuryPasses`、`TestRule_AddressWhitelist_RejectsNonListedAddress`、与 treasury.example 的 e2e 等价用例 | evm_address_list / evm_address_whitelist |
| `e2e_rule_solidity_test.go` | Solidity 表达式块：`TestRule_SolidityBlocklist_PassesForNormalAddress`、`TestRule_TransactionToBurnAddressBlocked`、与 security.example 中 blocklist 的 e2e 等价 | evm_solidity_expression |
| `e2e_rule_value_test.go` | 价值限制：`TestRule_ValueLimitWhitelist_AllowsUnderLimit`、`TestRule_ValueLimitRuleBlocks`、与 treasury.example 中 value_limit 的 e2e 等价 | evm_value_limit |
| `e2e_rule_signer_test.go` | 签名者限制：`TestRule_SignerRestrictionAllowsTestSigner`、`TestRule_SignerRestrictionBlocksUnknownSigner`、`TestRule_SignerRestriction_BlocksSignerNotInAllowList`、`TestRule_CreateSignerRestrictionViaAPI` | signer_restriction |
| `e2e_rule_sign_type_test.go` | 签名类型限制：`TestRule_SignTypeRestrictionAllowsPersonalSign`、`TestRule_SignTypeRestrictionAllowsTransaction`、`TestRule_SignTypeRestrictionAllowsHashSign`、`TestRule_CreateSignTypeRestrictionViaAPI`、`TestRule_SignTypeRestrictionBlocksDisallowedType` | sign_type_restriction |
| `e2e_rule_message_pattern_test.go` | 消息模式：`TestRule_MessagePattern_AllowsMatching`、`TestRule_MessagePattern_RejectsMatchingBlocklist` | message_pattern |
| `e2e_rule_contract_method_test.go` | 合约方法：`TestRule_ContractMethod_AllowsTransfer`、`TestRule_ContractMethod_BlocklistBlocksApproval` | evm_contract_method |
| `e2e_rule_evm_js_test.go` | evm_js：`TestRule_SignRequestMatchesWhitelistRule`、`TestRule_JSBlocklistBlocksBurnAddress`、`TestRule_DelegationSinglePasses`、`TestRule_SafeMultisendERC20Chain`、`TestRule_SafeMultisendMultiDelegate`、Safe/Polymarket 链上用例（见下节） | evm_js |
| `e2e_rule_polymarket_test.go`（可选） | 仅 Polymarket 模板相关 e2e：`TestRule_PolymarketSafeChain`、`TestRule_PolymarketSafeChain_CTFSetApprovalForAll`、`TestRule_PolymarketSafeChain_RejectDelegateCall`、`TestRule_PolymarketSafeChain_CTFRedeemPositions`、`TestRule_PolymarketSafeChain_ExecTransactionCTFRedeemPositions` 等 | polymarket_safe.template.js.yaml |
| `e2e_request_audit_test.go` | `TestRequest_ListRequests`、`TestRequest_GetRequest`、`TestAudit_ListAuditRecords` | - |
| `e2e_pagination_test.go` | 所有 `TestPagination_*` | - |
| `e2e_signer_test.go` | 所有 `TestSigner_*`（List, ListWithTypeFilter, ListSignersPagination, CreateKeystoreSigner, CreateSignerValidationErrors, NonAdmin*） | - |
| `e2e_template_test.go` | 所有 `TestTemplate_*`（含 ConfigLoadedTemplatesAndInstanceRules、InstanceWithBudget 等） | 模板加载与实例 |
| `e2e_client_test.go`（可选） | `TestJavaScriptClientE2E`、`TestMetaMaskSnapE2E` | 客户端集成 |

现有 `security_test.go`、`tls_test.go`、`tls_helpers_test.go` 保持不变。

---

## 4. 规则模板 test_cases 在 E2E 中的覆盖策略

原则：模板内 `test_cases` 已在 `validate-rules` 中做单元级校验；e2e 对同一批“场景”做端到端校验（真实 HTTP + 真实签名/拒绝），形成双保险。

### 4.1 覆盖方式

- **可端到端复现的用例**：用 e2e 发相同含义的 sign request（personal_sign / typed_data / transaction），断言 allowed / rejected 与模板中 `expect_pass` / `expect_reason` 一致。
- **难以在 e2e 复现的用例**（强依赖特定链上数据、复杂 typed_data 等）：在方案中标注为“仅 validate-rules 覆盖”，e2e 只覆盖该规则类型的代表性正/负向用例。

### 4.2 按模板的覆盖矩阵

| 模板 | 模板内 test_cases 数量（约） | E2E 覆盖策略 |
|------|-----------------------------|--------------|
| **E2E Minimal** | 无独立 test_cases | 已有 `TestTemplate_ConfigLoadedTemplatesAndInstanceRules`；可加 1 个“向 allowed_address 发 tx 通过”的用例。 |
| **safe.template.js.yaml** | 6（SafeTx pass/reject, transaction pass/reject 等） | e2e 已有 Safe 链（Safe → Multisend → ERC20/ERC721）。为每个“通过/拒绝”场景各补 1 个 e2e：SafeTx 通过、SafeTx 错误 verifyingContract、SafeTx 错误 inner to、transaction 非 Safe to 拒绝等。 |
| **multisend.template.js.yaml** | 2（to=multisend 通过，to≠multisend 拒绝） | 已有 `TestRule_SafeMultisendERC20Chain` 等；补 1 个“tx to 非 multisend 被拒”的 e2e。 |
| **erc20.template.js.yaml** | 6（transfer/approve/transferFrom 通过，错误 contract/recipient/method 拒绝） | 在现有 Safe→Multisend→ERC20 链上，补：允许的 transfer、允许的 approve、错误 token 或错误 method 拒绝。 |
| **erc721.template.js.yaml** | 6（transferFrom/approve/setApprovalForAll 通过，错误 contract/recipient/method 拒绝） | 同上，补 ERC721 的允许/拒绝代表性用例。 |
| **polymarket_safe.template.js.yaml** | 多规则（ClobAuth, Order, CreateProxy, Safe Wallet Creation, inner tx） | 已有 `TestRule_PolymarketSafeChain*`。e2e 覆盖：ClobAuth 通过/无效 domain 拒绝、Order 通过/非零 taker 拒绝、CreateProxy 通过/错误 target 拒绝、inner USDC approve 通过/错误 spender 拒绝。 |

### 4.3 规则类型与 E2E 对应关系（汇总）

| 规则类型 | E2E 测试文件 | 覆盖要点 |
|----------|--------------|----------|
| evm_address_list / evm_address_whitelist | e2e_rule_address_test.go | 白名单通过、非名单拒绝；treasury.example 等价 e2e |
| evm_solidity_expression | e2e_rule_solidity_test.go | blocklist 通过/拒绝；security.example 等价 e2e |
| evm_value_limit | e2e_rule_value_test.go | 低于限制通过、超限拒绝；treasury.example 等价 e2e |
| signer_restriction | e2e_rule_signer_test.go | 允许的 signer 通过、不允许的拒绝 |
| sign_type_restriction | e2e_rule_sign_type_test.go | 允许的类型通过、不允许的类型拒绝；security.example 可选 |
| message_pattern | e2e_rule_message_pattern_test.go | 白名单/黑名单模式匹配 |
| evm_contract_method | e2e_rule_contract_method_test.go | 允许的 method 通过、blocklist method 拒绝 |
| evm_js | e2e_rule_evm_js_test.go + e2e_rule_polymarket_test.go | 委托、Safe/Multisend/ERC20/ERC721/Polymarket 链；与各模板 test_cases 对齐的通过/拒绝用例 |

---

## 5. 实施顺序建议

1. **规则文件清理**  
   - 删除 `rules/polymarket_safe.yaml`、`rules/polymarket_eoa.yaml`、`rules/predict_eoa.yaml`、`rules/opinion.yaml`。  
   - 更新 `cmd/validate-rules/main.go` 中的示例路径/帮助文案。

2. **E2E 拆分**  
   - 新建上表所列 `e2e_*_test.go` 文件，按上表从 `e2e_test.go` 迁移对应 `Test*` 函数。  
   - 保留 `e2e_test.go` 中仅剩的 `TestMain`、常量、全局变量。  
   - 共享逻辑放 `e2e_helpers.go` 或 `test_server.go`，避免重复。

3. **简单示例规则 e2e 覆盖**  
   - 在 `config.e2e.yaml` 或 e2e 专用 fixture 中引入/引用 `treasury.example.yaml`、`security.example.yaml` 的规则或等价配置。  
   - 在 `e2e_rule_address_test.go`、`e2e_rule_solidity_test.go`、`e2e_rule_value_test.go` 中增加与示例文件等价的用例（例如 treasury 地址通过、burn/zero 拒绝、value 超限拒绝）。

4. **模板 test_cases 的 e2e 对齐**  
   - 按 4.2 表逐模板补充 e2e：优先 Safe、Multisend、ERC20、ERC721、Polymarket 中“通过 + 至少 1 个典型拒绝”场景，使 e2e 与模板内 test_cases 一一对应或成子集。

5. **CI 与文档**  
   - 确保 `go test -tags=e2e ./e2e/...` 全部通过。  
   - 在 `docs/` 或 README 中简短说明 e2e 文件与规则类型/模板的对应关系（可引用本文档）。

---

## 6. 文件清单小结

### 6.1 将删除的规则文件（4 个）

- `rules/polymarket_safe.yaml`
- `rules/polymarket_eoa.yaml`
- `rules/predict_eoa.yaml`
- `rules/opinion.yaml`

### 6.2 保留并需 e2e 覆盖的示例文件（2 个）

- `rules/treasury.example.yaml`
- `rules/security.example.yaml`

### 6.3 E2E 新增/拆分的测试文件（约 16 个，不含现有 security/tls）

- `e2e_test.go`（仅 Main + 常量 + 全局变量）
- `e2e_health_test.go`
- `e2e_auth_test.go`
- `e2e_sign_test.go`
- `e2e_approval_guard_test.go`
- `e2e_rule_crud_test.go`
- `e2e_rule_address_test.go`
- `e2e_rule_solidity_test.go`
- `e2e_rule_value_test.go`
- `e2e_rule_signer_test.go`
- `e2e_rule_sign_type_test.go`
- `e2e_rule_message_pattern_test.go`
- `e2e_rule_contract_method_test.go`
- `e2e_rule_evm_js_test.go`
- `e2e_rule_polymarket_test.go`（可选，也可合并进 evm_js）
- `e2e_request_audit_test.go`
- `e2e_pagination_test.go`
- `e2e_signer_test.go`
- `e2e_template_test.go`
- `e2e_client_test.go`（可选）
- `e2e_helpers.go`（可选）

---

请 review 本方案，确认后再按此实施（先删旧规则文件与拆分 e2e，再补模板与示例的 e2e 覆盖）。
