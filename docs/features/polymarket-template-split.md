# Polymarket Template Split: auth / create_safe / enable_trading / trading

## 1. 目标与原则

- **模板**：按能力拆成四块，每块 Safe 无关（不关心“有没有 Safe”）。
- **实例化**：只有在对 enable_trading / trading **做 Safe 委托**时，才在实例里填 `allowed_safe_addresses` 等变量。
- **流程**：Safe 分步时用预设 **polymarket_safe_init_polygon**（auth + create_safe + enable_trading）→ 起服务 → createProxy → 拿到 Safe 地址 → 实例化时对 enable_trading 填 Safe 地址；需要交易时再加 trading 或改用 **polymarket_safe_polygon** 全量。

## 2. 四个模板的职责与规则归属

| 模板 | 职责 | 规则归属（来自现有 polymarket_safe.template.yaml） | 是否需要 Safe 变量 |
|------|------|----------------------------------------------------|--------------------|
| **auth** | CLOB 登录鉴权 | Polymarket CLOB Auth Signature | 否（仅 chain_id + domain） |
| **create_safe** | 创建 Safe / createProxy | Polymarket Safe Wallet Creation Signature + Polymarket Safe Wallet Creation | 否 |
| **enable_trading** | 为某个 Safe 开通交易（approve / setApprovalForAll） | SafeTx + execTransaction 中**仅** approve(USDC→协议)、setApprovalForAll(CTF→协议) 部分 | 模板层不需要；**实例化时**绑定 Safe |
| **trading** | 某个 Safe 的日常交易（Order + split/merge/redeem） | Polymarket Order Signature + SafeTx + execTransaction 完整逻辑 | 同上 |

说明：enable_trading 与 trading 的“需要 Safe”只体现在**实例**上（preset 的 override_hints 里填 `allowed_safe_addresses`），不是模板本身依赖 Safe。

## 3. 文件与变量规划

### 3.1 模板文件（新建，从现有大模板拆出）

**命名遵循统一规范**：`xxx_yyy.template.yaml`（见 `docs/RULES_TEMPLATES_AND_PRESETS.md`）。

| 文件 | 内容概要 | 变量（variables + test_variables） |
|------|----------|-----------------------------------|
| `rules/templates/polymarket_auth.template.yaml` | 仅 ClobAuth 一条规则 | chain_id, clob_auth_domain_name, clob_auth_domain_version |
| `rules/templates/polymarket_create_safe.template.yaml` | CreateProxy 签名规则 + “Polymarket Safe Wallet Creation” 直连交易规则 | chain_id, safe_proxy_factory_address, safe_factory_domain_name, usdc_bridged_address（仅 test 用） |
| `rules/templates/polymarket_enable_trading.template.yaml` | SafeTx Signature + Safe Execute Transaction，但表达式**只允许**：USDC.e 的 approve(协议合约)、CTF 的 setApprovalForAll(协议合约)；禁止 split/merge/redeem 等 | chain_id, ctf_exchange_address, neg_risk_adapter_address, neg_risk_exchange_address, conditional_tokens_address, usdc_bridged_address, **allowed_safe_addresses**, **allowed_safe_address_for_testing**, safe_factory_domain_name（若 SafeTx 需要 domain）等；实例化时必填 Safe 相关 |
| `rules/templates/polymarket_trading.template.yaml` | Polymarket Order Signature + SafeTx Signature + Safe Execute Transaction（完整：approve + setApprovalForAll + split/merge/redeem） | 与当前大模板中 trading 相关变量一致（含 allowed_safe_addresses, allowed_safe_address_for_testing, ctf_exchange_domain_* 等）；实例化时必填 Safe 相关 |

### 3.2 预设文件（组合式：一个预设 = 多个模板）

预设是**组合**，每个预设引用多块模板，不是“一个预设对应一个模板”。

| 预设文件 | 组合的模板 | 说明 |
|----------|------------|------|
| `polymarket_eoa_polygon.preset.yaml` | **auth** + **enable_trading** + **trading** | EOA 用：鉴权 + 开通交易 + 交易；无 create_safe |
| `polymarket_safe_init_polygon.preset.yaml` | **auth** + **create_safe** + **enable_trading** | Safe 初始化：鉴权 + 创建 Safe + 开通交易；不含 trading（可后续单独加） |
| `polymarket_safe_polygon.preset.yaml` | **auth** + **create_safe** + **enable_trading** + **trading** | Safe 全量：鉴权 + 创建 Safe + 开通交易 + 交易 |

- **polymarket_eoa_polygon**：EOA 用户，不创建 Safe，只需 auth + enable_trading + trading；实例化时对 enable_trading/trading 绑定 EOA 或对应地址。
- **polymarket_safe_init_polygon**：先起服务 → createProxy（create_safe）→ 拿到 Safe 地址 → 实例化时对 enable_trading 绑定该 Safe；不含 trading，需要时再加 trading 实例。
- **polymarket_safe_polygon**：一键全量，实例化时填一次 Safe 地址，同时绑定 create_safe（无需 Safe）/ enable_trading / trading。

预设格式需支持**多模板**：例如 `templates: [auth, enable_trading, trading]` 与对应的 `template_paths` 列表，或等价结构；CLI/setup 按列表注入多块模板并生成多条规则（或合并为一条 instance 引用多模板，依当前 config 能力而定）。各预设的 `override_hints` 仍可统一列出该预设下需要用户填的变量（如 allowed_safe_addresses、allowed_safe_address_for_testing）。

## 4. 具体改动清单（如何改）

### 4.1 从现有大模板拆规则与变量

- **auth**  
  - 从 `polymarket_safe.template.yaml` 中只保留 “Polymarket CLOB Auth Signature” 及对应 variables/test_variables（chain_id, clob_auth_domain_*）。  
  - test_cases 里用到的地址可保留为占位或固定 test 地址，不引入 allowed_safe_addresses。

- **create_safe**  
  - 保留 “Polymarket Safe Wallet Creation Signature” + “Polymarket Safe Wallet Creation” 两条规则及依赖变量（chain_id, safe_proxy_factory_address, safe_factory_domain_name, usdc_bridged_address 等）。  
  - 不包含 allowed_safe_addresses / allowed_safe_address_for_testing。

- **enable_trading**  
  - 复制当前 “Polymarket SafeTx Signature” 与 “Polymarket Safe Execute Transaction” 的**结构**，重写表达式：  
    - 只允许：`approve(address,uint256)` 目标为 USDC.e、spender 为协议三合约之一；`setApprovalForAll(address,bool)` 目标为 CTF、operator 为协议三合约之一且 approved=true。  
    - 其余 selector（split/merge/redeem 等）一律 `revert` 或 `require(false, "...")`。  
  - 变量与当前 SafeTx 一致（含 allowed_safe_addresses、allowed_safe_address_for_testing），便于实例化时绑定 Safe。  
  - *实现说明*：当前 `polymarket_enable_trading.template.yaml` 与 full SafeTx/execTransaction 逻辑一致；上述「仅 approve/setApprovalForAll」限制可后续在模板内收紧。

- **trading**  
  - 包含 “Polymarket Order Signature” + 当前完整的 “Polymarket SafeTx Signature” + “Polymarket Safe Execute Transaction”（与现有大模板一致）。  
  - 变量保持现有全部 trading 相关变量。

### 4.2 预设 YAML 写法（支持多模板）

- 预设需支持**多模板**：如 `templates: [auth, enable_trading, trading]` 与 `template_paths: [polymarket_auth.template.yaml, polymarket_enable_trading.template.yaml, polymarket_trading.template.yaml]`（或单数组 `template_entries: [{ name, path }]`），具体字段名依实现而定。
- 三个预设的变量与 override_hints：  
  - **polymarket_eoa_polygon**：需填 enable_trading/trading 相关地址（如 allowed_safe_addresses 或 EOA 对应字段），`override_hints` 列出这些变量。  
  - **polymarket_safe_init_polygon**：create_safe 无 Safe；enable_trading 实例化时需 Safe 地址，`override_hints` 含 allowed_safe_addresses、allowed_safe_address_for_testing。  
  - **polymarket_safe_polygon**：同上，enable_trading + trading 均需 Safe 地址，`override_hints` 含 allowed_safe_addresses、allowed_safe_address_for_testing。
- CLI/setup：根据预设的模板列表依次注入模板、生成规则（或一条 instance 引用多模板），并统一提示 override_hints 中的变量。

### 4.3 文档与流程说明

- README 或 Polymarket 小节中写明：  
  - **EOA**：选预设 **polymarket_eoa_polygon**（auth + enable_trading + trading），按提示填变量。  
  - **Safe 分步**：选 **polymarket_safe_init_polygon**（auth + create_safe + enable_trading）→ 起服务 → createProxy → 拿到 Safe 地址 → 实例化时填 allowed_safe_addresses；需要交易时再单独加 trading 或改用全量预设。  
  - **Safe 一键**：选 **polymarket_safe_polygon**（auth + create_safe + enable_trading + trading），实例化时填一次 Safe 地址。

## 5. 小结

- **模板**：auth / create_safe 完全不涉及 Safe；enable_trading / trading 模板本身也不“关心有没有 Safe”，只是规则里会用到 `allowed_safe_addresses` 等占位，在**实例化**时由用户绑定具体 Safe。  
- **预设（组合）**：三个预设分别为  
  - **polymarket_eoa_polygon**：auth + enable_trading + trading；  
  - **polymarket_safe_init_polygon**：auth + create_safe + enable_trading；  
  - **polymarket_safe_polygon**：auth + create_safe + enable_trading + trading。  
  预设格式需支持多模板（templates + template_paths 或等价），CLI/setup 按列表注入并统一处理 override_hints。  
- **实现**：按 4.1 拆模板文件；预设改为上述三个组合，并扩展 preset 结构以支持多模板引用。
