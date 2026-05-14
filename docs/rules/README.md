# Protocol Rules Documentation

Human-readable documentation for remote-signer rules, organized by protocol. Each protocol has Chinese and English versions.

| Protocol | 中文 | English |
|----------|------|---------|
| **Predict.fun** | [predict.zh.md](predict.zh.md) | [predict.en.md](predict.en.md) |
| **Polymarket** | [polymarket.zh.md](polymarket.zh.md) | [polymarket.en.md](polymarket.en.md) |
| **Uniswap** | [uniswap.zh.md](uniswap.zh.md) | [uniswap.en.md](uniswap.en.md) |
| **USDC** | [usdc.zh.md](usdc.zh.md) | [usdc.en.md](usdc.en.md) |

---

## Preset 与模板映射 / Preset and Template Mapping

| Preset | 模板组合 / Templates | 说明 / Notes |
|--------|---------------------|--------------|
| erc20 | erc20 (transfer-limit + approve-limit) | ERC20 单币种额度与审批限制（evm_js，支持 budget） |
| predict_eoa_bnb | auth + enable_trading + trading | Predict EOA，BNB Chain |
| polymarket_eoa_polygon | auth + enable_trading + trading | Polymarket EOA，Polygon |
| polymarket_safe_init_polygon | auth + create_safe + enable_trading | Safe 初始化（创建钱包 + 开通交易） |
| polymarket_safe_polygon | auth + create_safe + enable_trading + trading | Safe 全量 |
| uniswap_v2 | dex_swap (V2 method whitelist) | Uniswap V2 Router，多链 matrix |
| uniswap_v3 | dex_swap_v3 (V3/V4 method whitelist + tuple validation) | Uniswap V3 SwapRouter，多链 matrix |
| uniswap_v4 | dex_swap_v3 (V3/V4 method whitelist + tuple validation) | Uniswap V4 Universal Router，多链 matrix |
| usdc | erc20 (transfer-limit + approve-limit) | USDC 多链 matrix，含 budget 计量 |

---

For template/preset concepts and configuration, see [rules-templates-and-presets.md](../rules-templates-and-presets.md).
