# Protocol Rules Documentation

Human-readable documentation for remote-signer rules, organized by protocol. Each protocol has Chinese and English versions.

| Protocol | 中文 | English |
|----------|------|---------|
| **Predict.fun** | [predict.zh.md](predict.zh.md) | [predict.en.md](predict.en.md) |
| **Polymarket** | [polymarket.zh.md](polymarket.zh.md) | [polymarket.en.md](polymarket.en.md) |

---

## Preset 与模板映射 / Preset and Template Mapping

| Preset | 模板组合 / Templates | 说明 / Notes |
|--------|---------------------|--------------|
| predict_eoa_bnb | auth + enable_trading + trading | Predict EOA，BNB Chain |
| polymarket_eoa_polygon | auth + enable_trading + trading | Polymarket EOA，Polygon |
| polymarket_safe_init_polygon | auth + create_safe + enable_trading | Safe 初始化（创建钱包 + 开通交易） |
| polymarket_safe_polygon | auth + create_safe + enable_trading + trading | Safe 全量 |

---

For template/preset concepts and configuration, see [RULES_TEMPLATES_AND_PRESETS.md](../RULES_TEMPLATES_AND_PRESETS.md).
