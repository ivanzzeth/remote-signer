# Rule evaluation performance

Benchmarks for JS and Solidity rule evaluation live in `internal/chain/evm/`:

- **JS** (`js_evaluator_bench_test.go`): `BenchmarkJSRuleEvaluator_Evaluate`, `BenchmarkJSRuleEvaluator_wrappedValidate`
- **Solidity** (`solidity_evaluator_bench_test.go`): `BenchmarkSolidityRuleEvaluator_Evaluate`

## Targets (per request)

| Rule type | Expected latency | Notes |
|-----------|------------------|--------|
| **evm_js** | **&lt;10ms** | In-process Sobek VM; typical ~0.02–0.1ms |
| **evm_solidity_expression** | **100ms–2s** | Forge script subprocess; typical ~50–150ms |

## How to run

```bash
# JS (no deps)
go test -run=^$ -bench=BenchmarkJSRuleEvaluator -benchmem ./internal/chain/evm/...

# Solidity (requires forge in PATH; use -run=^$ to avoid shared temp dir)
go test -run=^$ -bench=BenchmarkSolidityRuleEvaluator -benchmem -benchtime=3s ./internal/chain/evm/...
```

Solidity benchmark is skipped if `forge` is not available.
