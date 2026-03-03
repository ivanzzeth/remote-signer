// Benchmarks for evm_solidity_expression rule evaluation.
//
// Target: 100ms–2s per request (forge script subprocess). Typical: ~50–150ms per Evaluate.
// Requires forge in PATH; skipped if not found. Use -run=^$ to avoid shared temp dir with other tests.
// Run: go test -run=^$ -bench=BenchmarkSolidityRuleEvaluator -benchmem -benchtime=3s ./internal/chain/evm/...

package evm

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// benchmarkSolidityEvaluator creates evaluator or skips the benchmark if forge is not available.
func benchmarkSolidityEvaluator(b *testing.B) *SolidityRuleEvaluator {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	evaluator, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		Timeout: 60 * time.Second,
	}, logger)
	if err != nil {
		b.Skipf("solidity benchmark skipped (forge not available): %v", err)
		return nil
	}
	return evaluator
}

// BenchmarkSolidityRuleEvaluator_Evaluate measures full Evaluate (expression mode, one require).
// Expected: 100ms–2s per request (runs forge run in subprocess).
func BenchmarkSolidityRuleEvaluator_Evaluate(b *testing.B) {
	evaluator := benchmarkSolidityEvaluator(b)
	if evaluator == nil {
		return
	}

	config := SolidityExpressionConfig{
		Expression:  `require(value <= 1000000000000000000, "exceeds limit");`,
		Description: "Max 1 ETH",
		TestCases: []SolidityTestCase{
			{Name: "pass", Input: SolidityTestInput{Value: "500000000000000000"}, ExpectPass: true},
		},
	}
	configBytes, err := json.Marshal(config)
	require.NoError(b, err)

	rule := &types.Rule{
		ID:     "bench-sol",
		Type:   types.RuleTypeEVMSolidityExpression,
		Config: configBytes,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}
	value := "500000000000000000"
	parsed := &types.ParsedPayload{Value: &value}

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := evaluator.Evaluate(ctx, rule, req, parsed)
		if err != nil {
			b.Fatal(err)
		}
	}
}
