// Benchmarks for evm_js rule evaluation.
//
// Target: <10ms per request (in-process Sobek VM). Typical: ~0.02–0.1ms per Evaluate.
// Run: go test -run=^$ -bench=BenchmarkJSRuleEvaluator -benchmem ./internal/chain/evm/...

package evm

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// BenchmarkJSRuleEvaluator_Evaluate measures full Evaluate (BuildRuleInput + script run) per request.
// Expected: well under 10ms per request (in-process Sobek VM).
func BenchmarkJSRuleEvaluator_Evaluate(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	e, err := NewJSRuleEvaluator(logger)
	if err != nil {
		b.Fatal(err)
	}

	script := `function validate(i){ return { valid: true }; }`
	config, _ := json.Marshal(map[string]string{"script": script})
	rule := &types.Rule{
		ID:     "bench-js",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: config,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"1000000000000000000","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	parsed := &types.ParsedPayload{
		Recipient: strPtrForRuleInput("0x742d35cc6634c0532925a3b844bc454e4438f44e"),
		Value:     strPtrForRuleInput("1000000000000000000"),
	}

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := e.Evaluate(ctx, rule, req, parsed)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkJSRuleEvaluator_wrappedValidate measures script execution only (no BuildRuleInput).
// Use to isolate VM cost; full Evaluate adds RuleInput building and config unmarshaling.
func BenchmarkJSRuleEvaluator_wrappedValidate(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	e, err := NewJSRuleEvaluator(logger)
	if err != nil {
		b.Fatal(err)
	}

	script := `function validate(i){ return { valid: true }; }`
	input := &RuleInput{
		SignType: "transaction",
		ChainID:  1,
		Signer:   "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.wrappedValidate(script, input, nil, nil)
	}
}
