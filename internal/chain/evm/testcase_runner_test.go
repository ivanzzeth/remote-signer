package evm

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestRunJSTestCases_VarsContextSubstitutesPerTestChain(t *testing.T) {
	eval, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	script := `function validate(input) {
		require(parseInt(String(input.chain_id),10) === parseInt(String(config.chain_id),10), 'chain mismatch');
		return ok();
	}`
	vars := map[string]string{"chain_id": "56", "domain_name": "Aori"}
	cases := []JSTestCase{{
		Name:       "pass on chain 56",
		ExpectPass: true,
		Input: map[string]interface{}{
			"sign_type": "typed_data",
			"chain_id":  56,
			"signer":    "0x0000000000000000000000000000000000000001",
			"typed_data": map[string]interface{}{
				"primaryType": "Order",
				"domain":      map[string]interface{}{"name": "Aori", "version": "0.3.1", "verifyingContract": "0xffe691a6ddb5d2645321e0a920c2e7bdd00dd3d8"},
				"message":     map[string]interface{}{"offerer": "0x0000000000000000000000000000000000000001"},
			},
		},
	}}

	results, ok := eval.RunJSTestCases(script, cases, VarsEvalContext(vars))
	require.Len(t, results, 1)
	assert.True(t, ok)
	assert.True(t, results[0].Passed)
}

func TestRunJSTestCases_MatrixContextUsesBSCRow(t *testing.T) {
	eval, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	script := `function validate(input) {
		var ctx = rs.typedData.require(input, 'Order');
		rs.addr.requireInListIfNonEmpty(String(ctx.message.inputToken||'').trim(), config.allowed_input_tokens, 'inputToken not allowed');
		return ok();
	}`
	rule := &types.Rule{
		Variables: []byte(`{"domain_name":"Aori"}`),
		Matrix: []byte(`[
			{"chain_id":"56","allowed_input_tokens":"0x55d398326f99059ff775485246999027b3197955"}
		]`),
	}
	cases := []JSTestCase{{
		Name:       "BSC USDT allowed",
		ExpectPass: true,
		Input: map[string]interface{}{
			"sign_type": "typed_data",
			"chain_id":  56,
			"signer":    "0x0000000000000000000000000000000000000001",
			"typed_data": map[string]interface{}{
				"primaryType": "Order",
				"domain":      map[string]interface{}{"name": "Aori", "version": "0.3.1", "verifyingContract": "0xffe691a6ddb5d2645321e0a920c2e7bdd00dd3d8"},
				"message":     map[string]interface{}{"inputToken": "0x55d398326f99059fF775485246999027B3197955"},
			},
		},
	}}

	results, ok := eval.RunJSTestCases(script, cases, MatrixRuleEvalContext(rule))
	require.Len(t, results, 1)
	assert.True(t, ok, "reason=%q", results[0].Reason)
}
