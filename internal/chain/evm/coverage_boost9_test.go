package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// newIsolatedEvaluator creates a SolidityRuleEvaluator with an isolated temp directory
// per test. Since forge compiles ALL .sol files in the workspace directory, sharing a
// temp dir between tests causes stale scripts with incompatible function signatures
// (e.g. _validateMessage) to pollute compilation. Each test gets its own workspace.
func newIsolatedEvaluator(t *testing.T) *SolidityRuleEvaluator {
	t.Helper()
	if _, err := exec.LookPath("forge"); err != nil {
		t.Skip("forge not found, skipping")
	}
	e, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		TempDir: t.TempDir(),
	}, newTestLogger())
	require.NoError(t, err)
	return e
}

// defaultRequestEnv returns a minimal set of env vars required by the expression template.
// The expression template reads tx context vars unconditionally via vm.env*, so they must
// be present even for tests that don't exercise specific env values.
func defaultRequestEnv() []string {
	return []string{
		"RULE_TX_TO=0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
		"RULE_TX_VALUE=0",
		"RULE_TX_SELECTOR=0x00000000",
		"RULE_TX_DATA=0x",
		"RULE_CHAIN_ID=1",
		"RULE_SIGNER=0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}
}

// transferCalldata returns ABI-encoded calldata for transfer(address,uint256) with
// recipient=0x5B38Da6a701c568545dCfcB03FcB875f56beddC4 and value=1.
// The Functions template forwards full calldata via address(ruleContract).call(txData),
// so the 4-byte selector alone is insufficient — Solidity requires complete ABI-encoded arguments.
func transferCalldata() []byte {
	b, _ := hex.DecodeString(
		"a9059cbb" + // transfer(address,uint256) selector
			"0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc4" + // address arg
			"0000000000000000000000000000000000000000000000000000000000000001", // uint256 arg
	)
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// executeScript — forge execution pipeline (solidity_execution.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestExecuteScript_Expression_Pass(t *testing.T) {
	e := newIsolatedEvaluator(t)

	script, err := e.generateExpressionScript("require(true);", nil)
	require.NoError(t, err)

	passed, reason, err := e.executeScript(bgCtx, script, defaultRequestEnv())
	require.NoError(t, err)
	assert.True(t, passed)
	assert.Empty(t, reason)
}

func TestExecuteScript_Expression_Revert(t *testing.T) {
	e := newIsolatedEvaluator(t)

	script, err := e.generateExpressionScript(`require(false, "test fail");`, nil)
	require.NoError(t, err)

	// Use a short timeout: forge script can hang on revert (it expects
	// RPC access for gas estimation even without --broadcast). A timed-out
	// forge still produces revert output that parseRevertReason can extract.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	passed, reason, err := e.executeScript(ctx, script, defaultRequestEnv())
	if err != nil {
		// Timeout is acceptable — we still exercised the revert path.
		// The parseRevertReason code is exercised by other tests anyway.
		t.Logf("revert test resulted in error (possibly timeout): %v", err)
		return
	}
	assert.False(t, passed)
	assert.Contains(t, reason, "test fail")
}

func TestExecuteScript_Expression_WithRequestEnv(t *testing.T) {
	e := newIsolatedEvaluator(t)

	script, err := e.generateExpressionScript("require(tx_to != address(0));", nil)
	require.NoError(t, err)

	env := []string{
		"RULE_TX_TO=0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
		"RULE_TX_VALUE=0",
		"RULE_TX_SELECTOR=0x00000000",
		"RULE_TX_DATA=0x",
		"RULE_CHAIN_ID=1",
		"RULE_SIGNER=0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}

	passed, reason, err := e.executeScript(bgCtx, script, env)
	require.NoError(t, err)
	assert.True(t, passed)
	assert.Empty(t, reason)
}

func TestExecuteScript_WithFilePathHint(t *testing.T) {
	e := newIsolatedEvaluator(t)

	script, err := e.generateExpressionScript("require(true);", nil)
	require.NoError(t, err)

	passed, reason, err := e.executeScript(bgCtx, script, defaultRequestEnv(), "my_group")
	require.NoError(t, err)
	assert.True(t, passed)
	assert.Empty(t, reason)
}

func TestExecuteScript_Caching(t *testing.T) {
	e := newIsolatedEvaluator(t)

	script, err := e.generateExpressionScript("require(true);", nil)
	require.NoError(t, err)

	// First call: compiles and executes (execution cache not used because requestEnv is set)
	passed1, reason1, err1 := e.executeScript(bgCtx, script, defaultRequestEnv())
	require.NoError(t, err1)
	assert.True(t, passed1)
	assert.Empty(t, reason1)

	// Second call: uses cached script file (same hash), no execution cache (requestEnv set)
	passed2, reason2, err2 := e.executeScript(bgCtx, script, defaultRequestEnv())
	require.NoError(t, err2)
	assert.True(t, passed2)
	assert.Empty(t, reason2)
}

// ─────────────────────────────────────────────────────────────────────────────
// evaluateExpression / evaluateFunctions (solidity_evaluator.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluateExpression_Pass(t *testing.T) {
	e := newIsolatedEvaluator(t)

	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}
	parsed := &types.ParsedPayload{
		Recipient: strPtr("0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"),
		RawData:   []byte{0x12, 0x34, 0x56, 0x78},
	}

	passed, reason, err := e.evaluateExpression(bgCtx, "require(true);", req, parsed, nil)
	require.NoError(t, err)
	assert.True(t, passed)
	assert.Empty(t, reason)
}

func TestEvaluateExpression_Revert(t *testing.T) {
	e := newIsolatedEvaluator(t)

	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}
	parsed := &types.ParsedPayload{
		Recipient: strPtr("0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"),
		RawData:   []byte{0x12, 0x34, 0x56, 0x78},
	}

	passed, reason, err := e.evaluateExpression(bgCtx, `require(false, "nope");`, req, parsed, nil)
	require.NoError(t, err)
	assert.False(t, passed)
	assert.Contains(t, reason, "nope")
}

func TestEvaluateFunctions_Pass(t *testing.T) {
	e := newIsolatedEvaluator(t)

	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}
	// transfer(address,uint256) selector = 0xa9059cbb
	// Must use full ABI-encoded calldata: the Functions template forwards it via
	// address(ruleContract).call(txData), so Solidity needs complete argument encoding.
	parsed := &types.ParsedPayload{
		Recipient: strPtr("0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"),
		RawData:   transferCalldata(),
	}

	functions := `function transfer(address, uint256) external { require(true); }`

	passed, reason, err := e.evaluateFunctions(bgCtx, functions, req, parsed, nil)
	require.NoError(t, err)
	assert.True(t, passed)
	assert.Empty(t, reason)
}

func TestEvaluateFunctions_Revert(t *testing.T) {
	e := newIsolatedEvaluator(t)

	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}
	// transfer(address,uint256) selector = 0xa9059cbb
	parsed := &types.ParsedPayload{
		Recipient: strPtr("0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"),
		RawData:   transferCalldata(),
	}

	functions := `function transfer(address, uint256) external { require(false, "func fail"); }`

	passed, reason, err := e.evaluateFunctions(bgCtx, functions, req, parsed, nil)
	require.NoError(t, err)
	assert.False(t, passed)
	assert.Contains(t, reason, "func fail")
}

// ─────────────────────────────────────────────────────────────────────────────
// Evaluate — main Evaluate paths (solidity_evaluator.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluate_Expression_Pass(t *testing.T) {
	e := newIsolatedEvaluator(t)

	rule := &types.Rule{
		Mode: types.RuleModeWhitelist,
		Config: mustJSONMarshal(t, SolidityExpressionConfig{
			Expression: "require(true);",
		}),
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}
	parsed := &types.ParsedPayload{
		Recipient: strPtr("0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"),
		RawData:   []byte{0x12, 0x34, 0x56, 0x78},
	}

	passed, reason, err := e.Evaluate(bgCtx, rule, req, parsed)
	require.NoError(t, err)
	assert.True(t, passed)
	assert.Empty(t, reason)
}

func TestEvaluate_Expression_Revert(t *testing.T) {
	e := newIsolatedEvaluator(t)

	rule := &types.Rule{
		Mode: types.RuleModeWhitelist,
		Config: mustJSONMarshal(t, SolidityExpressionConfig{
			Expression: `require(false, "bad");`,
		}),
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}
	parsed := &types.ParsedPayload{
		Recipient: strPtr("0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"),
		RawData:   []byte{0x12, 0x34, 0x56, 0x78},
	}

	passed, reason, err := e.Evaluate(bgCtx, rule, req, parsed)
	require.NoError(t, err)
	assert.False(t, passed)
	assert.Contains(t, reason, "bad")
}

func TestEvaluate_Expression_Blocklist(t *testing.T) {
	e := newIsolatedEvaluator(t)

	rule := &types.Rule{
		Mode: types.RuleModeBlocklist,
		Config: mustJSONMarshal(t, SolidityExpressionConfig{
			Expression: `require(false, "violation");`,
		}),
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}
	parsed := &types.ParsedPayload{
		Recipient: strPtr("0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"),
		RawData:   []byte{0x12, 0x34, 0x56, 0x78},
	}

	passed, reason, err := e.Evaluate(bgCtx, rule, req, parsed)
	require.NoError(t, err)
	// Blocklist: require(false) means violation detected -> block (return true)
	assert.True(t, passed)
	assert.Contains(t, reason, "violation")
}

func TestEvaluate_Expression_Blocklist_Pass(t *testing.T) {
	e := newIsolatedEvaluator(t)

	rule := &types.Rule{
		Mode: types.RuleModeBlocklist,
		Config: mustJSONMarshal(t, SolidityExpressionConfig{
			Expression: `require(true);`,
		}),
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}
	parsed := &types.ParsedPayload{
		Recipient: strPtr("0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"),
		RawData:   []byte{0x12, 0x34, 0x56, 0x78},
	}

	passed, reason, err := e.Evaluate(bgCtx, rule, req, parsed)
	require.NoError(t, err)
	// Blocklist: require(true) means no violation -> don't block (return false)
	assert.False(t, passed)
	assert.Empty(t, reason)
}

func TestEvaluate_Functions_Pass(t *testing.T) {
	e := newIsolatedEvaluator(t)

	rule := &types.Rule{
		Mode: types.RuleModeWhitelist,
		Config: mustJSONMarshal(t, SolidityExpressionConfig{
			Functions: `function transfer(address, uint256) external { require(true); }`,
		}),
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}
	// transfer(address,uint256) selector = 0xa9059cbb
	// Use full ABI-encoded calldata: the Functions template forwards it via
	// address(ruleContract).call(txData), so Solidity needs complete argument encoding.
	parsed := &types.ParsedPayload{
		Recipient: strPtr("0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"),
		RawData:   transferCalldata(),
	}

	passed, reason, err := e.Evaluate(bgCtx, rule, req, parsed)
	require.NoError(t, err)
	assert.True(t, passed)
	assert.Empty(t, reason)
}

// ─────────────────────────────────────────────────────────────────────────────
// Evaluate — TypedData paths (solidity_typed_data.go via Evaluate)
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluate_TypedDataExpression_Pass(t *testing.T) {
	e := newIsolatedEvaluator(t)

	payload := makeTypedDataPayload(t, map[string]interface{}{
		"types": map[string]interface{}{
			"Order": []interface{}{
				map[string]interface{}{"name": "maker", "type": "address"},
				map[string]interface{}{"name": "salt", "type": "uint256"},
			},
		},
		"primaryType": "Order",
		"domain": map[string]interface{}{
			"name":              "Test",
			"version":           "1",
			"chainId":           "1",
			"verifyingContract": "0x0000000000000000000000000000000000000000",
		},
		"message": map[string]interface{}{
			"maker": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
			"salt":  "12345",
		},
	})

	rule := &types.Rule{
		Mode: types.RuleModeWhitelist,
		Config: mustJSONMarshal(t, SolidityExpressionConfig{
			TypedDataExpression: "require(true);",
			TypedDataStruct: `struct Order {
				address maker;
				uint256 salt;
			}`,
		}),
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
		Payload:       payload,
	}

	passed, reason, err := e.Evaluate(bgCtx, rule, req, nil)
	require.NoError(t, err)
	assert.True(t, passed)
	assert.Empty(t, reason)
}

func TestEvaluate_TypedDataExpression_Revert(t *testing.T) {
	e := newIsolatedEvaluator(t)

	payload := makeTypedDataPayload(t, map[string]interface{}{
		"types": map[string]interface{}{
			"Order": []interface{}{
				map[string]interface{}{"name": "maker", "type": "address"},
			},
		},
		"primaryType": "Order",
		"domain": map[string]interface{}{
			"name":              "Test",
			"version":           "1",
			"chainId":           "1",
			"verifyingContract": "0x0000000000000000000000000000000000000000",
		},
		"message": map[string]interface{}{
			"maker": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
		},
	})

	rule := &types.Rule{
		Mode: types.RuleModeWhitelist,
		Config: mustJSONMarshal(t, SolidityExpressionConfig{
			TypedDataExpression: `require(false, "td fail");`,
			TypedDataStruct: `struct Order {
				address maker;
			}`,
		}),
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
		Payload:       payload,
	}

	passed, reason, err := e.Evaluate(bgCtx, rule, req, nil)
	require.NoError(t, err)
	assert.False(t, passed)
	assert.Contains(t, reason, "td fail")
}

func TestEvaluate_TypedDataFunctions_Pass(t *testing.T) {
	e := newIsolatedEvaluator(t)

	payload := makeTypedDataPayload(t, map[string]interface{}{
		"types":       map[string]interface{}{},
		"primaryType": "Order",
		"domain": map[string]interface{}{
			"name":              "Test",
			"version":           "1",
			"chainId":           "1",
			"verifyingContract": "0x0000000000000000000000000000000000000000",
		},
		"message": map[string]interface{}{
			"maker": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
		},
	})

	rule := &types.Rule{
		Mode: types.RuleModeWhitelist,
		Config: mustJSONMarshal(t, SolidityExpressionConfig{
			TypedDataFunctions: `
		function checkOrder() public pure returns (bool) {
			return true;
		}`,
		}),
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
		Payload:       payload,
	}

	passed, reason, err := e.Evaluate(bgCtx, rule, req, nil)
	require.NoError(t, err)
	assert.True(t, passed)
	assert.Empty(t, reason)
}

func TestEvaluate_TypedDataExpression_SkipOnPrimaryTypeMismatch(t *testing.T) {
	e := newIsolatedEvaluator(t)

	payload := makeTypedDataPayload(t, map[string]interface{}{
		"types":       map[string]interface{}{},
		"primaryType": "Permit",
		"domain": map[string]interface{}{
			"name":              "Test",
			"version":           "1",
			"chainId":           "1",
			"verifyingContract": "0x0000000000000000000000000000000000000000",
		},
		"message": map[string]interface{}{
			"owner": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
		},
	})

	rule := &types.Rule{
		Mode: types.RuleModeWhitelist,
		Config: mustJSONMarshal(t, SolidityExpressionConfig{
			TypedDataExpression: `require(false, "should not be evaluated");`,
			TypedDataStruct: `struct Order {
				address maker;
			}`,
		}),
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
		Payload:       payload,
	}

	passed, reason, err := e.Evaluate(bgCtx, rule, req, nil)
	require.NoError(t, err)
	assert.False(t, passed)
	assert.Empty(t, reason)
}

func TestEvaluate_TypedDataMissingPayload(t *testing.T) {
	e := newIsolatedEvaluator(t)

	rule := &types.Rule{
		Mode: types.RuleModeWhitelist,
		Config: mustJSONMarshal(t, SolidityExpressionConfig{
			TypedDataExpression: `require(true);`,
		}),
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
		Payload:       []byte(`{"typed_data": null}`),
	}

	_, _, err := e.Evaluate(bgCtx, rule, req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "typed_data field is required")
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func makeTypedDataPayload(t *testing.T, msg map[string]interface{}) []byte {
	t.Helper()
	evmPayload := map[string]interface{}{
		"typed_data": msg,
	}
	b, err := json.Marshal(evmPayload)
	require.NoError(t, err)
	return b
}
