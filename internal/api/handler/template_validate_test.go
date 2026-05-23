package handler

import (
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ---------------------------------------------------------------------------
// runJSTestCase
// ---------------------------------------------------------------------------

func newTestJSEvaluator(t *testing.T) *evm.JSRuleEvaluator {
	t.Helper()
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	return eval
}

func alwaysAllowScript() string {
	return `function validate(input) { return {valid: true}; }`
}

func TestRunJSTestCase_SimplePass(t *testing.T) {
	eval := newTestJSEvaluator(t)
	script := alwaysAllowScript()
	cfgMap := map[string]interface{}{"foo": "bar"}
	tc := evmhandlerJSRuleTestCase{
		Name: "test-pass",
		Input: map[string]interface{}{
			"sign_type": "transaction",
			"chain_id":  "1",
			"signer":    "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			"transaction": map[string]interface{}{
				"to":    "0xRecipientAddress0000000000000000000000000000",
				"value": "1000000000000000000",
				"data":  "0x",
			},
		},
		ExpectPass: true,
	}
	result := runJSTestCase(eval, script, cfgMap, tc, types.RuleModeWhitelist)
	assert.True(t, result.Passed, "expected pass but got reason: %s", result.Reason)
	assert.Equal(t, "test-pass", result.Name)
}

func TestRunJSTestCase_ExpectFailButPasses(t *testing.T) {
	eval := newTestJSEvaluator(t)
	script := alwaysAllowScript()
	cfgMap := map[string]interface{}{"foo": "bar"}
	tc := evmhandlerJSRuleTestCase{
		Name: "expect-fail",
		Input: map[string]interface{}{
			"sign_type": "transaction",
			"chain_id":  "1",
			"signer":    "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			"transaction": map[string]interface{}{
				"to":    "0xRecipientAddress0000000000000000000000000000",
				"value": "0",
				"data":  "0x",
			},
		},
		ExpectPass: false,
	}
	result := runJSTestCase(eval, script, cfgMap, tc, types.RuleModeWhitelist)
	assert.False(t, result.Passed, "should report failure: expected fail but passed")
	assert.Contains(t, result.Reason, "expected fail but passed")
}

func TestRunJSTestCase_InvalidInput(t *testing.T) {
	eval := newTestJSEvaluator(t)
	script := alwaysAllowScript()
	cfgMap := map[string]interface{}{}
	tc := evmhandlerJSRuleTestCase{
		Name: "bad-input",
		Input: map[string]interface{}{
			"sign_type": "transaction",
			// No chain_id, no transaction -> BuildRuleInput fails
		},
		ExpectPass: true,
	}
	result := runJSTestCase(eval, script, cfgMap, tc, types.RuleModeWhitelist)
	assert.False(t, result.Passed)
	assert.Contains(t, result.Reason, "build input")
}

func TestRunJSTestCase_NilInput(t *testing.T) {
	eval := newTestJSEvaluator(t)
	script := alwaysAllowScript()
	cfgMap := map[string]interface{}{}
	tc := evmhandlerJSRuleTestCase{
		Name: "nil-input",
		// Input is nil (zero value)
		ExpectPass: true,
	}
	result := runJSTestCase(eval, script, cfgMap, tc, types.RuleModeWhitelist)
	assert.False(t, result.Passed)
	assert.Contains(t, result.Reason, "invalid input")
}

// ---------------------------------------------------------------------------
// ValidateTemplateConfig
// ---------------------------------------------------------------------------

func TestValidateTemplateConfig_NonJS(t *testing.T) {
	eval := newTestJSEvaluator(t)
	config := []byte(`{"rules":[{"name":"test-rule","type":"sign_type_restriction","mode":"whitelist","config":{}}]}`)
	results, allPassed := ValidateTemplateConfig(eval, "test-template", config, nil)
	assert.True(t, allPassed)
	require.Len(t, results, 1)
	assert.True(t, results[0].Valid)
}

func TestValidateTemplateConfig_EmptyRules(t *testing.T) {
	eval := newTestJSEvaluator(t)
	config := []byte(`{}`)
	results, allPassed := ValidateTemplateConfig(eval, "test-template", config, nil)
	assert.True(t, allPassed)
	require.Len(t, results, 1)
	assert.Equal(t, "no rules array in config (skipped)", results[0].Error)
}

func TestValidateTemplateConfig_JSWithScriptAndTestCases(t *testing.T) {
	eval := newTestJSEvaluator(t)
	config := []byte(`{
		"rules": [{
			"name": "js-rule",
			"type": "evm_js",
			"mode": "whitelist",
			"config": {
				"script": "function validate(input) { return {valid: true}; }",
				"test_cases": [{
					"name": "tc1",
					"input": {
						"sign_type": "transaction",
						"chain_id": "1",
						"signer": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
						"transaction": {"to": "0xRecipientAddress0000000000000000000000000000", "value": "0", "data": "0x"}
					},
					"expect_pass": true
				}]
			}
		}]
	}`)
	results, allPassed := ValidateTemplateConfig(eval, "test-template", config, nil)
	assert.True(t, allPassed)
	assert.NotEmpty(t, results)
}

func TestValidateTemplateConfig_MissingScript(t *testing.T) {
	eval := newTestJSEvaluator(t)
	config := []byte(`{
		"rules": [{
			"name": "js-rule",
			"type": "evm_js",
			"mode": "whitelist",
			"config": {
				"test_cases": [{"name":"tc1","input":{"sign_type":"transaction","chain_id":"1","signer":"0x0000000000000000000000000000000000000000","transaction":{"to":"0x0000000000000000000000000000000000000000","value":"0","data":"0x"}},"expect_pass":true}]
			}
		}]
	}`)
	results, allPassed := ValidateTemplateConfig(eval, "test-template", config, nil)
	assert.False(t, allPassed)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].Error, "no script")
}

func TestValidateTemplateConfig_ScriptNotString(t *testing.T) {
	eval := newTestJSEvaluator(t)
	config := []byte(`{
		"rules": [{
			"name": "js-rule",
			"type": "evm_js",
			"mode": "whitelist",
			"config": {
				"script": 42,
				"test_cases": [{"name":"tc1","input":{"sign_type":"transaction","chain_id":"1","signer":"0x0000000000000000000000000000000000000000","transaction":{"to":"0x0000000000000000000000000000000000000000","value":"0","data":"0x"}},"expect_pass":true}]
			}
		}]
	}`)
	results, allPassed := ValidateTemplateConfig(eval, "test-template", config, nil)
	assert.False(t, allPassed)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].Error, "script is not a string")
}

// ---------------------------------------------------------------------------
// ValidateConfigTestCases
// ---------------------------------------------------------------------------

func TestValidateConfigTestCases_NonJS(t *testing.T) {
	eval := newTestJSEvaluator(t)
	config := map[string]interface{}{"foo": "bar"}
	results, allPassed := ValidateConfigTestCases(eval, types.RuleTypeSignTypeRestriction, types.RuleModeWhitelist, "test-rule", config)
	assert.True(t, allPassed)
	require.Len(t, results, 1)
	assert.True(t, results[0].Valid)
}

func TestValidateConfigTestCases_NoTestCases(t *testing.T) {
	eval := newTestJSEvaluator(t)
	config := map[string]interface{}{"script": "function validate(i){return{valid:true}}"}
	results, allPassed := ValidateConfigTestCases(eval, types.RuleTypeEVMJS, types.RuleModeWhitelist, "test-rule", config)
	assert.True(t, allPassed)
	require.Len(t, results, 1)
	assert.True(t, results[0].Valid)
}

func TestValidateConfigTestCases_WithTestCases(t *testing.T) {
	eval := newTestJSEvaluator(t)
	tcJSON, _ := json.Marshal([]map[string]interface{}{
		{
			"name": "tc1",
			"input": map[string]interface{}{
				"sign_type": "transaction",
				"chain_id":  "1",
				"signer":    "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
				"transaction": map[string]interface{}{
					"to":    "0xRecipientAddress0000000000000000000000000000",
					"value": "0",
					"data":  "0x",
				},
			},
			"expect_pass": true,
		},
	})
	config := map[string]interface{}{
		"script":     "function validate(input) { return {valid: true}; }",
		"test_cases": json.RawMessage(tcJSON),
	}
	results, allPassed := ValidateConfigTestCases(eval, types.RuleTypeEVMJS, types.RuleModeWhitelist, "test-rule", config)
	assert.True(t, allPassed)
	assert.NotEmpty(t, results)
}

func TestValidateConfigTestCases_MissingScript(t *testing.T) {
	eval := newTestJSEvaluator(t)
	tcJSON, _ := json.Marshal([]map[string]interface{}{
		{"name": "tc1", "input": map[string]interface{}{"sign_type": "transaction", "chain_id": "1", "signer": "0x0000000000000000000000000000000000000000", "transaction": map[string]interface{}{"to": "0x0000000000000000000000000000000000000000", "value": "0", "data": "0x"}}, "expect_pass": true},
	})
	config := map[string]interface{}{
		"test_cases": json.RawMessage(tcJSON),
	}
	results, allPassed := ValidateConfigTestCases(eval, types.RuleTypeEVMJS, types.RuleModeWhitelist, "test-rule", config)
	assert.False(t, allPassed)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].Error, "no script")
}

func TestValidateConfigTestCases_ScriptNotString(t *testing.T) {
	eval := newTestJSEvaluator(t)
	tcJSON, _ := json.Marshal([]map[string]interface{}{
		{"name": "tc1", "input": map[string]interface{}{"sign_type": "transaction", "chain_id": "1", "signer": "0x0000000000000000000000000000000000000000", "transaction": map[string]interface{}{"to": "0x0000000000000000000000000000000000000000", "value": "0", "data": "0x"}}, "expect_pass": true},
	})
	config := map[string]interface{}{
		"script":     42,
		"test_cases": json.RawMessage(tcJSON),
	}
	results, allPassed := ValidateConfigTestCases(eval, types.RuleTypeEVMJS, types.RuleModeWhitelist, "test-rule", config)
	assert.False(t, allPassed)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].Error, "script is not a string")
}
