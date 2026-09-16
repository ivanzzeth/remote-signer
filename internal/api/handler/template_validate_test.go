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

// TestValidateTemplateConfig_BrokenJSONIsInvalid 钉住 2026-09-16 修掉的 fail-open。
//
// ⛔ 改动之前这里返回的是 Valid:true / allPassed:true —— 校验器在**自己解析不了
// 输入**的时候报告「通过」。判据一句话:*校验器失效时,它说的是通过还是不通过?*
//
// ⚠️ 生产可达性(查过,不是假设):这个函数有**五个**调用点,只有
// template.go:479 那条前面挡了一道 isUnrecognizedTemplateConfig(语法坏的配置
// 在那里就被判成 "non-evm_js template" 提前返回了)。而另外两个恰恰是做**放行
// 决定**的,且都没有那道关、传的还是未经 normalize 的 tmpl.Config:
//   - template_actions.go:163  template instantiate(强制校验,注释标着 fund-loss risk)
//   - preset.go:714            preset apply
func TestValidateTemplateConfig_BrokenJSONIsInvalid(t *testing.T) {
	eval := newTestJSEvaluator(t)
	results, allPassed := ValidateTemplateConfig(eval, "test-template", []byte(`{"rules": [`), nil)
	assert.False(t, allPassed, "解析不了的配置被报告成通过")
	require.Len(t, results, 1)
	assert.False(t, results[0].Valid)
	assert.Contains(t, results[0].Error, "not valid JSON")
}

// TestValidateTemplateConfig_NonBundleShapeIsSkipped 是上一条的**边界**,
// 也是我第一版改过头的地方:`rules` 键在、但不是数组 —— 这是合法 JSON,
// 按 normalizeTemplateConfigForValidation 的规则属于「bundle 形态、不许包装」,
// 原样传到这里应当**跳过**而不是判失败。
//
// ⛔ 少了这条,把「语法坏」和「形状不是 bundle」一刀切的回归就没有东西拦得住 ——
// 那会让一批合法的扁平模板在 instantiate / apply 上突然被拒。
func TestValidateTemplateConfig_NonBundleShapeIsSkipped(t *testing.T) {
	eval := newTestJSEvaluator(t)
	config := []byte(`{"rules":"not-an-array","script":"function validate(i){return {valid:true};}"}`)
	results, allPassed := ValidateTemplateConfig(eval, "test-template", config, nil)
	assert.True(t, allPassed, "合法 JSON 但非 bundle 形态被判成了失败")
	require.Len(t, results, 1)
	assert.True(t, results[0].Valid)
	assert.Contains(t, results[0].Error, "skipped")
}

// TestValidateTemplateConfig_BrokenTestCasesIsInvalid 是同一形状的第二处:
// test_cases 的形状不对(这里是字符串而非数组)以前同样被跳过成 Valid:true。
// ⚠️ 与「一条用例都没有」区分开 —— 后者合法,由下面那条测试钉住。
func TestValidateTemplateConfig_BrokenTestCasesIsInvalid(t *testing.T) {
	eval := newTestJSEvaluator(t)
	config := []byte(`{
		"rules": [{
			"name": "js-rule", "type": "evm_js", "mode": "whitelist",
			"config": {"script": "function validate(i){return {valid:true};}", "test_cases": "not-an-array"}
		}]
	}`)
	results, allPassed := ValidateTemplateConfig(eval, "test-template", config, nil)
	assert.False(t, allPassed, "形状不对的 test_cases 被报告成通过")
	require.Len(t, results, 1)
	assert.False(t, results[0].Valid)
	assert.Contains(t, results[0].Error, "wrong shape")
}

// TestValidateTemplateConfig_EmptyTestCasesIsSkipped 是上一条的**反方向**:
// 一条测试用例都没有是合法的,不该被判失败 —— 否则这次修复就从「校验器不再
// 说谎」变成了「校验器开始误伤」。
func TestValidateTemplateConfig_EmptyTestCasesIsSkipped(t *testing.T) {
	eval := newTestJSEvaluator(t)
	config := []byte(`{
		"rules": [{
			"name": "js-rule", "type": "evm_js", "mode": "whitelist",
			"config": {"script": "function validate(i){return {valid:true};}", "test_cases": []}
		}]
	}`)
	results, allPassed := ValidateTemplateConfig(eval, "test-template", config, nil)
	assert.True(t, allPassed, "空的 test_cases 不该被判失败")
	require.Len(t, results, 1)
	assert.True(t, results[0].Valid)
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
