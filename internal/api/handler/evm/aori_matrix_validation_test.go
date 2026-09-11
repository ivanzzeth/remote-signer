package evm

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

const (
	bscUSDT         = "0x55d398326f99059fF775485246999027B3197955"
	arbUSDT0        = "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9"
	aoriBSCContract = "0xffe691a6ddb5d2645321e0a920c2e7bdd00dd3d8"
	testSigner      = "0x0000000000000000000000000000000000000001"
)

// stargateAoriMatrixRule builds a Stargate-like matrix instance (nil Rule.ChainID).
func stargateAoriMatrixRule(t *testing.T, config json.RawMessage) *types.Rule {
	t.Helper()
	ct := types.ChainTypeEVM
	return &types.Rule{
		ID:        "stargate-aori",
		Name:      "Stargate — Aori Order Signature",
		Type:      types.RuleTypeEVMJS,
		Mode:      types.RuleModeWhitelist,
		ChainType: &ct,
		Config:    config,
		Variables: []byte(`{
			"domain_name":"Aori",
			"domain_version":"0.3.1",
			"allowed_dst_eids":"30101,30111,30333,30102,30390,30396,30398,30184,30383,30110",
			"allowed_output_tokens":"0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9",
			"max_input_amount":"-1",
			"max_output_amount":"-1"
		}`),
		Matrix: []byte(`[
			{"chain_id":"56","aori_contract_address":"0xffe691a6ddb5d2645321e0a920c2e7bdd00dd3d8","allowed_src_eids":"30102","allowed_input_tokens":"0x55d398326f99059ff775485246999027b3197955,0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82"}
		]`),
	}
}

func loadAoriTemplateConfig(t *testing.T) json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "rules", "templates", "evm", "aori.yaml"))
	require.NoError(t, err)
	var tmpl struct {
		Rules []struct {
			Config map[string]interface{} `yaml:"config"`
		} `yaml:"rules"`
	}
	require.NoError(t, yaml.Unmarshal(data, &tmpl))
	require.NotEmpty(t, tmpl.Rules)
	cfgBytes, err := json.Marshal(tmpl.Rules[0].Config)
	require.NoError(t, err)
	return cfgBytes
}

// Bug: matrix preset validation used empty chain_id → BSC matrix row never applied.
// Regression: full aori.yaml test_cases pass on a Stargate-like matrix instance.
func TestAoriMatrixInstance_AllTestCasesPass(t *testing.T) {
	eval := newJSEvaluator(t)
	rule := stargateAoriMatrixRule(t, loadAoriTemplateConfig(t))

	h, err := NewRuleHandler(newMockRuleRepo(), slog.New(slog.NewTextHandler(io.Discard, nil)), WithJSEvaluator(eval))
	require.NoError(t, err)

	testCases, err := testCasesFromConfig(rule.Config)
	require.NoError(t, err)
	require.NotEmpty(t, testCases)

	results, valid := h.runJSTestCases(rule, rule.Config, testCases)
	require.Len(t, results, len(testCases))
	for _, r := range results {
		t.Logf("%s passed=%v reason=%q", r.Name, r.Passed, r.Reason)
	}
	assert.True(t, valid, "all Aori matrix instance test cases should pass")
}

// Bug: validateRule extracted test_cases from EffectiveConfig(rule) with empty chain_id,
// so ${aori_contract_address} and matrix vars were wrong before evaluation.
func TestRuleValidate_MatrixPresetUsesTestInputChainID(t *testing.T) {
	eval := newJSEvaluator(t)
	rule := stargateAoriMatrixRule(t, loadAoriTemplateConfig(t))

	repo := newMockRuleRepo()
	repo.addRule(rule)
	h, err := NewRuleHandler(repo, slog.Default(), WithJSEvaluator(eval))
	require.NoError(t, err)

	rec := doRuleEndpoint(t, h.ValidateRule, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/validate", nil, ruleAdminKey())
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var resp ValidateRuleResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.True(t, resp.Valid, "matrix preset Aori rule should validate; error=%q results=%+v", resp.Error, resp.Results)
}

// Bug: inputToken: "${allowed_input_tokens}" was pre-substituted to the full CSV allowlist
// string, which is not a valid single address → "inputToken not allowed".
func TestRunJSTestCases_PreSubstitutedAllowlistCSV_FailsInputToken(t *testing.T) {
	eval := newJSEvaluator(t)
	script := `function validate(input) {
		var ctx = rs.typedData.require(input, 'Order');
		var msg = ctx.message || {};
		rs.addr.requireInListIfNonEmpty(String(msg.inputToken || '').trim(), config.allowed_input_tokens, 'inputToken not allowed');
		return ok();
	}`
	cfg := json.RawMessage(`{"script":` + mustJSON(t, script) + `}`)
	rule := stargateAoriMatrixRule(t, cfg)

	// Simulates the OLD bug: EffectiveConfig substituted the entire BSC allowlist CSV
	// into the inputToken field before the evaluator ran.
	csvAllowlist := "0x55d398326f99059ff775485246999027b3197955,0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82"
	tcs := []JSRuleTestCase{{
		Name: "pass with CSV stuffed into inputToken (broken pre-substitution)",
		Input: map[string]interface{}{
			"sign_type": "typed_data",
			"chain_id":  56,
			"signer":    testSigner,
			"typed_data": map[string]interface{}{
				"primaryType": "Order",
				"domain": map[string]interface{}{
					"name": "Aori", "version": "0.3.1",
					"verifyingContract": aoriBSCContract,
				},
				"message": map[string]interface{}{
					"inputToken": csvAllowlist,
				},
			},
		},
		ExpectPass: true,
	}}

	h, err := NewRuleHandler(newMockRuleRepo(), slog.New(slog.NewTextHandler(io.Discard, nil)), WithJSEvaluator(eval))
	require.NoError(t, err)

	results, valid := h.runJSTestCases(rule, rule.Config, tcs)
	require.Len(t, results, 1)
	assert.False(t, valid)
	assert.False(t, results[0].Passed)
	assert.Contains(t, results[0].Reason, "inputToken not allowed")
}

// Fix counterpart: hardcoded single token address in test case message passes.
func TestRunJSTestCases_HardcodedInputToken_PassesWithMatrixAllowlist(t *testing.T) {
	eval := newJSEvaluator(t)
	script := `function validate(input) {
		var ctx = rs.typedData.require(input, 'Order');
		var msg = ctx.message || {};
		rs.addr.requireInListIfNonEmpty(String(msg.inputToken || '').trim(), config.allowed_input_tokens, 'inputToken not allowed');
		return ok();
	}`
	cfg := json.RawMessage(`{"script":` + mustJSON(t, script) + `}`)
	rule := stargateAoriMatrixRule(t, cfg)

	tcs := []JSRuleTestCase{{
		Name: "pass with hardcoded BSC USDT",
		Input: map[string]interface{}{
			"sign_type": "typed_data",
			"chain_id":  56,
			"signer":    testSigner,
			"typed_data": map[string]interface{}{
				"primaryType": "Order",
				"domain": map[string]interface{}{
					"name": "Aori", "version": "0.3.1",
					"verifyingContract": "${aori_contract_address}",
				},
				"message": map[string]interface{}{
					"inputToken": bscUSDT,
				},
			},
		},
		ExpectPass: true,
	}}

	h, err := NewRuleHandler(newMockRuleRepo(), slog.New(slog.NewTextHandler(io.Discard, nil)), WithJSEvaluator(eval))
	require.NoError(t, err)

	results, valid := h.runJSTestCases(rule, rule.Config, tcs)
	require.Len(t, results, 1)
	assert.True(t, valid)
	assert.True(t, results[0].Passed, "reason=%q", results[0].Reason)
}

// Bug: reject-dstEid test used 30101, but Stargate preset allows 30101 (Ethereum eid).
func TestRunJSTestCases_StargateDstEid30101_IsAllowed(t *testing.T) {
	eval := newJSEvaluator(t)
	script := `function validate(input) {
		var ctx = rs.typedData.require(input, 'Order');
		var msg = ctx.message || {};
		var allowed = String(config.allowed_dst_eids || '').split(',').map(function(s){ return parseInt(s.trim(),10); });
		var n = parseInt(String(msg.dstEid), 10);
		if (allowed.indexOf(n) < 0) revert('dstEid not allowed');
		return ok();
	}`
	cfg := json.RawMessage(`{"script":` + mustJSON(t, script) + `}`)
	rule := stargateAoriMatrixRule(t, cfg)

	tcs := []JSRuleTestCase{{
		Name:       "dstEid 30101 allowed in Stargate preset",
		ExpectPass: true,
		Input:      aoriOrderInput(30101, 30102),
	}}

	h, err := NewRuleHandler(newMockRuleRepo(), slog.New(slog.NewTextHandler(io.Discard, nil)), WithJSEvaluator(eval))
	require.NoError(t, err)

	results, valid := h.runJSTestCases(rule, rule.Config, tcs)
	require.Len(t, results, 1)
	assert.True(t, valid)
	assert.True(t, results[0].Passed, "30101 is in Stargate allowed_dst_eids; reason=%q", results[0].Reason)
}

func TestRunJSTestCases_StargateDstEid99999_IsRejected(t *testing.T) {
	eval := newJSEvaluator(t)
	script := `function validate(input) {
		var ctx = rs.typedData.require(input, 'Order');
		var msg = ctx.message || {};
		var allowed = String(config.allowed_dst_eids || '').split(',').map(function(s){ return parseInt(s.trim(),10); });
		var n = parseInt(String(msg.dstEid), 10);
		if (allowed.indexOf(n) < 0) revert('dstEid not allowed');
		return ok();
	}`
	cfg := json.RawMessage(`{"script":` + mustJSON(t, script) + `}`)
	rule := stargateAoriMatrixRule(t, cfg)

	tcs := []JSRuleTestCase{{
		Name:       "dstEid 99999 not in allowlist",
		ExpectPass: false,
		Input:      aoriOrderInput(99999, 30102),
	}}

	h, err := NewRuleHandler(newMockRuleRepo(), slog.New(slog.NewTextHandler(io.Discard, nil)), WithJSEvaluator(eval))
	require.NoError(t, err)

	results, valid := h.runJSTestCases(rule, rule.Config, tcs)
	require.Len(t, results, 1)
	assert.True(t, valid, "negative test case should match expect_pass=false")
	assert.True(t, results[0].Passed)
	assert.False(t, results[0].ActualPass)
	assert.Contains(t, results[0].Reason, "dstEid not allowed")
}

func aoriOrderInput(dstEid, srcEid int) map[string]interface{} {
	return map[string]interface{}{
		"sign_type": "typed_data",
		"chain_id":  56,
		"signer":    testSigner,
		"typed_data": map[string]interface{}{
			"primaryType": "Order",
			"domain": map[string]interface{}{
				"name": "Aori", "version": "0.3.1",
				"verifyingContract": aoriBSCContract,
			},
			"message": map[string]interface{}{
				"inputAmount":  "1000000000000000000",
				"outputAmount": "990000000000000000",
				"inputToken":   bscUSDT,
				"outputToken":  arbUSDT0,
				"startTime":    "1704067200",
				"endTime":      "1704070800",
				"srcEid":       srcEid,
				"dstEid":       dstEid,
				"offerer":      testSigner,
				"recipient":    testSigner,
			},
		},
	}
}

func mustJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	require.NoError(t, err)
	return string(b)
}
