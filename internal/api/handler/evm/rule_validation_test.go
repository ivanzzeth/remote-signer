package evm

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func newJSEvaluator(t *testing.T) *evmchain.JSRuleEvaluator {
	t.Helper()
	eval, err := evmchain.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	return eval
}

// --- Single rule validate ---

func TestRuleValidate_SingleRule(t *testing.T) {
	eval := newJSEvaluator(t)

	t.Run("no_auth_returns_401", func(t *testing.T) {
		repo := newMockRuleRepo()
		h, err := NewRuleHandler(repo, slog.Default(), WithJSEvaluator(eval))
		require.NoError(t, err)

		rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/some-rule/validate", nil, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("agent_cannot_validate", func(t *testing.T) {
		repo := newMockRuleRepo()
		h, err := NewRuleHandler(repo, slog.Default(), WithJSEvaluator(eval))
		require.NoError(t, err)

		rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/some-rule/validate", nil, ruleAgentKey())
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("not_found", func(t *testing.T) {
		repo := newMockRuleRepo()
		h, err := NewRuleHandler(repo, slog.Default(), WithJSEvaluator(eval))
		require.NoError(t, err)

		rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/nonexistent/validate", nil, ruleAdminKey())
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("non_evm_js_rule", func(t *testing.T) {
		repo := newMockRuleRepo()
		rule := newAPIRule() // evm_address_list, not evm_js
		repo.addRule(rule)

		h, err := NewRuleHandler(repo, slog.Default(), WithJSEvaluator(eval))
		require.NoError(t, err)

		rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/validate", nil, ruleAdminKey())
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "only supported for evm_js")
	})

	t.Run("no_test_cases", func(t *testing.T) {
		repo := newMockRuleRepo()
		ct := types.ChainTypeEVM
		rule := &types.Rule{
			ID:          "rule_js_no_tc",
			Name:        "js-no-tc",
			Type:        types.RuleTypeEVMJS,
			Mode:        types.RuleModeWhitelist,
			Source:      types.RuleSourceAPI,
			ChainType:   &ct,
			Config:      json.RawMessage(`{"script":"function validate(input) { return { valid: true }; }"}`),
			Enabled:     true,
		}
		repo.addRule(rule)

		h, err := NewRuleHandler(repo, slog.Default(), WithJSEvaluator(eval))
		require.NoError(t, err)

		rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/validate", nil, ruleAdminKey())
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp ValidateRuleResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.True(t, resp.Valid)
		assert.Nil(t, resp.Results)
	})

	t.Run("with_passing_test_case", func(t *testing.T) {
		repo := newMockRuleRepo()
		ct := types.ChainTypeEVM
		tc := JSRuleTestCase{
			Name: "passing-tc",
			Input: map[string]interface{}{
				"sign_type": "transaction",
				"signer":    "0x1234567890123456789012345678901234567890",
				"transaction": map[string]interface{}{
					"to":    "0xaabbccddaabbccddaabbccddaabbccddaabbccdd",
					"value": "0",
				},
			},
			ExpectPass: true,
		}
		cfg := map[string]interface{}{
			"script":     "function validate(input) { return { valid: true }; }",
			"test_cases": []JSRuleTestCase{tc},
		}
		cfgJSON, _ := json.Marshal(cfg)
		rule := &types.Rule{
			ID:        "rule_js_pass",
			Name:      "js-pass",
			Type:      types.RuleTypeEVMJS,
			Mode:      types.RuleModeWhitelist,
			Source:    types.RuleSourceAPI,
			ChainType: &ct,
			Config:    cfgJSON,
			Enabled:   true,
		}
		repo.addRule(rule)

		h, err := NewRuleHandler(repo, slog.Default(), WithJSEvaluator(eval))
		require.NoError(t, err)

		rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/validate", nil, ruleAdminKey())
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp ValidateRuleResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.True(t, resp.Valid)
		require.Len(t, resp.Results, 1)
		assert.True(t, resp.Results[0].Passed)
		assert.True(t, resp.Results[0].ActualPass)
	})

	t.Run("with_failing_test_case", func(t *testing.T) {
		repo := newMockRuleRepo()
		ct := types.ChainTypeEVM
		tc := JSRuleTestCase{
			Name: "failing-tc",
			Input: map[string]interface{}{
				"sign_type": "transaction",
				"signer":    "0x1234567890123456789012345678901234567890",
				"transaction": map[string]interface{}{
					"to":    "0xaabbccddaabbccddaabbccddaabbccddaabbccdd",
					"value": "0",
				},
			},
			ExpectPass: true, // expects pass, but script returns valid=false
		}
		cfg := map[string]interface{}{
			"script":     "function validate(input) { return { valid: false }; }",
			"test_cases": []JSRuleTestCase{tc},
		}
		cfgJSON, _ := json.Marshal(cfg)
		rule := &types.Rule{
			ID:        "rule_js_fail",
			Name:      "js-fail",
			Type:      types.RuleTypeEVMJS,
			Mode:      types.RuleModeWhitelist,
			Source:    types.RuleSourceAPI,
			ChainType: &ct,
			Config:    cfgJSON,
			Enabled:   true,
		}
		repo.addRule(rule)

		h, err := NewRuleHandler(repo, slog.Default(), WithJSEvaluator(eval))
		require.NoError(t, err)

		rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/validate", nil, ruleAdminKey())
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp ValidateRuleResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.False(t, resp.Valid)
		assert.Contains(t, resp.Error, "one or more test cases failed")
		require.Len(t, resp.Results, 1)
		assert.False(t, resp.Results[0].Passed)
		assert.False(t, resp.Results[0].ActualPass)
	})
}

// --- Batch validate ---

func TestRuleValidate_Batch(t *testing.T) {
	eval := newJSEvaluator(t)

	t.Run("no_auth_returns_401", func(t *testing.T) {
		repo := newMockRuleRepo()
		h, err := NewRuleHandler(repo, slog.Default(), WithJSEvaluator(eval))
		require.NoError(t, err)

		rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/validate", nil, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("agent_cannot_validate", func(t *testing.T) {
		repo := newMockRuleRepo()
		h, err := NewRuleHandler(repo, slog.Default(), WithJSEvaluator(eval))
		require.NoError(t, err)

		rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/validate", nil, ruleAgentKey())
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("empty_rules", func(t *testing.T) {
		repo := newMockRuleRepo()
		h, err := NewRuleHandler(repo, slog.Default(), WithJSEvaluator(eval))
		require.NoError(t, err)

		rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/validate", nil, ruleAdminKey())
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp BatchValidateResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, 0, resp.Total)
		assert.Equal(t, 0, resp.Passed)
		assert.Equal(t, 0, resp.Failed)
		assert.Empty(t, resp.Results)
	})

	t.Run("mixed_pass_fail", func(t *testing.T) {
		repo := newMockRuleRepo()
		ct := types.ChainTypeEVM

		// Passing rule
		passTC := JSRuleTestCase{
			Name: "pass-tc",
			Input: map[string]interface{}{
				"sign_type": "transaction",
				"signer":    "0x1234567890123456789012345678901234567890",
				"transaction": map[string]interface{}{
					"to":    "0xaabbccddaabbccddaabbccddaabbccddaabbccdd",
					"value": "0",
				},
			},
			ExpectPass: true,
		}
		passCfg := map[string]interface{}{
			"script":     "function validate(input) { return { valid: true }; }",
			"test_cases": []JSRuleTestCase{passTC},
		}
		passCfgJSON, _ := json.Marshal(passCfg)
		passRule := &types.Rule{
			ID:        "rule_js_batch_pass",
			Name:      "js-batch-pass",
			Type:      types.RuleTypeEVMJS,
			Mode:      types.RuleModeWhitelist,
			Source:    types.RuleSourceAPI,
			ChainType: &ct,
			Config:    passCfgJSON,
			Enabled:   true,
		}
		repo.addRule(passRule)

		// Failing rule
		failTC := JSRuleTestCase{
			Name: "fail-tc",
			Input: map[string]interface{}{
				"sign_type": "transaction",
				"signer":    "0x1234567890123456789012345678901234567890",
				"transaction": map[string]interface{}{
					"to":    "0xaabbccddaabbccddaabbccddaabbccddaabbccdd",
					"value": "0",
				},
			},
			ExpectPass: true,
		}
		failCfg := map[string]interface{}{
			"script":     "function validate(input) { return { valid: false }; }",
			"test_cases": []JSRuleTestCase{failTC},
		}
		failCfgJSON, _ := json.Marshal(failCfg)
		failRule := &types.Rule{
			ID:        "rule_js_batch_fail",
			Name:      "js-batch-fail",
			Type:      types.RuleTypeEVMJS,
			Mode:      types.RuleModeWhitelist,
			Source:    types.RuleSourceAPI,
			ChainType: &ct,
			Config:    failCfgJSON,
			Enabled:   true,
		}
		repo.addRule(failRule)

		h, err := NewRuleHandler(repo, slog.Default(), WithJSEvaluator(eval))
		require.NoError(t, err)

		rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/validate", nil, ruleAdminKey())
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp BatchValidateResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, 2, resp.Total)
		assert.Equal(t, 1, resp.Passed)
		assert.Equal(t, 1, resp.Failed)

		for _, r := range resp.Results {
			switch r.RuleName {
			case "js-batch-pass":
				assert.True(t, r.Valid, "passing rule should be valid")
			case "js-batch-fail":
				assert.False(t, r.Valid, "failing rule should be invalid")
			}
		}
	})
}

