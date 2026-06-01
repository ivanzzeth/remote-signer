package evm

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// TestRuleValidate_TemplateFormConfig is the regression guard for the Option A
// refactor: instance rules store Config in template form (${var}), including
// their test_cases. The validation endpoints must run those test cases against
// the EFFECTIVE config (Variables substituted), otherwise inputs like
// "${first:allowed_addresses}" or "${chain_id}" reach the evaluator unresolved
// and fail with "from address not derivable" / "must be on configured chain".
func TestRuleValidate_TemplateFormConfig(t *testing.T) {
	eval := newJSEvaluator(t)
	ct := types.ChainTypeEVM
	chainID := "137"

	// A whitelist evm_js rule whose script checks tx.to is in config.allowed and
	// the chain matches config.chain_id. Config is TEMPLATE FORM: allowed and the
	// test-case inputs reference ${...} placeholders resolved from Variables.
	rule := &types.Rule{
		ID:        "inst_tf",
		Name:      "Template-form rule",
		Type:      types.RuleTypeEVMJS,
		Mode:      types.RuleModeWhitelist,
		Source:    types.RuleSourceInstance,
		ChainType: &ct,
		ChainID:   &chainID,
		TemplateID: strPtr("evm/x"),
		Variables: json.RawMessage(`{"allowed":"0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","chain_id":"137"}`),
		Config: json.RawMessage(`{
			"script": "function validate(input){ require(input.chain_id===parseInt(config.chain_id,10),'must be on configured chain'); require(rs.addr.inList(input.transaction.to, config.allowed),'to not allowed'); return ok(); }",
			"allowed": "${allowed}",
			"chain_id": "${chain_id}",
			"test_cases": [
				{
					"name": "pass: to first allowed, on chain",
					"input": {"sign_type":"transaction","chain_id":137,"signer":"${first:allowed}","transaction":{"from":"${first:allowed}","to":"${first:allowed}","value":"0x0","data":"0x"}},
					"expect_pass": true
				},
				{
					"name": "reject: to not allowed",
					"input": {"sign_type":"transaction","chain_id":137,"signer":"${first:allowed}","transaction":{"from":"${first:allowed}","to":"0x000000000000000000000000000000000000dEaD","value":"0x0","data":"0x"}},
					"expect_pass": false
				}
			]
		}`),
		Enabled: true,
	}

	repo := newMockRuleRepo()
	repo.addRule(rule)
	h, err := NewRuleHandler(repo, slog.Default(), WithJSEvaluator(eval))
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/validate", nil, ruleAdminKey())
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var resp ValidateRuleResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.True(t, resp.Valid, "template-form rule should validate via effective config; got error=%q results=%+v", resp.Error, resp.Results)
	require.Len(t, resp.Results, 2)
	for _, r := range resp.Results {
		assert.True(t, r.Passed, "case %q should pass (no unresolved ${} reaching evaluator), reason=%q", r.Name, r.Reason)
	}
}
