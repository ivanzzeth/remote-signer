package evm

import (
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/stretchr/testify/assert"
)

func TestResolveRuleConfig_AppliesTemplateDefaults(t *testing.T) {
	tmplID := "evm/erc20"
	SetTemplateVariableDefs(map[string][]types.TemplateVariable{
		tmplID: {
			{Name: "max_approve_amount", Default: "-1"},
			{Name: "max_transfer_amount", Default: "-1"},
		},
	})
	t.Cleanup(func() { SetTemplateVariableDefs(nil) })

	rule := &types.Rule{
		TemplateID: &tmplID,
		Variables:  []byte(`{"trusted_contracts":"0xffe691a6ddb5d2645321e0a920c2e7bdd00dd3d8"}`),
	}
	config := resolveRuleConfig(rule, "56")
	assert.Equal(t, "-1", config["max_approve_amount"])
	assert.Equal(t, "-1", config["max_transfer_amount"])
	assert.Equal(t, "0xffe691a6ddb5d2645321e0a920c2e7bdd00dd3d8", config["trusted_contracts"])
	assert.Equal(t, "56", config["chain_id"])
}

func TestRuleConfigObjectForChain_MatrixPresetUsesInputChain(t *testing.T) {
	rule := &types.Rule{
		Variables: []byte(`{"aori_contract_address":"0xffe691a6ddb5d2645321e0a920c2e7bdd00dd3d8"}`),
		Matrix: []byte(`[
			{"chain_id":"56","aori_contract_address":"0xffe691a6ddb5d2645321e0a920c2e7bdd00dd3d8","allowed_src_eids":"30102"},
			{"chain_id":"42161","aori_contract_address":"0xc6868edf1d2a7a8b759856cb8afa333210dfeda6","allowed_src_eids":"30110"}
		]`),
	}
	// Matrix presets leave Rule.ChainID nil; validation must pass request chain.
	empty := RuleConfigObject(rule)
	assert.Equal(t, "", empty["chain_id"])

	cfg := RuleConfigObjectForChain(rule, "56")
	assert.Equal(t, "56", cfg["chain_id"])
	assert.Equal(t, "0xffe691a6ddb5d2645321e0a920c2e7bdd00dd3d8", cfg["aori_contract_address"])
	assert.Equal(t, "30102", cfg["allowed_src_eids"])
}

func TestChainIDFromTestInput(t *testing.T) {
	assert.Equal(t, "", ChainIDFromTestInput(nil))
	assert.Equal(t, "", ChainIDFromTestInput(map[string]interface{}{}))
	assert.Equal(t, "56", ChainIDFromTestInput(map[string]interface{}{"chain_id": float64(56)}))
	assert.Equal(t, "1", ChainIDFromTestInput(map[string]interface{}{"chain_id": 1}))
	assert.Equal(t, "42161", ChainIDFromTestInput(map[string]interface{}{"chain_id": int64(42161)}))
	assert.Equal(t, "137", ChainIDFromTestInput(map[string]interface{}{"chain_id": "137"}))
}

func TestRuleVarMapForChain_MatrixBSCAllowedInputTokens(t *testing.T) {
	rule := &types.Rule{
		Variables: []byte(`{"domain_name":"Aori"}`),
		Matrix: []byte(`[
			{"chain_id":"56","allowed_input_tokens":"0x55d398326f99059ff775485246999027b3197955"},
			{"chain_id":"42161","allowed_input_tokens":"0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9"}
		]`),
	}
	vars := RuleVarMapForChain(rule, "56")
	assert.Equal(t, "56", vars["chain_id"])
	assert.Equal(t, "0x55d398326f99059ff775485246999027b3197955", vars["allowed_input_tokens"])

	vars42161 := RuleVarMapForChain(rule, "42161")
	assert.Equal(t, "42161", vars42161["chain_id"])
	assert.Equal(t, "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9", vars42161["allowed_input_tokens"])
}

func TestSubstituteTestCaseInput_PreservesHardcodedTokenAddress(t *testing.T) {
	rule := &types.Rule{
		Variables: []byte(`{"allowed_input_tokens":"0x55d398326f99059ff775485246999027b3197955"}`),
		Matrix: []byte(`[
			{"chain_id":"56","allowed_input_tokens":"0x55d398326f99059ff775485246999027b3197955,0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82"}
		]`),
	}
	input := map[string]interface{}{
		"chain_id": float64(56),
		"typed_data": map[string]interface{}{
			"message": map[string]interface{}{
				"inputToken": "0x55d398326f99059fF775485246999027B3197955",
			},
		},
	}
	out, err := SubstituteTestCaseInput(input, RuleVarMapForChain(rule, "56"))
	assert.NoError(t, err)
	msg := out["typed_data"].(map[string]interface{})["message"].(map[string]interface{})
	assert.Equal(t, "0x55d398326f99059fF775485246999027B3197955", msg["inputToken"],
		"hardcoded token must not be replaced by CSV allowlist substitution")
}

func TestSubstituteTestCaseInput_MatrixPresetUsesPerChainVars(t *testing.T) {
	rule := &types.Rule{
		Variables: []byte(`{"domain_name":"Aori","domain_version":"0.3.1"}`),
		Matrix: []byte(`[
			{"chain_id":"56","aori_contract_address":"0xffe691a6ddb5d2645321e0a920c2e7bdd00dd3d8","allowed_input_tokens":"0x55d398326f99059ff775485246999027b3197955"},
			{"chain_id":"42161","aori_contract_address":"0xc6868edf1d2a7a8b759856cb8afa333210dfeda6","allowed_input_tokens":"0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9"}
		]`),
	}
	input := map[string]interface{}{
		"chain_id": float64(56),
		"typed_data": map[string]interface{}{
			"domain": map[string]interface{}{
				"verifyingContract": "${aori_contract_address}",
			},
			"message": map[string]interface{}{
				"inputToken": "0x55d398326f99059fF775485246999027B3197955",
			},
		},
	}
	vars := RuleVarMapForChain(rule, "56")
	out, err := SubstituteTestCaseInput(input, vars)
	assert.NoError(t, err)
	td := out["typed_data"].(map[string]interface{})
	domain := td["domain"].(map[string]interface{})
	assert.Equal(t, "0xffe691a6ddb5d2645321e0a920c2e7bdd00dd3d8", domain["verifyingContract"])
}
