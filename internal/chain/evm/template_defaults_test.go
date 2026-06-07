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
