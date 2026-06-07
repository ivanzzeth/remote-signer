package rule

import (
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeVariablesMap_PreservesBase(t *testing.T) {
	base := map[string]string{
		"max_approve_amount": "-1",
		"trusted_contracts":  "0xabc",
	}
	patch := map[string]string{
		"trusted_contracts": "0xdef",
	}
	merged := MergeVariablesMap(base, patch)
	assert.Equal(t, "-1", merged["max_approve_amount"])
	assert.Equal(t, "0xdef", merged["trusted_contracts"])
}

func TestMergeVariablesJSON_PartialPatch(t *testing.T) {
	base := []byte(`{"max_approve_amount":"-1","trusted_contracts":"0xabc"}`)
	patch := []byte(`{"trusted_contracts":"0xdef"}`)
	merged, err := MergeVariablesJSON(base, patch)
	require.NoError(t, err)
	assert.JSONEq(t, `{"max_approve_amount":"-1","trusted_contracts":"0xdef"}`, string(merged))
}

func TestApplyVariableDefaults_FillsMissingOnly(t *testing.T) {
	defs := []types.TemplateVariable{
		{Name: "max_approve_amount", Default: "-1"},
		{Name: "token_address", Default: ""},
	}
	vars := map[string]string{"trusted_contracts": "0xabc"}
	out := ApplyVariableDefaults(defs, vars)
	assert.Equal(t, "0xabc", out["trusted_contracts"])
	assert.Equal(t, "-1", out["max_approve_amount"])
	assert.Equal(t, "", out["token_address"])
}

func TestApplyVariableDefaults_DoesNotOverrideProvided(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "max_approve_amount", Default: "-1"}}
	vars := map[string]string{"max_approve_amount": "100"}
	out := ApplyVariableDefaults(defs, vars)
	assert.Equal(t, "100", out["max_approve_amount"])
}
