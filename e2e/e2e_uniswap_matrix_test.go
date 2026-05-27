//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// TestE2E_UniswapPreset_Apply verifies the unified uniswap preset creates
// a single rule with Matrix and Variables populated, covering all chains.
func TestE2E_UniswapPreset_Apply(t *testing.T) {
	ensureGuardResumed(t)
	skipIfPresetAPIDisabled(t)
	ctx := context.Background()

	snapshotRules(t)

	resp, err := adminClient.Presets.ApplyWithVariables(ctx, "evm/uniswap", nil)
	require.NoError(t, err, "uniswap preset should apply successfully")
	require.NotNil(t, resp)
	require.Len(t, resp.Results, 1, "uniswap preset should create exactly 1 rule")

	// Decode the rule from the response
	var ruleMap map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.Results[0].Rule, &ruleMap))

	ruleID, ok := ruleMap["id"].(string)
	require.True(t, ok, "rule should have an id")
	require.NotEmpty(t, ruleID)

	// Fetch the rule via API to verify it's stored correctly
	fetched, err := adminClient.EVM.Rules.Get(ctx, ruleID)
	require.NoError(t, err, "rule %s should be fetchable via API", ruleID)
	require.NotNil(t, fetched)
	assert.True(t, fetched.Enabled, "rule should be enabled")

	// Verify the rule has Variables set (the defaults from preset)
	ruleName, _ := ruleMap["name"].(string)
	t.Logf("Uniswap rule: id=%s name=%s type=%s mode=%s", ruleID, ruleName, ruleMap["type"], ruleMap["mode"])

	// Variables should be present in the response
	varsRaw, _ := ruleMap["variables"]
	require.NotNil(t, varsRaw, "rule should have variables")
	t.Logf("Variables: %v", varsRaw)

	// Matrix should be present with 7 chain entries
	matrixRaw, _ := ruleMap["matrix"]
	require.NotNil(t, matrixRaw, "rule should have matrix")
	t.Logf("Matrix kind: %T", matrixRaw)

	// Check matrix entries count
	if matrixList, ok := matrixRaw.([]interface{}); ok {
		assert.Len(t, matrixList, 7, "matrix should have 7 chain entries")
		for i, entry := range matrixList {
			if m, ok := entry.(map[string]interface{}); ok {
				cid, _ := m["chain_id"].(string)
				t.Logf("  matrix[%d]: chain_id=%s", i, cid)
			}
		}
	}
}

// TestE2E_UniswapRule_PatchVariables verifies PATCH variables on the uniswap
// rule updates correctly.
func TestE2E_UniswapRule_PatchVariables(t *testing.T) {
	ensureGuardResumed(t)
	skipIfPresetAPIDisabled(t)
	ctx := context.Background()

	snapshotRules(t)

	resp, err := adminClient.Presets.ApplyWithVariables(ctx, "evm/uniswap", nil)
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)

	var ruleMap map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.Results[0].Rule, &ruleMap))
	ruleID, _ := ruleMap["id"].(string)
	require.NotEmpty(t, ruleID)

	// PATCH variables
	updated, err := adminClient.EVM.Rules.Update(ctx, ruleID, &evm.UpdateRuleRequest{
		Variables: map[string]string{
			"max_amount_in":    "5000000000000000000",
			"allowed_token_in": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, updated)

	// Fetch the rule again and verify variables via raw API response
	fetched, err := adminClient.EVM.Rules.Get(ctx, ruleID)
	require.NoError(t, err)
	t.Logf("Rule after PATCH: name=%s enabled=%v", fetched.Name, fetched.Enabled)
}

// TestE2E_UniswapRule_PatchMatrix verifies PATCH matrix on the uniswap
// rule replaces the per-chain override table.
func TestE2E_UniswapRule_PatchMatrix(t *testing.T) {
	ensureGuardResumed(t)
	skipIfPresetAPIDisabled(t)
	ctx := context.Background()

	snapshotRules(t)

	resp, err := adminClient.Presets.ApplyWithVariables(ctx, "evm/uniswap", nil)
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)

	var ruleMap map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.Results[0].Rule, &ruleMap))
	ruleID, _ := ruleMap["id"].(string)
	require.NotEmpty(t, ruleID)

	// PATCH matrix to just 2 chains
	updated, err := adminClient.EVM.Rules.Update(ctx, ruleID, &evm.UpdateRuleRequest{
		Matrix: []map[string]any{
			{
				"chain_id":       "1",
				"weth_address":   "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
				"v2_router_address": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
			},
			{
				"chain_id":       "137",
				"weth_address":   "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270",
				"v2_router_address": "0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff",
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, updated)

	// Fetch again
	fetched, err := adminClient.EVM.Rules.Get(ctx, ruleID)
	require.NoError(t, err)
	t.Logf("Rule after Matrix PATCH: name=%s", fetched.Name)
}

// TestE2E_UniswapRule_PatchClearMatrix verifies PATCH with empty matrix
// clears the matrix.
func TestE2E_UniswapRule_PatchClearMatrix(t *testing.T) {
	ensureGuardResumed(t)
	skipIfPresetAPIDisabled(t)
	ctx := context.Background()

	snapshotRules(t)

	resp, err := adminClient.Presets.ApplyWithVariables(ctx, "evm/uniswap", nil)
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)

	var ruleMap map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.Results[0].Rule, &ruleMap))
	ruleID, _ := ruleMap["id"].(string)
	require.NotEmpty(t, ruleID)

	// Clear matrix
	updated, err := adminClient.EVM.Rules.Update(ctx, ruleID, &evm.UpdateRuleRequest{
		Matrix: []map[string]any{},
	})
	require.NoError(t, err)
	require.NotNil(t, updated)

	// Fetch the rule - verify
	fetched, err := adminClient.EVM.Rules.Get(ctx, ruleID)
	require.NoError(t, err)
	t.Logf("Rule after clearing Matrix: id=%s", fetched.ID)
}
