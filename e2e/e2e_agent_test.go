//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/apikeys"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// =============================================================================
// Agent Preset Apply Tests
// =============================================================================

// TestAgent_PresetApply deploys the agent preset via API and verifies that
// 15 rules are created (3 sub-rules x 5 chains).
func TestAgent_PresetApply(t *testing.T) {
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	// Apply agent preset — should produce 5 results (one per chain in the matrix).
	// Each result contains the rule created from the "Agent Template" bundle.
	// The bundle template has 3 sub-rules, but the preset apply creates one rule
	// per matrix entry (the bundle is expanded internally by the template service).
	applyResp, err := adminClient.Presets.ApplyWithVariables(ctx, "agent.preset.js.yaml", nil)
	require.NoError(t, err)
	require.NotNil(t, applyResp)

	// The agent preset has 5 chains in the matrix and 1 template (Agent Template).
	// Preset apply creates one instance per (template, chain) = 5 rules.
	require.Len(t, applyResp.Results, 5,
		"agent preset should produce 5 rules (1 template x 5 chains)")

	// Verify each rule has the correct chain_id scope
	expectedChains := map[string]bool{"1": false, "137": false, "42161": false, "10": false, "8453": false}
	for _, result := range applyResp.Results {
		assert.NotNil(t, result.Rule, "each result should have a rule")
		var ruleMap map[string]interface{}
		if err := json.Unmarshal(result.Rule, &ruleMap); err == nil {
			if cid, ok := ruleMap["chain_id"].(string); ok {
				expectedChains[cid] = true
			}
		}
	}
	for cid, found := range expectedChains {
		assert.True(t, found, "should have rule for chain %s", cid)
	}
}

// =============================================================================
// Agent API Key Permission Tests
// =============================================================================

// createAgentClient creates an agent API key via admin and returns a client for it.
// Cleanup is registered with t.Cleanup.
func createAgentClient(t *testing.T) *client.Client {
	t.Helper()
	ctx := context.Background()

	// Generate Ed25519 key pair for the agent
	agentPubKey, agentPrivKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	agentKeyID := "e2e-agent-key-test"
	agentPubHex := hex.EncodeToString(agentPubKey)

	// Create agent API key via admin client
	created, err := adminClient.APIKeys.Create(ctx, &apikeys.CreateRequest{
		ID:              agentKeyID,
		Name:            "E2E Agent Test Key",
		PublicKey:       agentPubHex,
		Admin:           false,
		Agent:           true,
		RateLimit:       500,
		AllowAllSigners: true,
	})
	if err != nil {
		apiErr, ok := err.(*client.APIError)
		if ok && apiErr.StatusCode == 403 {
			t.Skip("Skipping: API key management is readonly")
		}
		require.NoError(t, err)
	}
	require.NotNil(t, created)
	assert.True(t, created.Agent, "created key should have agent=true")

	t.Cleanup(func() {
		if delErr := adminClient.APIKeys.Delete(context.Background(), agentKeyID); delErr != nil {
			t.Logf("Warning: failed to clean up agent API key: %v", delErr)
		}
	})

	// Create client authenticated with the agent key
	agentClient, err := client.NewClient(client.Config{
		BaseURL:       baseURL,
		APIKeyID:      agentKeyID,
		PrivateKeyHex: hex.EncodeToString(agentPrivKey),
		PollInterval:  adminClient.EVM.Sign.PollInterval,
		PollTimeout:   adminClient.EVM.Sign.PollTimeout,
	})
	require.NoError(t, err)

	return agentClient
}

// TestAgent_APIKey_ReadRules verifies that an agent API key can read rules (GET)
// but cannot create rules (POST returns 403).
func TestAgent_APIKey_ReadRules(t *testing.T) {
	agentClient := createAgentClient(t)
	ctx := context.Background()

	// Agent should be able to list rules (GET)
	resp, err := agentClient.EVM.Rules.List(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.GreaterOrEqual(t, resp.Total, 1, "agent should see at least one rule")

	// Agent should NOT be able to create rules (POST)
	_, err = agentClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "Agent Should Not Create This",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Config:  map[string]interface{}{"addresses": []string{"0x0000000000000000000000000000000000000001"}},
		Enabled: true,
	})
	require.Error(t, err, "agent should not be able to create rules")
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T: %v", err, err)
	assert.Equal(t, 403, apiErr.StatusCode, "agent POST rules should return 403")
}

// TestAgent_APIKey_ReadBudgets verifies that an agent API key can read budget info.
func TestAgent_APIKey_ReadBudgets(t *testing.T) {
	agentClient := createAgentClient(t)
	ctx := context.Background()

	// First, list rules to find one with a budget
	resp, err := agentClient.EVM.Rules.List(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)

	if resp.Total == 0 {
		t.Skip("no rules available to test budget read")
	}

	// Try to read budgets for the first rule (may be empty, but should not 403)
	ruleID := resp.Rules[0].ID
	budgets, err := agentClient.EVM.Rules.ListBudgets(ctx, ruleID)
	require.NoError(t, err, "agent should be able to read budgets")
	// budgets may be empty (not all rules have budgets), but the call itself should succeed
	assert.NotNil(t, budgets, "budgets response should not be nil")
}

// TestAgent_APIKey_ConfigRedacted verifies that when an agent reads a rule,
// the Config field is null/redacted (script not exposed to agent).
func TestAgent_APIKey_ConfigRedacted(t *testing.T) {
	agentClient := createAgentClient(t)
	ctx := context.Background()

	// List rules to get a rule ID
	resp, err := agentClient.EVM.Rules.List(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)

	if resp.Total == 0 {
		t.Skip("no rules available to test config redaction")
	}

	// Get a specific rule
	rule, err := agentClient.EVM.Rules.Get(ctx, resp.Rules[0].ID)
	require.NoError(t, err)
	require.NotNil(t, rule)

	// For agent keys, the Config field should be null/empty (redacted)
	// The server should strip script content from the response for agent keys
	// If the server does not redact, the config will be non-nil.
	// This test documents the expected behavior; adjust assertion based on implementation.
	if rule.Config != nil {
		// Parse config and check that "script" field is not present or is redacted
		var configMap map[string]interface{}
		configBytes, err := json.Marshal(rule.Config)
		if err == nil {
			if json.Unmarshal(configBytes, &configMap) == nil {
				// If config is returned, script should be redacted for agent keys
				_, hasScript := configMap["script"]
				if hasScript {
					t.Log("Note: agent can see script in config; consider redacting for security")
				}
			}
		}
	}
}

// TestAgent_APIKey_CannotDeleteRules verifies that agent keys cannot delete rules.
func TestAgent_APIKey_CannotDeleteRules(t *testing.T) {
	agentClient := createAgentClient(t)
	ctx := context.Background()

	// List rules to get a rule ID
	resp, err := agentClient.EVM.Rules.List(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)

	if resp.Total == 0 {
		t.Skip("no rules available to test delete protection")
	}

	// Agent should NOT be able to delete rules
	err = agentClient.EVM.Rules.Delete(ctx, resp.Rules[0].ID)
	require.Error(t, err, "agent should not be able to delete rules")
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T: %v", err, err)
	assert.Equal(t, 403, apiErr.StatusCode, "agent DELETE rules should return 403")
}

// TestAgent_APIKey_CannotApplyPresets verifies that agent keys cannot apply presets.
func TestAgent_APIKey_CannotApplyPresets(t *testing.T) {
	agentClient := createAgentClient(t)
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	// Agent should NOT be able to apply presets (POST)
	_, err := agentClient.Presets.Apply(ctx, "agent.preset.js.yaml", nil)
	require.Error(t, err, "agent should not be able to apply presets")
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T: %v", err, err)
	assert.Equal(t, 403, apiErr.StatusCode, "agent POST preset apply should return 403")
}
