//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Agent Preset Apply + Admin Approval E2E Tests
// =============================================================================
//
// These tests verify that an agent can apply a preset (creating self-owned
// rules) and that admin can then inspect and approve those rules. This is the
// end-to-end flow: agent requests prepackaged rules via preset apply, admin
// approves them to confirm they are active.

// TestE2E_AgentPresetApply_CreatesSelfOwnedRules applies the agent preset
// via an agent API key and verifies the created rules are owned by the agent
// key ID and have applied_to=["self"].
func TestE2E_AgentPresetApply_CreatesSelfOwnedRules(t *testing.T) {
	agentClient := createAgentClient(t)
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	// Agent applies the agent preset
	results, err := agentClient.Presets.Apply(ctx, "agent.preset.js", nil)
	require.NoError(t, err, "agent should be able to apply the agent preset")
	require.NotNil(t, results)

	// Clean up created rules
	cleanupApplyResults(t, results.Results)

	// Verify each created rule is owned by the agent key and scoped to self
	for i, result := range results.Results {
		var ruleMap map[string]interface{}
		err := json.Unmarshal(result.Rule, &ruleMap)
		require.NoError(t, err, "result %d should be valid JSON", i)

		ruleID, _ := ruleMap["id"].(string)
		require.NotEmpty(t, ruleID, "result %d should have a rule ID", i)

		// Fetch the rule via admin to see full fields
		fetched, err := adminClient.EVM.Rules.Get(ctx, ruleID)
		require.NoError(t, err, "rule %s should be fetchable via admin API", ruleID)
		require.NotNil(t, fetched)

		// Owner should be set to the agent's key ID
		require.NotNil(t, fetched.Owner, "rule %s should have owner set", ruleID)
		assert.Equal(t, "e2e-agent-key-test", *fetched.Owner,
			"rule %s owner should be the agent key ID", ruleID)

		// applied_to should be ["self"]
		assert.Contains(t, fetched.AppliedTo, "self",
			"rule %s applied_to should contain self", ruleID)

		// Rule should be active
		assert.Equal(t, "active", fetched.Status,
			"rule %s should be active", ruleID)

		t.Logf("  rule %s: name=%s type=%s owner=%s status=%s",
			ruleID, ruleMap["name"], ruleMap["type"], *fetched.Owner, fetched.Status)
	}
}

// TestE2E_AgentPresetApply_AdminCanApproveCreatedRules applies a preset via
// the admin client directly, then calls approve on each created rule to verify
// the approve endpoint works on preset-created rules.
func TestE2E_AgentPresetApply_AdminCanApproveCreatedRules(t *testing.T) {
	snapshotRules(t)
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	// Apply agent preset via admin
	resp, err := adminClient.Presets.ApplyWithVariables(ctx, "evm/agent", nil)
	require.NoError(t, err, "admin should be able to apply the agent preset")
	require.NotNil(t, resp)
	require.GreaterOrEqual(t, len(resp.Results), 1, "agent preset should create at least 1 rule")

	// Approve each created rule (idempotent — already active, but may carry
	// approved_by attribution)
	for i, result := range resp.Results {
		var ruleMap map[string]interface{}
		err := json.Unmarshal(result.Rule, &ruleMap)
		require.NoError(t, err, "result %d should be valid JSON", i)

		ruleID, _ := ruleMap["id"].(string)
		require.NotEmpty(t, ruleID, "result %d should have a rule ID", i)

		approved, err := adminClient.EVM.Rules.Approve(ctx, ruleID)
		require.NoError(t, err, "admin should be able to approve preset-created rule %s", ruleID)
		require.NotNil(t, approved)

		assert.Equal(t, "active", approved.Status,
			"rule %s should be active after approve", ruleID)

		t.Logf("  rule %s: status=%s approved_by=%v", ruleID, approved.Status, approved.ApprovedBy)
	}
}
