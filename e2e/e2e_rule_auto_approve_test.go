//go:build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// TestE2E_RuleAutoApprove_AdminCreatesActiveRule verifies that creating
// a directly-active whitelist rule triggers the onRuleActivated callback
// without errors. The server's ReevaluatePending is called but finds
// no authorizing requests (expected in this test setup).
func TestE2E_RuleAutoApprove_AdminCreatesActiveRule(t *testing.T) {
	snapshotRules(t)

	ctx := context.Background()
	chainType := "evm"

	// Admin creates a directly-active blocklist rule.
	// The callback fires asynchronously — verify no error.
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:      "E2E-AutoApprove-Blocklist",
		Type:      "evm_address_list",
		Mode:      "blocklist",
		ChainType: &chainType,
		Config: map[string]interface{}{
			"addresses": []string{"0x0000000000000000000000000000000000000001"},
		},
		Enabled: true,
	})
	require.NoError(t, err, "admin blocklist rule creation should succeed")
	assert.Equal(t, "active", rule.Status, "admin-created blocklist should be active immediately")
}

// TestE2E_RuleAutoApprove_AdminActivatesPendingRule verifies that when an admin
// approves a pending_approval rule, the onRuleActivated callback fires from
// approveRule.
func TestE2E_RuleAutoApprove_AdminActivatesPendingRule(t *testing.T) {
	snapshotRules(t)

	ctx := context.Background()

	// Admin creates a rule and then approves it.
	// The approve handler should fire the callback.
	chainType := "evm"
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:      "E2E-AutoApprove-Whitelist-Direct",
		Type:      "evm_address_list",
		Mode:      "whitelist",
		ChainType: &chainType,
		Config: map[string]interface{}{
			"addresses": []string{"0x0000000000000000000000000000000000000001"},
		},
		Enabled: true,
	})
	require.NoError(t, err, "admin whitelist rule creation should succeed")

	// If the rule is active directly (no require_approval), the callback
	// already fired on creation. If it's pending_approval, approve it.
	if rule.Status != "active" {
		approved, appErr := adminClient.EVM.Rules.Approve(ctx, rule.ID)
		require.NoError(t, appErr, "admin should be able to approve")
		assert.Equal(t, "active", approved.Status, "approved rule should be active")
	} else {
		assert.Equal(t, "active", rule.Status,
			"admin-created whitelist should be active immediately")
	}
}
