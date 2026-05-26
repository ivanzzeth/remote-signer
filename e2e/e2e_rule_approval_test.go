//go:build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// =============================================================================
// Rule Approval / Rejection E2E Tests
// =============================================================================
//
// These tests exercise the approve and reject endpoints for rules. The server
// may create rules as immediately active (when require_approval_for_agent_rules
// is disabled) or as pending_approval (when enabled). The tests handle both
// modes by observing the actual status transitions.

// TestE2E_RuleApproval_AdminApproves verifies that an admin can call the approve
// endpoint on a rule and get a valid response.
func TestE2E_RuleApproval_AdminApproves(t *testing.T) {
	snapshotRules(t)
	ctx := context.Background()
	chainType := "evm"

	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:      "E2E-RuleApproval-AdminApproves",
		Type:      "evm_address_list",
		Mode:      "whitelist",
		ChainType: &chainType,
		Config:    map[string]interface{}{"addresses": []string{"0x0000000000000000000000000000000000000001"}},
		Enabled:   true,
	})
	require.NoError(t, err, "admin should be able to create a rule")

	t.Logf("Created rule %s with initial status=%s", rule.ID, rule.Status)

	// Approve via admin
	approved, err := adminClient.EVM.Rules.Approve(ctx, rule.ID)
	require.NoError(t, err, "admin should be able to approve a rule")
	require.NotNil(t, approved)

	t.Logf("Approved rule: status=%s, approved_by=%v", approved.Status, approved.ApprovedBy)

	// The rule should remain active (or transition to active if it was pending_approval)
	assert.Equal(t, "active", approved.Status,
		"after approving, rule status should be active")
}

// TestE2E_RuleApproval_AdminRejects verifies that an admin can reject a rule
// and the rule's status transitions to "rejected".
func TestE2E_RuleApproval_AdminRejects(t *testing.T) {
	snapshotRules(t)
	ctx := context.Background()
	chainType := "evm"

	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:      "E2E-RuleApproval-AdminRejects",
		Type:      "evm_address_list",
		Mode:      "whitelist",
		ChainType: &chainType,
		Config:    map[string]interface{}{"addresses": []string{"0x0000000000000000000000000000000000000001"}},
		Enabled:   true,
	})
	require.NoError(t, err, "admin should be able to create a rule")

	t.Logf("Created rule %s with initial status=%s", rule.ID, rule.Status)

	// Reject via admin
	rejected, err := adminClient.EVM.Rules.Reject(ctx, rule.ID, "E2E test rejection")
	require.NoError(t, err, "admin should be able to reject a rule")
	require.NotNil(t, rejected)

	t.Logf("Rejected rule: status=%s", rejected.Status)

	// After rejection the rule should be in "rejected" status
	assert.Equal(t, "rejected", rejected.Status,
		"after rejecting, rule status should be rejected")
}

// TestE2E_RuleApproval_RBAC_Approve verifies that only admin roles can
// call the approve endpoint. Dev and agent roles must get 403.
func TestE2E_RuleApproval_RBAC_Approve(t *testing.T) {
	ctx := context.Background()

	roles := []struct {
		name  string
		keyID string
	}{
		{"dev", "e2e-ra-dev-appr"},
		{"agent", "e2e-ra-agent-appr"},
	}

	for _, role := range roles {
		t.Run(role.name, func(t *testing.T) {
			c := createRoleClient(t, role.name, role.keyID)
			_, err := c.EVM.Rules.Approve(ctx, "test-approve-nonexistent")
			require.Error(t, err, "%s should not be able to approve rules", role.name)
			apiErr, ok := err.(*client.APIError)
			require.True(t, ok, "expected APIError, got %T: %v", err, err)
			assert.Equal(t, 403, apiErr.StatusCode,
				"%s approve should return 403", role.name)
		})
	}
}

// TestE2E_RuleApproval_RBAC_Reject verifies that only admin roles can
// call the reject endpoint. Dev and agent roles must get 403.
func TestE2E_RuleApproval_RBAC_Reject(t *testing.T) {
	ctx := context.Background()

	roles := []struct {
		name  string
		keyID string
	}{
		{"dev", "e2e-ra-dev-rej"},
		{"agent", "e2e-ra-agent-rej"},
	}

	for _, role := range roles {
		t.Run(role.name, func(t *testing.T) {
			c := createRoleClient(t, role.name, role.keyID)
			_, err := c.EVM.Rules.Reject(ctx, "test-reject-nonexistent", "not allowed")
			require.Error(t, err, "%s should not be able to reject rules", role.name)
			apiErr, ok := err.(*client.APIError)
			require.True(t, ok, "expected APIError, got %T: %v", err, err)
			assert.Equal(t, 403, apiErr.StatusCode,
				"%s reject should return 403", role.name)
		})
	}
}
