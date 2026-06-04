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

func TestRule_AdminCanCreateRule(t *testing.T) {
	ctx := context.Background()
	rule := &evm.CreateRuleRequest{
		Name:    "Test Rule - Address Whitelist",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{
				"0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
				"0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
			},
		},
	}
	created, err := adminClient.EVM.Rules.Create(ctx, rule)
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.Equal(t, rule.Name, created.Name)
	assert.Equal(t, rule.Type, created.Type)
	assert.True(t, created.Enabled)
	err = adminClient.EVM.Rules.Delete(ctx, created.ID)
	require.NoError(t, err)
}

func TestRule_AdminCanListRules(t *testing.T) {
	ctx := context.Background()
	resp, err := adminClient.EVM.Rules.List(ctx, &evm.ListRulesFilter{Limit: 1000})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.GreaterOrEqual(t, len(resp.Rules), 1)
}

func TestRule_AdminCanGetRule(t *testing.T) {
	ctx := context.Background()
	createReq := &evm.CreateRuleRequest{
		Name:    "Test Rule - Get",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
	}
	created, err := adminClient.EVM.Rules.Create(ctx, createReq)
	require.NoError(t, err)
	rule, err := adminClient.EVM.Rules.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, rule.ID)
	assert.Equal(t, created.Name, rule.Name)
	require.NoError(t, adminClient.EVM.Rules.Delete(ctx, created.ID))
}

func TestRule_AdminCanUpdateRule(t *testing.T) {
	ctx := context.Background()
	createReq := &evm.CreateRuleRequest{
		Name:    "Test Rule - Update Original",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
	}
	created, err := adminClient.EVM.Rules.Create(ctx, createReq)
	require.NoError(t, err)
	updated, err := adminClient.EVM.Rules.Update(ctx, created.ID, &evm.UpdateRuleRequest{
		Name:    "Test Rule - Update Modified",
		Enabled: false,
	})
	require.NoError(t, err)
	assert.Equal(t, "Test Rule - Update Modified", updated.Name)
	assert.False(t, updated.Enabled)
	require.NoError(t, adminClient.EVM.Rules.Delete(ctx, created.ID))
}

func TestRule_AdminCanDeleteRule(t *testing.T) {
	ctx := context.Background()
	createReq := &evm.CreateRuleRequest{
		Name:    "Test Rule - Delete",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
	}
	created, err := adminClient.EVM.Rules.Create(ctx, createReq)
	require.NoError(t, err)
	require.NoError(t, adminClient.EVM.Rules.Delete(ctx, created.ID))
	_, err = adminClient.EVM.Rules.Get(ctx, created.ID)
	require.Error(t, err)
}

func TestRule_AdminCanDisableRule(t *testing.T) {
	ctx := context.Background()
	createReq := &evm.CreateRuleRequest{
		Name:    "Test Rule - Disable",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
	}
	created, err := adminClient.EVM.Rules.Create(ctx, createReq)
	require.NoError(t, err)
	assert.True(t, created.Enabled)
	updated, err := adminClient.EVM.Rules.Update(ctx, created.ID, &evm.UpdateRuleRequest{Enabled: false})
	require.NoError(t, err)
	assert.False(t, updated.Enabled)
	updated, err = adminClient.EVM.Rules.Update(ctx, created.ID, &evm.UpdateRuleRequest{Enabled: true})
	require.NoError(t, err)
	assert.True(t, updated.Enabled)
	require.NoError(t, adminClient.EVM.Rules.Delete(ctx, created.ID))
}

func TestRule_NonAdminCannotCreateRule(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}
	ctx := context.Background()
	rule := &evm.CreateRuleRequest{
		Name:    "Test Rule - Non-Admin Create",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
	}
	_, err := nonAdminClient.EVM.Rules.Create(ctx, rule)
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok)
	assert.Equal(t, 403, apiErr.StatusCode)
}

func TestRule_NonAdminCannotUpdateRule(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}
	ctx := context.Background()
	created, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "Test Rule - Non-Admin Update",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
	})
	require.NoError(t, err)
	_, err = nonAdminClient.EVM.Rules.Update(ctx, created.ID, &evm.UpdateRuleRequest{Name: "Modified by non-admin"})
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok)
	assert.Equal(t, 403, apiErr.StatusCode)
	require.NoError(t, adminClient.EVM.Rules.Delete(ctx, created.ID))
}

func TestRule_NonAdminCannotDeleteRule(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}
	ctx := context.Background()
	created, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "Test Rule - Non-Admin Delete",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
	})
	require.NoError(t, err)
	err = nonAdminClient.EVM.Rules.Delete(ctx, created.ID)
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok)
	assert.Equal(t, 403, apiErr.StatusCode)
	require.NoError(t, adminClient.EVM.Rules.Delete(ctx, created.ID))
}

func TestRule_NonAdminCannotListRules(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}
	ctx := context.Background()
	_, err := nonAdminClient.EVM.Rules.List(ctx, &evm.ListRulesFilter{Limit: 1000})
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok)
	assert.Equal(t, 403, apiErr.StatusCode)
}

// --- Proposal approve ---

func TestRule_ProposeAndApprove(t *testing.T) {
	ctx := context.Background()

	// Admin creates a target rule
	rule := &evm.CreateRuleRequest{
		Name:    "Test Rule - Proposal Target",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{"max_value": "100"},
	}
	created, err := adminClient.EVM.Rules.Create(ctx, rule)
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.Contains(t, string(created.Config), `"max_value":"100"`)
	t.Logf("created target rule: %s", created.ID)

	// Agent proposes a change to the target rule
	proposal, err := adminClient.EVM.Rules.Propose(ctx, created.ID, &evm.ProposeRuleRequest{
		Config: map[string]interface{}{"max_value": "500"},
	})
	require.NoError(t, err)
	require.NotNil(t, proposal)
	assert.Equal(t, created.ID, *proposal.ProposalFor, "proposal should reference target")
	assert.Equal(t, "pending_approval", proposal.Status)
	assert.False(t, proposal.Enabled, "proposals are never active")
	t.Logf("created proposal: %s -> target %s", proposal.ID, *proposal.ProposalFor)

	// Target rule is unchanged (proposal not yet approved)
	targetBefore, err := adminClient.EVM.Rules.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.Contains(t, string(targetBefore.Config), `"max_value":"100"`, "target should be unchanged before approval")

	// Admin approves the proposal
	approved, err := adminClient.EVM.Rules.Approve(ctx, proposal.ID)
	require.NoError(t, err)
	require.NotNil(t, approved)
	assert.Equal(t, created.ID, approved.ID, "approve response should return target rule")
	assert.Equal(t, "active", approved.Status)
	t.Logf("approved proposal, response target ID: %s", approved.ID)

	// Target rule is now updated
	targetAfter, err := adminClient.EVM.Rules.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.Contains(t, string(targetAfter.Config), `"max_value":"500"`, "target should be updated after approval")

	// Proposal is deleted (not found)
	_, err = adminClient.EVM.Rules.Get(ctx, proposal.ID)
	require.Error(t, err, "proposal should be deleted after approval")

	// Cleanup
	require.NoError(t, adminClient.EVM.Rules.Delete(ctx, created.ID))
}

func TestRule_ProposeAndReject(t *testing.T) {
	ctx := context.Background()

	// Admin creates a target rule
	rule := &evm.CreateRuleRequest{
		Name:    "Test Rule - Proposal Reject",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{"max_value": "200"},
	}
	created, err := adminClient.EVM.Rules.Create(ctx, rule)
	require.NoError(t, err)
	require.NotNil(t, created)
	t.Logf("created target rule: %s", created.ID)

	// Propose a change
	proposal, err := adminClient.EVM.Rules.Propose(ctx, created.ID, &evm.ProposeRuleRequest{
		Config: map[string]interface{}{"max_value": "999"},
	})
	require.NoError(t, err)
	require.NotNil(t, proposal)
	assert.Equal(t, "pending_approval", proposal.Status)
	t.Logf("created proposal: %s", proposal.ID)

	// Reject the proposal
	rejected, err := adminClient.EVM.Rules.Reject(ctx, proposal.ID, "not needed")
	require.NoError(t, err)
	require.NotNil(t, rejected)
	assert.Equal(t, "rejected", rejected.Status)

	// Target rule is unchanged
	targetAfter, err := adminClient.EVM.Rules.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.Contains(t, string(targetAfter.Config), `"max_value":"200"`, "target should NOT change after rejection")

	// Proposal is still findable (rejected, not deleted)
	rejectedProposal, err := adminClient.EVM.Rules.Get(ctx, proposal.ID)
	require.NoError(t, err)
	assert.Equal(t, "rejected", rejectedProposal.Status)

	// Cleanup
	require.NoError(t, adminClient.EVM.Rules.Delete(ctx, created.ID))
	require.NoError(t, adminClient.EVM.Rules.Delete(ctx, proposal.ID))
}
