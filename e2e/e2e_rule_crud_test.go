//go:build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
)

func TestRule_AdminCanCreateRule(t *testing.T) {
	ctx := context.Background()
	rule := &client.CreateRuleRequest{
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
	created, err := adminClient.CreateRule(ctx, rule)
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.Equal(t, rule.Name, created.Name)
	assert.Equal(t, rule.Type, created.Type)
	assert.True(t, created.Enabled)
	err = adminClient.DeleteRule(ctx, created.ID)
	require.NoError(t, err)
}

func TestRule_AdminCanListRules(t *testing.T) {
	ctx := context.Background()
	resp, err := adminClient.ListRules(ctx, nil)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.GreaterOrEqual(t, len(resp.Rules), 1)
}

func TestRule_AdminCanGetRule(t *testing.T) {
	ctx := context.Background()
	createReq := &client.CreateRuleRequest{
		Name:    "Test Rule - Get",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
	}
	created, err := adminClient.CreateRule(ctx, createReq)
	require.NoError(t, err)
	rule, err := adminClient.GetRule(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, rule.ID)
	assert.Equal(t, created.Name, rule.Name)
	require.NoError(t, adminClient.DeleteRule(ctx, created.ID))
}

func TestRule_AdminCanUpdateRule(t *testing.T) {
	ctx := context.Background()
	createReq := &client.CreateRuleRequest{
		Name:    "Test Rule - Update Original",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
	}
	created, err := adminClient.CreateRule(ctx, createReq)
	require.NoError(t, err)
	updated, err := adminClient.UpdateRule(ctx, created.ID, &client.UpdateRuleRequest{
		Name:    "Test Rule - Update Modified",
		Enabled: false,
	})
	require.NoError(t, err)
	assert.Equal(t, "Test Rule - Update Modified", updated.Name)
	assert.False(t, updated.Enabled)
	require.NoError(t, adminClient.DeleteRule(ctx, created.ID))
}

func TestRule_AdminCanDeleteRule(t *testing.T) {
	ctx := context.Background()
	createReq := &client.CreateRuleRequest{
		Name:    "Test Rule - Delete",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
	}
	created, err := adminClient.CreateRule(ctx, createReq)
	require.NoError(t, err)
	require.NoError(t, adminClient.DeleteRule(ctx, created.ID))
	_, err = adminClient.GetRule(ctx, created.ID)
	require.Error(t, err)
}

func TestRule_AdminCanDisableRule(t *testing.T) {
	ctx := context.Background()
	createReq := &client.CreateRuleRequest{
		Name:    "Test Rule - Disable",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
	}
	created, err := adminClient.CreateRule(ctx, createReq)
	require.NoError(t, err)
	assert.True(t, created.Enabled)
	updated, err := adminClient.UpdateRule(ctx, created.ID, &client.UpdateRuleRequest{Enabled: false})
	require.NoError(t, err)
	assert.False(t, updated.Enabled)
	updated, err = adminClient.UpdateRule(ctx, created.ID, &client.UpdateRuleRequest{Enabled: true})
	require.NoError(t, err)
	assert.True(t, updated.Enabled)
	require.NoError(t, adminClient.DeleteRule(ctx, created.ID))
}

func TestRule_NonAdminCannotCreateRule(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}
	ctx := context.Background()
	rule := &client.CreateRuleRequest{
		Name:    "Test Rule - Non-Admin Create",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
	}
	_, err := nonAdminClient.CreateRule(ctx, rule)
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
	created, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "Test Rule - Non-Admin Update",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
	})
	require.NoError(t, err)
	_, err = nonAdminClient.UpdateRule(ctx, created.ID, &client.UpdateRuleRequest{Name: "Modified by non-admin"})
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok)
	assert.Equal(t, 403, apiErr.StatusCode)
	require.NoError(t, adminClient.DeleteRule(ctx, created.ID))
}

func TestRule_NonAdminCannotDeleteRule(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}
	ctx := context.Background()
	created, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "Test Rule - Non-Admin Delete",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
	})
	require.NoError(t, err)
	err = nonAdminClient.DeleteRule(ctx, created.ID)
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok)
	assert.Equal(t, 403, apiErr.StatusCode)
	require.NoError(t, adminClient.DeleteRule(ctx, created.ID))
}

func TestRule_NonAdminCannotListRules(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}
	ctx := context.Background()
	_, err := nonAdminClient.ListRules(ctx, nil)
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok)
	assert.Equal(t, 403, apiErr.StatusCode)
}
