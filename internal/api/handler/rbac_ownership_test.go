package handler

import (
	"context"
	"testing"

	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestDetermineRuleOwnership_NilAPIKey(t *testing.T) {
	_, err := DetermineRuleOwnership(context.Background(), nil, nil, types.RuleModeWhitelist, false, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestDetermineRuleOwnership_AdminNoAppliedTo(t *testing.T) {
	apiKey := &types.APIKey{ID: "admin", Role: types.RoleAdmin}
	result, err := DetermineRuleOwnership(context.Background(), apiKey, nil, types.RuleModeWhitelist, false, nil)
	require.NoError(t, err)
	assert.Equal(t, "admin", result.Owner)
	assert.Equal(t, pq.StringArray{"*"}, result.AppliedTo)
	assert.Equal(t, types.RuleStatusActive, result.Status)
}

func TestDetermineRuleOwnership_AdminWithAppliedTo(t *testing.T) {
	apiKey := &types.APIKey{ID: "admin", Role: types.RoleAdmin}
	repo := newMockAPIKeyRepo()
	repo.keys["agent"] = &types.APIKey{ID: "agent", Role: types.RoleAgent}
	result, err := DetermineRuleOwnership(context.Background(), apiKey, []string{"agent"}, types.RuleModeWhitelist, false, repo)
	require.NoError(t, err)
	assert.Equal(t, "admin", result.Owner)
	assert.Equal(t, pq.StringArray{"agent"}, result.AppliedTo)
	assert.Equal(t, types.RuleStatusActive, result.Status)
}

func TestDetermineRuleOwnership_AdminAppliedToNotFound(t *testing.T) {
	apiKey := &types.APIKey{ID: "admin", Role: types.RoleAdmin}
	repo := newMockAPIKeyRepo()
	_, err := DetermineRuleOwnership(context.Background(), apiKey, []string{"no-such-key"}, types.RuleModeWhitelist, false, repo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "applied_to key ID not found")
}

func TestDetermineRuleOwnership_AdminAppliedToInvalidFormat(t *testing.T) {
	apiKey := &types.APIKey{ID: "admin", Role: types.RoleAdmin}
	repo := newMockAPIKeyRepo()
	_, err := DetermineRuleOwnership(context.Background(), apiKey, []string{"invalid key!!"}, types.RuleModeWhitelist, false, repo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid applied_to key ID format")
}

func TestDetermineRuleOwnership_AdminWildcardSkipsValidation(t *testing.T) {
	apiKey := &types.APIKey{ID: "admin", Role: types.RoleAdmin}
	repo := newMockAPIKeyRepo()
	result, err := DetermineRuleOwnership(context.Background(), apiKey, []string{"*"}, types.RuleModeWhitelist, false, repo)
	require.NoError(t, err)
	assert.Equal(t, pq.StringArray{"*"}, result.AppliedTo)
}

func TestDetermineRuleOwnership_NonAdminForceSelf(t *testing.T) {
	for _, role := range []types.APIKeyRole{types.RoleAgent, types.RoleDev, types.RoleStrategy} {
		apiKey := &types.APIKey{ID: "user1", Role: role}
		result, err := DetermineRuleOwnership(context.Background(), apiKey, []string{"should-be-ignored"}, types.RuleModeWhitelist, false, nil)
		require.NoError(t, err)
		assert.Equal(t, "user1", result.Owner)
		assert.Equal(t, pq.StringArray{"self"}, result.AppliedTo, "role %s should force self", role)
	}
}

func TestDetermineRuleOwnership_AgentWhitelistRequireApproval(t *testing.T) {
	apiKey := &types.APIKey{ID: "agent1", Role: types.RoleAgent}
	result, err := DetermineRuleOwnership(context.Background(), apiKey, nil, types.RuleModeWhitelist, true, nil)
	require.NoError(t, err)
	assert.Equal(t, types.RuleStatusPendingApproval, result.Status)
}

func TestDetermineRuleOwnership_AgentBlocklistAlwaysActive(t *testing.T) {
	apiKey := &types.APIKey{ID: "agent1", Role: types.RoleAgent}
	result, err := DetermineRuleOwnership(context.Background(), apiKey, nil, types.RuleModeBlocklist, true, nil)
	require.NoError(t, err)
	assert.Equal(t, types.RuleStatusActive, result.Status)
}

func TestDetermineRuleOwnership_AgentWhitelistNoApproval(t *testing.T) {
	apiKey := &types.APIKey{ID: "agent1", Role: types.RoleAgent}
	result, err := DetermineRuleOwnership(context.Background(), apiKey, nil, types.RuleModeWhitelist, false, nil)
	require.NoError(t, err)
	assert.Equal(t, types.RuleStatusActive, result.Status)
}
