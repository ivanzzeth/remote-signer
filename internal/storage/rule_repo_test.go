package storage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func setupRuleRepoTestDB(t *testing.T) (*gorm.DB, *GormRuleRepository) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.Rule{}))
	repo, err := NewGormRuleRepository(db)
	require.NoError(t, err)
	return db, repo
}

// TestRuleRepo_List_ExcludesExpiredRules_WhenEnabledOnly ensures that when
// EnabledOnly is true, rules with expires_at in the past are excluded from List.
// This is the core behaviour for "rule with expiry": expired rules must not be used.
func TestRuleRepo_List_ExcludesExpiredRules_WhenEnabledOnly(t *testing.T) {
	db, repo := setupRuleRepoTestDB(t)
	ctx := context.Background()

	now := time.Now()
	expiredAt := now.Add(-1 * time.Hour)
	notExpiredAt := now.Add(24 * time.Hour)

	// Rule with no expiry (NULL) — should always be returned when enabled
	noExpiry := &types.Rule{
		ID:        types.RuleID("rule-no-expiry"),
		Name:      "No expiry",
		Type:      types.RuleTypeEVMAddressList,
		Source:    types.RuleSourceConfig,
		Enabled:   true,
		ExpiresAt: nil,
	}
	require.NoError(t, repo.Create(ctx, noExpiry))

	// Rule that has already expired
	expired := &types.Rule{
		ID:        types.RuleID("rule-expired"),
		Name:      "Expired",
		Type:      types.RuleTypeEVMAddressList,
		Source:    types.RuleSourceConfig,
		Enabled:   true,
		ExpiresAt: &expiredAt,
	}
	require.NoError(t, repo.Create(ctx, expired))

	// Rule that expires in the future
	valid := &types.Rule{
		ID:        types.RuleID("rule-valid"),
		Name:      "Valid",
		Type:      types.RuleTypeEVMAddressList,
		Source:    types.RuleSourceConfig,
		Enabled:   true,
		ExpiresAt: &notExpiredAt,
	}
	require.NoError(t, repo.Create(ctx, valid))

	evm := types.ChainTypeEVM
	filter := RuleFilter{ChainType: &evm, EnabledOnly: true}
	list, err := repo.List(ctx, filter)
	require.NoError(t, err)

	ids := make(map[types.RuleID]struct{})
	for _, r := range list {
		ids[r.ID] = struct{}{}
	}

	assert.Contains(t, ids, types.RuleID("rule-no-expiry"), "rule with no expiry must be returned")
	assert.Contains(t, ids, types.RuleID("rule-valid"), "rule with future expiry must be returned")
	assert.NotContains(t, ids, types.RuleID("rule-expired"), "expired rule must be excluded when EnabledOnly=true")

	count, err := repo.Count(ctx, filter)
	require.NoError(t, err)
	assert.Equal(t, 2, count, "count must match list length (no expiry + valid only)")
	_ = db
}

// TestRuleRepo_List_ReturnsExpiredRules_WhenNotEnabledOnly ensures that when
// EnabledOnly is false we do not filter by expiry (e.g. for admin listing).
func TestRuleRepo_List_ReturnsExpiredRules_WhenNotEnabledOnly(t *testing.T) {
	_, repo := setupRuleRepoTestDB(t)
	ctx := context.Background()

	expiredAt := time.Now().Add(-1 * time.Hour)
	r := &types.Rule{
		ID:        types.RuleID("rule-expired-admin"),
		Name:      "Expired for admin",
		Type:      types.RuleTypeEVMAddressList,
		Source:    types.RuleSourceConfig,
		Enabled:   true,
		ExpiresAt: &expiredAt,
	}
	require.NoError(t, repo.Create(ctx, r))

	evm := types.ChainTypeEVM
	list, err := repo.List(ctx, RuleFilter{ChainType: &evm, EnabledOnly: false})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(list), 1)
	var found bool
	for _, x := range list {
		if x.ID == r.ID {
			found = true
			break
		}
	}
	assert.True(t, found, "expired rule should appear when EnabledOnly=false")
}
