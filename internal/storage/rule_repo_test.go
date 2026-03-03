package storage

import (
	"context"
	"fmt"
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

// setupIsolatedRuleRepoTestDB creates an isolated in-memory DB (no shared cache)
// so tests don't interfere with each other.
func setupIsolatedRuleRepoTestDB(t *testing.T) (*gorm.DB, *GormRuleRepository) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
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

// --- Additional GormRuleRepository tests for uncovered functions ---

func TestGormRuleRepo_NewGormRuleRepository_NilDB(t *testing.T) {
	repo, err := NewGormRuleRepository(nil)
	assert.Nil(t, repo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database connection is required")
}

func TestGormRuleRepo_Create_Nil(t *testing.T) {
	_, repo := setupIsolatedRuleRepoTestDB(t)
	err := repo.Create(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rule cannot be nil")
}

func TestGormRuleRepo_Get(t *testing.T) {
	_, repo := setupIsolatedRuleRepoTestDB(t)
	ctx := context.Background()

	rule := &types.Rule{ID: "grr-get-1", Name: "test-get", Enabled: true, Type: types.RuleTypeEVMAddressList, Source: types.RuleSourceConfig}
	require.NoError(t, repo.Create(ctx, rule))

	got, err := repo.Get(ctx, "grr-get-1")
	require.NoError(t, err)
	assert.Equal(t, types.RuleID("grr-get-1"), got.ID)
	assert.Equal(t, "test-get", got.Name)
}

func TestGormRuleRepo_Get_NotFound(t *testing.T) {
	_, repo := setupIsolatedRuleRepoTestDB(t)
	_, err := repo.Get(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestGormRuleRepo_Update(t *testing.T) {
	_, repo := setupIsolatedRuleRepoTestDB(t)
	ctx := context.Background()

	rule := &types.Rule{ID: "grr-upd-1", Name: "original", Enabled: true, Type: types.RuleTypeEVMAddressList, Source: types.RuleSourceConfig}
	require.NoError(t, repo.Create(ctx, rule))

	rule.Name = "updated"
	rule.Enabled = false
	err := repo.Update(ctx, rule)
	require.NoError(t, err)

	got, err := repo.Get(ctx, "grr-upd-1")
	require.NoError(t, err)
	assert.Equal(t, "updated", got.Name)
	assert.False(t, got.Enabled)
}

func TestGormRuleRepo_Update_Nil(t *testing.T) {
	_, repo := setupIsolatedRuleRepoTestDB(t)
	err := repo.Update(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rule cannot be nil")
}

func TestGormRuleRepo_Delete(t *testing.T) {
	_, repo := setupIsolatedRuleRepoTestDB(t)
	ctx := context.Background()

	rule := &types.Rule{ID: "grr-del-1", Name: "to-delete", Enabled: true, Type: types.RuleTypeEVMAddressList, Source: types.RuleSourceConfig}
	require.NoError(t, repo.Create(ctx, rule))

	err := repo.Delete(ctx, "grr-del-1")
	require.NoError(t, err)

	_, err = repo.Get(ctx, "grr-del-1")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestGormRuleRepo_Delete_NotFound(t *testing.T) {
	_, repo := setupIsolatedRuleRepoTestDB(t)
	err := repo.Delete(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestGormRuleRepo_ListByChainType(t *testing.T) {
	_, repo := setupIsolatedRuleRepoTestDB(t)
	ctx := context.Background()

	evm := types.ChainTypeEVM
	require.NoError(t, repo.Create(ctx, &types.Rule{ID: "grr-lbct-1", ChainType: &evm, Enabled: true, Type: types.RuleTypeEVMAddressList, Source: types.RuleSourceConfig}))
	require.NoError(t, repo.Create(ctx, &types.Rule{ID: "grr-lbct-2", Enabled: false, Type: types.RuleTypeEVMAddressList, Source: types.RuleSourceConfig}))

	list, err := repo.ListByChainType(ctx, types.ChainTypeEVM)
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, types.RuleID("grr-lbct-1"), list[0].ID)
}

func TestGormRuleRepo_IncrementMatchCount(t *testing.T) {
	_, repo := setupIsolatedRuleRepoTestDB(t)
	ctx := context.Background()

	rule := &types.Rule{ID: "grr-inc-1", Name: "counter", Enabled: true, Type: types.RuleTypeEVMAddressList, Source: types.RuleSourceConfig}
	require.NoError(t, repo.Create(ctx, rule))

	err := repo.IncrementMatchCount(ctx, "grr-inc-1")
	require.NoError(t, err)

	got, _ := repo.Get(ctx, "grr-inc-1")
	assert.Equal(t, uint64(1), got.MatchCount)
	assert.NotNil(t, got.LastMatchedAt)

	// Increment again
	require.NoError(t, repo.IncrementMatchCount(ctx, "grr-inc-1"))
	got, _ = repo.Get(ctx, "grr-inc-1")
	assert.Equal(t, uint64(2), got.MatchCount)
}

func TestGormRuleRepo_IncrementMatchCount_NotFound(t *testing.T) {
	_, repo := setupIsolatedRuleRepoTestDB(t)
	err := repo.IncrementMatchCount(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestGormRuleRepo_List_AllFilters(t *testing.T) {
	_, repo := setupIsolatedRuleRepoTestDB(t)
	ctx := context.Background()

	evm := types.ChainTypeEVM
	chainID := "1"
	apiKeyID := "key-1"
	signerAddr := "0xABC"

	rule := &types.Rule{
		ID:            "grr-af-1",
		Name:          "all-filters",
		Type:          types.RuleTypeEVMAddressList,
		Source:        types.RuleSourceAPI,
		ChainType:     &evm,
		ChainID:       &chainID,
		APIKeyID:      &apiKeyID,
		SignerAddress: &signerAddr,
		Enabled:       true,
	}
	require.NoError(t, repo.Create(ctx, rule))

	ruleType := types.RuleTypeEVMAddressList
	ruleSource := types.RuleSourceAPI
	list, err := repo.List(ctx, RuleFilter{
		ChainType:     &evm,
		ChainID:       &chainID,
		APIKeyID:      &apiKeyID,
		SignerAddress: &signerAddr,
		Type:          &ruleType,
		Source:        &ruleSource,
		EnabledOnly:   true,
		Limit:         10,
		Offset:        0,
	})
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, types.RuleID("grr-af-1"), list[0].ID)

	// Count with same filters
	count, err := repo.Count(ctx, RuleFilter{
		ChainType:     &evm,
		ChainID:       &chainID,
		APIKeyID:      &apiKeyID,
		SignerAddress: &signerAddr,
		Type:          &ruleType,
		Source:        &ruleSource,
		EnabledOnly:   true,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestGormRuleRepo_List_Pagination(t *testing.T) {
	_, repo := setupIsolatedRuleRepoTestDB(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		require.NoError(t, repo.Create(ctx, &types.Rule{
			ID:      types.RuleID(fmt.Sprintf("grr-pag-%d", i)),
			Name:    fmt.Sprintf("rule-%d", i),
			Type:    types.RuleTypeEVMAddressList,
			Source:  types.RuleSourceConfig,
			Enabled: true,
		}))
	}

	// With limit
	list, err := repo.List(ctx, RuleFilter{Limit: 2})
	require.NoError(t, err)
	assert.Len(t, list, 2)

	// With offset
	list, err = repo.List(ctx, RuleFilter{Limit: 10, Offset: 3})
	require.NoError(t, err)
	assert.Len(t, list, 2)
}
