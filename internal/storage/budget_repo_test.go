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

func setupBudgetTestDB(t *testing.T) (*gorm.DB, *GormBudgetRepository) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RuleBudget{}))
	repo, err := NewGormBudgetRepository(db)
	require.NoError(t, err)
	return db, repo
}

func setupIsolatedBudgetTestDB(t *testing.T) (*gorm.DB, *GormBudgetRepository) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RuleBudget{}))
	repo, err := NewGormBudgetRepository(db)
	require.NoError(t, err)
	return db, repo
}

func TestBudgetRepo_Create(t *testing.T) {
	_, repo := setupBudgetTestDB(t)
	ctx := context.Background()

	budget := &types.RuleBudget{
		ID:         "budget-1",
		RuleID:     types.RuleID("rule-1"),
		Unit:       "count",
		MaxTotal:   "10",
		MaxPerTx:   "1",
		Spent:      "0",
		TxCount:    0,
		MaxTxCount: 5,
	}
	err := repo.Create(ctx, budget)
	require.NoError(t, err)

	got, err := repo.GetByRuleID(ctx, types.RuleID("rule-1"), "count")
	require.NoError(t, err)
	assert.Equal(t, "budget-1", got.ID)
	assert.Equal(t, types.RuleID("rule-1"), got.RuleID)
	assert.Equal(t, "10", got.MaxTotal)
	assert.Equal(t, "0", got.Spent)
	assert.Equal(t, 0, got.TxCount)
}

func TestBudgetRepo_AtomicSpend_Success(t *testing.T) {
	_, repo := setupBudgetTestDB(t)
	ctx := context.Background()

	budget := &types.RuleBudget{
		ID:         "budget-2",
		RuleID:     types.RuleID("rule-2"),
		Unit:       "count",
		MaxTotal:   "10",
		MaxPerTx:   "5",
		Spent:      "0",
		TxCount:    0,
		MaxTxCount: 3,
	}
	require.NoError(t, repo.Create(ctx, budget))

	err := repo.AtomicSpend(ctx, types.RuleID("rule-2"), "count", "3")
	require.NoError(t, err)

	got, err := repo.GetByRuleID(ctx, types.RuleID("rule-2"), "count")
	require.NoError(t, err)
	assert.Equal(t, "3", got.Spent)
	assert.Equal(t, 1, got.TxCount)

	err = repo.AtomicSpend(ctx, types.RuleID("rule-2"), "count", "2")
	require.NoError(t, err)
	got, _ = repo.GetByRuleID(ctx, types.RuleID("rule-2"), "count")
	assert.Equal(t, "5", got.Spent)
	assert.Equal(t, 2, got.TxCount)
}

func TestBudgetRepo_AtomicSpend_ExceedTotal(t *testing.T) {
	_, repo := setupBudgetTestDB(t)
	ctx := context.Background()

	budget := &types.RuleBudget{
		ID:         "budget-3",
		RuleID:     types.RuleID("rule-3"),
		Unit:       "eth",
		MaxTotal:   "5",
		MaxPerTx:   "10",
		Spent:      "0",
		TxCount:    0,
		MaxTxCount: 0,
	}
	require.NoError(t, repo.Create(ctx, budget))

	require.NoError(t, repo.AtomicSpend(ctx, types.RuleID("rule-3"), "eth", "3"))
	err := repo.AtomicSpend(ctx, types.RuleID("rule-3"), "eth", "3")
	assert.ErrorIs(t, err, ErrBudgetExceeded)

	got, _ := repo.GetByRuleID(ctx, types.RuleID("rule-3"), "eth")
	assert.Equal(t, "3", got.Spent)
	assert.Equal(t, 1, got.TxCount)
}

func TestBudgetRepo_AtomicSpend_ExceedTxCount(t *testing.T) {
	_, repo := setupBudgetTestDB(t)
	ctx := context.Background()

	budget := &types.RuleBudget{
		ID:         "budget-4",
		RuleID:     types.RuleID("rule-4"),
		Unit:       "count",
		MaxTotal:   "100",
		MaxPerTx:   "1",
		Spent:      "0",
		TxCount:    0,
		MaxTxCount: 2,
	}
	require.NoError(t, repo.Create(ctx, budget))

	require.NoError(t, repo.AtomicSpend(ctx, types.RuleID("rule-4"), "count", "1"))
	require.NoError(t, repo.AtomicSpend(ctx, types.RuleID("rule-4"), "count", "1"))
	err := repo.AtomicSpend(ctx, types.RuleID("rule-4"), "count", "1")
	assert.ErrorIs(t, err, ErrBudgetExceeded)

	got, _ := repo.GetByRuleID(ctx, types.RuleID("rule-4"), "count")
	assert.Equal(t, "2", got.Spent)
	assert.Equal(t, 2, got.TxCount)
}

func TestBudgetRepo_ResetBudget(t *testing.T) {
	_, repo := setupBudgetTestDB(t)
	ctx := context.Background()

	budget := &types.RuleBudget{
		ID:         "budget-5",
		RuleID:     types.RuleID("rule-5"),
		Unit:       "count",
		MaxTotal:   "10",
		Spent:      "5",
		TxCount:    2,
		AlertSent:  true,
	}
	require.NoError(t, repo.Create(ctx, budget))

	// Reset for new period (updated_at before currentPeriodStart)
	currentPeriodStart := time.Now().Add(time.Hour)
	err := repo.ResetBudget(ctx, types.RuleID("rule-5"), "count", currentPeriodStart)
	require.NoError(t, err)

	got, err := repo.GetByRuleID(ctx, types.RuleID("rule-5"), "count")
	require.NoError(t, err)
	assert.Equal(t, "0", got.Spent)
	assert.Equal(t, 0, got.TxCount)
	assert.False(t, got.AlertSent)
}

func TestBudgetRepo_DeleteByRuleID(t *testing.T) {
	_, repo := setupBudgetTestDB(t)
	ctx := context.Background()

	budget := &types.RuleBudget{
		ID:     "budget-6",
		RuleID: types.RuleID("rule-6"),
		Unit:   "count",
		MaxTotal: "10",
	}
	require.NoError(t, repo.Create(ctx, budget))

	err := repo.DeleteByRuleID(ctx, types.RuleID("rule-6"))
	require.NoError(t, err)

	_, err = repo.GetByRuleID(ctx, types.RuleID("rule-6"), "count")
	assert.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestBudgetRepo_ListByRuleID(t *testing.T) {
	_, repo := setupBudgetTestDB(t)
	ctx := context.Background()

	require.NoError(t, repo.Create(ctx, &types.RuleBudget{ID: "b1", RuleID: "rule-7", Unit: "count", MaxTotal: "10"}))
	require.NoError(t, repo.Create(ctx, &types.RuleBudget{ID: "b2", RuleID: "rule-7", Unit: "eth", MaxTotal: "5"}))

	list, err := repo.ListByRuleID(ctx, types.RuleID("rule-7"))
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

// --- Additional budget repo tests for uncovered functions ---

func TestBudgetRepo_NewGormBudgetRepository_NilDB(t *testing.T) {
	repo, err := NewGormBudgetRepository(nil)
	assert.Nil(t, repo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database connection is required")
}

func TestBudgetRepo_Create_Nil(t *testing.T) {
	_, repo := setupIsolatedBudgetTestDB(t)
	err := repo.Create(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "budget cannot be nil")
}

func TestBudgetRepo_GetByRuleID_NotFound(t *testing.T) {
	_, repo := setupIsolatedBudgetTestDB(t)
	_, err := repo.GetByRuleID(context.Background(), "nonexistent", "count")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestBudgetRepo_Delete_Success(t *testing.T) {
	_, repo := setupIsolatedBudgetTestDB(t)
	ctx := context.Background()

	budget := &types.RuleBudget{
		ID:       "bd-del-1",
		RuleID:   types.RuleID("rule-del-1"),
		Unit:     "count",
		MaxTotal: "10",
		Spent:    "0",
	}
	require.NoError(t, repo.Create(ctx, budget))

	err := repo.Delete(ctx, "bd-del-1")
	require.NoError(t, err)

	_, err = repo.GetByRuleID(ctx, types.RuleID("rule-del-1"), "count")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestBudgetRepo_Delete_NotFound(t *testing.T) {
	_, repo := setupIsolatedBudgetTestDB(t)
	err := repo.Delete(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestBudgetRepo_ListByRuleIDs(t *testing.T) {
	_, repo := setupIsolatedBudgetTestDB(t)
	ctx := context.Background()

	require.NoError(t, repo.Create(ctx, &types.RuleBudget{ID: "lbri-1", RuleID: "rule-a", Unit: "count", MaxTotal: "10", Spent: "0"}))
	require.NoError(t, repo.Create(ctx, &types.RuleBudget{ID: "lbri-2", RuleID: "rule-b", Unit: "eth", MaxTotal: "5", Spent: "0"}))
	require.NoError(t, repo.Create(ctx, &types.RuleBudget{ID: "lbri-3", RuleID: "rule-c", Unit: "usdt", MaxTotal: "100", Spent: "0"}))

	list, err := repo.ListByRuleIDs(ctx, []types.RuleID{"rule-a", "rule-b"})
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestBudgetRepo_ListByRuleIDs_Empty(t *testing.T) {
	_, repo := setupIsolatedBudgetTestDB(t)
	list, err := repo.ListByRuleIDs(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, list)

	list, err = repo.ListByRuleIDs(context.Background(), []types.RuleID{})
	require.NoError(t, err)
	assert.Nil(t, list)
}

func TestBudgetRepo_Create_SetsTimestamps(t *testing.T) {
	_, repo := setupIsolatedBudgetTestDB(t)
	ctx := context.Background()

	before := time.Now()
	budget := &types.RuleBudget{
		ID:       "bd-ts-1",
		RuleID:   types.RuleID("rule-ts-1"),
		Unit:     "count",
		MaxTotal: "10",
		Spent:    "0",
	}
	require.NoError(t, repo.Create(ctx, budget))
	after := time.Now()

	got, err := repo.GetByRuleID(ctx, types.RuleID("rule-ts-1"), "count")
	require.NoError(t, err)
	assert.False(t, got.CreatedAt.Before(before))
	assert.False(t, got.CreatedAt.After(after))
	assert.False(t, got.UpdatedAt.Before(before))
	assert.False(t, got.UpdatedAt.After(after))
}
