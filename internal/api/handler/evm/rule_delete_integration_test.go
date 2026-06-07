//go:build integration

package evm

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

func setupRuleDeleteIntegrationDB(t *testing.T) (*storage.GormRuleRepository, *storage.GormBudgetRepository) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.Rule{}, &types.RuleBudget{}))

	ruleRepo, err := storage.NewGormRuleRepository(db)
	require.NoError(t, err)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	return ruleRepo, budgetRepo
}

func TestRuleHandler_DeleteRule_AtomicBudgetCleanup(t *testing.T) {
	ruleRepo, budgetRepo := setupRuleDeleteIntegrationDB(t)
	ctx := context.Background()

	ruleID := types.RuleID("inst_delete_budget_test")
	require.NoError(t, ruleRepo.Create(ctx, &types.Rule{
		ID:     ruleID,
		Name:   "Agent — ERC20 approve limit",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Source: types.RuleSourceInstance,
		Status: types.RuleStatusActive,
		Owner:  "admin-key",
	}))
	require.NoError(t, budgetRepo.Create(ctx, &types.RuleBudget{
		ID:       types.BudgetID(ruleID, "count"),
		RuleID:   ruleID,
		Unit:     "count",
		MaxTotal: "1000",
		MaxPerTx: "1",
	}))

	h, err := NewRuleHandler(ruleRepo, slog.Default(), WithBudgetRepo(budgetRepo))
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/evm/rules/"+string(ruleID), nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, ruleAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)

	_, err = ruleRepo.Get(ctx, ruleID)
	assert.ErrorIs(t, err, types.ErrNotFound)

	budgets, err := budgetRepo.ListByRuleID(ctx, ruleID)
	require.NoError(t, err)
	assert.Empty(t, budgets, "budgets must be deleted atomically with the rule")
}

func TestRuleHandler_DeleteRule_BudgetCleanupFailureRollsBack(t *testing.T) {
	ruleRepo, budgetRepo := setupRuleDeleteIntegrationDB(t)
	ctx := context.Background()

	ruleID := types.RuleID("inst_delete_budget_rollback")
	require.NoError(t, ruleRepo.Create(ctx, &types.Rule{
		ID:     ruleID,
		Name:   "Agent — test rollback",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Source: types.RuleSourceInstance,
		Status: types.RuleStatusActive,
		Owner:  "admin-key",
	}))
	require.NoError(t, budgetRepo.Create(ctx, &types.RuleBudget{
		ID:       types.BudgetID(ruleID, "count"),
		RuleID:   ruleID,
		Unit:     "count",
		MaxTotal: "1000",
		MaxPerTx: "1",
	}))

	txRuleRepo := &transactionalRuleRepoWithBudgetFailure{
		GormRuleRepository: ruleRepo,
		budgetRepo:         budgetRepo,
	}
	h, err := NewRuleHandler(txRuleRepo, slog.Default(), WithBudgetRepo(budgetRepo))
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/evm/rules/"+string(ruleID), nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, ruleAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	_, err = ruleRepo.Get(ctx, ruleID)
	assert.NoError(t, err, "rule must remain when budget cleanup fails inside transaction")

	budgets, err := budgetRepo.ListByRuleID(ctx, ruleID)
	require.NoError(t, err)
	assert.Len(t, budgets, 1, "budget must remain when delete transaction rolls back")
}

// transactionalRuleRepoWithBudgetFailure injects a failing budget repo into the
// transactional delete path so rollback semantics can be tested without
// bypassing RuleBudgetTransactional (which always constructs fresh GORM repos).
type transactionalRuleRepoWithBudgetFailure struct {
	*storage.GormRuleRepository
	budgetRepo storage.BudgetRepository
}

func (t *transactionalRuleRepoWithBudgetFailure) RunInRuleBudgetTransaction(
	ctx context.Context,
	fn func(txRule storage.RuleRepository, txBudget storage.BudgetRepository) error,
) error {
	return t.GormRuleRepository.RunInRuleBudgetTransaction(ctx, func(txRule storage.RuleRepository, _ storage.BudgetRepository) error {
		return fn(txRule, &budgetDeleteByRuleIDFailRepo{})
	})
}

type budgetDeleteByRuleIDFailRepo struct{}

func (b *budgetDeleteByRuleIDFailRepo) Create(_ context.Context, _ *types.RuleBudget) error {
	return nil
}
func (b *budgetDeleteByRuleIDFailRepo) CreateOrGet(_ context.Context, _ *types.RuleBudget) (*types.RuleBudget, bool, error) {
	return nil, false, nil
}
func (b *budgetDeleteByRuleIDFailRepo) GetByRuleID(_ context.Context, _ types.RuleID, _ string) (*types.RuleBudget, error) {
	return nil, types.ErrNotFound
}
func (b *budgetDeleteByRuleIDFailRepo) Get(_ context.Context, _ string) (*types.RuleBudget, error) {
	return nil, types.ErrNotFound
}
func (b *budgetDeleteByRuleIDFailRepo) Update(_ context.Context, _ *types.RuleBudget) error { return nil }
func (b *budgetDeleteByRuleIDFailRepo) CountByRuleID(_ context.Context, _ types.RuleID) (int, error) {
	return 0, nil
}
func (b *budgetDeleteByRuleIDFailRepo) Delete(_ context.Context, _ string) error { return nil }
func (b *budgetDeleteByRuleIDFailRepo) DeleteByRuleID(_ context.Context, _ types.RuleID) error {
	return assert.AnError
}
func (b *budgetDeleteByRuleIDFailRepo) ListAll(_ context.Context) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (b *budgetDeleteByRuleIDFailRepo) AtomicSpend(_ context.Context, _ types.RuleID, _, _ string) error {
	return nil
}
func (b *budgetDeleteByRuleIDFailRepo) ResetBudget(_ context.Context, _ types.RuleID, _ string, _ time.Time) error {
	return nil
}
func (b *budgetDeleteByRuleIDFailRepo) MarkAlertSent(_ context.Context, _ types.RuleID, _ string) error {
	return nil
}
func (b *budgetDeleteByRuleIDFailRepo) UpsertLimits(_ context.Context, _ types.RuleID, _ []storage.BudgetSyncRequest) error {
	return nil
}
func (b *budgetDeleteByRuleIDFailRepo) ListByRuleID(_ context.Context, _ types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (b *budgetDeleteByRuleIDFailRepo) ListByRuleIDs(_ context.Context, _ []types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
