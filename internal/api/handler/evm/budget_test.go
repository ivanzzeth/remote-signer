package evm

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// TestBudgetListHandler covers the classification logic — the reason the
// endpoint exists. The list combines real rule budgets and synthetic
// simulation budgets ("sim:0x..." rule_ids), which the per-rule listing
// can't surface because they have no row in the rules table.
func TestBudgetListHandler(t *testing.T) {
	ctx := context.Background()
	t.Run("classifies_rule_and_sim_budgets", func(t *testing.T) {
		ruleRepo := newMockRuleRepo()
		ruleRepo.addRule(&types.Rule{
			ID:    "rule_00000000-0000-0000-0000-000000000001",
			Name:  "Daily Spend Cap",
			Type:  types.RuleTypeEVMValueLimit,
			Mode:  types.RuleModeBlocklist,
			Owner: "agent-1",
		})
		budgetRepo := &mockBudgetRepo{
			listAll: func(_ context.Context) ([]*types.RuleBudget, error) {
				return []*types.RuleBudget{
					{
						ID:        "id-rule",
						RuleID:    "rule_00000000-0000-0000-0000-000000000001",
						Unit:      "1:0x0:eth",
						MaxTotal:  "1000",
						Spent:     "250",
						TxCount:   3,
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					},
					{
						ID:        "id-sim",
						RuleID:    "sim:0xABCDef0000000000000000000000000000000001",
						Unit:      "1:native",
						MaxTotal:  "10000",
						Spent:     "500",
						TxCount:   1,
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					},
				}, nil
			},
		}

		h, err := NewBudgetListHandler(budgetRepo, ruleRepo, slog.Default())
		require.NoError(t, err)

		rec := doBudgetRequest(t, h, http.MethodGet, "/api/v1/evm/budgets", &types.APIKey{
			ID: "admin-1", Role: types.RoleAdmin, Enabled: true,
		})
		require.Equal(t, http.StatusOK, rec.Code)

		var resp ListBudgetsResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Equal(t, 2, resp.Total)
		require.Len(t, resp.Budgets, 2)

		var ruleEntry, simEntry *BudgetEntry
		for i := range resp.Budgets {
			switch resp.Budgets[i].Kind {
			case BudgetKindRule:
				ruleEntry = &resp.Budgets[i]
			case BudgetKindSimulation:
				simEntry = &resp.Budgets[i]
			}
		}
		require.NotNil(t, ruleEntry, "rule budget missing from response")
		require.NotNil(t, simEntry, "simulation budget missing from response")

		assert.Equal(t, "Daily Spend Cap", ruleEntry.RuleName)
		assert.Equal(t, "evm_value_limit", ruleEntry.RuleType)
		assert.Equal(t, "blocklist", ruleEntry.RuleMode)
		assert.Empty(t, ruleEntry.SignerAddress, "real-rule budgets must not carry signer_address")

		assert.Equal(t, "0xABCDef0000000000000000000000000000000001", simEntry.SignerAddress)
		assert.Empty(t, simEntry.RuleName, "synthetic sim budgets have no real rule")
	})

	t.Run("agent_sees_only_own_rule_budgets_no_sim", func(t *testing.T) {
		ruleRepo := newMockRuleRepo()
		ruleRepo.addRule(&types.Rule{
			ID:    "rule_own",
			Name:  "Own",
			Type:  types.RuleTypeEVMValueLimit,
			Owner: "agent-self",
		})
		ruleRepo.addRule(&types.Rule{
			ID:    "rule_other",
			Name:  "Other",
			Type:  types.RuleTypeEVMValueLimit,
			Owner: "agent-other",
		})
		budgetRepo := &mockBudgetRepo{
			listAll: func(_ context.Context) ([]*types.RuleBudget, error) {
				return []*types.RuleBudget{
					{ID: "b-own", RuleID: "rule_own", Unit: "u", CreatedAt: time.Now(), UpdatedAt: time.Now()},
					{ID: "b-other", RuleID: "rule_other", Unit: "u", CreatedAt: time.Now(), UpdatedAt: time.Now()},
					// Sim budget — must be hidden from agents.
					{ID: "b-sim", RuleID: "sim:0x1111111111111111111111111111111111111111", Unit: "u", CreatedAt: time.Now(), UpdatedAt: time.Now()},
				}, nil
			},
		}
		h, err := NewBudgetListHandler(budgetRepo, ruleRepo, slog.Default())
		require.NoError(t, err)

		rec := doBudgetRequest(t, h, http.MethodGet, "/api/v1/evm/budgets", &types.APIKey{
			ID: "agent-self", Role: types.RoleAgent, Enabled: true,
		})
		require.Equal(t, http.StatusOK, rec.Code)

		var resp ListBudgetsResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		require.Len(t, resp.Budgets, 1)
		assert.Equal(t, "b-own", resp.Budgets[0].ID)
	})

	t.Run("orphaned_rule_budget_shown_to_admin", func(t *testing.T) {
		// Budget row references a rule_id that no longer exists in the
		// rules table — handler should still emit it (admin/dev) so
		// operators can clean it up.
		ruleRepo := newMockRuleRepo()
		budgetRepo := &mockBudgetRepo{
			listAll: func(_ context.Context) ([]*types.RuleBudget, error) {
				return []*types.RuleBudget{
					{ID: "b-orph", RuleID: "rule_deleted", Unit: "u", CreatedAt: time.Now(), UpdatedAt: time.Now()},
				}, nil
			},
		}
		h, err := NewBudgetListHandler(budgetRepo, ruleRepo, slog.Default())
		require.NoError(t, err)

		rec := doBudgetRequest(t, h, http.MethodGet, "/api/v1/evm/budgets", &types.APIKey{
			ID: "admin-1", Role: types.RoleAdmin, Enabled: true,
		})
		require.Equal(t, http.StatusOK, rec.Code)

		var resp ListBudgetsResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		require.Len(t, resp.Budgets, 1)
		assert.Equal(t, "b-orph", resp.Budgets[0].ID)
		assert.Empty(t, resp.Budgets[0].RuleName)
	})

	t.Run("rejects_non_GET", func(t *testing.T) {
		h, err := NewBudgetListHandler(&mockBudgetRepo{}, newMockRuleRepo(), slog.Default())
		require.NoError(t, err)
		rec := doBudgetRequest(t, h, http.MethodPost, "/api/v1/evm/budgets", &types.APIKey{
			ID: "admin", Role: types.RoleAdmin, Enabled: true,
		})
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("rejects_unauthenticated", func(t *testing.T) {
		h, err := NewBudgetListHandler(&mockBudgetRepo{}, newMockRuleRepo(), slog.Default())
		require.NoError(t, err)
		rec := doBudgetRequest(t, h, http.MethodGet, "/api/v1/evm/budgets", nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	_ = ctx
}

func doBudgetRequest(t *testing.T, h http.Handler, method, path string, apiKey *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if apiKey != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
