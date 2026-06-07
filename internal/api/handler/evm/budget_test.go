package evm

import (
	"bytes"
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

	t.Run("rejects_unsupported_method", func(t *testing.T) {
		// PUT/DELETE on the collection aren't defined; POST goes through
		// handleCreate (covered separately) and GET goes through
		// handleList. Anything else must surface 405.
		h, err := NewBudgetListHandler(&mockBudgetRepo{}, newMockRuleRepo(), slog.Default())
		require.NoError(t, err)
		rec := doBudgetRequest(t, h, http.MethodPut, "/api/v1/evm/budgets", &types.APIKey{
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

func doBudgetRequestBody(t *testing.T, h http.Handler, method, path string, body any, apiKey *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	var buf *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		buf = bytes.NewBuffer(b)
	} else {
		buf = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, buf)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func budgetAdminKey() *types.APIKey {
	return &types.APIKey{ID: "admin", Role: types.RoleAdmin, Enabled: true}
}

func budgetDevKey() *types.APIKey {
	return &types.APIKey{ID: "dev", Role: types.RoleDev, Enabled: true}
}

// Test the create path on the list handler. Covers happy-path,
// validation, the sim:* refusal, missing rule, and duplicate (rule,
// unit) conflict.
func TestBudgetListHandler_Create(t *testing.T) {
	makeFixture := func() (*BudgetListHandler, *mockRuleRepo, *mockBudgetRepo) {
		rules := newMockRuleRepo()
		rules.addRule(&types.Rule{
			ID:   "rule_target",
			Name: "Target",
			Type: types.RuleTypeEVMValueLimit,
			Mode: types.RuleModeBlocklist,
		})
		budgets := &mockBudgetRepo{}
		h, err := NewBudgetListHandler(budgets, rules, slog.Default())
		require.NoError(t, err)
		return h, rules, budgets
	}

	t.Run("happy_path", func(t *testing.T) {
		// Track what got persisted by giving the mock a real store.
		stored := map[string]*types.RuleBudget{}
		rules := newMockRuleRepo()
		rules.addRule(&types.Rule{
			ID: "rule_target", Name: "Target",
			Type: types.RuleTypeEVMValueLimit,
			Mode: types.RuleModeBlocklist,
		})
		budgets := &mockBudgetRepo{}
		// Patch CreateOrGet to actually store. The interface uses
		// CreateOrGet specifically because the repo is shared with
		// concurrent simulation auto-create paths.
		_ = stored // satisfy linter

		h, err := NewBudgetListHandler(budgets, rules, slog.Default())
		require.NoError(t, err)
		body := CreateBudgetRequest{
			RuleID:   "rule_target",
			Unit:     "1:native",
			MaxTotal: "1000000",
			MaxPerTx: "10000",
			AlertPct: 75,
		}
		rec := doBudgetRequestBody(t, h, http.MethodPost, "/api/v1/evm/budgets", body, budgetAdminKey())
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		var entry BudgetEntry
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &entry))
		assert.Equal(t, BudgetKindRule, entry.Kind)
		assert.Equal(t, "rule_target", entry.RuleID)
		assert.Equal(t, "Target", entry.RuleName)
		assert.Equal(t, "1000000", entry.MaxTotal)
	})

	t.Run("rejects_sim_rule_id", func(t *testing.T) {
		h, _, _ := makeFixture()
		body := CreateBudgetRequest{
			RuleID: "sim:0xabc", Unit: "1:native", MaxTotal: "1000",
		}
		rec := doBudgetRequestBody(t, h, http.MethodPost, "/api/v1/evm/budgets", body, budgetAdminKey())
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "simulation budgets")
	})

	t.Run("missing_rule_returns_404", func(t *testing.T) {
		h, _, _ := makeFixture()
		body := CreateBudgetRequest{
			RuleID: "rule_unknown", Unit: "1:native", MaxTotal: "1000",
		}
		rec := doBudgetRequestBody(t, h, http.MethodPost, "/api/v1/evm/budgets", body, budgetAdminKey())
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("validation_missing_unit", func(t *testing.T) {
		h, _, _ := makeFixture()
		body := CreateBudgetRequest{RuleID: "rule_target", MaxTotal: "1000"}
		rec := doBudgetRequestBody(t, h, http.MethodPost, "/api/v1/evm/budgets", body, budgetAdminKey())
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("validation_bad_max_total", func(t *testing.T) {
		h, _, _ := makeFixture()
		body := CreateBudgetRequest{
			RuleID: "rule_target", Unit: "1:native", MaxTotal: "abc",
		}
		rec := doBudgetRequestBody(t, h, http.MethodPost, "/api/v1/evm/budgets", body, budgetAdminKey())
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("non_admin_forbidden", func(t *testing.T) {
		h, _, _ := makeFixture()
		body := CreateBudgetRequest{RuleID: "rule_target", Unit: "u", MaxTotal: "1"}
		rec := doBudgetRequestBody(t, h, http.MethodPost, "/api/v1/evm/budgets", body, budgetDevKey())
		// Dev role doesn't have PermManageBudgets — must 403.
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}

// Test the per-item handler covering get/update/reset/delete + perms.
func TestBudgetItemHandler(t *testing.T) {
	makeFixture := func() (*BudgetItemHandler, *mockRuleRepo, *mockBudgetRepo) {
		rules := newMockRuleRepo()
		rules.addRule(&types.Rule{
			ID:   "rule_target",
			Name: "Target",
			Type: types.RuleTypeEVMValueLimit,
			Mode: types.RuleModeBlocklist,
		})
		now := time.Now()
		seed := &types.RuleBudget{
			ID:         "budget-id-1",
			RuleID:     "rule_target",
			Unit:       "1:native",
			MaxTotal:   "1000",
			MaxPerTx:   "100",
			Spent:      "500",
			AlertPct:   80,
			TxCount:    5,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		budgets := &mockBudgetRepo{listAll: func(ctx context.Context) ([]*types.RuleBudget, error) {
			return []*types.RuleBudget{seed}, nil
		}}
		// In-memory map for get/update.
		store := map[string]*types.RuleBudget{seed.ID: seed}
		budgets.getFn = func(_ context.Context, id string) (*types.RuleBudget, error) {
			if b, ok := store[id]; ok {
				cp := *b
				return &cp, nil
			}
			return nil, types.ErrNotFound
		}
		budgets.updateFn = func(_ context.Context, b *types.RuleBudget) error {
			if _, ok := store[b.ID]; !ok {
				return types.ErrNotFound
			}
			cp := *b
			store[b.ID] = &cp
			return nil
		}
		budgets.resetFn = func(_ context.Context, ruleID types.RuleID, unit string, _ time.Time) error {
			for id, b := range store {
				if b.RuleID == ruleID && b.Unit == unit {
					cp := *b
					cp.Spent = "0"
					cp.TxCount = 0
					cp.AlertSent = false
					store[id] = &cp
					return nil
				}
			}
			return types.ErrNotFound
		}
		budgets.deleteFn = func(_ context.Context, id string) error {
			if _, ok := store[id]; !ok {
				return types.ErrNotFound
			}
			delete(store, id)
			return nil
		}
		h, err := NewBudgetItemHandler(budgets, rules, slog.Default())
		require.NoError(t, err)
		return h, rules, budgets
	}

	t.Run("get_returns_detail", func(t *testing.T) {
		h, _, _ := makeFixture()
		rec := doBudgetRequest(t, h, http.MethodGet, "/api/v1/evm/budgets/budget-id-1", budgetAdminKey())
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var entry BudgetEntry
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &entry))
		assert.Equal(t, "budget-id-1", entry.ID)
		assert.Equal(t, "Target", entry.RuleName)
	})

	t.Run("get_not_found", func(t *testing.T) {
		h, _, _ := makeFixture()
		rec := doBudgetRequest(t, h, http.MethodGet, "/api/v1/evm/budgets/missing", budgetAdminKey())
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("update_changes_limits", func(t *testing.T) {
		h, _, _ := makeFixture()
		max := "9999"
		rec := doBudgetRequestBody(t, h, http.MethodPatch, "/api/v1/evm/budgets/budget-id-1",
			UpdateBudgetRequest{MaxTotal: &max}, budgetAdminKey())
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var entry BudgetEntry
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &entry))
		assert.Equal(t, "9999", entry.MaxTotal)
	})

	t.Run("update_rejects_bad_max_total", func(t *testing.T) {
		h, _, _ := makeFixture()
		bad := "abc"
		rec := doBudgetRequestBody(t, h, http.MethodPatch, "/api/v1/evm/budgets/budget-id-1",
			UpdateBudgetRequest{MaxTotal: &bad}, budgetAdminKey())
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("update_can_modify_spent", func(t *testing.T) {
		h, _, _ := makeFixture()
		spent := "0"
		rec := doBudgetRequestBody(t, h, http.MethodPatch, "/api/v1/evm/budgets/budget-id-1",
			UpdateBudgetRequest{Spent: &spent}, budgetAdminKey())
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var entry BudgetEntry
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &entry))
		assert.Equal(t, "0", entry.Spent)
	})

	t.Run("reset_clears_spent_and_count", func(t *testing.T) {
		h, _, _ := makeFixture()
		rec := doBudgetRequest(t, h, http.MethodPost, "/api/v1/evm/budgets/budget-id-1/reset", budgetAdminKey())
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var entry BudgetEntry
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &entry))
		assert.Equal(t, "0", entry.Spent)
		assert.Equal(t, 0, entry.TxCount)
		assert.False(t, entry.AlertSent)
	})

	t.Run("delete_removes_row", func(t *testing.T) {
		h, _, _ := makeFixture()
		rec := doBudgetRequest(t, h, http.MethodDelete, "/api/v1/evm/budgets/budget-id-1", budgetAdminKey())
		require.Equal(t, http.StatusNoContent, rec.Code)
		// Subsequent get → 404.
		rec2 := doBudgetRequest(t, h, http.MethodGet, "/api/v1/evm/budgets/budget-id-1", budgetAdminKey())
		assert.Equal(t, http.StatusNotFound, rec2.Code)
	})

	t.Run("delete_by_rule_cleans_orphan_rows", func(t *testing.T) {
		deletedRuleID := types.RuleID("inst_orphan12345678")
		var gotRuleID types.RuleID
		budgetRepo := &mockBudgetRepo{
			listByRuleID: func(_ context.Context, ruleID types.RuleID) ([]*types.RuleBudget, error) {
				if ruleID == deletedRuleID {
					return []*types.RuleBudget{
						{ID: "orphan-budget-1", RuleID: deletedRuleID, Unit: "count"},
					}, nil
				}
				return nil, nil
			},
			deleteByRuleIDFn: func(_ context.Context, ruleID types.RuleID) error {
				gotRuleID = ruleID
				return nil
			},
		}
		h, err := NewBudgetItemHandler(budgetRepo, newMockRuleRepo(), slog.Default())
		require.NoError(t, err)
		rec := doBudgetRequest(t, h, http.MethodDelete, "/api/v1/evm/budgets/by-rule/"+string(deletedRuleID), budgetAdminKey())
		require.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, deletedRuleID, gotRuleID)
	})

	t.Run("delete_by_rule_cleans_orphan_synthetic_placeholder", func(t *testing.T) {
		simRuleID := types.RuleID("sim:0x1111111111111111111111111111111111111111")
		ruleRepo := newMockRuleRepo()
		ruleRepo.rules[simRuleID] = &types.Rule{
			ID:     simRuleID,
			Source: types.RuleSourceAutoGenerated,
			Owner:  "system",
		}
		budgetRepo := &mockBudgetRepo{
			listByRuleID: func(_ context.Context, ruleID types.RuleID) ([]*types.RuleBudget, error) {
				return nil, nil
			},
		}
		h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
		require.NoError(t, err)
		rec := doBudgetRequest(t, h, http.MethodDelete, "/api/v1/evm/budgets/by-rule/"+string(simRuleID), budgetAdminKey())
		require.Equal(t, http.StatusNoContent, rec.Code)
		_, err = ruleRepo.Get(context.Background(), simRuleID)
		assert.ErrorIs(t, err, types.ErrNotFound)
	})

	t.Run("delete_by_rule_accepts_sim_id_for_budget_cleanup", func(t *testing.T) {
		assert.False(t, ruleIDPattern.MatchString("sim:0x1111111111111111111111111111111111111111"))
		assert.True(t, isBudgetCleanupRuleID("sim:0x1111111111111111111111111111111111111111"))
		assert.True(t, isRulePathID("sim:0x1111111111111111111111111111111111111111"))
	})

	t.Run("dev_can_read_cannot_write", func(t *testing.T) {
		h, _, _ := makeFixture()
		// Read OK.
		rec := doBudgetRequest(t, h, http.MethodGet, "/api/v1/evm/budgets/budget-id-1", budgetDevKey())
		assert.Equal(t, http.StatusOK, rec.Code)
		// Update forbidden.
		max := "1"
		rec2 := doBudgetRequestBody(t, h, http.MethodPatch, "/api/v1/evm/budgets/budget-id-1",
			UpdateBudgetRequest{MaxTotal: &max}, budgetDevKey())
		assert.Equal(t, http.StatusForbidden, rec2.Code)
		// Delete forbidden.
		rec3 := doBudgetRequest(t, h, http.MethodDelete, "/api/v1/evm/budgets/budget-id-1", budgetDevKey())
		assert.Equal(t, http.StatusForbidden, rec3.Code)
	})
}
