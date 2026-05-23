package config

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ---------------------------------------------------------------------------
// substituteBudgetValue
// ---------------------------------------------------------------------------

func TestSubstituteBudgetValue(t *testing.T) {
	t.Run("string with vars", func(t *testing.T) {
		vars := map[string]string{"chain_id": "1", "token": "0xabc"}
		result := substituteBudgetValue("${chain_id}:${token}", vars)
		assert.Equal(t, "1:0xabc", result)
	})

	t.Run("string without vars returns as-is", func(t *testing.T) {
		vars := map[string]string{"chain_id": "1"}
		result := substituteBudgetValue("plain-string", vars)
		assert.Equal(t, "plain-string", result)
	})

	t.Run("empty vars returns value unchanged", func(t *testing.T) {
		result := substituteBudgetValue("${chain_id}", nil)
		assert.Equal(t, "${chain_id}", result)
	})

	t.Run("int value unchanged", func(t *testing.T) {
		vars := map[string]string{"chain_id": "1"}
		result := substituteBudgetValue(42, vars)
		assert.Equal(t, 42, result)
	})

	t.Run("float value unchanged", func(t *testing.T) {
		vars := map[string]string{"chain_id": "1"}
		result := substituteBudgetValue(3.14, vars)
		assert.Equal(t, 3.14, result)
	})

	t.Run("bool value unchanged", func(t *testing.T) {
		vars := map[string]string{"chain_id": "1"}
		result := substituteBudgetValue(true, vars)
		assert.Equal(t, true, result)
	})

	t.Run("nil value unchanged", func(t *testing.T) {
		vars := map[string]string{"chain_id": "1"}
		result := substituteBudgetValue(nil, vars)
		assert.Nil(t, result)
	})

	t.Run("map string interface with vars", func(t *testing.T) {
		vars := map[string]string{"token": "0xabc"}
		m := map[string]interface{}{
			"unit":     "${token}",
			"max_total": "100",
		}
		result := substituteBudgetValue(m, vars)
		rm, ok := result.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "0xabc", rm["unit"])
		assert.Equal(t, "100", rm["max_total"])
	})

	t.Run("map interface interface with vars", func(t *testing.T) {
		vars := map[string]string{"token": "0xdef"}
		m := map[interface{}]interface{}{
			"unit":      "${token}",
			"max_per_tx": "50",
		}
		result := substituteBudgetValue(m, vars)
		rm, ok := result.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "0xdef", rm["unit"])
		assert.Equal(t, "50", rm["max_per_tx"])
	})

	t.Run("nested map substitution", func(t *testing.T) {
		vars := map[string]string{"token": "0x123"}
		m := map[string]interface{}{
			"unit": "${token}",
			"details": map[string]interface{}{
				"label": "token-${token}",
			},
		}
		result := substituteBudgetValue(m, vars)
		rm, ok := result.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "0x123", rm["unit"])
		details := rm["details"].(map[string]interface{})
		assert.Equal(t, "token-0x123", details["label"])
	})
}

// ---------------------------------------------------------------------------
// substituteBudgetMapVars
// ---------------------------------------------------------------------------

func TestSubstituteBudgetMapVars(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := substituteBudgetMapVars(nil, map[string]string{"a": "b"})
		assert.Nil(t, result)
	})

	t.Run("substitutes all string values", func(t *testing.T) {
		m := map[string]interface{}{
			"unit":      "${chain_id}:${token}",
			"max_total": "100",
			"count":     5,
		}
		vars := map[string]string{"chain_id": "1", "token": "0xabc"}
		result := substituteBudgetMapVars(m, vars)
		assert.Equal(t, "1:0xabc", result["unit"])
		assert.Equal(t, "100", result["max_total"])
		assert.Equal(t, 5, result["count"])
	})
}

// ---------------------------------------------------------------------------
// ruleVariablesToStringMap
// ---------------------------------------------------------------------------

func TestRuleVariablesToStringMap(t *testing.T) {
	t.Run("nil JSON returns nil", func(t *testing.T) {
		result := ruleVariablesToStringMap(nil)
		assert.Nil(t, result)
	})

	t.Run("empty JSON returns nil", func(t *testing.T) {
		result := ruleVariablesToStringMap([]byte{})
		assert.Nil(t, result)
	})

	t.Run("valid JSON converts string and number values", func(t *testing.T) {
		json := []byte(`{"chain_id": "1", "token": "0xabc", "limit": 100}`)
		result := ruleVariablesToStringMap(json)
		require.NotNil(t, result)
		assert.Equal(t, "1", result["chain_id"])
		assert.Equal(t, "0xabc", result["token"])
		assert.Equal(t, "100", result["limit"])
	})

	t.Run("skips nil values", func(t *testing.T) {
		json := []byte(`{"chain_id": "1", "token": null}`)
		result := ruleVariablesToStringMap(json)
		require.NotNil(t, result)
		assert.Equal(t, "1", result["chain_id"])
		_, exists := result["token"]
		assert.False(t, exists)
	})

	t.Run("skips empty string values", func(t *testing.T) {
		json := []byte(`{"chain_id": "", "token": "0xabc"}`)
		result := ruleVariablesToStringMap(json)
		require.NotNil(t, result)
		assert.Equal(t, "0xabc", result["token"])
		_, exists := result["chain_id"]
		assert.False(t, exists)
	})
}

// ---------------------------------------------------------------------------
// stringFromMapField
// ---------------------------------------------------------------------------

func TestStringFromMapField(t *testing.T) {
	t.Run("existing key", func(t *testing.T) {
		m := map[string]interface{}{"key": "value"}
		assert.Equal(t, "value", stringFromMapField(m, "key"))
	})

	t.Run("missing key", func(t *testing.T) {
		m := map[string]interface{}{}
		assert.Equal(t, "", stringFromMapField(m, "missing"))
	})

	t.Run("nil value", func(t *testing.T) {
		m := map[string]interface{}{"key": nil}
		assert.Equal(t, "", stringFromMapField(m, "key"))
	})

	t.Run("int value", func(t *testing.T) {
		m := map[string]interface{}{"key": 42}
		assert.Equal(t, "42", stringFromMapField(m, "key"))
	})
}

// ---------------------------------------------------------------------------
// resolveBudgetUnit
// ---------------------------------------------------------------------------

func TestResolveBudgetUnit(t *testing.T) {
	t.Run("simple unit", func(t *testing.T) {
		rule := &types.Rule{ID: "test-rule"}
		unit, err := resolveBudgetUnit(rule, nil, map[string]interface{}{"unit": "eth"})
		require.NoError(t, err)
		assert.Equal(t, "eth", unit)
	})

	t.Run("unit with variables", func(t *testing.T) {
		rule := &types.Rule{
			ID:        "test-rule",
			Variables: []byte(`{"chain_id": "1"}`),
		}
		unit, err := resolveBudgetUnit(rule, nil, map[string]interface{}{"unit": "${chain_id}:eth"})
		require.NoError(t, err)
		assert.Equal(t, "1:eth", unit)
	})

	t.Run("empty unit returns error", func(t *testing.T) {
		rule := &types.Rule{ID: "test-rule"}
		_, err := resolveBudgetUnit(rule, nil, map[string]interface{}{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unit is required")
	})

	t.Run("unresolved variable in unit returns error", func(t *testing.T) {
		rule := &types.Rule{
			ID:        "test-rule",
			Variables: []byte(`{"chain_id": "1"}`),
		}
		_, err := resolveBudgetUnit(rule, nil, map[string]interface{}{"unit": "${unknown}:eth"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must resolve to a non-empty value")
	})
}

// ---------------------------------------------------------------------------
// createBudgetFromInstanceConfig
// ---------------------------------------------------------------------------

// mockBudgetRepository implements storage.BudgetRepository for testing.
type mockBudgetRepository struct {
	mu      sync.Mutex
	budgets map[string]*types.RuleBudget
}

func newMockBudgetRepo() *mockBudgetRepository {
	return &mockBudgetRepository{budgets: make(map[string]*types.RuleBudget)}
}

func (m *mockBudgetRepository) Create(ctx context.Context, budget *types.RuleBudget) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.budgets[budget.ID]; ok {
		return fmt.Errorf("budget already exists: %s", budget.ID)
	}
	clone := *budget
	m.budgets[budget.ID] = &clone
	return nil
}

func (m *mockBudgetRepository) CreateOrGet(ctx context.Context, budget *types.RuleBudget) (*types.RuleBudget, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.budgets[budget.ID]; ok {
		clone := *existing
		return &clone, false, nil
	}
	clone := *budget
	m.budgets[budget.ID] = &clone
	return budget, true, nil
}

func (m *mockBudgetRepository) GetByRuleID(ctx context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range m.budgets {
		if b.RuleID == ruleID && b.Unit == unit {
			clone := *b
			return &clone, nil
		}
	}
	return nil, types.ErrNotFound
}

func (m *mockBudgetRepository) Get(ctx context.Context, id string) (*types.RuleBudget, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.budgets[id]; ok {
		clone := *b
		return &clone, nil
	}
	return nil, types.ErrNotFound
}

func (m *mockBudgetRepository) Update(ctx context.Context, budget *types.RuleBudget) error {
	return nil
}

func (m *mockBudgetRepository) CountByRuleID(ctx context.Context, ruleID types.RuleID) (int, error) {
	return 0, nil
}

func (m *mockBudgetRepository) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.budgets, id)
	return nil
}

func (m *mockBudgetRepository) DeleteByRuleID(ctx context.Context, ruleID types.RuleID) error {
	return nil
}

func (m *mockBudgetRepository) AtomicSpend(ctx context.Context, ruleID types.RuleID, unit string, amount string) error {
	return nil
}

func (m *mockBudgetRepository) ResetBudget(ctx context.Context, ruleID types.RuleID, unit string, currentPeriodStart time.Time) error {
	return nil
}

func (m *mockBudgetRepository) ListByRuleID(ctx context.Context, ruleID types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}

func (m *mockBudgetRepository) ListByRuleIDs(ctx context.Context, ruleIDs []types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}

func (m *mockBudgetRepository) ListAll(ctx context.Context) ([]*types.RuleBudget, error) {
	return nil, nil
}

func (m *mockBudgetRepository) MarkAlertSent(ctx context.Context, ruleID types.RuleID, unit string) error {
	return nil
}

func TestCreateBudgetFromInstanceConfig(t *testing.T) {
	ctx := context.Background()

	t.Run("creates budget with minimal config", func(t *testing.T) {
		rule := &types.Rule{ID: "test-rule"}
		tmpl := &types.RuleTemplate{}
		budgetMap := map[string]interface{}{"unit": "eth"}
		budgetRepo := newMockBudgetRepo()

		err := createBudgetFromInstanceConfig(ctx, rule, tmpl, budgetMap, budgetRepo)
		require.NoError(t, err)

		budget, err := budgetRepo.GetByRuleID(ctx, "test-rule", "eth")
		require.NoError(t, err)
		assert.Equal(t, "-1", budget.MaxTotal)
		assert.Equal(t, "-1", budget.MaxPerTx)
		assert.Equal(t, 80, budget.AlertPct)
	})

	t.Run("creates budget with explicit limits", func(t *testing.T) {
		rule := &types.Rule{ID: "test-rule-2", Variables: []byte(`{"chain_id": "1"}`)}
		tmpl := &types.RuleTemplate{BudgetMetering: []byte(`{}`)}
		budgetMap := map[string]interface{}{
			"unit":         "${chain_id}:usdc",
			"max_total":    "1000",
			"max_per_tx":   "100",
			"max_tx_count": "50",
			"alert_pct":    "90",
		}
		budgetRepo := newMockBudgetRepo()

		err := createBudgetFromInstanceConfig(ctx, rule, tmpl, budgetMap, budgetRepo)
		require.NoError(t, err)

		budget, err := budgetRepo.GetByRuleID(ctx, "test-rule-2", "1:usdc")
		require.NoError(t, err)
		assert.Equal(t, "1000", budget.MaxTotal)
		assert.Equal(t, "100", budget.MaxPerTx)
		assert.Equal(t, 50, budget.MaxTxCount)
		assert.Equal(t, 90, budget.AlertPct)
	})

	t.Run("idempotent: already exists returns nil", func(t *testing.T) {
		rule := &types.Rule{ID: "test-idempotent"}
		tmpl := &types.RuleTemplate{}
		budgetMap := map[string]interface{}{"unit": "btc"}
		budgetRepo := newMockBudgetRepo()

		err := createBudgetFromInstanceConfig(ctx, rule, tmpl, budgetMap, budgetRepo)
		require.NoError(t, err)

		err = createBudgetFromInstanceConfig(ctx, rule, tmpl, budgetMap, budgetRepo)
		require.NoError(t, err)
	})

	t.Run("missing unit returns error", func(t *testing.T) {
		rule := &types.Rule{ID: "test-no-unit"}
		tmpl := &types.RuleTemplate{}
		budgetRepo := newMockBudgetRepo()

		err := createBudgetFromInstanceConfig(ctx, rule, tmpl, map[string]interface{}{}, budgetRepo)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unit is required")
	})
}
