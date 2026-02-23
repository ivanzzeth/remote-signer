package rule

import (
	"context"
	"encoding/json"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// mockBudgetRepoForRenewal implements storage.BudgetRepository for testing periodic renewal.
// Returns a budget with UpdatedAt in the past so checkPeriodicRenewal triggers ResetBudget.
type mockBudgetRepoForRenewal struct {
	mu sync.Mutex
	// key: ruleID + ":" + unit
	state    map[string]*types.RuleBudget
	resetCall *struct {
		RuleID             types.RuleID
		Unit               string
		CurrentPeriodStart time.Time
	}
}

func newMockBudgetRepoForRenewal(updatedAt time.Time, spent, maxTotal string) *mockBudgetRepoForRenewal {
	return &mockBudgetRepoForRenewal{
		state: map[string]*types.RuleBudget{
			"rule-period:count": {
				ID:         "budget-period",
				RuleID:     types.RuleID("rule-period"),
				Unit:       "count",
				MaxTotal:   maxTotal,
				MaxPerTx:   "10",
				Spent:      spent,
				TxCount:    2,
				MaxTxCount: 5,
				UpdatedAt:  updatedAt,
			},
		},
	}
}

func (m *mockBudgetRepoForRenewal) Create(ctx context.Context, budget *types.RuleBudget) error { return nil }
func (m *mockBudgetRepoForRenewal) Delete(ctx context.Context, id string) error               { return nil }
func (m *mockBudgetRepoForRenewal) DeleteByRuleID(ctx context.Context, ruleID types.RuleID) error {
	return nil
}
func (m *mockBudgetRepoForRenewal) ListByRuleID(ctx context.Context, ruleID types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (m *mockBudgetRepoForRenewal) ListByRuleIDs(ctx context.Context, ruleIDs []types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}

func (m *mockBudgetRepoForRenewal) GetByRuleID(ctx context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := string(ruleID) + ":" + unit
	if b, ok := m.state[key]; ok {
		cp := *b
		return &cp, nil
	}
	return nil, types.ErrNotFound
}

func (m *mockBudgetRepoForRenewal) ResetBudget(ctx context.Context, ruleID types.RuleID, unit string, currentPeriodStart time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resetCall = &struct {
		RuleID             types.RuleID
		Unit               string
		CurrentPeriodStart time.Time
	}{ruleID, unit, currentPeriodStart}
	key := string(ruleID) + ":" + unit
	if b, ok := m.state[key]; ok {
		b.Spent = "0"
		b.TxCount = 0
		b.AlertSent = false
		b.UpdatedAt = currentPeriodStart
	}
	return nil
}

func (m *mockBudgetRepoForRenewal) AtomicSpend(ctx context.Context, ruleID types.RuleID, unit string, amount string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := string(ruleID) + ":" + unit
	b, ok := m.state[key]
	if !ok {
		return types.ErrNotFound
	}
	amt := new(big.Int)
	if _, ok := amt.SetString(amount, 10); !ok {
		return nil
	}
	cur := new(big.Int)
	if _, ok := cur.SetString(b.Spent, 10); !ok {
		return nil
	}
	max := new(big.Int)
	if _, ok := max.SetString(b.MaxTotal, 10); !ok {
		return nil
	}
	newSpent := new(big.Int).Add(cur, amt)
	if newSpent.Cmp(max) > 0 {
		return storage.ErrBudgetExceeded
	}
	b.Spent = newSpent.String()
	b.TxCount++
	if b.MaxTxCount > 0 && b.TxCount > b.MaxTxCount {
		return storage.ErrBudgetExceeded
	}
	b.UpdatedAt = time.Now()
	return nil
}

// mockTemplateRepoForBudget returns a template with count_only BudgetMetering.
type mockTemplateRepoForBudget struct {
	tmpl *types.RuleTemplate
}

func (m *mockTemplateRepoForBudget) Get(ctx context.Context, id string) (*types.RuleTemplate, error) {
	if m.tmpl != nil && m.tmpl.ID == id {
		return m.tmpl, nil
	}
	return nil, types.ErrNotFound
}

func (m *mockTemplateRepoForBudget) Create(ctx context.Context, tmpl *types.RuleTemplate) error   { return nil }
func (m *mockTemplateRepoForBudget) GetByName(ctx context.Context, name string) (*types.RuleTemplate, error) {
	return nil, nil
}
func (m *mockTemplateRepoForBudget) Update(ctx context.Context, tmpl *types.RuleTemplate) error { return nil }
func (m *mockTemplateRepoForBudget) Delete(ctx context.Context, id string) error                 { return nil }
func (m *mockTemplateRepoForBudget) List(ctx context.Context, filter storage.TemplateFilter) ([]*types.RuleTemplate, error) {
	return nil, nil
}
func (m *mockTemplateRepoForBudget) Count(ctx context.Context, filter storage.TemplateFilter) (int, error) {
	return 0, nil
}

// TestBudgetChecker_CheckAndDeductBudget_PeriodicRenewal_ResetsThenAllowsSpend ensures that
// when a rule has BudgetPeriod and BudgetPeriodStart (creation time + period), and the budget
// was last updated in a previous period, CheckAndDeductBudget triggers ResetBudget and then
// allows the spend (auto-renew behaviour).
func TestBudgetChecker_CheckAndDeductBudget_PeriodicRenewal_ResetsThenAllowsSpend(t *testing.T) {
	now := time.Now()
	period := 24 * time.Hour
	// Period start 72h ago → period 0: [72h ago, 48h ago), period 1: [48h ago, 24h ago), period 2: [24h ago, now]
	periodStart := now.Add(-72 * time.Hour)
	// Budget was updated 48h ago (in period 1); current period is 2 → renewal should run
	budgetUpdatedAt := now.Add(-48 * time.Hour)

	mockBudget := newMockBudgetRepoForRenewal(budgetUpdatedAt, "10", "10")
	metering, _ := json.Marshal(types.BudgetMetering{Method: "count_only", Unit: "count"})
	mockTmpl := &mockTemplateRepoForBudget{
		tmpl: &types.RuleTemplate{
			ID:             "tmpl-1",
			BudgetMetering: metering,
		},
	}

	bc := NewBudgetChecker(mockBudget, mockTmpl, slog.Default())

	rule := &types.Rule{
		ID:                 types.RuleID("rule-period"),
		TemplateID:         ptrString("tmpl-1"),
		BudgetPeriod:      &period,
		BudgetPeriodStart: &periodStart,
	}
	req := &types.SignRequest{ID: "req-1"}
	parsed := &types.ParsedPayload{}

	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.True(t, ok, "CheckAndDeductBudget must succeed after periodic renewal")

	require.NotNil(t, mockBudget.resetCall, "ResetBudget must have been called")
	assert.Equal(t, types.RuleID("rule-period"), mockBudget.resetCall.RuleID)
	assert.Equal(t, "count", mockBudget.resetCall.Unit)
	// elapsed = 72h, period = 24h → periodIndex = 3; currentPeriodStart = periodStart + 3*period ≈ now
	expectedPeriodStart := periodStart.Add(3 * period)
	assert.True(t, mockBudget.resetCall.CurrentPeriodStart.Equal(expectedPeriodStart) ||
		mockBudget.resetCall.CurrentPeriodStart.Sub(expectedPeriodStart).Abs() < time.Second,
		"ResetBudget must be called with current period start")
}

// TestBudgetChecker_CheckAndDeductBudget_NoPeriod_NoReset ensures that when the rule
// has no BudgetPeriod/BudgetPeriodStart, checkPeriodicRenewal does not call ResetBudget.
func TestBudgetChecker_CheckAndDeductBudget_NoPeriod_NoReset(t *testing.T) {
	now := time.Now()
	// Budget already has room; rule has no period
	mockBudget := newMockBudgetRepoForRenewal(now.Add(-time.Hour), "0", "10")
	metering, _ := json.Marshal(types.BudgetMetering{Method: "count_only", Unit: "count"})
	mockTmpl := &mockTemplateRepoForBudget{
		tmpl: &types.RuleTemplate{ID: "tmpl-1", BudgetMetering: metering},
	}
	bc := NewBudgetChecker(mockBudget, mockTmpl, slog.Default())

	rule := &types.Rule{
		ID:         types.RuleID("rule-period"),
		TemplateID: ptrString("tmpl-1"),
		// No BudgetPeriod / BudgetPeriodStart
	}
	req := &types.SignRequest{ID: "req-1"}
	parsed := &types.ParsedPayload{}

	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Nil(t, mockBudget.resetCall, "ResetBudget must not be called when rule has no period")
}

func ptrString(s string) *string { return &s }
