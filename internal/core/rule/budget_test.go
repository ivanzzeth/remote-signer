package rule

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func (m *mockBudgetRepoForRenewal) MarkAlertSent(ctx context.Context, ruleID types.RuleID, unit string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := string(ruleID) + ":" + unit
	if b, ok := m.state[key]; ok {
		b.AlertSent = true
	}
	return nil
}

func (m *mockBudgetRepoForRenewal) CountByRuleID(_ context.Context, _ types.RuleID) (int, error) {
	return 0, nil
}
func (m *mockBudgetRepoForRenewal) CreateOrGet(_ context.Context, budget *types.RuleBudget) (*types.RuleBudget, bool, error) {
	return budget, true, nil
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

// --- decimalToRaw tests ---

func TestDecimalToRaw(t *testing.T) {
	tests := []struct {
		name     string
		human    string
		decimals int
		want     string
		wantErr  bool
	}{
		{"integer 1000 with 6 decimals", "1000", 6, "1000000000", false},
		{"integer 1 with 18 decimals", "1", 18, "1000000000000000000", false},
		{"fractional 0.1 with 18 decimals", "0.1", 18, "100000000000000000", false},
		{"fractional 0.5 with 6 decimals", "0.5", 6, "500000", false},
		{"zero", "0", 18, "0", false},
		{"pass-through empty", "", 6, "", false},
		{"pass-through -1", "-1", 6, "-1", false},
		{"too many fractional digits", "1.1234567", 6, "", true},
		{"negative value", "-100", 6, "", true},
		{"multiple decimal points", "1.2.3", 6, "", true},
		{"integer with 0 decimals", "42", 0, "42", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decimalToRaw(tc.human, tc.decimals)
			if tc.wantErr {
				require.Error(t, err, "expected error for input %q", tc.human)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// --- Dynamic budget auto-create tests ---

// dynamicBudgetRepo extends mockBudgetRepoForRenewal with Create tracking.
type dynamicBudgetRepo struct {
	mu       sync.Mutex
	state    map[string]*types.RuleBudget
	created  []*types.RuleBudget
}

func newDynamicBudgetRepo() *dynamicBudgetRepo {
	return &dynamicBudgetRepo{
		state: make(map[string]*types.RuleBudget),
	}
}

func (m *dynamicBudgetRepo) Create(ctx context.Context, budget *types.RuleBudget) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.created = append(m.created, budget)
	m.state[string(budget.RuleID)+":"+budget.Unit] = budget
	return nil
}

func (m *dynamicBudgetRepo) GetByRuleID(ctx context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := string(ruleID) + ":" + unit
	if b, ok := m.state[key]; ok {
		cp := *b
		return &cp, nil
	}
	return nil, types.ErrNotFound
}

func (m *dynamicBudgetRepo) Delete(ctx context.Context, id string) error               { return nil }
func (m *dynamicBudgetRepo) DeleteByRuleID(ctx context.Context, ruleID types.RuleID) error { return nil }
func (m *dynamicBudgetRepo) ListByRuleID(ctx context.Context, ruleID types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (m *dynamicBudgetRepo) ListByRuleIDs(ctx context.Context, ruleIDs []types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (m *dynamicBudgetRepo) ResetBudget(ctx context.Context, ruleID types.RuleID, unit string, t time.Time) error {
	return nil
}
func (m *dynamicBudgetRepo) AtomicSpend(ctx context.Context, ruleID types.RuleID, unit string, amount string) error {
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
	maxT := new(big.Int)
	if _, ok := maxT.SetString(b.MaxTotal, 10); !ok {
		return nil
	}
	newSpent := new(big.Int).Add(cur, amt)
	if newSpent.Cmp(maxT) > 0 {
		return storage.ErrBudgetExceeded
	}
	b.Spent = newSpent.String()
	b.TxCount++
	b.UpdatedAt = time.Now()
	return nil
}
func (m *dynamicBudgetRepo) MarkAlertSent(ctx context.Context, ruleID types.RuleID, unit string) error {
	return nil
}
func (m *dynamicBudgetRepo) CountByRuleID(_ context.Context, _ types.RuleID) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.state), nil
}
func (m *dynamicBudgetRepo) CreateOrGet(ctx context.Context, budget *types.RuleBudget) (*types.RuleBudget, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := string(budget.RuleID) + ":" + budget.Unit
	if existing, ok := m.state[key]; ok {
		cp := *existing
		return &cp, false, nil
	}
	m.created = append(m.created, budget)
	m.state[key] = budget
	cp := *budget
	return &cp, true, nil
}

// TestBudgetChecker_DynamicBudget_AutoCreateKnownUnit tests that when JS returns {amount, unit}
// with a known unit, a budget record is auto-created with the configured limits.
func TestBudgetChecker_DynamicBudget_AutoCreateKnownUnit(t *testing.T) {
	budgetRepo := newDynamicBudgetRepo()
	metering := types.BudgetMetering{
		Method:  "js",
		Dynamic: true,
		KnownUnits: map[string]types.UnitConf{
			"native": {MaxTotal: "1000000000000000000", MaxPerTx: "100000000000000000"},
		},
	}
	meteringJSON, _ := json.Marshal(metering)
	tmplRepo := &mockTemplateRepoForBudget{
		tmpl: &types.RuleTemplate{ID: "tmpl-dyn", BudgetMetering: meteringJSON},
	}

	bc := NewBudgetChecker(budgetRepo, tmplRepo, slog.Default())
	bc.SetJSEvaluator(&stubJSEvaluator{
		amount: big.NewInt(50000000000000000), // 0.05 ETH
		unit:   "native",
	})

	chainID := "1"
	rule := &types.Rule{
		ID:         types.RuleID("rule-dyn"),
		TemplateID: ptrString("tmpl-dyn"),
		ChainID:    &chainID,
	}
	req := &types.SignRequest{ID: "req-dyn"}
	parsed := &types.ParsedPayload{}

	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.True(t, ok, "should allow spend within budget")

	// Verify budget was auto-created
	require.Len(t, budgetRepo.created, 1, "should auto-create one budget record")
	created := budgetRepo.created[0]
	assert.Equal(t, "1:native", created.Unit)
	assert.Equal(t, "1000000000000000000", created.MaxTotal)
	assert.Equal(t, "100000000000000000", created.MaxPerTx)
}

// TestBudgetChecker_DynamicBudget_AutoCreateUnknownDefault tests that unknown units fall back
// to unknown_default configuration.
func TestBudgetChecker_DynamicBudget_AutoCreateUnknownDefault(t *testing.T) {
	budgetRepo := newDynamicBudgetRepo()
	metering := types.BudgetMetering{
		Method:  "js",
		Dynamic: true,
		UnknownDefault: &types.UnitConf{
			MaxTotal:   "999",
			MaxPerTx:   "99",
			MaxTxCount: 50,
		},
	}
	meteringJSON, _ := json.Marshal(metering)
	tmplRepo := &mockTemplateRepoForBudget{
		tmpl: &types.RuleTemplate{ID: "tmpl-unk", BudgetMetering: meteringJSON},
	}

	bc := NewBudgetChecker(budgetRepo, tmplRepo, slog.Default())
	bc.SetJSEvaluator(&stubJSEvaluator{
		amount: big.NewInt(10),
		unit:   "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
	})

	chainID := "137"
	rule := &types.Rule{
		ID:         types.RuleID("rule-unk"),
		TemplateID: ptrString("tmpl-unk"),
		ChainID:    &chainID,
	}

	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{ID: "req"}, &types.ParsedPayload{})
	require.NoError(t, err)
	assert.True(t, ok)

	require.Len(t, budgetRepo.created, 1)
	created := budgetRepo.created[0]
	assert.Equal(t, "137:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", created.Unit)
	assert.Equal(t, "999", created.MaxTotal)
	assert.Equal(t, 50, created.MaxTxCount)
}

// TestBudgetChecker_DynamicBudget_NoConfig_FailsClosed tests that when no known_units or
// unknown_default is configured, a dynamic unit fails closed.
func TestBudgetChecker_DynamicBudget_NoConfig_FailsClosed(t *testing.T) {
	budgetRepo := newDynamicBudgetRepo()
	metering := types.BudgetMetering{
		Method:  "js",
		Dynamic: true,
		// No KnownUnits, no UnknownDefault
	}
	meteringJSON, _ := json.Marshal(metering)
	tmplRepo := &mockTemplateRepoForBudget{
		tmpl: &types.RuleTemplate{ID: "tmpl-noconf", BudgetMetering: meteringJSON},
	}

	bc := NewBudgetChecker(budgetRepo, tmplRepo, slog.Default())
	bc.SetJSEvaluator(&stubJSEvaluator{
		amount: big.NewInt(1),
		unit:   "someToken",
	})

	chainID := "1"
	rule := &types.Rule{
		ID:         types.RuleID("rule-noconf"),
		TemplateID: ptrString("tmpl-noconf"),
		ChainID:    &chainID,
	}

	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{ID: "req"}, &types.ParsedPayload{})
	require.Error(t, err, "should fail-closed with no config for dynamic unit")
	assert.False(t, ok)
	assert.Contains(t, err.Error(), "no budget config for dynamic unit")
}

// TestBudgetChecker_DynamicBudget_UnitDecimalConversion tests that unit_decimal mode
// converts human-readable limits to raw big integers.
func TestBudgetChecker_DynamicBudget_UnitDecimalConversion(t *testing.T) {
	budgetRepo := newDynamicBudgetRepo()
	metering := types.BudgetMetering{
		Method:      "js",
		Dynamic:     true,
		UnitDecimal: true,
		KnownUnits: map[string]types.UnitConf{
			"usdc": {MaxTotal: "1000", MaxPerTx: "100", Decimals: 6},
		},
	}
	meteringJSON, _ := json.Marshal(metering)
	tmplRepo := &mockTemplateRepoForBudget{
		tmpl: &types.RuleTemplate{ID: "tmpl-dec", BudgetMetering: meteringJSON},
	}

	bc := NewBudgetChecker(budgetRepo, tmplRepo, slog.Default())
	bc.SetJSEvaluator(&stubJSEvaluator{
		amount: big.NewInt(500000), // 0.5 USDC in raw
		unit:   "usdc",
	})

	chainID := "1"
	rule := &types.Rule{
		ID:         types.RuleID("rule-dec"),
		TemplateID: ptrString("tmpl-dec"),
		ChainID:    &chainID,
	}

	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{ID: "req"}, &types.ParsedPayload{})
	require.NoError(t, err)
	assert.True(t, ok)

	require.Len(t, budgetRepo.created, 1)
	created := budgetRepo.created[0]
	// 1000 * 10^6 = 1000000000
	assert.Equal(t, "1000000000", created.MaxTotal)
	// 100 * 10^6 = 100000000
	assert.Equal(t, "100000000", created.MaxPerTx)
}

// TestBudgetChecker_DynamicBudget_BackwardCompatPlainBigInt tests that when JS returns
// a plain BigInt (no unit), the static unit is used as before.
func TestBudgetChecker_DynamicBudget_BackwardCompatPlainBigInt(t *testing.T) {
	budgetRepo := newDynamicBudgetRepo()
	// Pre-create budget for the static unit
	budgetRepo.state["rule-static:count"] = &types.RuleBudget{
		ID:        "budget-static",
		RuleID:    types.RuleID("rule-static"),
		Unit:      "count",
		MaxTotal:  "100",
		MaxPerTx:  "10",
		Spent:     "0",
		UpdatedAt: time.Now(),
	}

	metering := types.BudgetMetering{Method: "js", Unit: "count"}
	meteringJSON, _ := json.Marshal(metering)
	tmplRepo := &mockTemplateRepoForBudget{
		tmpl: &types.RuleTemplate{ID: "tmpl-static", BudgetMetering: meteringJSON},
	}

	bc := NewBudgetChecker(budgetRepo, tmplRepo, slog.Default())
	bc.SetJSEvaluator(&stubJSEvaluator{
		amount: big.NewInt(1),
		unit:   "", // empty unit = backward compat
	})

	rule := &types.Rule{
		ID:         types.RuleID("rule-static"),
		TemplateID: ptrString("tmpl-static"),
	}

	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{ID: "req"}, &types.ParsedPayload{})
	require.NoError(t, err)
	assert.True(t, ok)
	// No new budget created
	assert.Empty(t, budgetRepo.created, "should not auto-create budget for static unit")
}

// TestBudgetChecker_DynamicBudget_ConcurrentAutoCreate verifies that racing goroutines
// calling CheckAndDeductBudget for the same dynamic unit don't create duplicate budget
// records. This tests the CRITICAL-3 fix (CreateOrGet upsert pattern).
func TestBudgetChecker_DynamicBudget_ConcurrentAutoCreate(t *testing.T) {
	budgetRepo := newDynamicBudgetRepo()
	metering := types.BudgetMetering{
		Method:  "js",
		Dynamic: true,
		KnownUnits: map[string]types.UnitConf{
			"native": {MaxTotal: "1000000000000000000", MaxPerTx: "100000000000000000"},
		},
	}
	meteringJSON, _ := json.Marshal(metering)
	tmplRepo := &mockTemplateRepoForBudget{
		tmpl: &types.RuleTemplate{ID: "tmpl-race", BudgetMetering: meteringJSON},
	}

	bc := NewBudgetChecker(budgetRepo, tmplRepo, slog.Default())
	bc.SetJSEvaluator(&stubJSEvaluator{
		amount: big.NewInt(1000),
		unit:   "native",
	})

	chainID := "1"
	rule := &types.Rule{
		ID:         types.RuleID("rule-race"),
		TemplateID: ptrString("tmpl-race"),
		ChainID:    &chainID,
	}

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make([]error, goroutines)
	oks := make([]bool, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			ok, err := bc.CheckAndDeductBudget(context.Background(), rule,
				&types.SignRequest{ID: types.SignRequestID("req-" + string(rune('a'+idx)))},
				&types.ParsedPayload{})
			errs[idx] = err
			oks[idx] = ok
		}(i)
	}
	wg.Wait()

	// All goroutines should succeed (no errors, all ok)
	for i := 0; i < goroutines; i++ {
		assert.NoError(t, errs[i], "goroutine %d should not error", i)
		assert.True(t, oks[i], "goroutine %d should be allowed", i)
	}

	// CRITICAL: Only one budget record should exist in state (CreateOrGet dedup)
	budgetRepo.mu.Lock()
	stateCount := len(budgetRepo.state)
	budgetRepo.mu.Unlock()
	assert.Equal(t, 1, stateCount, "exactly one budget record should exist despite concurrent creation")

	// created may have 1 entry (only the first CreateOrGet creates; others get existing)
	budgetRepo.mu.Lock()
	createdCount := len(budgetRepo.created)
	budgetRepo.mu.Unlock()
	assert.Equal(t, 1, createdCount, "only one goroutine should have created the budget record")
}

// ─────────────────────────────────────────────────────────────────────────────
// DecimalsQuerier auto-query tests
// ─────────────────────────────────────────────────────────────────────────────

// mockDecimalsQuerier implements DecimalsQuerier for testing.
type mockDecimalsQuerier struct {
	mu       sync.Mutex
	results  map[string]int // key: chainID + ":" + address (lowercased)
	err      error
	callCount int
}

func newMockDecimalsQuerier() *mockDecimalsQuerier {
	return &mockDecimalsQuerier{results: make(map[string]int)}
}

func (m *mockDecimalsQuerier) QueryDecimals(ctx context.Context, chainID, address string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++
	if m.err != nil {
		return 0, m.err
	}
	key := strings.ToLower(chainID + ":" + address)
	if d, ok := m.results[key]; ok {
		return d, nil
	}
	return 0, fmt.Errorf("no decimals for %s", key)
}

// TestBudgetChecker_UnitDecimal_NamedUnit_SkipsConversion tests that named units like
// "sign_count", "tx_count" with decimals=0 skip decimal conversion entirely.
func TestBudgetChecker_UnitDecimal_NamedUnit_SkipsConversion(t *testing.T) {
	budgetRepo := newDynamicBudgetRepo()
	metering := types.BudgetMetering{
		Method:      "js",
		Dynamic:     true,
		UnitDecimal: true,
		KnownUnits: map[string]types.UnitConf{
			"sign_count": {MaxTotal: "100", MaxPerTx: "10"},
			// decimals=0 (zero value) + named unit → should skip conversion
		},
	}
	meteringJSON, _ := json.Marshal(metering)
	tmplRepo := &mockTemplateRepoForBudget{
		tmpl: &types.RuleTemplate{ID: "tmpl-named", BudgetMetering: meteringJSON},
	}

	bc := NewBudgetChecker(budgetRepo, tmplRepo, slog.Default())
	bc.SetJSEvaluator(&stubJSEvaluator{
		amount: big.NewInt(1),
		unit:   "sign_count",
	})

	chainID := "1"
	rule := &types.Rule{
		ID:         types.RuleID("rule-named"),
		TemplateID: ptrString("tmpl-named"),
		ChainID:    &chainID,
	}

	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{ID: "req"}, &types.ParsedPayload{})
	require.NoError(t, err)
	assert.True(t, ok, "named unit with decimals=0 should pass without conversion")

	require.Len(t, budgetRepo.created, 1)
	created := budgetRepo.created[0]
	// MaxTotal should remain "100" (no decimal conversion applied)
	assert.Equal(t, "100", created.MaxTotal, "named unit should not have decimal conversion")
	assert.Equal(t, "10", created.MaxPerTx, "named unit should not have decimal conversion")
}

// TestBudgetChecker_UnitDecimal_AddressUnit_AutoQueryDecimals tests that address-like
// units with decimals=0 auto-query erc20.decimals() via RPC.
func TestBudgetChecker_UnitDecimal_AddressUnit_AutoQueryDecimals(t *testing.T) {
	budgetRepo := newDynamicBudgetRepo()
	metering := types.BudgetMetering{
		Method:      "js",
		Dynamic:     true,
		UnitDecimal: true,
		UnknownDefault: &types.UnitConf{
			MaxTotal: "1000",
			MaxPerTx: "100",
			// decimals=0 → auto-query
		},
	}
	meteringJSON, _ := json.Marshal(metering)
	tmplRepo := &mockTemplateRepoForBudget{
		tmpl: &types.RuleTemplate{ID: "tmpl-autoq", BudgetMetering: meteringJSON},
	}

	querier := newMockDecimalsQuerier()
	querier.results["137:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"] = 6 // USDC = 6 decimals

	bc := NewBudgetChecker(budgetRepo, tmplRepo, slog.Default())
	bc.SetJSEvaluator(&stubJSEvaluator{
		amount: big.NewInt(500000), // 0.5 USDC raw
		unit:   "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
	})
	bc.SetDecimalsQuerier(querier)

	chainID := "137"
	rule := &types.Rule{
		ID:         types.RuleID("rule-autoq"),
		TemplateID: ptrString("tmpl-autoq"),
		ChainID:    &chainID,
	}

	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{ID: "req"}, &types.ParsedPayload{})
	require.NoError(t, err)
	assert.True(t, ok, "should allow spend within auto-queried budget")

	require.Len(t, budgetRepo.created, 1)
	created := budgetRepo.created[0]
	// 1000 * 10^6 = 1000000000
	assert.Equal(t, "1000000000", created.MaxTotal, "auto-queried decimals=6 should convert max_total")
	// 100 * 10^6 = 100000000
	assert.Equal(t, "100000000", created.MaxPerTx, "auto-queried decimals=6 should convert max_per_tx")

	// Verify RPC was called exactly once
	querier.mu.Lock()
	assert.Equal(t, 1, querier.callCount, "should query decimals exactly once")
	querier.mu.Unlock()
}

// TestBudgetChecker_UnitDecimal_AddressUnit_AutoQuery_RPCFails_FailsClosed tests that
// when RPC is unavailable for decimals auto-query, it fails closed.
func TestBudgetChecker_UnitDecimal_AddressUnit_AutoQuery_RPCFails_FailsClosed(t *testing.T) {
	budgetRepo := newDynamicBudgetRepo()
	metering := types.BudgetMetering{
		Method:      "js",
		Dynamic:     true,
		UnitDecimal: true,
		UnknownDefault: &types.UnitConf{
			MaxTotal: "1000",
			MaxPerTx: "100",
		},
	}
	meteringJSON, _ := json.Marshal(metering)
	tmplRepo := &mockTemplateRepoForBudget{
		tmpl: &types.RuleTemplate{ID: "tmpl-rpcfail", BudgetMetering: meteringJSON},
	}

	querier := newMockDecimalsQuerier()
	querier.err = fmt.Errorf("rpc timeout")

	bc := NewBudgetChecker(budgetRepo, tmplRepo, slog.Default())
	bc.SetJSEvaluator(&stubJSEvaluator{
		amount: big.NewInt(1),
		unit:   "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
	})
	bc.SetDecimalsQuerier(querier)

	chainID := "137"
	rule := &types.Rule{
		ID:         types.RuleID("rule-rpcfail"),
		TemplateID: ptrString("tmpl-rpcfail"),
		ChainID:    &chainID,
	}

	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{ID: "req"}, &types.ParsedPayload{})
	// RPC timeout (not a revert) → fail-closed
	require.Error(t, err, "should fail-closed when RPC is unavailable (not a revert)")
	assert.False(t, ok)
	assert.Contains(t, err.Error(), "auto-query failed")
}

// TestBudgetChecker_UnitDecimal_AddressUnit_NoQuerier_FailsClosed tests that when
// no DecimalsQuerier is set, address units with decimals=0 fail closed.
func TestBudgetChecker_UnitDecimal_AddressUnit_NoQuerier_FailsClosed(t *testing.T) {
	budgetRepo := newDynamicBudgetRepo()
	metering := types.BudgetMetering{
		Method:      "js",
		Dynamic:     true,
		UnitDecimal: true,
		UnknownDefault: &types.UnitConf{
			MaxTotal: "1000",
			MaxPerTx: "100",
		},
	}
	meteringJSON, _ := json.Marshal(metering)
	tmplRepo := &mockTemplateRepoForBudget{
		tmpl: &types.RuleTemplate{ID: "tmpl-noq", BudgetMetering: meteringJSON},
	}

	bc := NewBudgetChecker(budgetRepo, tmplRepo, slog.Default())
	bc.SetJSEvaluator(&stubJSEvaluator{
		amount: big.NewInt(1),
		unit:   "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
	})
	// No SetDecimalsQuerier called

	chainID := "1"
	rule := &types.Rule{
		ID:         types.RuleID("rule-noq"),
		TemplateID: ptrString("tmpl-noq"),
		ChainID:    &chainID,
	}

	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{ID: "req"}, &types.ParsedPayload{})
	require.Error(t, err, "should fail-closed without decimals querier")
	assert.False(t, ok)
	assert.Contains(t, err.Error(), "decimals querier not configured")
}

// TestBudgetChecker_UnitDecimal_ExplicitDecimals_StillWorks tests that explicit
// decimals > 0 in config still works (existing behavior not broken).
func TestBudgetChecker_UnitDecimal_ExplicitDecimals_StillWorks(t *testing.T) {
	budgetRepo := newDynamicBudgetRepo()
	metering := types.BudgetMetering{
		Method:      "js",
		Dynamic:     true,
		UnitDecimal: true,
		KnownUnits: map[string]types.UnitConf{
			"native": {MaxTotal: "1", MaxPerTx: "0.1", Decimals: 18},
		},
	}
	meteringJSON, _ := json.Marshal(metering)
	tmplRepo := &mockTemplateRepoForBudget{
		tmpl: &types.RuleTemplate{ID: "tmpl-explicit", BudgetMetering: meteringJSON},
	}

	bc := NewBudgetChecker(budgetRepo, tmplRepo, slog.Default())
	bc.SetJSEvaluator(&stubJSEvaluator{
		amount: big.NewInt(50000000000000000), // 0.05 ETH
		unit:   "native",
	})

	chainID := "1"
	rule := &types.Rule{
		ID:         types.RuleID("rule-explicit"),
		TemplateID: ptrString("tmpl-explicit"),
		ChainID:    &chainID,
	}

	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{ID: "req"}, &types.ParsedPayload{})
	require.NoError(t, err)
	assert.True(t, ok)

	require.Len(t, budgetRepo.created, 1)
	created := budgetRepo.created[0]
	// 1 * 10^18 = 1000000000000000000
	assert.Equal(t, "1000000000000000000", created.MaxTotal)
	// 0.1 * 10^18 = 100000000000000000
	assert.Equal(t, "100000000000000000", created.MaxPerTx)
}

// TestBudgetChecker_UnitDecimal_AddressWithSuffix_AutoQuery tests that address units
// with a :suffix (e.g. "0xABC:approve") correctly extract the base address for auto-query.
func TestBudgetChecker_UnitDecimal_AddressWithSuffix_AutoQuery(t *testing.T) {
	budgetRepo := newDynamicBudgetRepo()
	metering := types.BudgetMetering{
		Method:      "js",
		Dynamic:     true,
		UnitDecimal: true,
		UnknownDefault: &types.UnitConf{
			MaxTotal: "500",
			MaxPerTx: "50",
		},
	}
	meteringJSON, _ := json.Marshal(metering)
	tmplRepo := &mockTemplateRepoForBudget{
		tmpl: &types.RuleTemplate{ID: "tmpl-suffix", BudgetMetering: meteringJSON},
	}

	querier := newMockDecimalsQuerier()
	querier.results["1:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"] = 6

	bc := NewBudgetChecker(budgetRepo, tmplRepo, slog.Default())
	bc.SetJSEvaluator(&stubJSEvaluator{
		amount: big.NewInt(1000000), // 1 USDC raw
		unit:   "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48:approve",
	})
	bc.SetDecimalsQuerier(querier)

	chainID := "1"
	rule := &types.Rule{
		ID:         types.RuleID("rule-suffix"),
		TemplateID: ptrString("tmpl-suffix"),
		ChainID:    &chainID,
	}

	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{ID: "req"}, &types.ParsedPayload{})
	require.NoError(t, err)
	assert.True(t, ok)

	require.Len(t, budgetRepo.created, 1)
	created := budgetRepo.created[0]
	// 500 * 10^6 = 500000000
	assert.Equal(t, "500000000", created.MaxTotal)
	// 50 * 10^6 = 50000000
	assert.Equal(t, "50000000", created.MaxPerTx)
}

// TestBudgetChecker_UnitDecimal_CachesDecimalsQuery tests that the decimals auto-query
// result is cached and not re-queried on subsequent calls.
func TestBudgetChecker_UnitDecimal_CachesDecimalsQuery(t *testing.T) {
	querier := newMockDecimalsQuerier()
	querier.results["1:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"] = 6

	bc := NewBudgetChecker(nil, nil, slog.Default())
	bc.SetDecimalsQuerier(querier)

	ctx := context.Background()
	// First call — should hit RPC
	d1, err := bc.queryDecimalsCached(ctx, "1", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	require.NoError(t, err)
	assert.Equal(t, 6, d1)

	// Second call — should hit cache
	d2, err := bc.queryDecimalsCached(ctx, "1", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	require.NoError(t, err)
	assert.Equal(t, 6, d2)

	// Verify only one RPC call was made
	querier.mu.Lock()
	assert.Equal(t, 1, querier.callCount, "decimals should be cached after first query")
	querier.mu.Unlock()
}

// TestExtractUnitBase tests the extractUnitBase helper.
func TestExtractUnitBase(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},
		{"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48:approve", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},
		{"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48:nft", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},
		{"native", "native"},
		{"tx_count", "tx_count"},
		{"sign_count", "sign_count"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := extractUnitBase(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// SubstituteMeteringJSON tests
// ─────────────────────────────────────────────────────────────────────────────

// TestSubstituteMeteringJSON_SubstitutesKnownUnits verifies that ${var} in
// KnownUnits and UnknownDefault are replaced with bound variable values.
func TestSubstituteMeteringJSON_SubstitutesKnownUnits(t *testing.T) {
	metering := types.BudgetMetering{
		Method:      "js",
		Dynamic:     true,
		UnitDecimal: true,
		KnownUnits: map[string]types.UnitConf{
			"native": {MaxTotal: "${max_native_total}", MaxPerTx: "${max_native_per_tx}", Decimals: 18},
			"tx_count": {MaxTotal: "${max_tx_count}", MaxPerTx: "1", Decimals: 0},
		},
		UnknownDefault: &types.UnitConf{
			MaxTotal: "${max_unknown_token_total}",
			MaxPerTx: "${max_unknown_token_per_tx}",
		},
	}
	meteringJSON, err := json.Marshal(metering)
	require.NoError(t, err)

	variables := map[string]interface{}{
		"max_native_total":         "0.01",
		"max_native_per_tx":        "0.005",
		"max_tx_count":             "100",
		"max_unknown_token_total":  "500",
		"max_unknown_token_per_tx": "50",
	}
	variablesJSON, err := json.Marshal(variables)
	require.NoError(t, err)

	result := SubstituteMeteringJSON(meteringJSON, variablesJSON)

	var resolved types.BudgetMetering
	require.NoError(t, json.Unmarshal(result, &resolved))

	// KnownUnits
	assert.Equal(t, "0.01", resolved.KnownUnits["native"].MaxTotal)
	assert.Equal(t, "0.005", resolved.KnownUnits["native"].MaxPerTx)
	assert.Equal(t, 18, resolved.KnownUnits["native"].Decimals)
	assert.Equal(t, "100", resolved.KnownUnits["tx_count"].MaxTotal)
	assert.Equal(t, "1", resolved.KnownUnits["tx_count"].MaxPerTx)

	// UnknownDefault
	assert.Equal(t, "500", resolved.UnknownDefault.MaxTotal)
	assert.Equal(t, "50", resolved.UnknownDefault.MaxPerTx)

	// Other fields preserved
	assert.True(t, resolved.Dynamic)
	assert.True(t, resolved.UnitDecimal)
	assert.Equal(t, "js", resolved.Method)
}

// TestSubstituteMeteringJSON_NoVariables returns original when no variables.
func TestSubstituteMeteringJSON_NoVariables(t *testing.T) {
	metering := types.BudgetMetering{
		Method: "count_only",
		Unit:   "count",
	}
	meteringJSON, _ := json.Marshal(metering)

	result := SubstituteMeteringJSON(meteringJSON, nil)
	assert.Equal(t, meteringJSON, result)

	result2 := SubstituteMeteringJSON(meteringJSON, []byte(`{}`))
	assert.Equal(t, meteringJSON, result2)
}

// TestSubstituteMeteringJSON_IntFields verifies that int fields like max_tx_count
// are correctly unquoted after substitution.
func TestSubstituteMeteringJSON_IntFields(t *testing.T) {
	// Simulate what the template YAML produces: max_tx_count as a string "${var}"
	raw := `{"method":"js","dynamic":true,"unknown_default":{"max_total":"${max_total}","max_per_tx":"${max_per_tx}","max_tx_count":"${max_tx_count}","decimals":"${decimals}"}}`
	variables := map[string]interface{}{
		"max_total":    "1000",
		"max_per_tx":   "100",
		"max_tx_count": "50",
		"decimals":     "6",
	}
	variablesJSON, _ := json.Marshal(variables)

	result := SubstituteMeteringJSON([]byte(raw), variablesJSON)

	var resolved types.BudgetMetering
	require.NoError(t, json.Unmarshal(result, &resolved), "should unmarshal after int field unquoting; got: %s", string(result))

	assert.Equal(t, "1000", resolved.UnknownDefault.MaxTotal)
	assert.Equal(t, "100", resolved.UnknownDefault.MaxPerTx)
	assert.Equal(t, 50, resolved.UnknownDefault.MaxTxCount)
	assert.Equal(t, 6, resolved.UnknownDefault.Decimals)
}

// TestSubstituteMeteringJSON_PartialSubstitution leaves non-matching ${var} as-is.
func TestSubstituteMeteringJSON_PartialSubstitution(t *testing.T) {
	metering := types.BudgetMetering{
		Method:  "js",
		Dynamic: true,
		KnownUnits: map[string]types.UnitConf{
			"native": {MaxTotal: "${max_native_total}", MaxPerTx: "0.1", Decimals: 18},
		},
	}
	meteringJSON, _ := json.Marshal(metering)

	// Only provide one variable; the other stays as ${var}
	variables := map[string]interface{}{
		"max_native_total": "5",
	}
	variablesJSON, _ := json.Marshal(variables)

	result := SubstituteMeteringJSON(meteringJSON, variablesJSON)

	var resolved types.BudgetMetering
	require.NoError(t, json.Unmarshal(result, &resolved))

	assert.Equal(t, "5", resolved.KnownUnits["native"].MaxTotal)
	assert.Equal(t, "0.1", resolved.KnownUnits["native"].MaxPerTx)
}

// TestBudgetChecker_DynamicBudget_TemplateVariablesInKnownUnits tests that when
// the template has ${var} placeholders in KnownUnits, the budget checker resolves
// them from rule.Variables at runtime and uses the resolved values.
func TestBudgetChecker_DynamicBudget_TemplateVariablesInKnownUnits(t *testing.T) {
	budgetRepo := newDynamicBudgetRepo()

	// Template has ${var} placeholders — like the agent template after this change
	metering := types.BudgetMetering{
		Method:      "js",
		Dynamic:     true,
		UnitDecimal: true,
		KnownUnits: map[string]types.UnitConf{
			"native":     {MaxTotal: "${max_native_total}", MaxPerTx: "${max_native_per_tx}", Decimals: 18},
			"sign_count": {MaxTotal: "${max_sign_count}", MaxPerTx: "1", Decimals: 0},
		},
	}
	meteringJSON, _ := json.Marshal(metering)
	tmplRepo := &mockTemplateRepoForBudget{
		tmpl: &types.RuleTemplate{ID: "tmpl-var", BudgetMetering: meteringJSON},
	}

	bc := NewBudgetChecker(budgetRepo, tmplRepo, slog.Default())
	bc.SetJSEvaluator(&stubJSEvaluator{
		amount: big.NewInt(1),
		unit:   "sign_count",
	})

	// Instance variables resolve the template placeholders
	instanceVars := map[string]interface{}{
		"max_native_total":  "0.01",
		"max_native_per_tx": "0.005",
		"max_sign_count":    "3", // Override from preset --set max_sign_count=3
	}
	instanceVarsJSON, _ := json.Marshal(instanceVars)

	chainID := "1"
	rule := &types.Rule{
		ID:         types.RuleID("rule-var"),
		TemplateID: ptrString("tmpl-var"),
		ChainID:    &chainID,
		Variables:  instanceVarsJSON,
	}

	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{ID: "req"}, &types.ParsedPayload{})
	require.NoError(t, err)
	assert.True(t, ok, "should allow spend within variable-resolved budget")

	// Verify budget was auto-created with resolved values (not template ${var})
	require.Len(t, budgetRepo.created, 1)
	created := budgetRepo.created[0]
	assert.Equal(t, "1:sign_count", created.Unit)
	// sign_count has decimals=0, so max_total stays as-is (no decimal conversion for named units)
	assert.Equal(t, "3", created.MaxTotal, "should use instance variable value, not template default")
	assert.Equal(t, "1", created.MaxPerTx)
}

// TestBudgetChecker_DynamicBudget_TemplateDefaultsUsedWhenNoOverride tests that
// template variable defaults are used when instance variables don't include overrides.
func TestBudgetChecker_DynamicBudget_TemplateDefaultsUsedWhenNoOverride(t *testing.T) {
	budgetRepo := newDynamicBudgetRepo()

	metering := types.BudgetMetering{
		Method:      "js",
		Dynamic:     true,
		UnitDecimal: true,
		KnownUnits: map[string]types.UnitConf{
			"sign_count": {MaxTotal: "${max_sign_count}", MaxPerTx: "1", Decimals: 0},
		},
	}
	meteringJSON, _ := json.Marshal(metering)
	tmplRepo := &mockTemplateRepoForBudget{
		tmpl: &types.RuleTemplate{ID: "tmpl-default", BudgetMetering: meteringJSON},
	}

	bc := NewBudgetChecker(budgetRepo, tmplRepo, slog.Default())
	bc.SetJSEvaluator(&stubJSEvaluator{
		amount: big.NewInt(1),
		unit:   "sign_count",
	})

	// Instance variables have the default from template (filled by fillOptionalTemplateVariables)
	instanceVars := map[string]interface{}{
		"max_sign_count": "500", // Template default
	}
	instanceVarsJSON, _ := json.Marshal(instanceVars)

	chainID := "1"
	rule := &types.Rule{
		ID:         types.RuleID("rule-default"),
		TemplateID: ptrString("tmpl-default"),
		ChainID:    &chainID,
		Variables:  instanceVarsJSON,
	}

	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{ID: "req"}, &types.ParsedPayload{})
	require.NoError(t, err)
	assert.True(t, ok)

	require.Len(t, budgetRepo.created, 1)
	created := budgetRepo.created[0]
	assert.Equal(t, "500", created.MaxTotal, "should use template default value")
}

// TestBudgetChecker_DynamicBudget_InstanceOverridesNativeTotal tests that when an
// instance overrides max_native_total, the runtime budget uses the overridden value
// (not the template default), and budget enforcement works correctly.
func TestBudgetChecker_DynamicBudget_InstanceOverridesNativeTotal(t *testing.T) {
	budgetRepo := newDynamicBudgetRepo()

	metering := types.BudgetMetering{
		Method:      "js",
		Dynamic:     true,
		UnitDecimal: true,
		KnownUnits: map[string]types.UnitConf{
			"native": {MaxTotal: "${max_native_total}", MaxPerTx: "${max_native_per_tx}", Decimals: 18},
		},
	}
	meteringJSON, _ := json.Marshal(metering)
	tmplRepo := &mockTemplateRepoForBudget{
		tmpl: &types.RuleTemplate{ID: "tmpl-override", BudgetMetering: meteringJSON},
	}

	// 0.004 ETH in wei
	bc := NewBudgetChecker(budgetRepo, tmplRepo, slog.Default())
	bc.SetJSEvaluator(&stubJSEvaluator{
		amount: big.NewInt(4000000000000000), // 0.004 ETH
		unit:   "native",
	})

	// Instance overrides: max_native_total=0.005 (not default 1)
	instanceVars := map[string]interface{}{
		"max_native_total":  "0.005",
		"max_native_per_tx": "0.01",
	}
	instanceVarsJSON, _ := json.Marshal(instanceVars)

	chainID := "1"
	rule := &types.Rule{
		ID:         types.RuleID("rule-override"),
		TemplateID: ptrString("tmpl-override"),
		ChainID:    &chainID,
		Variables:  instanceVarsJSON,
	}

	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{ID: "req"}, &types.ParsedPayload{})
	require.NoError(t, err)
	assert.True(t, ok, "first spend 0.004 should be within 0.005 budget")

	// Verify max_total is 0.005 * 10^18 = 5000000000000000
	require.Len(t, budgetRepo.created, 1)
	created := budgetRepo.created[0]
	assert.Equal(t, "5000000000000000", created.MaxTotal, "should use overridden value 0.005 ETH")

	// Second spend: 0.002 ETH would push total to 0.006 > 0.005 — should be rejected
	bc.SetJSEvaluator(&stubJSEvaluator{
		amount: big.NewInt(2000000000000000), // 0.002 ETH
		unit:   "native",
	})

	ok2, err2 := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{ID: "req2"}, &types.ParsedPayload{})
	require.NoError(t, err2)
	assert.False(t, ok2, "second spend should exceed budget (0.004+0.002 > 0.005)")
}

// TestSubstituteMeteringJSON_UnresolvedVariable leaves ${unknown} in the string.
// The budget checker will see the literal "${unknown}" as max_total, which will fail
// when trying to parse it as a number — this is correct fail-closed behavior.
func TestSubstituteMeteringJSON_UnresolvedVariable(t *testing.T) {
	metering := types.BudgetMetering{
		Method:  "js",
		Dynamic: true,
		KnownUnits: map[string]types.UnitConf{
			"native": {MaxTotal: "${nonexistent_var}", MaxPerTx: "0.1", Decimals: 18},
		},
	}
	meteringJSON, _ := json.Marshal(metering)

	// Variables don't contain "nonexistent_var"
	variables := map[string]interface{}{
		"some_other_var": "42",
	}
	variablesJSON, _ := json.Marshal(variables)

	result := SubstituteMeteringJSON(meteringJSON, variablesJSON)

	var resolved types.BudgetMetering
	require.NoError(t, json.Unmarshal(result, &resolved))

	// The unresolved ${nonexistent_var} stays as-is — will fail at budget enforcement
	assert.Equal(t, "${nonexistent_var}", resolved.KnownUnits["native"].MaxTotal,
		"unresolved variable should remain as literal string")
}

// TestBudgetChecker_DynamicBudget_UnresolvedMaxTotal_FailsClosed tests that when
// a template variable is unresolved (stays as "${var}"), the budget enforcement
// fails closed because "${var}" cannot be parsed as a number.
func TestBudgetChecker_DynamicBudget_UnresolvedMaxTotal_FailsClosed(t *testing.T) {
	budgetRepo := newDynamicBudgetRepo()

	metering := types.BudgetMetering{
		Method:      "js",
		Dynamic:     true,
		UnitDecimal: true,
		KnownUnits: map[string]types.UnitConf{
			"native": {MaxTotal: "${max_native_total}", MaxPerTx: "0.1", Decimals: 18},
		},
	}
	meteringJSON, _ := json.Marshal(metering)
	tmplRepo := &mockTemplateRepoForBudget{
		tmpl: &types.RuleTemplate{ID: "tmpl-unresolved", BudgetMetering: meteringJSON},
	}

	bc := NewBudgetChecker(budgetRepo, tmplRepo, slog.Default())
	bc.SetJSEvaluator(&stubJSEvaluator{
		amount: big.NewInt(1000),
		unit:   "native",
	})

	// No variables set — ${max_native_total} stays unresolved
	chainID := "1"
	rule := &types.Rule{
		ID:         types.RuleID("rule-unresolved"),
		TemplateID: ptrString("tmpl-unresolved"),
		ChainID:    &chainID,
		Variables:  nil, // No variables
	}

	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{ID: "req"}, &types.ParsedPayload{})
	require.Error(t, err, "should fail when max_total contains unresolved ${var}")
	assert.False(t, ok)
	// The error comes from decimalToRaw trying to parse "${max_native_total}"
}

// TestSubstituteMeteringJSON_EmptyJSON handles edge cases.
func TestSubstituteMeteringJSON_EmptyJSON(t *testing.T) {
	result := SubstituteMeteringJSON(nil, []byte(`{"x":"1"}`))
	assert.Nil(t, result)

	result2 := SubstituteMeteringJSON([]byte(`{}`), nil)
	assert.Equal(t, []byte(`{}`), result2)
}

// TestUnquoteIntFields verifies the JSON int field unquoting helper.
func TestUnquoteIntFields(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		fields []string
		want   string
	}{
		{
			"unquote max_tx_count",
			`{"max_tx_count":"50","max_total":"1000"}`,
			[]string{"max_tx_count"},
			`{"max_tx_count":50,"max_total":"1000"}`,
		},
		{
			"unquote multiple fields",
			`{"max_tx_count":"50","decimals":"18"}`,
			[]string{"max_tx_count", "decimals"},
			`{"max_tx_count":50,"decimals":18}`,
		},
		{
			"leave non-numeric string",
			`{"max_tx_count":"abc","decimals":"18"}`,
			[]string{"max_tx_count", "decimals"},
			`{"max_tx_count":"abc","decimals":18}`,
		},
		{
			"already numeric (no quotes around value)",
			`{"max_tx_count":50}`,
			[]string{"max_tx_count"},
			`{"max_tx_count":50}`,
		},
		{
			"negative integer",
			`{"max_tx_count":"-1"}`,
			[]string{"max_tx_count"},
			`{"max_tx_count":-1}`,
		},
		{
			"space after colon (YAML-to-JSON format)",
			`{"max_tx_count": "50", "decimals": 18}`,
			[]string{"max_tx_count"},
			`{"max_tx_count": 50, "decimals": 18}`,
		},
		{
			"space after colon nested",
			`{"unknown_default": {"max_total": "1000", "max_tx_count": "50"}}`,
			[]string{"max_tx_count"},
			`{"unknown_default": {"max_total": "1000", "max_tx_count": 50}}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := unquoteIntFields(tc.input, tc.fields)
			assert.Equal(t, tc.want, got)
		})
	}
}
