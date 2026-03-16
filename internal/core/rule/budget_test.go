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
		return existing, false, nil
	}
	m.created = append(m.created, budget)
	m.state[key] = budget
	return budget, true, nil
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
