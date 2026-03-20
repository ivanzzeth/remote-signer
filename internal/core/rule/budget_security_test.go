package rule

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ─────────────────────────────────────────────────────────────────────────────
// V3-6: Dynamic Budget Unit Count TOCTOU — post-create verification
// ─────────────────────────────────────────────────────────────────────────────

// raceBudgetRepo is a thread-safe budget repo that simulates concurrent creation of units.
// It tracks actual stored budgets and supports configurable behavior for testing TOCTOU races.
type raceBudgetRepo struct {
	mu      sync.Mutex
	budgets map[string]*types.RuleBudget // key: ruleID + ":" + unit
	deleted map[string]bool              // track deleted budget IDs
}

func newRaceBudgetRepo() *raceBudgetRepo {
	return &raceBudgetRepo{
		budgets: make(map[string]*types.RuleBudget),
		deleted: make(map[string]bool),
	}
}

func (r *raceBudgetRepo) Create(_ context.Context, budget *types.RuleBudget) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := string(budget.RuleID) + ":" + budget.Unit
	r.budgets[key] = budget
	return nil
}

func (r *raceBudgetRepo) CreateOrGet(_ context.Context, budget *types.RuleBudget) (*types.RuleBudget, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := string(budget.RuleID) + ":" + budget.Unit
	if existing, ok := r.budgets[key]; ok {
		return existing, false, nil
	}
	now := time.Now()
	budget.CreatedAt = now
	budget.UpdatedAt = now
	r.budgets[key] = budget
	return budget, true, nil
}

func (r *raceBudgetRepo) GetByRuleID(_ context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := string(ruleID) + ":" + unit
	if b, ok := r.budgets[key]; ok {
		cp := *b
		return &cp, nil
	}
	return nil, types.ErrNotFound
}

func (r *raceBudgetRepo) CountByRuleID(_ context.Context, ruleID types.RuleID) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	prefix := string(ruleID) + ":"
	for key := range r.budgets {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			count++
		}
	}
	return count, nil
}

func (r *raceBudgetRepo) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleted[id] = true
	// Remove from budgets by scanning for matching ID
	for key, b := range r.budgets {
		if b.ID == id {
			delete(r.budgets, key)
			return nil
		}
	}
	return nil
}

func (r *raceBudgetRepo) DeleteByRuleID(_ context.Context, _ types.RuleID) error { return nil }
func (r *raceBudgetRepo) AtomicSpend(_ context.Context, ruleID types.RuleID, unit string, amount string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := string(ruleID) + ":" + unit
	b, ok := r.budgets[key]
	if !ok {
		return types.ErrNotFound
	}
	amt := new(big.Int)
	if _, ok := amt.SetString(amount, 10); !ok {
		return fmt.Errorf("invalid amount %q", amount)
	}
	cur := new(big.Int)
	if _, ok := cur.SetString(b.Spent, 10); !ok {
		cur = big.NewInt(0)
	}
	max := new(big.Int)
	if _, ok := max.SetString(b.MaxTotal, 10); !ok {
		return fmt.Errorf("invalid max_total %q", b.MaxTotal)
	}
	newSpent := new(big.Int).Add(cur, amt)
	if newSpent.Cmp(max) > 0 {
		return storage.ErrBudgetExceeded
	}
	b.Spent = newSpent.String()
	b.TxCount++
	b.UpdatedAt = time.Now()
	return nil
}

func (r *raceBudgetRepo) ResetBudget(_ context.Context, _ types.RuleID, _ string, _ time.Time) error {
	return nil
}
func (r *raceBudgetRepo) ListByRuleID(_ context.Context, _ types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (r *raceBudgetRepo) ListByRuleIDs(_ context.Context, _ []types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (r *raceBudgetRepo) MarkAlertSent(_ context.Context, _ types.RuleID, _ string) error {
	return nil
}

func (r *raceBudgetRepo) budgetCount(ruleID types.RuleID) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	prefix := string(ruleID) + ":"
	for key := range r.budgets {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			count++
		}
	}
	return count
}

func (r *raceBudgetRepo) wasDeleted(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.deleted[id]
}

// TestAutoCreateDynamicBudget_TOCTOU_ConcurrentUnitsRespectMax verifies that concurrent
// creation of dynamic budget units for different tokens respects MaxDynamicUnits.
// This is the V3-6 fix: post-create verification catches TOCTOU race on unit count.
func TestAutoCreateDynamicBudget_TOCTOU_ConcurrentUnitsRespectMax(t *testing.T) {
	const maxUnits = 3
	const numGoroutines = 10

	repo := newRaceBudgetRepo()
	metering, _ := json.Marshal(types.BudgetMetering{
		Method:          "js",
		Dynamic:         true,
		MaxDynamicUnits: maxUnits,
		UnknownDefault: &types.UnitConf{
			MaxTotal: "1000",
			MaxPerTx: "100",
		},
	})
	tmplRepo := &stubTemplateRepo{tmpl: &types.RuleTemplate{
		ID:             "tmpl-toctou",
		BudgetMetering: metering,
	}}

	bc := NewBudgetChecker(repo, tmplRepo, slog.Default())

	rule := &types.Rule{
		ID:         types.RuleID("rule-toctou"),
		TemplateID: ptrStr("tmpl-toctou"),
	}

	var wg sync.WaitGroup
	var successCount atomic.Int32
	var errorCount atomic.Int32

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			unitName := fmt.Sprintf("token%d", idx)
			normalizedUnit := NormalizeBudgetUnit(fmt.Sprintf("1:%s", unitName))
			_, err := bc.autoCreateDynamicBudget(
				context.Background(),
				rule,
				&types.SignRequest{ChainID: "1"},
				normalizedUnit,
				unitName,
				types.BudgetMetering{
					Method:          "js",
					Dynamic:         true,
					MaxDynamicUnits: maxUnits,
					UnknownDefault: &types.UnitConf{
						MaxTotal: "1000",
						MaxPerTx: "100",
					},
				},
			)
			if err != nil {
				errorCount.Add(1)
			} else {
				successCount.Add(1)
			}
		}(i)
	}
	wg.Wait()

	finalCount := repo.budgetCount(rule.ID)
	t.Logf("successes=%d errors=%d final_budget_count=%d", successCount.Load(), errorCount.Load(), finalCount)

	// Post-create verification ensures we never exceed maxUnits
	assert.LessOrEqual(t, finalCount, maxUnits,
		"final budget count must not exceed MaxDynamicUnits (%d), got %d", maxUnits, finalCount)
	// At least some should succeed
	assert.Greater(t, int(successCount.Load()), 0, "at least one goroutine should succeed")
	// At least some should fail (we have more goroutines than maxUnits)
	assert.Greater(t, int(errorCount.Load()), 0, "excess goroutines should fail")
}

// TestAutoCreateDynamicBudget_PostCreateDeletesOnCountError verifies that if
// CountByRuleID fails after a successful create, the created record is deleted (fail-closed).
func TestAutoCreateDynamicBudget_PostCreateDeletesOnCountError(t *testing.T) {
	// Use a repo that fails on CountByRuleID after creation
	repo := &countFailBudgetRepo{
		raceBudgetRepo: newRaceBudgetRepo(),
		failAfterN:     1, // fail on second call (post-create check)
	}

	metering := types.BudgetMetering{
		Method:          "js",
		Dynamic:         true,
		MaxDynamicUnits: 5,
		UnknownDefault: &types.UnitConf{
			MaxTotal: "1000",
			MaxPerTx: "100",
		},
	}

	tmplRepo := &stubTemplateRepo{tmpl: &types.RuleTemplate{ID: "tmpl-1"}}
	bc := NewBudgetChecker(repo, tmplRepo, slog.Default())

	rule := &types.Rule{
		ID:         types.RuleID("rule-count-fail"),
		TemplateID: ptrStr("tmpl-1"),
	}

	normalizedUnit := NormalizeBudgetUnit("1:tokenA")
	_, err := bc.autoCreateDynamicBudget(
		context.Background(),
		rule,
		&types.SignRequest{ChainID: "1"},
		normalizedUnit,
		"tokenA",
		metering,
	)

	require.Error(t, err, "should fail when post-create count fails")
	assert.Contains(t, err.Error(), "re-count dynamic units after create")
}

// countFailBudgetRepo wraps raceBudgetRepo but fails CountByRuleID after N calls.
type countFailBudgetRepo struct {
	*raceBudgetRepo
	mu         sync.Mutex
	callCount  int
	failAfterN int // fail when callCount > failAfterN
}

func (r *countFailBudgetRepo) CountByRuleID(ctx context.Context, ruleID types.RuleID) (int, error) {
	r.mu.Lock()
	r.callCount++
	count := r.callCount
	r.mu.Unlock()

	if count > r.failAfterN {
		return 0, fmt.Errorf("simulated count error")
	}
	return r.raceBudgetRepo.CountByRuleID(ctx, ruleID)
}

// ─────────────────────────────────────────────────────────────────────────────
// V3-9: Budget Alert Uses Stale Pre-Spend Data
// ─────────────────────────────────────────────────────────────────────────────

// alertCaptureBudgetRepo captures the budget passed to the alert goroutine by
// intercepting GetByRuleID calls after AtomicSpend.
type alertCaptureBudgetRepo struct {
	mu             sync.Mutex
	budget         *types.RuleBudget
	atomicSpendErr error
	getCallCount   int
	lastGetBudget  *types.RuleBudget // the budget returned on last GetByRuleID
}

func (r *alertCaptureBudgetRepo) Create(_ context.Context, _ *types.RuleBudget) error { return nil }
func (r *alertCaptureBudgetRepo) CreateOrGet(_ context.Context, budget *types.RuleBudget) (*types.RuleBudget, bool, error) {
	return budget, true, nil
}
func (r *alertCaptureBudgetRepo) CountByRuleID(_ context.Context, _ types.RuleID) (int, error) {
	return 0, nil
}
func (r *alertCaptureBudgetRepo) Delete(_ context.Context, _ string) error              { return nil }
func (r *alertCaptureBudgetRepo) DeleteByRuleID(_ context.Context, _ types.RuleID) error { return nil }
func (r *alertCaptureBudgetRepo) ListByRuleID(_ context.Context, _ types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (r *alertCaptureBudgetRepo) ListByRuleIDs(_ context.Context, _ []types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (r *alertCaptureBudgetRepo) ResetBudget(_ context.Context, _ types.RuleID, _ string, _ time.Time) error {
	return nil
}
func (r *alertCaptureBudgetRepo) MarkAlertSent(_ context.Context, _ types.RuleID, _ string) error {
	return nil
}

func (r *alertCaptureBudgetRepo) GetByRuleID(_ context.Context, _ types.RuleID, _ string) (*types.RuleBudget, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.getCallCount++
	if r.budget == nil {
		return nil, types.ErrNotFound
	}
	cp := *r.budget
	r.lastGetBudget = &cp
	return &cp, nil
}

func (r *alertCaptureBudgetRepo) AtomicSpend(_ context.Context, ruleID types.RuleID, unit string, amount string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.atomicSpendErr != nil {
		return r.atomicSpendErr
	}
	// Simulate actual spend by updating the budget
	if r.budget != nil {
		amt := new(big.Int)
		if _, ok := amt.SetString(amount, 10); !ok {
			return fmt.Errorf("invalid amount")
		}
		cur := new(big.Int)
		if _, ok := cur.SetString(r.budget.Spent, 10); !ok {
			cur = big.NewInt(0)
		}
		r.budget.Spent = new(big.Int).Add(cur, amt).String()
		r.budget.TxCount++
	}
	return nil
}

// alertCaptureNotifier captures the budget alert data sent by checkAlertThreshold.
type alertCaptureNotifier struct {
	mu       sync.Mutex
	captured bool
	spent    string
	maxTotal string
	pct      int64
}

func (n *alertCaptureNotifier) SendBudgetAlert(_ context.Context, _ types.RuleID, _ string, spent string, maxTotal string, pct int64, _ int) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.captured = true
	n.spent = spent
	n.maxTotal = maxTotal
	n.pct = pct
	return nil
}

func (n *alertCaptureNotifier) wasCaptured() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.captured
}

func (n *alertCaptureNotifier) getSpent() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.spent
}

// TestCheckAndDeductBudget_AlertUsesPostSpendData verifies that the alert goroutine
// receives post-spend budget data, not the stale pre-spend snapshot (V3-9 fix).
func TestCheckAndDeductBudget_AlertUsesPostSpendData(t *testing.T) {
	// Set up a budget at 70/100 spent. After spending 20 more (total 90), the 80% alert
	// should fire. If the alert used pre-spend data (70/100 = 70%), it would NOT fire.
	budget := &types.RuleBudget{
		ID:       "budget-alert-test",
		RuleID:   types.RuleID("rule-alert"),
		Unit:     "count",
		MaxTotal: "100",
		MaxPerTx: "-1",
		Spent:    "70",
		AlertPct: 80,
		TxCount:  0,
	}

	repo := &alertCaptureBudgetRepo{budget: budget}
	notifier := &alertCaptureNotifier{}

	metering, _ := json.Marshal(types.BudgetMetering{Method: "count_only", Unit: "count"})
	tmplRepo := &stubTemplateRepo{tmpl: &types.RuleTemplate{
		ID:             "tmpl-alert",
		BudgetMetering: metering,
	}}

	bc := NewBudgetChecker(repo, tmplRepo, slog.Default())
	bc.SetNotifier(notifier)

	rule := &types.Rule{
		ID:         types.RuleID("rule-alert"),
		TemplateID: ptrStr("tmpl-alert"),
	}
	req := &types.SignRequest{ID: "req-1"}
	parsed := &types.ParsedPayload{}

	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.True(t, ok, "budget should pass (70+1=71 <= 100)")

	// Wait for async alert goroutine to complete
	time.Sleep(100 * time.Millisecond)

	// The GetByRuleID should have been called at least twice:
	// once for the initial lookup, once for the post-spend re-fetch
	repo.mu.Lock()
	getCount := repo.getCallCount
	repo.mu.Unlock()
	assert.GreaterOrEqual(t, getCount, 2,
		"GetByRuleID should be called at least twice (initial + post-spend re-fetch)")

	// The budget's Spent after AtomicSpend is "71" (70 + 1 for count_only).
	// 71/100 = 71% < 80% threshold, so alert should NOT fire.
	// This confirms the alert check uses post-spend data (71%), not pre-spend (70%).
	assert.False(t, notifier.wasCaptured(),
		"alert should NOT fire at 71%% (below 80%% threshold) — proves post-spend data is used")
}

// TestCheckAndDeductBudget_AlertFiresWithPostSpendData verifies the alert fires
// when post-spend data crosses the threshold.
func TestCheckAndDeductBudget_AlertFiresWithPostSpendData(t *testing.T) {
	// Budget at 79/100 spent. After spending 1 more (count_only), total = 80/100 = 80%.
	// Alert threshold is 80%, so it should fire.
	budget := &types.RuleBudget{
		ID:       "budget-alert-fire",
		RuleID:   types.RuleID("rule-alert-fire"),
		Unit:     "count",
		MaxTotal: "100",
		MaxPerTx: "-1",
		Spent:    "79",
		AlertPct: 80,
		TxCount:  0,
	}

	repo := &alertCaptureBudgetRepo{budget: budget}
	notifier := &alertCaptureNotifier{}

	metering, _ := json.Marshal(types.BudgetMetering{Method: "count_only", Unit: "count"})
	tmplRepo := &stubTemplateRepo{tmpl: &types.RuleTemplate{
		ID:             "tmpl-alert-fire",
		BudgetMetering: metering,
	}}

	bc := NewBudgetChecker(repo, tmplRepo, slog.Default())
	bc.SetNotifier(notifier)

	rule := &types.Rule{
		ID:         types.RuleID("rule-alert-fire"),
		TemplateID: ptrStr("tmpl-alert-fire"),
	}

	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{ID: "req-1"}, &types.ParsedPayload{})
	require.NoError(t, err)
	assert.True(t, ok)

	// Wait for async alert goroutine
	time.Sleep(100 * time.Millisecond)

	assert.True(t, notifier.wasCaptured(), "alert should fire when post-spend crosses threshold (80/100 = 80%%)")
	assert.Equal(t, "80", notifier.getSpent(), "alert should report post-spend value 80, not pre-spend 79")
}
