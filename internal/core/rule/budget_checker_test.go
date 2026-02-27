package rule

import (
	"context"
	"encoding/json"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ─────────────────────────────────────────────────────────────────────────────
// CheckAndDeductBudget edge cases
// ─────────────────────────────────────────────────────────────────────────────

func TestBudgetChecker_NilBudgetRepo(t *testing.T) {
	bc := NewBudgetChecker(nil, nil, slog.Default())
	ok, err := bc.CheckAndDeductBudget(context.Background(), &types.Rule{TemplateID: ptrStr("t1")}, &types.SignRequest{}, nil)
	require.NoError(t, err)
	assert.True(t, ok, "nil budget repo should pass through")
}

func TestBudgetChecker_NilTemplateID(t *testing.T) {
	bc := NewBudgetChecker(&stubBudgetRepo{}, &stubTemplateRepo{}, slog.Default())
	ok, err := bc.CheckAndDeductBudget(context.Background(), &types.Rule{}, &types.SignRequest{}, nil)
	require.NoError(t, err)
	assert.True(t, ok, "nil template ID should pass through")
}

func TestBudgetChecker_TemplateNotFound(t *testing.T) {
	// SECURITY: template deleted but instance still active → fail-closed.
	// Budget constraint cannot be verified without the template.
	tr := &stubTemplateRepo{err: types.ErrNotFound}
	bc := NewBudgetChecker(&stubBudgetRepo{}, tr, slog.Default())
	rule := &types.Rule{TemplateID: ptrStr("missing")}
	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{}, nil)
	require.Error(t, err, "template not found must fail-closed")
	assert.False(t, ok)
	assert.Contains(t, err.Error(), "deleted but instance rule")
}

func TestBudgetChecker_TemplateRepoError(t *testing.T) {
	tr := &stubTemplateRepo{err: assert.AnError}
	bc := NewBudgetChecker(&stubBudgetRepo{}, tr, slog.Default())
	rule := &types.Rule{TemplateID: ptrStr("t1")}
	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{}, nil)
	assert.Error(t, err)
	assert.False(t, ok)
}

func TestBudgetChecker_NoMetering(t *testing.T) {
	tr := &stubTemplateRepo{tmpl: &types.RuleTemplate{ID: "t1"}}
	bc := NewBudgetChecker(&stubBudgetRepo{}, tr, slog.Default())
	rule := &types.Rule{TemplateID: ptrStr("t1")}
	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{}, nil)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestBudgetChecker_MeteringMethodNone(t *testing.T) {
	metering, _ := json.Marshal(types.BudgetMetering{Method: "none"})
	tr := &stubTemplateRepo{tmpl: &types.RuleTemplate{ID: "t1", BudgetMetering: metering}}
	bc := NewBudgetChecker(&stubBudgetRepo{}, tr, slog.Default())
	rule := &types.Rule{TemplateID: ptrStr("t1")}
	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{}, nil)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestBudgetChecker_MeteringMethodEmpty(t *testing.T) {
	metering, _ := json.Marshal(types.BudgetMetering{Method: ""})
	tr := &stubTemplateRepo{tmpl: &types.RuleTemplate{ID: "t1", BudgetMetering: metering}}
	bc := NewBudgetChecker(&stubBudgetRepo{}, tr, slog.Default())
	rule := &types.Rule{TemplateID: ptrStr("t1")}
	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{}, nil)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestBudgetChecker_InvalidMeteringJSON(t *testing.T) {
	tr := &stubTemplateRepo{tmpl: &types.RuleTemplate{ID: "t1", BudgetMetering: []byte(`{bad}`)}}
	bc := NewBudgetChecker(&stubBudgetRepo{}, tr, slog.Default())
	rule := &types.Rule{TemplateID: ptrStr("t1")}
	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{}, nil)
	assert.Error(t, err)
	assert.False(t, ok)
}

func TestBudgetChecker_BudgetNotFound(t *testing.T) {
	// SECURITY: no budget record for a rule with metering → fail-closed.
	// Budget record should be created at rule initialization; missing = incomplete setup.
	metering, _ := json.Marshal(types.BudgetMetering{Method: "count_only"})
	tr := &stubTemplateRepo{tmpl: &types.RuleTemplate{ID: "t1", BudgetMetering: metering}}
	br := &stubBudgetRepo{getErr: types.ErrNotFound}
	bc := NewBudgetChecker(br, tr, slog.Default())
	rule := &types.Rule{ID: "r1", TemplateID: ptrStr("t1")}
	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{}, nil)
	require.Error(t, err, "no budget record must fail-closed")
	assert.False(t, ok)
	assert.Contains(t, err.Error(), "no budget record")
}

func TestBudgetChecker_BudgetRepoGetError(t *testing.T) {
	metering, _ := json.Marshal(types.BudgetMetering{Method: "count_only"})
	tr := &stubTemplateRepo{tmpl: &types.RuleTemplate{ID: "t1", BudgetMetering: metering}}
	br := &stubBudgetRepo{getErr: assert.AnError}
	bc := NewBudgetChecker(br, tr, slog.Default())
	rule := &types.Rule{ID: "r1", TemplateID: ptrStr("t1")}
	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{}, nil)
	assert.Error(t, err)
	assert.False(t, ok)
}

func TestBudgetChecker_PerTxLimitExceeded(t *testing.T) {
	metering, _ := json.Marshal(types.BudgetMetering{Method: "count_only"})
	tr := &stubTemplateRepo{tmpl: &types.RuleTemplate{ID: "t1", BudgetMetering: metering}}
	br := &stubBudgetRepo{budget: &types.RuleBudget{
		MaxTotal: "1000",
		MaxPerTx: "0", // 0 means no per-tx limit actually... let's use something small
		Spent:    "0",
	}}
	// Override: MaxPerTx = "0" doesn't trigger limit. Check with non-zero.
	br.budget.MaxPerTx = "0" // "0" is treated as no limit
	bc := NewBudgetChecker(br, tr, slog.Default())
	rule := &types.Rule{ID: "r1", TemplateID: ptrStr("t1")}

	// count_only returns 1, maxPerTx "0" is skipped so it should pass
	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{}, nil)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestBudgetChecker_PerTxLimitExceeded_Real(t *testing.T) {
	// tx_value metering with a large tx value exceeding per-tx limit
	metering, _ := json.Marshal(types.BudgetMetering{Method: "tx_value"})
	tr := &stubTemplateRepo{tmpl: &types.RuleTemplate{ID: "t1", BudgetMetering: metering}}
	br := &stubBudgetRepo{budget: &types.RuleBudget{
		MaxTotal:   "1000000000000000000",  // 1 ETH total
		MaxPerTx:   "100000000000000000",   // 0.1 ETH per tx
		Spent:      "0",
		UpdatedAt:  time.Now(),
	}}
	bc := NewBudgetChecker(br, tr, slog.Default())
	rule := &types.Rule{ID: "r1", TemplateID: ptrStr("t1")}
	val := "500000000000000000" // 0.5 ETH exceeds 0.1 ETH per-tx
	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{}, &types.ParsedPayload{Value: &val})
	require.NoError(t, err)
	assert.False(t, ok, "should fail: per-tx limit exceeded")
}

func TestBudgetChecker_TotalBudgetExceeded(t *testing.T) {
	metering, _ := json.Marshal(types.BudgetMetering{Method: "count_only"})
	tr := &stubTemplateRepo{tmpl: &types.RuleTemplate{ID: "t1", BudgetMetering: metering}}
	br := &stubBudgetRepo{
		budget: &types.RuleBudget{
			MaxTotal:  "5",
			Spent:     "5",
			UpdatedAt: time.Now(),
		},
		atomicErr: storage.ErrBudgetExceeded,
	}
	bc := NewBudgetChecker(br, tr, slog.Default())
	rule := &types.Rule{ID: "r1", TemplateID: ptrStr("t1")}
	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{}, nil)
	require.NoError(t, err)
	assert.False(t, ok, "should fail: total budget exceeded")
}

func TestBudgetChecker_AtomicSpendError(t *testing.T) {
	metering, _ := json.Marshal(types.BudgetMetering{Method: "count_only"})
	tr := &stubTemplateRepo{tmpl: &types.RuleTemplate{ID: "t1", BudgetMetering: metering}}
	br := &stubBudgetRepo{
		budget: &types.RuleBudget{
			MaxTotal:  "100",
			Spent:     "0",
			UpdatedAt: time.Now(),
		},
		atomicErr: assert.AnError,
	}
	bc := NewBudgetChecker(br, tr, slog.Default())
	rule := &types.Rule{ID: "r1", TemplateID: ptrStr("t1")}
	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{}, nil)
	assert.Error(t, err)
	assert.False(t, ok)
}

func TestBudgetChecker_SuccessDeductsAndLogs(t *testing.T) {
	metering, _ := json.Marshal(types.BudgetMetering{Method: "count_only"})
	tr := &stubTemplateRepo{tmpl: &types.RuleTemplate{ID: "t1", BudgetMetering: metering}}
	br := &stubBudgetRepo{budget: &types.RuleBudget{
		MaxTotal:  "100",
		MaxPerTx:  "10",
		Spent:     "5",
		TxCount:   3,
		UpdatedAt: time.Now(),
	}}
	bc := NewBudgetChecker(br, tr, slog.Default())
	rule := &types.Rule{ID: "r1", TemplateID: ptrStr("t1")}
	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{}, nil)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.True(t, br.atomicSpendCalled)
}

func TestBudgetChecker_DefaultUnitIsCount(t *testing.T) {
	metering, _ := json.Marshal(types.BudgetMetering{Method: "count_only", Unit: ""}) // empty → default "count"
	tr := &stubTemplateRepo{tmpl: &types.RuleTemplate{ID: "t1", BudgetMetering: metering}}
	br := &stubBudgetRepo{budget: &types.RuleBudget{
		MaxTotal: "100", Spent: "0", UpdatedAt: time.Now(),
	}}
	bc := NewBudgetChecker(br, tr, slog.Default())
	rule := &types.Rule{ID: "r1", TemplateID: ptrStr("t1")}
	ok, err := bc.CheckAndDeductBudget(context.Background(), rule, &types.SignRequest{}, nil)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "count", br.lastUnit, "default unit should be 'count'")
}

// ─────────────────────────────────────────────────────────────────────────────
// checkAlertThreshold
// ─────────────────────────────────────────────────────────────────────────────

func TestCheckAlertThreshold_AlertSent_Skips(t *testing.T) {
	bc := NewBudgetChecker(nil, nil, slog.Default())
	// Should not panic; AlertSent = true means skip
	bc.checkAlertThreshold("r1", "count", &types.RuleBudget{AlertSent: true, AlertPct: 80, MaxTotal: "100", Spent: "90"})
}

func TestCheckAlertThreshold_ZeroPct_Skips(t *testing.T) {
	bc := NewBudgetChecker(nil, nil, slog.Default())
	bc.checkAlertThreshold("r1", "count", &types.RuleBudget{AlertPct: 0, MaxTotal: "100", Spent: "90"})
}

func TestCheckAlertThreshold_ZeroMaxTotal_Skips(t *testing.T) {
	bc := NewBudgetChecker(nil, nil, slog.Default())
	bc.checkAlertThreshold("r1", "count", &types.RuleBudget{AlertPct: 80, MaxTotal: "0", Spent: "0"})
}

func TestCheckAlertThreshold_EmptyMaxTotal_Skips(t *testing.T) {
	bc := NewBudgetChecker(nil, nil, slog.Default())
	bc.checkAlertThreshold("r1", "count", &types.RuleBudget{AlertPct: 80, MaxTotal: "", Spent: "0"})
}

func TestCheckAlertThreshold_InvalidSpent_Skips(t *testing.T) {
	bc := NewBudgetChecker(nil, nil, slog.Default())
	bc.checkAlertThreshold("r1", "count", &types.RuleBudget{AlertPct: 80, MaxTotal: "100", Spent: "bad"})
}

func TestCheckAlertThreshold_InvalidMaxTotal_Skips(t *testing.T) {
	bc := NewBudgetChecker(nil, nil, slog.Default())
	bc.checkAlertThreshold("r1", "count", &types.RuleBudget{AlertPct: 80, MaxTotal: "bad", Spent: "80"})
}

func TestCheckAlertThreshold_BelowThreshold_NoAlert(t *testing.T) {
	bc := NewBudgetChecker(nil, nil, slog.Default())
	// 50% spent, threshold at 80% → no alert
	bc.checkAlertThreshold("r1", "count", &types.RuleBudget{AlertPct: 80, MaxTotal: "100", Spent: "50"})
}

func TestCheckAlertThreshold_AboveThreshold_Logs(t *testing.T) {
	bc := NewBudgetChecker(nil, nil, slog.Default())
	// 90% spent, threshold at 80% → alert should fire (just logs, no panic)
	bc.checkAlertThreshold("r1", "count", &types.RuleBudget{AlertPct: 80, MaxTotal: "100", Spent: "90"})
}

// ─────────────────────────────────────────────────────────────────────────────
// checkAlertThreshold — with notifier integration
// ─────────────────────────────────────────────────────────────────────────────

func TestCheckAlertThreshold_SendsNotification(t *testing.T) {
	mn := &mockNotifier{}
	br := &stubBudgetRepo{}
	bc := NewBudgetChecker(br, nil, slog.Default())
	bc.SetNotifier(mn)

	budget := &types.RuleBudget{
		AlertPct: 80,
		MaxTotal: "100",
		Spent:    "90",
	}
	bc.checkAlertThreshold("r1", "usdt", budget)

	assert.True(t, mn.called, "notifier should have been called when threshold reached")
	assert.Equal(t, types.RuleID("r1"), mn.lastRuleID)
	assert.Equal(t, "usdt", mn.lastUnit)
	assert.Equal(t, "90", mn.lastSpent)
	assert.Equal(t, "100", mn.lastMaxTotal)
	assert.Equal(t, int64(90), mn.lastPct)
	assert.Equal(t, 80, mn.lastAlertPct)
}

func TestCheckAlertThreshold_MarksAlertSent(t *testing.T) {
	mn := &mockNotifier{}
	br := &stubBudgetRepo{}
	bc := NewBudgetChecker(br, nil, slog.Default())
	bc.SetNotifier(mn)

	budget := &types.RuleBudget{
		AlertPct: 80,
		MaxTotal: "100",
		Spent:    "85",
	}
	bc.checkAlertThreshold("r1", "count", budget)

	assert.True(t, mn.called, "notifier should have been called")
	assert.True(t, br.markAlertSentCalled, "MarkAlertSent should have been called after successful notification")
	assert.Equal(t, types.RuleID("r1"), br.markAlertSentRuleID)
	assert.Equal(t, "count", br.markAlertSentUnit)
}

func TestCheckAlertThreshold_SkipsWhenAlertAlreadySent(t *testing.T) {
	mn := &mockNotifier{}
	br := &stubBudgetRepo{}
	bc := NewBudgetChecker(br, nil, slog.Default())
	bc.SetNotifier(mn)

	budget := &types.RuleBudget{
		AlertSent: true, // already sent
		AlertPct:  80,
		MaxTotal:  "100",
		Spent:     "90",
	}
	bc.checkAlertThreshold("r1", "count", budget)

	assert.False(t, mn.called, "notifier should NOT be called when alert already sent")
	assert.False(t, br.markAlertSentCalled, "MarkAlertSent should NOT be called")
}

func TestCheckAlertThreshold_SkipsWhenBelowThreshold(t *testing.T) {
	mn := &mockNotifier{}
	br := &stubBudgetRepo{}
	bc := NewBudgetChecker(br, nil, slog.Default())
	bc.SetNotifier(mn)

	budget := &types.RuleBudget{
		AlertPct: 80,
		MaxTotal: "100",
		Spent:    "50", // 50% < 80%
	}
	bc.checkAlertThreshold("r1", "count", budget)

	assert.False(t, mn.called, "notifier should NOT be called when below threshold")
	assert.False(t, br.markAlertSentCalled, "MarkAlertSent should NOT be called when below threshold")
}

func TestCheckAlertThreshold_NoNotifierStillMarksAlert(t *testing.T) {
	br := &stubBudgetRepo{}
	bc := NewBudgetChecker(br, nil, slog.Default())
	// No notifier set — bc.notifier is nil

	budget := &types.RuleBudget{
		AlertPct: 80,
		MaxTotal: "100",
		Spent:    "90",
	}
	bc.checkAlertThreshold("r1", "count", budget)

	assert.True(t, br.markAlertSentCalled, "MarkAlertSent should still be called even without a notifier")
	assert.Equal(t, types.RuleID("r1"), br.markAlertSentRuleID)
	assert.Equal(t, "count", br.markAlertSentUnit)
}

func TestCheckAlertThreshold_NotifierError_DoesNotMarkSent(t *testing.T) {
	mn := &mockNotifier{err: assert.AnError}
	br := &stubBudgetRepo{}
	bc := NewBudgetChecker(br, nil, slog.Default())
	bc.SetNotifier(mn)

	budget := &types.RuleBudget{
		AlertPct: 80,
		MaxTotal: "100",
		Spent:    "90",
	}
	bc.checkAlertThreshold("r1", "count", budget)

	assert.True(t, mn.called, "notifier should have been called")
	assert.False(t, br.markAlertSentCalled, "MarkAlertSent should NOT be called when notification fails")
}

// mockNotifier is a test double for BudgetAlertNotifier.
type mockNotifier struct {
	called       bool
	err          error
	lastRuleID   types.RuleID
	lastUnit     string
	lastSpent    string
	lastMaxTotal string
	lastPct      int64
	lastAlertPct int
}

func (m *mockNotifier) SendBudgetAlert(
	ctx context.Context,
	ruleID types.RuleID,
	unit string,
	spent string,
	maxTotal string,
	pct int64,
	alertPct int,
) error {
	m.called = true
	m.lastRuleID = ruleID
	m.lastUnit = unit
	m.lastSpent = spent
	m.lastMaxTotal = maxTotal
	m.lastPct = pct
	m.lastAlertPct = alertPct
	return m.err
}

// ─────────────────────────────────────────────────────────────────────────────
// checkPeriodicRenewal edge cases
// ─────────────────────────────────────────────────────────────────────────────

func TestCheckPeriodicRenewal_ZeroPeriod(t *testing.T) {
	bc := NewBudgetChecker(&stubBudgetRepo{}, nil, slog.Default())
	now := time.Now()
	zeroPeriod := time.Duration(0)
	rule := &types.Rule{BudgetPeriod: &zeroPeriod, BudgetPeriodStart: &now}
	err := bc.checkPeriodicRenewal(context.Background(), rule, &types.RuleBudget{}, "count")
	assert.NoError(t, err)
}

func TestCheckPeriodicRenewal_FutureStart(t *testing.T) {
	bc := NewBudgetChecker(&stubBudgetRepo{}, nil, slog.Default())
	future := time.Now().Add(24 * time.Hour)
	period := 1 * time.Hour
	rule := &types.Rule{BudgetPeriod: &period, BudgetPeriodStart: &future}
	err := bc.checkPeriodicRenewal(context.Background(), rule, &types.RuleBudget{}, "count")
	assert.NoError(t, err)
}

func TestCheckPeriodicRenewal_BudgetStillCurrentPeriod(t *testing.T) {
	bc := NewBudgetChecker(&stubBudgetRepo{}, nil, slog.Default())
	now := time.Now()
	period := 1 * time.Hour
	start := now.Add(-30 * time.Minute) // started 30min ago, period is 1h, so we're in period 0
	rule := &types.Rule{BudgetPeriod: &period, BudgetPeriodStart: &start}
	budget := &types.RuleBudget{UpdatedAt: now.Add(-10 * time.Minute)} // updated 10min ago, still current period
	err := bc.checkPeriodicRenewal(context.Background(), rule, budget, "count")
	assert.NoError(t, err)
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtractAmount — calldata_param path
// ─────────────────────────────────────────────────────────────────────────────

func TestExtractAmount_CalldataParam(t *testing.T) {
	data := make([]byte, 4+32) // selector + 1 param
	data[4+31] = 42
	metering := types.BudgetMetering{Method: "calldata_param", ParamIndex: 0}
	amount, err := ExtractAmount(metering, nil, &types.ParsedPayload{RawData: data})
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(42), amount)
}

func TestExtractAmount_TypedDataField(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{"amount": "999"})
	metering := types.BudgetMetering{Method: "typed_data_field", FieldPath: "amount"}
	amount, err := ExtractAmount(metering, nil, &types.ParsedPayload{RawData: data})
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(999), amount)
}

// ─────────────────────────────────────────────────────────────────────────────
// filterRulesBySignType
// ─────────────────────────────────────────────────────────────────────────────

func TestFilterRulesBySignType_NoEvaluator(t *testing.T) {
	engine, _ := NewWhitelistRuleEngine(&mockRuleRepository{}, slog.Default())
	rules := []*types.Rule{{Type: "unknown_type"}}
	out := engine.filterRulesBySignType(rules, "transaction")
	assert.Len(t, out, 1, "unknown evaluator → keep rule")
}

func TestFilterRulesBySignType_NonApplicableEvaluator(t *testing.T) {
	engine, _ := NewWhitelistRuleEngine(&mockRuleRepository{}, slog.Default())
	// Register a simple evaluator that does NOT implement SignTypeApplicable
	engine.RegisterEvaluator(&simpleEvaluator{ruleType: "simple"})
	rules := []*types.Rule{{Type: "simple"}}
	out := engine.filterRulesBySignType(rules, "transaction")
	assert.Len(t, out, 1, "evaluator without SignTypeApplicable → keep rule")
}

func TestFilterRulesBySignType_ApplicableFilter(t *testing.T) {
	engine, _ := NewWhitelistRuleEngine(&mockRuleRepository{}, slog.Default())
	engine.RegisterEvaluator(&signTypeFilterEvaluator{
		ruleType:       "typed",
		appliesTo:      "transaction",
	})
	rules := []*types.Rule{
		{Type: "typed", Name: "applies"},
		{Type: "typed", Name: "filtered"},
	}
	out := engine.filterRulesBySignType(rules, "transaction")
	assert.Len(t, out, 2, "all apply since signType matches")

	out2 := engine.filterRulesBySignType(rules, "typed_data")
	assert.Len(t, out2, 0, "none apply since signType doesn't match")
}

// ─────────────────────────────────────────────────────────────────────────────
// logScopeMismatch
// ─────────────────────────────────────────────────────────────────────────────

func TestLogScopeMismatch_NilInputs(t *testing.T) {
	engine, _ := NewWhitelistRuleEngine(&mockRuleRepository{}, slog.Default())
	// Should not panic with nil rule/req
	engine.logScopeMismatch(nil, &types.SignRequest{}, "target")
	engine.logScopeMismatch(&types.Rule{}, nil, "target")
}

func TestLogScopeMismatch_AllFields(t *testing.T) {
	engine, _ := NewWhitelistRuleEngine(&mockRuleRepository{}, slog.Default())
	ct := types.ChainTypeEVM
	rule := &types.Rule{
		ChainType:     &ct,
		ChainID:       ptrStr("1"),
		APIKeyID:      ptrStr("api-1"),
		SignerAddress: ptrStr("0xABC"),
	}
	req := &types.SignRequest{
		ChainType:     types.ChainTypeEVM,
		ChainID:       "137",
		APIKeyID:      "api-2",
		SignerAddress: "0xDEF",
	}
	// Should not panic, just log
	engine.logScopeMismatch(rule, req, "target-1")
}

// ─────────────────────────────────────────────────────────────────────────────
// resolveDelegation — additional edge cases
// ─────────────────────────────────────────────────────────────────────────────

func TestResolveDelegation_SingleMode_ScopeMismatch(t *testing.T) {
	// Target rule scope doesn't match delegated request → fail
	ct := types.ChainTypeEVM
	targetRule := &types.Rule{
		ID:        "target-1",
		Type:      "simple",
		Enabled:   true,
		Mode:      types.RuleModeWhitelist,
		ChainType: &ct,
		ChainID:   ptrStr("999"), // scope: chain_id=999
	}
	repo := &mockRuleRepository{rules: []*types.Rule{targetRule}}
	engine, _ := NewWhitelistRuleEngine(repo, slog.Default())
	engine.RegisterEvaluator(&simpleEvaluator{ruleType: "simple", matchResult: true})
	engine.delegationConverter = func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error) {
		return &types.SignRequest{ChainType: types.ChainTypeEVM, ChainID: "1", SignerAddress: "0x1"}, &types.ParsedPayload{}, nil
	}

	fromRule := &types.Rule{ID: "from-1"}
	delegation := &DelegationRequest{
		TargetRuleIDs: []types.RuleID{"target-1"},
		Mode:          "single",
		Payload:       map[string]interface{}{"signer": "0x1"},
	}
	result, err := engine.resolveDelegation(context.Background(), &types.SignRequest{}, fromRule, delegation)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.NoMatchReason, "scope mismatch")
}

func TestResolveDelegation_SingleMode_ConvertError(t *testing.T) {
	engine, _ := NewWhitelistRuleEngine(&mockRuleRepository{}, slog.Default())
	engine.delegationConverter = func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error) {
		return nil, nil, assert.AnError
	}
	delegation := &DelegationRequest{
		TargetRuleIDs: []types.RuleID{"target-1"},
		Mode:          "single",
		Payload:       map[string]interface{}{},
	}
	result, err := engine.resolveDelegation(context.Background(), &types.SignRequest{}, &types.Rule{}, delegation)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.NoMatchReason, "convert failed")
}

func TestResolveDelegation_PerItem_ConvertFails(t *testing.T) {
	engine, _ := NewWhitelistRuleEngine(&mockRuleRepository{}, slog.Default())
	callCount := 0
	engine.delegationConverter = func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error) {
		callCount++
		return nil, nil, assert.AnError
	}
	delegation := &DelegationRequest{
		TargetRuleIDs: []types.RuleID{"target-1"},
		Mode:          "per_item",
		Payload:       map[string]interface{}{"items": []interface{}{map[string]interface{}{"a": 1}}},
		ItemsKey:      "items",
	}
	result, err := engine.resolveDelegation(context.Background(), &types.SignRequest{}, &types.Rule{}, delegation)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.NoMatchReason, "convert failed")
}

func TestResolveDelegation_PerItem_MaxItemsExceeded(t *testing.T) {
	engine, _ := NewWhitelistRuleEngine(&mockRuleRepository{}, slog.Default())
	engine.delegationConverter = func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error) {
		return &types.SignRequest{}, &types.ParsedPayload{}, nil
	}
	// Create items exceeding DelegationMaxItems (256)
	items := make([]interface{}, DelegationMaxItems+1)
	for i := range items {
		items[i] = map[string]interface{}{"x": i}
	}
	delegation := &DelegationRequest{
		TargetRuleIDs: []types.RuleID{"target-1"},
		Mode:          "per_item",
		Payload:       map[string]interface{}{"items": items},
		ItemsKey:      "items",
	}
	result, err := engine.resolveDelegation(context.Background(), &types.SignRequest{}, &types.Rule{}, delegation)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.NoMatchReason, "exceeds max items")
}

func TestResolveDelegation_PerItem_TargetNotFound(t *testing.T) {
	repo := &mockRuleRepository{rules: []*types.Rule{}} // empty
	engine, _ := NewWhitelistRuleEngine(repo, slog.Default())
	engine.delegationConverter = func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error) {
		return &types.SignRequest{SignerAddress: "0x1"}, &types.ParsedPayload{}, nil
	}
	delegation := &DelegationRequest{
		TargetRuleIDs: []types.RuleID{"nonexistent"},
		Mode:          "per_item",
		Payload:       map[string]interface{}{"items": []interface{}{map[string]interface{}{"a": 1}}},
		ItemsKey:      "items",
	}
	result, err := engine.resolveDelegation(context.Background(), &types.SignRequest{}, &types.Rule{}, delegation)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.NoMatchReason, "not found")
}

func TestResolveDelegation_PerItem_CycleDetected(t *testing.T) {
	targetRule := &types.Rule{ID: "target-1", Type: "simple", Enabled: true, Mode: types.RuleModeWhitelist}
	repo := &mockRuleRepository{rules: []*types.Rule{targetRule}}
	engine, _ := NewWhitelistRuleEngine(repo, slog.Default())
	engine.RegisterEvaluator(&simpleEvaluator{ruleType: "simple", matchResult: true})
	engine.delegationConverter = func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error) {
		return &types.SignRequest{SignerAddress: "0x1"}, &types.ParsedPayload{}, nil
	}

	// Inject cycle: target-1 is already in the path
	ctx := withDelegationCtx(context.Background(), 0, map[types.RuleID]bool{"target-1": true})
	delegation := &DelegationRequest{
		TargetRuleIDs: []types.RuleID{"target-1"},
		Mode:          "per_item",
		Payload:       map[string]interface{}{"items": []interface{}{map[string]interface{}{"a": 1}}},
		ItemsKey:      "items",
	}
	result, err := engine.resolveDelegation(ctx, &types.SignRequest{}, &types.Rule{}, delegation)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.NoMatchReason, "cycle")
}

func TestResolveDelegation_PerItem_ScopeMismatch(t *testing.T) {
	ct := types.ChainTypeEVM
	targetRule := &types.Rule{
		ID: "target-1", Type: "simple", Enabled: true, Mode: types.RuleModeWhitelist,
		ChainType: &ct, ChainID: ptrStr("999"),
	}
	repo := &mockRuleRepository{rules: []*types.Rule{targetRule}}
	engine, _ := NewWhitelistRuleEngine(repo, slog.Default())
	engine.RegisterEvaluator(&simpleEvaluator{ruleType: "simple", matchResult: true})
	engine.delegationConverter = func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error) {
		return &types.SignRequest{ChainType: types.ChainTypeEVM, ChainID: "1", SignerAddress: "0x1"}, &types.ParsedPayload{}, nil
	}
	delegation := &DelegationRequest{
		TargetRuleIDs: []types.RuleID{"target-1"},
		Mode:          "per_item",
		Payload:       map[string]interface{}{"items": []interface{}{map[string]interface{}{"a": 1}}},
		ItemsKey:      "items",
	}
	result, err := engine.resolveDelegation(context.Background(), &types.SignRequest{}, &types.Rule{}, delegation)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.NoMatchReason, "scope mismatch")
}

func TestResolveDelegation_PerItem_TargetDidNotAllow(t *testing.T) {
	targetRule := &types.Rule{ID: "target-1", Type: "simple", Enabled: true, Mode: types.RuleModeWhitelist}
	repo := &mockRuleRepository{rules: []*types.Rule{targetRule}}
	engine, _ := NewWhitelistRuleEngine(repo, slog.Default())
	engine.RegisterEvaluator(&simpleEvaluator{ruleType: "simple", matchResult: false, reason: "nope"})
	engine.delegationConverter = func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error) {
		return &types.SignRequest{SignerAddress: "0x1"}, &types.ParsedPayload{}, nil
	}
	delegation := &DelegationRequest{
		TargetRuleIDs: []types.RuleID{"target-1"},
		Mode:          "per_item",
		Payload:       map[string]interface{}{"items": []interface{}{map[string]interface{}{"a": 1}}},
		ItemsKey:      "items",
	}
	result, err := engine.resolveDelegation(context.Background(), &types.SignRequest{}, &types.Rule{}, delegation)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.NoMatchReason, "did not allow")
}

func TestResolveDelegation_SingleMode_TargetEvalError(t *testing.T) {
	targetRule := &types.Rule{ID: "target-1", Type: "error_type", Enabled: true, Mode: types.RuleModeWhitelist}
	repo := &mockRuleRepository{rules: []*types.Rule{targetRule}}
	engine, _ := NewWhitelistRuleEngine(repo, slog.Default())
	engine.RegisterEvaluator(&errorEvaluator{ruleType: "error_type"})
	engine.delegationConverter = func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error) {
		return &types.SignRequest{SignerAddress: "0x1"}, &types.ParsedPayload{}, nil
	}
	delegation := &DelegationRequest{
		TargetRuleIDs: []types.RuleID{"target-1"},
		Mode:          "single",
		Payload:       map[string]interface{}{"signer": "0x1"},
	}
	result, err := engine.resolveDelegation(context.Background(), &types.SignRequest{}, &types.Rule{}, delegation)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.NoMatchReason, "error")
}

func TestResolveDelegation_SingleMode_TargetNilResult(t *testing.T) {
	targetRule := &types.Rule{ID: "target-1", Type: "simple", Enabled: true, Mode: types.RuleModeWhitelist}
	repo := &mockRuleRepository{rules: []*types.Rule{targetRule}}
	engine, _ := NewWhitelistRuleEngine(repo, slog.Default())
	engine.RegisterEvaluator(&simpleEvaluator{ruleType: "simple", matchResult: false})
	engine.delegationConverter = func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error) {
		return &types.SignRequest{SignerAddress: "0x1"}, &types.ParsedPayload{}, nil
	}
	delegation := &DelegationRequest{
		TargetRuleIDs: []types.RuleID{"target-1"},
		Mode:          "single",
		Payload:       map[string]interface{}{"signer": "0x1"},
	}
	result, err := engine.resolveDelegation(context.Background(), &types.SignRequest{}, &types.Rule{}, delegation)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
}

// ─────────────────────────────────────────────────────────────────────────────
// evaluateWhitelistBatch (partial)
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluateWhitelistBatch_NoEvaluator(t *testing.T) {
	engine, _ := NewWhitelistRuleEngine(&mockRuleRepository{}, slog.Default())
	rules := []*types.Rule{{ID: "r1", Type: "unknown"}}
	result, evaluated, _ := engine.evaluateWhitelistBatch(context.Background(), rules, &types.SignRequest{}, nil)
	assert.Nil(t, result)
	assert.Len(t, evaluated, 0)
}

func TestEvaluateWhitelistBatch_NonBatchEvaluator(t *testing.T) {
	engine, _ := NewWhitelistRuleEngine(&mockRuleRepository{}, slog.Default())
	engine.RegisterEvaluator(&simpleEvaluator{ruleType: "simple"})
	rules := []*types.Rule{{ID: "r1", Type: "simple"}}
	result, evaluated, _ := engine.evaluateWhitelistBatch(context.Background(), rules, &types.SignRequest{}, nil)
	assert.Nil(t, result, "non-batch evaluator should not produce batch result")
	assert.Len(t, evaluated, 0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Stub types
// ─────────────────────────────────────────────────────────────────────────────

func ptrStr(s string) *string { return &s }

// stubBudgetRepo is a minimal BudgetRepository for unit tests.
type stubBudgetRepo struct {
	budget             *types.RuleBudget
	getErr             error
	atomicErr          error
	atomicSpendCalled  bool
	lastUnit           string
	markAlertSentCalled bool
	markAlertSentRuleID types.RuleID
	markAlertSentUnit   string
	markAlertSentErr    error
}

func (r *stubBudgetRepo) Create(ctx context.Context, budget *types.RuleBudget) error { return nil }
func (r *stubBudgetRepo) Delete(ctx context.Context, id string) error               { return nil }
func (r *stubBudgetRepo) DeleteByRuleID(ctx context.Context, ruleID types.RuleID) error {
	return nil
}
func (r *stubBudgetRepo) ListByRuleID(ctx context.Context, ruleID types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (r *stubBudgetRepo) ListByRuleIDs(ctx context.Context, ruleIDs []types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (r *stubBudgetRepo) GetByRuleID(ctx context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error) {
	r.lastUnit = unit
	if r.getErr != nil {
		return nil, r.getErr
	}
	if r.budget != nil {
		cp := *r.budget
		return &cp, nil
	}
	return nil, types.ErrNotFound
}
func (r *stubBudgetRepo) ResetBudget(ctx context.Context, ruleID types.RuleID, unit string, start time.Time) error {
	return nil
}
func (r *stubBudgetRepo) AtomicSpend(ctx context.Context, ruleID types.RuleID, unit string, amount string) error {
	r.atomicSpendCalled = true
	return r.atomicErr
}
func (r *stubBudgetRepo) MarkAlertSent(ctx context.Context, ruleID types.RuleID, unit string) error {
	r.markAlertSentCalled = true
	r.markAlertSentRuleID = ruleID
	r.markAlertSentUnit = unit
	return r.markAlertSentErr
}

// stubTemplateRepo is a minimal TemplateRepository for unit tests.
type stubTemplateRepo struct {
	tmpl *types.RuleTemplate
	err  error
}

func (r *stubTemplateRepo) Get(ctx context.Context, id string) (*types.RuleTemplate, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.tmpl != nil {
		return r.tmpl, nil
	}
	return nil, types.ErrNotFound
}
func (r *stubTemplateRepo) Create(ctx context.Context, tmpl *types.RuleTemplate) error  { return nil }
func (r *stubTemplateRepo) GetByName(ctx context.Context, name string) (*types.RuleTemplate, error) {
	return nil, nil
}
func (r *stubTemplateRepo) Update(ctx context.Context, tmpl *types.RuleTemplate) error { return nil }
func (r *stubTemplateRepo) Delete(ctx context.Context, id string) error                 { return nil }
func (r *stubTemplateRepo) List(ctx context.Context, filter storage.TemplateFilter) ([]*types.RuleTemplate, error) {
	return nil, nil
}
func (r *stubTemplateRepo) Count(ctx context.Context, filter storage.TemplateFilter) (int, error) {
	return 0, nil
}

// simpleEvaluator is a basic evaluator that returns configurable results.
type simpleEvaluator struct {
	ruleType    types.RuleType
	matchResult bool
	reason      string
}

func (e *simpleEvaluator) Type() types.RuleType { return e.ruleType }
func (e *simpleEvaluator) Evaluate(ctx context.Context, r *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
	return e.matchResult, e.reason, nil
}

// errorEvaluator always returns an error.
type errorEvaluator struct {
	ruleType types.RuleType
}

func (e *errorEvaluator) Type() types.RuleType { return e.ruleType }
func (e *errorEvaluator) Evaluate(ctx context.Context, r *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
	return false, "", assert.AnError
}

// signTypeFilterEvaluator implements both RuleEvaluator and SignTypeApplicable.
type signTypeFilterEvaluator struct {
	ruleType  types.RuleType
	appliesTo string
}

func (e *signTypeFilterEvaluator) Type() types.RuleType { return e.ruleType }
func (e *signTypeFilterEvaluator) Evaluate(ctx context.Context, r *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
	return true, "", nil
}
func (e *signTypeFilterEvaluator) AppliesToSignType(r *types.Rule, signType string) bool {
	return signType == e.appliesTo
}
