package rule

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// budgetExceededRuleRepo is a rule repo that returns two whitelist instance rules (both match).
type budgetExceededRuleRepo struct {
	rules []*types.Rule
}

func (r *budgetExceededRuleRepo) Create(ctx context.Context, rule *types.Rule) error   { return nil }
func (r *budgetExceededRuleRepo) Update(ctx context.Context, rule *types.Rule) error   { return nil }
func (r *budgetExceededRuleRepo) Delete(ctx context.Context, id types.RuleID) error    { return nil }
func (r *budgetExceededRuleRepo) Get(ctx context.Context, id types.RuleID) (*types.Rule, error) {
	for _, x := range r.rules {
		if x.ID == id {
			return x, nil
		}
	}
	return nil, types.ErrNotFound
}
func (r *budgetExceededRuleRepo) Count(ctx context.Context, filter storage.RuleFilter) (int, error) {
	return len(r.rules), nil
}
func (r *budgetExceededRuleRepo) ListByChainType(ctx context.Context, chainType types.ChainType) ([]*types.Rule, error) {
	return r.rules, nil
}
func (r *budgetExceededRuleRepo) IncrementMatchCount(ctx context.Context, id types.RuleID) error {
	return nil
}

func (r *budgetExceededRuleRepo) List(ctx context.Context, filter storage.RuleFilter) ([]*types.Rule, error) {
	return r.rules, nil
}

// budgetExceededBudgetRepo: rule-1 has budget exhausted, rule-2 has no budget (pass-through).
type budgetExceededBudgetRepo struct {
	mu    sync.Mutex
	state map[string]*types.RuleBudget
}

func newBudgetExceededBudgetRepo() *budgetExceededBudgetRepo {
	return &budgetExceededBudgetRepo{
		state: map[string]*types.RuleBudget{
			"rule-budget-1:count": {
				ID: "b1", RuleID: types.RuleID("rule-budget-1"), Unit: "count",
				MaxTotal: "10", Spent: "10", TxCount: 5, MaxTxCount: 5,
				UpdatedAt: time.Now(),
			},
		},
	}
}

func (m *budgetExceededBudgetRepo) Create(ctx context.Context, budget *types.RuleBudget) error { return nil }
func (m *budgetExceededBudgetRepo) Delete(ctx context.Context, id string) error               { return nil }
func (m *budgetExceededBudgetRepo) DeleteByRuleID(ctx context.Context, ruleID types.RuleID) error {
	return nil
}
func (m *budgetExceededBudgetRepo) ListByRuleID(ctx context.Context, ruleID types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (m *budgetExceededBudgetRepo) ListByRuleIDs(ctx context.Context, ruleIDs []types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}

func (m *budgetExceededBudgetRepo) GetByRuleID(ctx context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := string(ruleID) + ":" + unit
	if b, ok := m.state[key]; ok {
		cp := *b
		return &cp, nil
	}
	return nil, types.ErrNotFound
}

func (m *budgetExceededBudgetRepo) ResetBudget(ctx context.Context, ruleID types.RuleID, unit string, currentPeriodStart time.Time) error {
	return nil
}

func (m *budgetExceededBudgetRepo) AtomicSpend(ctx context.Context, ruleID types.RuleID, unit string, amount string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := string(ruleID) + ":" + unit
	b, ok := m.state[key]
	if !ok {
		return types.ErrNotFound
	}
	// Already at limit
	if b.Spent == b.MaxTotal {
		return storage.ErrBudgetExceeded
	}
	return nil
}

func (m *budgetExceededBudgetRepo) MarkAlertSent(ctx context.Context, ruleID types.RuleID, unit string) error {
	return nil
}

// budgetExceededTemplateRepo returns a template with count_only metering for any ID.
type budgetExceededTemplateRepo struct {
	metering []byte
}

func newBudgetExceededTemplateRepo() *budgetExceededTemplateRepo {
	m, _ := json.Marshal(types.BudgetMetering{Method: "count_only", Unit: "count"})
	return &budgetExceededTemplateRepo{metering: m}
}

func (r *budgetExceededTemplateRepo) Get(ctx context.Context, id string) (*types.RuleTemplate, error) {
	return &types.RuleTemplate{ID: id, BudgetMetering: r.metering}, nil
}
func (r *budgetExceededTemplateRepo) Create(ctx context.Context, tmpl *types.RuleTemplate) error   { return nil }
func (r *budgetExceededTemplateRepo) GetByName(ctx context.Context, name string) (*types.RuleTemplate, error) {
	return nil, nil
}
func (r *budgetExceededTemplateRepo) Update(ctx context.Context, tmpl *types.RuleTemplate) error { return nil }
func (r *budgetExceededTemplateRepo) Delete(ctx context.Context, id string) error                 { return nil }
func (r *budgetExceededTemplateRepo) List(ctx context.Context, filter storage.TemplateFilter) ([]*types.RuleTemplate, error) {
	return nil, nil
}
func (r *budgetExceededTemplateRepo) Count(ctx context.Context, filter storage.TemplateFilter) (int, error) {
	return 0, nil
}

// TestWhitelistRuleEngine_BudgetExceeded_SkipsToNextRule ensures that when the first
// matching whitelist rule has budget exceeded, the engine skips it (fail-open) and
// allows via the next rule that has budget available.
func TestWhitelistRuleEngine_BudgetExceeded_SkipsToNextRule(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	tmpl1, tmpl2 := "tmpl-1", "tmpl-2"
	ruleRepo := &budgetExceededRuleRepo{
		rules: []*types.Rule{
			{ID: types.RuleID("rule-budget-1"), Name: "Rule1", Type: "mock_type", Mode: types.RuleModeWhitelist, TemplateID: &tmpl1},
			{ID: types.RuleID("rule-budget-2"), Name: "Rule2", Type: "mock_type", Mode: types.RuleModeWhitelist, TemplateID: &tmpl2},
		},
	}
	budgetRepo := newBudgetExceededBudgetRepo()
	templateRepo := newBudgetExceededTemplateRepo()
	bc := NewBudgetChecker(budgetRepo, templateRepo, logger)

	engine, err := NewWhitelistRuleEngine(ruleRepo, logger, WithBudgetChecker(bc))
	require.NoError(t, err)

	// Evaluator that matches both rules (batch path returns both passed)
	engine.RegisterEvaluator(&mockBatchEvaluator{
		mockEvaluator: mockEvaluator{},
		canBatchFunc: func(rules []*types.Rule) bool { return true },
		evaluateBatchFunc: func(ctx context.Context, rules []*types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) ([]BatchEvaluationResult, error) {
			return []BatchEvaluationResult{
				{RuleID: types.RuleID("rule-budget-1"), Passed: true, Reason: "match1"},
				{RuleID: types.RuleID("rule-budget-2"), Passed: true, Reason: "match2"},
			}, nil
		},
	})

	req := &types.SignRequest{ID: "req-1", ChainType: types.ChainTypeEVM}
	parsed := &types.ParsedPayload{}

	ruleID, reason, err := engine.Evaluate(context.Background(), req, parsed)
	require.NoError(t, err)
	require.NotNil(t, ruleID)
	assert.Equal(t, types.RuleID("rule-budget-2"), *ruleID, "must allow via second rule when first rule budget exceeded")
	assert.Equal(t, "match2", reason)
}
