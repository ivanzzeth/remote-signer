package rule

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// =============================================================================
// Mock Implementations for Testing
// =============================================================================

// mockRuleRepository implements storage.RuleRepository for testing
type mockRuleRepository struct {
	rules []*types.Rule
}

func (m *mockRuleRepository) Create(ctx context.Context, rule *types.Rule) error {
	return nil
}

func (m *mockRuleRepository) Get(ctx context.Context, id types.RuleID) (*types.Rule, error) {
	for _, r := range m.rules {
		if r.ID == id {
			return r, nil
		}
	}
	return nil, fmt.Errorf("rule not found")
}

func (m *mockRuleRepository) List(ctx context.Context, filter storage.RuleFilter) ([]*types.Rule, error) {
	return m.rules, nil
}

func (m *mockRuleRepository) Update(ctx context.Context, rule *types.Rule) error {
	return nil
}

func (m *mockRuleRepository) Delete(ctx context.Context, id types.RuleID) error {
	return nil
}

func (m *mockRuleRepository) Count(ctx context.Context, filter storage.RuleFilter) (int, error) {
	return len(m.rules), nil
}

func (m *mockRuleRepository) ListByChainType(ctx context.Context, chainType types.ChainType) ([]*types.Rule, error) {
	var result []*types.Rule
	for _, r := range m.rules {
		if r.ChainType != nil && *r.ChainType == chainType {
			result = append(result, r)
		}
	}
	return result, nil
}

func (m *mockRuleRepository) IncrementMatchCount(ctx context.Context, id types.RuleID) error {
	return nil
}

// mockEvaluator implements RuleEvaluator for testing
type mockEvaluator struct {
	evaluateFunc func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error)
}

func (m *mockEvaluator) Type() types.RuleType {
	return "mock_type"
}

func (m *mockEvaluator) Evaluate(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
	if m.evaluateFunc != nil {
		return m.evaluateFunc(ctx, rule, req, parsed)
	}
	return false, "", nil
}

// mockBatchEvaluator implements BatchRuleEvaluator for testing
type mockBatchEvaluator struct {
	mockEvaluator
	canBatchFunc      func(rules []*types.Rule) bool
	evaluateBatchFunc func(ctx context.Context, rules []*types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) ([]BatchEvaluationResult, error)
}

func (m *mockBatchEvaluator) CanBatchEvaluate(rules []*types.Rule) bool {
	if m.canBatchFunc != nil {
		return m.canBatchFunc(rules)
	}
	return true
}

func (m *mockBatchEvaluator) EvaluateBatch(ctx context.Context, rules []*types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) ([]BatchEvaluationResult, error) {
	if m.evaluateBatchFunc != nil {
		return m.evaluateBatchFunc(ctx, rules, req, parsed)
	}
	return nil, nil
}

// =============================================================================
// RuleEvaluationError Tests
// =============================================================================

func TestRuleEvaluationError_Error(t *testing.T) {
	innerErr := fmt.Errorf("some inner error")
	err := &RuleEvaluationError{
		RuleID:   "test-rule-id",
		RuleName: "Test Rule",
		RuleType: "solidity_expression",
		Err:      innerErr,
	}

	msg := err.Error()
	assert.Contains(t, msg, "test-rule-id")
	assert.Contains(t, msg, "Test Rule")
	assert.Contains(t, msg, "evaluation failed")
}

func TestRuleEvaluationError_Unwrap(t *testing.T) {
	innerErr := fmt.Errorf("some inner error")
	err := &RuleEvaluationError{
		RuleID:   "test-rule-id",
		RuleName: "Test Rule",
		RuleType: "solidity_expression",
		Err:      innerErr,
	}

	// Unwrap should return ErrRuleEvaluationFailed
	assert.ErrorIs(t, err, ErrRuleEvaluationFailed)
}

// =============================================================================
// BlockedError Tests
// =============================================================================

func TestBlockedError_Error(t *testing.T) {
	err := &BlockedError{
		RuleID:   "test-rule-id",
		RuleName: "Test Rule",
		Reason:   "exceeded limit",
	}

	msg := err.Error()
	assert.Contains(t, msg, "test-rule-id")
	assert.Contains(t, msg, "exceeded limit")
}

func TestBlockedError_Unwrap(t *testing.T) {
	err := &BlockedError{
		RuleID:   "test-rule-id",
		RuleName: "Test Rule",
		Reason:   "exceeded limit",
	}

	// Unwrap should return ErrBlockedByRule
	assert.ErrorIs(t, err, ErrBlockedByRule)
}

// =============================================================================
// BatchEvaluationResult Tests
// =============================================================================

func TestBatchEvaluationResult_Fields(t *testing.T) {
	result := BatchEvaluationResult{
		RuleID:  "test-rule-id",
		Passed:  true,
		Reason:  "test reason",
		Err:     nil,
		Skipped: false,
	}

	assert.Equal(t, types.RuleID("test-rule-id"), result.RuleID)
	assert.True(t, result.Passed)
	assert.Equal(t, "test reason", result.Reason)
	assert.Nil(t, result.Err)
	assert.False(t, result.Skipped)
}

func TestBatchEvaluationResult_WithError(t *testing.T) {
	testErr := fmt.Errorf("test error")
	result := BatchEvaluationResult{
		RuleID:  "test-rule-id",
		Passed:  false,
		Reason:  "",
		Err:     testErr,
		Skipped: false,
	}

	assert.Equal(t, testErr, result.Err)
	assert.False(t, result.Passed)
}

func TestBatchEvaluationResult_Skipped(t *testing.T) {
	result := BatchEvaluationResult{
		RuleID:  "test-rule-id",
		Skipped: true,
	}

	assert.True(t, result.Skipped)
}

// =============================================================================
// WhitelistRuleEngine Batch Evaluation Tests
// =============================================================================

func TestWhitelistRuleEngine_evaluateWhitelistBatch_NoBatchEvaluator(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo := &mockRuleRepository{
		rules: []*types.Rule{
			{ID: "rule1", Type: "mock_type", Mode: types.RuleModeWhitelist},
		},
	}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)

	// Register non-batch evaluator
	engine.RegisterEvaluator(&mockEvaluator{})

	req := &types.SignRequest{ID: "test-req"}

	// Should return nil because evaluator doesn't support batch
	result := engine.evaluateWhitelistBatch(context.Background(), repo.rules, req, nil)
	assert.Nil(t, result)
}

func TestWhitelistRuleEngine_evaluateWhitelistBatch_CannotBatch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo := &mockRuleRepository{
		rules: []*types.Rule{
			{ID: "rule1", Type: "mock_type", Mode: types.RuleModeWhitelist},
		},
	}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)

	// Register batch evaluator that says it cannot batch
	engine.RegisterEvaluator(&mockBatchEvaluator{
		canBatchFunc: func(rules []*types.Rule) bool {
			return false
		},
	})

	req := &types.SignRequest{ID: "test-req"}

	// Should return nil because evaluator says cannot batch
	result := engine.evaluateWhitelistBatch(context.Background(), repo.rules, req, nil)
	assert.Nil(t, result)
}

func TestWhitelistRuleEngine_evaluateWhitelistBatch_BatchEvaluationError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo := &mockRuleRepository{
		rules: []*types.Rule{
			{ID: "rule1", Type: "mock_type", Mode: types.RuleModeWhitelist},
		},
	}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)

	// Register batch evaluator that returns error
	engine.RegisterEvaluator(&mockBatchEvaluator{
		canBatchFunc: func(rules []*types.Rule) bool {
			return true
		},
		evaluateBatchFunc: func(ctx context.Context, rules []*types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) ([]BatchEvaluationResult, error) {
			return nil, fmt.Errorf("batch evaluation failed")
		},
	})

	req := &types.SignRequest{ID: "test-req"}

	// Should return nil because batch evaluation failed
	result := engine.evaluateWhitelistBatch(context.Background(), repo.rules, req, nil)
	assert.Nil(t, result)
}

func TestWhitelistRuleEngine_evaluateWhitelistBatch_AllSkipped(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo := &mockRuleRepository{
		rules: []*types.Rule{
			{ID: "rule1", Type: "mock_type", Mode: types.RuleModeWhitelist},
			{ID: "rule2", Type: "mock_type", Mode: types.RuleModeWhitelist},
		},
	}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)

	// Register batch evaluator that skips all rules
	engine.RegisterEvaluator(&mockBatchEvaluator{
		canBatchFunc: func(rules []*types.Rule) bool {
			return true
		},
		evaluateBatchFunc: func(ctx context.Context, rules []*types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) ([]BatchEvaluationResult, error) {
			return []BatchEvaluationResult{
				{RuleID: "rule1", Skipped: true},
				{RuleID: "rule2", Skipped: true},
			}, nil
		},
	})

	req := &types.SignRequest{ID: "test-req"}

	// Should return nil because all rules were skipped
	result := engine.evaluateWhitelistBatch(context.Background(), repo.rules, req, nil)
	assert.Nil(t, result)
}

func TestWhitelistRuleEngine_evaluateWhitelistBatch_AllFailed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo := &mockRuleRepository{
		rules: []*types.Rule{
			{ID: "rule1", Type: "mock_type", Mode: types.RuleModeWhitelist},
			{ID: "rule2", Type: "mock_type", Mode: types.RuleModeWhitelist},
		},
	}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)

	// Register batch evaluator that fails all rules
	engine.RegisterEvaluator(&mockBatchEvaluator{
		canBatchFunc: func(rules []*types.Rule) bool {
			return true
		},
		evaluateBatchFunc: func(ctx context.Context, rules []*types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) ([]BatchEvaluationResult, error) {
			return []BatchEvaluationResult{
				{RuleID: "rule1", Passed: false, Reason: "failed1"},
				{RuleID: "rule2", Passed: false, Reason: "failed2"},
			}, nil
		},
	})

	req := &types.SignRequest{ID: "test-req"}

	// Should return nil because no rule passed
	result := engine.evaluateWhitelistBatch(context.Background(), repo.rules, req, nil)
	assert.Nil(t, result)
}

func TestWhitelistRuleEngine_evaluateWhitelistBatch_FirstPasses(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo := &mockRuleRepository{
		rules: []*types.Rule{
			{ID: "rule1", Name: "Rule 1", Type: "mock_type", Mode: types.RuleModeWhitelist},
			{ID: "rule2", Name: "Rule 2", Type: "mock_type", Mode: types.RuleModeWhitelist},
		},
	}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)

	// Register batch evaluator where first rule passes
	engine.RegisterEvaluator(&mockBatchEvaluator{
		canBatchFunc: func(rules []*types.Rule) bool {
			return true
		},
		evaluateBatchFunc: func(ctx context.Context, rules []*types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) ([]BatchEvaluationResult, error) {
			return []BatchEvaluationResult{
				{RuleID: "rule1", Passed: true, Reason: "allowed by rule1"},
				{RuleID: "rule2", Passed: false, Reason: "failed2"},
			}, nil
		},
	})

	req := &types.SignRequest{ID: "test-req"}

	result := engine.evaluateWhitelistBatch(context.Background(), repo.rules, req, nil)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)
	assert.Equal(t, types.RuleID("rule1"), result.AllowedBy.ID)
	assert.Equal(t, "allowed by rule1", result.AllowReason)
}

func TestWhitelistRuleEngine_evaluateWhitelistBatch_SecondPasses(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo := &mockRuleRepository{
		rules: []*types.Rule{
			{ID: "rule1", Name: "Rule 1", Type: "mock_type", Mode: types.RuleModeWhitelist},
			{ID: "rule2", Name: "Rule 2", Type: "mock_type", Mode: types.RuleModeWhitelist},
		},
	}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)

	// Register batch evaluator where second rule passes
	engine.RegisterEvaluator(&mockBatchEvaluator{
		canBatchFunc: func(rules []*types.Rule) bool {
			return true
		},
		evaluateBatchFunc: func(ctx context.Context, rules []*types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) ([]BatchEvaluationResult, error) {
			return []BatchEvaluationResult{
				{RuleID: "rule1", Passed: false, Reason: "failed1"},
				{RuleID: "rule2", Passed: true, Reason: "allowed by rule2"},
			}, nil
		},
	})

	req := &types.SignRequest{ID: "test-req"}

	result := engine.evaluateWhitelistBatch(context.Background(), repo.rules, req, nil)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)
	assert.Equal(t, types.RuleID("rule2"), result.AllowedBy.ID)
	assert.Equal(t, "allowed by rule2", result.AllowReason)
}

func TestWhitelistRuleEngine_evaluateWhitelistBatch_SkipAndPass(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo := &mockRuleRepository{
		rules: []*types.Rule{
			{ID: "rule1", Name: "Rule 1", Type: "mock_type", Mode: types.RuleModeWhitelist},
			{ID: "rule2", Name: "Rule 2", Type: "mock_type", Mode: types.RuleModeWhitelist},
		},
	}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)

	// Register batch evaluator where first is skipped, second passes
	engine.RegisterEvaluator(&mockBatchEvaluator{
		canBatchFunc: func(rules []*types.Rule) bool {
			return true
		},
		evaluateBatchFunc: func(ctx context.Context, rules []*types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) ([]BatchEvaluationResult, error) {
			return []BatchEvaluationResult{
				{RuleID: "rule1", Skipped: true},
				{RuleID: "rule2", Passed: true, Reason: "allowed"},
			}, nil
		},
	})

	req := &types.SignRequest{ID: "test-req"}

	result := engine.evaluateWhitelistBatch(context.Background(), repo.rules, req, nil)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)
	assert.Equal(t, types.RuleID("rule2"), result.AllowedBy.ID)
}

func TestWhitelistRuleEngine_evaluateWhitelistBatch_ResultWithError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo := &mockRuleRepository{
		rules: []*types.Rule{
			{ID: "rule1", Name: "Rule 1", Type: "mock_type", Mode: types.RuleModeWhitelist},
			{ID: "rule2", Name: "Rule 2", Type: "mock_type", Mode: types.RuleModeWhitelist},
		},
	}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)

	// Register batch evaluator where first has error, second passes
	engine.RegisterEvaluator(&mockBatchEvaluator{
		canBatchFunc: func(rules []*types.Rule) bool {
			return true
		},
		evaluateBatchFunc: func(ctx context.Context, rules []*types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) ([]BatchEvaluationResult, error) {
			return []BatchEvaluationResult{
				{RuleID: "rule1", Err: fmt.Errorf("evaluation error")},
				{RuleID: "rule2", Passed: true, Reason: "allowed"},
			}, nil
		},
	})

	req := &types.SignRequest{ID: "test-req"}

	result := engine.evaluateWhitelistBatch(context.Background(), repo.rules, req, nil)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)
	assert.Equal(t, types.RuleID("rule2"), result.AllowedBy.ID)
}

func TestWhitelistRuleEngine_evaluateWhitelistBatch_MultipleTypes(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo := &mockRuleRepository{
		rules: []*types.Rule{
			{ID: "rule1", Type: "type1", Mode: types.RuleModeWhitelist},
			{ID: "rule2", Type: "type2", Mode: types.RuleModeWhitelist},
		},
	}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)

	// Register batch evaluator for type1 that passes
	batchEval1 := &mockBatchEvaluator{
		canBatchFunc: func(rules []*types.Rule) bool {
			return true
		},
		evaluateBatchFunc: func(ctx context.Context, rules []*types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) ([]BatchEvaluationResult, error) {
			return []BatchEvaluationResult{
				{RuleID: "rule1", Passed: true, Reason: "allowed by type1"},
			}, nil
		},
	}
	batchEval1.mockEvaluator = mockEvaluator{}
	// Override Type method
	engine.evaluators["type1"] = batchEval1

	// Register batch evaluator for type2 that fails
	batchEval2 := &mockBatchEvaluator{
		canBatchFunc: func(rules []*types.Rule) bool {
			return true
		},
		evaluateBatchFunc: func(ctx context.Context, rules []*types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) ([]BatchEvaluationResult, error) {
			return []BatchEvaluationResult{
				{RuleID: "rule2", Passed: false},
			}, nil
		},
	}
	engine.evaluators["type2"] = batchEval2

	req := &types.SignRequest{ID: "test-req"}

	result := engine.evaluateWhitelistBatch(context.Background(), repo.rules, req, nil)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)
}

func TestWhitelistRuleEngine_evaluateWhitelistBatch_EmptyRules(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo := &mockRuleRepository{rules: []*types.Rule{}}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)

	req := &types.SignRequest{ID: "test-req"}

	result := engine.evaluateWhitelistBatch(context.Background(), repo.rules, req, nil)
	assert.Nil(t, result)
}

func TestWhitelistRuleEngine_evaluateWhitelistBatch_NoEvaluator(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo := &mockRuleRepository{
		rules: []*types.Rule{
			{ID: "rule1", Type: "unknown_type", Mode: types.RuleModeWhitelist},
		},
	}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)

	// Don't register any evaluator

	req := &types.SignRequest{ID: "test-req"}

	result := engine.evaluateWhitelistBatch(context.Background(), repo.rules, req, nil)
	assert.Nil(t, result)
}

// =============================================================================
// Integration with EvaluateWithResult Tests
// =============================================================================

func TestWhitelistRuleEngine_EvaluateWithResult_UsesBatchEvaluation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	rule1 := &types.Rule{ID: "rule1", Name: "Rule 1", Type: "mock_type", Mode: types.RuleModeWhitelist}
	repo := &mockRuleRepository{
		rules: []*types.Rule{rule1},
	}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)

	// Track whether batch evaluation was called
	batchCalled := false

	engine.RegisterEvaluator(&mockBatchEvaluator{
		canBatchFunc: func(rules []*types.Rule) bool {
			return true
		},
		evaluateBatchFunc: func(ctx context.Context, rules []*types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) ([]BatchEvaluationResult, error) {
			batchCalled = true
			return []BatchEvaluationResult{
				{RuleID: "rule1", Passed: true, Reason: "batch allowed"},
			}, nil
		},
	})

	req := &types.SignRequest{ID: "test-req"}

	result, err := engine.EvaluateWithResult(context.Background(), req, nil)
	require.NoError(t, err)
	assert.True(t, batchCalled, "Batch evaluation should have been called")
	assert.True(t, result.Allowed)
	assert.Equal(t, "batch allowed", result.AllowReason)
}

func TestWhitelistRuleEngine_EvaluateWithResult_FallsBackToSequential(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	rule1 := &types.Rule{ID: "rule1", Name: "Rule 1", Type: "mock_type", Mode: types.RuleModeWhitelist}
	repo := &mockRuleRepository{
		rules: []*types.Rule{rule1},
	}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)

	// Track call order
	sequentialCalled := false

	// Register non-batch evaluator
	engine.RegisterEvaluator(&mockEvaluator{
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			sequentialCalled = true
			return true, "sequential allowed", nil
		},
	})

	req := &types.SignRequest{ID: "test-req"}

	result, err := engine.EvaluateWithResult(context.Background(), req, nil)
	require.NoError(t, err)
	assert.True(t, sequentialCalled, "Sequential evaluation should have been called")
	assert.True(t, result.Allowed)
	assert.Equal(t, "sequential allowed", result.AllowReason)
}

// =============================================================================
// BatchRuleEvaluator Interface Tests
// =============================================================================

func TestBatchRuleEvaluator_Interface(t *testing.T) {
	// Ensure mockBatchEvaluator implements BatchRuleEvaluator
	var _ BatchRuleEvaluator = (*mockBatchEvaluator)(nil)

	eval := &mockBatchEvaluator{}

	// Test interface methods exist
	assert.NotNil(t, eval.Type)
	assert.NotNil(t, eval.Evaluate)
	assert.NotNil(t, eval.CanBatchEvaluate)
	assert.NotNil(t, eval.EvaluateBatch)
}
