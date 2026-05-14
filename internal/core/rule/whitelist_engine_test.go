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

// ─────────────────────────────────────────────────────────────────────────────
// New / Factory
// ─────────────────────────────────────────────────────────────────────────────

func TestNewWhitelistRuleEngine_NilRepo(t *testing.T) {
	_, err := NewWhitelistRuleEngine(nil, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rule repository is required")
}

func TestNewWhitelistRuleEngine_NilLogger(t *testing.T) {
	_, err := NewWhitelistRuleEngine(&mockRuleRepository{}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

func TestNewWhitelistRuleEngine_Success(t *testing.T) {
	engine, err := NewWhitelistRuleEngine(
		&mockRuleRepository{},
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
	)
	require.NoError(t, err)
	assert.NotNil(t, engine)
}

func TestNewWhitelistRuleEngine_WithOptions(t *testing.T) {
	engine, err := NewWhitelistRuleEngine(
		&mockRuleRepository{},
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
		WithBudgetChecker(nil),
	)
	require.NoError(t, err)
	assert.NotNil(t, engine)
	assert.Nil(t, engine.budgetChecker)
}

// ─────────────────────────────────────────────────────────────────────────────
// RegisterEvaluator
// ─────────────────────────────────────────────────────────────────────────────

func TestRegisterEvaluator(t *testing.T) {
	engine, _ := NewWhitelistRuleEngine(
		&mockRuleRepository{},
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
	)

	eval := &mockEvaluator{evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
		return true, "test", nil
	}}

	engine.RegisterEvaluator(eval)
	assert.Len(t, engine.evaluators, 1)
	assert.NotNil(t, engine.evaluators["mock_type"])
}

// ─────────────────────────────────────────────────────────────────────────────
// EvaluateWithResult - nil request
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluateWithResult_NilRequest(t *testing.T) {
	engine, _ := NewWhitelistRuleEngine(
		&mockRuleRepository{},
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
	)

	_, err := engine.EvaluateWithResult(context.Background(), nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request is required")
}

// ─────────────────────────────────────────────────────────────────────────────
// EvaluateWithResult - repo error
// ─────────────────────────────────────────────────────────────────────────────

type errorRepo struct {
	mockRuleRepository
}

func (r *errorRepo) List(ctx context.Context, filter storage.RuleFilter) ([]*types.Rule, error) {
	return nil, fmt.Errorf("db connection failed")
}

func TestEvaluateWithResult_RepoError(t *testing.T) {
	engine, _ := NewWhitelistRuleEngine(
		&errorRepo{},
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
	)

	req := &types.SignRequest{
		ID:            "req-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		APIKeyID:      "key-1",
		SignType:      "transaction",
	}

	_, err := engine.EvaluateWithResult(context.Background(), req, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list rules")
}

// ─────────────────────────────────────────────────────────────────────────────
// Blocklist: violation => block immediately
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluate_BlocklistViolation(t *testing.T) {
	repo := &mockRuleRepository{
		rules: []*types.Rule{
			{
				ID:      "block-1",
				Name:    "blocker",
				Type:    "mock_type",
				Mode:    types.RuleModeBlocklist,
				Enabled: true,
			},
		},
	}
	engine, _ := NewWhitelistRuleEngine(repo, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	engine.RegisterEvaluator(&mockEvaluator{
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			return true, "value too high", nil // violated
		},
	})

	req := &types.SignRequest{
		ID:            "req-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		APIKeyID:      "key-1",
		SignType:      "transaction",
	}

	// Using Evaluate (wrapper): should return BlockedError
	_, _, err := engine.Evaluate(context.Background(), req, nil)
	assert.Error(t, err)
	var blocked *BlockedError
	assert.ErrorAs(t, err, &blocked)
	assert.Equal(t, types.RuleID("block-1"), blocked.RuleID)
	assert.Contains(t, blocked.Reason, "value too high")
}

// ─────────────────────────────────────────────────────────────────────────────
// Blocklist: no violation => proceed to whitelist
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluate_BlocklistNoViolation_WhitelistMatch(t *testing.T) {
	repo := &mockRuleRepository{
		rules: []*types.Rule{
			{
				ID:      "block-1",
				Name:    "blocker",
				Type:    "mock_block",
				Mode:    types.RuleModeBlocklist,
				Enabled: true,
			},
			{
				ID:      "allow-1",
				Name:    "allower",
				Type:    "mock_allow",
				Mode:    types.RuleModeWhitelist,
				Enabled: true,
			},
		},
	}
	engine, _ := NewWhitelistRuleEngine(repo, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	// Blocklist evaluator: no violation
	engine.RegisterEvaluator(&customTypeEvaluator{
		ruleType: "mock_block",
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			return false, "", nil // no violation
		},
	})

	// Whitelist evaluator: match
	engine.RegisterEvaluator(&customTypeEvaluator{
		ruleType: "mock_allow",
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			return true, "allowed by test", nil
		},
	})

	req := &types.SignRequest{
		ID:            "req-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		APIKeyID:      "key-1",
		SignType:      "transaction",
	}

	ruleID, reason, err := engine.Evaluate(context.Background(), req, nil)
	require.NoError(t, err)
	assert.NotNil(t, ruleID)
	assert.Equal(t, types.RuleID("allow-1"), *ruleID)
	assert.Contains(t, reason, "allowed by test")
}

// ─────────────────────────────────────────────────────────────────────────────
// Blocklist: evaluator error => Fail-Closed (reject immediately)
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluate_BlocklistEvaluatorError_FailClosed(t *testing.T) {
	repo := &mockRuleRepository{
		rules: []*types.Rule{
			{
				ID:      "block-1",
				Name:    "error blocker",
				Type:    "mock_type",
				Mode:    types.RuleModeBlocklist,
				Enabled: true,
			},
		},
	}
	engine, _ := NewWhitelistRuleEngine(repo, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	engine.RegisterEvaluator(&mockEvaluator{
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			return false, "", fmt.Errorf("evaluator crashed")
		},
	})

	req := &types.SignRequest{
		ID:            "req-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		APIKeyID:      "key-1",
		SignType:      "transaction",
	}

	_, err := engine.EvaluateWithResult(context.Background(), req, nil)
	assert.Error(t, err)
	var ruleErr *RuleEvaluationError
	assert.ErrorAs(t, err, &ruleErr)
	assert.Equal(t, types.RuleID("block-1"), ruleErr.RuleID)
}

// ─────────────────────────────────────────────────────────────────────────────
// Blocklist: missing evaluator => Fail-Closed
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluate_BlocklistMissingEvaluator_FailClosed(t *testing.T) {
	repo := &mockRuleRepository{
		rules: []*types.Rule{
			{
				ID:      "block-1",
				Name:    "missing eval",
				Type:    "unknown_type",
				Mode:    types.RuleModeBlocklist,
				Enabled: true,
			},
		},
	}
	engine, _ := NewWhitelistRuleEngine(repo, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	// Don't register any evaluator

	req := &types.SignRequest{
		ID:            "req-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		APIKeyID:      "key-1",
		SignType:      "transaction",
	}

	_, err := engine.EvaluateWithResult(context.Background(), req, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no evaluator registered")
}

// ─────────────────────────────────────────────────────────────────────────────
// Whitelist: evaluator error => Fail-Open (skip to next)
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluate_WhitelistEvaluatorError_FailOpen(t *testing.T) {
	repo := &mockRuleRepository{
		rules: []*types.Rule{
			{
				ID:      "allow-err",
				Name:    "error rule",
				Type:    "mock_err",
				Mode:    types.RuleModeWhitelist,
				Enabled: true,
			},
			{
				ID:      "allow-ok",
				Name:    "good rule",
				Type:    "mock_ok",
				Mode:    types.RuleModeWhitelist,
				Enabled: true,
			},
		},
	}
	engine, _ := NewWhitelistRuleEngine(repo, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	engine.RegisterEvaluator(&customTypeEvaluator{
		ruleType: "mock_err",
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			return false, "", fmt.Errorf("evaluator crashed")
		},
	})
	engine.RegisterEvaluator(&customTypeEvaluator{
		ruleType: "mock_ok",
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			return true, "allowed", nil
		},
	})

	req := &types.SignRequest{
		ID:            "req-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		APIKeyID:      "key-1",
		SignType:      "transaction",
	}

	ruleID, _, err := engine.Evaluate(context.Background(), req, nil)
	require.NoError(t, err)
	assert.NotNil(t, ruleID)
	assert.Equal(t, types.RuleID("allow-ok"), *ruleID)
}

// ─────────────────────────────────────────────────────────────────────────────
// Whitelist: missing evaluator => Fail-Open (skip)
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluate_WhitelistMissingEvaluator_FailOpen(t *testing.T) {
	repo := &mockRuleRepository{
		rules: []*types.Rule{
			{
				ID:      "allow-1",
				Name:    "no eval",
				Type:    "unknown_type",
				Mode:    types.RuleModeWhitelist,
				Enabled: true,
			},
		},
	}
	engine, _ := NewWhitelistRuleEngine(repo, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	req := &types.SignRequest{
		ID:            "req-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		APIKeyID:      "key-1",
		SignType:      "transaction",
	}

	// Should not error, just no match → manual approval
	ruleID, _, err := engine.Evaluate(context.Background(), req, nil)
	require.NoError(t, err)
	assert.Nil(t, ruleID, "no match => nil ruleID")
}

// ─────────────────────────────────────────────────────────────────────────────
// No rules => no match, manual approval
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluate_NoRules(t *testing.T) {
	repo := &mockRuleRepository{rules: []*types.Rule{}}
	engine, _ := NewWhitelistRuleEngine(repo, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	req := &types.SignRequest{
		ID:            "req-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		APIKeyID:      "key-1",
		SignType:      "transaction",
	}

	result, err := engine.EvaluateWithResult(context.Background(), req, nil)
	require.NoError(t, err)
	assert.False(t, result.Blocked)
	assert.False(t, result.Allowed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Whitelist: no match => manual approval needed
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluate_WhitelistNoMatch(t *testing.T) {
	repo := &mockRuleRepository{
		rules: []*types.Rule{
			{
				ID:      "allow-1",
				Name:    "no match rule",
				Type:    "mock_type",
				Mode:    types.RuleModeWhitelist,
				Enabled: true,
			},
		},
	}
	engine, _ := NewWhitelistRuleEngine(repo, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	engine.RegisterEvaluator(&mockEvaluator{
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			return false, "not matching", nil
		},
	})

	req := &types.SignRequest{
		ID:            "req-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		APIKeyID:      "key-1",
		SignType:      "transaction",
	}

	result, err := engine.EvaluateWithResult(context.Background(), req, nil)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.False(t, result.Blocked)
}

// TestEvaluate_WhitelistNoMatch_ViaEvaluate tests Evaluate() wrapper on no-match path
func TestEvaluate_WhitelistNoMatch_ViaEvaluate(t *testing.T) {
	repo := &mockRuleRepository{rules: []*types.Rule{}}
	engine, _ := NewWhitelistRuleEngine(repo, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	req := &types.SignRequest{
		ID:        "req-1",
		ChainType: types.ChainTypeEVM,
		SignType:  "transaction",
	}
	ruleID, reason, err := engine.Evaluate(context.Background(), req, nil)
	assert.NoError(t, err, "no match should not return error")
	assert.Nil(t, ruleID, "no match should return nil rule ID")
	assert.Empty(t, reason, "no match should return empty reason")
}

// ─────────────────────────────────────────────────────────────────────────────
// ruleScopeMatches
// ─────────────────────────────────────────────────────────────────────────────

func TestRuleScopeMatches(t *testing.T) {
	evm := types.ChainTypeEVM
	solana := types.ChainTypeSolana
	chain1 := "1"
	chain137 := "137"
	signer1 := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	signer2 := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

	req := &types.SignRequest{
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		APIKeyID:      "key-1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
	}

	tests := []struct {
		name  string
		rule  *types.Rule
		match bool
	}{
		{"nil scope matches all", &types.Rule{}, true},
		{"match chain type", &types.Rule{ChainType: &evm}, true},
		{"mismatch chain type", &types.Rule{ChainType: &solana}, false},
		{"match chain ID", &types.Rule{ChainID: &chain1}, true},
		{"mismatch chain ID", &types.Rule{ChainID: &chain137}, false},
		{"match signer", &types.Rule{SignerAddress: &signer1}, true},
		{"mismatch signer", &types.Rule{SignerAddress: &signer2}, false},
		{"case-insensitive signer match", &types.Rule{SignerAddress: strPtr("0xF39FD6E51AAD88F6F4CE6AB8827279CFFFB92266")}, true},
		{"all fields match", &types.Rule{ChainType: &evm, ChainID: &chain1, SignerAddress: &signer1}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.match, ruleScopeMatches(tc.rule, req))
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Delegation: single mode
// ─────────────────────────────────────────────────────────────────────────────

// delegationEvaluator implements EvaluatorWithDelegation for testing
type delegationEvaluator struct {
	ruleType       types.RuleType
	matched        bool
	reason         string
	delegation     *DelegationRequest
	err            error
}

func (d *delegationEvaluator) Type() types.RuleType { return d.ruleType }

func (d *delegationEvaluator) Evaluate(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
	return d.matched, d.reason, d.err
}

func (d *delegationEvaluator) EvaluateWithDelegation(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, *DelegationRequest, error) {
	return d.matched, d.reason, d.delegation, d.err
}

func TestDelegation_Single_Success(t *testing.T) {
	// Parent rule delegates to target rule
	targetRule := &types.Rule{
		ID:      "target-1",
		Name:    "target",
		Type:    "mock_target",
		Mode:    types.RuleModeWhitelist,
		Enabled: true,
	}
	parentRule := &types.Rule{
		ID:      "parent-1",
		Name:    "parent",
		Type:    "mock_parent",
		Mode:    types.RuleModeWhitelist,
		Enabled: true,
	}

	repo := &mockRuleRepository{rules: []*types.Rule{parentRule, targetRule}}

	engine, _ := NewWhitelistRuleEngine(
		repo,
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
		WithDelegationPayloadConverter(func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error) {
			return &types.SignRequest{
				ChainType:     types.ChainTypeEVM,
				ChainID:       "1",
				SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				SignType:      "transaction",
			}, &types.ParsedPayload{}, nil
		}),
	)

	// Parent delegates to target
	engine.RegisterEvaluator(&delegationEvaluator{
		ruleType: "mock_parent",
		matched:  true,
		reason:   "parent matched",
		delegation: &DelegationRequest{
			TargetRuleIDs: []types.RuleID{"target-1"},
			Mode:          "single",
			Payload:       map[string]interface{}{"test": true},
		},
	})

	// Target allows
	engine.RegisterEvaluator(&customTypeEvaluator{
		ruleType: "mock_target",
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			return true, "target allows", nil
		},
	})

	req := &types.SignRequest{
		ID:            "req-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		APIKeyID:      "key-1",
		SignType:      "transaction",
	}

	result, err := engine.EvaluateWithResult(context.Background(), req, nil)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, types.RuleID("parent-1"), result.AllowedBy.ID) // AllowedBy is the parent
}

// ─────────────────────────────────────────────────────────────────────────────
// Delegation: max depth exceeded
// ─────────────────────────────────────────────────────────────────────────────

func TestDelegation_MaxDepth(t *testing.T) {
	parentRule := &types.Rule{
		ID:      "parent-1",
		Name:    "parent",
		Type:    "mock_parent",
		Mode:    types.RuleModeWhitelist,
		Enabled: true,
	}

	repo := &mockRuleRepository{rules: []*types.Rule{parentRule}}

	engine, _ := NewWhitelistRuleEngine(
		repo,
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
		WithDelegationPayloadConverter(func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error) {
			return &types.SignRequest{}, &types.ParsedPayload{}, nil
		}),
	)

	engine.RegisterEvaluator(&delegationEvaluator{
		ruleType: "mock_parent",
		matched:  true,
		reason:   "matched",
		delegation: &DelegationRequest{
			TargetRuleIDs: []types.RuleID{"target-1"},
			Mode:          "single",
			Payload:       map[string]interface{}{},
		},
	})

	req := &types.SignRequest{
		ID:            "req-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		APIKeyID:      "key-1",
		SignType:      "transaction",
	}

	// Set depth at max in context
	ctx := withDelegationCtx(context.Background(), DelegationMaxDepth, nil)
	result, err := engine.resolveDelegation(ctx, req, parentRule, &DelegationRequest{
		TargetRuleIDs: []types.RuleID{"target-1"},
		Mode:          "single",
		Payload:       map[string]interface{}{},
	})
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.NoMatchReason, "max depth exceeded")
}

// ─────────────────────────────────────────────────────────────────────────────
// Delegation: cycle detection
// ─────────────────────────────────────────────────────────────────────────────

func TestDelegation_CycleDetected(t *testing.T) {
	targetRule := &types.Rule{
		ID:      "target-1",
		Name:    "target",
		Type:    "mock_target",
		Mode:    types.RuleModeWhitelist,
		Enabled: true,
	}
	parentRule := &types.Rule{
		ID:      "parent-1",
		Name:    "parent",
		Type:    "mock_parent",
		Mode:    types.RuleModeWhitelist,
		Enabled: true,
	}
	repo := &mockRuleRepository{rules: []*types.Rule{parentRule, targetRule}}

	engine, _ := NewWhitelistRuleEngine(
		repo,
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
		WithDelegationPayloadConverter(func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error) {
			return &types.SignRequest{ChainType: types.ChainTypeEVM}, &types.ParsedPayload{}, nil
		}),
	)
	engine.RegisterEvaluator(&customTypeEvaluator{ruleType: "mock_target"})

	// Already visited target-1
	ctx := withDelegationCtx(context.Background(), 0, map[types.RuleID]bool{"target-1": true})
	result, err := engine.resolveDelegation(ctx, &types.SignRequest{
		ChainType:     types.ChainTypeEVM,
		APIKeyID:      "k",
		SignerAddress: "0x0",
	}, parentRule, &DelegationRequest{
		TargetRuleIDs: []types.RuleID{"target-1"},
		Mode:          "single",
		Payload:       map[string]interface{}{},
	})
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.NoMatchReason, "cycle")
}

// ─────────────────────────────────────────────────────────────────────────────
// Delegation: no converter set
// ─────────────────────────────────────────────────────────────────────────────

func TestDelegation_NoConverter(t *testing.T) {
	parentRule := &types.Rule{ID: "p", Type: "t", Mode: types.RuleModeWhitelist}
	repo := &mockRuleRepository{rules: []*types.Rule{parentRule}}
	engine, _ := NewWhitelistRuleEngine(repo, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	result, err := engine.resolveDelegation(context.Background(), &types.SignRequest{}, parentRule, &DelegationRequest{
		TargetRuleIDs: []types.RuleID{"target-1"},
		Mode:          "single",
		Payload:       map[string]interface{}{},
	})
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.NoMatchReason, "converter not set")
}

// ─────────────────────────────────────────────────────────────────────────────
// Delegation: empty targets
// ─────────────────────────────────────────────────────────────────────────────

func TestDelegation_EmptyTargets(t *testing.T) {
	parentRule := &types.Rule{ID: "p", Type: "t", Mode: types.RuleModeWhitelist}
	repo := &mockRuleRepository{rules: []*types.Rule{parentRule}}
	engine, _ := NewWhitelistRuleEngine(repo, slog.New(slog.NewTextHandler(os.Stderr, nil)),
		WithDelegationPayloadConverter(func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error) {
			return &types.SignRequest{}, nil, nil
		}),
	)

	result, err := engine.resolveDelegation(context.Background(), &types.SignRequest{}, parentRule, &DelegationRequest{
		TargetRuleIDs: []types.RuleID{},
		Mode:          "single",
		Payload:       map[string]interface{}{},
	})
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.NoMatchReason, "no target")
}

// ─────────────────────────────────────────────────────────────────────────────
// Delegation: per_item mode
// ─────────────────────────────────────────────────────────────────────────────

func TestDelegation_PerItem_Success(t *testing.T) {
	targetRule := &types.Rule{
		ID: "target-1", Name: "target", Type: "mock_target",
		Mode: types.RuleModeWhitelist, Enabled: true,
	}
	parentRule := &types.Rule{
		ID: "parent-1", Name: "parent", Type: "mock_parent",
		Mode: types.RuleModeWhitelist, Enabled: true,
	}
	repo := &mockRuleRepository{rules: []*types.Rule{parentRule, targetRule}}

	engine, _ := NewWhitelistRuleEngine(
		repo,
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
		WithDelegationPayloadConverter(func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error) {
			return &types.SignRequest{ChainType: types.ChainTypeEVM}, &types.ParsedPayload{}, nil
		}),
	)
	engine.RegisterEvaluator(&customTypeEvaluator{
		ruleType: "mock_target",
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			return true, "target allows", nil
		},
	})

	result, err := engine.resolveDelegation(context.Background(), &types.SignRequest{APIKeyID: "k"}, parentRule, &DelegationRequest{
		TargetRuleIDs: []types.RuleID{"target-1"},
		Mode:          "per_item",
		Payload: map[string]interface{}{
			"items": []interface{}{
				map[string]interface{}{"x": 1},
				map[string]interface{}{"x": 2},
			},
		},
		ItemsKey: "items",
	})
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestDelegation_PerItem_OneItemFails(t *testing.T) {
	targetRule := &types.Rule{
		ID: "target-1", Name: "target", Type: "mock_target",
		Mode: types.RuleModeWhitelist, Enabled: true,
	}
	parentRule := &types.Rule{
		ID: "parent-1", Name: "parent", Type: "mock_parent",
		Mode: types.RuleModeWhitelist, Enabled: true,
	}
	repo := &mockRuleRepository{rules: []*types.Rule{parentRule, targetRule}}

	callCount := 0
	engine, _ := NewWhitelistRuleEngine(
		repo,
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
		WithDelegationPayloadConverter(func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error) {
			return &types.SignRequest{ChainType: types.ChainTypeEVM}, &types.ParsedPayload{}, nil
		}),
	)
	engine.RegisterEvaluator(&customTypeEvaluator{
		ruleType: "mock_target",
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			callCount++
			if callCount == 2 {
				return false, "second item rejected", nil
			}
			return true, "ok", nil
		},
	})

	result, err := engine.resolveDelegation(context.Background(), &types.SignRequest{APIKeyID: "k"}, parentRule, &DelegationRequest{
		TargetRuleIDs: []types.RuleID{"target-1"},
		Mode:          "per_item",
		Payload: map[string]interface{}{
			"items": []interface{}{
				map[string]interface{}{"x": 1},
				map[string]interface{}{"x": 2},
			},
		},
		ItemsKey: "items",
	})
	require.NoError(t, err)
	assert.False(t, result.Allowed, "should fail when one item fails")
}

// ─────────────────────────────────────────────────────────────────────────────
// delegationItems
// ─────────────────────────────────────────────────────────────────────────────

func TestDelegationItems(t *testing.T) {
	tests := []struct {
		name     string
		payload  interface{}
		key      string
		wantErr  bool
		wantLen  int
	}{
		{"nil payload", nil, "items", true, 0},
		{"empty key", map[string]interface{}{"items": []interface{}{}}, "", true, 0},
		{"not a map", "string payload", "items", true, 0},
		{"key not found", map[string]interface{}{}, "items", true, 0},
		{"not an array", map[string]interface{}{"items": "not array"}, "items", true, 0},
		{"empty array", map[string]interface{}{"items": []interface{}{}}, "items", false, 0},
		{"two items", map[string]interface{}{"items": []interface{}{"a", "b"}}, "items", false, 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			items, err := delegationItems(tc.payload, tc.key)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, items, tc.wantLen)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Delegation: unknown mode
// ─────────────────────────────────────────────────────────────────────────────

func TestDelegation_UnknownMode(t *testing.T) {
	parentRule := &types.Rule{ID: "p", Type: "t", Mode: types.RuleModeWhitelist}
	repo := &mockRuleRepository{rules: []*types.Rule{parentRule}}
	engine, _ := NewWhitelistRuleEngine(repo, slog.New(slog.NewTextHandler(os.Stderr, nil)),
		WithDelegationPayloadConverter(func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error) {
			return &types.SignRequest{}, nil, nil
		}),
	)

	result, err := engine.resolveDelegation(context.Background(), &types.SignRequest{}, parentRule, &DelegationRequest{
		TargetRuleIDs: []types.RuleID{"t"},
		Mode:          "unknown_mode",
		Payload:       map[string]interface{}{},
	})
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.NoMatchReason, "unknown mode")
}

// ─────────────────────────────────────────────────────────────────────────────
// Delegation: missing target fails immediately (no fallback)
// ─────────────────────────────────────────────────────────────────────────────

// TestDelegation_MissingTargetFailsImmediately verifies that when a delegation target
// rule is not found, the engine returns Allowed: false immediately with no fallback
// to the next target. This tests that "missing-id,real-id" fails on missing-id without
// ever reaching real-id.
func TestDelegation_MissingTargetFailsImmediately(t *testing.T) {
	realTargetRule := &types.Rule{
		ID:      "real-target",
		Name:    "real target",
		Type:    "mock_target",
		Mode:    types.RuleModeWhitelist,
		Enabled: true,
	}
	parentRule := &types.Rule{
		ID:      "parent-1",
		Name:    "parent",
		Type:    "mock_parent",
		Mode:    types.RuleModeWhitelist,
		Enabled: true,
	}

	repo := &mockRuleRepository{rules: []*types.Rule{parentRule, realTargetRule}}

	engine, _ := NewWhitelistRuleEngine(
		repo,
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
		WithDelegationPayloadConverter(func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error) {
			return &types.SignRequest{
				ChainType:     types.ChainTypeEVM,
				ChainID:       "1",
				SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				SignType:      "transaction",
			}, &types.ParsedPayload{}, nil
		}),
	)

	// resolveDelegation directly: "missing-id" first, then "real-target"
	result, err := engine.resolveDelegation(context.Background(), &types.SignRequest{
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		SignType:      "transaction",
	}, parentRule, &DelegationRequest{
		TargetRuleIDs: []types.RuleID{"missing-id", "real-target"},
		Mode:          "single",
		Payload:       map[string]interface{}{"test": true},
	})
	require.NoError(t, err)
	assert.False(t, result.Allowed, "should be denied when delegation target is missing")
	assert.Contains(t, result.NoMatchReason, "delegation target rule not found")
	assert.Contains(t, result.NoMatchReason, "missing-id")
}

// TestDelegation_MissingTargetFailsImmediately_PerItem verifies the same no-fallback
// behavior in per_item delegation mode.
func TestDelegation_MissingTargetFailsImmediately_PerItem(t *testing.T) {
	realTargetRule := &types.Rule{
		ID:      "real-target",
		Name:    "real target",
		Type:    "mock_target",
		Mode:    types.RuleModeWhitelist,
		Enabled: true,
	}
	parentRule := &types.Rule{
		ID:      "parent-1",
		Name:    "parent",
		Type:    "mock_parent",
		Mode:    types.RuleModeWhitelist,
		Enabled: true,
	}

	repo := &mockRuleRepository{rules: []*types.Rule{parentRule, realTargetRule}}

	engine, _ := NewWhitelistRuleEngine(
		repo,
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
		WithDelegationPayloadConverter(func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error) {
			return &types.SignRequest{
				ChainType:     types.ChainTypeEVM,
				ChainID:       "1",
				SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				SignType:      "transaction",
			}, &types.ParsedPayload{}, nil
		}),
	)

	result, err := engine.resolveDelegation(context.Background(), &types.SignRequest{
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		SignType:      "transaction",
	}, parentRule, &DelegationRequest{
		TargetRuleIDs: []types.RuleID{"missing-id", "real-target"},
		Mode:          "per_item",
		Payload:       map[string]interface{}{"items": []interface{}{map[string]interface{}{"val": 1}}},
		ItemsKey:      "items",
	})
	require.NoError(t, err)
	assert.False(t, result.Allowed, "should be denied when delegation target is missing in per_item mode")
	assert.Contains(t, result.NoMatchReason, "delegation target rule not found")
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// customTypeEvaluator is a mock evaluator with configurable rule type
type customTypeEvaluator struct {
	ruleType     types.RuleType
	evaluateFunc func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error)
}

func (c *customTypeEvaluator) Type() types.RuleType { return c.ruleType }

func (c *customTypeEvaluator) Evaluate(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
	if c.evaluateFunc != nil {
		return c.evaluateFunc(ctx, rule, req, parsed)
	}
	return false, "", nil
}

func strPtr(s string) *string { return &s }
