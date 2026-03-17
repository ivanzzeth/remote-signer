package rule

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// FilterRulesForCaller unit tests
// ─────────────────────────────────────────────────────────────────────────────

func TestFilterRulesForCaller_WildcardMatchesAnyCaller(t *testing.T) {
	rule := &types.Rule{
		ID:        "r1",
		Status:    types.RuleStatusActive,
		AppliedTo: pq.StringArray{"*"},
		Owner:     "config",
	}
	result := FilterRulesForCaller([]*types.Rule{rule}, "any-key")
	require.Len(t, result, 1)
	assert.Equal(t, types.RuleID("r1"), result[0].ID)
}

func TestFilterRulesForCaller_SelfMatchesOwner(t *testing.T) {
	rule := &types.Rule{
		ID:        "r2",
		Status:    types.RuleStatusActive,
		AppliedTo: pq.StringArray{"self"},
		Owner:     "agent-K",
	}

	// Owner matches caller
	result := FilterRulesForCaller([]*types.Rule{rule}, "agent-K")
	require.Len(t, result, 1)

	// Different caller does NOT match
	result = FilterRulesForCaller([]*types.Rule{rule}, "agent-J")
	require.Len(t, result, 0)
}

func TestFilterRulesForCaller_ExplicitKeyMatch(t *testing.T) {
	rule := &types.Rule{
		ID:        "r3",
		Status:    types.RuleStatusActive,
		AppliedTo: pq.StringArray{"agent-K"},
		Owner:     "admin",
	}

	// Matches caller K
	result := FilterRulesForCaller([]*types.Rule{rule}, "agent-K")
	require.Len(t, result, 1)

	// Does NOT match caller J
	result = FilterRulesForCaller([]*types.Rule{rule}, "agent-J")
	require.Len(t, result, 0)
}

func TestFilterRulesForCaller_InactiveStatusExcluded(t *testing.T) {
	statuses := []types.RuleStatus{
		types.RuleStatusPendingApproval,
		types.RuleStatusRejected,
		types.RuleStatusRevoked,
	}
	for _, status := range statuses {
		rule := &types.Rule{
			ID:        "r4",
			Status:    status,
			AppliedTo: pq.StringArray{"*"},
			Owner:     "config",
		}
		result := FilterRulesForCaller([]*types.Rule{rule}, "any-key")
		assert.Len(t, result, 0, "status=%s should be excluded", status)
	}
}

func TestFilterRulesForCaller_EmptyCallerOnlyGlobal(t *testing.T) {
	global := &types.Rule{
		ID: "global", Status: types.RuleStatusActive,
		AppliedTo: pq.StringArray{"*"}, Owner: "config",
	}
	selfRule := &types.Rule{
		ID: "self-rule", Status: types.RuleStatusActive,
		AppliedTo: pq.StringArray{"self"}, Owner: "agent-K",
	}
	explicit := &types.Rule{
		ID: "explicit", Status: types.RuleStatusActive,
		AppliedTo: pq.StringArray{"agent-K"}, Owner: "admin",
	}
	result := FilterRulesForCaller([]*types.Rule{global, selfRule, explicit}, "")
	require.Len(t, result, 1)
	assert.Equal(t, types.RuleID("global"), result[0].ID)
}

func TestFilterRulesForCaller_MultipleAppliedTo(t *testing.T) {
	rule := &types.Rule{
		ID:        "r5",
		Status:    types.RuleStatusActive,
		AppliedTo: pq.StringArray{"agent-A", "agent-B"},
		Owner:     "admin",
	}

	result := FilterRulesForCaller([]*types.Rule{rule}, "agent-A")
	require.Len(t, result, 1)

	result = FilterRulesForCaller([]*types.Rule{rule}, "agent-B")
	require.Len(t, result, 1)

	result = FilterRulesForCaller([]*types.Rule{rule}, "agent-C")
	require.Len(t, result, 0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration: Blocklist evaluated before whitelist with scoping
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluate_BlocklistBeforeWhitelist_WithScoping(t *testing.T) {
	// Admin blocklist (global) + agent whitelist (self-scoped)
	// Admin blocklist must win.
	ct := types.ChainTypeEVM
	adminBlocklist := &types.Rule{
		ID:        "admin-blocklist",
		Name:      "Block Bad Address",
		Type:      "mock_type",
		Mode:      types.RuleModeBlocklist,
		ChainType: &ct,
		Owner:     "config",
		AppliedTo: pq.StringArray{"*"},
		Status:    types.RuleStatusActive,
		Enabled:   true,
	}
	agentWhitelist := &types.Rule{
		ID:        "agent-whitelist",
		Name:      "Allow All",
		Type:      "mock_type",
		Mode:      types.RuleModeWhitelist,
		ChainType: &ct,
		Owner:     "agent-K",
		AppliedTo: pq.StringArray{"self"},
		Status:    types.RuleStatusActive,
		Enabled:   true,
	}

	repo := &mockRuleRepository{rules: []*types.Rule{adminBlocklist, agentWhitelist}}
	engine, err := NewWhitelistRuleEngine(repo, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NoError(t, err)

	// Blocklist evaluator returns "violated"
	eval := &mockEvaluator{
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			if rule.Mode == types.RuleModeBlocklist {
				return true, "blocked by admin", nil
			}
			return true, "allowed", nil
		},
	}
	engine.RegisterEvaluator(eval)
	engine.Seal()

	req := &types.SignRequest{
		ID:        "req-1",
		APIKeyID:  "agent-K",
		ChainType: types.ChainTypeEVM,
	}

	result, err := engine.EvaluateWithResult(context.Background(), req, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Blocked, "admin blocklist must win over agent whitelist")
	assert.Equal(t, types.RuleID("admin-blocklist"), result.BlockedBy.ID)
}

func TestEvaluate_AgentSelfRuleNotVisibleToOtherAgent(t *testing.T) {
	ct := types.ChainTypeEVM
	agentARule := &types.Rule{
		ID:        "agent-a-rule",
		Name:      "Agent A Whitelist",
		Type:      "mock_type",
		Mode:      types.RuleModeWhitelist,
		ChainType: &ct,
		Owner:     "agent-A",
		AppliedTo: pq.StringArray{"self"},
		Status:    types.RuleStatusActive,
		Enabled:   true,
	}

	repo := &mockRuleRepository{rules: []*types.Rule{agentARule}}
	engine, err := NewWhitelistRuleEngine(repo, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NoError(t, err)

	eval := &mockEvaluator{
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			return true, "allowed", nil
		},
	}
	engine.RegisterEvaluator(eval)
	engine.Seal()

	// Agent B should not see Agent A's self-scoped rule
	req := &types.SignRequest{
		ID:        "req-2",
		APIKeyID:  "agent-B",
		ChainType: types.ChainTypeEVM,
	}

	result, err := engine.EvaluateWithResult(context.Background(), req, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed, "agent-B should not match agent-A's self-scoped rule")
	assert.False(t, result.Blocked)
}

func TestEvaluate_PendingRuleNotEvaluated(t *testing.T) {
	ct := types.ChainTypeEVM
	pendingRule := &types.Rule{
		ID:        "pending-rule",
		Name:      "Pending Whitelist",
		Type:      "mock_type",
		Mode:      types.RuleModeWhitelist,
		ChainType: &ct,
		Owner:     "agent-K",
		AppliedTo: pq.StringArray{"self"},
		Status:    types.RuleStatusPendingApproval,
		Enabled:   true,
	}

	repo := &mockRuleRepository{rules: []*types.Rule{pendingRule}}
	engine, err := NewWhitelistRuleEngine(repo, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NoError(t, err)

	eval := &mockEvaluator{
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			t.Fatal("pending rule should not be evaluated")
			return true, "should not reach", nil
		},
	}
	engine.RegisterEvaluator(eval)
	engine.Seal()

	req := &types.SignRequest{
		ID:        "req-3",
		APIKeyID:  "agent-K",
		ChainType: types.ChainTypeEVM,
	}

	result, err := engine.EvaluateWithResult(context.Background(), req, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed, "pending rule should not allow requests")
}

func TestEvaluate_GlobalRuleMatchesAllCallers(t *testing.T) {
	ct := types.ChainTypeEVM
	globalRule := &types.Rule{
		ID:        "global-rule",
		Name:      "Global Whitelist",
		Type:      "mock_type",
		Mode:      types.RuleModeWhitelist,
		ChainType: &ct,
		Owner:     "config",
		AppliedTo: pq.StringArray{"*"},
		Status:    types.RuleStatusActive,
		Enabled:   true,
	}

	repo := &mockRuleRepository{rules: []*types.Rule{globalRule}}
	engine, err := NewWhitelistRuleEngine(repo, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NoError(t, err)

	eval := &mockEvaluator{
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			return true, "allowed by global rule", nil
		},
	}
	engine.RegisterEvaluator(eval)
	engine.Seal()

	callers := []string{"agent-A", "agent-B", "strategy-X", "admin"}
	for _, caller := range callers {
		req := &types.SignRequest{
			ID:        types.SignRequestID("req-" + caller),
			APIKeyID:  caller,
			ChainType: types.ChainTypeEVM,
		}
		result, err := engine.EvaluateWithResult(context.Background(), req, nil)
		require.NoError(t, err, "caller=%s", caller)
		require.NotNil(t, result, "caller=%s", caller)
		assert.True(t, result.Allowed, "global rule should allow caller=%s", caller)
	}
}

func TestEvaluate_ExplicitKeyTargeting(t *testing.T) {
	ct := types.ChainTypeEVM
	targetedRule := &types.Rule{
		ID:        "targeted-rule",
		Name:      "For Agent K Only",
		Type:      "mock_type",
		Mode:      types.RuleModeWhitelist,
		ChainType: &ct,
		Owner:     "admin",
		AppliedTo: pq.StringArray{"agent-K"},
		Status:    types.RuleStatusActive,
		Enabled:   true,
	}

	repo := &mockRuleRepository{rules: []*types.Rule{targetedRule}}
	engine, err := NewWhitelistRuleEngine(repo, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NoError(t, err)

	eval := &mockEvaluator{
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			return true, "allowed", nil
		},
	}
	engine.RegisterEvaluator(eval)
	engine.Seal()

	// agent-K should match
	reqK := &types.SignRequest{ID: "req-K", APIKeyID: "agent-K", ChainType: types.ChainTypeEVM}
	resultK, err := engine.EvaluateWithResult(context.Background(), reqK, nil)
	require.NoError(t, err)
	assert.True(t, resultK.Allowed, "agent-K should match targeted rule")

	// agent-J should NOT match
	reqJ := &types.SignRequest{ID: "req-J", APIKeyID: "agent-J", ChainType: types.ChainTypeEVM}
	resultJ, err := engine.EvaluateWithResult(context.Background(), reqJ, nil)
	require.NoError(t, err)
	assert.False(t, resultJ.Allowed, "agent-J should not match targeted rule")
}
