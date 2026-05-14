package rule

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

func TestAddDelegationTargets_DirectChain(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	repo := storage.NewMemoryRuleRepository()
	allRulesMap := make(map[types.RuleID]*types.Rule)

	// Create delegate_to target rule
	targetRule := &types.Rule{
		ID:          "target-1",
		Name:        "Target Rule",
		Type:        types.RuleTypeEVMAddressList,
		Mode:        types.RuleModeWhitelist,
		Enabled:     true,
		Config:      json.RawMessage(`{"addresses":["0x123"]}`),
		ChainType:   ptr(types.ChainTypeEVM),
	}
	allRulesMap[targetRule.ID] = targetRule

	// Create delegating rule that delegates to target-1
	delegatingRule := &types.Rule{
		ID:          "delegator-1",
		Name:        "Delegating Rule",
		Type:        types.RuleTypeEVMJS,
		Mode:        types.RuleModeWhitelist,
		Enabled:     true,
		Config:      json.RawMessage(`{"delegate_to":"target-1"}`),
		ChainType:   ptr(types.ChainTypeEVM),
	}

	visited := make(map[types.RuleID]bool)
	err := AddDelegationTargets(ctx, delegatingRule, allRulesMap, repo, visited, log)
	if err != nil {
		t.Fatalf("AddDelegationTargets failed: %v", err)
	}

	// Verify target was added to the repo with Enabled=false
	stored, err := repo.Get(ctx, targetRule.ID)
	if err != nil {
		t.Fatalf("failed to get target rule from repo: %v", err)
	}
	if stored == nil {
		t.Fatal("target rule not found in repo")
	}
	if stored.Enabled {
		t.Error("target rule should have Enabled=false when added for delegation")
	}
}

func TestAddDelegationTargets_NoDelegationConfig(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	repo := storage.NewMemoryRuleRepository()
	allRulesMap := make(map[types.RuleID]*types.Rule)

	rule := &types.Rule{
		ID:        "no-delegate",
		Name:      "No Delegation Rule",
		Type:      types.RuleTypeEVMAddressList,
		Mode:      types.RuleModeWhitelist,
		Enabled:   true,
		Config:    json.RawMessage(`{"addresses":["0x456"]}`),
		ChainType: ptr(types.ChainTypeEVM),
	}

	visited := make(map[types.RuleID]bool)
	err := AddDelegationTargets(ctx, rule, allRulesMap, repo, visited, log)
	if err != nil {
		t.Fatalf("AddDelegationTargets failed: %v", err)
	}

	// Repo should remain empty since there was no delegate_to
	rules, err := repo.List(ctx, storage.RuleFilter{EnabledOnly: false, Limit: 100})
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules in repo, got %d", len(rules))
	}
}

func TestAddDelegationTargets_RecursiveChain(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	repo := storage.NewMemoryRuleRepository()
	allRulesMap := make(map[types.RuleID]*types.Rule)

	// Level 3
	rule3 := &types.Rule{
		ID:   "rule-3",
		Name: "Rule 3",
		Type: types.RuleTypeEVMAddressList,
		Mode: types.RuleModeWhitelist, Config: json.RawMessage(`{"addresses":["0x789"]}`),
		ChainType: ptr(types.ChainTypeEVM),
	}
	allRulesMap[rule3.ID] = rule3

	// Level 2 → delegates to rule-3
	rule2 := &types.Rule{
		ID:   "rule-2",
		Name: "Rule 2",
		Type: types.RuleTypeEVMJS, Mode: types.RuleModeWhitelist,
		Config:    json.RawMessage(`{"delegate_to":"rule-3"}`),
		ChainType: ptr(types.ChainTypeEVM),
	}
	allRulesMap[rule2.ID] = rule2

	// Level 1 → delegates to rule-2
	rule1 := &types.Rule{
		ID:   "rule-1",
		Name: "Rule 1",
		Type: types.RuleTypeEVMJS, Mode: types.RuleModeWhitelist,
		Config:    json.RawMessage(`{"delegate_to":"rule-2"}`),
		ChainType: ptr(types.ChainTypeEVM),
	}

	visited := make(map[types.RuleID]bool)
	err := AddDelegationTargets(ctx, rule1, allRulesMap, repo, visited, log)
	if err != nil {
		t.Fatalf("AddDelegationTargets failed: %v", err)
	}

	// Both rule-2 and rule-3 should be in the repo
	for _, id := range []types.RuleID{"rule-2", "rule-3"} {
		stored, err := repo.Get(ctx, id)
		if err != nil {
			t.Fatalf("failed to get %s: %v", id, err)
		}
		if stored == nil {
			t.Fatalf("expected %s to be in repo", id)
		}
		if stored.Enabled {
			t.Errorf("delegation target %s should have Enabled=false", id)
		}
	}
}

func TestAddDelegationTargets_NonexistentTarget(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	repo := storage.NewMemoryRuleRepository()
	allRulesMap := make(map[types.RuleID]*types.Rule)

	rule := &types.Rule{
		ID:   "delegator",
		Name: "Delegating Rule",
		Type: types.RuleTypeEVMJS, Mode: types.RuleModeWhitelist,
		Config:    json.RawMessage(`{"delegate_to":"nonexistent"}`),
		ChainType: ptr(types.ChainTypeEVM),
	}

	visited := make(map[types.RuleID]bool)
	err := AddDelegationTargets(ctx, rule, allRulesMap, repo, visited, log)
	if err == nil {
		t.Fatal("expected error for non-existent delegate_to target")
	}
	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}
}

func TestBuildIsolatedEngine_Basic(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	allRulesMap := make(map[types.RuleID]*types.Rule)

	// Blocklist rule
	blocklistRule := &types.Rule{
		ID:        "block-1",
		Name:      "Blocklist",
		Type:      types.RuleTypeEVMAddressList,
		Mode:      types.RuleModeBlocklist,
		Enabled:   true,
		Config:    json.RawMessage(`{"addresses":["0xblock"]}`),
		ChainType: ptr(types.ChainTypeEVM),
	}
	allRulesMap[blocklistRule.ID] = blocklistRule

	// Dynamic blocklist rule (should be skipped)
	dynBlocklist := &types.Rule{
		ID:        "dyn-block-1",
		Name:      "Dynamic Blocklist",
		Type:      types.RuleTypeEVMDynamicBlocklist,
		Mode:      types.RuleModeBlocklist,
		Enabled:   true,
		Config:    json.RawMessage(`{}`),
		ChainType: ptr(types.ChainTypeEVM),
	}
	allRulesMap[dynBlocklist.ID] = dynBlocklist

	// Rule under test
	ruleUnderTest := &types.Rule{
		ID:        "whitelist-1",
		Name:      "Whitelist Rule",
		Type:      types.RuleTypeEVMAddressList,
		Mode:      types.RuleModeWhitelist,
		Enabled:   true,
		Config:    json.RawMessage(`{"addresses":["0xok"]}`),
		ChainType: ptr(types.ChainTypeEVM),
	}

	var evalCalled bool
	dummyEval := &dummyEvaluator{
		ruleType:   types.RuleTypeEVMAddressList,
		evaluateFn: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			evalCalled = true
			// Only match whitelist rules, not blocklist
			if rule.Mode == types.RuleModeWhitelist {
				return true, "matched", nil
			}
			return false, "no match", nil
		},
	}

	engine, err := BuildIsolatedEngine(ctx, allRulesMap, ruleUnderTest, log, []RuleEvaluator{dummyEval})
	if err != nil {
		t.Fatalf("BuildIsolatedEngine failed: %v", err)
	}

	// Verify engine can evaluate a request
	req := &types.SignRequest{
		ChainType:     types.ChainTypeEVM,
		SignerAddress: "0xsigner",
	}
	parsed := &types.ParsedPayload{}
	result, err := engine.EvaluateWithResult(ctx, req, parsed)
	if err != nil {
		t.Fatalf("EvaluateWithResult failed: %v", err)
	}
	if !evalCalled {
		t.Error("evaluator was not called")
	}
	if !result.Allowed {
		t.Error("expected request to be allowed")
	}
}

func TestBuildIsolatedEngine_BlocklistRuleUnderTest(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	allRulesMap := make(map[types.RuleID]*types.Rule)

	ruleUnderTest := &types.Rule{
		ID:        "block-under-test",
		Name:      "Blocklist Under Test",
		Type:      types.RuleTypeEVMAddressList,
		Mode:      types.RuleModeBlocklist,
		Enabled:   true,
		Config:    json.RawMessage(`{"addresses":["0xblock"]}`),
		ChainType: ptr(types.ChainTypeEVM),
	}
	allRulesMap[ruleUnderTest.ID] = ruleUnderTest

	dummyEval := &dummyEvaluator{
		ruleType: types.RuleTypeEVMAddressList,
	}

	engine, err := BuildIsolatedEngine(ctx, allRulesMap, ruleUnderTest, log, []RuleEvaluator{dummyEval})
	if err != nil {
		t.Fatalf("BuildIsolatedEngine failed: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
}

// ptr returns a pointer to the given value
func ptr[T any](v T) *T {
	return &v
}

// dummyEvaluator is a minimal evaluator for testing
type dummyEvaluator struct {
	ruleType   types.RuleType
	evaluateFn func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error)
}

func (e *dummyEvaluator) Type() types.RuleType { return e.ruleType }

func (e *dummyEvaluator) Evaluate(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
	if e.evaluateFn != nil {
		return e.evaluateFn(ctx, rule, req, parsed)
	}
	return false, "no match", nil
}
