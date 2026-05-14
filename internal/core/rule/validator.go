package rule

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// AddDelegationTargets recursively adds delegation target rules to the minimal repo
// with Enabled=false so they are reachable via Get() (for delegation resolution)
// but NOT included in top-level List(EnabledOnly=true) evaluation.
func AddDelegationTargets(ctx context.Context, r *types.Rule, allRulesMap map[types.RuleID]*types.Rule, minimalRepo *storage.MemoryRuleRepository, visited map[types.RuleID]bool, log *slog.Logger) error {
	if visited[r.ID] {
		return nil
	}
	visited[r.ID] = true

	var cfg struct {
		DelegateTo string `json:"delegate_to"`
	}
	if err := json.Unmarshal(r.Config, &cfg); err != nil {
		return fmt.Errorf("unmarshal config for rule %q: %w", r.ID, err)
	}
	if cfg.DelegateTo == "" {
		return nil
	}

	for _, part := range strings.Split(cfg.DelegateTo, ",") {
		targetID := types.RuleID(strings.TrimSpace(part))
		if targetID == "" {
			continue
		}
		target, ok := allRulesMap[targetID]
		if !ok {
			return fmt.Errorf("rule %q delegate_to references non-existent target %q", r.ID, targetID)
		}
		clone := *target
		clone.Enabled = false
		if err := minimalRepo.Create(ctx, &clone); err != nil {
			log.Debug("delegation target already in minimal repo", "target", targetID)
		}
		if err := AddDelegationTargets(ctx, target, allRulesMap, minimalRepo, visited, log); err != nil {
			return err
		}
	}
	return nil
}

// BuildIsolatedEngine creates a minimal rule engine containing only blocklist rules
// plus the given rule (and its delegation targets). This ensures evm_js expected-fail
// test cases are evaluated without another whitelist rule allowing the request.
//
// Blocklist rules of type evm_dynamic_blocklist are skipped because the DynamicBlocklist
// runtime is typically not available in validation contexts.
//
// evaluators provides the RuleEvaluator instances to register on the engine.
// opts may include RuleEngineOption values such as WithDelegationPayloadConverter.
func BuildIsolatedEngine(
	ctx context.Context,
	allRulesMap map[types.RuleID]*types.Rule,
	ruleUnderTest *types.Rule,
	log *slog.Logger,
	evaluators []RuleEvaluator,
	opts ...RuleEngineOption,
) (*WhitelistRuleEngine, error) {
	minimalRepo := storage.NewMemoryRuleRepository()
	for _, r := range allRulesMap {
		if r.Mode == types.RuleModeBlocklist {
			// Skip evm_dynamic_blocklist — its evaluator depends on runtime DynamicBlocklist
			// which is not available during startup validation.
			if r.Type == types.RuleTypeEVMDynamicBlocklist {
				continue
			}
			if err := minimalRepo.Create(ctx, r); err != nil {
				return nil, fmt.Errorf("add blocklist rule %s: %w", r.ID, err)
			}
		}
	}
	if ruleUnderTest.Mode != types.RuleModeBlocklist {
		if err := minimalRepo.Create(ctx, ruleUnderTest); err != nil {
			return nil, fmt.Errorf("add rule under test %s: %w", ruleUnderTest.ID, err)
		}
	}
	if err := AddDelegationTargets(ctx, ruleUnderTest, allRulesMap, minimalRepo, make(map[types.RuleID]bool), log); err != nil {
		return nil, err
	}
	eng, err := NewWhitelistRuleEngine(minimalRepo, log, opts...)
	if err != nil {
		return nil, err
	}
	for _, eval := range evaluators {
		eng.RegisterEvaluator(eval)
	}
	return eng, nil
}
