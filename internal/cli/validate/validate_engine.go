package validate

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/ruleconfig"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// buildEngineForRuleTest builds an engine containing only blocklist rules plus the given rule.
// This ensures evm_js test cases (especially "expect fail") are evaluated without another whitelist
// rule allowing the request (e.g. E2E Delegate Target with script that allows all).
func buildEngineForRuleTest(ctx context.Context, fullRepo *storage.MemoryRuleRepository, ruleUnderTest *types.Rule, hasSolidity bool, validator *evm.SolidityRuleValidator, log *slog.Logger) (*rule.WhitelistRuleEngine, error) {
	const listLimit = 10000
	allRules, err := fullRepo.List(ctx, storage.RuleFilter{EnabledOnly: true, Limit: listLimit})
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	allRulesMap := make(map[types.RuleID]*types.Rule, len(allRules))
	for _, r := range allRules {
		allRulesMap[r.ID] = r
	}
	minimalRepo := storage.NewMemoryRuleRepository()
	for _, r := range allRules {
		if r.Mode == types.RuleModeBlocklist {
			if err := minimalRepo.Create(ctx, r); err != nil {
				return nil, fmt.Errorf("add blocklist rule %s: %w", r.ID, err)
			}
		}
	}
	// Add the rule under test (whitelist); blocklist rules were already added above.
	if ruleUnderTest.Mode != types.RuleModeBlocklist {
		if err := minimalRepo.Create(ctx, ruleUnderTest); err != nil {
			return nil, fmt.Errorf("add rule under test %s: %w", ruleUnderTest.ID, err)
		}
	}
	// Recursively add delegation target rules so delegate_to resolution works.
	if err := addDelegationTargets(ctx, ruleUnderTest, allRulesMap, minimalRepo, make(map[types.RuleID]bool), log); err != nil {
		return nil, err
	}
	eng, err := rule.NewWhitelistRuleEngine(minimalRepo, log, rule.WithDelegationPayloadConverter(evm.DelegatePayloadToSignRequest))
	if err != nil {
		return nil, err
	}
	eng.RegisterEvaluator(&evm.AddressListEvaluator{})
	eng.RegisterEvaluator(&evm.ContractMethodEvaluator{})
	eng.RegisterEvaluator(&evm.ValueLimitEvaluator{})
	eng.RegisterEvaluator(&evm.SignerRestrictionEvaluator{})
	eng.RegisterEvaluator(&evm.SignTypeRestrictionEvaluator{})
	eng.RegisterEvaluator(&evm.MessagePatternEvaluator{})
	// Internal transfer evaluator: nil repo for validation-only mode
	internalTransferEval, err := evm.NewInternalTransferEvaluator(nil)
	if err != nil {
		return nil, err
	}
	eng.RegisterEvaluator(internalTransferEval)
	if hasSolidity && validator != nil {
		if solidityEval := validator.Evaluator(); solidityEval != nil {
			eng.RegisterEvaluator(solidityEval)
		}
	}
	jsEval, err := evm.NewJSRuleEvaluator(log)
	if err != nil {
		return nil, err
	}
	eng.RegisterEvaluator(jsEval)
	return eng, nil
}

// addDelegationTargets recursively adds delegation target rules to the minimal repo
// with Enabled=false so they are reachable via Get() (for delegation resolution)
// but NOT included in top-level List(EnabledOnly=true) evaluation.
func addDelegationTargets(ctx context.Context, r *types.Rule, allRulesMap map[types.RuleID]*types.Rule, minimalRepo *storage.MemoryRuleRepository, visited map[types.RuleID]bool, log *slog.Logger) error {
	if visited[r.ID] {
		return nil
	}
	visited[r.ID] = true
	var cfg struct {
		DelegateTo string `json:"delegate_to"`
	}
	if err := json.Unmarshal(r.Config, &cfg); err != nil || cfg.DelegateTo == "" {
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
		if err := addDelegationTargets(ctx, target, allRulesMap, minimalRepo, visited, log); err != nil {
			return err
		}
	}
	return nil
}

// validateDeclarativeRule validates declarative rule config format using shared ruleconfig (same as API and config load).
func validateDeclarativeRule(rule *types.Rule) error {
	var config map[string]interface{}
	if err := json.Unmarshal(rule.Config, &config); err != nil {
		return fmt.Errorf("invalid rule config JSON: %w", err)
	}
	return ruleconfig.ValidateRuleConfig(string(rule.Type), config)
}
