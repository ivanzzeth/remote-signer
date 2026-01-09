package rule

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// WhitelistRuleEngine implements RuleEngine with two-tier evaluation:
// 1. Blocklist rules (mandatory): ANY violation = blocked immediately
// 2. Whitelist rules (permissive): ANY match = allowed
type WhitelistRuleEngine struct {
	repo       storage.RuleRepository
	evaluators map[types.RuleType]RuleEvaluator
	mu         sync.RWMutex
	logger     *slog.Logger
}

// NewWhitelistRuleEngine creates a new two-tier rule engine
func NewWhitelistRuleEngine(repo storage.RuleRepository, logger *slog.Logger) (*WhitelistRuleEngine, error) {
	if repo == nil {
		return nil, fmt.Errorf("rule repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &WhitelistRuleEngine{
		repo:       repo,
		evaluators: make(map[types.RuleType]RuleEvaluator),
		logger:     logger,
	}, nil
}

// RegisterEvaluator registers a rule evaluator for a specific rule type
func (e *WhitelistRuleEngine) RegisterEvaluator(evaluator RuleEvaluator) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.evaluators[evaluator.Type()] = evaluator
	e.logger.Info("registered rule evaluator", "type", evaluator.Type())
}

// Evaluate performs two-tier rule evaluation
func (e *WhitelistRuleEngine) Evaluate(ctx context.Context, req *types.SignRequest, parsed *types.ParsedPayload) (*types.RuleID, string, error) {
	result, err := e.EvaluateWithResult(ctx, req, parsed)
	if err != nil {
		return nil, "", err
	}

	if result.Blocked {
		return nil, "", &BlockedError{
			RuleID:   result.BlockedBy.ID,
			RuleName: result.BlockedBy.Name,
			Reason:   result.BlockReason,
		}
	}

	if result.Allowed {
		return &result.AllowedBy.ID, result.AllowReason, nil
	}

	return nil, "", nil // No whitelist match, needs manual approval
}

// EvaluateWithResult returns detailed evaluation result
func (e *WhitelistRuleEngine) EvaluateWithResult(ctx context.Context, req *types.SignRequest, parsed *types.ParsedPayload) (*EvaluationResult, error) {
	if req == nil {
		return nil, fmt.Errorf("request is required")
	}

	// Get all applicable rules filtered by chain_type, signer, api_key
	rules, err := e.repo.List(ctx, storage.RuleFilter{
		ChainType:     &req.ChainType,
		APIKeyID:      &req.APIKeyID,
		SignerAddress: &req.SignerAddress,
		EnabledOnly:   true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	// Separate rules by mode
	var blocklistRules []*types.Rule
	var whitelistRules []*types.Rule
	for _, rule := range rules {
		if rule.Mode == types.RuleModeBlocklist {
			blocklistRules = append(blocklistRules, rule)
		} else {
			// Default to whitelist mode for backward compatibility
			whitelistRules = append(whitelistRules, rule)
		}
	}

	e.logger.Debug("evaluating rules",
		"request_id", req.ID,
		"chain_type", req.ChainType,
		"blocklist_count", len(blocklistRules),
		"whitelist_count", len(whitelistRules),
	)

	e.mu.RLock()
	defer e.mu.RUnlock()

	// Phase 1: Check blocklist rules first
	// ANY violation = blocked immediately (no manual approval possible)
	for _, rule := range blocklistRules {
		evaluator, exists := e.evaluators[rule.Type]
		if !exists {
			e.logger.Warn("no evaluator for blocklist rule type", "type", rule.Type, "rule_id", rule.ID)
			continue
		}

		violated, reason, err := evaluator.Evaluate(ctx, rule, req, parsed)
		if err != nil {
			e.logger.Error("blocklist rule evaluation error",
				"rule_id", rule.ID,
				"type", rule.Type,
				"error", err,
			)
			continue
		}

		if violated {
			e.logger.Warn("request blocked by rule",
				"rule_id", rule.ID,
				"rule_name", rule.Name,
				"request_id", req.ID,
				"reason", reason,
			)
			// Update match count asynchronously
			go func(ruleID types.RuleID) {
				if err := e.repo.IncrementMatchCount(context.Background(), ruleID); err != nil {
					e.logger.Error("failed to increment match count", "rule_id", ruleID, "error", err)
				}
			}(rule.ID)

			return &EvaluationResult{
				Blocked:     true,
				BlockedBy:   rule,
				BlockReason: reason,
			}, nil
		}
	}

	// Phase 2: Check whitelist rules
	// ANY match = allowed
	for _, rule := range whitelistRules {
		evaluator, exists := e.evaluators[rule.Type]
		if !exists {
			e.logger.Warn("no evaluator for whitelist rule type", "type", rule.Type, "rule_id", rule.ID)
			continue
		}

		matched, reason, err := evaluator.Evaluate(ctx, rule, req, parsed)
		if err != nil {
			e.logger.Error("whitelist rule evaluation error",
				"rule_id", rule.ID,
				"type", rule.Type,
				"error", err,
			)
			continue
		}

		if matched {
			e.logger.Info("request allowed by whitelist rule",
				"rule_id", rule.ID,
				"rule_name", rule.Name,
				"request_id", req.ID,
				"reason", reason,
			)
			// Update match count asynchronously
			go func(ruleID types.RuleID) {
				if err := e.repo.IncrementMatchCount(context.Background(), ruleID); err != nil {
					e.logger.Error("failed to increment match count", "rule_id", ruleID, "error", err)
				}
			}(rule.ID)

			return &EvaluationResult{
				Allowed:     true,
				AllowedBy:   rule,
				AllowReason: reason,
			}, nil
		}
	}

	e.logger.Debug("no rule matched, requires manual approval", "request_id", req.ID)
	return &EvaluationResult{
		Blocked: false,
		Allowed: false,
	}, nil
}

// Compile-time check that WhitelistRuleEngine implements RuleEngine
var _ RuleEngine = (*WhitelistRuleEngine)(nil)
