package rule

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/metrics"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// WhitelistRuleEngine implements RuleEngine with two-tier evaluation:
// 1. Blocklist rules (mandatory): ANY violation = blocked immediately
// 2. Whitelist rules (permissive): ANY match = allowed
//
// Security: Blocklist rules use mandatory Fail-Closed behavior - any blocklist
// evaluation error results in immediate request rejection. This prevents attackers
// from bypassing blocklist rules by causing evaluation failures.
//
// Whitelist rules use Fail-Open behavior - if a whitelist rule evaluation fails,
// it's skipped and the next whitelist rule is evaluated. This ensures that one
// failing whitelist rule doesn't prevent other valid whitelist rules from matching.
type WhitelistRuleEngine struct {
	repo           storage.RuleRepository
	evaluators     map[types.RuleType]RuleEvaluator
	budgetChecker  *BudgetChecker // optional: budget checking for template instances
	mu             sync.RWMutex
	logger         *slog.Logger
}

// RuleEngineOption is a functional option for WhitelistRuleEngine
type RuleEngineOption func(*WhitelistRuleEngine)

// WithBudgetChecker adds budget checking capability to the rule engine
func WithBudgetChecker(checker *BudgetChecker) RuleEngineOption {
	return func(e *WhitelistRuleEngine) {
		e.budgetChecker = checker
	}
}

// NewWhitelistRuleEngine creates a new two-tier rule engine
func NewWhitelistRuleEngine(repo storage.RuleRepository, logger *slog.Logger, opts ...RuleEngineOption) (*WhitelistRuleEngine, error) {
	if repo == nil {
		return nil, fmt.Errorf("rule repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	engine := &WhitelistRuleEngine{
		repo:       repo,
		evaluators: make(map[types.RuleType]RuleEvaluator),
		logger:     logger,
	}
	for _, opt := range opts {
		opt(engine)
	}
	logger.Info("rule engine initialized",
		"budget_enabled", engine.budgetChecker != nil,
	)
	return engine, nil
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

	// Get all applicable rules filtered by chain_type, chain_id, signer, api_key
	filter := storage.RuleFilter{
		ChainType:     &req.ChainType,
		APIKeyID:      &req.APIKeyID,
		SignerAddress: &req.SignerAddress,
		EnabledOnly:   true,
	}
	if req.ChainID != "" {
		filter.ChainID = &req.ChainID
	}
	rules, err := e.repo.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	// Filter rules by sign type before evaluation (avoid calling evaluator for non-applicable rules)
	e.mu.RLock()
	rules = e.filterRulesBySignType(rules, req.SignType)
	e.mu.RUnlock()

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

	// Phase 1: Check blocklist rules first (mandatory Fail-Closed)
	// ANY violation = blocked immediately (no manual approval possible)
	// ANY evaluation error = immediate rejection (Fail-Closed is mandatory for blocklist)
	for _, rule := range blocklistRules {
		evaluator, exists := e.evaluators[rule.Type]
		if !exists {
			e.logger.Error("no evaluator for blocklist rule type (Fail-Closed)",
				"type", rule.Type,
				"rule_id", rule.ID,
			)
			// Fail-Closed (mandatory): missing evaluator is a configuration error, reject immediately
			return nil, &RuleEvaluationError{
				RuleID:   rule.ID,
				RuleName: rule.Name,
				RuleType: rule.Type,
				Err:      fmt.Errorf("no evaluator registered for rule type %s", rule.Type),
			}
		}

		start := time.Now()
		violated, reason, err := evaluator.Evaluate(ctx, rule, req, parsed)
		duration := time.Since(start)
		if err != nil {
			metrics.RecordRuleEvaluation(string(rule.Type), metrics.OutcomeError, duration)
			e.logger.Error("blocklist rule evaluation error (Fail-Closed)",
				"rule_id", rule.ID,
				"type", rule.Type,
				"error", err,
			)
			// Fail-Closed (mandatory): evaluation error must reject immediately
			return nil, &RuleEvaluationError{
				RuleID:   rule.ID,
				RuleName: rule.Name,
				RuleType: rule.Type,
				Err:      err,
			}
		}
		if violated {
			metrics.RecordRuleEvaluation(string(rule.Type), metrics.OutcomeBlock, duration)
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
		metrics.RecordRuleEvaluation(string(rule.Type), metrics.OutcomeNoMatch, duration)
	}

	// Phase 2: Check whitelist rules
	// ANY match = allowed
	// NOTE: Whitelist rules use Fail-Open behavior - if evaluation fails, skip to next rule.
	// This ensures that one failing whitelist rule doesn't block other valid whitelist rules.
	// Fail-Closed only applies to Blocklist rules for security.

	// Try batch evaluation for whitelist rules (optimization)
	// Track which rules were evaluated in batch (not skipped) so sequential fallback skips them
	batchResult, batchEvaluatedRules := e.evaluateWhitelistBatch(ctx, whitelistRules, req, parsed)
	if batchResult != nil {
		return batchResult, nil
	}

	// Fallback to sequential evaluation for rules not evaluated in batch
	sequentialCount := 0
	for _, rule := range whitelistRules {
		// Skip rules already evaluated (not skipped) in batch
		if batchEvaluatedRules[rule.ID] {
			continue
		}

		evaluator, exists := e.evaluators[rule.Type]
		if !exists {
			e.logger.Warn("no evaluator for whitelist rule type, skipping",
				"type", rule.Type,
				"rule_id", rule.ID,
			)
			// Fail-Open for whitelist: skip and continue to next rule
			continue
		}

		sequentialCount++
		start := time.Now()
		matched, reason, err := evaluator.Evaluate(ctx, rule, req, parsed)
		duration := time.Since(start)
		if err != nil {
			metrics.RecordRuleEvaluation(string(rule.Type), metrics.OutcomeError, duration)
			e.logger.Debug("whitelist rule evaluation error, skipping",
				"rule_id", rule.ID,
				"rule_name", rule.Name,
				"type", rule.Type,
				"error", err,
			)
			// Fail-Open for whitelist: skip and continue to next rule
			continue
		}
		if matched {
			metrics.RecordRuleEvaluation(string(rule.Type), metrics.OutcomeAllow, duration)
		} else {
			metrics.RecordRuleEvaluation(string(rule.Type), metrics.OutcomeNoMatch, duration)
		}

		if !matched {
			e.logger.Debug("whitelist rule did not match",
				"rule_id", rule.ID,
				"rule_name", rule.Name,
				"request_id", req.ID,
			)
		}

		if matched {
			// Budget check for instance rules with budget (post-match, pre-approve)
			if e.budgetChecker != nil && rule.TemplateID != nil {
				budgetOK, budgetErr := e.budgetChecker.CheckAndDeductBudget(ctx, rule, req, parsed)
				if budgetErr != nil {
					e.logger.Warn("budget check error, skipping rule (fail-open)",
						"rule_id", rule.ID,
						"rule_name", rule.Name,
						"error", budgetErr,
					)
					continue // Fail-open: try next whitelist rule
				}
				if !budgetOK {
					e.logger.Warn("budget exceeded for rule, skipping to next (fail-open)",
						"rule_id", rule.ID,
						"rule_name", rule.Name,
					)
					continue // Budget exceeded: try next whitelist rule
				}
			}

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

	e.logger.Debug("no rule matched, requires manual approval",
		"request_id", req.ID,
		"batch_evaluated", len(batchEvaluatedRules),
		"sequential_evaluated", sequentialCount,
		"total_whitelist", len(whitelistRules),
	)
	return &EvaluationResult{
		Blocked: false,
		Allowed: false,
	}, nil
}

// filterRulesBySignType returns only rules that apply to the given sign type.
// Must be called while holding e.mu.RLock(). Evaluators that implement SignTypeApplicable
// are consulted; others are kept (no sign-type filtering).
func (e *WhitelistRuleEngine) filterRulesBySignType(rules []*types.Rule, signType string) []*types.Rule {
	out := make([]*types.Rule, 0, len(rules))
	for _, r := range rules {
		ev, exists := e.evaluators[r.Type]
		if !exists {
			out = append(out, r)
			continue
		}
		app, ok := ev.(SignTypeApplicable)
		if !ok {
			out = append(out, r)
			continue
		}
		if app.AppliesToSignType(r, signType) {
			out = append(out, r)
		}
	}
	return out
}

// evaluateWhitelistBatch performs batch evaluation for whitelist rules that support it.
// Returns:
//   - result: non-nil if a rule matched (allowed)
//   - evaluated: set of rule IDs that were fully evaluated (not skipped) in batch
func (e *WhitelistRuleEngine) evaluateWhitelistBatch(
	ctx context.Context,
	rules []*types.Rule,
	req *types.SignRequest,
	parsed *types.ParsedPayload,
) (*EvaluationResult, map[types.RuleID]bool) {
	evaluated := make(map[types.RuleID]bool)

	// Group rules by evaluator type for batch evaluation
	rulesByType := make(map[types.RuleType][]*types.Rule)
	for _, rule := range rules {
		rulesByType[rule.Type] = append(rulesByType[rule.Type], rule)
	}

	// Evaluate each group with batch evaluator if available
	for ruleType, typeRules := range rulesByType {
		evaluator, exists := e.evaluators[ruleType]
		if !exists {
			continue
		}

		batchEval, ok := evaluator.(BatchRuleEvaluator)
		if !ok {
			// This evaluator doesn't support batch, will be handled in sequential fallback
			continue
		}

		if !batchEval.CanBatchEvaluate(typeRules) {
			// Rules can't be batched together, will be handled sequentially
			e.logger.Debug("rules cannot be batched, falling back to sequential",
				"type", ruleType,
				"count", len(typeRules),
			)
			continue
		}

		e.logger.Debug("batch evaluating whitelist rules",
			"type", ruleType,
			"count", len(typeRules),
			"request_id", req.ID,
		)

		results, err := batchEval.EvaluateBatch(ctx, typeRules, req, parsed)
		if err != nil {
			e.logger.Debug("batch evaluation error, falling back to sequential",
				"type", ruleType,
				"error", err,
			)
			continue
		}

		// Check results for any match
		for i, result := range results {
			if result.Skipped {
				continue
			}

			// Mark as evaluated in batch (not skipped)
			evaluated[result.RuleID] = true

			if result.Err != nil {
				e.logger.Debug("whitelist rule batch evaluation error, skipping",
					"rule_id", result.RuleID,
					"error", result.Err,
				)
				continue
			}
			if result.Passed {
				rule := typeRules[i]

				// Budget check for instance rules with budget (post-match, pre-approve)
				if e.budgetChecker != nil && rule.TemplateID != nil {
					budgetOK, budgetErr := e.budgetChecker.CheckAndDeductBudget(ctx, rule, req, parsed)
					if budgetErr != nil {
						e.logger.Warn("budget check error in batch, skipping rule (fail-open)",
							"rule_id", rule.ID,
							"rule_name", rule.Name,
							"error", budgetErr,
						)
						continue
					}
					if !budgetOK {
						e.logger.Warn("budget exceeded for batch rule, skipping to next (fail-open)",
							"rule_id", rule.ID,
							"rule_name", rule.Name,
						)
						continue
					}
				}

				e.logger.Info("request allowed by whitelist rule (batch)",
					"rule_id", rule.ID,
					"rule_name", rule.Name,
					"request_id", req.ID,
					"reason", result.Reason,
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
					AllowReason: result.Reason,
				}, evaluated
			}
		}
	}

	return nil, evaluated
}

// Compile-time check that WhitelistRuleEngine implements RuleEngine
var _ RuleEngine = (*WhitelistRuleEngine)(nil)
