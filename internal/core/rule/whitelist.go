package rule

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/metrics"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

type delegationCtxKey struct{}

type delegationCtxVal struct {
	Depth int
	Path  map[types.RuleID]bool
}

func getDelegationCtx(ctx context.Context) (depth int, path map[types.RuleID]bool) {
	v, _ := ctx.Value(delegationCtxKey{}).(delegationCtxVal)
	if v.Path == nil {
		return v.Depth, nil
	}
	return v.Depth, v.Path
}

func withDelegationCtx(ctx context.Context, depth int, path map[types.RuleID]bool) context.Context {
	return context.WithValue(ctx, delegationCtxKey{}, delegationCtxVal{Depth: depth, Path: path})
}

// ruleScopeMatches returns true if the rule's scope (ChainType, ChainID, APIKeyID, SignerAddress) matches the request.
// Nil rule scope fields mean "any".
func ruleScopeMatches(rule *types.Rule, req *types.SignRequest) bool {
	if rule.ChainType != nil && *rule.ChainType != req.ChainType {
		return false
	}
	if rule.ChainID != nil && *rule.ChainID != req.ChainID {
		return false
	}
	if rule.APIKeyID != nil && *rule.APIKeyID != req.APIKeyID {
		return false
	}
	if rule.SignerAddress != nil && !strings.EqualFold(*rule.SignerAddress, req.SignerAddress) {
		return false
	}
	return true
}

// logScopeMismatch logs rule and request scope fields when delegation target scope mismatch occurs, for root cause diagnosis.
func (e *WhitelistRuleEngine) logScopeMismatch(rule *types.Rule, req *types.SignRequest, targetID types.RuleID) {
	if e.logger == nil || rule == nil || req == nil {
		return
	}
	var ruleChainType, ruleChainID, ruleAPIKeyID, ruleSigner string
	if rule.ChainType != nil {
		ruleChainType = string(*rule.ChainType)
	}
	if rule.ChainID != nil {
		ruleChainID = *rule.ChainID
	}
	if rule.APIKeyID != nil {
		ruleAPIKeyID = *rule.APIKeyID
	}
	if rule.SignerAddress != nil {
		ruleSigner = *rule.SignerAddress
	}
	e.logger.Info("delegation target scope mismatch",
		"target_id", targetID,
		"rule_chain_type", ruleChainType, "rule_chain_id", ruleChainID, "rule_api_key_id", ruleAPIKeyID, "rule_signer", ruleSigner,
		"req_chain_type", string(req.ChainType), "req_chain_id", req.ChainID, "req_api_key_id", req.APIKeyID, "req_signer", req.SignerAddress,
	)
}

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
	repo                  storage.RuleRepository
	evaluators            map[types.RuleType]RuleEvaluator
	budgetChecker         *BudgetChecker // optional: budget checking for template instances
	delegationConverter   DelegationPayloadConverter
	mu                    sync.RWMutex
	logger                *slog.Logger
}

// RuleEngineOption is a functional option for WhitelistRuleEngine
type RuleEngineOption func(*WhitelistRuleEngine)

// WithBudgetChecker adds budget checking capability to the rule engine
func WithBudgetChecker(checker *BudgetChecker) RuleEngineOption {
	return func(e *WhitelistRuleEngine) {
		e.budgetChecker = checker
	}
}

// WithDelegationPayloadConverter sets the converter used to turn delegation payloads into (SignRequest, ParsedPayload).
// Required for evm_js delegation (e.g. pass evm.DelegatePayloadToSignRequest from the chain adapter).
func WithDelegationPayloadConverter(c DelegationPayloadConverter) RuleEngineOption {
	return func(e *WhitelistRuleEngine) {
		e.delegationConverter = c
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

	// Get all applicable rules filtered by chain_type, chain_id, signer, api_key.
	// SECURITY: Use Limit=-1 to fetch ALL matching rules without pagination.
	// A default limit (e.g. 100) could silently drop blocklist rules, allowing
	// malicious transactions through. This is a security-critical path.
	filter := storage.RuleFilter{
		ChainType:     &req.ChainType,
		APIKeyID:      &req.APIKeyID,
		SignerAddress: &req.SignerAddress,
		EnabledOnly:   true,
		Limit:         -1, // No limit: must load ALL rules for security evaluation
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
	batchResult, batchEvaluatedRules, batchNoMatchReason := e.evaluateWhitelistBatch(ctx, whitelistRules, req, parsed)
	if batchResult != nil {
		return batchResult, nil
	}

	// Fallback to sequential evaluation for rules not evaluated in batch
	sequentialCount := 0
	var firstNoMatchReason, lastNoMatchReason string
	if batchNoMatchReason != "" {
		firstNoMatchReason = batchNoMatchReason
		lastNoMatchReason = batchNoMatchReason
	}
	for _, rule := range whitelistRules {
		// Skip rules already evaluated (not skipped) in batch
		if batchEvaluatedRules[rule.ID] {
			continue
		}

		_, exists := e.evaluators[rule.Type]
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
		result, err := e.evaluateOneRuleWithDelegation(ctx, rule, req, parsed)
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
		matched := result != nil && result.Allowed
		if matched {
			metrics.RecordRuleEvaluation(string(rule.Type), metrics.OutcomeAllow, duration)
		} else {
			metrics.RecordRuleEvaluation(string(rule.Type), metrics.OutcomeNoMatch, duration)
		}

		if !matched {
			if result != nil && result.NoMatchReason != "" {
				if firstNoMatchReason == "" {
					firstNoMatchReason = result.NoMatchReason
				}
				lastNoMatchReason = result.NoMatchReason
			}
			attrs := []any{"rule_id", rule.ID, "rule_name", rule.Name, "request_id", req.ID}
			if result != nil && result.NoMatchReason != "" {
				attrs = append(attrs, "reason", result.NoMatchReason)
			}
			e.logger.Debug("whitelist rule did not match", attrs...)
		}

		// SECURITY: budget check is now done inside evaluateOneRuleWithDelegation
		// (covers both delegation and non-delegation paths). If budget is exhausted,
		// result.Blocked=true is returned — handle it here with fail-closed.
		if result != nil && result.Blocked {
			return result, nil
		}

		if matched {
			e.logger.Info("request allowed by whitelist rule",
				"rule_id", result.AllowedBy.ID,
				"rule_name", result.AllowedBy.Name,
				"request_id", req.ID,
				"reason", result.AllowReason,
			)
			// Update match count asynchronously
			go func(ruleID types.RuleID) {
				if err := e.repo.IncrementMatchCount(context.Background(), ruleID); err != nil {
					e.logger.Error("failed to increment match count", "rule_id", ruleID, "error", err)
				}
			}(result.AllowedBy.ID)

			return result, nil
		}
	}

	infoAttrs := []any{
		"request_id", req.ID,
		"batch_evaluated", len(batchEvaluatedRules),
		"sequential_evaluated", sequentialCount,
		"total_whitelist", len(whitelistRules),
	}
	if lastNoMatchReason != "" {
		infoAttrs = append(infoAttrs, "last_no_match_reason", lastNoMatchReason)
	}
	e.logger.Info("no rule matched, requires manual approval or will reject", infoAttrs...)
	return &EvaluationResult{
		Blocked:       false,
		Allowed:       false,
		NoMatchReason: lastNoMatchReason,
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

// evaluateOneRuleWithDelegation evaluates a single whitelist rule; if the rule matches and returns
// a delegation, it resolves the delegation (depth/cycle/scope/size checks, convert payload, recurse).
// Used by the sequential whitelist loop. Caller must hold e.mu at least RLock.
func (e *WhitelistRuleEngine) evaluateOneRuleWithDelegation(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (*EvaluationResult, error) {
	evaluator, exists := e.evaluators[rule.Type]
	if !exists {
		return &EvaluationResult{Allowed: false}, nil
	}

	var matched bool
	var reason string
	var delegation *DelegationRequest
	var err error

	if ev, ok := evaluator.(EvaluatorWithDelegation); ok {
		matched, reason, delegation, err = ev.EvaluateWithDelegation(ctx, rule, req, parsed)
	} else {
		matched, reason, err = evaluator.Evaluate(ctx, rule, req, parsed)
	}

	if err != nil {
		return nil, err
	}
	if !matched {
		return &EvaluationResult{Allowed: false, NoMatchReason: reason}, nil
	}
	// SECURITY: check parent rule's budget BEFORE delegation or allowing.
	// Without this, a delegating rule's budget is never deducted, enabling budget bypass.
	if matched && e.budgetChecker != nil && rule.TemplateID != nil {
		budgetOK, budgetErr := e.budgetChecker.CheckAndDeductBudget(ctx, rule, req, parsed)
		if budgetErr != nil {
			e.logger.Error("budget check error in delegation path, denying request (fail-closed)",
				"rule_id", rule.ID, "rule_name", rule.Name, "error", budgetErr)
			return &EvaluationResult{
				Blocked:     true,
				BlockedBy:   rule,
				BlockReason: fmt.Sprintf("budget check error: %v", budgetErr),
			}, nil
		}
		if !budgetOK {
			e.logger.Warn("budget exceeded for rule, denying request (fail-closed)",
				"rule_id", rule.ID, "rule_name", rule.Name)
			return &EvaluationResult{
				Blocked:     true,
				BlockedBy:   rule,
				BlockReason: "budget exceeded",
			}, nil
		}
	}

	if matched && delegation != nil {
		return e.resolveDelegation(ctx, req, rule, delegation)
	}
	return &EvaluationResult{
		Allowed:     true,
		AllowedBy:   rule,
		AllowReason: reason,
	}, nil
}

// delegationTargetIDs returns the list of rule IDs to try; any one allowing the payload/item is enough.
func delegationTargetIDs(d *DelegationRequest) []types.RuleID {
	return d.TargetRuleIDs
}

// resolveDelegation loads target rule(s), enforces depth/cycle/scope/size, converts payload(s),
// and recurses via evaluateOneRuleWithDelegation. When multiple targets are set, tries each in order
// until one allows (single: one payload; per_item: each item must be allowed by at least one target).
// AllowedBy on success is the fromRule (first matcher).
func (e *WhitelistRuleEngine) resolveDelegation(ctx context.Context, originalReq *types.SignRequest, fromRule *types.Rule, delegation *DelegationRequest) (*EvaluationResult, error) {
	depth, path := getDelegationCtx(ctx)
	targetIDs := delegationTargetIDs(delegation)
	if len(targetIDs) == 0 {
		e.logger.Debug("delegation has no target rule id(s)")
		return &EvaluationResult{Allowed: false, NoMatchReason: "delegation has no target rule id(s)"}, nil
	}
	if depth >= DelegationMaxDepth {
		e.logger.Debug("delegation max depth exceeded", "depth", depth, "targets", targetIDs)
		return &EvaluationResult{Allowed: false, NoMatchReason: "delegation max depth exceeded"}, nil
	}
	if e.delegationConverter == nil {
		e.logger.Debug("delegation converter not set")
		return &EvaluationResult{Allowed: false, NoMatchReason: "delegation converter not set"}, nil
	}

	if delegation.Mode == "single" {
		req2, parsed2, err := e.delegationConverter(ctx, delegation.Payload, delegation.Mode)
		if err != nil {
			e.logger.Debug("delegation single convert failed", "error", err)
			return &EvaluationResult{Allowed: false, NoMatchReason: "delegation single convert failed: " + err.Error()}, nil
		}
		req2.APIKeyID = originalReq.APIKeyID

		// SECURITY: Run blocklist rules against the delegated payload.
		// Without this check, a delegated payload could bypass blocklist rules
		// (e.g., send funds to a blacklisted address).
		if blockResult, blockErr := e.evaluateBlocklistForRequest(ctx, req2, parsed2); blockErr != nil {
			return nil, blockErr
		} else if blockResult != nil {
			return blockResult, nil
		}

		var lastReason string
		for _, targetID := range targetIDs {
			targetRule, err := e.repo.Get(ctx, targetID)
			if err != nil || targetRule == nil {
				return &EvaluationResult{
					Allowed:       false,
					NoMatchReason: "delegation target rule not found: " + string(targetID),
				}, nil
			}
			path2 := make(map[types.RuleID]bool)
			for k, v := range path {
				path2[k] = v
			}
			if path2[targetRule.ID] {
				e.logger.Debug("delegation cycle detected", "target", targetRule.ID)
				lastReason = "delegation cycle detected"
				continue
			}
			path2[targetRule.ID] = true
			childCtx := withDelegationCtx(ctx, depth+1, path2)
			if !ruleScopeMatches(targetRule, req2) {
				lastReason = "delegation target scope mismatch: " + string(targetID)
				e.logScopeMismatch(targetRule, req2, targetID)
				continue
			}
			result, err := e.evaluateOneRuleWithDelegation(childCtx, targetRule, req2, parsed2)
			if err != nil {
				lastReason = "delegation target error: " + err.Error()
				continue
			}
			if result == nil || !result.Allowed {
				if result != nil && result.NoMatchReason != "" {
					lastReason = "delegation target did not allow: " + result.NoMatchReason
				} else {
					lastReason = "delegation target did not allow: " + string(targetID)
				}
				continue
			}
			return &EvaluationResult{
				Allowed:     true,
				AllowedBy:   fromRule,
				AllowReason: result.AllowReason,
			}, nil
		}
		if lastReason == "" {
			lastReason = "delegation no target allowed"
		}
		return &EvaluationResult{Allowed: false, NoMatchReason: lastReason}, nil
	}

	if delegation.Mode == "per_item" {
		items, err := delegationItems(delegation.Payload, delegation.ItemsKey)
		if err != nil {
			e.logger.Debug("delegation per_item items invalid", "error", err)
			return &EvaluationResult{Allowed: false, NoMatchReason: "delegation per_item items invalid: " + err.Error()}, nil
		}
		if len(items) > DelegationMaxItems {
			e.logger.Debug("delegation per_item exceeds max items", "len", len(items), "max", DelegationMaxItems)
			return &EvaluationResult{Allowed: false, NoMatchReason: "delegation per_item exceeds max items"}, nil
		}
		for _, item := range items {
			req2, parsed2, err := e.delegationConverter(ctx, item, delegation.Mode)
			if err != nil {
				e.logger.Debug("delegation per_item convert failed", "error", err)
				return &EvaluationResult{Allowed: false, NoMatchReason: "delegation per_item convert failed: " + err.Error()}, nil
			}
			req2.APIKeyID = originalReq.APIKeyID

			// SECURITY: Run blocklist rules against each delegated item.
			if blockResult, blockErr := e.evaluateBlocklistForRequest(ctx, req2, parsed2); blockErr != nil {
				return nil, blockErr
			} else if blockResult != nil {
				return blockResult, nil
			}

			itemAllowed := false
			var itemReason string
			for _, targetID := range targetIDs {
				targetRule, err := e.repo.Get(ctx, targetID)
				if err != nil || targetRule == nil {
					return &EvaluationResult{
						Allowed:       false,
						NoMatchReason: "delegation target rule not found: " + string(targetID),
					}, nil
				}
				path2 := make(map[types.RuleID]bool)
				for k, v := range path {
					path2[k] = v
				}
				if path2[targetRule.ID] {
					itemReason = "delegation cycle detected"
					continue
				}
				path2[targetRule.ID] = true
				childCtx := withDelegationCtx(ctx, depth+1, path2)
				if !ruleScopeMatches(targetRule, req2) {
					itemReason = "delegation target scope mismatch: " + string(targetID)
					e.logScopeMismatch(targetRule, req2, targetID)
					continue
				}
				result, err := e.evaluateOneRuleWithDelegation(childCtx, targetRule, req2, parsed2)
				if err == nil && result != nil && result.Allowed {
					itemAllowed = true
					break
				}
				if result != nil && result.NoMatchReason != "" {
					itemReason = "delegation target did not allow: " + result.NoMatchReason
				} else {
					itemReason = "delegation target did not allow: " + string(targetID)
				}
			}
			if !itemAllowed {
				if itemReason == "" {
					itemReason = "delegation per_item no target allowed"
				}
				return &EvaluationResult{Allowed: false, NoMatchReason: itemReason}, nil
			}
		}
		return &EvaluationResult{
			Allowed:     true,
			AllowedBy:   fromRule,
			AllowReason: "delegation per_item",
		}, nil
	}

	e.logger.Debug("delegation unknown mode", "mode", delegation.Mode)
	return &EvaluationResult{Allowed: false, NoMatchReason: "delegation unknown mode: " + delegation.Mode}, nil
}

// delegationItems extracts the items array from payload for per_item delegation.
func delegationItems(payload interface{}, itemsKey string) ([]interface{}, error) {
	if payload == nil || itemsKey == "" {
		return nil, fmt.Errorf("payload or items_key empty")
	}
	m, ok := payload.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("payload is not a map")
	}
	raw, ok := m[itemsKey]
	if !ok {
		return nil, fmt.Errorf("items_key %q not found", itemsKey)
	}
	sl, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("items_key %q is not an array", itemsKey)
	}
	return sl, nil
}

// evaluateWhitelistBatch performs batch evaluation for whitelist rules that support it.
// Returns:
//   - result: non-nil if a rule matched (allowed)
//   - evaluated: set of rule IDs that were fully evaluated (not skipped) in batch
//   - lastNoMatchReason: the last non-empty reason from non-matching rules (for diagnostics)
func (e *WhitelistRuleEngine) evaluateWhitelistBatch(
	ctx context.Context,
	rules []*types.Rule,
	req *types.SignRequest,
	parsed *types.ParsedPayload,
) (*EvaluationResult, map[types.RuleID]bool, string) {
	evaluated := make(map[types.RuleID]bool)
	var lastNoMatchReason string

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
				// SECURITY: fail-closed — budget exhaustion or error terminates evaluation
				// to prevent bypass via other matching rules without budget constraints.
				if e.budgetChecker != nil && rule.TemplateID != nil {
					budgetOK, budgetErr := e.budgetChecker.CheckAndDeductBudget(ctx, rule, req, parsed)
					if budgetErr != nil {
						e.logger.Error("budget check error in batch, denying request (fail-closed)",
							"rule_id", rule.ID,
							"rule_name", rule.Name,
							"error", budgetErr,
						)
						return &EvaluationResult{
							Blocked:     true,
							BlockedBy:   rule,
							BlockReason: fmt.Sprintf("budget check error: %v", budgetErr),
						}, evaluated, ""
					}
					if !budgetOK {
						e.logger.Warn("budget exceeded for batch rule, denying request (fail-closed)",
							"rule_id", rule.ID,
							"rule_name", rule.Name,
						)
						return &EvaluationResult{
							Blocked:     true,
							BlockedBy:   rule,
							BlockReason: "budget exceeded",
						}, evaluated, ""
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
				}, evaluated, ""
			} else if result.Reason != "" {
				lastNoMatchReason = result.Reason
			}
		}
	}

	return nil, evaluated, lastNoMatchReason
}

// evaluateBlocklistForRequest runs all applicable blocklist rules against a request.
// Used by delegation to ensure delegated payloads are checked against blocklist rules.
// Returns (nil, nil) if no blocklist rule is violated; otherwise returns the blocking result.
// Uses Fail-Closed semantics: evaluation errors cause immediate rejection.
func (e *WhitelistRuleEngine) evaluateBlocklistForRequest(ctx context.Context, req *types.SignRequest, parsed *types.ParsedPayload) (*EvaluationResult, error) {
	filter := storage.RuleFilter{
		ChainType:     &req.ChainType,
		APIKeyID:      &req.APIKeyID,
		SignerAddress: &req.SignerAddress,
		EnabledOnly:   true,
		Limit:         -1, // No limit: must load ALL rules for security evaluation
	}
	if req.ChainID != "" {
		filter.ChainID = &req.ChainID
	}
	rules, err := e.repo.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules for delegation blocklist check: %w", err)
	}

	e.mu.RLock()
	rules = e.filterRulesBySignType(rules, req.SignType)
	e.mu.RUnlock()

	for _, rule := range rules {
		if rule.Mode != types.RuleModeBlocklist {
			continue
		}
		evaluator, exists := e.evaluators[rule.Type]
		if !exists {
			e.logger.Error("no evaluator for blocklist rule type in delegation (Fail-Closed)",
				"type", rule.Type,
				"rule_id", rule.ID,
			)
			return nil, &RuleEvaluationError{
				RuleID:   rule.ID,
				RuleName: rule.Name,
				RuleType: rule.Type,
				Err:      fmt.Errorf("no evaluator registered for blocklist rule type %s (delegation check)", rule.Type),
			}
		}
		violated, reason, evalErr := evaluator.Evaluate(ctx, rule, req, parsed)
		if evalErr != nil {
			e.logger.Error("blocklist rule evaluation error in delegation (Fail-Closed)",
				"rule_id", rule.ID,
				"type", rule.Type,
				"error", evalErr,
			)
			return nil, &RuleEvaluationError{
				RuleID:   rule.ID,
				RuleName: rule.Name,
				RuleType: rule.Type,
				Err:      evalErr,
			}
		}
		if violated {
			e.logger.Warn("delegated request blocked by blocklist rule",
				"rule_id", rule.ID,
				"rule_name", rule.Name,
				"request_id", req.ID,
				"reason", reason,
			)
			return &EvaluationResult{
				Blocked:     true,
				BlockedBy:   rule,
				BlockReason: reason,
			}, nil
		}
	}
	return nil, nil
}

// Compile-time check that WhitelistRuleEngine implements RuleEngine
var _ RuleEngine = (*WhitelistRuleEngine)(nil)
