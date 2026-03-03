package rule

import (
	"context"
	"errors"
	"fmt"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ErrBlockedByRule indicates the request was blocked by a blocklist rule
var ErrBlockedByRule = errors.New("request blocked by rule")

// ErrRuleEvaluationFailed indicates rule evaluation failed (Fail-Closed for blocklist)
var ErrRuleEvaluationFailed = errors.New("rule evaluation failed")

// RuleEvaluationError contains details about a rule evaluation failure
type RuleEvaluationError struct {
	RuleID   types.RuleID
	RuleName string
	RuleType types.RuleType
	Err      error
}

func (e *RuleEvaluationError) Error() string {
	return fmt.Sprintf("rule %s (%s) evaluation failed: %v", e.RuleName, e.RuleID, e.Err)
}

func (e *RuleEvaluationError) Unwrap() error {
	return ErrRuleEvaluationFailed
}

// BlockedError contains details about why a request was blocked
type BlockedError struct {
	RuleID   types.RuleID
	RuleName string
	Reason   string
}

func (e *BlockedError) Error() string {
	return "blocked by rule " + string(e.RuleID) + ": " + e.Reason
}

func (e *BlockedError) Unwrap() error {
	return ErrBlockedByRule
}

// EvaluationResult represents the result of rule evaluation
type EvaluationResult struct {
	// Blocked indicates the request was blocked by a blocklist rule
	Blocked bool

	// BlockedBy contains the rule that blocked the request (if Blocked is true)
	BlockedBy *types.Rule

	// BlockReason explains why the request was blocked
	BlockReason string

	// Allowed indicates the request was allowed by a whitelist rule
	Allowed bool

	// AllowedBy contains the rule that allowed the request (if Allowed is true)
	AllowedBy *types.Rule

	// AllowReason explains why the request was allowed
	AllowReason string

	// NoMatchReason explains why a whitelist rule didn't match (used internally for delegation and diagnostics)
	NoMatchReason string
}

// RuleEngine evaluates rules for sign requests
type RuleEngine interface {
	// Evaluate performs two-tier rule evaluation:
	// 1. Check blocklist rules first - ANY violation = blocked (returns BlockedError)
	// 2. Check whitelist rules - ANY match = allowed
	// Returns:
	// - (*RuleID, reason, nil) if whitelisted
	// - (nil, "", nil) if no whitelist match (needs manual approval)
	// - (nil, "", BlockedError) if blocked by a blocklist rule
	Evaluate(ctx context.Context, req *types.SignRequest, parsed *types.ParsedPayload) (*types.RuleID, string, error)

	// EvaluateWithResult returns detailed evaluation result
	EvaluateWithResult(ctx context.Context, req *types.SignRequest, parsed *types.ParsedPayload) (*EvaluationResult, error)

	// RegisterEvaluator registers a chain-specific rule evaluator
	RegisterEvaluator(evaluator RuleEvaluator)
}

// RuleEvaluator evaluates a specific rule type
type RuleEvaluator interface {
	// Type returns the rule type this evaluator handles
	Type() types.RuleType

	// Evaluate evaluates the rule against the request
	// For whitelist mode: returns (true, reason, nil) if request matches the whitelist
	// For blocklist mode: returns (true, reason, nil) if request VIOLATES the limit (should be blocked)
	Evaluate(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error)
}

// SignTypeApplicable is an optional interface for evaluators that restrict by sign_type.
// When implemented, the engine filters out rules that don't apply to the request's sign type
// before calling Evaluate, avoiding unnecessary evaluator calls and config parsing.
type SignTypeApplicable interface {
	// AppliesToSignType returns false if the rule does not apply to the given sign type (e.g. sign_type_filter mismatch).
	AppliesToSignType(rule *types.Rule, signType string) bool
}

// BatchEvaluationResult represents the result of evaluating a single rule in a batch
type BatchEvaluationResult struct {
	RuleID  types.RuleID
	Passed  bool
	Reason  string
	Err     error
	Skipped bool // true if rule was skipped (e.g., primaryType mismatch)
}

// BatchRuleEvaluator extends RuleEvaluator with batch evaluation capability
// This is optional - evaluators that don't support batch evaluation will fall back to sequential
type BatchRuleEvaluator interface {
	RuleEvaluator

	// EvaluateBatch evaluates multiple rules against the same request in a single execution
	// Returns results in the same order as the input rules
	// Rules that don't apply (e.g., primaryType mismatch) will have Skipped=true
	EvaluateBatch(ctx context.Context, rules []*types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) ([]BatchEvaluationResult, error)

	// CanBatchEvaluate returns true if the given rules can be evaluated together
	// Rules might not be batchable if they use different validation modes
	CanBatchEvaluate(rules []*types.Rule) bool
}

// Delegation limits per §11.8
const (
	DelegationMaxDepth = 6
	DelegationMaxItems = 256
)

// DelegationRequest is returned by evaluators that support delegation (e.g. evm_js).
// TargetRuleIDs: engine tries each target in order until one allows (single: one payload;
// per_item: each item must be allowed by at least one target).
type DelegationRequest struct {
	TargetRuleIDs []types.RuleID // target rule IDs; any one passing is OK per payload/item
	Mode          string         // "single" | "per_item"
	Payload       interface{}
	ItemsKey      string
	PayloadKey    string
}

// EvaluatorWithDelegation is an optional interface for evaluators that can return a delegation.
// When implemented, the engine calls EvaluateWithDelegation and may recurse to the target rule.
type EvaluatorWithDelegation interface {
	RuleEvaluator
	EvaluateWithDelegation(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (matched bool, reason string, delegation *DelegationRequest, err error)
}

// DelegationPayloadConverter converts a delegation payload to (SignRequest, ParsedPayload) for the target rule.
// Set via WithDelegationPayloadConverter when the engine is created (e.g. evm.DelegatePayloadToSignRequest).
type DelegationPayloadConverter func(ctx context.Context, payload interface{}, mode string) (*types.SignRequest, *types.ParsedPayload, error)
