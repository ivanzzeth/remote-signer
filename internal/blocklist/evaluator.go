package blocklist

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// Evaluator implements the rule.RuleEvaluator interface for dynamic blocklist rules.
// It checks tx.to (transactions) and verifyingContract (typed_data) against the dynamic blocklist.
type Evaluator struct {
	blocklist *DynamicBlocklist
}

// EvaluatorConfig is the JSON config stored in rule.Config for evm_dynamic_blocklist rules.
type EvaluatorConfig struct {
	CheckRecipient         bool `json:"check_recipient"`          // Check tx.to for transactions
	CheckVerifyingContract bool `json:"check_verifying_contract"` // Check domain.verifyingContract for typed_data
}

// NewEvaluator creates a new dynamic blocklist evaluator.
func NewEvaluator(bl *DynamicBlocklist) (*Evaluator, error) {
	if bl == nil {
		return nil, fmt.Errorf("blocklist is required")
	}
	return &Evaluator{blocklist: bl}, nil
}

// Type returns the rule type this evaluator handles.
func (e *Evaluator) Type() types.RuleType {
	return types.RuleTypeEVMDynamicBlocklist
}

// Evaluate checks whether the sign request targets a blocked address.
// For blocklist mode: returns (true, reason) if violated (should block).
// For whitelist mode: returns (true, reason) if matched (should allow) — unlikely use case.
func (e *Evaluator) Evaluate(ctx context.Context, r *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
	// Fail-closed: if blocklist is in fail-close mode with no data, reject everything.
	if r.Mode == types.RuleModeBlocklist && e.blocklist.IsFailClosed() {
		return true, "dynamic blocklist unavailable (fail-close mode)", nil
	}

	var cfg EvaluatorConfig
	if err := json.Unmarshal(r.Config, &cfg); err != nil {
		return false, "", fmt.Errorf("invalid dynamic blocklist config: %w", err)
	}

	// Check transaction recipient.
	if cfg.CheckRecipient && parsed != nil && parsed.Recipient != nil {
		if blocked, reason := e.blocklist.IsBlocked(*parsed.Recipient); blocked {
			return true, reason, nil
		}
	}

	// Check typed_data verifyingContract from payload.
	if cfg.CheckVerifyingContract && req.SignType == "typed_data" && len(req.Payload) > 0 {
		vc := extractVerifyingContract(req.Payload)
		if vc != "" {
			if blocked, reason := e.blocklist.IsBlocked(vc); blocked {
				return true, reason, nil
			}
		}
	}

	return false, "", nil
}

// AppliesToSignType implements the optional SignTypeApplicable interface.
// Dynamic blocklist applies to all sign types.
func (e *Evaluator) AppliesToSignType(_ *types.Rule, _ string) bool {
	return true
}

// extractVerifyingContract extracts domain.verifyingContract from typed_data payload JSON.
func extractVerifyingContract(payload []byte) string {
	var p struct {
		TypedData *struct {
			Domain *struct {
				VerifyingContract string `json:"verifyingContract"`
			} `json:"domain"`
		} `json:"typed_data"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return ""
	}
	if p.TypedData == nil || p.TypedData.Domain == nil {
		return ""
	}
	return strings.TrimSpace(p.TypedData.Domain.VerifyingContract)
}
