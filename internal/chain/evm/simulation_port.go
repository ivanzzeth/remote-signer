package evm

import (
	"context"

	"github.com/ivanzzeth/remote-signer/internal/core/ports"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// SimulationBudgetPort adapts SimulationBudgetRule to
// ports.SimulationBudgetEvaluator.
//
// The rule returns a full SimulationOutcome — balance deltas, decoded events,
// gas, the lot — because the UI renders it. The signing path reads two fields.
// Rather than have the use-case layer depend on the simulator's struct just to
// look at Decision and Reason, the mapping happens here, on the adapter side of
// the boundary where knowing both shapes is fine.
type SimulationBudgetPort struct {
	rule *SimulationBudgetRule
}

// NewSimulationBudgetPort wraps a rule, or returns nil when there is none, so
// that callers can pass the result straight through: a nil evaluator means
// "no simulation fallback", which is a supported configuration.
func NewSimulationBudgetPort(rule *SimulationBudgetRule) ports.SimulationBudgetEvaluator {
	if rule == nil {
		return nil
	}
	return &SimulationBudgetPort{rule: rule}
}

func (p *SimulationBudgetPort) Available() bool {
	return p.rule != nil && p.rule.Available()
}

func (p *SimulationBudgetPort) EvaluateSingle(
	ctx context.Context, req *types.SignRequest, parsed *types.ParsedPayload,
) (*ports.SimulationOutcome, error) {
	out, err := p.rule.EvaluateSingle(ctx, req, parsed)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, nil
	}
	return &ports.SimulationOutcome{Decision: out.Decision, Reason: out.Reason}, nil
}
