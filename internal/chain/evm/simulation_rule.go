package evm

import (
	"context"
	"fmt"
	"log/slog"
	"math/big"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/simulation"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// SimulationBudgetRule is a built-in fallback rule that runs AFTER all user-defined rules.
// When no user whitelist rule matches a sign_type=transaction request:
//   - If simulator not available: return no-match (preserves existing deny/manual-approval behavior)
//   - Simulate the transaction(s)
//   - If simulation detects approval events: return no-match (the existing approval guard
//     and manual approval flow handle this — approve txs without a whitelist rule match
//     naturally route to manual approval)
//   - Extract net balance changes -> feed outflows into budget engine
//   - Budget passes -> allow; budget exceeded -> deny
type SimulationBudgetRule struct {
	simulator  simulation.AnvilForkManager
	budgetRepo storage.BudgetRepository
	logger     *slog.Logger
}

// NewSimulationBudgetRule creates a new SimulationBudgetRule.
// simulator may be nil (in which case the rule always returns no-match).
func NewSimulationBudgetRule(
	simulator simulation.AnvilForkManager,
	budgetRepo storage.BudgetRepository,
	logger *slog.Logger,
) (*SimulationBudgetRule, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &SimulationBudgetRule{
		simulator:  simulator,
		budgetRepo: budgetRepo,
		logger:     logger,
	}, nil
}

// Available returns true if the simulation engine is configured and ready.
func (r *SimulationBudgetRule) Available() bool {
	return r.simulator != nil
}

// SimulationOutcome represents the result of simulation-based evaluation.
type SimulationOutcome struct {
	Decision   string                         // "allow", "deny", "no_match"
	Reason     string                         // human-readable reason for deny
	Simulation *simulation.SimulationResult   // non-nil when simulation ran
}

// BatchSimulationOutcome represents the result of batch simulation-based evaluation.
type BatchSimulationOutcome struct {
	Decision   string                              // "allow", "deny", "no_match"
	Simulation *simulation.BatchSimulationResult   // non-nil when simulation ran
}

// EvaluateSingle evaluates a single sign request that wasn't matched by any user rule.
// Returns:
//   - decision="allow": simulation passed, budget OK
//   - decision="no_match": simulator not available, non-transaction, or approval detected
//     (caller falls through to existing manual-approval / deny logic)
//   - decision="deny": simulation reverted or budget exceeded
func (r *SimulationBudgetRule) EvaluateSingle(
	ctx context.Context,
	req *types.SignRequest,
	parsed *types.ParsedPayload,
) (*SimulationOutcome, error) {
	if r.simulator == nil {
		return &SimulationOutcome{Decision: "no_match"}, nil
	}

	// Only applies to sign_type: transaction
	if req.SignType != SignTypeTransaction {
		return &SimulationOutcome{Decision: "no_match"}, nil
	}

	// Extract transaction params from parsed payload
	to, value, data, gas, err := extractTxParamsForSimulation(parsed)
	if err != nil {
		r.logger.Warn("failed to extract tx params for simulation", "error", err)
		return &SimulationOutcome{Decision: "no_match"}, nil
	}

	// Simulate
	simReq := &simulation.SimulationRequest{
		ChainID: req.ChainID,
		From:    req.SignerAddress,
		To:      to,
		Value:   value,
		Data:    data,
		Gas:     gas,
	}

	result, err := r.simulator.Simulate(ctx, simReq)
	if err != nil {
		r.logger.Error("simulation failed in fallback rule", "error", err, "chain_id", req.ChainID, "signer", req.SignerAddress)
		return &SimulationOutcome{Decision: "no_match"}, nil
	}

	// Check if simulation itself reverted — this means the tx has a problem
	// (insufficient balance, expired data, wrong params), NOT a budget issue.
	if !result.Success {
		reason := fmt.Sprintf("transaction simulation reverted: %s", result.RevertReason)
		r.logger.Warn("simulation reverted in fallback rule",
			"chain_id", req.ChainID,
			"signer", req.SignerAddress,
			"revert_reason", result.RevertReason,
		)
		return &SimulationOutcome{Decision: "deny", Reason: reason, Simulation: result}, nil
	}

	// Budget check against balance changes (outflows only).
	// Approve events don't move tokens — they have no outflow, so budget is unaffected.
	if err := r.checkBudgetFromBalanceChanges(ctx, req.ChainID, req.SignerAddress, result.BalanceChanges); err != nil {
		reason := fmt.Sprintf("simulation budget exceeded: %s", err)
		r.logger.Warn("budget check failed in simulation fallback",
			"chain_id", req.ChainID,
			"signer", req.SignerAddress,
			"error", err,
		)
		return &SimulationOutcome{Decision: "deny", Reason: reason, Simulation: result}, nil
	}

	return &SimulationOutcome{Decision: "allow", Simulation: result}, nil
}

// EvaluateBatch evaluates a batch of transactions for the batch sign endpoint.
// All transactions must share the same chain_id and signer_address.
// Budget is checked against NET balance changes across the entire batch.
// Returns:
//   - decision="allow": all txs pass simulation and budget
//   - decision="no_match": approval detected in any tx (defers to manual approval)
//   - decision="deny": simulation failed or budget exceeded
func (r *SimulationBudgetRule) EvaluateBatch(
	ctx context.Context,
	chainID string,
	signerAddress string,
	txParams []simulation.TxParams,
) (*BatchSimulationOutcome, error) {
	if r.simulator == nil {
		return &BatchSimulationOutcome{Decision: "no_match"}, nil
	}

	if len(txParams) == 0 {
		return nil, fmt.Errorf("empty batch")
	}

	// Simulate entire batch
	batchReq := &simulation.BatchSimulationRequest{
		ChainID:      chainID,
		From:         signerAddress,
		Transactions: txParams,
	}

	batchResult, err := r.simulator.SimulateBatch(ctx, batchReq)
	if err != nil {
		r.logger.Error("batch simulation failed", "error", err, "chain_id", chainID, "signer", signerAddress)
		return &BatchSimulationOutcome{Decision: "no_match"}, nil
	}

	// Check if any tx reverted — reject entire batch
	for i, result := range batchResult.Results {
		if !result.Success {
			r.logger.Warn("batch simulation tx reverted",
				"index", i,
				"chain_id", chainID,
				"signer", signerAddress,
				"revert_reason", result.RevertReason,
			)
			return &BatchSimulationOutcome{Decision: "deny", Simulation: batchResult}, nil
		}
	}

	// Budget check against NET balance changes (not per-tx).
	// Approve events don't move tokens — they have no outflow, so budget is unaffected.
	if err := r.checkBudgetFromBalanceChanges(ctx, chainID, signerAddress, batchResult.NetBalanceChanges); err != nil {
		r.logger.Warn("budget check failed in batch simulation",
			"chain_id", chainID,
			"signer", signerAddress,
			"error", err,
		)
		return &BatchSimulationOutcome{Decision: "deny", Simulation: batchResult}, nil
	}

	return &BatchSimulationOutcome{Decision: "allow", Simulation: batchResult}, nil
}

// checkBudgetFromBalanceChanges validates that outflow balance changes are within budget.
// For each net outflow, it creates a budget entry with unit "chainID:tokenAddress".
// If no budget repo is configured, passes through (budget is optional).
func (r *SimulationBudgetRule) checkBudgetFromBalanceChanges(
	ctx context.Context,
	chainID string,
	signerAddress string,
	changes []simulation.BalanceChange,
) error {
	if r.budgetRepo == nil {
		// No budget repo configured, pass through
		return nil
	}

	for _, change := range changes {
		// Only check outflows (negative amounts)
		if change.Amount == nil || change.Amount.Sign() >= 0 {
			continue
		}

		absAmount := new(big.Int).Abs(change.Amount)
		unit := rule.NormalizeBudgetUnit(fmt.Sprintf("%s:%s", chainID, change.Token))

		r.logger.Debug("simulation budget check",
			"chain_id", chainID,
			"signer", signerAddress,
			"token", change.Token,
			"unit", unit,
			"amount", absAmount.String(),
		)

		// Use a synthetic rule ID based on signer address for simulation-based budgets
		syntheticRuleID := types.RuleID("sim:" + strings.ToLower(signerAddress))

		budget, err := r.budgetRepo.GetByRuleID(ctx, syntheticRuleID, unit)
		if err != nil {
			if types.IsNotFound(err) {
				// No budget record for this token — allow (no constraint configured)
				r.logger.Debug("no simulation budget record, allowing",
					"signer", signerAddress,
					"unit", unit,
				)
				continue
			}
			return fmt.Errorf("failed to get simulation budget: %w", err)
		}

		// Check per-tx limit
		if budget.MaxPerTx != "" && budget.MaxPerTx != "-1" {
			maxPerTx := new(big.Int)
			if _, ok := maxPerTx.SetString(budget.MaxPerTx, 10); !ok {
				return fmt.Errorf("invalid max_per_tx value %q", budget.MaxPerTx)
			}
			if absAmount.Cmp(maxPerTx) > 0 {
				return fmt.Errorf("amount %s exceeds per-tx limit %s for unit %s", absAmount.String(), budget.MaxPerTx, unit)
			}
		}

		// Atomic spend
		if err := r.budgetRepo.AtomicSpend(ctx, syntheticRuleID, unit, absAmount.String()); err != nil {
			if err == storage.ErrBudgetExceeded {
				return fmt.Errorf("budget exceeded for unit %s (amount: %s)", unit, absAmount.String())
			}
			return fmt.Errorf("budget deduction failed: %w", err)
		}

		r.logger.Info("simulation budget deducted",
			"signer", signerAddress,
			"unit", unit,
			"amount", absAmount.String(),
		)
	}

	return nil
}

// extractTxParamsForSimulation extracts transaction parameters from a parsed payload for simulation.
func extractTxParamsForSimulation(parsed *types.ParsedPayload) (to, value, data, gas string, err error) {
	if parsed == nil {
		return "", "", "", "", fmt.Errorf("parsed payload is nil")
	}

	if parsed.Recipient != nil {
		to = *parsed.Recipient
	}
	if parsed.Value != nil {
		// Convert decimal value to hex for simulation
		val := new(big.Int)
		if _, ok := val.SetString(*parsed.Value, 10); ok {
			value = "0x" + val.Text(16)
		} else if _, ok := val.SetString(strings.TrimPrefix(*parsed.Value, "0x"), 16); ok {
			value = "0x" + val.Text(16)
		}
	}
	if len(parsed.RawData) > 0 {
		data = fmt.Sprintf("0x%x", parsed.RawData)
	} else if parsed.MethodSig != nil {
		data = *parsed.MethodSig
	}

	return to, value, data, gas, nil
}
