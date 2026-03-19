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
// SimBudgetDefaults configures auto-created budget records for unknown tokens.
// Values are in human-readable units (e.g. "100" = 100 USDC, "0.01" = 0.01 ETH).
// Decimals are auto-queried from chain via DecimalsQuerier.
type SimBudgetDefaults struct {
	NativeMaxTotal string // max total native per period (human-readable, e.g. "0.01")
	NativeMaxPerTx string // max native per tx (human-readable, e.g. "0.005")
	ERC20MaxTotal  string // max total ERC20 per period per token (human-readable, e.g. "100")
	ERC20MaxPerTx  string // max ERC20 per tx per token (human-readable, e.g. "50")
}

// ManagedSignerLister returns the set of all signer addresses managed by the system.
type ManagedSignerLister interface {
	ListManagedAddresses(ctx context.Context) (map[string]bool, error)
}

type SimulationBudgetRule struct {
	simulator        simulation.AnvilForkManager
	budgetRepo       storage.BudgetRepository
	budgetDefaults   *SimBudgetDefaults
	decimalsQuerier  rule.DecimalsQuerier
	signerLister     ManagedSignerLister
	logger           *slog.Logger
}

// NewSimulationBudgetRule creates a new SimulationBudgetRule.
// simulator may be nil (in which case the rule always returns no-match).
// budgetDefaults may be nil (in which case unknown tokens have no limit).
func NewSimulationBudgetRule(
	simulator simulation.AnvilForkManager,
	budgetRepo storage.BudgetRepository,
	budgetDefaults *SimBudgetDefaults,
	decimalsQuerier rule.DecimalsQuerier,
	signerLister ManagedSignerLister,
	logger *slog.Logger,
) (*SimulationBudgetRule, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &SimulationBudgetRule{
		simulator:       simulator,
		budgetRepo:      budgetRepo,
		budgetDefaults:  budgetDefaults,
		decimalsQuerier: decimalsQuerier,
		signerLister:    signerLister,
		logger:          logger,
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

// EVMAdapterSignerLister adapts EVMAdapter to ManagedSignerLister.
type EVMAdapterSignerLister struct {
	adapter *EVMAdapter
}

// NewEVMAdapterSignerLister creates a new adapter.
func NewEVMAdapterSignerLister(adapter *EVMAdapter) *EVMAdapterSignerLister {
	return &EVMAdapterSignerLister{adapter: adapter}
}

// ListManagedAddresses returns all managed signer addresses as a lowercase set.
func (l *EVMAdapterSignerLister) ListManagedAddresses(ctx context.Context) (map[string]bool, error) {
	signers, err := l.adapter.ListSigners(ctx)
	if err != nil {
		return nil, err
	}
	result := make(map[string]bool, len(signers))
	for _, s := range signers {
		result[strings.ToLower(s.Address)] = true
	}
	return result, nil
}

// getManagedSigners returns the set of all managed signer addresses (lowercase).
func (r *SimulationBudgetRule) getManagedSigners(ctx context.Context) map[string]bool {
	if r.signerLister == nil {
		return nil
	}
	signers, err := r.signerLister.ListManagedAddresses(ctx)
	if err != nil {
		r.logger.Warn("failed to list managed signers for approval check", "error", err)
		return nil
	}
	return signers
}

// hasManagedSignerApproval checks if the simulation result contains approval events for any managed signer.
func (r *SimulationBudgetRule) hasManagedSignerApproval(ctx context.Context, result *simulation.SimulationResult) bool {
	managedSigners := r.getManagedSigners(ctx)
	return simulation.DetectApproval(result.Events, managedSigners)
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
	// Always run budget check first, even for approve txs (approve has no outflow, so budget is unaffected).
	if err := r.checkBudgetFromBalanceChanges(ctx, req.ChainID, req.SignerAddress, result.BalanceChanges); err != nil {
		reason := fmt.Sprintf("simulation budget exceeded: %s", err)
		r.logger.Warn("budget check failed in simulation fallback",
			"chain_id", req.ChainID,
			"signer", req.SignerAddress,
			"error", err,
		)
		return &SimulationOutcome{Decision: "deny", Reason: reason, Simulation: result}, nil
	}

	// After budget passes: check if any managed signer has approval events.
	// Only approvals where the owner is one of our managed signers matter.
	// Internal contract-to-contract approvals (DEX router internals) are ignored.
	if r.hasManagedSignerApproval(ctx, result) {
		r.logger.Info("approval detected for managed signer, deferring to manual approval",
			"chain_id", req.ChainID,
			"signer", req.SignerAddress,
		)
		return &SimulationOutcome{Decision: "no_match", Simulation: result}, nil
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

	// After budget passes: check if any tx has approval events for our managed signers.
	managedSigners := r.getManagedSigners(ctx)
	for i, result := range batchResult.Results {
		if simulation.DetectApproval(result.Events, managedSigners) {
			r.logger.Info("approval detected for managed signer in batch, deferring to manual approval",
				"chain_id", chainID,
				"signer", signerAddress,
				"tx_index", i,
			)
			return &BatchSimulationOutcome{Decision: "no_match", Simulation: batchResult}, nil
		}
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
			if !types.IsNotFound(err) {
				return fmt.Errorf("failed to get simulation budget: %w", err)
			}
			// Auto-create budget record with defaults
			budget = r.autoCreateBudget(ctx, chainID, signerAddress, change.Token, syntheticRuleID, unit)
			if budget == nil {
				continue // no defaults → allow without limit
			}
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

// autoCreateBudget creates a budget record with defaults for a previously unseen token.
// Returns nil if no defaults are configured (allow without limit).
func (r *SimulationBudgetRule) autoCreateBudget(
	ctx context.Context,
	chainID string,
	signerAddress string,
	token string,
	syntheticRuleID types.RuleID,
	unit string,
) *types.RuleBudget {
	if r.budgetDefaults == nil {
		r.logger.Debug("no simulation budget defaults, allowing without limit",
			"signer", signerAddress, "unit", unit)
		return nil
	}

	isNative := strings.ToLower(token) == "native"

	var maxTotalHuman, maxPerTxHuman string
	var decimals int
	if isNative {
		maxTotalHuman = r.budgetDefaults.NativeMaxTotal
		maxPerTxHuman = r.budgetDefaults.NativeMaxPerTx
		decimals = 18
	} else {
		maxTotalHuman = r.budgetDefaults.ERC20MaxTotal
		maxPerTxHuman = r.budgetDefaults.ERC20MaxPerTx
		// Query decimals from chain
		if r.decimalsQuerier != nil {
			d, dErr := r.decimalsQuerier.QueryDecimals(ctx, chainID, token)
			if dErr != nil {
				r.logger.Warn("failed to query decimals, using 18",
					"token", token, "chain_id", chainID, "error", dErr)
				decimals = 18
			} else {
				decimals = d
			}
		} else {
			decimals = 18
		}
	}

	if maxTotalHuman == "" {
		r.logger.Debug("no simulation budget default for token type, allowing",
			"signer", signerAddress, "unit", unit, "native", isNative)
		return nil
	}

	// Convert human-readable to raw (e.g. "100" with 6 decimals → "100000000")
	maxTotal := humanToRaw(maxTotalHuman, decimals)
	maxPerTx := humanToRaw(maxPerTxHuman, decimals)

	newBudget := &types.RuleBudget{
		ID:       types.BudgetID(syntheticRuleID, unit),
		RuleID:   syntheticRuleID,
		Unit:     unit,
		MaxTotal: maxTotal,
		MaxPerTx: maxPerTx,
		AlertPct: 80,
	}

	created, _, createErr := r.budgetRepo.CreateOrGet(ctx, newBudget)
	if createErr != nil {
		r.logger.Error("failed to auto-create simulation budget",
			"unit", unit, "error", createErr)
		return nil
	}

	r.logger.Info("auto-created simulation budget",
		"signer", signerAddress,
		"unit", unit,
		"token", token,
		"decimals", decimals,
		"max_total", maxTotal,
		"max_per_tx", maxPerTx,
	)
	return created
}

// humanToRaw converts a human-readable decimal string to raw integer with the given decimals.
// e.g. humanToRaw("100", 6) → "100000000", humanToRaw("0.01", 18) → "10000000000000000"
func humanToRaw(human string, decimals int) string {
	if human == "" || human == "-1" {
		return human // -1 = unlimited
	}

	// Split on decimal point
	parts := strings.SplitN(human, ".", 2)
	intPart := parts[0]
	fracPart := ""
	if len(parts) == 2 {
		fracPart = parts[1]
	}

	// Pad or trim fractional part to exactly `decimals` digits
	if len(fracPart) > decimals {
		fracPart = fracPart[:decimals]
	} else {
		fracPart += strings.Repeat("0", decimals-len(fracPart))
	}

	raw := intPart + fracPart
	// Remove leading zeros (but keep at least "0")
	raw = strings.TrimLeft(raw, "0")
	if raw == "" {
		raw = "0"
	}
	return raw
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
