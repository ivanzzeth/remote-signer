// Package rule implements rule engine, budget checking, and whitelist/blocklist evaluation.
// budget_checker.go defines the BudgetChecker struct and its core CheckAndDeductBudget method
// (auto-creation and alert helpers live in budget_checker_auto.go).
package rule

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// BudgetChecker checks and deducts budget for rule instances
type BudgetChecker struct {
	budgetRepo       storage.BudgetRepository
	templateRepo     storage.TemplateRepository
	notifier         BudgetAlertNotifier
	jsEvaluator      BudgetJSEvaluator // optional: for method "js" budget metering
	decimalsQuerier  DecimalsQuerier    // optional: for auto-querying ERC20 decimals when unit_decimal is true
	logger           *slog.Logger

	// decimalsCache caches queried decimals results keyed by "chainID:address" (lowercased).
	// SECURITY: Cache is per BudgetChecker instance; decimals are immutable for deployed tokens.
	decimalsCacheMu sync.RWMutex
	decimalsCache   map[string]int
}

// NewBudgetChecker creates a new budget checker
func NewBudgetChecker(
	budgetRepo storage.BudgetRepository,
	templateRepo storage.TemplateRepository,
	logger *slog.Logger,
) *BudgetChecker {
	return &BudgetChecker{
		budgetRepo:    budgetRepo,
		templateRepo:  templateRepo,
		logger:        logger,
		decimalsCache: make(map[string]int),
	}
}

// SetNotifier sets the budget alert notifier.
// This is a setter instead of a constructor param because the NotifyService may
// be created after the BudgetChecker in the application initialization order.
func (bc *BudgetChecker) SetNotifier(n BudgetAlertNotifier) {
	bc.notifier = n
}

// SetJSEvaluator sets the JS evaluator for budget_metering method "js".
// Required when any template uses method "js"; otherwise CheckAndDeductBudget fails closed for those rules.
func (bc *BudgetChecker) SetJSEvaluator(eval BudgetJSEvaluator) {
	bc.jsEvaluator = eval
}

// SetDecimalsQuerier sets the decimals querier for auto-querying ERC20 token decimals.
// When set and unit_decimal is true, address-like units with decimals=0 will auto-query
// via RPC instead of failing. Without this, address units with decimals=0 fail-closed.
func (bc *BudgetChecker) SetDecimalsQuerier(q DecimalsQuerier) {
	bc.decimalsQuerier = q
}

// CheckAndDeductBudget checks if the rule has budget and deducts the spending amount.
// Returns:
//   - (true, nil) if budget is available or no budget constraint
//   - (false, nil) if budget is exceeded
//   - (false, err) if an error occurred
func (bc *BudgetChecker) CheckAndDeductBudget(
	ctx context.Context,
	rule *types.Rule,
	req *types.SignRequest,
	parsed *types.ParsedPayload,
) (bool, error) {
	if bc.budgetRepo == nil || rule.TemplateID == nil {
		// No budget system or not an instance rule — pass through
		return true, nil
	}

	// Load template to get BudgetMetering
	tmpl, err := bc.templateRepo.Get(ctx, *rule.TemplateID)
	if err != nil {
		if types.IsNotFound(err) {
			// SECURITY: template deleted but instance still active — fail-closed.
			// The budget constraint cannot be verified without the template.
			return false, fmt.Errorf("template %s deleted but instance rule %s still active", *rule.TemplateID, rule.ID)
		}
		return false, fmt.Errorf("failed to load template: %w", err)
	}

	// Parse budget metering
	var metering types.BudgetMetering
	if len(tmpl.BudgetMetering) == 0 {
		// No metering defined — no budget constraint
		return true, nil
	}
	// Substitute template variables in raw JSON before parsing so that int fields
	// like max_tx_count can be resolved from "${var}" strings to actual integers.
	meteringJSON := SubstituteMeteringJSON(tmpl.BudgetMetering, rule.Variables)
	if err := json.Unmarshal(meteringJSON, &metering); err != nil {
		return false, fmt.Errorf("failed to parse budget metering: %w", err)
	}

	if metering.Method == "" || metering.Method == "none" {
		return true, nil
	}

	// For dynamic budget with JS method, the unit is determined at evaluation time,
	// so we defer budget lookup until after JS evaluation.
	if metering.Dynamic && metering.Method == "js" {
		return bc.checkDynamicBudget(ctx, rule, req, parsed, metering)
	}

	unit := metering.Unit
	if unit == "" {
		unit = "count"
	}
	// Substitute rule instance variables so unit matches the budget record created at sync (e.g. "${chain_id}:${token_address}" -> "1:0xA0b8...").
	unit = substituteUnitVariables(unit, rule.Variables)
	// Normalize so lookup matches stored unit regardless of address casing (0xA0b8 vs 0xa0b8).
	unit = NormalizeBudgetUnit(unit)

	// Get budget for this rule+unit
	budget, err := bc.budgetRepo.GetByRuleID(ctx, rule.ID, unit)
	if err != nil {
		if types.IsNotFound(err) {
			// SECURITY: no budget record for a rule with metering — fail-closed.
			// Budget record should be created at rule initialization. Missing record
			// means incomplete setup; allowing would bypass budget constraints.
			return false, fmt.Errorf("no budget record for rule %s (unit=%s) with metering method %q", rule.ID, unit, metering.Method)
		}
		return false, fmt.Errorf("failed to get budget: %w", err)
	}

	// Check periodic renewal
	// SECURITY: fail-closed on renewal error — stale budget data could allow
	// spending beyond the intended period limit.
	if err := bc.checkPeriodicRenewal(ctx, rule, budget, unit); err != nil {
		return false, fmt.Errorf("failed to check periodic renewal for rule %s: %w", rule.ID, err)
	}

	// Extract spending amount (method "js" uses JS evaluator; others use ExtractAmount)
	var amount *big.Int
	if metering.Method == "js" {
		if bc.jsEvaluator == nil {
			return false, fmt.Errorf("budget metering method %q requires SetJSEvaluator to be set", metering.Method)
		}
		budgetResult, evalErr := bc.jsEvaluator.EvaluateBudget(ctx, rule, req, parsed)
		if evalErr != nil {
			return false, fmt.Errorf("js budget evaluation: %w", evalErr)
		}
		amount = budgetResult.Amount
	} else {
		amount, err = ExtractAmount(metering, req, parsed)
		if err != nil {
			return false, fmt.Errorf("failed to extract amount: %w", err)
		}
	}

	// Check per-tx limit. Only -1 means no cap; 0 means cap of 0.
	// SECURITY: fail-closed on parse error — unparseable limit could allow
	// arbitrarily large transactions.
	if budget.MaxPerTx != "" && budget.MaxPerTx != "-1" {
		maxPerTx := new(big.Int)
		if _, ok := maxPerTx.SetString(budget.MaxPerTx, 10); !ok {
			return false, fmt.Errorf("invalid max_per_tx value %q for rule %s", budget.MaxPerTx, rule.ID)
		}
		if amount.Cmp(maxPerTx) > 0 {
			bc.logger.Warn("per-tx budget exceeded",
				"rule_id", rule.ID,
				"amount", amount.String(),
				"max_per_tx", budget.MaxPerTx,
			)
			return false, nil
		}
	}

	// Atomic spend (checks total budget and tx count atomically)
	if err := bc.budgetRepo.AtomicSpend(ctx, rule.ID, unit, amount.String()); err != nil {
		if err == storage.ErrBudgetExceeded {
			bc.logger.Warn("total budget exceeded",
				"rule_id", rule.ID,
				"unit", unit,
				"amount", amount.String(),
			)
			return false, nil
		}
		return false, fmt.Errorf("failed to deduct budget: %w", err)
	}

	// Log at Info so operators can verify budget usage and periodic renewal in production
	bc.logger.Info("budget deducted",
		"rule_id", rule.ID,
		"unit", unit,
		"amount", amount.String(),
		"max_total", budget.MaxTotal,
		"tx_count_after", budget.TxCount+1,
	)

	// SECURITY (V3-9): Re-fetch budget after AtomicSpend so alert goroutine sees post-spend data.
	// The budget variable above is a pre-spend snapshot; using it would cause the alert to
	// evaluate against stale Spent values, potentially missing threshold crossings.
	freshBudget, freshErr := bc.budgetRepo.GetByRuleID(ctx, rule.ID, unit)
	if freshErr != nil {
		bc.logger.Warn("failed to fetch fresh budget for alert check", "error", freshErr)
	} else {
		// #nosec G118 -- intentional: async alert check must outlive request context
		go bc.checkAlertThreshold(rule.ID, unit, freshBudget)
	}

	return true, nil
}

// checkDynamicBudget handles the dynamic budget path where the unit is determined by JS evaluation.
// Called when metering.Dynamic is true and method is "js".
//
// SECURITY (HIGH-1 known limitation): A single multicall TX that batches N transfers
// only costs 1 tx_count. This is a v1 trade-off; the per-token amount budget still applies
// to each transfer's decoded amount if the JS validateBudget correctly decodes the inner calls.
// For multicall-unaware scripts, the tx_count fallback undercounts. Document in operator guide.
func (bc *BudgetChecker) checkDynamicBudget(
	ctx context.Context,
	rule *types.Rule,
	req *types.SignRequest,
	parsed *types.ParsedPayload,
	metering types.BudgetMetering,
) (bool, error) {
	if bc.jsEvaluator == nil {
		return false, fmt.Errorf("budget metering method %q requires SetJSEvaluator to be set", metering.Method)
	}

	budgetResult, evalErr := bc.jsEvaluator.EvaluateBudget(ctx, rule, req, parsed)
	if evalErr != nil {
		return false, fmt.Errorf("js budget evaluation: %w", evalErr)
	}

	amount := budgetResult.Amount
	rawUnit := budgetResult.Unit
	if rawUnit == "" {
		return false, fmt.Errorf("dynamic budget JS must return {amount, unit} but unit was empty")
	}

	// SECURITY (CRITICAL-2): Validate unit string to prevent injection and storage abuse.
	if err := validateDynamicUnit(rawUnit); err != nil {
		return false, fmt.Errorf("invalid dynamic budget unit: %w", err)
	}

	// Prefer request chain_id (always present) over rule chain_id (may be empty for multi-chain rules)
	chainID := req.ChainID
	if chainID == "" && rule.ChainID != nil {
		chainID = *rule.ChainID
	}
	unit := NormalizeBudgetUnit(chainID + ":" + rawUnit)

	// Look up or auto-create budget for the dynamic unit
	budget, err := bc.budgetRepo.GetByRuleID(ctx, rule.ID, unit)
	if err != nil {
		if !types.IsNotFound(err) {
			return false, fmt.Errorf("failed to get dynamic budget: %w", err)
		}
		budget, err = bc.autoCreateDynamicBudget(ctx, rule, req, unit, rawUnit, metering)
		if err != nil {
			return false, fmt.Errorf("failed to auto-create dynamic budget: %w", err)
		}
	}

	// Check periodic renewal
	if err := bc.checkPeriodicRenewal(ctx, rule, budget, unit); err != nil {
		return false, fmt.Errorf("failed to check periodic renewal for rule %s: %w", rule.ID, err)
	}

	// Check per-tx limit
	if budget.MaxPerTx != "" && budget.MaxPerTx != "-1" {
		maxPerTx := new(big.Int)
		if _, ok := maxPerTx.SetString(budget.MaxPerTx, 10); !ok {
			return false, fmt.Errorf("invalid max_per_tx value %q for rule %s", budget.MaxPerTx, rule.ID)
		}
		if amount.Cmp(maxPerTx) > 0 {
			bc.logger.Warn("per-tx budget exceeded",
				"rule_id", rule.ID,
				"amount", amount.String(),
				"max_per_tx", budget.MaxPerTx,
			)
			return false, nil
		}
	}

	// Atomic spend
	if err := bc.budgetRepo.AtomicSpend(ctx, rule.ID, unit, amount.String()); err != nil {
		if err == storage.ErrBudgetExceeded {
			bc.logger.Warn("total budget exceeded",
				"rule_id", rule.ID,
				"unit", unit,
				"amount", amount.String(),
			)
			return false, nil
		}
		return false, fmt.Errorf("failed to deduct budget: %w", err)
	}

	bc.logger.Info("budget deducted",
		"rule_id", rule.ID,
		"unit", unit,
		"amount", amount.String(),
		"max_total", budget.MaxTotal,
		"tx_count_after", budget.TxCount+1,
	)

	// SECURITY (V3-9): Re-fetch budget after AtomicSpend so alert goroutine sees post-spend data.
	freshBudget, freshErr := bc.budgetRepo.GetByRuleID(ctx, rule.ID, unit)
	if freshErr != nil {
		bc.logger.Warn("failed to fetch fresh budget for alert check", "error", freshErr)
	} else {
		// #nosec G118 -- intentional: async alert check must outlive request context
		go bc.checkAlertThreshold(rule.ID, unit, freshBudget)
	}

	return true, nil
}

// checkPeriodicRenewal checks if the budget needs to be reset for a new period
func (bc *BudgetChecker) checkPeriodicRenewal(ctx context.Context, rule *types.Rule, budget *types.RuleBudget, unit string) error {
	if rule.BudgetPeriod == nil || rule.BudgetPeriodStart == nil {
		return nil // No periodic renewal
	}

	now := time.Now()
	period := *rule.BudgetPeriod
	start := *rule.BudgetPeriodStart

	if period <= 0 || now.Before(start) {
		return nil
	}

	// Calculate current period
	elapsed := now.Sub(start)
	periodIndex := int64(elapsed / period)
	currentPeriodStart := start.Add(time.Duration(periodIndex) * period)

	// If budget was updated before current period, it belongs to an old period — reset
	if budget.UpdatedAt.Before(currentPeriodStart) {
		bc.logger.Info("resetting budget for new period",
			"rule_id", rule.ID,
			"unit", unit,
			"period_index", periodIndex,
			"current_period_start", currentPeriodStart,
		)
		return bc.budgetRepo.ResetBudget(ctx, rule.ID, unit, currentPeriodStart)
	}

	return nil
}
