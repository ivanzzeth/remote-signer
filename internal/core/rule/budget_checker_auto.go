// Package rule implements rule engine, budget checking, and whitelist/blocklist evaluation.
// This file handles auto-creation of dynamic budget records, alert threshold checks,
// and cached ERC20 decimals querying.
package rule

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// autoCreateDynamicBudget creates a new budget record for a dynamic unit discovered at evaluation time.
// Looks up known_units config first, then falls back to unknown_default. Applies unit_decimal conversion.
//
// SECURITY (CRITICAL-2): Enforces MaxDynamicUnits to cap the number of distinct units per rule.
// SECURITY (CRITICAL-3): Uses CreateOrGet (upsert) to prevent TOCTOU race on concurrent auto-creation.
func (bc *BudgetChecker) autoCreateDynamicBudget(
	ctx context.Context,
	rule *types.Rule,
	req *types.SignRequest,
	normalizedUnit string,
	rawUnit string,
	metering types.BudgetMetering,
) (*types.RuleBudget, error) {
	// SECURITY (CRITICAL-2): Enforce max dynamic units per rule.
	maxUnits := metering.MaxDynamicUnits
	if maxUnits <= 0 {
		maxUnits = defaultMaxDynamicUnits
	}
	unitCount, err := bc.budgetRepo.CountByRuleID(ctx, rule.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to count dynamic units: %w", err)
	}
	if unitCount >= maxUnits {
		return nil, fmt.Errorf("dynamic budget unit limit reached (%d/%d) for rule %s", unitCount, maxUnits, rule.ID)
	}

	// Look up unit config: check known_units by raw unit (before chain_id prefix), then unknown_default
	var conf *types.UnitConf
	if metering.KnownUnits != nil {
		if c, ok := metering.KnownUnits[rawUnit]; ok {
			conf = &c
		} else if c, ok := metering.KnownUnits[NormalizeBudgetUnit(rawUnit)]; ok {
			conf = &c
		}
	}
	if conf == nil {
		if metering.UnknownDefault != nil {
			conf = metering.UnknownDefault
		} else {
			// SECURITY: no config for unknown unit and no default — fail-closed
			return nil, fmt.Errorf("no budget config for dynamic unit %q and no unknown_default configured", rawUnit)
		}
	}

	maxTotal := conf.MaxTotal
	maxPerTx := conf.MaxPerTx

	// unit_decimal conversion: convert human-readable limits to raw big integer
	if metering.UnitDecimal {
		decimals := conf.Decimals

		if decimals == 0 {
			// Decimals not explicitly configured. Behavior depends on the unit type:
			// - Address-like unit (0x + 40 hex chars): auto-query erc20.decimals() via RPC
			// - Named unit (sign_count, tx_count, native without explicit decimals): skip conversion
			//   These are integer counters where decimals=0 means no fractional part.
			unitBase := extractUnitBase(rawUnit)
			if isEthAddressRe.MatchString(unitBase) {
				chainID := req.ChainID
				if chainID == "" && rule.ChainID != nil {
					chainID = *rule.ChainID
				}
				queried, queryErr := bc.queryDecimalsCached(ctx, chainID, unitBase)
				if queryErr != nil {
					errMsg := queryErr.Error()
					if strings.Contains(errMsg, "execution reverted") || strings.Contains(errMsg, "rpc error 3:") {
						bc.logger.Debug("decimals() reverted, not an ERC20 token, defaulting to decimals=0",
							"unit", rawUnit, "chain_id", chainID)
						decimals = 0
					} else {
						return nil, fmt.Errorf("unit_decimal auto-query failed for unit %q on chain %q: %w", rawUnit, chainID, queryErr)
					}
				} else {
					decimals = queried
				}
			}
		}

		if err := validateDecimals(decimals); err != nil {
			return nil, fmt.Errorf("invalid decimals for unit %q: %w", rawUnit, err)
		}

		if decimals > 0 {
			var convertErr error
			maxTotal, convertErr = decimalToRaw(maxTotal, decimals)
			if convertErr != nil {
				return nil, fmt.Errorf("failed to convert max_total for unit %q: %w", rawUnit, convertErr)
			}
			if maxPerTx != "" && maxPerTx != "-1" {
				maxPerTx, convertErr = decimalToRaw(maxPerTx, decimals)
				if convertErr != nil {
					return nil, fmt.Errorf("failed to convert max_per_tx for unit %q: %w", rawUnit, convertErr)
				}
			}
		}
	}

	alertPct := conf.AlertPct
	if alertPct <= 0 {
		alertPct = 80
	}

	budget := &types.RuleBudget{
		ID:         types.BudgetID(rule.ID, normalizedUnit),
		RuleID:     rule.ID,
		Unit:       normalizedUnit,
		MaxTotal:   maxTotal,
		MaxPerTx:   maxPerTx,
		Spent:      "0",
		AlertPct:   alertPct,
		TxCount:    0,
		MaxTxCount: conf.MaxTxCount,
	}

	// SECURITY (CRITICAL-3): Use CreateOrGet to prevent TOCTOU race.
	result, created, err := bc.budgetRepo.CreateOrGet(ctx, budget)
	if err != nil {
		return nil, fmt.Errorf("failed to create-or-get budget record: %w", err)
	}

	if created {
		postCount, countErr := bc.budgetRepo.CountByRuleID(ctx, rule.ID)
		if countErr != nil {
			if delErr := bc.budgetRepo.Delete(ctx, budget.ID); delErr != nil {
				bc.logger.Error("failed to delete budget after count error",
					"rule_id", rule.ID, "unit", normalizedUnit, "error", delErr)
			}
			return nil, fmt.Errorf("failed to re-count dynamic units after create: %w", countErr)
		}
		if postCount > maxUnits {
			if delErr := bc.budgetRepo.Delete(ctx, budget.ID); delErr != nil {
				bc.logger.Error("failed to delete excess dynamic budget",
					"rule_id", rule.ID, "unit", normalizedUnit, "error", delErr)
			}
			return nil, fmt.Errorf("dynamic budget unit limit exceeded after race (%d/%d) for rule %s", postCount, maxUnits, rule.ID)
		}

		bc.logger.Info("auto-created dynamic budget record",
			"rule_id", rule.ID,
			"unit", normalizedUnit,
			"raw_unit", rawUnit,
			"max_total", maxTotal,
			"max_per_tx", maxPerTx,
		)
	}

	return result, nil
}

// checkAlertThreshold checks if the budget usage has reached the alert threshold.
func (bc *BudgetChecker) checkAlertThreshold(ruleID types.RuleID, unit string, budget *types.RuleBudget) {
	if budget.AlertSent || budget.AlertPct <= 0 || budget.MaxTotal == "" || budget.MaxTotal == "-1" || budget.MaxTotal == "0" {
		return
	}

	spent := new(big.Int)
	maxTotal := new(big.Int)

	if _, ok := spent.SetString(budget.Spent, 10); !ok {
		return
	}
	if _, ok := maxTotal.SetString(budget.MaxTotal, 10); !ok {
		return
	}

	pct := new(big.Int).Mul(spent, big.NewInt(100))
	pct.Div(pct, maxTotal)

	if pct.Int64() >= int64(budget.AlertPct) {
		bc.logger.Warn("budget alert threshold reached",
			"rule_id", ruleID,
			"unit", unit,
			"spent", budget.Spent,
			"max_total", budget.MaxTotal,
			"pct", pct.Int64(),
			"alert_pct", budget.AlertPct,
		)

		if bc.notifier != nil {
			nctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := bc.notifier.SendBudgetAlert(nctx, ruleID, unit, budget.Spent, budget.MaxTotal, pct.Int64(), budget.AlertPct); err != nil {
				bc.logger.Error("failed to send budget alert notification",
					"rule_id", ruleID, "unit", unit, "error", err)
				return
			}
		}

		if bc.budgetRepo != nil {
			mctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := bc.budgetRepo.MarkAlertSent(mctx, ruleID, unit); err != nil {
				bc.logger.Error("failed to mark budget alert as sent",
					"rule_id", ruleID, "unit", unit, "error", err)
			}
		}
	}
}

// queryDecimalsCached queries ERC20 decimals via the decimalsQuerier with in-memory caching.
func (bc *BudgetChecker) queryDecimalsCached(ctx context.Context, chainID, address string) (int, error) {
	if bc.decimalsQuerier == nil {
		return 0, fmt.Errorf("decimals querier not configured (SetDecimalsQuerier not called)")
	}

	cacheKey := strings.ToLower(chainID + ":" + address)

	bc.decimalsCacheMu.RLock()
	if cached, ok := bc.decimalsCache[cacheKey]; ok {
		bc.decimalsCacheMu.RUnlock()
		return cached, nil
	}
	bc.decimalsCacheMu.RUnlock()

	decimals, err := bc.decimalsQuerier.QueryDecimals(ctx, chainID, address)
	if err != nil {
		return 0, err
	}

	bc.decimalsCacheMu.Lock()
	bc.decimalsCache[cacheKey] = decimals
	bc.decimalsCacheMu.Unlock()

	bc.logger.Info("auto-queried ERC20 decimals",
		"chain_id", chainID, "address", address, "decimals", decimals)

	return decimals, nil
}
