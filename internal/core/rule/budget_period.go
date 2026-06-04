package rule

import (
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// CurrentPeriodStart returns the start timestamp of the active budget period for
// rule, or (zero, false) when periodic renewal is not configured.
func CurrentPeriodStart(rule *types.Rule, now time.Time) (time.Time, bool) {
	if rule == nil || rule.BudgetPeriod == nil || rule.BudgetPeriodStart == nil {
		return time.Time{}, false
	}
	period := *rule.BudgetPeriod
	start := *rule.BudgetPeriodStart
	if period <= 0 {
		return time.Time{}, false
	}
	if start.IsZero() {
		start = rule.CreatedAt
	}
	if start.IsZero() || now.Before(start) {
		return time.Time{}, false
	}
	elapsed := now.Sub(start)
	periodIndex := int64(elapsed / period)
	return start.Add(time.Duration(periodIndex) * period), true
}

// NeedsPeriodReset reports whether a budget row belongs to a prior period and
// should be reset before evaluating spend limits.
func NeedsPeriodReset(rule *types.Rule, budget *types.RuleBudget, now time.Time) (bool, time.Time) {
	if rule == nil || budget == nil {
		return false, time.Time{}
	}
	currentPeriodStart, ok := CurrentPeriodStart(rule, now)
	if !ok {
		return false, time.Time{}
	}
	updatedAt := budget.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = budget.CreatedAt
	}
	return updatedAt.Before(currentPeriodStart), currentPeriodStart
}
