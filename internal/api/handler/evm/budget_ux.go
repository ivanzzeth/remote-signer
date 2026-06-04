package evm

import (
	"time"

	"strings"

	rulepkg "github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// budgetUXMeta holds operator-facing annotations for budget rows.
type budgetUXMeta struct {
	UnitDisplay        string `json:"unit_display,omitempty"`
	BudgetPeriod       string `json:"budget_period,omitempty"`
	PeriodStart        string `json:"period_start,omitempty"`
	PeriodEndsAt       string `json:"period_ends_at,omitempty"`
	EnforcesLimit      bool   `json:"enforces_limit"`
	IsStalePlaceholder bool   `json:"is_stale_placeholder,omitempty"`
}

func buildBudgetUXMeta(rule *types.Rule, b *types.RuleBudget, siblingUnits []string) budgetUXMeta {
	meta := budgetUXMeta{
		UnitDisplay:   rulepkg.FormatUnitDisplay(b.Unit),
		EnforcesLimit: rulepkg.EnforcesBudgetLimit(b.MaxTotal),
	}
	if rule != nil {
		period := rulepkg.BuildBudgetPeriodInfo(rule, b, time.Now())
		meta.BudgetPeriod = period.BudgetPeriod
		meta.PeriodStart = period.PeriodStart
		meta.PeriodEndsAt = period.PeriodEndsAt
		chainID := rulepkg.ResolveRuleChainID(rule)
		meta.IsStalePlaceholder = isStaleByScopedSibling(chainID, b.Unit, siblingUnits) ||
			isLikelyStaleTemplateUnit(chainID, b.Unit)
	}
	return meta
}

func isLikelyStaleTemplateUnit(chainID, unit string) bool {
	if chainID == "" || strings.Contains(unit, ":") {
		return false
	}
	switch rulepkg.NormalizeBudgetUnit(unit) {
	case "sign_count", "tx_count", "native", "count":
		return true
	default:
		return false
	}
}

func isStaleByScopedSibling(chainID, unit string, siblings []string) bool {
	if chainID == "" || strings.Contains(unit, ":") {
		return false
	}
	scoped := rulepkg.ScopeDynamicUnit(chainID, unit)
	for _, s := range siblings {
		if s == scoped {
			return true
		}
	}
	return false
}

func applyBudgetUX(entry *BudgetEntry, rule *types.Rule, b *types.RuleBudget, siblingUnits []string) {
	meta := buildBudgetUXMeta(rule, b, siblingUnits)
	entry.UnitDisplay = meta.UnitDisplay
	entry.BudgetPeriod = meta.BudgetPeriod
	entry.PeriodStart = meta.PeriodStart
	entry.PeriodEndsAt = meta.PeriodEndsAt
	entry.EnforcesLimit = meta.EnforcesLimit
	entry.IsStalePlaceholder = meta.IsStalePlaceholder
}

// RuleBudgetListItem is returned by GET /rules/{id}/budgets with UX annotations.
type RuleBudgetListItem struct {
	ID         string `json:"id"`
	RuleID     string `json:"rule_id"`
	Unit       string `json:"unit"`
	MaxTotal   string `json:"max_total"`
	MaxPerTx   string `json:"max_per_tx"`
	Spent      string `json:"spent"`
	AlertPct   int    `json:"alert_pct"`
	AlertSent  bool   `json:"alert_sent"`
	TxCount    int    `json:"tx_count"`
	MaxTxCount int    `json:"max_tx_count"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
	budgetUXMeta
}

func ruleBudgetListItem(rule *types.Rule, b *types.RuleBudget, siblingUnits []string) RuleBudgetListItem {
	item := RuleBudgetListItem{
		ID:         b.ID,
		RuleID:     string(b.RuleID),
		Unit:       b.Unit,
		MaxTotal:   b.MaxTotal,
		MaxPerTx:   b.MaxPerTx,
		Spent:      b.Spent,
		AlertPct:   b.AlertPct,
		AlertSent:  b.AlertSent,
		TxCount:    b.TxCount,
		MaxTxCount: b.MaxTxCount,
		CreatedAt:  b.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  b.UpdatedAt.Format(time.RFC3339),
	}
	item.budgetUXMeta = buildBudgetUXMeta(rule, b, siblingUnits)
	return item
}
