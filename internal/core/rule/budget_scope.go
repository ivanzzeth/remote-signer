package rule

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ResolveRuleChainID returns the chain scope for a rule instance.
func ResolveRuleChainID(rule *types.Rule) string {
	if rule == nil {
		return ""
	}
	if rule.ChainID != nil {
		if cid := strings.TrimSpace(*rule.ChainID); cid != "" {
			return cid
		}
	}
	for _, key := range []string{"chain_id", "ChainID"} {
		if v := variableString(rule.Variables, key); v != "" {
			return v
		}
	}
	return ""
}

func variableString(variablesJSON []byte, key string) string {
	vars := variablesToStringMap(variablesJSON)
	if vars == nil {
		return ""
	}
	return strings.TrimSpace(vars[key])
}

// ScopeDynamicUnit prefixes a JS budget unit with chain_id when scoped.
func ScopeDynamicUnit(chainID, rawUnit string) string {
	unit := NormalizeBudgetUnit(rawUnit)
	if chainID = strings.TrimSpace(chainID); chainID != "" {
		return NormalizeBudgetUnit(chainID + ":" + rawUnit)
	}
	return unit
}

// IsRuntimeDynamicBudgetUnit reports auto-created token/permit rows that must
// survive config sync (not listed in template known_units).
func IsRuntimeDynamicBudgetUnit(unit string) bool {
	unit = strings.ToLower(strings.TrimSpace(unit))
	return strings.Contains(unit, "0x")
}

// IsKnownUnitFamily reports whether a budget row belongs to template known_units
// (prefixed or legacy unprefixed), as opposed to ad-hoc runtime units like token:permit.
func IsKnownUnitFamily(unit string, knownBaseNames map[string]bool) bool {
	if len(knownBaseNames) == 0 {
		return false
	}
	norm := NormalizeBudgetUnit(unit)
	if knownBaseNames[norm] {
		return true
	}
	if idx := strings.Index(norm, ":"); idx > 0 {
		if _, err := strconv.ParseUint(norm[:idx], 10, 64); err == nil {
			return knownBaseNames[norm[idx+1:]]
		}
	}
	return false
}

// IsStaleUnprefixedKnownUnit reports template rows that are never debited at sign time.
func IsStaleUnprefixedKnownUnit(chainID, unit string, knownBaseNames map[string]bool) bool {
	if chainID == "" {
		return false
	}
	norm := NormalizeBudgetUnit(unit)
	return knownBaseNames[norm] && !strings.Contains(norm, ":")
}
func FormatUnitDisplay(unit string) string {
	unit = strings.TrimSpace(unit)
	if unit == "" {
		return unit
	}
	if idx := strings.Index(unit, ":"); idx > 0 {
		prefix := unit[:idx]
		suffix := unit[idx+1:]
		if _, err := strconv.ParseUint(prefix, 10, 64); err == nil {
			return fmt.Sprintf("chain %s · %s", prefix, humanizeUnitSuffix(suffix))
		}
	}
	return humanizeUnitSuffix(unit)
}

func humanizeUnitSuffix(s string) string {
	switch NormalizeBudgetUnit(s) {
	case "sign_count":
		return "signatures"
	case "tx_count":
		return "transactions"
	case "native":
		return "native token"
	case "count":
		return "count"
	default:
		if strings.HasSuffix(s, ":permit") {
			addr := strings.TrimSuffix(s, ":permit")
			return fmt.Sprintf("permit (%s…)", shortenHex(addr))
		}
		return s
	}
}

func shortenHex(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 12 {
		return s
	}
	return s[:6] + "…" + s[len(s)-4:]
}

// EnforcesBudgetLimit is true when max_total is a positive cap.
func EnforcesBudgetLimit(maxTotal string) bool {
	maxTotal = strings.TrimSpace(maxTotal)
	if maxTotal == "" || maxTotal == "-1" {
		return false
	}
	for _, c := range maxTotal {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// BudgetPeriodInfo carries renewal metadata for UI surfaces.
type BudgetPeriodInfo struct {
	BudgetPeriod string
	PeriodStart  string
	PeriodEndsAt string
}

// BuildBudgetPeriodInfo derives the active period window from rule + budget row.
func BuildBudgetPeriodInfo(rule *types.Rule, budget *types.RuleBudget, now time.Time) BudgetPeriodInfo {
	info := BudgetPeriodInfo{}
	if rule == nil || rule.BudgetPeriod == nil || *rule.BudgetPeriod <= 0 {
		return info
	}
	info.BudgetPeriod = rule.BudgetPeriod.String()
	start, ok := CurrentPeriodStart(rule, now)
	if !ok {
		return info
	}
	info.PeriodStart = start.UTC().Format(time.RFC3339)
	info.PeriodEndsAt = start.Add(*rule.BudgetPeriod).UTC().Format(time.RFC3339)
	_ = budget
	return info
}
