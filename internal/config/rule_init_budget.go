// Package config handles remote-signer configuration loading and rule initialization.
// This file syncs budget configurations from rule config and templates into storage.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	rulepkg "github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ruleVariablesToStringMap unmarshals rule.Variables (JSON may have number or string values from YAML)
// into a map with string values so substitution never drops keys (e.g. chain_id: 1 -> "1").
func ruleVariablesToStringMap(variablesJSON []byte) map[string]string {
	if len(variablesJSON) == 0 {
		return nil
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(variablesJSON, &raw); err != nil || len(raw) == 0 {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if v == nil {
			continue
		}
		s := strings.TrimSpace(fmt.Sprintf("%v", v))
		// Skip empty so we never substitute with "" (which would produce ":" for unit "${chain_id}:${token_address}")
		if s != "" {
			out[k] = s
		}
	}
	return out
}

// substituteBudgetMapVars replaces ${var} in all string values of m using vars (e.g. rule.Variables).
// So every budget field (unit, max_total, max_per_tx, max_tx_count, alert_pct) supports template variables at sync time.
func substituteBudgetMapVars(m map[string]interface{}, vars map[string]string) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = substituteBudgetValue(v, vars)
	}
	return out
}

func substituteBudgetValue(v interface{}, vars map[string]string) interface{} {
	if len(vars) == 0 {
		return v
	}
	switch val := v.(type) {
	case string:
		s := val
		for k, vv := range vars {
			s = strings.ReplaceAll(s, "${"+k+"}", vv)
		}
		return s
	case map[string]interface{}:
		return substituteBudgetMapVars(val, vars)
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(val))
		for kk, vv := range val {
			if sk, ok := kk.(string); ok {
				out[sk] = substituteBudgetValue(vv, vars)
			}
		}
		return out
	default:
		return v
	}
}

// syncBudgetFromConfig makes the DB budget state match config: remove budgets for units no longer in config,
// then ensure the current unit has a budget record. Keeps config-sourced rules' budgets in sync and avoids stale units.
// For dynamic budget templates (budget_metering.dynamic=true), known_units from the preset config are pre-created
// and no static budget.unit field is required (units are determined at JS evaluation time).
func syncBudgetFromConfig(ctx context.Context, rule *types.Rule, tmpl *types.RuleTemplate, budgetMap map[string]interface{}, budgetRepo storage.BudgetRepository) error {
	// Check if this is a dynamic budget template — if so, pre-create known_units budgets instead of requiring a static unit.
	if tmpl != nil && len(tmpl.BudgetMetering) > 0 {
		var metering types.BudgetMetering
		// Substitute template variables in BudgetMetering JSON so that ${var} placeholders
		// (e.g. "${max_unknown_token_tx_count}") are resolved before JSON unmarshal.
		// This is needed because int fields like max_tx_count would fail to parse as "${var}" strings.
		resolvedJSON := rulepkg.SubstituteMeteringJSON(tmpl.BudgetMetering, rule.Variables)
		if err := json.Unmarshal(resolvedJSON, &metering); err == nil && metering.Dynamic {
			return syncDynamicBudgetFromConfig(ctx, rule, tmpl, budgetMap, budgetRepo, &metering)
		}
	}

	currentUnit, err := resolveBudgetUnit(rule, tmpl, budgetMap)
	if err != nil {
		return err
	}
	existingList, err := budgetRepo.ListByRuleID(ctx, rule.ID)
	if err != nil {
		return fmt.Errorf("list budgets for rule: %w", err)
	}
	for _, b := range existingList {
		if b.Unit != currentUnit {
			if delErr := budgetRepo.Delete(ctx, b.ID); delErr != nil {
				return fmt.Errorf("delete stale budget %s (unit=%s): %w", b.ID, b.Unit, delErr)
			}
		}
	}
	return createBudgetFromInstanceConfig(ctx, rule, tmpl, budgetMap, budgetRepo)
}

// syncDynamicBudgetFromConfig handles budget sync for dynamic budget templates.
// Pre-creates budget records for each known_unit defined in the preset config.
// Unknown units will be auto-created at runtime by the budget checker.
func syncDynamicBudgetFromConfig(ctx context.Context, rule *types.Rule, tmpl *types.RuleTemplate, budgetMap map[string]interface{}, budgetRepo storage.BudgetRepository, metering *types.BudgetMetering) error {
	vars := ruleVariablesToStringMap(rule.Variables)
	substituted := substituteBudgetMapVars(budgetMap, vars)
	if substituted == nil {
		substituted = budgetMap
	}

	// Resolve alert_pct
	alertPct := 80
	if v, ok := substituted["alert_pct"]; ok && v != nil {
		if s := strings.TrimSpace(fmt.Sprintf("%v", v)); s != "" {
			var n int
			if _, err := fmt.Sscanf(s, "%d", &n); err == nil && n > 0 {
				alertPct = n
			}
		}
	}

	// Collect known_units from the instance budget config (preset-generated)
	knownUnitsRaw := substituted["known_units"]
	knownUnits := make(map[string]map[string]interface{})
	switch ku := knownUnitsRaw.(type) {
	case map[string]interface{}:
		for unitName, conf := range ku {
			if confMap, ok := conf.(map[string]interface{}); ok {
				knownUnits[unitName] = confMap
			}
		}
	case map[interface{}]interface{}:
		for k, v := range ku {
			if sk, ok := k.(string); ok {
				if confMap, ok := v.(map[string]interface{}); ok {
					knownUnits[sk] = confMap
				} else if confMap2, ok := v.(map[interface{}]interface{}); ok {
					converted := make(map[string]interface{})
					for ck, cv := range confMap2 {
						if cks, ok := ck.(string); ok {
							converted[cks] = cv
						}
					}
					knownUnits[sk] = converted
				}
			}
		}
	}

	// Build set of expected units and known base names for stale-row cleanup.
	chainID := rulepkg.ResolveRuleChainID(rule)
	expectedUnits := make(map[string]bool)
	knownBaseNames := make(map[string]bool)
	for unitName := range knownUnits {
		base := rulepkg.NormalizeBudgetUnit(unitName)
		knownBaseNames[base] = true
		scoped := rulepkg.ScopeDynamicUnit(chainID, unitName)
		expectedUnits[scoped] = true
	}

	// Remove stale budgets: unprefixed template rows when chain-scoped, or units dropped from config.
	existingList, err := budgetRepo.ListByRuleID(ctx, rule.ID)
	if err != nil {
		return fmt.Errorf("list budgets for rule: %w", err)
	}
	for _, b := range existingList {
		if !expectedUnits[b.Unit] && rulepkg.IsKnownUnitFamily(b.Unit, knownBaseNames) {
			if delErr := budgetRepo.Delete(ctx, b.ID); delErr != nil {
				return fmt.Errorf("delete stale budget %s (unit=%s): %w", b.ID, b.Unit, delErr)
			}
		}
	}

	// Create budget records for each known_unit (idempotent via CreateOrGet)
	for unitName, unitConf := range knownUnits {
		unit := rulepkg.ScopeDynamicUnit(chainID, unitName)
		maxTotal := stringFromMapField(unitConf, "max_total")
		maxPerTx := stringFromMapField(unitConf, "max_per_tx")
		maxTxCount := 0
		if s := stringFromMapField(unitConf, "max_tx_count"); s != "" {
			if _, err := fmt.Sscanf(s, "%d", &maxTxCount); err != nil {
				return fmt.Errorf("invalid max_tx_count %q for budget unit %q: %w", s, unit, err)
			}
		}

		budget := &types.RuleBudget{
			ID:         types.BudgetID(rule.ID, unit),
			RuleID:     rule.ID,
			Unit:       unit,
			MaxTotal:   maxTotal,
			MaxPerTx:   maxPerTx,
			MaxTxCount: maxTxCount,
			AlertPct:   alertPct,
			Spent:      "0",
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}

		if _, _, err := budgetRepo.CreateOrGet(ctx, budget); err != nil {
			return fmt.Errorf("create budget for unit %s: %w", unit, err)
		}
	}

	return nil
}

// stringFromMapField extracts a trimmed string from a map field.
func stringFromMapField(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", v))
}

// resolveBudgetUnit returns the normalized budget unit for a config-sourced rule (same logic as createBudgetFromInstanceConfig).
func resolveBudgetUnit(rule *types.Rule, tmpl *types.RuleTemplate, budgetMap map[string]interface{}) (string, error) {
	vars := ruleVariablesToStringMap(rule.Variables)
	unitRaw, _ := budgetMap["unit"].(string)
	if unitRaw == "" {
		if u, ok := budgetMap["Unit"].(string); ok {
			unitRaw = u
		}
	}
	for k, v := range vars {
		unitRaw = strings.ReplaceAll(unitRaw, "${"+k+"}", v)
	}
	unit := strings.TrimSpace(unitRaw)
	substituted := substituteBudgetMapVars(budgetMap, vars)
	if substituted == nil {
		substituted = budgetMap
	}
	if unit == "" {
		if v, ok := substituted["unit"]; ok && v != nil {
			unit = strings.TrimSpace(fmt.Sprintf("%v", v))
		}
	}
	if unit == "" {
		return "", fmt.Errorf("budget.unit is required when budget is set (e.g. \"${chain_id}:${token_address}\") to identify what is being consumed")
	}
	if strings.Contains(unit, "${") {
		return "", fmt.Errorf("budget.unit is required and must resolve to a non-empty value after variable substitution (rule %s had unit %q, variables=%s)", rule.ID, unit, string(rule.Variables))
	}
	if unit == ":" || len(unit) < 3 {
		if len(tmpl.BudgetMetering) > 0 && len(vars) > 0 {
			var metering types.BudgetMetering
			resolvedBM := rulepkg.SubstituteMeteringJSON(tmpl.BudgetMetering, rule.Variables)
			if err := json.Unmarshal(resolvedBM, &metering); err == nil && metering.Unit != "" {
				unitFallback := metering.Unit
				for k, v := range vars {
					unitFallback = strings.ReplaceAll(unitFallback, "${"+k+"}", v)
				}
				unitFallback = strings.TrimSpace(unitFallback)
				if unitFallback != "" && !strings.Contains(unitFallback, "${") {
					unit = unitFallback
				}
			}
		}
	}
	if unit == ":" || len(unit) < 3 {
		return "", fmt.Errorf("budget.unit resolved to invalid value %q for rule %s (variables=%s)", unit, rule.ID, string(rule.Variables))
	}
	return rulepkg.NormalizeBudgetUnit(unit), nil
}

// createBudgetFromInstanceConfig creates a budget record for a config-synced instance rule
// so that budget enforcement (max_total, max_per_tx) and period reset apply.
// All budget fields support template variables (${var}); unit is required and must resolve to non-empty.
// Optional fields (max_total, max_per_tx, max_tx_count, alert_pct): empty after substitution is accepted (defaults: 0 or 80).
func createBudgetFromInstanceConfig(ctx context.Context, rule *types.Rule, tmpl *types.RuleTemplate, budgetMap map[string]interface{}, budgetRepo storage.BudgetRepository) error {
	vars := ruleVariablesToStringMap(rule.Variables)
	unitRaw, _ := budgetMap["unit"].(string)
	if unitRaw == "" {
		if u, ok := budgetMap["Unit"].(string); ok {
			unitRaw = u
		}
	}
	for k, v := range vars {
		unitRaw = strings.ReplaceAll(unitRaw, "${"+k+"}", v)
	}
	unit := strings.TrimSpace(unitRaw)
	substituted := substituteBudgetMapVars(budgetMap, vars)
	if substituted == nil {
		substituted = budgetMap
	}
	if unit == "" {
		if v, ok := substituted["unit"]; ok && v != nil {
			unit = strings.TrimSpace(fmt.Sprintf("%v", v))
		}
	}
	if unit == "" {
		return fmt.Errorf("budget.unit is required when budget is set (e.g. \"${chain_id}:${token_address}\") to identify what is being consumed")
	}
	if strings.Contains(unit, "${") {
		return fmt.Errorf("budget.unit is required and must resolve to a non-empty value after variable substitution (rule %s had unit %q, variables=%s)", rule.ID, unit, string(rule.Variables))
	}
	if unit == ":" || len(unit) < 3 {
		if len(tmpl.BudgetMetering) > 0 && len(vars) > 0 {
			var metering types.BudgetMetering
			resolvedBM := rulepkg.SubstituteMeteringJSON(tmpl.BudgetMetering, rule.Variables)
			if err := json.Unmarshal(resolvedBM, &metering); err == nil && metering.Unit != "" {
				unitFallback := metering.Unit
				for k, v := range vars {
					unitFallback = strings.ReplaceAll(unitFallback, "${"+k+"}", v)
				}
				unitFallback = strings.TrimSpace(unitFallback)
				if unitFallback != "" && !strings.Contains(unitFallback, "${") {
					unit = unitFallback
				}
			}
		}
	}
	if unit == ":" || len(unit) < 3 {
		return fmt.Errorf("budget.unit resolved to invalid value %q for rule %s (variables=%s)", unit, rule.ID, string(rule.Variables))
	}
	unit = rulepkg.NormalizeBudgetUnit(unit)
	// Optional: alert_pct; empty or 0 → default 80
	alertPct := 80
	if v, ok := substituted["alert_pct"]; ok && v != nil {
		s := strings.TrimSpace(fmt.Sprintf("%v", v))
		if s != "" {
			var n int
			if _, err := fmt.Sscanf(s, "%d", &n); err == nil && n > 0 {
				alertPct = n
			}
		}
	}
	if alertPct <= 0 {
		alertPct = 80
	}
	// Optional: max_total; empty → "-1" (no cap). Only -1 means no cap; 0 means cap of 0 (so you can temporarily disable by setting -1).
	maxTotal := "-1"
	if v, ok := substituted["max_total"]; ok && v != nil {
		s := strings.TrimSpace(fmt.Sprintf("%v", v))
		if s != "" {
			maxTotal = s
		}
	}
	// Optional: max_per_tx; empty → "-1" (no per-tx cap). Only -1 means no cap; 0 = cap of 0.
	maxPerTx := "-1"
	if v, ok := substituted["max_per_tx"]; ok && v != nil {
		s := strings.TrimSpace(fmt.Sprintf("%v", v))
		if s != "" {
			maxPerTx = s
		}
	}
	// Optional: max_tx_count; empty → 0
	maxTxCount := 0
	if v, ok := substituted["max_tx_count"]; ok && v != nil {
		s := strings.TrimSpace(fmt.Sprintf("%v", v))
		if s != "" {
			var n int
			if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
				maxTxCount = n
			}
		} else {
			switch n := v.(type) {
			case int:
				maxTxCount = n
			case float64:
				maxTxCount = int(n)
			}
		}
	}
	// Idempotent: if a budget for this rule+unit already exists (e.g. from a previous sync or after variable change), skip create.
	existing, err := budgetRepo.GetByRuleID(ctx, rule.ID, unit)
	if err == nil && existing != nil {
		return nil // budget already exists for current unit
	}
	if err != nil && !types.IsNotFound(err) {
		return fmt.Errorf("failed to check existing budget: %w", err)
	}

	budget := &types.RuleBudget{
		ID:         types.BudgetID(rule.ID, unit),
		RuleID:     rule.ID,
		Unit:       unit,
		MaxTotal:   maxTotal,
		MaxPerTx:   maxPerTx,
		Spent:      "0",
		AlertPct:   alertPct,
		TxCount:    0,
		MaxTxCount: maxTxCount,
	}
	return budgetRepo.Create(ctx, budget)
}
