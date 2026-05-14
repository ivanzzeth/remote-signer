// Package config handles remote-signer configuration loading and rule initialization.
// rule_init_sync_rule.go syncs individual rules from config into the database, handling
// both create/update paths, disabled rules, template instances, and deferred budget creation.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/ruleconfig"
	"github.com/ivanzzeth/remote-signer/internal/storage"
	pkgvalidate "github.com/ivanzzeth/remote-signer/internal/validate"
)

// pendingBudgetCreate holds data to create a budget after the rule-sync transaction commits.
type pendingBudgetCreate struct {
	Rule           *types.Rule
	Tmpl           *types.RuleTemplate
	InstanceBudget map[string]interface{}
}

// syncRule syncs a single rule from config into the database. It handles both create and update
// paths, including disabled rules, template-based instance rules, and budget deferral for
// post-transaction budget sync.
func (i *RuleInitializer) syncRule(ctx context.Context, repo storage.RuleRepository, ruleID types.RuleID, ruleCfg RuleConfig, templatesByName map[string]*types.RuleTemplate, pendingBudgets *[]pendingBudgetCreate) error {
	// Check if rule already exists in DB (needed for both enabled and disabled paths)
	existing, err := repo.Get(ctx, ruleID)
	if err != nil && !types.IsNotFound(err) {
		return fmt.Errorf("failed to check existing rule: %w", err)
	}

	// Handle disabled rules: update existing DB rule to disabled, skip creation of new ones
	if !ruleCfg.Enabled {
		if existing != nil {
			existing.Enabled = false
			existing.UpdatedAt = time.Now()
			if err := repo.Update(ctx, existing); err != nil {
				return fmt.Errorf("failed to disable rule: %w", err)
			}
			i.logger.Info("Disabled rule from config",
				"id", ruleID,
				"name", ruleCfg.Name,
			)
		} else {
			i.logger.Debug("Skipping disabled rule (not in DB)", "name", ruleCfg.Name)
		}
		return nil
	}

	// Validate mode (whitelist or blocklist only)
	if err := pkgvalidate.ValidateRuleMode(ruleCfg.Mode); err != nil {
		return fmt.Errorf("rule %q: %w", ruleCfg.Name, err)
	}

	// Extract instance-only fields for TemplateID + budget + schedule (stripped before persist)
	var templateName string
	var instanceBudget map[string]interface{}
	var instanceSchedule map[string]interface{}
	if ruleCfg.Config != nil {
		if n, ok := ruleCfg.Config["__template_name"].(string); ok && n != "" {
			templateName = n
		}
		if b, ok := ruleCfg.Config["__budget"].(map[string]interface{}); ok {
			instanceBudget = b
		}
		if s, ok := ruleCfg.Config["__schedule"].(map[string]interface{}); ok {
			instanceSchedule = s
		}
		// Strip so they are not stored in rule config
		configCopy := make(map[string]interface{}, len(ruleCfg.Config))
		for k, v := range ruleCfg.Config {
			if k != "__template_name" && k != "__budget" && k != "__schedule" {
				configCopy[k] = v
			}
		}
		ruleCfg.Config = configCopy
	}

	// Validate rule config format (same logic as API and validate-rules)
	if ruleCfg.Type != RuleFileType && ruleCfg.Config != nil {
		if err := ruleconfig.ValidateRuleConfig(ruleCfg.Type, ruleCfg.Config); err != nil {
			return fmt.Errorf("rule %q: %w", ruleCfg.Name, err)
		}
	}

	// Marshal config to JSON
	configJSON, err := json.Marshal(ruleCfg.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal rule config: %w", err)
	}

	// Build rule
	rule := &types.Rule{
		ID:          ruleID,
		Name:        ruleCfg.Name,
		Description: ruleCfg.Description,
		Type:        types.RuleType(pkgvalidate.NormalizeRuleType(ruleCfg.Type)),
		Mode:        types.RuleMode(ruleCfg.Mode),
		Source:      types.RuleSourceConfig,
		Config:      configJSON,
		Enabled:     ruleCfg.Enabled,
	}
	// Prepare variables map; chain_id will be injected from rule-level scope below.
	variables := make(map[string]interface{})
	for k, v := range ruleCfg.Variables {
		variables[k] = v
	}

	// Set and validate optional scope fields
	if ruleCfg.ChainType != "" {
		if !pkgvalidate.IsValidChainType(ruleCfg.ChainType) {
			return fmt.Errorf("rule %q: invalid chain_type %q", ruleCfg.Name, ruleCfg.ChainType)
		}
		ct := types.ChainType(ruleCfg.ChainType)
		rule.ChainType = &ct
	} else {
		// Default to EVM
		ct := types.ChainTypeEVM
		rule.ChainType = &ct
	}
	if ruleCfg.ChainID != "" {
		rule.ChainID = &ruleCfg.ChainID
		// Inject chain_id as reserved variable from rule-level scope.
		if old, exists := variables["chain_id"]; exists && fmt.Sprintf("%v", old) != ruleCfg.ChainID {
			i.logger.Warn("overriding config chain_id variable with rule-level scope",
				"rule", ruleCfg.Name, "var_value", old, "scope_value", ruleCfg.ChainID)
		}
		variables["chain_id"] = ruleCfg.ChainID
	}

	// Marshal variables (with chain_id injected from scope)
	if len(variables) > 0 {
		variablesJSON, err := json.Marshal(variables)
		if err != nil {
			return fmt.Errorf("failed to marshal rule variables: %w", err)
		}
		rule.Variables = variablesJSON
	}

	// Config-sourced rules: owner="config", applied_to=["*"], status="active"
	rule.Owner = "config"
	rule.AppliedTo = []string{"*"}
	rule.Status = types.RuleStatusActive

	if ruleCfg.SignerAddress != "" {
		if !pkgvalidate.IsValidEthereumAddress(ruleCfg.SignerAddress) {
			return fmt.Errorf("rule %q: invalid signer_address %q: must be 0x followed by 40 hex characters", ruleCfg.Name, ruleCfg.SignerAddress)
		}
		rule.SignerAddress = &ruleCfg.SignerAddress
	}

	// Instance-rule: set TemplateID and schedule so budget enforcement and period reset apply
	var tmpl *types.RuleTemplate
	if templateName != "" {
		if templatesByName != nil {
			tmpl = templatesByName[templateName]
		} else if i.templateRepo != nil {
			t, err := i.templateRepo.GetByName(ctx, templateName)
			if err == nil && t != nil {
				tmpl = t
			}
		}
		if tmpl != nil {
			rule.TemplateID = &tmpl.ID
		}
	}
	if len(instanceSchedule) > 0 {
		if p, ok := instanceSchedule["period"].(string); ok && p != "" {
			if d, err := time.ParseDuration(p); err == nil && d > 0 {
				rule.BudgetPeriod = &d
				rule.BudgetPeriodStart = &time.Time{}
				*rule.BudgetPeriodStart = time.Now()
				if s, ok := instanceSchedule["start_at"].(string); ok && s != "" {
					if t, err := time.Parse(time.RFC3339, s); err == nil {
						rule.BudgetPeriodStart = &t
					}
				}
			}
		}
	}

	if existing == nil {
		// Create new rule
		rule.CreatedAt = time.Now()
		rule.UpdatedAt = time.Now()

		if err := repo.Create(ctx, rule); err != nil {
			return fmt.Errorf("failed to create rule: %w", err)
		}

		// Defer budget creation until after the transaction to avoid using a second DB connection inside tx.
		// Copy rule (heap) so Variables are not overwritten when the next syncRule reuses the same rule struct.
		i.logger.Info("syncRule budget check",
			"rule_id", ruleID,
			"budgetRepo_nil", i.budgetRepo == nil,
			"instanceBudget_len", len(instanceBudget),
			"tmpl_nil", tmpl == nil,
			"tmpl_budgetMetering_len", func() int {
				if tmpl != nil {
					return len(tmpl.BudgetMetering)
				}
				return -1
			}(),
			"pendingBudgets_nil", pendingBudgets == nil,
		)
		if i.budgetRepo != nil && len(instanceBudget) > 0 && tmpl != nil && len(tmpl.BudgetMetering) > 0 && pendingBudgets != nil {
			ruleCopy := new(types.Rule)
			*ruleCopy = *rule
			ruleCopy.Variables = make([]byte, len(rule.Variables))
			copy(ruleCopy.Variables, rule.Variables)
			*pendingBudgets = append(*pendingBudgets, pendingBudgetCreate{
				Rule:           ruleCopy,
				Tmpl:           tmpl,
				InstanceBudget: instanceBudget,
			})
		}

		i.logger.Info("Created rule from config",
			"id", ruleID,
			"name", ruleCfg.Name,
			"type", ruleCfg.Type,
			"mode", ruleCfg.Mode,
		)
		if i.auditLogger != nil {
			i.auditLogger.LogRuleCreated(ctx, "config", "config-sync", ruleID, ruleCfg.Name)
		}
	} else {
		// Update existing rule with config values
		existing.Name = rule.Name
		existing.Description = rule.Description
		existing.Type = rule.Type
		existing.Mode = rule.Mode
		existing.Config = rule.Config
		existing.ChainType = rule.ChainType
		existing.ChainID = rule.ChainID
		existing.Owner = rule.Owner
		existing.AppliedTo = rule.AppliedTo
		existing.Status = rule.Status
		existing.SignerAddress = rule.SignerAddress
		existing.Enabled = rule.Enabled
		existing.Variables = rule.Variables
		if rule.TemplateID != nil {
			existing.TemplateID = rule.TemplateID
		}
		if rule.BudgetPeriod != nil {
			existing.BudgetPeriod = rule.BudgetPeriod
		}
		if rule.BudgetPeriodStart != nil {
			existing.BudgetPeriodStart = rule.BudgetPeriodStart
		}
		existing.UpdatedAt = time.Now()

		if err := repo.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update rule: %w", err)
		}

		// When variables (e.g. chain_id) change, the budget unit changes; ensure a budget record exists for the current unit.
		if i.budgetRepo != nil && len(instanceBudget) > 0 && tmpl != nil && len(tmpl.BudgetMetering) > 0 && pendingBudgets != nil {
			ruleCopy := new(types.Rule)
			*ruleCopy = *existing
			ruleCopy.Variables = make([]byte, len(existing.Variables))
			copy(ruleCopy.Variables, existing.Variables)
			*pendingBudgets = append(*pendingBudgets, pendingBudgetCreate{
				Rule:           ruleCopy,
				Tmpl:           tmpl,
				InstanceBudget: instanceBudget,
			})
		}

		i.logger.Info("Updated rule from config",
			"id", ruleID,
			"name", ruleCfg.Name,
			"type", ruleCfg.Type,
			"mode", ruleCfg.Mode,
		)
		if i.auditLogger != nil {
			i.auditLogger.LogRuleUpdated(ctx, "config", "config-sync", ruleID, ruleCfg.Name, nil, nil)
		}
	}

	return nil
}
