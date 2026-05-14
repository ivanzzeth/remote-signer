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

// SyncFromConfig syncs rules from config to database
// - Creates new rules that don't exist (identified by explicit id from config)
// - Updates existing rules with new values from config
// - Deletes config-sourced rules that are no longer in config (preserves API-created rules)
// - Expands "file" type rules by loading rules from external YAML files
// - Wraps all operations in a transaction if the repository supports it
func (i *RuleInitializer) SyncFromConfig(ctx context.Context, rules []RuleConfig) error {
	// Expand file-type rules
	expandedRules, err := i.expandFileRules(rules)
	if err != nil {
		return fmt.Errorf("failed to expand file rules: %w", err)
	}

	// Require explicit id for all rules (stable IDs across preset/config changes)
	if err := ValidateExplicitRuleIDs(expandedRules); err != nil {
		return fmt.Errorf("rule config validation: %w", err)
	}

	// Build set of expected rule IDs (explicit id); enforce uniqueness
	expectedIDs := make(map[types.RuleID]bool)
	for idx, ruleCfg := range expandedRules {
		ruleID := i.effectiveRuleID(idx, ruleCfg)
		if expectedIDs[ruleID] {
			return fmt.Errorf("duplicate rule id %q (rule %q); custom id must be unique", ruleID, ruleCfg.Name)
		}
		expectedIDs[ruleID] = true
	}

	// Pre-load templates needed by instance rules so we do not call templateRepo inside the
	// transaction (avoids deadlock when DB has a single connection).
	templatesByName := i.preloadTemplatesForSync(ctx, expandedRules)

	var pendingBudgets []pendingBudgetCreate
	syncBody := func(repo storage.RuleRepository) error {
		return i.executeSyncBody(ctx, repo, i.budgetRepo, expandedRules, expectedIDs, templatesByName, &pendingBudgets)
	}

	if txRepo, ok := i.repo.(storage.Transactional); ok {
		if err = txRepo.RunInTransaction(ctx, syncBody); err != nil {
			return err
		}
	} else {
		if err = syncBody(i.repo); err != nil {
			return err
		}
	}

	// Sync budgets from config after the transaction: diff so DB matches config (delete stale units, ensure current unit exists).
	for _, p := range pendingBudgets {
		if syncErr := syncBudgetFromConfig(ctx, p.Rule, p.Tmpl, p.InstanceBudget, i.budgetRepo); syncErr != nil {
			return fmt.Errorf("sync budget for rule %s: %w", p.Rule.ID, syncErr)
		}
	}
	return nil
}

// preloadTemplatesForSync returns a map of template name -> template for all instance rules
// that reference a template. Loaded outside any transaction to avoid deadlock with single-conn DB.
func (i *RuleInitializer) preloadTemplatesForSync(ctx context.Context, expandedRules []RuleConfig) map[string]*types.RuleTemplate {
	if i.templateRepo == nil {
		return nil
	}
	names := make(map[string]struct{})
	for _, ruleCfg := range expandedRules {
		if ruleCfg.Config == nil {
			continue
		}
		if n, ok := ruleCfg.Config["__template_name"].(string); ok && n != "" {
			names[n] = struct{}{}
		}
	}
	if len(names) == 0 {
		return nil
	}
	out := make(map[string]*types.RuleTemplate, len(names))
	for name := range names {
		t, err := i.templateRepo.GetByName(ctx, name)
		if err == nil && t != nil {
			out[name] = t
		}
	}
	return out
}

// executeSyncBody performs the actual sync: delete stale rules, upsert current rules, verify consistency.
// repo is the (possibly transactional) repository to use for all operations.
// budgetRepo is optional; when set, budgets for deleted rules are removed so DB stays in sync with config.
// templatesByName is optional; when set, instance-rule template lookup uses it instead of templateRepo (avoids DB calls inside tx).
// pendingBudgets is filled with rules that need budget sync; caller runs syncBudgetFromConfig after the transaction.
func (i *RuleInitializer) executeSyncBody(ctx context.Context, repo storage.RuleRepository, budgetRepo storage.BudgetRepository, expandedRules []RuleConfig, expectedIDs map[types.RuleID]bool, templatesByName map[string]*types.RuleTemplate, pendingBudgets *[]pendingBudgetCreate) error {
	// Get all existing config-sourced rules from database
	configSource := types.RuleSourceConfig
	existingRules, err := repo.List(ctx, storage.RuleFilter{
		Source: &configSource,
		Limit:  -1, // No limit — fetch all config rules
	})
	if err != nil {
		return fmt.Errorf("failed to list config rules: %w", err)
	}

	// Delete config rules that are no longer in config (and their budgets so DB matches config)
	deleted := 0
	for _, rule := range existingRules {
		if !expectedIDs[rule.ID] {
			if budgetRepo != nil {
				if delErr := budgetRepo.DeleteByRuleID(ctx, rule.ID); delErr != nil {
					return fmt.Errorf("failed to delete budgets for stale config rule %s: %w", rule.ID, delErr)
				}
			}
			if err := repo.Delete(ctx, rule.ID); err != nil {
				return fmt.Errorf("failed to delete stale config rule %s: %w", rule.ID, err)
			}
			i.logger.Info("Deleted stale config rule",
				"id", rule.ID,
				"name", rule.Name,
			)
			if i.auditLogger != nil {
				i.auditLogger.LogRuleDeleted(ctx, "config", "config-sync", rule.ID)
			}
			deleted++
		}
	}

	if len(expandedRules) == 0 {
		i.logger.Info("No rules configured in config file", "deleted", deleted)
		return nil
	}

	// Sync rules from config
	synced := 0
	for idx, ruleCfg := range expandedRules {
		ruleID := i.effectiveRuleID(idx, ruleCfg)
		if err := i.syncRule(ctx, repo, ruleID, ruleCfg, templatesByName, pendingBudgets); err != nil {
			return fmt.Errorf("failed to sync rule %s: %w", ruleCfg.Name, err)
		}
		synced++
	}

	// Verify post-sync consistency
	if err := i.verifySyncConsistency(ctx, repo, expectedIDs); err != nil {
		return fmt.Errorf("post-sync verification failed: %w", err)
	}

	i.logger.Info("Rules synced from config", "synced", synced, "deleted", deleted)
	return nil
}

// verifySyncConsistency checks that DB state matches expected rule IDs after sync.
// Returns error if extra config-sourced rules are found (stale leak detection).
func (i *RuleInitializer) verifySyncConsistency(ctx context.Context, repo storage.RuleRepository, expectedIDs map[types.RuleID]bool) error {
	configSource := types.RuleSourceConfig
	dbRules, err := repo.List(ctx, storage.RuleFilter{
		Source: &configSource,
		Limit:  -1,
	})
	if err != nil {
		return fmt.Errorf("failed to list rules for verification: %w", err)
	}

	var extraIDs []string
	for _, rule := range dbRules {
		if !expectedIDs[rule.ID] {
			extraIDs = append(extraIDs, string(rule.ID))
		}
	}
	if len(extraIDs) > 0 {
		return fmt.Errorf("stale config rules detected in DB after sync: %v", extraIDs)
	}

	// Audit summary
	syncedIDs := make([]string, 0, len(expectedIDs))
	for id := range expectedIDs {
		syncedIDs = append(syncedIDs, string(id))
	}
	i.logger.Info("Post-sync verification passed",
		"db_rule_count", len(dbRules),
		"expected_count", len(expectedIDs),
		"synced_ids", syncedIDs,
	)
	return nil
}

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
