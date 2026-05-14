// Package config handles remote-signer configuration loading and rule initialization.
// rule_init_sync.go orchestrates rule sync from config — expanding instance template rules,
// syncing source rules, pruning orphaned rules, and syncing budgets in post-transaction.
package config

import (
	"context"
	"fmt"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

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
