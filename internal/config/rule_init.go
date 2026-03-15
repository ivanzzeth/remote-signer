package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/internal/audit"
	rulepkg "github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/ruleconfig"
	"github.com/ivanzzeth/remote-signer/internal/storage"
	pkgvalidate "github.com/ivanzzeth/remote-signer/internal/validate"
)

// RuleFileType is the special rule type for including rules from external files
const RuleFileType = "file"

// RuleFileConfig represents the config structure for file-type rules
type RuleFileConfig struct {
	Path string `yaml:"path"` // Path to the YAML file containing rules
}

// RuleInitializer handles syncing rules from config to database
type RuleInitializer struct {
	repo         storage.RuleRepository
	templateRepo storage.TemplateRepository // optional: for instance rules — set TemplateID and create budget
	budgetRepo   storage.BudgetRepository  // optional: for instance rules with budget
	logger       *slog.Logger
	configDir    string // Base directory for resolving relative file paths
	auditLogger  *audit.AuditLogger
}

// NewRuleInitializer creates a new rule initializer
func NewRuleInitializer(repo storage.RuleRepository, logger *slog.Logger) (*RuleInitializer, error) {
	if repo == nil {
		return nil, fmt.Errorf("rule repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &RuleInitializer{
		repo:      repo,
		logger:    logger,
		configDir: ".", // Default to current directory
	}, nil
}

// SetTemplateRepo sets the template repository for instance-rule sync (TemplateID + budget).
func (i *RuleInitializer) SetTemplateRepo(repo storage.TemplateRepository) {
	i.templateRepo = repo
}

// SetBudgetRepo sets the budget repository for instance-rule sync (create budget records).
func (i *RuleInitializer) SetBudgetRepo(repo storage.BudgetRepository) {
	i.budgetRepo = repo
}

// SetConfigDir sets the base directory for resolving relative file paths in rule files
func (i *RuleInitializer) SetConfigDir(dir string) {
	i.configDir = dir
}

// SetAuditLogger sets the audit logger for recording config rule sync events.
func (i *RuleInitializer) SetAuditLogger(al *audit.AuditLogger) {
	i.auditLogger = al
}

// ValidateExplicitRuleIDs ensures every rule has an explicit id. Returns error if any rule lacks id.
// Required to keep rule IDs stable across preset/config changes (avoids index-based ID drift).
func ValidateExplicitRuleIDs(rules []RuleConfig) error {
	var missing []string
	for idx, r := range rules {
		if strings.TrimSpace(r.Id) == "" {
			missing = append(missing, fmt.Sprintf("rule %q (index %d)", r.Name, idx))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("rules must have explicit id; missing id for: %s", strings.Join(missing, ", "))
	}
	return nil
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

// pendingBudgetCreate holds data to create a budget after the rule-sync transaction commits.
type pendingBudgetCreate struct {
	Rule           *types.Rule
	Tmpl           *types.RuleTemplate
	InstanceBudget map[string]interface{}
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

// expandFileRules expands "file" type rules by loading rules from external YAML files
// It recursively expands nested file rules up to a maximum depth
func (i *RuleInitializer) expandFileRules(rules []RuleConfig) ([]RuleConfig, error) {
	return ExpandFileRules(rules, i.configDir, i.logger)
}

// ExpandFileRules expands "file" type rules by loading from external YAML files (no DB).
// Use for validation (e.g. validate-rules -config). configDir resolves relative paths.
func ExpandFileRules(rules []RuleConfig, configDir string, logger *slog.Logger) ([]RuleConfig, error) {
	return expandFileRulesWithDepth(rules, configDir, logger, 0, 10)
}

func expandFileRulesWithDepth(rules []RuleConfig, configDir string, logger *slog.Logger, depth, maxDepth int) ([]RuleConfig, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("maximum rule file inclusion depth (%d) exceeded", maxDepth)
	}
	var expanded []RuleConfig
	for _, rule := range rules {
		if rule.Type == RuleFileType {
			fileRules, err := loadRulesFromFileStatic(rule, configDir, logger)
			if err != nil {
				return nil, fmt.Errorf("failed to load rules from file: %w", err)
			}
			nestedExpanded, err := expandFileRulesWithDepth(fileRules, configDir, logger, depth+1, maxDepth)
			if err != nil {
				return nil, err
			}
			expanded = append(expanded, nestedExpanded...)
		} else {
			expanded = append(expanded, rule)
		}
	}
	return expanded, nil
}

func loadRulesFromFileStatic(fileCfg RuleConfig, configDir string, logger *slog.Logger) ([]RuleConfig, error) {
	pathValue, ok := fileCfg.Config["path"]
	if !ok {
		return nil, fmt.Errorf("file rule '%s' missing 'path' in config", fileCfg.Name)
	}
	path, ok := pathValue.(string)
	if !ok {
		return nil, fmt.Errorf("file rule '%s' path must be a string", fileCfg.Name)
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(configDir, path)
	}
	if logger != nil {
		logger.Info("Loading rules from file", "name", fileCfg.Name, "path", path)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is admin-configured via config file
	if err != nil {
		return nil, fmt.Errorf("failed to read rule file '%s': %w", path, err)
	}
	expandedData := ExpandEnvWithDefaults(string(data))
	var fileContent struct {
		Rules []RuleConfig `yaml:"rules"`
	}
	if err := yaml.Unmarshal([]byte(expandedData), &fileContent); err != nil {
		return nil, fmt.Errorf("failed to parse rule file '%s': %w", path, err)
	}
	if logger != nil {
		logger.Info("Loaded rules from file", "name", fileCfg.Name, "path", path, "count", len(fileContent.Rules))
	}
	return fileContent.Rules, nil
}

// loadRulesFromFile loads rules from an external YAML file (RuleInitializer wrapper)
func (i *RuleInitializer) loadRulesFromFile(fileCfg RuleConfig) ([]RuleConfig, error) {
	return loadRulesFromFileStatic(fileCfg, i.configDir, i.logger)
}

// generateRuleID generates a deterministic rule ID based on config content
// when no custom id is set (format: cfg_<sha256 prefix>).
func (i *RuleInitializer) generateRuleID(idx int, ruleCfg RuleConfig) types.RuleID {
	return EffectiveRuleID(idx, ruleCfg)
}

// EffectiveRuleID returns the rule ID for a config rule at the given index.
// Used by rule sync and by evm_js startup validation (same as validate-rules).
// Exported so cmd/remote-signer can run evm_js test cases at startup.
func EffectiveRuleID(idx int, ruleCfg RuleConfig) types.RuleID {
	if s := strings.TrimSpace(ruleCfg.Id); s != "" {
		return types.RuleID(s)
	}
	data := fmt.Sprintf("config:%d:%s:%s", idx, ruleCfg.Name, ruleCfg.Type)
	hash := sha256.Sum256([]byte(data))
	return types.RuleID("cfg_" + hex.EncodeToString(hash[:8]))
}

// ValidateDelegationTargets checks that all delegate_to references in rules
// resolve to existing rule IDs. Returns error if any target is missing.
func ValidateDelegationTargets(rules []RuleConfig) error {
	// Build set of all known rule IDs
	knownIDs := make(map[types.RuleID]bool, len(rules))
	for idx, r := range rules {
		knownIDs[EffectiveRuleID(idx, r)] = true
	}
	// Check each rule's delegate_to
	var errs []string
	for idx, r := range rules {
		delegateTo, _ := r.Config["delegate_to"].(string)
		if delegateTo == "" {
			continue
		}
		ruleID := EffectiveRuleID(idx, r)
		for _, part := range strings.Split(delegateTo, ",") {
			targetID := types.RuleID(strings.TrimSpace(part))
			if targetID == "" {
				continue
			}
			if strings.Contains(string(targetID), "${") {
				continue // unresolved variable — skip
			}
			if !knownIDs[targetID] {
				errs = append(errs, fmt.Sprintf("rule %q (%s) delegate_to references non-existent target %q", r.Name, ruleID, targetID))
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("delegation target validation failed:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

// effectiveRuleID returns the rule ID to use: custom RuleConfig.Id if non-empty, else generated.
func (i *RuleInitializer) effectiveRuleID(idx int, ruleCfg RuleConfig) types.RuleID {
	return EffectiveRuleID(idx, ruleCfg)
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

	if ruleCfg.APIKeyID != "" {
		rule.APIKeyID = &ruleCfg.APIKeyID
	}
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
		existing.APIKeyID = rule.APIKeyID
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
			i.auditLogger.LogRuleUpdated(ctx, "config", "config-sync", ruleID, ruleCfg.Name)
		}
	}

	return nil
}

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
func syncBudgetFromConfig(ctx context.Context, rule *types.Rule, tmpl *types.RuleTemplate, budgetMap map[string]interface{}, budgetRepo storage.BudgetRepository) error {
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
			if err := json.Unmarshal(tmpl.BudgetMetering, &metering); err == nil && metering.Unit != "" {
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
			if err := json.Unmarshal(tmpl.BudgetMetering, &metering); err == nil && metering.Unit != "" {
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
