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
	repo        storage.RuleRepository
	logger      *slog.Logger
	configDir   string // Base directory for resolving relative file paths
	auditLogger *audit.AuditLogger
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

	syncBody := func(repo storage.RuleRepository) error {
		return i.executeSyncBody(ctx, repo, expandedRules, expectedIDs)
	}

	// Use transaction if repository supports it
	if txRepo, ok := i.repo.(storage.Transactional); ok {
		return txRepo.RunInTransaction(ctx, syncBody)
	}
	return syncBody(i.repo)
}

// executeSyncBody performs the actual sync: delete stale rules, upsert current rules, verify consistency.
// repo is the (possibly transactional) repository to use for all operations.
func (i *RuleInitializer) executeSyncBody(ctx context.Context, repo storage.RuleRepository, expandedRules []RuleConfig, expectedIDs map[types.RuleID]bool) error {
	// Get all existing config-sourced rules from database
	configSource := types.RuleSourceConfig
	existingRules, err := repo.List(ctx, storage.RuleFilter{
		Source: &configSource,
		Limit:  -1, // No limit — fetch all config rules
	})
	if err != nil {
		return fmt.Errorf("failed to list config rules: %w", err)
	}

	// Delete config rules that are no longer in config
	deleted := 0
	for _, rule := range existingRules {
		if !expectedIDs[rule.ID] {
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
		if err := i.syncRule(ctx, repo, ruleID, ruleCfg); err != nil {
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

func (i *RuleInitializer) syncRule(ctx context.Context, repo storage.RuleRepository, ruleID types.RuleID, ruleCfg RuleConfig) error {
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
	if len(ruleCfg.Variables) > 0 {
		variablesJSON, err := json.Marshal(ruleCfg.Variables)
		if err != nil {
			return fmt.Errorf("failed to marshal rule variables: %w", err)
		}
		rule.Variables = variablesJSON
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

	if existing == nil {
		// Create new rule
		rule.CreatedAt = time.Now()
		rule.UpdatedAt = time.Now()

		if err := repo.Create(ctx, rule); err != nil {
			return fmt.Errorf("failed to create rule: %w", err)
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
		existing.UpdatedAt = time.Now()

		if err := repo.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update rule: %w", err)
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
