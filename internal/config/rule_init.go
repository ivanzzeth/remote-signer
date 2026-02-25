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

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/ruleconfig"
	pkgvalidate "github.com/ivanzzeth/remote-signer/internal/validate"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// RuleFileType is the special rule type for including rules from external files
const RuleFileType = "file"

// RuleFileConfig represents the config structure for file-type rules
type RuleFileConfig struct {
	Path string `yaml:"path"` // Path to the YAML file containing rules
}

// RuleInitializer handles syncing rules from config to database
type RuleInitializer struct {
	repo      storage.RuleRepository
	logger    *slog.Logger
	configDir string // Base directory for resolving relative file paths
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

// SyncFromConfig syncs rules from config to database
// - Creates new rules that don't exist (identified by generated ID from config)
// - Updates existing rules with new values from config
// - Deletes config-sourced rules that are no longer in config (preserves API-created rules)
// - Expands "file" type rules by loading rules from external YAML files
func (i *RuleInitializer) SyncFromConfig(ctx context.Context, rules []RuleConfig) error {
	// Expand file-type rules
	expandedRules, err := i.expandFileRules(rules)
	if err != nil {
		return fmt.Errorf("failed to expand file rules: %w", err)
	}

	// Build set of expected rule IDs (custom id or generated); enforce uniqueness
	expectedIDs := make(map[types.RuleID]bool)
	for idx, ruleCfg := range expandedRules {
		ruleID := i.effectiveRuleID(idx, ruleCfg)
		if expectedIDs[ruleID] {
			return fmt.Errorf("duplicate rule id %q (rule %q); custom id must be unique", ruleID, ruleCfg.Name)
		}
		expectedIDs[ruleID] = true
	}

	// Get all existing config-sourced rules from database
	configSource := types.RuleSourceConfig
	existingRules, err := i.repo.List(ctx, storage.RuleFilter{
		Source: &configSource,
		Limit:  1000, // Get all config rules
	})
	if err != nil {
		return fmt.Errorf("failed to list config rules: %w", err)
	}

	// Delete config rules that are no longer in config
	deleted := 0
	for _, rule := range existingRules {
		if !expectedIDs[rule.ID] {
			if err := i.repo.Delete(ctx, rule.ID); err != nil {
				return fmt.Errorf("failed to delete stale config rule %s: %w", rule.ID, err)
			}
			i.logger.Info("Deleted stale config rule",
				"id", rule.ID,
				"name", rule.Name,
			)
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
		if err := i.syncRule(ctx, ruleID, ruleCfg); err != nil {
			return fmt.Errorf("failed to sync rule %s: %w", ruleCfg.Name, err)
		}
		synced++
	}

	i.logger.Info("Rules synced from config", "synced", synced, "deleted", deleted)
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
	data, err := os.ReadFile(path)
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
	data := fmt.Sprintf("config:%d:%s:%s", idx, ruleCfg.Name, ruleCfg.Type)
	hash := sha256.Sum256([]byte(data))
	return types.RuleID("cfg_" + hex.EncodeToString(hash[:8]))
}

// effectiveRuleID returns the rule ID to use: custom RuleConfig.Id if non-empty, else generated.
func (i *RuleInitializer) effectiveRuleID(idx int, ruleCfg RuleConfig) types.RuleID {
	if s := strings.TrimSpace(ruleCfg.Id); s != "" {
		return types.RuleID(s)
	}
	return i.generateRuleID(idx, ruleCfg)
}

func (i *RuleInitializer) syncRule(ctx context.Context, ruleID types.RuleID, ruleCfg RuleConfig) error {
	// Skip disabled rules
	if !ruleCfg.Enabled {
		i.logger.Debug("Skipping disabled rule", "name", ruleCfg.Name)
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

	// Check if rule exists
	existing, err := i.repo.Get(ctx, ruleID)
	if err != nil && !types.IsNotFound(err) {
		return fmt.Errorf("failed to check existing rule: %w", err)
	}

	// Build rule
	rule := &types.Rule{
		ID:          ruleID,
		Name:        ruleCfg.Name,
		Description: ruleCfg.Description,
		Type:        types.RuleType(ruleCfg.Type),
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

	// Set optional scope fields
	if ruleCfg.ChainType != "" {
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
		rule.SignerAddress = &ruleCfg.SignerAddress
	}

	if existing == nil {
		// Create new rule
		rule.CreatedAt = time.Now()
		rule.UpdatedAt = time.Now()

		if err := i.repo.Create(ctx, rule); err != nil {
			return fmt.Errorf("failed to create rule: %w", err)
		}

		i.logger.Info("Created rule from config",
			"id", ruleID,
			"name", ruleCfg.Name,
			"type", ruleCfg.Type,
			"mode", ruleCfg.Mode,
		)
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

		if err := i.repo.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update rule: %w", err)
		}

		i.logger.Info("Updated rule from config",
			"id", ruleID,
			"name", ruleCfg.Name,
			"type", ruleCfg.Type,
			"mode", ruleCfg.Mode,
		)
	}

	return nil
}
