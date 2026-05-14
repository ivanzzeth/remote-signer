package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

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

// effectiveRuleID returns the rule ID to use: custom RuleConfig.Id if non-empty, else generated.
func (i *RuleInitializer) effectiveRuleID(idx int, ruleCfg RuleConfig) types.RuleID {
	return EffectiveRuleID(idx, ruleCfg)
}
