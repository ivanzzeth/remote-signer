package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ruleConfig mirrors the RuleConfig from validate-rules CLI (avoid circular imports).
type ruleConfig struct {
	Name          string         `yaml:"name"`
	Description   string         `yaml:"description,omitempty"`
	Type          string         `yaml:"type"`
	Mode          string         `yaml:"mode"`
	ChainType     string         `yaml:"chain_type,omitempty"`
	ChainID       string         `yaml:"chain_id,omitempty"`
	APIKeyID      string         `yaml:"api_key_id,omitempty"`
	SignerAddress string         `yaml:"signer_address,omitempty"`
	Config        map[string]any `yaml:"config"`
	Enabled       bool           `yaml:"enabled"`
}

// ruleFile represents a YAML file containing rules.
type ruleFile struct {
	Rules []ruleConfig `yaml:"rules"`
}

// templateRuleFile represents a YAML template file (variables + test_variables + rules).
type templateRuleFile struct {
	Variables     []map[string]interface{} `yaml:"variables"`
	TestVariables map[string]string        `yaml:"test_variables"`
	Rules         []ruleConfig             `yaml:"rules"`
}

// substituteVarsInString replaces ${var} placeholders with values from vars.
func substituteVarsInString(s string, vars map[string]string) (string, error) {
	result := s
	for k, v := range vars {
		result = strings.ReplaceAll(result, "${"+k+"}", v)
	}
	if idx := strings.Index(result, "${"); idx >= 0 {
		end := strings.Index(result[idx:], "}")
		if end > 0 {
			varName := result[idx+2 : idx+end]
			if !strings.Contains(varName, ":") {
				return "", fmt.Errorf("unresolved template variable: ${%s}", varName)
			}
		}
	}
	return result, nil
}

// projectRoot returns the project root by walking up from the current test file.
func projectRoot() string {
	_, filename, _, _ := runtime.Caller(0)
	// filename is .../internal/chain/evm/solidity_rules_validation_test.go
	dir := filepath.Dir(filename)
	// Walk up: evm -> chain -> internal -> project root
	return filepath.Join(dir, "..", "..", "..")
}

// configToRule converts a ruleConfig to a types.Rule.
func configToRule(idx int, cfg ruleConfig) (*types.Rule, error) {
	configJSON, err := json.Marshal(cfg.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	rule := &types.Rule{
		ID:          types.RuleID(fmt.Sprintf("test_%d", idx)),
		Name:        cfg.Name,
		Description: cfg.Description,
		Type:        types.RuleType(cfg.Type),
		Mode:        types.RuleMode(cfg.Mode),
		Source:      types.RuleSourceConfig,
		Config:      configJSON,
		Enabled:     cfg.Enabled,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if cfg.ChainType != "" {
		ct := types.ChainType(cfg.ChainType)
		rule.ChainType = &ct
	} else {
		ct := types.ChainTypeEVM
		rule.ChainType = &ct
	}
	if cfg.ChainID != "" {
		rule.ChainID = &cfg.ChainID
	}

	return rule, nil
}

// TestRulesDirectoryValidation validates all rule YAML files in the rules/ directory.
// This test ensures that every rule in the repository is syntactically and semantically
// valid, preventing broken rules from being committed.
//
// Requires: forge (foundry) to be installed. Skips automatically if forge is unavailable.
func TestRulesDirectoryValidation(t *testing.T) {
	// Skip if forge is not available
	forgePath, err := exec.LookPath("forge")
	if err != nil {
		t.Skip("forge not found in PATH, skipping rule validation (install foundry to enable)")
	}
	t.Logf("Using forge: %s", forgePath)

	rulesDir := filepath.Join(projectRoot(), "rules")
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		t.Fatalf("rules directory not found at %s", rulesDir)
	}

	// Find all YAML files in the rules directory (plain rule files)
	yamlFiles, err := filepath.Glob(filepath.Join(rulesDir, "*.yaml"))
	require.NoError(t, err)

	// Find all template YAML files
	templatesDir := filepath.Join(rulesDir, "templates")
	templateFiles, _ := filepath.Glob(filepath.Join(templatesDir, "*.yaml"))
	if templateFiles == nil {
		templateFiles = []string{}
	}

	allYamlCount := len(yamlFiles) + len(templateFiles)
	if allYamlCount == 0 {
		t.Fatal("no YAML files found in rules or rules/templates directory")
	}

	// Initialize evaluator and validator
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
	evaluator, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		Timeout: 60 * time.Second,
	}, logger)
	require.NoError(t, err)

	validator, err := NewSolidityRuleValidator(evaluator, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Collect all rules from all files
	var allRules []*types.Rule
	type ruleFileInfo struct {
		file     string
		ruleName string
	}
	var ruleInfos []ruleFileInfo

	// Process plain rule files
	for _, filePath := range yamlFiles {
		data, err := os.ReadFile(filePath)
		require.NoError(t, err, "failed to read %s", filePath)

		var rf ruleFile
		require.NoError(t, yaml.Unmarshal(data, &rf), "failed to parse %s", filePath)

		fileName := filepath.Base(filePath)
		for i, cfg := range rf.Rules {
			if cfg.Type != string(types.RuleTypeEVMSolidityExpression) {
				continue
			}
			if !cfg.Enabled {
				continue
			}

			rule, err := configToRule(len(allRules)+i, cfg)
			require.NoError(t, err, "failed to convert rule %q from %s", cfg.Name, fileName)

			allRules = append(allRules, rule)
			ruleInfos = append(ruleInfos, ruleFileInfo{
				file:     fileName,
				ruleName: cfg.Name,
			})
		}
	}

	// Process template files: substitute test_variables then validate resolved rules
	for _, filePath := range templateFiles {
		data, err := os.ReadFile(filePath)
		require.NoError(t, err, "failed to read %s", filePath)

		var tf templateRuleFile
		require.NoError(t, yaml.Unmarshal(data, &tf), "failed to parse template %s", filePath)
		if len(tf.Variables) == 0 || len(tf.Rules) == 0 {
			continue
		}
		require.NotEmpty(t, tf.TestVariables, "template %s must have test_variables for validation", filePath)

		rulesJSON, err := json.Marshal(tf.Rules)
		require.NoError(t, err, "failed to marshal template rules from %s", filePath)
		resolved, err := substituteVarsInString(string(rulesJSON), tf.TestVariables)
		require.NoError(t, err, "template variable substitution failed in %s", filePath)
		var resolvedRules []ruleConfig
		require.NoError(t, json.Unmarshal([]byte(resolved), &resolvedRules), "failed to unmarshal resolved rules from %s", filePath)

		fileName := filepath.Base(filePath)
		for i, cfg := range resolvedRules {
			if cfg.Type != string(types.RuleTypeEVMSolidityExpression) {
				continue
			}
			if !cfg.Enabled {
				continue
			}

			rule, err := configToRule(len(allRules)+i, cfg)
			require.NoError(t, err, "failed to convert rule %q from template %s", cfg.Name, fileName)

			allRules = append(allRules, rule)
			ruleInfos = append(ruleInfos, ruleFileInfo{
				file:     fileName,
				ruleName: cfg.Name,
			})
		}
	}

	require.NotEmpty(t, allRules, "no Solidity expression rules found across all files")
	t.Logf("Validating %d Solidity expression rules from %d plain + %d template files", len(allRules), len(yamlFiles), len(templateFiles))

	// Batch validate all rules
	batchResult, err := validator.ValidateRulesBatch(ctx, allRules)
	require.NoError(t, err, "batch validation failed")
	require.Equal(t, len(allRules), len(batchResult.Results), "result count mismatch")

	// Check each rule
	failedRules := 0
	for i, result := range batchResult.Results {
		info := ruleInfos[i]
		t.Run(fmt.Sprintf("%s/%s", info.file, info.ruleName), func(t *testing.T) {
			if !result.Valid {
				failedRules++
				if result.SyntaxError != nil {
					t.Errorf("Syntax error: %s (line %d)", result.SyntaxError.Message, result.SyntaxError.Line)
				}
				for _, tc := range result.TestCaseResults {
					if !tc.Passed {
						t.Errorf("Test case %q failed: %s", tc.Name, tc.Error)
					}
				}
			}
			assert.True(t, result.Valid, "rule %q from %s should be valid", info.ruleName, info.file)
		})
	}

	if failedRules > 0 {
		t.Errorf("%d out of %d rules failed validation", failedRules, len(allRules))
	}
}
