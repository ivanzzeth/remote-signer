package validate

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// validateTemplateOptionalVarsHaveDefault ensures optional variables declare default.
func validateTemplateOptionalVarsHaveDefault(vars []TemplateVarConfig, filePath string) error {
	for _, v := range vars {
		if v.Required {
			continue
		}
		if v.Default == nil {
			return fmt.Errorf("optional variable %q must declare default (file: %s)", v.Name, filePath)
		}
	}
	return nil
}

func validateFile(ctx context.Context, filePath string, validator *evm.SolidityRuleValidator, msgValidator *evm.MessagePatternRuleValidator, jsValidator *evm.JSRuleValidator, log *slog.Logger, verbose bool) ([]ValidationFileResult, int, int, error) {
	// Read file
	data, err := os.ReadFile(filePath) // #nosec G304 -- filePath is CLI argument
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to read file: %w", err)
	}

	// Try template format first (has variables + rules)
	var templateFile TemplateFile
	if err := yaml.Unmarshal(data, &templateFile); err != nil {
		return nil, 0, 0, fmt.Errorf("failed to parse YAML: %w", err)
	}

	var rules []RuleConfig
	if len(templateFile.Variables) > 0 && len(templateFile.Rules) > 0 {
		// Template file: validate optional vars have default, substitute test_variables, then validate
		if err := validateTemplateOptionalVarsHaveDefault(templateFile.Variables, filePath); err != nil {
			return nil, 0, 0, err
		}
		if len(templateFile.TestVariables) == 0 {
			return nil, 0, 0, fmt.Errorf("template file requires test_variables for validation (file: %s)", filePath)
		}
		rulesJSON, err := json.Marshal(templateFile.Rules)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("failed to marshal template rules: %w", err)
		}
		resolved, err := substituteVarsInString(string(rulesJSON), templateFile.TestVariables)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("template variable substitution failed: %w", err)
		}
		if err := json.Unmarshal([]byte(resolved), &rules); err != nil {
			return nil, 0, 0, fmt.Errorf("failed to unmarshal resolved template rules: %w", err)
		}
		log.Debug("Validating template file with test_variables", "file", filePath, "rules", len(rules))
	} else {
		// Plain rule file
		rules = templateFile.Rules
	}

	if len(rules) == 0 {
		log.Warn("No rules found in file", "file", filePath)
		return nil, 0, 0, nil
	}
	if err := validateExplicitRuleIDsLocal(rules); err != nil {
		return nil, 0, 0, fmt.Errorf("rule id validation: %w", err)
	}

	// Template files use isolated engines (per-rule) so other rules don't interfere with template test cases.
	return validateRules(ctx, rules, validator, msgValidator, jsValidator, templateFile.TestVariables, log, verbose, false)
}

// validateExplicitRuleIDsLocal ensures every rule has an explicit id (for validate-rules local RuleConfig).
func validateExplicitRuleIDsLocal(rules []RuleConfig) error {
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

// configToRule converts RuleConfig to types.Rule.
func configToRule(idx int, cfg RuleConfig) (*types.Rule, error) {
	return configToRuleWithID(idx, cfg)
}

// configToRuleWithID converts RuleConfig to types.Rule using effectiveRuleID (for delegate_to resolution).
func configToRuleWithID(idx int, cfg RuleConfig) (*types.Rule, error) {
	configJSON, err := json.Marshal(cfg.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	rule := &types.Rule{
		ID:          types.RuleID(effectiveRuleID(idx, cfg)),
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
	if cfg.APIKeyID != "" {
		rule.Owner = cfg.APIKeyID
	}
	if cfg.SignerAddress != "" {
		rule.SignerAddress = &cfg.SignerAddress
	}

	return rule, nil
}
