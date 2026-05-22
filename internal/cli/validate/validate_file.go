// Package validate provides the rule-validation CLI logic for remote-signer validate.
// This file handles file-level rule validation including template variables and rule ID generation.
package validate

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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

	// Detect preset files (have template_ids key) vs template/rule files
	var rawMap map[string]any
	if err := yaml.Unmarshal(data, &rawMap); err != nil {
		return nil, 0, 0, fmt.Errorf("failed to parse YAML: %w", err)
	}
	if _, ok := rawMap["template_ids"]; ok {
		return validatePresetFile(ctx, data, filePath, validator, msgValidator, jsValidator, log, verbose)
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

	// Some templates nest test_cases inside the config map rather than at the
	// rule level. Extract them so the validation pipeline can find them.
	extractTestCasesFromConfig(rules)

	// Template files use isolated engines (per-rule) so other rules don't interfere with template test cases.
	return validateRules(ctx, rules, validator, msgValidator, jsValidator, templateFile.TestVariables, log, verbose, false)
}

// validatePresetFile validates a preset YAML file by finding each referenced
// template, merging preset variables, and running the existing template
// validation pipeline.
func validatePresetFile(ctx context.Context, data []byte, filePath string, validator *evm.SolidityRuleValidator, msgValidator *evm.MessagePatternRuleValidator, jsValidator *evm.JSRuleValidator, log *slog.Logger, verbose bool) ([]ValidationFileResult, int, int, error) {
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, 0, 0, fmt.Errorf("failed to parse preset YAML: %w", err)
	}

	// Extract template_ids
	templateIDsRaw, ok := raw["template_ids"]
	if !ok {
		return nil, 0, 0, fmt.Errorf("preset file has no template_ids")
	}
	templateIDsRawSlice, ok := templateIDsRaw.([]interface{})
	if !ok {
		return nil, 0, 0, fmt.Errorf("template_ids must be a list")
	}
	templateIDs := make([]string, 0, len(templateIDsRawSlice))
	for _, t := range templateIDsRawSlice {
		s, ok := t.(string)
		if !ok {
			return nil, 0, 0, fmt.Errorf("template_ids entry must be a string")
		}
		templateIDs = append(templateIDs, s)
	}

	// Extract preset variables
	presetVarsRaw, _ := raw["variables"].(map[string]interface{})
	presetVars := interfaceMapToStringMap(presetVarsRaw)

	// Inject chain_id from preset top-level into variables
	if chainID, ok := raw["chain_id"].(string); ok && chainID != "" {
		presetVars["chain_id"] = chainID
	}

	// Derive templates root: replace /presets/ with /templates/, go up one level
	templatesCandidate := strings.Replace(filePath, "/presets/", "/templates/", 1)
	if templatesCandidate == filePath {
		// Fallback for edge-case paths
		templatesCandidate = filepath.Join(filepath.Dir(filePath), "..", "templates")
	}
	templatesRoot := filepath.Dir(filepath.Dir(templatesCandidate))

	// Collect ALL rules from ALL templates first, then validate them together
	// so delegate_to cross-references between templates resolve correctly.
	var allRules []RuleConfig
	mergedVars := make(map[string]string)
	// Base: collect template test_variables from each template
	for _, tid := range templateIDs {
		tmplPath := filepath.Join(templatesRoot, tid+".yaml")
		tmplData, err := os.ReadFile(tmplPath)
		if err != nil {
			log.Warn("Preset references unresolvable template", "template_id", tid, "path", tmplPath, "error", err)
			continue
		}
		var tmplFile TemplateFile
		if err := yaml.Unmarshal(tmplData, &tmplFile); err != nil {
			log.Warn("Failed to parse template file referenced by preset", "template_id", tid, "path", tmplPath, "error", err)
			continue
		}
		if len(tmplFile.Rules) == 0 {
			log.Warn("Template has no rules, skipping", "template_id", tid)
			continue
		}
		// Collect test_variables from each template
		for k, v := range tmplFile.TestVariables {
			if _, exists := mergedVars[k]; !exists {
				mergedVars[k] = v
			}
		}
	}
	// Preset variables override template test_variables
	for k, v := range presetVars {
		mergedVars[k] = v
	}

	for _, tid := range templateIDs {
		tmplPath := filepath.Join(templatesRoot, tid+".yaml")
		tmplData, err := os.ReadFile(tmplPath)
		if err != nil {
			continue
		}
		var tmplFile TemplateFile
		if err := yaml.Unmarshal(tmplData, &tmplFile); err != nil {
			continue
		}
		if len(tmplFile.Rules) == 0 {
			continue
		}

		// Substitute variables into template rules
		rulesJSON, err := json.Marshal(tmplFile.Rules)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("failed to marshal template rules for %q: %w", tid, err)
		}
		resolved, err := substituteVarsInString(string(rulesJSON), mergedVars)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("variable substitution failed for template %q: %w", tid, err)
		}
		var resolvedRules []RuleConfig
		if err := json.Unmarshal([]byte(resolved), &resolvedRules); err != nil {
			return nil, 0, 0, fmt.Errorf("failed to unmarshal resolved rules for template %q: %w", tid, err)
		}

		// Set mergedVars as TestVariables so validateRules seeds the JS engine with preset values
		for i := range resolvedRules {
			resolvedRules[i].TestVariables = mergedVars
		}

		allRules = append(allRules, resolvedRules...)
	}

	if len(allRules) == 0 {
		return nil, 0, 0, fmt.Errorf("no valid rules found in preset templates")
	}

	extractTestCasesFromConfig(allRules)

	// Validate ALL rules together so delegate_to cross-references work
	return validateRules(ctx, allRules, validator, msgValidator, jsValidator, mergedVars, log, verbose, true)
}

// extractTestCasesFromConfig moves test_cases out of the Config map and onto
// the RuleConfig.TestCases field when they were nested inside config in YAML.
// This handles templates like polymarket_v2.yaml where test_cases is a peer of
// script/description inside the config: block rather than a rule-level field.
// Does NOT delete from config so other validators (e.g. solidity) can still
// find test_cases in the config JSON.
func extractTestCasesFromConfig(rules []RuleConfig) {
	for i, r := range rules {
		if len(r.TestCases) > 0 {
			continue // already at rule level
		}
		tcRaw, ok := r.Config["test_cases"]
		if !ok {
			continue
		}
		tcJSON, err := json.Marshal(tcRaw)
		if err != nil {
			continue
		}
		var tcs []TestCaseConfig
		if err := json.Unmarshal(tcJSON, &tcs); err != nil {
			continue
		}
		if len(tcs) > 0 {
			rules[i].TestCases = tcs
		}
	}
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
