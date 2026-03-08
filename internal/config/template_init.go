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
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	pkgvalidate "github.com/ivanzzeth/remote-signer/internal/validate"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// TemplateFileType is the special template type for including templates from external files
const TemplateFileType = "file"

// TemplateInitializer handles syncing templates from config to database
type TemplateInitializer struct {
	repo        storage.TemplateRepository
	logger      *slog.Logger
	configDir   string // Base directory for resolving relative file paths
	auditLogger *audit.AuditLogger
}

// NewTemplateInitializer creates a new template initializer
func NewTemplateInitializer(repo storage.TemplateRepository, logger *slog.Logger) (*TemplateInitializer, error) {
	if repo == nil {
		return nil, fmt.Errorf("template repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &TemplateInitializer{
		repo:      repo,
		logger:    logger,
		configDir: ".",
	}, nil
}

// SetConfigDir sets the base directory for resolving relative file paths
func (i *TemplateInitializer) SetConfigDir(dir string) {
	i.configDir = dir
}

// SetAuditLogger sets the audit logger for recording config template sync events.
func (i *TemplateInitializer) SetAuditLogger(al *audit.AuditLogger) {
	i.auditLogger = al
}

// SyncFromConfig syncs templates from config to database.
// Follows the same three-way sync pattern as RuleInitializer:
// - Creates new templates
// - Updates existing templates
// - Deletes templates no longer in config (preserves API-created ones)
func (i *TemplateInitializer) SyncFromConfig(ctx context.Context, templates []TemplateConfig) error {
	// Expand file-type templates
	expandedTemplates, err := i.expandFileTemplates(templates)
	if err != nil {
		return fmt.Errorf("failed to expand file templates: %w", err)
	}

	// Build set of expected template IDs from config
	expectedIDs := make(map[string]bool)
	for idx, tmplCfg := range expandedTemplates {
		tmplID := i.generateTemplateID(idx, tmplCfg)
		expectedIDs[tmplID] = true
	}

	// Get all existing config-sourced templates from database
	configSource := types.RuleSourceConfig
	existingTemplates, err := i.repo.List(ctx, storage.TemplateFilter{
		Source: &configSource,
		Limit:  1000,
	})
	if err != nil {
		return fmt.Errorf("failed to list config templates: %w", err)
	}

	// Delete config templates that are no longer in config
	deleted := 0
	for _, tmpl := range existingTemplates {
		if !expectedIDs[tmpl.ID] {
			if err := i.repo.Delete(ctx, tmpl.ID); err != nil {
				return fmt.Errorf("failed to delete stale config template %s: %w", tmpl.ID, err)
			}
			i.logger.Info("Deleted stale config template",
				"id", tmpl.ID,
				"name", tmpl.Name,
			)
			if i.auditLogger != nil {
				i.auditLogger.LogTemplateSynced(ctx, "deleted", tmpl.ID, tmpl.Name)
			}
			deleted++
		}
	}

	if len(expandedTemplates) == 0 {
		i.logger.Info("No templates configured in config file", "deleted", deleted)
		return nil
	}

	// Sync templates from config
	synced := 0
	for idx, tmplCfg := range expandedTemplates {
		if err := i.syncTemplate(ctx, idx, tmplCfg); err != nil {
			return fmt.Errorf("failed to sync template %s: %w", tmplCfg.Name, err)
		}
		synced++
	}

	i.logger.Info("Templates synced from config", "synced", synced, "deleted", deleted)
	return nil
}

// GetLoadedTemplates returns templates expanded from config (for use by RuleInitializer)
func (i *TemplateInitializer) GetLoadedTemplates(templates []TemplateConfig) ([]TemplateConfig, error) {
	return ExpandTemplatesFromFiles(templates, i.configDir, i.logger)
}

// ExpandTemplatesFromFiles expands "file" type templates by loading from external YAML files.
// Does not require DB; use for validation (e.g. validate-rules -config). configDir resolves relative paths.
func ExpandTemplatesFromFiles(templates []TemplateConfig, configDir string, logger *slog.Logger) ([]TemplateConfig, error) {
	var expanded []TemplateConfig
	for _, tmpl := range templates {
		if tmpl.Type == TemplateFileType {
			if !tmpl.Enabled {
				// Skip loading file for disabled templates (file may not exist)
				expanded = append(expanded, tmpl)
				continue
			}
			loaded, err := loadTemplateFromFileStatic(tmpl, configDir, logger)
			if err != nil {
				return nil, err
			}
			expanded = append(expanded, loaded...)
		} else {
			expanded = append(expanded, tmpl)
		}
	}
	return expanded, nil
}

func loadTemplateFromFileStatic(fileCfg TemplateConfig, configDir string, logger *slog.Logger) ([]TemplateConfig, error) {
	pathValue, ok := fileCfg.Config["path"]
	if !ok {
		return nil, fmt.Errorf("template '%s' missing 'path' in config", fileCfg.Name)
	}
	path, ok := pathValue.(string)
	if !ok {
		return nil, fmt.Errorf("template '%s' path must be a string", fileCfg.Name)
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(configDir, path)
	}
	if logger != nil {
		logger.Info("Loading template from file", "name", fileCfg.Name, "path", path)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is admin-configured via config file
	if err != nil {
		return nil, fmt.Errorf("failed to read template file '%s': %w", path, err)
	}
	// Do NOT apply ExpandEnvWithDefaults here: template files use ${var} for template
	// variables (substituted later in expandInstanceRule). Expanding env vars would
	// replace those with empty or env values and break substitution.
	var fileContent templateFileContent
	if err := yaml.Unmarshal(data, &fileContent); err != nil {
		return nil, fmt.Errorf("failed to parse template file '%s': %w", path, err)
	}
	rulesJSON, err := json.Marshal(fileContent.Rules)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal template rules: %w", err)
	}
	result := TemplateConfig{
		Name:           fileCfg.Name,
		Description:    fileCfg.Description,
		Variables:      fileContent.Variables,
		BudgetMetering: fileContent.BudgetMetering,
		TestVariables:  fileContent.TestVariables,
		Enabled:        fileCfg.Enabled,
		Config: map[string]interface{}{
			"rules_json": string(rulesJSON),
		},
	}
	if len(fileContent.Rules) > 0 {
		result.Type = "template_bundle"
		result.Mode = fileContent.Rules[0].Mode
	}
	if logger != nil {
		logger.Info("Loaded template from file", "name", fileCfg.Name, "path", path, "variables", len(fileContent.Variables), "rules", len(fileContent.Rules))
	}
	return []TemplateConfig{result}, nil
}

// expandFileTemplates expands "file" type templates by loading from external YAML files
func (i *TemplateInitializer) expandFileTemplates(templates []TemplateConfig) ([]TemplateConfig, error) {
	return ExpandTemplatesFromFiles(templates, i.configDir, i.logger)
}

// templateFileContent represents the YAML structure of a template file
type templateFileContent struct {
	Variables      []TemplateVarConfig    `yaml:"variables"`
	BudgetMetering map[string]interface{} `yaml:"budget_metering"`
	TestVariables  map[string]string      `yaml:"test_variables"`
	Rules          []RuleConfig           `yaml:"rules"`
}

// loadTemplateFromFile loads a template from an external YAML file.
// The file contains variables, budget_metering, test_variables, and rules.
// The template is returned as a single TemplateConfig with the file content as config.
func (i *TemplateInitializer) loadTemplateFromFile(fileCfg TemplateConfig) ([]TemplateConfig, error) {
	return loadTemplateFromFileStatic(fileCfg, i.configDir, i.logger)
}

// generateTemplateID generates a deterministic template ID based on config content
func (i *TemplateInitializer) generateTemplateID(idx int, tmplCfg TemplateConfig) string {
	data := fmt.Sprintf("tmpl_cfg:%d:%s:%s", idx, tmplCfg.Name, tmplCfg.Type)
	hash := sha256.Sum256([]byte(data))
	return "tmpl_cfg_" + hex.EncodeToString(hash[:8])
}

func (i *TemplateInitializer) syncTemplate(ctx context.Context, idx int, tmplCfg TemplateConfig) error {
	if !tmplCfg.Enabled {
		i.logger.Debug("Skipping disabled template", "name", tmplCfg.Name)
		return nil
	}

	if err := pkgvalidate.ValidateRuleMode(tmplCfg.Mode); err != nil {
		return fmt.Errorf("template %q: %w", tmplCfg.Name, err)
	}
	// template_bundle is set when expanding file-type templates; allow it. Otherwise require known rule type.
	if tmplCfg.Type != TemplateFileType && tmplCfg.Type != "template_bundle" && !pkgvalidate.IsValidRuleType(tmplCfg.Type) {
		return fmt.Errorf("template %q: unknown type %q", tmplCfg.Name, tmplCfg.Type)
	}
	// Template config may contain variable placeholders; validated when instance is created.

	tmplID := i.generateTemplateID(idx, tmplCfg)

	// Marshal config to JSON
	configJSON, err := json.Marshal(tmplCfg.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal template config: %w", err)
	}

	// Marshal variables
	variablesJSON, err := json.Marshal(tmplCfg.Variables)
	if err != nil {
		return fmt.Errorf("failed to marshal template variables: %w", err)
	}

	// Marshal budget metering (nullable)
	var budgetMeteringJSON []byte
	if tmplCfg.BudgetMetering != nil {
		budgetMeteringJSON, err = json.Marshal(tmplCfg.BudgetMetering)
		if err != nil {
			return fmt.Errorf("failed to marshal budget metering: %w", err)
		}
	}

	// Marshal test variables (nullable)
	var testVariablesJSON []byte
	if tmplCfg.TestVariables != nil {
		testVariablesJSON, err = json.Marshal(tmplCfg.TestVariables)
		if err != nil {
			return fmt.Errorf("failed to marshal test variables: %w", err)
		}
	}

	// Check if template exists
	existing, err := i.repo.Get(ctx, tmplID)
	if err != nil && !types.IsNotFound(err) {
		return fmt.Errorf("failed to check existing template: %w", err)
	}

	tmpl := &types.RuleTemplate{
		ID:             tmplID,
		Name:           tmplCfg.Name,
		Description:    tmplCfg.Description,
		Type:           types.RuleType(tmplCfg.Type),
		Mode:           types.RuleMode(tmplCfg.Mode),
		Variables:      variablesJSON,
		Config:         configJSON,
		BudgetMetering: budgetMeteringJSON,
		TestVariables:  testVariablesJSON,
		Source:         types.RuleSourceConfig,
		Enabled:        tmplCfg.Enabled,
	}

	if existing == nil {
		tmpl.CreatedAt = time.Now()
		tmpl.UpdatedAt = time.Now()

		if err := i.repo.Create(ctx, tmpl); err != nil {
			return fmt.Errorf("failed to create template: %w", err)
		}

		i.logger.Info("Created template from config",
			"id", tmplID,
			"name", tmplCfg.Name,
			"type", tmplCfg.Type,
		)
		if i.auditLogger != nil {
			i.auditLogger.LogTemplateSynced(ctx, "created", tmplID, tmplCfg.Name)
		}
	} else {
		existing.Name = tmpl.Name
		existing.Description = tmpl.Description
		existing.Type = tmpl.Type
		existing.Mode = tmpl.Mode
		existing.Variables = tmpl.Variables
		existing.Config = tmpl.Config
		existing.BudgetMetering = tmpl.BudgetMetering
		existing.TestVariables = tmpl.TestVariables
		existing.Enabled = tmpl.Enabled
		existing.UpdatedAt = time.Now()

		if err := i.repo.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update template: %w", err)
		}

		i.logger.Info("Updated template from config",
			"id", tmplID,
			"name", tmplCfg.Name,
			"type", tmplCfg.Type,
		)
		if i.auditLogger != nil {
			i.auditLogger.LogTemplateSynced(ctx, "updated", tmplID, tmplCfg.Name)
		}
	}

	return nil
}

// ExpandInstanceRules expands "instance" type rules in config by substituting template variables.
// Called during rule loading to convert instance references into concrete rules.
func ExpandInstanceRules(rules []RuleConfig, templates []TemplateConfig) ([]RuleConfig, error) {
	var expanded []RuleConfig

	// Build template lookup by name
	tmplByName := make(map[string]TemplateConfig)
	for _, tmpl := range templates {
		tmplByName[tmpl.Name] = tmpl
	}

	for _, rule := range rules {
		if rule.Type != "instance" {
			expanded = append(expanded, rule)
			continue
		}

		// Expand instance rule
		instanceRules, err := expandInstanceRule(rule, tmplByName)
		if err != nil {
			return nil, fmt.Errorf("failed to expand instance rule '%s': %w", rule.Name, err)
		}
		expanded = append(expanded, instanceRules...)
	}

	return expanded, nil
}

// expandInstanceRule converts an instance rule into concrete rules by template substitution
func expandInstanceRule(rule RuleConfig, templates map[string]TemplateConfig) ([]RuleConfig, error) {
	// Get template reference
	templateName, ok := rule.Config["template"].(string)
	if !ok || templateName == "" {
		return nil, fmt.Errorf("instance rule must have 'template' in config")
	}

	tmpl, found := templates[templateName]
	if !found {
		return nil, fmt.Errorf("template '%s' not found", templateName)
	}

	// Get variables (YAML often unmarshals nested maps as map[interface{}]interface{},
	// so we must support both to avoid empty variables and broken substitution)
	variables := make(map[string]string)
	if vars, ok := rule.Config["variables"].(map[string]interface{}); ok {
		for k, v := range vars {
			variables[k] = fmt.Sprintf("%v", v)
		}
	} else if vars, ok := rule.Config["variables"].(map[interface{}]interface{}); ok {
		for k, v := range vars {
			if sk, ok := k.(string); ok {
				variables[sk] = fmt.Sprintf("%v", v)
			}
		}
	}

	// Get the rules JSON from template config (missing when template is disabled and file was not loaded)
	rulesJSON, ok := tmpl.Config["rules_json"].(string)
	if !ok {
		if !tmpl.Enabled {
			// Disabled template was not loaded from file; skip this instance rule
			return nil, nil
		}
		return nil, fmt.Errorf("template '%s' has no rules_json in config", templateName)
	}

	// Replace in(expr, ${var}) with in(expr, var) so the body keeps the array variable name
	// for InMappingArrays; then substitute other ${var} with values
	rulesJSON = substituteInMappingVarsToIdentifiers(rulesJSON)
	resolvedJSON, err := substituteVarsInString(rulesJSON, variables)
	if err != nil {
		return nil, fmt.Errorf("variable substitution failed: %w", err)
	}

	// Parse the resolved rules
	var templateRules []RuleConfig
	if err := json.Unmarshal([]byte(resolvedJSON), &templateRules); err != nil {
		return nil, fmt.Errorf("failed to parse resolved template rules: %w", err)
	}

	// Fill in_mapping_arrays for each rule from variables (for in(expr, varName) usage)
	for idx := range templateRules {
		if err := fillInMappingArrays(&templateRules[idx], variables); err != nil {
			return nil, fmt.Errorf("rule %q: %w", templateRules[idx].Name, err)
		}
	}

	// Apply test_cases_overrides from instance config (if any).
	// Instance rules can override template test_cases for full-engine validation
	// (e.g. using a different signer to avoid being auto-allowed by a global signer_restriction rule).
	if overrides := extractTestCasesOverrides(rule.Config); len(overrides) > 0 {
		for idx := range templateRules {
			if tcs, ok := overrides[templateRules[idx].Name]; ok {
				templateRules[idx].TestCases = tcs
			}
		}
	}

	// Apply scope and instance variables to all template rules
	for idx := range templateRules {
		if rule.ChainType != "" {
			templateRules[idx].ChainType = rule.ChainType
		}
		if rule.ChainID != "" {
			templateRules[idx].ChainID = rule.ChainID
		}
		if rule.APIKeyID != "" {
			templateRules[idx].APIKeyID = rule.APIKeyID
		}
		if rule.SignerAddress != "" {
			templateRules[idx].SignerAddress = rule.SignerAddress
		}
		// Inherit enabled state from instance
		templateRules[idx].Enabled = rule.Enabled
		// Pass instance variables so evaluators (e.g. evm_js) get config.chain_id, config.allowed_safe_addresses, etc.
		if len(variables) > 0 {
			templateRules[idx].Variables = make(map[string]interface{}, len(variables))
			for k, v := range variables {
				templateRules[idx].Variables[k] = v
			}
		}
	}
	instanceID, hasInstanceID := rule.Config["id"].(string)
	instanceID = strings.TrimSpace(instanceID)
	if hasInstanceID && instanceID != "" {
		if len(templateRules) == 1 {
			templateRules[0].Id = instanceID
		} else {
			// Prefix only rules that already have an id, so multiple instances of the same template get unique ids; leave empty id as-is
			for idx := range templateRules {
				tid := strings.TrimSpace(templateRules[idx].Id)
				if tid != "" {
					templateRules[idx].Id = instanceID + "_" + tid
				}
			}
		}
	}

	return templateRules, nil
}

// substituteVarsInString replaces ${var} placeholders with values
func substituteVarsInString(s string, vars map[string]string) (string, error) {
	result := s
	for k, v := range vars {
		result = strings.ReplaceAll(result, "${"+k+"}", v)
	}
	// Check for unresolved variables (but ignore ${VAR:-default} env var syntax)
	// Template variables are simple ${name} without colons
	if idx := strings.Index(result, "${"); idx >= 0 {
		// Extract variable name
		end := strings.Index(result[idx:], "}")
		if end > 0 {
			varName := result[idx+2 : idx+end]
			// Only error if it doesn't look like an env var (no colon)
			if !strings.Contains(varName, ":") {
				return "", fmt.Errorf("unresolved template variable: ${%s}", varName)
			}
		}
	}
	return result, nil
}

// substituteInMappingVarsToIdentifiers replaces in(expr, ${var}) with in(expr, var) so the
// body keeps the variable name for InMappingArrays; other ${var} are left for substituteVarsInString.
var inMappingVarRe = regexp.MustCompile(`in\s*\(\s*([^,]+)\s*,\s*\$\{(\w+)\}\s*\)`)

func substituteInMappingVarsToIdentifiers(s string) string {
	return inMappingVarRe.ReplaceAllString(s, "in($1, $2)")
}

// fillInMappingArrays scans rule config for in(expr, varName) and sets config["in_mapping_arrays"]
// from variables so the evaluator can generate mappings.
func fillInMappingArrays(rule *RuleConfig, variables map[string]string) error {
	if rule.Config == nil {
		return nil
	}
	// Keys that may contain in(expr, varName)
	configKeys := []string{"expression", "functions", "typed_data_expression", "typed_data_functions"}
	var re = regexp.MustCompile(`in\s*\(\s*[^,]+,\s*(\w+)\s*\)`)
	seen := make(map[string]bool)
	for _, key := range configKeys {
		v, ok := rule.Config[key].(string)
		if !ok || v == "" {
			continue
		}
		for _, sub := range re.FindAllStringSubmatch(v, -1) {
			if len(sub) >= 2 {
				seen[sub[1]] = true
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	inMappingArrays := make(map[string][]string)
	for varName := range seen {
		raw, ok := variables[varName]
		if !ok {
			continue
		}
		// Parse comma-separated addresses
		parts := strings.Split(raw, ",")
		var addrs []string
		for _, p := range parts {
			a := strings.TrimSpace(p)
			if a != "" {
				addrs = append(addrs, a)
			}
		}
		inMappingArrays[varName] = addrs
	}
	if len(inMappingArrays) > 0 {
		rule.Config["in_mapping_arrays"] = inMappingArrays
	}
	return nil
}

// extractTestCasesOverrides parses the test_cases_overrides field from an instance rule's config.
// Returns a map of rule_name -> []TestCaseConfig. If the field is absent or invalid, returns nil.
func extractTestCasesOverrides(instanceConfig map[string]interface{}) map[string][]TestCaseConfig {
	raw, ok := instanceConfig["test_cases_overrides"]
	if !ok || raw == nil {
		return nil
	}

	// The YAML deserializes this as map[string]interface{} where each value is []interface{}.
	// We need to marshal/unmarshal through JSON for proper type conversion.
	data, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var overrides map[string][]TestCaseConfig
	if err := json.Unmarshal(data, &overrides); err != nil {
		return nil
	}
	return overrides
}
