// Package preset provides shared preset parsing and metadata for both CLI and server.
// Preset YAML can be single-rule (template + template_path), composite (template_paths + template_names),
// or multi-rule (rules: list). ParsePresetFile returns a list of PresetRule that the CLI converts to
// config.RuleConfig and the server converts to template.CreateInstanceRequest.
package preset

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// PresetEntry is a preset file summary for listing (e.g. presets directory).
type PresetEntry struct {
	ID            string   // file name without path
	TemplateNames []string // template name(s) used by this preset
}

// PresetMeta holds template name(s), path(s), and override hints from a preset file.
type PresetMeta struct {
	Template      string
	TemplatePath  string
	TemplatePaths []string
	TemplateNames []string
	OverrideHints []string
}

// PresetRule is one rule derived from a preset. Used by CLI to build config.RuleConfig
// and by server to build template.CreateInstanceRequest.
type PresetRule struct {
	TemplateName string
	Name         string
	Mode         string                 // e.g. "whitelist" or "blocklist"; defaults to "whitelist" if empty in YAML
	Variables    map[string]string
	ChainType    string
	ChainID      string
	Enabled      bool
	Budget       map[string]interface{} // after ${var} substitution; optional
	Schedule     map[string]interface{} // after substitution; optional
}

// ListPresets reads a directory of preset YAML files and returns entries with template names.
func ListPresets(dir string) ([]PresetEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []PresetEntry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path) // #nosec G304 -- path from trusted presets-dir
		if err != nil {
			continue
		}
		names := TemplateNamesFromData(data)
		out = append(out, PresetEntry{ID: e.Name(), TemplateNames: names})
	}
	return out, nil
}

// TemplateNamesFromData returns template name(s) from preset YAML for listing.
// Supports single-rule (template), composite (template_names), and multi-rule (rules[].config.template).
func TemplateNamesFromData(data []byte) []string {
	meta, err := GetPresetMeta(data)
	if err != nil {
		return nil
	}
	if meta.Template != "" {
		return []string{meta.Template}
	}
	if len(meta.TemplateNames) > 0 {
		return meta.TemplateNames
	}
	var multi struct {
		Rules []struct {
			Config map[string]interface{} `yaml:"config"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &multi); err != nil || len(multi.Rules) == 0 {
		return nil
	}
	var names []string
	for _, r := range multi.Rules {
		if t, _ := r.Config["template"].(string); t != "" {
			names = append(names, t)
		}
	}
	return names
}

// GetPresetMeta parses preset YAML and returns template name(s), template_path(s), and override_hints.
func GetPresetMeta(data []byte) (PresetMeta, error) {
	var out PresetMeta
	var single struct {
		Template      string   `yaml:"template"`
		TemplatePath  string   `yaml:"template_path"`
		TemplatePaths []string `yaml:"template_paths"`
		TemplateNames []string `yaml:"template_names"`
		OverrideHints []string `yaml:"override_hints"`
	}
	if err := yaml.Unmarshal(data, &single); err != nil {
		return out, fmt.Errorf("parse preset meta: %w", err)
	}
	out.Template = single.Template
	out.TemplatePath = single.TemplatePath
	out.TemplatePaths = single.TemplatePaths
	out.TemplateNames = single.TemplateNames
	out.OverrideHints = single.OverrideHints
	if out.OverrideHints == nil {
		out.OverrideHints = []string{}
	}
	return out, nil
}

// ParsePresetFile parses preset YAML (single-rule, composite template_paths, or multi-rule) and returns
// a slice of PresetRule. Overrides are merged into variables (e.g. from --set or API body).
func ParsePresetFile(data []byte, overrides map[string]string) ([]PresetRule, error) {
	var single struct {
		Name          string                   `yaml:"name"`
		Template      string                   `yaml:"template"`
		TemplatePath  string                   `yaml:"template_path"`
		TemplatePaths []string                 `yaml:"template_paths"`
		TemplateNames []string                 `yaml:"template_names"`
		Mode          string                   `yaml:"mode"`
		ChainType     string                   `yaml:"chain_type"`
		ChainID       string                   `yaml:"chain_id"`
		Enabled       bool                     `yaml:"enabled"`
		Variables     map[string]interface{}   `yaml:"variables"`
		Budget        map[string]interface{}   `yaml:"budget"`
		Schedule      map[string]interface{}   `yaml:"schedule"`
		Matrix        []map[string]interface{} `yaml:"matrix"`
		Defaults      map[string]interface{}   `yaml:"defaults"`
	}
	if err := yaml.Unmarshal(data, &single); err != nil {
		return nil, err
	}

	// Matrix preset: one rule per matrix entry, each with chain-specific variables
	if len(single.Matrix) > 0 {
		return parseMatrixPreset(single.Name, single.Template, single.TemplatePath,
			single.TemplatePaths, single.TemplateNames,
			single.Mode, single.ChainType, single.Enabled,
			single.Matrix, single.Defaults, single.Variables,
			single.Budget, single.Schedule, overrides)
	}

	// Composite preset: one rule per (template_paths[i], template_names[i])
	if len(single.TemplatePaths) > 0 && len(single.TemplateNames) > 0 {
		n := len(single.TemplatePaths)
		if len(single.TemplateNames) < n {
			n = len(single.TemplateNames)
		}
		variables := normalizeVariables(single.Variables)
		if variables == nil {
			variables = make(map[string]interface{})
		}
		for k, v := range overrides {
			variables[k] = v
		}
		varsStr := mapInterfaceToStringMap(variables)
		rules := make([]PresetRule, 0, n)
		if single.Name == "" {
			return nil, fmt.Errorf("composite preset requires non-empty name")
		}
		baseName := single.Name
		for i := 0; i < n; i++ {
			templateName := single.TemplateNames[i]
			if templateName == "" {
				continue
			}
			ruleName := baseName
			if n > 1 {
				ruleName = baseName + " (" + templateName + ")"
			}
			r := PresetRule{
				TemplateName: templateName,
				Name:        ruleName,
				Mode:        single.Mode,
				Variables:   copyStringMap(varsStr),
				ChainType:   single.ChainType,
				ChainID:     single.ChainID,
				Enabled:     single.Enabled,
			}
			if len(single.Budget) > 0 {
				r.Budget = substituteBudgetMapVars(copyMapInterface(single.Budget), variables)
			}
			if len(single.Schedule) > 0 {
				r.Schedule = substituteMapVars(copyMapInterface(single.Schedule), variables)
			}
			applyChainIDOverride(&r, overrides)
			rules = append(rules, r)
		}
		if len(rules) == 0 {
			return nil, fmt.Errorf("composite preset produced no rules (template_paths/template_names)")
		}
		return rules, nil
	}

	if single.Template != "" {
		variables := normalizeVariables(single.Variables)
		if variables == nil {
			variables = make(map[string]interface{})
		}
		for k, v := range overrides {
			variables[k] = v
		}
		r := PresetRule{
			TemplateName: single.Template,
			Name:        single.Name,
			Mode:        single.Mode,
			Variables:   mapInterfaceToStringMap(variables),
			ChainType:   single.ChainType,
			ChainID:     single.ChainID,
			Enabled:     single.Enabled,
		}
		if len(single.Budget) > 0 {
			r.Budget = substituteBudgetMapVars(copyMapInterface(single.Budget), variables)
		}
		if len(single.Schedule) > 0 {
			r.Schedule = substituteMapVars(copyMapInterface(single.Schedule), variables)
		}
		applyChainIDOverride(&r, overrides)
		return []PresetRule{r}, nil
	}

	// Multi-rule preset
	var multi struct {
		Rules []struct {
			Name      string                 `yaml:"name"`
			Type      string                 `yaml:"type"`
			Mode      string                 `yaml:"mode"`
			ChainType string                 `yaml:"chain_type"`
			ChainID   string                 `yaml:"chain_id"`
			Enabled   bool                   `yaml:"enabled"`
			Config    map[string]interface{} `yaml:"config"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &multi); err != nil {
		return nil, err
	}
	if len(multi.Rules) == 0 {
		return nil, fmt.Errorf("preset has no rules and no single-rule fields")
	}
	rules := make([]PresetRule, 0, len(multi.Rules))
	for _, r := range multi.Rules {
		templateName, _ := r.Config["template"].(string)
		if templateName == "" {
			continue
		}
		vars := toMapStringInterface(r.Config["variables"])
		if vars == nil {
			vars = make(map[string]interface{})
		}
		vars = normalizeVariables(vars)
		for k, v := range overrides {
			vars[k] = v
		}
		pr := PresetRule{
			TemplateName: templateName,
			Name:         r.Name,
			Mode:         r.Mode,
			Variables:   mapInterfaceToStringMap(vars),
			ChainType:   r.ChainType,
			ChainID:     r.ChainID,
			Enabled:     r.Enabled,
		}
		if b, ok := r.Config["budget"].(map[string]interface{}); ok && len(b) > 0 {
			pr.Budget = substituteBudgetMapVars(copyMapInterface(b), vars)
		}
		if s, ok := r.Config["schedule"].(map[string]interface{}); ok && len(s) > 0 {
			pr.Schedule = substituteMapVars(copyMapInterface(s), vars)
		}
		applyChainIDOverride(&pr, overrides)
		rules = append(rules, pr)
	}
	return rules, nil
}

// parseMatrixPreset expands a matrix preset into one PresetRule per matrix entry.
// Each matrix entry must contain chain_id and may contain chain-specific variable overrides.
// Variables are resolved as: defaults ← matrix[i] ← --set overrides.
func parseMatrixPreset(
	name, template, templatePath string,
	templatePaths, templateNames []string,
	mode, chainType string, enabled bool,
	matrix []map[string]interface{},
	defaults, variables map[string]interface{},
	budget, schedule map[string]interface{},
	overrides map[string]string,
) ([]PresetRule, error) {
	if name == "" {
		return nil, fmt.Errorf("matrix preset requires non-empty name")
	}

	// Determine template name(s)
	isComposite := len(templatePaths) > 0 && len(templateNames) > 0
	if template == "" && !isComposite {
		return nil, fmt.Errorf("matrix preset requires 'template' or 'template_paths'+'template_names'")
	}

	// Top-level chain_id conflicts with matrix
	// (matrix entries each define their own chain_id)

	// Merge defaults and top-level variables (variables acts as defaults if defaults is empty)
	baseVars := make(map[string]interface{})
	if defaults != nil {
		for k, v := range normalizeVariables(defaults) {
			baseVars[k] = v
		}
	}
	if variables != nil {
		for k, v := range normalizeVariables(variables) {
			if _, exists := baseVars[k]; !exists {
				baseVars[k] = v
			}
		}
	}

	var rules []PresetRule
	for i, entry := range matrix {
		// Each matrix entry must have chain_id
		chainIDRaw, ok := entry["chain_id"]
		if !ok {
			return nil, fmt.Errorf("matrix entry %d: missing required 'chain_id'", i)
		}
		entryChainID := strings.TrimSpace(fmt.Sprintf("%v", chainIDRaw))
		if entryChainID == "" {
			return nil, fmt.Errorf("matrix entry %d: empty chain_id", i)
		}

		// Build variables: base ← matrix entry ← --set overrides
		merged := make(map[string]interface{}, len(baseVars)+len(entry))
		for k, v := range baseVars {
			merged[k] = v
		}
		for k, v := range entry {
			merged[k] = v
		}
		for k, v := range overrides {
			merged[k] = v
		}

		varsStr := mapInterfaceToStringMap(merged)

		// Determine effective chain_id (overrides > matrix entry)
		effectiveChainID := entryChainID
		if v, ok := overrides["chain_id"]; ok && v != "" {
			effectiveChainID = v
		}

		if isComposite {
			// Composite: one rule per template per matrix entry
			n := len(templatePaths)
			if len(templateNames) < n {
				n = len(templateNames)
			}
			for j := 0; j < n; j++ {
				tmplName := templateNames[j]
				if tmplName == "" {
					continue
				}
				ruleName := fmt.Sprintf("%s (chain %s, %s)", name, effectiveChainID, tmplName)
				r := PresetRule{
					TemplateName: tmplName,
					Name:         ruleName,
					Mode:         mode,
					Variables:    copyStringMap(varsStr),
					ChainType:    chainType,
					ChainID:      effectiveChainID,
					Enabled:      enabled,
				}
				if len(budget) > 0 {
					r.Budget = substituteBudgetMapVars(copyMapInterface(budget), merged)
				}
				if len(schedule) > 0 {
					r.Schedule = substituteMapVars(copyMapInterface(schedule), merged)
				}
				rules = append(rules, r)
			}
		} else {
			// Single template: one rule per matrix entry
			ruleName := fmt.Sprintf("%s (chain %s)", name, effectiveChainID)
			r := PresetRule{
				TemplateName: template,
				Name:         ruleName,
				Mode:         mode,
				Variables:    varsStr,
				ChainType:    chainType,
				ChainID:      effectiveChainID,
				Enabled:      enabled,
			}
			if len(budget) > 0 {
				r.Budget = substituteBudgetMapVars(copyMapInterface(budget), merged)
			}
			if len(schedule) > 0 {
				r.Schedule = substituteMapVars(copyMapInterface(schedule), merged)
			}
			rules = append(rules, r)
		}
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("matrix preset produced no rules")
	}
	return rules, nil
}

// applyChainIDOverride syncs the chain_id override into PresetRule.ChainID (scope).
// chain_id is a reserved variable — it should NOT appear in preset variables
// sections (deprecated). The only source of truth is the rule-level chain_id
// field. If the user passes --set chain_id=X, it updates the rule-level scope
// so that injectReservedVariables in the service layer uses the correct value.
func applyChainIDOverride(r *PresetRule, overrides map[string]string) {
	if v, ok := overrides["chain_id"]; ok && v != "" {
		r.ChainID = v
	}
}

func normalizeVariables(v map[string]interface{}) map[string]interface{} {
	if v == nil {
		return nil
	}
	out := make(map[string]interface{}, len(v))
	for k, val := range v {
		switch t := val.(type) {
		case []interface{}:
			var parts []string
			for _, p := range t {
				parts = append(parts, fmt.Sprintf("%v", p))
			}
			out[k] = strings.Join(parts, ",")
		default:
			out[k] = val
		}
	}
	return out
}

func mapInterfaceToStringMap(m map[string]interface{}) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = fmt.Sprintf("%v", v)
	}
	return out
}

func copyStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copyMapInterface(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// substituteBudgetMapVars substitutes ${var} in budget map values, except for the "unit" key.
// The unit key is kept as-is (e.g. "${chain_id}:${token_address}") so that config only needs
// variables (chain_id, token_address) changed when switching chains; sync resolves unit at runtime.
func substituteBudgetMapVars(m map[string]interface{}, variables map[string]interface{}) map[string]interface{} {
	if m == nil {
		return m
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		if k == "unit" {
			out[k] = v
			continue
		}
		if len(variables) > 0 {
			out[k] = substituteVarInValue(v, variables)
		} else {
			out[k] = v
		}
	}
	return out
}

func substituteMapVars(m map[string]interface{}, variables map[string]interface{}) map[string]interface{} {
	if m == nil || len(variables) == 0 {
		return m
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = substituteVarInValue(v, variables)
	}
	return out
}

func substituteVarInValue(v interface{}, variables map[string]interface{}) interface{} {
	switch val := v.(type) {
	case string:
		s := val
		for k, vv := range variables {
			s = strings.ReplaceAll(s, "${"+k+"}", fmt.Sprintf("%v", vv))
		}
		return s
	case map[string]interface{}:
		return substituteMapVars(val, variables)
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(val))
		for kk, vv := range val {
			if sk, ok := kk.(string); ok {
				out[sk] = substituteVarInValue(vv, variables)
			}
		}
		return out
	default:
		return v
	}
}

func toMapStringInterface(v interface{}) map[string]interface{} {
	if v == nil {
		return nil
	}
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	if m, ok := v.(map[interface{}]interface{}); ok {
		out := make(map[string]interface{}, len(m))
		for k, val := range m {
			if s, ok := k.(string); ok {
				out[s] = val
			}
		}
		return out
	}
	return nil
}
